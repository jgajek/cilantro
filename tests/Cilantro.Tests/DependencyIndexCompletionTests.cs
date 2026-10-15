using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DependencyIndexCompletionTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void PreservesPublicationOrderAndRecordAliases(bool alias, bool duplicateKey)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Index");
            var record = SyntheticContext.AddType(module, "Entry");
            var offset = new FieldDefUser("Offset", new FieldSig(module.CorLibTypes.Int64), FieldAttributes.Public);
            record.Fields.Add(offset);
            var ctor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Int64))
            { Attributes = MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, Body = new CilBody() };
            record.Methods.Add(ctor);
            foreach (var instruction in new[] { OpCodes.Ldarg_0.ToInstruction(), OpCodes.Call.ToInstruction(new MemberRefUser(module, ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void), module.CorLibTypes.Object.TypeDefOrRef)), OpCodes.Ldarg_0.ToInstruction(),
                OpCodes.Ldarg_1.ToInstruction(), OpCodes.Stfld.ToInstruction(offset), OpCodes.Ret.ToInstruction() }) ctor.Body.Instructions.Add(instruction);
            var tableType = module.CorLibTypes.GetTypeRef("System.Collections", "Hashtable");
            var field = new FieldDefUser("Table", new FieldSig(tableType.ToTypeSig()), FieldAttributes.Static | FieldAttributes.Private);
            owner.Fields.Add(field);
            var readerType = module.CorLibTypes.GetTypeRef("System.IO", "BinaryReader");
            var method = new MethodDefUser("Build", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object))
            { Attributes = MethodAttributes.Private | MethodAttributes.Static, Body = new CilBody { InitLocals = true } };
            owner.Methods.Add(method);
            var reader = new Local(readerType.ToTypeSig()); var saved = new Local(record.ToTypeSig());
            method.Body.Variables.Add(reader); method.Body.Variables.Add(saved);
            var il = method.Body.Instructions;
            il.Add(OpCodes.Ldarg_0.ToInstruction());
            il.Add(OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void,
                module.CorLibTypes.GetTypeRef("System.IO", "Stream").ToTypeSig()), readerType)));
            il.Add(OpCodes.Stloc.ToInstruction(reader));
            il.Add(OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), tableType)));
            il.Add(OpCodes.Stsfld.ToInstruction(field));
            for (var n = 0; n < 2; n++)
            {
                il.Add(OpCodes.Ldsfld.ToInstruction(field)); il.Add(OpCodes.Ldloc.ToInstruction(reader));
                il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "ReadString", MethodSig.CreateInstance(module.CorLibTypes.String), readerType)));
                if (n == 1 && alias) il.Add(OpCodes.Ldloc.ToInstruction(saved));
                else
                {
                    il.Add(OpCodes.Ldc_I8.ToInstruction(7L)); il.Add(OpCodes.Newobj.ToInstruction(ctor));
                    il.Add(OpCodes.Dup.ToInstruction()); il.Add(OpCodes.Stloc.ToInstruction(saved));
                }
                il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "set_Item", MethodSig.CreateInstance(module.CorLibTypes.Void,
                    module.CorLibTypes.Object, module.CorLibTypes.Object), tableType)));
            }
            il.Add(OpCodes.Ret.ToInstruction());
            using var output = new MemoryStream();
            using (var writer = new BinaryWriter(output, System.Text.Encoding.UTF8, true)) { writer.Write("Z"); writer.Write(duplicateKey ? "Z" : "A"); }
            module.Resources.Add(new EmbeddedResource("bundle", output.ToArray(), ManifestResourceAttributes.Private));
        });
        var build = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Build");
        var resource = context.Module.Resources.OfType<EmbeddedResource>().Single();
        Assert.True(DependencyIndexConstruction.TryRead(build, resource, out var original, out var reason), reason);
        Assert.True(original!.CanMaterialize);
        Assert.Equal(new[] { "Z", duplicateKey ? "Z" : "A" }, original.Publications.Select(p => p.Name));
        Assert.Equal(new[] { 0, alias ? 0 : 1 }, original.Publications.Select(p => p.Allocation!.Identity));
        build.Body = DependencyIndexCompletionPass.Materialize(build, original);
        Assert.True(DependencyIndexConstruction.TryRead(build, resource, out var after, out reason), reason);
        Assert.True(DependencyIndexCompletionPass.Equivalent(original, after!));
        Assert.Equal(alias ? 1 : 2, build.Body.Instructions.Count(i => i.OpCode.Code == Code.Newobj && i.Operand is MethodDef));
    }
}
