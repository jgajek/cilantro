using Cilantro.Core;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DependencyIndexConstructionTests
{
    [Theory]
    [InlineData("closed", true)]
    [InlineData("ambient", false)]
    [InlineData("old-table", false)]
    [InlineData("bypass", false)]
    [InlineData("foreign", false)]
    [InlineData("finalizer", false)]
    [InlineData("damaged", false)]
    [InlineData("late-write", false)]
    [InlineData("early-write", true)]
    [InlineData("literal", true)]
    [InlineData("narrow-argument", false)]
    public void ReadsOnlyClosedFreshIndexConstruction(string variant, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Index");
            var record = SyntheticContext.AddType(module, "Entry");
            var offset = new FieldDefUser("Offset", new FieldSig(module.CorLibTypes.Int64), FieldAttributes.Public);
            record.Fields.Add(offset);
            var constructor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Int64))
                { Attributes = MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, Body = new CilBody() };
            record.Methods.Add(constructor);
            var baseConstructor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), module.CorLibTypes.Object.TypeDefOrRef);
            foreach (var instruction in new[] { OpCodes.Ldarg_0.ToInstruction(), OpCodes.Call.ToInstruction(baseConstructor),
                OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldarg_1.ToInstruction(), OpCodes.Stfld.ToInstruction(offset), OpCodes.Ret.ToInstruction() })
                constructor.Body.Instructions.Add(instruction);
            if (variant == "finalizer")
                record.Methods.Add(new MethodDefUser("Finalize", MethodSig.CreateInstance(module.CorLibTypes.Void))
                    { Attributes = MethodAttributes.Family | MethodAttributes.Virtual, Body = new CilBody() });
            var tableType = module.CorLibTypes.GetTypeRef("System.Collections", "Hashtable");
            var table = new FieldDefUser("Table", new FieldSig(tableType.ToTypeSig()), FieldAttributes.Private | FieldAttributes.Static);
            owner.Fields.Add(table);
            var streamType = module.CorLibTypes.GetTypeRef("System.IO", "Stream");
            var readerType = variant == "foreign" ? new TypeRefUser(module, "System.IO", "BinaryReader", new AssemblyRefUser("Foreign"))
                : module.CorLibTypes.GetTypeRef("System.IO", "BinaryReader");
            var readerConstructor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, streamType.ToTypeSig()), readerType);
            var tableConstructor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), tableType);
            var readName = new MemberRefUser(module, "ReadString", MethodSig.CreateInstance(module.CorLibTypes.String), readerType);
            var readOffset = new MemberRefUser(module, variant == "narrow-argument" ? "ReadInt32" : "ReadInt64",
                MethodSig.CreateInstance(variant == "narrow-argument" ? module.CorLibTypes.Int32 : module.CorLibTypes.Int64), readerType);
            var put = new MemberRefUser(module, "set_Item", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.Object), tableType);
            var method = new MethodDefUser("Build", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object))
                { Attributes = MethodAttributes.Private | MethodAttributes.Static, Body = new CilBody { InitLocals = true } };
            owner.Methods.Add(method);
            var reader = new Local(readerType.ToTypeSig()); method.Body.Variables.Add(reader);
            var il = method.Body.Instructions;
            var ret = OpCodes.Ret.ToInstruction();
            if (variant == "literal") { il.Add(OpCodes.Ldstr.ToInstruction("interned")); il.Add(OpCodes.Pop.ToInstruction()); }
            if (variant == "ambient")
            {
                il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "get_TickCount", MethodSig.CreateStatic(module.CorLibTypes.Int32),
                    module.CorLibTypes.GetTypeRef("System", "Environment")))); il.Add(OpCodes.Pop.ToInstruction());
            }
            if (variant == "old-table") { il.Add(OpCodes.Ldsfld.ToInstruction(table)); il.Add(OpCodes.Pop.ToInstruction()); }
            if (variant == "bypass") il.Add(OpCodes.Br.ToInstruction(ret));
            foreach (var instruction in new[] { OpCodes.Ldarg_0.ToInstruction(), OpCodes.Newobj.ToInstruction(readerConstructor),
                OpCodes.Stloc.ToInstruction(reader), OpCodes.Newobj.ToInstruction(tableConstructor), OpCodes.Stsfld.ToInstruction(table),
                OpCodes.Ldsfld.ToInstruction(table), OpCodes.Ldloc.ToInstruction(reader), OpCodes.Callvirt.ToInstruction(readName),
                OpCodes.Ldloc.ToInstruction(reader), OpCodes.Callvirt.ToInstruction(readOffset), OpCodes.Newobj.ToInstruction(constructor),
                OpCodes.Callvirt.ToInstruction(put), ret }) il.Add(instruction);
            if (variant == "late-write")
            {
                var saved = new Local(record.ToTypeSig()); method.Body.Variables.Add(saved);
                var at = il.IndexOf(il.Single(i => i.OpCode.Code == Code.Newobj && i.Operand == constructor)) + 1;
                il.Insert(at, OpCodes.Dup.ToInstruction()); il.Insert(at + 1, OpCodes.Stloc.ToInstruction(saved));
                at = il.IndexOf(ret);
                il.Insert(at, OpCodes.Ldloc.ToInstruction(saved)); il.Insert(at + 1, OpCodes.Ldc_I8.ToInstruction(9L));
                il.Insert(at + 2, OpCodes.Stfld.ToInstruction(offset));
            }
            if (variant == "early-write")
            {
                var at = il.IndexOf(il.Single(i => i.OpCode.Code == Code.Newobj && i.Operand == constructor)) + 1;
                il.Insert(at, OpCodes.Dup.ToInstruction()); il.Insert(at + 1, OpCodes.Ldc_I8.ToInstruction(9L));
                il.Insert(at + 2, OpCodes.Stfld.ToInstruction(offset));
            }
            using var bytes = new MemoryStream();
            using (var writer = new BinaryWriter(bytes, System.Text.Encoding.UTF8, true))
            { writer.Write("Example, Version=1.0.0.0"); writer.Write(1234L); }
            module.Resources.Add(new EmbeddedResource("bundle", variant == "damaged" ? new byte[] { 255 } : bytes.ToArray(), ManifestResourceAttributes.Private));
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Build");
        var resource = context.Module.Resources.OfType<EmbeddedResource>().Single();
        var original = method.Body;
        var passed = DependencyIndexConstruction.TryRead(method, resource, out var snapshot, out var reason);
        Assert.Equal(expected, passed);
        Assert.Same(original, method.Body);
        if (!expected) { Assert.Null(snapshot); return; }
        Assert.True(passed, reason);
        var entry = Assert.Single(snapshot!.Entries);
        Assert.Equal("Example, Version=1.0.0.0", entry.Name);
        Assert.Equal(variant == "early-write" ? 9L : 1234L, Assert.Single(entry.Values).Value);
        Assert.Equal(resource.CreateReader().Length, snapshot.Position);
        Assert.Equal("bundle", snapshot.Source.Name);
        Assert.Equal(variant != "literal", snapshot.CanMaterialize);
        if (!snapshot.CanMaterialize) return;
        Assert.Equal(new long[] { 1234 }, Assert.Single(snapshot.Publications).Allocation!.Arguments);
        method.Body = DependencyIndexCompletionPass.Materialize(method, snapshot);
        Assert.True(DependencyIndexConstruction.TryRead(method, resource, out var materialized, out reason), reason);
        Assert.True(DependencyIndexCompletionPass.Equivalent(snapshot, materialized!));
        Assert.False(materialized!.CanMaterialize);
    }
}
