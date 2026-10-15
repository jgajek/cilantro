using Cilantro.Core.Recovery;
using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ResourceEnumerationAdapterTests
{
    [Theory]
    [InlineData("valid", true)]
    [InlineData("changed-resource", false)]
    [InlineData("shared-cache", false)]
    [InlineData("satellite-code", false)]
    [InlineData("shared-effect", false)]
    public void RetiresAdapterOnlyWithPreservedResourcesAndPrivateEffects(string scenario, bool expected)
    {
        using var satellite = new ModuleDefUser("Satellite.dll") { Kind = ModuleKind.Dll };
        var resource = new EmbeddedResource("application", new byte[] { 1, 2, 3 }, ManifestResourceAttributes.Public);
        satellite.Resources.Add(resource);
        if (scenario == "satellite-code")
        {
            var method = new MethodDefUser("Extra", MethodSig.CreateStatic(satellite.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            satellite.GlobalType.Methods.Add(method);
        }
        using var bytes = new MemoryStream(); satellite.Write(bytes);
        using var context = Fixture("valid", original =>
        {
            original.Resources.Add(new EmbeddedResource("bundle", bytes.ToArray(), ManifestResourceAttributes.Private));
            original.Resources.Add(new EmbeddedResource("application", scenario == "changed-resource" ? new byte[] { 9 } : new byte[] { 1, 2, 3 }, ManifestResourceAttributes.Public));
        });
        var module = context.Module;
        var source = (EmbeddedResource)module.Resources[0];
        var owner = module.Types.Single(t => t.Name == "Adapter");
        var caller = module.Types.Single(t => t.Name == "Consumer").Methods.Single();
        var wrapper = owner.Methods.Single(m => m.Name == "Names");
        var init = owner.Methods.Single(m => m.Name == "Init");
        context.SetFact<IReadOnlyList<RestoredResourceBundle>>("resources.validatedBundles",
            [new(RecoveredResourceOrigin.Capture(source), [RecoveredResourceOrigin.Capture(resource)])]);
        context.SetFact("options.removeRuntime", true);
        var assembly = module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly");
        var stream = module.CorLibTypes.GetTypeRef("System.IO", "Stream");
        var reader = module.CorLibTypes.GetTypeRef("System.IO", "BinaryReader");
        MemberRef Call(string name, MethodSig signature, ITypeDefOrRef type) => new MemberRefUser(module, name, signature, type);
        init.Body.Instructions.Clear();
        Instruction[] il = [
            OpCodes.Call.ToInstruction(Call("GetExecutingAssembly", MethodSig.CreateStatic(assembly.ToTypeSig()), assembly)),
            OpCodes.Ldstr.ToInstruction("bundle"),
            OpCodes.Callvirt.ToInstruction(Call("GetManifestResourceStream", MethodSig.CreateInstance(stream.ToTypeSig(), module.CorLibTypes.String), assembly)),
            OpCodes.Newobj.ToInstruction(Call(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, stream.ToTypeSig()), reader)),
            Instruction.CreateLdcI4((int)bytes.Length),
            OpCodes.Callvirt.ToInstruction(Call("ReadBytes", MethodSig.CreateInstance(new SZArraySig(module.CorLibTypes.Byte), module.CorLibTypes.Int32), reader)),
            OpCodes.Call.ToInstruction(Call("Load", MethodSig.CreateStatic(assembly.ToTypeSig(), new SZArraySig(module.CorLibTypes.Byte)), assembly)),
            OpCodes.Stsfld.ToInstruction(owner.Fields.Single(f => f.Name == "Satellite")),
            OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(owner.Fields.Single(f => f.Name == "Ready")),
            OpCodes.Ret.ToInstruction()];
        foreach (var instruction in il) init.Body.Instructions.Add(instruction);
        if (scenario == "shared-effect")
        {
            var field = new FieldDefUser("ApplicationState", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            caller.DeclaringType.Fields.Add(field);
            init.Body.Instructions.Insert(0, OpCodes.Ldc_I4_1.ToInstruction());
            init.Body.Instructions.Insert(1, OpCodes.Stsfld.ToInstruction(field));
        }
        if (scenario == "shared-cache")
        {
            caller.Body.Instructions.Insert(0, OpCodes.Ldsfld.ToInstruction(owner.Fields[0]));
            caller.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
        }
        var result = new ResourceEnumerationCompletionPass().Run(context);
        Assert.True(result.Changes == (expected ? 1 : 0), string.Join("; ", result.Diagnostics));
        if (!expected)
        {
            Assert.Contains(caller.Body.Instructions, i => i.OpCode == OpCodes.Call && i.Operand == wrapper);
            Assert.Contains(owner, module.Types);
            return;
        }
        Assert.DoesNotContain(caller.Body.Instructions, i => i.Operand == wrapper);
        new ResourceEnumerationRuntimeCleanupPass().Run(context);
        Assert.DoesNotContain(owner, module.Types);
        Assert.Equal(1, new ProtectorResourceCleanupPass().Run(context).Changes);
        Assert.Equal("application", Assert.Single(module.Resources).Name.String);
        using var serialized = new MemoryStream(); module.Write(serialized);
        Assert.Equal(0, new ResourceEnumerationCompletionPass().Run(context).Changes);
    }

    [Theory]
    [InlineData("valid", true)]
    [InlineData("nops", true)]
    [InlineData("foreign-api", false)]
    [InlineData("wrong-branch", false)]
    [InlineData("extra-effect", false)]
    [InlineData("wrong-owner", false)]
    [InlineData("instance-init", false)]
    public void RecognizesOnlyTheClosedEnumerationShape(string scenario, bool expected)
    {
        using var context = Fixture(scenario);
        var wrapper = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Names");
        Assert.Equal(expected, ResourceEnumerationAdapter.Match(wrapper) is not null);
    }
    private static Cilantro.Core.ArtifactContext Fixture(string scenario, Action<ModuleDefUser>? configure = null) => SyntheticContext.Build(module =>
        {
            configure?.Invoke(module);
            var owner = SyntheticContext.AddType(module, "Adapter");
            var assembly = module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly");
            var type = module.CorLibTypes.GetTypeRef("System", "Type");
            var handle = module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle");
            var list = new TypeSpecUser(new GenericInstSig(new ClassSig(module.CorLibTypes.GetTypeRef("System.Collections.Generic", "List`1")), module.CorLibTypes.String));
            var enumerable = new GenericInstSig(new ClassSig(module.CorLibTypes.GetTypeRef("System.Collections.Generic", "IEnumerable`1")), module.CorLibTypes.String);
            var strings = new SZArraySig(module.CorLibTypes.String);
            var flag = new FieldDefUser("Ready", new FieldSig(module.CorLibTypes.Boolean), FieldAttributes.Static);
            var satellite = new FieldDefUser("Satellite", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Static);
            owner.Fields.Add(flag); owner.Fields.Add(satellite);
            var initialize = new MethodDefUser("Init", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            initialize.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); owner.Methods.Add(initialize);
            var wrapper = new MethodDefUser("Names", MethodSig.CreateStatic(strings, assembly.ToTypeSig()))
                { Attributes = MethodAttributes.Static, Body = new CilBody() }; owner.Methods.Add(wrapper);
            MemberRef Call(string name, MethodSig sig, ITypeDefOrRef declaring) => new MemberRefUser(module, name, sig, declaring);
            var names = Call("GetManifestResourceNames", MethodSig.CreateInstance(strings), assembly);
            var add = Call("AddRange", MethodSig.CreateInstance(module.CorLibTypes.Void, enumerable), list);
            var foreignStart = OpCodes.Ldarg_0.ToInstruction();
            var build = OpCodes.Newobj.ToInstruction(Call(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), list));
            Instruction[] il = [
                OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldtoken.ToInstruction(owner),
                OpCodes.Call.ToInstruction(Call("GetTypeFromHandle", MethodSig.CreateStatic(type.ToTypeSig(), new ValueTypeSig(handle)), type)),
                OpCodes.Callvirt.ToInstruction(Call("get_Assembly", MethodSig.CreateInstance(assembly.ToTypeSig()), type)),
                OpCodes.Call.ToInstruction(Call("op_Equality", MethodSig.CreateStatic(module.CorLibTypes.Boolean, assembly.ToTypeSig(), assembly.ToTypeSig()), assembly)),
                OpCodes.Brfalse.ToInstruction(foreignStart), OpCodes.Ldsfld.ToInstruction(flag), OpCodes.Brtrue.ToInstruction(build),
                OpCodes.Call.ToInstruction(initialize), build, OpCodes.Dup.ToInstruction(), OpCodes.Ldarg_0.ToInstruction(),
                OpCodes.Callvirt.ToInstruction(names), OpCodes.Callvirt.ToInstruction(add), OpCodes.Dup.ToInstruction(),
                OpCodes.Ldsfld.ToInstruction(satellite), OpCodes.Castclass.ToInstruction(assembly), OpCodes.Callvirt.ToInstruction(names),
                OpCodes.Callvirt.ToInstruction(add), OpCodes.Callvirt.ToInstruction(Call("ToArray", MethodSig.CreateInstance(strings), list)),
                OpCodes.Ret.ToInstruction(), foreignStart, OpCodes.Callvirt.ToInstruction(names), OpCodes.Ret.ToInstruction()];
            foreach(var instruction in il) wrapper.Body.Instructions.Add(instruction);
            var consumer = SyntheticContext.AddType(module, "Consumer");
            consumer.Attributes = TypeAttributes.Public;
            var caller = new MethodDefUser("Run", MethodSig.CreateStatic(strings, assembly.ToTypeSig()))
                { Attributes = MethodAttributes.Static | MethodAttributes.Public, Body = new CilBody() };
            consumer.Methods.Add(caller);
            caller.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(wrapper));
            caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            if(scenario == "nops") wrapper.Body.Instructions.Insert(0, OpCodes.Nop.ToInstruction());
            if(scenario == "foreign-api") assembly.ResolutionScope = new AssemblyRefUser("Foreign");
            if(scenario == "wrong-branch") il[5].Operand = il[9];
            if(scenario == "extra-effect") wrapper.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(initialize));
            if(scenario == "wrong-owner") il[1].Operand = module.GlobalType;
            if(scenario == "instance-init") initialize.IsStatic = false;
        });

}
