using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Proxy;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class BabelProxyRecoveryTests
{
    [Fact]
    public void RecoveredProxyPreservesInitializerEffectsAndItsAnswer()
    {
        using var context = Fixture(false);
        new BabelDetectionPass().Run(context);
        var wrapper = context.Module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Forward");
        var counter = context.Module.GetTypes().SelectMany(type => type.Fields).Single(field => field.Name == "Count");
        static (string?, int) Read(ArtifactContext context, MethodDef wrapper, FieldDef counter)
        {
            Assert.True(BootstrapMachine.TrySeed(context, 100_000, out var machine, out var why), why);
            var answer = machine!.Execute(wrapper);
            Assert.True(answer.Succeeded, answer.Diagnostic);
            Assert.True(machine.State.Heap.TryGetString(answer.Value, out var text));
            return (text, machine.State.ReadStaticField(counter).AsInt32());
        }
        var original = Read(context, wrapper, counter);
        var result = new BabelProxyRecoveryPass().Run(context);
        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(1, result.Changes);
        Assert.Equal(("answer", 1), original);
        Assert.Equal(original, Read(context, wrapper, counter));
        Assert.Contains(wrapper.Body.Instructions, instruction => instruction.Operand is IMethod called && called.Name == "RunClassConstructor");
        Assert.DoesNotContain(wrapper.Body.Instructions, instruction => instruction.Operand is IMethod called && called.Name == "Invoke");
        Assert.True(context.TryGetFact<bool>(BabelProxyRecoveryPass.CompleteFact, out var complete) && complete);
    }

    [Fact]
    public void MutableProxyStorageIsNotRewritten()
    {
        using var context = Fixture(true);
        new BabelDetectionPass().Run(context);
        Assert.Equal(0, new BabelProxyRecoveryPass().Run(context).Changes);
        Assert.False(context.TryGetFact<bool>(BabelProxyRecoveryPass.CompleteFact, out var complete) && complete);
    }

    [Fact]
    public void PrivateTargetsRetainTheirAccessSkippingAdapters()
    {
        using var context = Fixture(false);
        var target = context.Module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Target");
        target.Access = MethodAttributes.Private;
        new BabelDetectionPass().Run(context);
        var result = new BabelProxyRecoveryPass().Run(context);
        Assert.Equal(PassStatus.Partial, result.Status);
        Assert.Equal(0, result.Changes);
        Assert.Contains(context.Evidence, evidence => evidence.Category == "babel-proxy-retained" && evidence.Message.Contains("Target"));
        Assert.True(context.TryGetFact<bool>(BabelProxyRecoveryPass.CompleteFact, out var complete) && complete);
        var wrapper = context.Module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Forward");
        Assert.Contains(wrapper.Body.Instructions, instruction => instruction.Operand is IMethod called && called.Name == "Invoke");
    }

    private static ArtifactContext Fixture(bool mutable) => SyntheticContext.Build(module =>
    {
        BabelTests.Marker(module);
        var proxy = new TypeDefUser("", "Proxy", new TypeRefUser(module, "System", "MulticastDelegate", module.CorLibTypes.AssemblyRef))
            { Attributes = TypeAttributes.NotPublic | TypeAttributes.Sealed | TypeAttributes.BeforeFieldInit };
        module.Types.Add(proxy);
        var field = new FieldDefUser("Binding", new FieldSig(new ClassSig(proxy)), FieldAttributes.Private | FieldAttributes.Static);
        proxy.Fields.Add(field);
        var constructor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr),
            MethodImplAttributes.Runtime, MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName);
        var invoke = new MethodDefUser("Invoke", MethodSig.CreateInstance(module.CorLibTypes.String), MethodImplAttributes.Runtime,
            MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.NewSlot);
        proxy.Methods.Add(constructor); proxy.Methods.Add(invoke);
        var host = SyntheticContext.AddType(module, "Host");
        var count = new FieldDefUser("Count", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static); host.Fields.Add(count);
        var target = new MethodDefUser("Target", MethodSig.CreateStatic(module.CorLibTypes.String), MethodAttributes.Static | MethodAttributes.Assembly) { Body = new CilBody() };
        host.Methods.Add(target); target.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("answer")); target.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        var binder = new MethodDefUser("Bind", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32, module.CorLibTypes.Int32, module.CorLibTypes.Int32),
            MethodAttributes.Static) { Body = new CilBody() }; host.Methods.Add(binder);
        var assembly = new TypeRefUser(module, "System.Reflection", "Assembly", module.CorLibTypes.AssemblyRef);
        var reflectedModule = new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef);
        var fieldInfo = new TypeRefUser(module, "System.Reflection", "FieldInfo", module.CorLibTypes.AssemblyRef);
        foreach (var instruction in new[] {
            OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetExecutingAssembly", MethodSig.CreateStatic(new ClassSig(assembly)), assembly)),
            OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_ManifestModule", MethodSig.CreateInstance(new ClassSig(reflectedModule)), assembly)),
            OpCodes.Ldc_I4.ToInstruction(0x04000001),
            OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "ResolveField", MethodSig.CreateInstance(new ClassSig(fieldInfo), module.CorLibTypes.Int32), reflectedModule)),
            OpCodes.Ldnull.ToInstruction(), OpCodes.Ldnull.ToInstruction(), OpCodes.Ldftn.ToInstruction(target), OpCodes.Newobj.ToInstruction(constructor),
            OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "SetValue", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.Object), fieldInfo)),
            OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(count), OpCodes.Ret.ToInstruction() }) binder.Body.Instructions.Add(instruction);
        var wrapper = new MethodDefUser("Forward", MethodSig.CreateStatic(module.CorLibTypes.String), MethodAttributes.Static) { Body = new CilBody() };
        proxy.Methods.Add(wrapper);
        wrapper.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(field)); wrapper.Body.Instructions.Add(OpCodes.Call.ToInstruction(invoke)); wrapper.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
            MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() }; proxy.Methods.Add(cctor);
        foreach (var instruction in new[] { OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Ldc_I4_2.ToInstruction(), OpCodes.Ldc_I4_3.ToInstruction(), OpCodes.Call.ToInstruction(binder), OpCodes.Ret.ToInstruction() })
            cctor.Body.Instructions.Add(instruction);
        if (mutable)
        {
            var writer = new MethodDefUser("Overwrite", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodAttributes.Static) { Body = new CilBody() }; host.Methods.Add(writer);
            writer.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); writer.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(field)); writer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        }
    });
}
