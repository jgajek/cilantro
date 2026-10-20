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

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void PrivateTargetCallsRecoverOnlyInAccessibleCallerContexts(bool accessible)
    {
        using var context = Fixture(false);
        var target = context.Module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Target");
        target.Access = MethodAttributes.Private;
        var wrapper = context.Module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Forward");
        var host = target.DeclaringType;
        if (!accessible)
        {
            host = new TypeDefUser("", "Unrelated", context.Module.CorLibTypes.Object.TypeDefOrRef);
            context.Module.Types.Add(host);
        }
        var caller = new MethodDefUser("Caller", MethodSig.CreateStatic(context.Module.CorLibTypes.String), MethodAttributes.Static | MethodAttributes.Assembly)
            { Body = new CilBody() };
        host.Methods.Add(caller);
        var call = OpCodes.Call.ToInstruction(wrapper);
        // A branch directly to the call must also execute the initialization trigger.
        caller.Body.Instructions.Add(OpCodes.Br_S.ToInstruction(call));
        caller.Body.Instructions.Add(call);
        caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        var counter = context.Module.GetTypes().SelectMany(type => type.Fields).Single(field => field.Name == "Count");
        static (string?, int) Read(ArtifactContext context, MethodDef caller, FieldDef counter)
        {
            Assert.True(BootstrapMachine.TrySeed(context, 100_000, out var machine, out var why), why);
            var answer = machine!.Execute(caller);
            Assert.True(answer.Succeeded, answer.Diagnostic);
            Assert.True(machine.State.Heap.TryGetString(answer.Value, out var text));
            return (text, machine.State.ReadStaticField(counter).AsInt32());
        }
        var original = Read(context, caller, counter);
        new BabelDetectionPass().Run(context);
        new BabelProxyRecoveryPass().Run(context);
        Assert.Equal(("answer", 1), original);
        Assert.Equal(original, Read(context, caller, counter));
        Assert.True(context.TryGetFact<int>("babel.proxies.directCallerSites", out var sites));
        Assert.Equal(accessible ? 1 : 0, sites);
        Assert.Contains(caller.Body.Instructions, instruction => instruction.Operand is IMethod called &&
            called.ResolveMethodDef() == (accessible ? target : wrapper));
        if (accessible)
        {
            Assert.Equal(Code.Ldtoken, call.OpCode.Code);
            Assert.Same(call, caller.Body.Instructions[0].Operand);
            var directory = Directory.CreateTempSubdirectory("Cilantro.BabelCaller.").FullName;
            try
            {
                var path = Path.Combine(directory, "caller.dll");
                context.Module.Write(path);
                Assert.DoesNotContain(IlVerification.Read(path).Findings, entry => entry.Key.Contains("Caller"));
            }
            finally { Directory.Delete(directory, true); }
        }
    }

    [Fact]
    public void ClosedPrivateDelegateConstructionCanBeRetiredAfterDirectRecovery()
    {
        using var context = Fixture(false, effects: false);
        new BabelDetectionPass().Run(context); context.SetFact("options.removeRuntime", true);
        Assert.Equal(PassStatus.Success, new BabelProxyRecoveryPass().Run(context).Status);
        var proxy = context.Module.GetTypes().Single(type => type.Name == "Proxy");
        var result = new BabelProxyInitializationPass().Run(context);
        Assert.Equal(PassStatus.Success, result.Status); Assert.Equal(1, result.Changes);
        Assert.Equal(Code.Ret, Assert.Single(proxy.FindStaticConstructor().Body.Instructions).OpCode.Code);
        var wrapper = proxy.Methods.Single(method => method.Name == "Forward");
        Assert.DoesNotContain(wrapper.Body.Instructions, instruction => instruction.Operand is IMethod called && called.Name == "RunClassConstructor");
        Assert.True(BootstrapMachine.TrySeed(context, 100_000, out var machine, out var why), why);
        var answer = machine!.Execute(wrapper);
        Assert.True(answer.Succeeded, answer.Diagnostic);
        Assert.True(machine.State.Heap.TryGetString(answer.Value, out var text)); Assert.Equal("answer", text);
    }

    [Fact]
    public void ApplicationInitializerEffectsPreventRetirement()
    {
        using var context = Fixture(false);
        new BabelDetectionPass().Run(context); context.SetFact("options.removeRuntime", true);
        new BabelProxyRecoveryPass().Run(context);
        var initializer = context.Module.GetTypes().Single(type => type.Name == "Proxy").FindStaticConstructor();
        var snapshot = Cilantro.Core.Verification.MethodBodySnapshot.Capture(initializer);
        Assert.Equal(0, new BabelProxyInitializationPass().Run(context).Changes);
        Assert.True(snapshot.StructurallyEquals(initializer));
        var wrapper = initializer.DeclaringType.Methods.Single(method => method.Name == "Forward");
        Assert.True(BootstrapMachine.TrySeed(context, 100_000, out var machine, out var why), why);
        Assert.True(machine!.Execute(wrapper).Succeeded);
        Assert.Equal(1, machine.State.ReadStaticField(context.Module.GetTypes().SelectMany(type => type.Fields).Single(field => field.Name == "Count")).AsInt32());
    }

    [Fact]
    public void AReachableUnrecoveredWrapperKeepsItsDelegateInitializer()
    {
        using var context = Fixture(false, effects: false);
        var target = context.Module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Target");
        target.Access = MethodAttributes.Private;
        var proxy = context.Module.GetTypes().Single(type => type.Name == "Proxy");
        var wrapper = proxy.Methods.Single(method => method.Name == "Forward");
        var host = target.DeclaringType; host.Visibility = TypeAttributes.Public;
        var run = new MethodDefUser("Run", MethodSig.CreateStatic(context.Module.CorLibTypes.String), MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
        host.Methods.Add(run); run.Body.Instructions.Add(OpCodes.Call.ToInstruction(wrapper)); run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        // A caller in a different type lacks the private target's access context.
        run.DeclaringType.Methods.Remove(run);
        var caller = new TypeDefUser("", "Caller", context.Module.CorLibTypes.Object.TypeDefOrRef) { Attributes = TypeAttributes.Public };
        context.Module.Types.Add(caller); caller.Methods.Add(run);
        new BabelDetectionPass().Run(context); context.SetFact("options.removeRuntime", true);
        new BabelProxyRecoveryPass().Run(context);
        Assert.Contains(wrapper.Body.Instructions, instruction => instruction.Operand is IMethod called && called.Name == "Invoke");
        Assert.Equal(0, new BabelProxyInitializationPass().Run(context).Changes);
        Assert.NotEqual(Code.Ret, proxy.FindStaticConstructor().Body.Instructions[0].OpCode.Code);
    }

    [Fact]
    public void BindingIdentityDistinguishesIdenticalMethodNamesInDifferentAssemblies()
    {
        using var module = new ModuleDefUser("scope-check");
        CilBody Call(string assembly)
        {
            var type = new TypeRefUser(module, "Same", "Type", new AssemblyRefUser(assembly));
            var target = new MemberRefUser(module, "Method", MethodSig.CreateStatic(module.CorLibTypes.Void), type);
            var body = new CilBody(); body.Instructions.Add(OpCodes.Call.ToInstruction(target)); body.Instructions.Add(OpCodes.Ret.ToInstruction());
            return body;
        }
        Assert.NotEqual(BabelProxyRecoveryPass.BindingFingerprint(Call("First")), BabelProxyRecoveryPass.BindingFingerprint(Call("Second")));
    }

    [Fact]
    public void ThreadSpecificProxyStorageIsNotTreatedAsAProcessWideBinding()
    {
        using var context = Fixture(false, effects: false);
        var type = new TypeRefUser(context.Module, "System", "ThreadStaticAttribute", context.Module.CorLibTypes.AssemblyRef);
        context.Module.GetTypes().Single(owner => owner.Name == "Proxy").Fields[0].CustomAttributes.Add(
            new CustomAttribute(new MemberRefUser(context.Module, ".ctor", MethodSig.CreateInstance(context.Module.CorLibTypes.Void), type)));
        new BabelDetectionPass().Run(context);
        Assert.Equal(0, new BabelProxyRecoveryPass().Run(context).Changes);
        Assert.False(context.TryGetFact<bool>(BabelProxyRecoveryPass.CompleteFact, out var complete) && complete);
    }

    private static ArtifactContext Fixture(bool mutable, bool effects = true) => SyntheticContext.Build(module =>
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
        if (!effects)
        {
            binder.Body.Instructions.RemoveAt(binder.Body.Instructions.Count - 2);
            binder.Body.Instructions.RemoveAt(binder.Body.Instructions.Count - 2);
            host.Fields.Remove(count);
        }
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
