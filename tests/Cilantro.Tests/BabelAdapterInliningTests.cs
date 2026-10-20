using Cilantro.Core;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class BabelAdapterInliningTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ClrBehaviorPreservesCastsBoxedReceiverMutationAndTheAmbientStack(bool valueType)
    {
        using var context = Build(valueType); var expected = Observe(context.Module);
        Assert.Equal("107|23|109|InvalidCastException|NullReferenceException", expected);
        Assert.Equal(3, BabelAdapterInlining.Run(context, out var why));
        Assert.Equal(expected, Observe(context.Module));
        Assert.True(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure, CilantroPipeline.BuildRewriteAllowance(context)).Passed, why);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ChainedAdaptersPreserveClrReceiverAndTemporaryStorage(bool valueType)
    {
        using var context = Build(valueType, true); var expected = Observe(context.Module);
        Assert.Equal(4, BabelAdapterInlining.Run(context, out _));
        Assert.Equal(expected, Observe(context.Module));
        Assert.DoesNotContain(Host(context.Module).Methods.Where(method => method.HasBody).SelectMany(method => method.Body.Instructions),
            instruction => instruction.Operand is IMethod called && called.Name.String is "Forward" or "ForwardOuter");
    }

    [Fact]
    public void AdapterCyclesRemainIntact()
    {
        using var context = Build(false, true);
        var wrapper = Wrapper(context.Module);
        wrapper.Body.Instructions.Single(instruction => instruction.OpCode.Code == Code.Callvirt).OpCode = OpCodes.Call;
        wrapper.Body.Instructions.Single(instruction => instruction.OpCode.Code == Code.Call).Operand = wrapper.DeclaringType.Methods.Single(method => method.Name == "ForwardOuter");
        var snapshots = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody).ToDictionary(method => method, MethodBodySnapshot.Capture);
        Assert.Equal(0, BabelAdapterInlining.Run(context, out _)); Assert.All(snapshots, pair => Assert.True(pair.Value.StructurallyEquals(pair.Key)));
    }

    [Theory]
    [InlineData("not-retired")]
    [InlineData("initializer")]
    [InlineData("unassigned-local")]
    [InlineData("effect")]
    [InlineData("uninitialized-caller")]
    public void UnprovedAdapterStateRemainsIntact(string change)
    {
        using var context = Build(false); var wrapper = Wrapper(context.Module); var host = Host(context.Module);
        if (change == "not-retired") context.SetFact<IReadOnlySet<MethodDef>>(BabelProxyInitializationPass.RetiredWrappersFact, new HashSet<MethodDef>());
        if (change == "initializer")
        {
            var counter = new FieldDefUser("Counter", new FieldSig(context.Module.CorLibTypes.Int32), FieldAttributes.Static); host.Fields.Add(counter);
            var initializer = new MethodDefUser(".cctor", MethodSig.CreateStatic(context.Module.CorLibTypes.Void),
                MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() };
            initializer.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction()); initializer.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(counter)); initializer.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); wrapper.DeclaringType.Methods.Add(initializer);
        }
        if (change == "unassigned-local")
        {
            var il = wrapper.Body.Instructions;
            il.Single(instruction => instruction.IsStloc()).OpCode = OpCodes.Pop;
            il.Single(instruction => instruction.IsLdloc()).Operand = wrapper.Body.Variables[0];
        }
        if (change == "effect")
        {
            var counter = new FieldDefUser("Counter", new FieldSig(context.Module.CorLibTypes.Int32), FieldAttributes.Static); host.Fields.Add(counter);
            wrapper.Body.Instructions.Insert(0, OpCodes.Ldc_I4_1.ToInstruction()); wrapper.Body.Instructions.Insert(1, OpCodes.Stsfld.ToInstruction(counter));
        }
        if (change == "uninitialized-caller")
            foreach (var method in host.Methods.Where(method => method.HasBody))
            { method.Body.InitLocals = false; method.Body.Variables.Add(new Local(context.Module.CorLibTypes.Int32)); }
        var snapshots = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody).ToDictionary(method => method, MethodBodySnapshot.Capture);
        Assert.Equal(0, BabelAdapterInlining.Run(context, out _));
        Assert.All(snapshots, pair => Assert.True(pair.Value.StructurallyEquals(pair.Key)));
        Assert.Empty(context.Changes);
    }

    [Fact]
    public void AnExceptionRegionStartingAtTheCallIncludesTheExpandedReturnCast()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = new TypeDefUser("Synthetic", "CatchHost", module.CorLibTypes.Object.TypeDefOrRef) { Attributes = TypeAttributes.Public }; module.Types.Add(host);
            var target = new MethodDefUser("Value", MethodSig.CreateStatic(module.CorLibTypes.Object), MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() }; host.Methods.Add(target);
            target.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction()); target.Body.Instructions.Add(OpCodes.Box.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef)); target.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var proxy = new TypeDefUser("Synthetic", "Proxy", module.CorLibTypes.GetTypeRef("System", "MulticastDelegate")) { Attributes = TypeAttributes.Sealed }; module.Types.Add(proxy);
            proxy.Methods.Add(new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr), MethodImplAttributes.Runtime,
                MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName));
            proxy.Methods.Add(new MethodDefUser("Invoke", MethodSig.CreateInstance(module.CorLibTypes.String), MethodImplAttributes.Runtime,
                MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.NewSlot | MethodAttributes.HideBySig));
            var wrapper = new MethodDefUser("Forward", MethodSig.CreateStatic(module.CorLibTypes.String), MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() }; proxy.Methods.Add(wrapper);
            wrapper.Body.Instructions.Add(OpCodes.Call.ToInstruction(target)); wrapper.Body.Instructions.Add(OpCodes.Castclass.ToInstruction(module.CorLibTypes.String.TypeDefOrRef)); wrapper.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var caller = new MethodDefUser("Catch", MethodSig.CreateStatic(module.CorLibTypes.Int32), MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody { InitLocals = true } }; host.Methods.Add(caller);
            var result = new Local(module.CorLibTypes.Int32); caller.Body.Variables.Add(result);
            var call = OpCodes.Call.ToInstruction(wrapper); var handler = OpCodes.Pop.ToInstruction(); var end = OpCodes.Ldloc.ToInstruction(result);
            foreach (var instruction in new[] { call, OpCodes.Pop.ToInstruction(), OpCodes.Ldc_I4_7.ToInstruction(), OpCodes.Stloc.ToInstruction(result), OpCodes.Leave.ToInstruction(end),
                         handler, OpCodes.Ldc_I4.ToInstruction(-17), OpCodes.Stloc.ToInstruction(result), OpCodes.Leave.ToInstruction(end), end, OpCodes.Ret.ToInstruction() }) caller.Body.Instructions.Add(instruction);
            caller.Body.ExceptionHandlers.Add(new(ExceptionHandlerType.Catch) { TryStart = call, TryEnd = handler, HandlerStart = handler, HandlerEnd = end,
                CatchType = module.CorLibTypes.GetTypeRef("System", "InvalidCastException") });
        });
        var caller = context.Module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Catch");
        var entry = caller.Body.ExceptionHandlers[0].TryStart;
        context.SetFact<IReadOnlySet<MethodDef>>(BabelProxyInitializationPass.RetiredWrappersFact, new HashSet<MethodDef> { Wrapper(context.Module) });
        int Observe()
        {
            using var bytes = new MemoryStream(); context.Module.Write(bytes);
            var loader = new System.Runtime.Loader.AssemblyLoadContext(Guid.NewGuid().ToString(), true);
            try { return (int)loader.LoadFromStream(new MemoryStream(bytes.ToArray())).GetType("Synthetic.CatchHost")!.GetMethod("Catch")!.Invoke(null, null)!; }
            finally { loader.Unload(); }
        }
        Assert.Equal(-17, Observe()); Assert.Equal(1, BabelAdapterInlining.Run(context, out _)); Assert.Equal(-17, Observe());
        Assert.Same(entry, caller.Body.ExceptionHandlers[0].TryStart);
    }

    [Fact]
    public void ARealTailCallKeepsItsAdapterAndPrefix()
    {
        using var context = Build(false); var caller = Host(context.Module).Methods.Single(method => method.Name == "Caller");
        caller.Body.Instructions.Clear();
        foreach (var instruction in new[] { OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldarg_1.ToInstruction(), OpCodes.Tailcall.ToInstruction(), OpCodes.Call.ToInstruction(Wrapper(context.Module)), OpCodes.Ret.ToInstruction() }) caller.Body.Instructions.Add(instruction);
        var snapshot = MethodBodySnapshot.Capture(caller);
        Assert.Equal(2, BabelAdapterInlining.Run(context, out _));
        Assert.True(snapshot.StructurallyEquals(caller));
    }

    private static ArtifactContext Build(bool valueType, bool chain = false)
    {
        var context = SyntheticContext.Build(module =>
        {
            var receiver = new TypeDefUser("Synthetic", "Receiver", valueType ? module.CorLibTypes.GetTypeRef("System", "ValueType") : module.CorLibTypes.Object.TypeDefOrRef)
                { Attributes = TypeAttributes.Public | (valueType ? TypeAttributes.Sealed | TypeAttributes.SequentialLayout : TypeAttributes.Class) };
            module.Types.Add(receiver);
            var state = new FieldDefUser("State", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Public); receiver.Fields.Add(state);
            if (!valueType)
            {
                var ctor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() };
                ctor.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction()); ctor.Body.Instructions.Add(OpCodes.Call.ToInstruction(new Importer(module).Import(typeof(object).GetConstructor(Type.EmptyTypes)!))); ctor.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); receiver.Methods.Add(ctor);
            }
            var target = new MethodDefUser("Change", MethodSig.CreateInstance(module.CorLibTypes.Int32, module.CorLibTypes.Int32), MethodAttributes.Public) { Body = new CilBody() }; receiver.Methods.Add(target);
            foreach (var instruction in new[] { OpCodes.Ldarg_0.ToInstruction(), OpCodes.Dup.ToInstruction(), OpCodes.Ldfld.ToInstruction(state), OpCodes.Ldarg_1.ToInstruction(), OpCodes.Add.ToInstruction(), OpCodes.Stfld.ToInstruction(state), OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldfld.ToInstruction(state), OpCodes.Ret.ToInstruction() }) target.Body.Instructions.Add(instruction);
            var proxy = new TypeDefUser("Synthetic", "Proxy", module.CorLibTypes.GetTypeRef("System", "MulticastDelegate")) { Attributes = TypeAttributes.Sealed }; module.Types.Add(proxy);
            proxy.Methods.Add(new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr), MethodImplAttributes.Runtime,
                MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName));
            proxy.Methods.Add(new MethodDefUser("Invoke", MethodSig.CreateInstance(module.CorLibTypes.Int32, module.CorLibTypes.Object, module.CorLibTypes.Int32), MethodImplAttributes.Runtime,
                MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.NewSlot | MethodAttributes.HideBySig));
            var wrapper = new MethodDefUser("Forward", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Object, module.CorLibTypes.Int32), MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody { InitLocals = true } }; proxy.Methods.Add(wrapper);
            var temporary = new Local(module.CorLibTypes.Int32); wrapper.Body.Variables.Add(temporary);
            foreach (var instruction in new[] { OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldarg_1.ToInstruction(), OpCodes.Stloc.ToInstruction(temporary), (valueType ? OpCodes.Unbox : OpCodes.Castclass).ToInstruction(receiver), OpCodes.Ldloc.ToInstruction(temporary), (valueType ? OpCodes.Call : OpCodes.Callvirt).ToInstruction(target), OpCodes.Ret.ToInstruction() }) wrapper.Body.Instructions.Add(instruction);
            var entry = wrapper;
            if (chain)
            {
                entry = new MethodDefUser("ForwardOuter", wrapper.MethodSig.Clone(), MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() }; proxy.Methods.Add(entry);
                foreach (var instruction in new[] { OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldarg_1.ToInstruction(), OpCodes.Call.ToInstruction(wrapper), OpCodes.Ret.ToInstruction() }) entry.Body.Instructions.Add(instruction);
            }
            var host = new TypeDefUser("Synthetic", "Host", module.CorLibTypes.Object.TypeDefOrRef) { Attributes = TypeAttributes.Public }; module.Types.Add(host);
            var caller = new MethodDefUser("Caller", wrapper.MethodSig.Clone(), MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() }; host.Methods.Add(caller);
            var site = OpCodes.Call.ToInstruction(entry);
            foreach (var instruction in new[] { OpCodes.Ldc_I4.ToInstruction(100), OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldarg_1.ToInstruction(), OpCodes.Br.ToInstruction(site), site, OpCodes.Add.ToInstruction(), OpCodes.Ret.ToInstruction() }) caller.Body.Instructions.Add(instruction);
            var twice = new MethodDefUser("Twice", wrapper.MethodSig.Clone(), MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody { InitLocals = true } }; host.Methods.Add(twice);
            var sum = new Local(module.CorLibTypes.Int32); twice.Body.Variables.Add(sum);
            foreach (var instruction in new[] { OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldarg_1.ToInstruction(), OpCodes.Call.ToInstruction(entry), OpCodes.Stloc.ToInstruction(sum), OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldarg_1.ToInstruction(), OpCodes.Call.ToInstruction(entry), OpCodes.Ldloc.ToInstruction(sum), OpCodes.Add.ToInstruction(), OpCodes.Ret.ToInstruction() }) twice.Body.Instructions.Add(instruction);
        });
        context.SetFact<IReadOnlySet<MethodDef>>(BabelProxyInitializationPass.RetiredWrappersFact,
            context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.Name.String is "Forward" or "ForwardOuter").ToHashSet());
        return context;
    }

    private static MethodDef Wrapper(ModuleDef module) => module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Forward");
    private static TypeDef Host(ModuleDef module) => module.GetTypes().Single(type => type.Name == "Host");

    private static string Observe(ModuleDef module)
    {
        // The fixture is generated entirely above; no protected application is loaded.
        using var bytes = new MemoryStream(); module.Write(bytes);
        var loader = new System.Runtime.Loader.AssemblyLoadContext(Guid.NewGuid().ToString(), true);
        try
        {
            var assembly = loader.LoadFromStream(new MemoryStream(bytes.ToArray()));
            var receiver = Activator.CreateInstance(assembly.GetType("Synthetic.Receiver")!)!;
            var caller = assembly.GetType("Synthetic.Host")!.GetMethod("Caller")!;
            var twice = assembly.GetType("Synthetic.Host")!.GetMethod("Twice")!;
            string Failure(object? value)
            {
                try { caller.Invoke(null, [value, 1]); return "no exception"; }
                catch (System.Reflection.TargetInvocationException exception) { return exception.InnerException!.GetType().Name; }
            }
            return string.Join("|", caller.Invoke(null, [receiver, 7]), twice.Invoke(null, [receiver, 3]), caller.Invoke(null, [receiver, -4]), Failure(new object()), Failure(null));
        }
        finally { loader.Unload(); }
    }
}
