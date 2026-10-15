using Cilantro.Core;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Passes;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class UnwrittenGuardCompletionTests
{
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void TypedNullReturnKeepsInitializationAndVerifies(bool throws)
    {
        using var context = Fixture(false, throws);
        context.SetFact("options.foldUnwrittenState", true);
        var getter = Method(context, "Guard");
        getter.MethodSig.RetType = context.Module.CorLibTypes.String;
        var before = Run(context, getter);
        Assert.Equal(1, new UnwrittenReferenceCompletionPass().Run(context).Changes);
        Assert.Equal(new[] { Code.Ldsfld, Code.Pop, Code.Ldnull, Code.Ret },
            getter.Body.Instructions.Select(i => i.OpCode.Code));
        var after = Run(context, getter);
        Assert.Equal(before.Result.Status, after.Result.Status);
        Assert.Equal(throws ? StaticExecutionStatus.Threw : StaticExecutionStatus.Completed, after.Result.Status);
        Assert.Contains(after.Machine.State.StaticFields,
            p => p.Key.Contains("Observed", StringComparison.Ordinal) && p.Value.AsInt32() == 7);
        if (!throws) Assert.Equal(before.Result.Value, after.Result.Value);
        else
        {
            Assert.True(before.Machine.State.Heap.TryGetRuntimeTypeName(before.Result.Value, out var original));
            Assert.True(after.Machine.State.Heap.TryGetRuntimeTypeName(after.Result.Value, out var rewritten));
            Assert.Equal(original, rewritten);
        }
        var written = Path.GetTempFileName();
        try
        {
            context.Module.Write(written);
            Assert.DoesNotContain("StackUnexpected", IlVerification.Read(written).Findings.Values.SelectMany(v => v));
        }
        finally { File.Delete(written); }
        Assert.Equal(0, new UnwrittenReferenceCompletionPass().Run(context).Changes);
    }

    [Theory]
    [InlineData("disabled")] [InlineData("write")] [InlineData("address")] [InlineData("effect")]
    public void NullReturnRequiresProofAndExactGetter(string refusal)
    {
        using var context = Fixture(false, false, refusal);
        context.SetFact("options.foldUnwrittenState", refusal != "disabled");
        var getter = Method(context, "Guard");
        getter.MethodSig.RetType = context.Module.CorLibTypes.String;
        var before = getter.Body;
        Assert.Equal(0, new UnwrittenReferenceCompletionPass().Run(context).Changes);
        Assert.Same(before, getter.Body);
    }

    [Theory]
    [InlineData(false, false)] [InlineData(true, false)]
    [InlineData(false, true)] [InlineData(true, true)]
    public void ConstantGuardRetainsInitializationAndItsFailure(bool boolean, bool throws)
    {
        using var context = Fixture(boolean, throws);
        context.SetFact("options.foldUnwrittenState", true);
        var caller = Method(context, "Run");
        var before = Run(context, caller);
        var result = new UnwrittenGuardCompletionPass().Run(context);
        Assert.Equal(1, result.Changes);
        Assert.Contains(caller.Body.Instructions, i => i.OpCode.Code == Code.Call && (i.Operand as IMethod)?.Name == "Guard");
        Assert.DoesNotContain(caller.Body.Instructions, i => i.OpCode.Code is Code.Brtrue or Code.Brtrue_S or Code.Brfalse or Code.Brfalse_S);
        var after = Run(context, caller);
        Assert.Equal(before.Result.Status, after.Result.Status);
        Assert.Contains(after.Machine.State.StaticFields, p => p.Key.Contains("Observed", StringComparison.Ordinal) && p.Value.AsInt32() == 7);
        if (throws)
        {
            Assert.Equal(StaticExecutionStatus.Threw, after.Result.Status);
            Assert.True(before.Machine.State.Heap.TryGetRuntimeTypeName(before.Result.Value, out var originalType));
            Assert.True(after.Machine.State.Heap.TryGetRuntimeTypeName(after.Result.Value, out var rewrittenType));
            Assert.Equal(originalType, rewrittenType);
        }
        else
        {
            Assert.Equal(StaticExecutionStatus.Completed, after.Result.Status);
            Assert.Equal(before.Result.Value, after.Result.Value);
            Assert.Equal(boolean ? 42 : 11, after.Result.Value.AsInt32());
        }
        Assert.Equal(0, new UnwrittenGuardCompletionPass().Run(context).Changes);
    }

    [Theory]
    [InlineData("disabled")] [InlineData("write")] [InlineData("address")] [InlineData("effect")]
    public void UnprovenOrDisabledGuardsRemainUnchanged(string refusal)
    {
        using var context = Fixture(true, false, refusal);
        context.SetFact("options.foldUnwrittenState", refusal != "disabled");
        var before = Method(context, "Run").Body;
        Assert.Equal(0, new UnwrittenGuardCompletionPass().Run(context).Changes);
        Assert.Same(before, Method(context, "Run").Body);
    }

    private static (StaticExecutionResult Result, StaticMachine Machine) Run(ArtifactContext context, MethodDef method)
    {
        var machine = new StaticMachine(modelTypeInitialization: true);
        machine.State.RegisterModuleMetadata(context.Module);
        return (machine.Execute(method), machine);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void StackCarriedGuardPreservesTheSourceCallAndItsFailure(bool throws)
    {
        using var context = Fixture(true, throws);
        var method = Method(context, "Run");
        var guard = Method(context, "Guard");
        var local = new Local(context.Module.CorLibTypes.Int32);
        method.Body.Variables.Add(local);
        var store = OpCodes.Stloc.ToInstruction(local);
        var done = OpCodes.Ldloc.ToInstruction(local);
        var il = method.Body.Instructions;
        il.Clear();
        foreach (var i in new[] { OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Call.ToInstruction(guard), OpCodes.Pop.ToInstruction(),
            OpCodes.Br.ToInstruction(store), store, OpCodes.Ldloc.ToInstruction(local), OpCodes.Ldc_I4_1.ToInstruction(),
            OpCodes.Add.ToInstruction(), OpCodes.Stloc.ToInstruction(local), OpCodes.Ldloc.ToInstruction(local),
            OpCodes.Switch.ToInstruction(new[] { done, done }), done, OpCodes.Ret.ToInstruction() }) il.Add(i);
        var before = Run(context, method);
        Assert.Equal(1, DispatcherPathPass.Rewrite(method));
        Assert.Contains(method.Body.Instructions, i => i.OpCode.Code == Code.Call && i.Operand == guard);
        var after = Run(context, method);
        Assert.Equal(before.Result.Status, after.Result.Status);
        Assert.Contains(after.Machine.State.StaticFields, p => p.Key.Contains("Observed", StringComparison.Ordinal) && p.Value.AsInt32() == 7);
        if (!throws) Assert.Equal(before.Result.Value, after.Result.Value);
        else Assert.Equal(StaticExecutionStatus.Threw, after.Result.Status);
    }

    [Fact]
    public void AThrowingSourceCallCannotPublishTheNewLocalValueToItsCatch()
    {
        using var context = Fixture(true, false);
        var method = Method(context, "Run");
        var throwing = new MethodDefUser("ThrowAndReturn", MethodSig.CreateStatic(context.Module.CorLibTypes.Boolean))
            { Attributes = MethodAttributes.Static, Body = new CilBody() };
        method.DeclaringType.Methods.Add(throwing);
        throwing.Body.Instructions.Add(OpCodes.Newobj.ToInstruction(new MemberRefUser(context.Module, ".ctor",
            MethodSig.CreateInstance(context.Module.CorLibTypes.Void), context.Module.CorLibTypes.GetTypeRef("System", "InvalidOperationException"))));
        throwing.Body.Instructions.Add(OpCodes.Throw.ToInstruction());
        var local = new Local(context.Module.CorLibTypes.Int32);
        method.Body.Variables.Add(local);
        var start = OpCodes.Ldc_I4_0.ToInstruction();
        var store = OpCodes.Stloc.ToInstruction(local);
        var end = OpCodes.Ldloc.ToInstruction(local);
        var leave = OpCodes.Leave.ToInstruction(end);
        var handler = OpCodes.Pop.ToInstruction();
        var il = method.Body.Instructions; il.Clear();
        foreach (var i in new[] { OpCodes.Ldc_I4_7.ToInstruction(), OpCodes.Stloc.ToInstruction(local),
            start, OpCodes.Call.ToInstruction(throwing), OpCodes.Pop.ToInstruction(), OpCodes.Br.ToInstruction(store),
            store, OpCodes.Ldloc.ToInstruction(local), OpCodes.Switch.ToInstruction(new[] { leave }), leave,
            handler, OpCodes.Leave.ToInstruction(end), end, OpCodes.Ret.ToInstruction() }) il.Add(i);
        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
        { TryStart = start, TryEnd = handler, HandlerStart = handler, HandlerEnd = end,
            CatchType = context.Module.CorLibTypes.GetTypeRef("System", "Exception") });
        var before = Run(context, method);
        Assert.Equal(StaticExecutionStatus.Completed, before.Result.Status);
        Assert.Equal(7, before.Result.Value.AsInt32());
        Assert.Equal(1, DispatcherPathPass.Rewrite(method));
        var after = Run(context, method);
        Assert.Equal(before.Result.Status, after.Result.Status);
        Assert.Equal(before.Result.Value, after.Result.Value);
    }

    private static MethodDef Method(ArtifactContext context, string name) => context.Module.GetTypes()
        .SelectMany(t => t.Methods).Single(m => m.Name == name);

    private static ArtifactContext Fixture(bool boolean, bool throws, string? refusal = null) => SyntheticContext.Build(module =>
    {
        var owner = SyntheticContext.AddType(module, "Singleton");
        var never = new FieldDefUser("Never", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Static);
        var observed = new FieldDefUser("Observed", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
        owner.Fields.Add(never); owner.Fields.Add(observed);
        var initializer = owner.FindOrCreateStaticConstructor();
        initializer.Body.Instructions.Clear();
        initializer.Body.Instructions.Add(OpCodes.Ldc_I4_7.ToInstruction());
        initializer.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(observed));
        if (throws)
        {
            initializer.Body.Instructions.Add(OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void), module.CorLibTypes.GetTypeRef("System", "InvalidOperationException"))));
            initializer.Body.Instructions.Add(OpCodes.Throw.ToInstruction());
        }
        else initializer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        var guard = new MethodDefUser("Guard", MethodSig.CreateStatic(boolean ? module.CorLibTypes.Boolean : module.CorLibTypes.Object))
            { Attributes = MethodAttributes.Static, Body = new CilBody() };
        owner.Methods.Add(guard);
        if (refusal == "effect")
        { guard.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction()); guard.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(observed)); }
        guard.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(never));
        if (boolean) { guard.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); guard.Body.Instructions.Add(OpCodes.Ceq.ToInstruction()); }
        guard.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        var callerOwner = SyntheticContext.AddType(module, "Caller");
        var caller = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32))
            { Attributes = MethodAttributes.Static, Body = new CilBody() };
        callerOwner.Methods.Add(caller);
        if (refusal == "write")
        { caller.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); caller.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(never)); }
        if (refusal == "address")
        { caller.Body.Instructions.Add(OpCodes.Ldsflda.ToInstruction(never)); caller.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); }
        var yes = Instruction.CreateLdcI4(42);
        foreach (var i in new[] { OpCodes.Call.ToInstruction(guard), OpCodes.Brtrue.ToInstruction(yes),
            Instruction.CreateLdcI4(11), OpCodes.Ret.ToInstruction(), yes, OpCodes.Ret.ToInstruction() }) caller.Body.Instructions.Add(i);
    });
}
