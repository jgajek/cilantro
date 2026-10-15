using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Passes;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ConvergentGuardTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void BooleanDiamondPreservesBothPathsAndAlternateEntry(bool firstTrue, bool secondTrue)
    {
        using var module = new ModuleDefUser("diamonds");
        var method = Method(module);
        var right = Instruction.CreateLdcI4(1);
        var destination = Instruction.CreateLdcI4(19);
        var test = (secondTrue ? OpCodes.Brtrue : OpCodes.Brfalse).ToInstruction(destination);
        var first = (firstTrue ? OpCodes.Brtrue : OpCodes.Brfalse).ToInstruction(right);
        var left = Instruction.CreateLdcI4(0);
        Add(method, OpCodes.Ldarg_0.ToInstruction(), Instruction.CreateLdcI4(42), OpCodes.Beq.ToInstruction(left),
            OpCodes.Ldarg_0.ToInstruction(), first, left, OpCodes.Br.ToInstruction(test), right, test,
            Instruction.CreateLdcI4(7), OpCodes.Ret.ToInstruction(), destination, OpCodes.Ret.ToInstruction());
        var inputs = new[] { 0, 1, -1, 42, int.MinValue, int.MaxValue };
        var before = inputs.Select(Run).ToArray();
        Assert.Equal(1, RedundantControlFlow.FoldBooleanDiamonds(method));
        Assert.Equal(before, inputs.Select(Run).ToArray());
        Assert.Equal(0, RedundantControlFlow.FoldBooleanDiamonds(method));
        Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);
        (StaticExecutionStatus, StaticValue) Run(int input)
        {
            var result = new StaticMachine().Execute(method, [StaticValue.FromInt32(input)]);
            return (result.Status, result.Value);
        }
    }

    [Fact]
    public void BooleanDiamondDoesNotCrossExceptionBoundary()
    {
        using var module = new ModuleDefUser("regions");
        var method = Method(module);
        var right = Instruction.CreateLdcI4(1);
        var destination = Instruction.CreateLdcI4(19);
        var test = OpCodes.Brtrue.ToInstruction(destination);
        var start = OpCodes.Ldarg_0.ToInstruction();
        Add(method, start, OpCodes.Brfalse.ToInstruction(right), Instruction.CreateLdcI4(0),
            OpCodes.Br.ToInstruction(test), right, test, Instruction.CreateLdcI4(7),
            OpCodes.Ret.ToInstruction(), destination, OpCodes.Ret.ToInstruction());
        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Finally)
        { TryStart = start, TryEnd = right, HandlerStart = right, HandlerEnd = destination });
        Assert.Equal(0, RedundantControlFlow.FoldBooleanDiamonds(method));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CarriedLiteralDisappearsWithoutRemovingCallOrException(bool throwing)
    {
        using var module = new ModuleDefUser("carried");
        var method = Method(module);
        var field = new FieldDefUser("Effect", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
        module.GlobalType.Fields.Add(field);
        var call = new MethodDefUser("Effect", MethodSig.CreateStatic(module.CorLibTypes.Int32))
        { Attributes = MethodAttributes.Static, Body = new CilBody() };
        module.GlobalType.Methods.Add(call);
        Add(call, Instruction.CreateLdcI4(19), OpCodes.Stsfld.ToInstruction(field));
        if (throwing) Add(call, OpCodes.Ldnull.ToInstruction(), OpCodes.Throw.ToInstruction());
        else Add(call, Instruction.CreateLdcI4(3), OpCodes.Ret.ToInstruction());
        Add(method, Instruction.CreateLdcI4(42), OpCodes.Call.ToInstruction(call),
            OpCodes.Pop.ToInstruction(), OpCodes.Pop.ToInstruction(), Instruction.CreateLdcI4(7), OpCodes.Ret.ToInstruction());
        var before = Run();
        Assert.Equal(2, DiscardedStackValues.Remove(method));
        Assert.DoesNotContain(method.Body.Instructions, i => i.IsLdcI4() && i.GetLdcI4Value() == 42);
        Assert.Contains(method.Body.Instructions, i => i.Operand == call);
        Assert.Equal(before, Run());
        Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);
        (StaticExecutionStatus, StaticValue, StaticValue) Run()
        {
            var machine = new StaticMachine();
            var result = machine.Execute(method, [StaticValue.FromInt32(0)]);
            return (result.Status, result.Value, machine.State.ReadStaticField(field));
        }
    }

    [Fact]
    public void DuplicatedLiteralWithLiveCopyIsPreserved()
    {
        using var module = new ModuleDefUser("duplicate");
        var method = Method(module);
        Add(method, Instruction.CreateLdcI4(42), OpCodes.Dup.ToInstruction(), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
        Assert.Equal(2, DiscardedStackValues.Remove(method));
        Assert.Contains(method.Body.Instructions, i => i.IsLdcI4() && i.GetLdcI4Value() == 42);
        Assert.Equal(StaticValue.FromInt32(42), new StaticMachine().Execute(method, [StaticValue.FromInt32(0)]).Value);
    }

    [Fact]
    public void IncomingBranchDoesNotInheritLiteralIdentity()
    {
        using var module = new ModuleDefUser("entry");
        var method = Method(module);
        var discard = OpCodes.Pop.ToInstruction();
        Add(method, Instruction.CreateLdcI4(42), OpCodes.Ldarg_0.ToInstruction(), OpCodes.Brtrue.ToInstruction(discard),
            OpCodes.Pop.ToInstruction(), Instruction.CreateLdcI4(19), discard, Instruction.CreateLdcI4(7), OpCodes.Ret.ToInstruction());
        Assert.Equal(0, DiscardedStackValues.Remove(method));
        Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DeadStateGuardDisappearsButCallAndExceptionRemain(bool throwing)
    {
        using var module = new ModuleDefUser("guards");
        var method = Method(module);
        var local = new Local(module.CorLibTypes.Int32); method.Body.Variables.Add(local);
        var field = new FieldDefUser("Observed", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
        module.GlobalType.Fields.Add(field);
        var guard = new MethodDefUser("Guard", MethodSig.CreateStatic(module.CorLibTypes.Boolean, module.CorLibTypes.Boolean))
        { Attributes = MethodAttributes.Static, Body = new CilBody() };
        module.GlobalType.Methods.Add(guard);
        Add(guard, Instruction.CreateLdcI4(19), OpCodes.Stsfld.ToInstruction(field));
        if (throwing) Add(guard, OpCodes.Ldnull.ToInstruction(), OpCodes.Throw.ToInstruction());
        else Add(guard, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ret.ToInstruction());
        var store = OpCodes.Stloc.ToInstruction(local); var done = Instruction.CreateLdcI4(7);
        Add(method, Instruction.CreateLdcI4(42), OpCodes.Ldarg_0.ToInstruction(), OpCodes.Call.ToInstruction(guard),
            OpCodes.Brtrue.ToInstruction(store), OpCodes.Pop.ToInstruction(), OpCodes.Br.ToInstruction(done),
            store, OpCodes.Br.ToInstruction(done), done, OpCodes.Ret.ToInstruction());
        var before0 = Run(0); var before1 = Run(1);
        Assert.NotNull(ControlFlowCompletionPass.TryComplete(method));
        Assert.DoesNotContain(method.Body.Instructions, i => i.OpCode.FlowControl == FlowControl.Cond_Branch);
        Assert.Contains(method.Body.Instructions, i => i.Operand == guard);
        Assert.Equal(before0, Run(0)); Assert.Equal(before1, Run(1));
        Assert.Equal(StaticValue.FromInt32(19), before0.Item3);
        Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);

        (StaticExecutionStatus, StaticValue, StaticValue) Run(int flag)
        {
            var machine = new StaticMachine();
            var result = machine.Execute(method, [StaticValue.FromInt32(flag)]);
            return (result.Status, result.Value, machine.State.ReadStaticField(field));
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(99)]
    public void ConvergentSwitchConsumesSelectorAndCarriedValue(int selector)
    {
        using var module = new ModuleDefUser("switch");
        var method = Method(module);
        var first = OpCodes.Pop.ToInstruction(); var second = OpCodes.Pop.ToInstruction();
        var done = Instruction.CreateLdcI4(7);
        Add(method, Instruction.CreateLdcI4(42), OpCodes.Ldarg_0.ToInstruction(),
            OpCodes.Switch.ToInstruction(new[] { first, second }), OpCodes.Pop.ToInstruction(), OpCodes.Br.ToInstruction(done),
            first, OpCodes.Br.ToInstruction(done), second, OpCodes.Br.ToInstruction(done), done, OpCodes.Ret.ToInstruction());
        Assert.NotNull(ControlFlowCompletionPass.TryComplete(method));
        Assert.DoesNotContain(method.Body.Instructions, i => i.OpCode.Code == Code.Switch);
        var result = new StaticMachine().Execute(method, [StaticValue.FromInt32(selector)]);
        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(StaticValue.FromInt32(7), result.Value);
        Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);
    }

    [Fact]
    public void ConvergentComparisonStillConsumesBothOperands()
    {
        using var module = new ModuleDefUser("comparison");
        var method = Method(module); var done = Instruction.CreateLdcI4(7);
        Add(method, OpCodes.Ldarg_0.ToInstruction(), Instruction.CreateLdcI4(3),
            OpCodes.Beq.ToInstruction(done), OpCodes.Br.ToInstruction(done), done, OpCodes.Ret.ToInstruction());
        Assert.Equal(1, RedundantControlFlow.FoldConvergentBranches(method));
        Assert.Equal(2, method.Body.Instructions.Count(i => i.OpCode.Code == Code.Pop));
        Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);
    }

    [Fact]
    public void DistinctEffectsAndCyclesDoNotConverge()
    {
        using var module = new ModuleDefUser("distinct");
        var method = Method(module); var done = Instruction.CreateLdcI4(7);
        var loop = OpCodes.Nop.ToInstruction();
        Add(method, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Brtrue.ToInstruction(loop),
            OpCodes.Br.ToInstruction(done), loop, OpCodes.Br.ToInstruction(loop), done, OpCodes.Ret.ToInstruction());
        Assert.Equal(0, RedundantControlFlow.FoldConvergentBranches(method));
        // A loop is not an empty path; neither is an assignment to externally visible state.
        var field = new FieldDefUser("Effect", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
        module.GlobalType.Fields.Add(field);
        method.Body.Instructions[4].Operand = done;
        method.Body.Instructions.Insert(4, Instruction.CreateLdcI4(19));
        method.Body.Instructions.Insert(5, OpCodes.Stsfld.ToInstruction(field));
        Assert.Equal(0, RedundantControlFlow.FoldConvergentBranches(method));
    }

    [Fact]
    public void ReadOrAddressTakenLocalsKeepTheirStores()
    {
        using var module = new ModuleDefUser("locals");
        var method = Method(module); var local = new Local(module.CorLibTypes.Int32);
        method.Body.Variables.Add(local);
        Add(method, Instruction.CreateLdcI4(42), OpCodes.Stloc.ToInstruction(local),
            OpCodes.Ldloc.ToInstruction(local), OpCodes.Ret.ToInstruction());
        Assert.Equal(0, RedundantControlFlow.RemoveUnreadIntegerStores(method));
        method.Body.Instructions[2].OpCode = OpCodes.Ldloca;
        Assert.Equal(0, RedundantControlFlow.RemoveUnreadIntegerStores(method));
        local.Type = module.CorLibTypes.Double;
        method.Body.Instructions.RemoveAt(2);
        Assert.Equal(0, RedundantControlFlow.RemoveUnreadIntegerStores(method));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ConvergentFieldGuardRetainsTheReadAndNullFailure(bool nullReceiver)
    {
        using var module = new ModuleDefUser("field-guard");
        var owner = new TypeDefUser("Owner", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(owner);
        var field = new FieldDefUser("Guard", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Public);
        owner.Fields.Add(field);
        var method = Method(module);
        method.MethodSig = MethodSig.CreateStatic(module.CorLibTypes.Int32, owner.ToTypeSig());
        var done = Instruction.CreateLdcI4(7);
        Add(method, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldfld.ToInstruction(field),
            OpCodes.Brtrue.ToInstruction(done), OpCodes.Br.ToInstruction(done), done, OpCodes.Ret.ToInstruction());
        var before = Run();
        Assert.NotNull(ControlFlowCompletionPass.TryComplete(method));
        Assert.DoesNotContain(method.Body.Instructions, i => i.OpCode.FlowControl == FlowControl.Cond_Branch);
        Assert.Contains(method.Body.Instructions, i => i.OpCode.Code == Code.Ldfld);
        Assert.Equal(before, Run());

        (StaticExecutionStatus, StaticValue) Run()
        {
            var machine = new StaticMachine();
            var receiver = StaticValue.Null;
            if (!nullReceiver) Assert.True(machine.State.Heap.TryAllocateObject(owner.FullName, out receiver));
            var result = machine.Execute(method, [receiver]);
            return (result.Status, result.Value);
        }
    }

    [Fact]
    public void ConvergentLeaveTargetsDoNotBypassFinally()
    {
        using var module = new ModuleDefUser("finally");
        var method = Method(module);
        var start = OpCodes.Ldarg_0.ToInstruction();
        var done = Instruction.CreateLdcI4(7);
        var secondLeave = OpCodes.Leave.ToInstruction(done);
        var handler = OpCodes.Nop.ToInstruction();
        Add(method, start, OpCodes.Brtrue.ToInstruction(secondLeave), OpCodes.Leave.ToInstruction(done),
            secondLeave, handler, OpCodes.Endfinally.ToInstruction(), done, OpCodes.Ret.ToInstruction());
        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Finally)
        { TryStart = start, TryEnd = handler, HandlerStart = handler, HandlerEnd = done });
        Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);
        Assert.Equal(0, RedundantControlFlow.FoldConvergentBranches(method));
    }

    private static MethodDefUser Method(ModuleDef module)
    {
        var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32))
        { Attributes = MethodAttributes.Static, Body = new CilBody() };
        module.GlobalType.Methods.Add(method); return method;
    }
    private static void Add(MethodDef method, params Instruction[] instructions)
    { foreach (var instruction in instructions) method.Body.Instructions.Add(instruction); }
}
