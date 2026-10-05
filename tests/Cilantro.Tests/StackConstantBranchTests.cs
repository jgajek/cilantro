using Cilantro.Core.Analysis;
using Cilantro.Core.Passes;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class StackConstantBranchTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ConditionalDispatcherEdgeKeepsConditionAndUntakenStack(bool storeState)
    {
        using var module = NewModule("ConditionalDispatch", ModuleKind.Dll);
        var method = Method(module);
        var state = new Local(module.CorLibTypes.Int32);
        method.Body.Variables.Add(state);
        var selected = Instruction.CreateLdcI4(17);
        var dispatch = OpCodes.Switch.ToInstruction(new[] { selected });
        var ingress = storeState ? OpCodes.Stloc.ToInstruction(state) : dispatch;
        var branch = OpCodes.Brtrue.ToInstruction(ingress);
        Add(method, Instruction.CreateLdcI4(0), OpCodes.Ldarg_0.ToInstruction(), branch,
            Instruction.CreateLdcI4(23), OpCodes.Add.ToInstruction(), OpCodes.Ret.ToInstruction());
        if (storeState) Add(method, ingress, OpCodes.Ldloc.ToInstruction(state));
        Add(method, dispatch, Instruction.CreateLdcI4(31), OpCodes.Ret.ToInstruction(), selected, OpCodes.Ret.ToInstruction());
        Assert.Equal(23, Invoke(module, 0));
        Assert.Equal(17, Invoke(module, 1));
        Assert.True(LocalConstantPropagation.Fold(method) > 0);
        Assert.Equal(Code.Brtrue, branch.OpCode.Code);
        Assert.NotSame(ingress, branch.Operand);
        Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);
        Assert.NotNull(ControlFlowCompletionPass.TryComplete(method));
        Assert.Equal(23, Invoke(module, 0));
        Assert.Equal(17, Invoke(module, 1));
    }

    [Fact]
    public void DeadExclusiveExceptionEndDoesNotKeepADeadDispatcherAlive()
    {
        using var module = NewModule("ExceptionEnd", ModuleKind.Dll);
        var method = Method(module);
        var value = new Local(module.CorLibTypes.Int32);
        method.Body.Variables.Add(value);
        var start = Instruction.CreateLdcI4(17);
        var handler = OpCodes.Ldloc.ToInstruction(value);
        var deadEnd = Instruction.CreateLdcI4(999);
        var end = OpCodes.Ldloc.ToInstruction(value);
        Add(method, start, OpCodes.Stloc.ToInstruction(value), OpCodes.Leave.ToInstruction(end),
            handler, Instruction.CreateLdcI4(1), OpCodes.Add.ToInstruction(), OpCodes.Stloc.ToInstruction(value),
            OpCodes.Endfinally.ToInstruction(), deadEnd, OpCodes.Pop.ToInstruction(), OpCodes.Br.ToInstruction(deadEnd),
            end, OpCodes.Ret.ToInstruction());
        var clause = new ExceptionHandler(ExceptionHandlerType.Finally)
        { TryStart = start, TryEnd = handler, HandlerStart = handler, HandlerEnd = deadEnd };
        method.Body.ExceptionHandlers.Add(clause);
        Assert.Equal(18, Invoke(module, 0));
        Assert.NotNull(ControlFlowCompletionPass.TryComplete(method));
        Assert.DoesNotContain(deadEnd, method.Body.Instructions);
        Assert.Same(end, clause.HandlerEnd);
        Assert.Same(handler, clause.TryEnd);
        Assert.Equal(18, Invoke(module, 0));
    }

    [Theory]
    [InlineData(1, true)]
    [InlineData(2, false)]
    public void FoldsMergedSelectorOnlyWhenBothPathsAgree(int other, bool folds)
    {
        using var module = NewModule("StackBranches", ModuleKind.Dll);
        var method = Method(module);
        var yes = Instruction.CreateLdcI4(17);
        var no = Instruction.CreateLdcI4(23);
        var alternate = Instruction.CreateLdcI4(other);
        var dispatch = OpCodes.Switch.ToInstruction(new[] { no, yes, no });
        Add(method, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Brtrue.ToInstruction(alternate),
            Instruction.CreateLdcI4(1), OpCodes.Br.ToInstruction(dispatch), alternate, dispatch,
            no, OpCodes.Ret.ToInstruction(), yes, OpCodes.Ret.ToInstruction());
        Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);
        LocalConstantPropagation.Fold(method);
        Assert.Equal(folds ? Code.Pop : Code.Switch, dispatch.OpCode.Code);
        Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);
        Assert.Equal(17, Invoke(module, 0));
        Assert.Equal(other == 1 ? 17 : 23, Invoke(module, 1));
    }

    [Fact]
    public void PreservesInputDependentApplicationSwitch()
    {
        using var module = NewModule("ApplicationSwitch", ModuleKind.Dll);
        var method = Method(module);
        var yes = Instruction.CreateLdcI4(17);
        var dispatch = OpCodes.Switch.ToInstruction(new[] { yes });
        Add(method, OpCodes.Ldarg_0.ToInstruction(), dispatch, Instruction.CreateLdcI4(23),
            OpCodes.Ret.ToInstruction(), yes, OpCodes.Ret.ToInstruction());
        var before = method.Body.Instructions.ToArray();
        Assert.Equal(0, LocalConstantPropagation.Fold(method));
        Assert.Equal(before, method.Body.Instructions);
        Assert.Equal(Code.Switch, dispatch.OpCode.Code);
        Assert.Equal(17, Invoke(module, 0));
        Assert.Equal(23, Invoke(module, 1));
    }

    [Fact]
    public void DuplicatedNullTestKeepsTheOriginalStackValue()
    {
        using var module = NewModule("NullBranch", ModuleKind.Dll);
        var method = Method(module);
        var consume = OpCodes.Pop.ToInstruction();
        Add(method, OpCodes.Ldnull.ToInstruction(), OpCodes.Dup.ToInstruction(),
            OpCodes.Brfalse.ToInstruction(consume), OpCodes.Pop.ToInstruction(),
            Instruction.CreateLdcI4(23), OpCodes.Ret.ToInstruction(), consume,
            Instruction.CreateLdcI4(17), OpCodes.Ret.ToInstruction());
        Assert.NotNull(ControlFlowCompletionPass.TryComplete(method));
        Assert.DoesNotContain(method.Body.Instructions, i => i.OpCode.FlowControl == FlowControl.Cond_Branch);
        Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);
        Assert.Equal(17, Invoke(module, 0));
    }

    [Fact]
    public void KnownComparisonConsumesBothOperandsButKeepsCarriedValue()
    {
        using var module = NewModule("Comparison", ModuleKind.Dll);
        var method = Method(module);
        var target = OpCodes.Ret.ToInstruction();
        var compare = OpCodes.Beq.ToInstruction(target);
        Add(method, Instruction.CreateLdcI4(42), Instruction.CreateLdcI4(7),
            OpCodes.Dup.ToInstruction(), OpCodes.Br.ToInstruction(compare), compare,
            OpCodes.Pop.ToInstruction(), Instruction.CreateLdcI4(23), OpCodes.Ret.ToInstruction(), target);
        Assert.True(LocalConstantPropagation.Fold(method) > 0);
        Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);
        Assert.NotNull(ControlFlowCompletionPass.TryComplete(method));
        Assert.Equal(42, Invoke(module, 0));
    }

    [Fact]
    public void FoldedDispatcherWithBackwardEntryStillWritesAndRuns()
    {
        using var module = NewModule("BackwardDiscard", ModuleKind.Dll);
        var method = Method(module);
        var counter = new Local(module.CorLibTypes.Int32);
        method.Body.Variables.Add(counter);
        method.Body.InitLocals = true;
        var body = OpCodes.Ldloc.ToInstruction(counter);
        var dispatch = OpCodes.Switch.ToInstruction(new[] { body });
        Add(method, Instruction.CreateLdcI4(0), OpCodes.Ldarg_0.ToInstruction(),
            OpCodes.Brfalse.ToInstruction(dispatch), OpCodes.Pop.ToInstruction(),
            OpCodes.Br.ToInstruction(body), dispatch, OpCodes.Br.ToInstruction(body),
            body, Instruction.CreateLdcI4(1), OpCodes.Add.ToInstruction(), OpCodes.Stloc.ToInstruction(counter),
            Instruction.CreateLdcI4(0), OpCodes.Ldloc.ToInstruction(counter), Instruction.CreateLdcI4(2),
            OpCodes.Blt.ToInstruction(dispatch), OpCodes.Pop.ToInstruction(),
            OpCodes.Ldloc.ToInstruction(counter), OpCodes.Ret.ToInstruction());
        Assert.Equal(2, Invoke(module, 0));
        Assert.Equal(2, Invoke(module, 1));
        Assert.NotNull(ControlFlowCompletionPass.TryComplete(method));
        Assert.DoesNotContain(method.Body.Instructions, i => i.OpCode.Code == Code.Switch);
        Assert.Equal(0, ForwardScan.Unnameable(method));
        Assert.Equal(2, Invoke(module, 0));
        Assert.Equal(2, Invoke(module, 1));
    }

    [Theory]
    [InlineData(-1, -1)]
    [InlineData(0, 100)]
    [InlineData(3, 3)]
    public void SharedStoreDispatcherPreservesTheStateOnCaseAndDefaultEdges(int state, int expected)
    {
        using var module = NewModule("SharedState", ModuleKind.Dll);
        var method = Method(module);
        var local = new Local(module.CorLibTypes.Int32);
        method.Body.Variables.Add(local);
        var store = OpCodes.Stloc.ToInstruction(local);
        var selected = OpCodes.Ldloc.ToInstruction(local);
        var jump = OpCodes.Br.ToInstruction(store);
        Add(method, Instruction.CreateLdcI4(state), jump, store, OpCodes.Ldloc.ToInstruction(local),
            OpCodes.Switch.ToInstruction(new[] { selected }), OpCodes.Ldloc.ToInstruction(local),
            OpCodes.Ret.ToInstruction(), selected, Instruction.CreateLdcI4(100),
            OpCodes.Add.ToInstruction(), OpCodes.Ret.ToInstruction());
        Assert.Equal(expected, Invoke(module, 0));
        Assert.True(LocalConstantPropagation.Fold(method) > 0);
        Assert.Equal(Code.Stloc, jump.OpCode.Code);
        Assert.Same(local, jump.Operand);
        Assert.NotNull(ControlFlowCompletionPass.TryComplete(method));
        Assert.Equal(expected, Invoke(module, 0));
    }

    private static ModuleDefUser NewModule(string name, ModuleKind kind)
    {
        var module = new ModuleDefUser(name) { Kind = kind };
        new AssemblyDefUser(name, new Version(1, 0)).Modules.Add(module);
        return module;
    }

    private static MethodDefUser Method(ModuleDef module)
    {
        var type = new TypeDefUser("Fixture", "Program", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(type);
        var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32))
        { Attributes = MethodAttributes.Public | MethodAttributes.Static, Body = new CilBody() };
        type.Methods.Add(method);
        return method;
    }

    private static void Add(MethodDef method, params Instruction[] instructions)
    {
        foreach (var instruction in instructions) method.Body.Instructions.Add(instruction);
    }

    private static int Invoke(ModuleDef module, int argument)
    {
        // Only this source-built fixture is executed, never a corpus input.
        using var image = new MemoryStream();
        module.Write(image);
        image.Position = 0;
        var loading = new System.Runtime.Loader.AssemblyLoadContext(Guid.NewGuid().ToString(), isCollectible: true);
        try { return (int)loading.LoadFromStream(image).GetType("Fixture.Program")!.GetMethod("Run")!.Invoke(null, [argument])!; }
        finally { loading.Unload(); }
    }
}
