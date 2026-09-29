using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Passes;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
namespace Cilantro.Tests;

public sealed class DispatcherStoreStateTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void ConditionalOnlyDispatcherKeepsSelectedSideEffects(int initial)
    {
        using var module = new ModuleDefUser("conditional-only");
        var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32))
        { Attributes = MethodAttributes.Static, Body = new CilBody() };
        module.GlobalType.Methods.Add(method);
        var field = new FieldDefUser("Effect", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
        module.GlobalType.Fields.Add(field);
        var local = new Local(module.CorLibTypes.Int32); method.Body.Variables.Add(local);
        var dispatch = OpCodes.Ldloc.ToInstruction(local);
        var done = OpCodes.Ldloc.ToInstruction(local);
        Add(method, Instruction.CreateLdcI4(initial), OpCodes.Stloc.ToInstruction(local), OpCodes.Br.ToInstruction(dispatch),
            dispatch, OpCodes.Brfalse.ToInstruction(done), Instruction.CreateLdcI4(19), OpCodes.Stsfld.ToInstruction(field), done, OpCodes.Ret.ToInstruction());
        var before = Execute();
        Assert.Equal(1, DispatcherPathPass.Rewrite(method));
        ControlFlowCompletionPass.TryComplete(method);
        Assert.Equal(before, Execute());
        Assert.DoesNotContain(method.Body.Instructions, i => i.OpCode.FlowControl == FlowControl.Cond_Branch);
        Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);
        (StaticExecutionStatus, StaticValue, StaticValue) Execute()
        {
            var machine = new StaticMachine();
            var result = machine.Execute(method, []);
            return (result.Status, result.Value, machine.State.ReadStaticField(field));
        }
    }

    [Theory]
    [InlineData(Code.Rem, -7, 3)]
    [InlineData(Code.Rem_Un, -7, 3)]
    [InlineData(Code.Div, -7, 3)]
    [InlineData(Code.Div_Un, -7, 3)]
    [InlineData(Code.Rem, 6, 3)]
    public void ArithmeticAndKnownConditionalPathsPreserveFinalLocal(Code arithmetic, int initial, int divisor)
    {
        using var module = new ModuleDefUser("arithmetic-path");
        var method = ArithmeticPath(module, arithmetic, initial, divisor);
        var before = Run(method, 0);
        Assert.Equal(1, DispatcherPathPass.Rewrite(method));
        Assert.Equal(before, Run(method, 0));
        Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);
        ControlFlowCompletionPass.TryComplete(method);
        Assert.DoesNotContain(method.Body.Instructions, i => i.OpCode.Code == Code.Switch);
    }

    [Theory]
    [InlineData(Code.Div, 7, 0)]
    [InlineData(Code.Rem_Un, 7, 0)]
    [InlineData(Code.Div, int.MinValue, -1)]
    [InlineData(Code.Rem, int.MinValue, -1)]
    public void PotentialArithmeticExceptionsPreventBypass(Code arithmetic, int initial, int divisor)
    {
        using var module = new ModuleDefUser("throwing-path");
        var method = ArithmeticPath(module, arithmetic, initial, divisor);
        var original = method.Body.Instructions.Select(i => (i.OpCode, i.Operand)).ToArray();
        Assert.Equal(0, DispatcherPathPass.Rewrite(method));
        Assert.Equal(original, method.Body.Instructions.Select(i => (i.OpCode, i.Operand)).ToArray());
    }

    private static MethodDefUser ArithmeticPath(ModuleDef module, Code arithmetic, int initial, int divisor)
    {
        var method = new MethodDefUser("Arithmetic", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32))
        { Attributes = MethodAttributes.Static, Body = new CilBody() };
        module.GlobalType.Methods.Add(method);
        var local = new Local(module.CorLibTypes.Int32); method.Body.Variables.Add(local);
        var dispatch = OpCodes.Ldloc.ToInstruction(local);
        var selected = OpCodes.Ldloc.ToInstruction(local);
        var result = OpCodes.Ldloc.ToInstruction(local);
        var operation = arithmetic switch { Code.Rem => OpCodes.Rem, Code.Rem_Un => OpCodes.Rem_Un, Code.Div => OpCodes.Div, _ => OpCodes.Div_Un };
        Add(method, Instruction.CreateLdcI4(initial), OpCodes.Stloc.ToInstruction(local), OpCodes.Br.ToInstruction(dispatch),
            dispatch, OpCodes.Dup.ToInstruction(), OpCodes.Pop.ToInstruction(), Instruction.CreateLdcI4(divisor), operation.ToInstruction(),
            OpCodes.Stloc.ToInstruction(local), OpCodes.Ldloc.ToInstruction(local), OpCodes.Brtrue.ToInstruction(selected),
            OpCodes.Br.ToInstruction(selected), selected, OpCodes.Switch.ToInstruction(new[] { result, result }),
            OpCodes.Br.ToInstruction(result), result, OpCodes.Ret.ToInstruction());
        return method;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SeparateStoresBypassSharedDispatcherAndPreserveFinalState(bool update)
    {
        using var module = new ModuleDefUser("edge-states");
        var method = Build(module, update);
        var before0 = Run(method, 0); var before1 = Run(method, 1);
        var changes = 0;
        for (var i = 0; i < 8; i++)
        {
            var changed = DispatcherPathPass.Rewrite(method);
            changes += changed;
            ControlFlowCompletionPass.TryComplete(method);
            if (changed == 0) break;
        }
        Assert.True(changes > 0, $"Changes: {changes}");
        Assert.DoesNotContain(method.Body.Instructions, i => i.OpCode.Code == Code.Switch);
        Assert.Equal(before0, Run(method, 0)); Assert.Equal(before1, Run(method, 1));
        Assert.Equal(StaticValue.FromInt32(update ? 2 : 1), Run(method, 0));
        Assert.Equal(StaticValue.FromInt32(update ? 1 : 0), Run(method, 1));
        Assert.Contains(method.Body.Instructions, i => i.OpCode.Code == Code.Call);
        Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);
    }

    [Fact]
    public void ConflictingValuesAtTheSameStoreAreNotInvented()
    {
        using var module = new ModuleDefUser("unknown-store");
        var method = Build(module, false);
        // Both paths now reach the first store, so its input is not constant.
        var stores = method.Body.Instructions.Where(i => i.IsStloc()).ToArray();
        foreach (var i in method.Body.Instructions)
            if (i.Operand == stores[1]) i.Operand = stores[0];
        Assert.Empty(LocalConstantPropagation.KnownStores(method));
        Assert.Equal(0, DispatcherPathPass.Rewrite(method));
    }

    [Fact]
    public void AddressTakenStatePreventsSpecialization()
    {
        using var module = new ModuleDefUser("escaped-store");
        var method = Build(module, false);
        method.Body.Instructions.Insert(0, OpCodes.Ldloca.ToInstruction(method.Body.Variables[0]));
        method.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
        Assert.Empty(LocalConstantPropagation.KnownStores(method));
        Assert.Equal(0, DispatcherPathPass.Rewrite(method));
    }

    private static StaticValue Run(MethodDef method, int flag)
    {
        var result = new StaticMachine().Execute(method, [StaticValue.FromInt32(flag)]);
        Assert.True(result.Status == StaticExecutionStatus.Completed, result.Diagnostic);
        return result.Value;
    }
    private static MethodDefUser Build(ModuleDef module, bool update)
    {
        var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Boolean))
        { Attributes = MethodAttributes.Static, Body = new CilBody() };
        module.GlobalType.Methods.Add(method);
        var guard = new MethodDefUser("Guard", MethodSig.CreateStatic(module.CorLibTypes.Boolean, module.CorLibTypes.Boolean))
        { Attributes = MethodAttributes.Static, Body = new CilBody() };
        module.GlobalType.Methods.Add(guard);
        Add(guard, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ret.ToInstruction());
        var local = new Local(module.CorLibTypes.Int32); method.Body.Variables.Add(local);
        var zero = OpCodes.Stloc.ToInstruction(local); var one = OpCodes.Stloc.ToInstruction(local);
        var alternate = OpCodes.Pop.ToInstruction(); var dispatch = OpCodes.Ldloc.ToInstruction(local);
        var result = OpCodes.Ldloc.ToInstruction(local);
        Add(method, Instruction.CreateLdcI4(0), OpCodes.Ldarg_0.ToInstruction(), OpCodes.Call.ToInstruction(guard),
            OpCodes.Brtrue.ToInstruction(zero), OpCodes.Br.ToInstruction(alternate),
            zero, OpCodes.Br.ToInstruction(dispatch), alternate, Instruction.CreateLdcI4(1),
            OpCodes.Ldarg_0.ToInstruction(), OpCodes.Call.ToInstruction(guard), OpCodes.Brfalse.ToInstruction(one),
            OpCodes.Br.ToInstruction(one), one, OpCodes.Br.ToInstruction(dispatch), dispatch);
        if (update) Add(method, Instruction.CreateLdcI4(1), OpCodes.Add.ToInstruction(), OpCodes.Stloc.ToInstruction(local), OpCodes.Ldloc.ToInstruction(local));
        Add(method, OpCodes.Switch.ToInstruction(new[] { result, result, result }), Instruction.CreateLdcI4(-1), OpCodes.Ret.ToInstruction(), result, OpCodes.Ret.ToInstruction());
        return method;
    }
    private static void Add(MethodDef method, params Instruction[] instructions)
    { foreach (var i in instructions) method.Body.Instructions.Add(i); }
}
