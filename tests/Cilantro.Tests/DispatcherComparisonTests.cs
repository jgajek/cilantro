using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Passes;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DispatcherComparisonTests
{
    [Theory]
    [InlineData(Code.Beq, false)]
    [InlineData(Code.Bne_Un, true)]
    [InlineData(Code.Bge, false)]
    [InlineData(Code.Bge_Un, true)]
    [InlineData(Code.Bgt, false)]
    [InlineData(Code.Bgt_Un, true)]
    [InlineData(Code.Ble, true)]
    [InlineData(Code.Ble_Un, false)]
    [InlineData(Code.Blt, true)]
    [InlineData(Code.Blt_Un, false)]
    public void ComputedStateThreadsSignedAndUnsignedComparisonsWithoutSwitch(Code code, bool taken)
    {
        using var module = new ModuleDefUser("comparison");
        var method = Method(module);
        var state = method.Body.Variables[0];
        var dispatch = OpCodes.Ldloc.ToInstruction(state);
        var target = Instruction.CreateLdcI4(77);
        var opcode = new[] { OpCodes.Beq, OpCodes.Bne_Un, OpCodes.Bge, OpCodes.Bge_Un, OpCodes.Bgt,
            OpCodes.Bgt_Un, OpCodes.Ble, OpCodes.Ble_Un, OpCodes.Blt, OpCodes.Blt_Un }.Single(o => o.Code == code);
        Add(method, Instruction.CreateLdcI4(-1), Instruction.CreateLdcI4(0), OpCodes.Add.ToInstruction(),
            OpCodes.Stloc.ToInstruction(state), OpCodes.Br.ToInstruction(dispatch), dispatch,
            Instruction.CreateLdcI4(1), opcode.ToInstruction(target), Instruction.CreateLdcI4(33), OpCodes.Ret.ToInstruction(),
            target, OpCodes.Ret.ToInstruction());
        var before = Run(method);
        Assert.Equal(StaticValue.FromInt32(taken ? 77 : 33), before);
        Assert.Equal(1, DispatcherPathPass.Rewrite(method));
        ControlFlowCompletionPass.TryComplete(method);
        Assert.Equal(before, Run(method));
        Assert.DoesNotContain(method.Body.Instructions, i => i.OpCode.FlowControl == FlowControl.Cond_Branch);
        Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);
    }

    [Theory]
    [InlineData(Code.Conv_I1, 255, -1)]
    [InlineData(Code.Conv_U1, -1, 255)]
    [InlineData(Code.Conv_I2, 65535, -1)]
    [InlineData(Code.Conv_U2, -1, 65535)]
    [InlineData(Code.Conv_I4, -1, -1)]
    [InlineData(Code.Conv_U4, -1, -1)]
    public void NarrowingConversionsSupplyCorrectLocalConstants(Code code, int input, int expected)
    {
        using var module = new ModuleDefUser("narrowing");
        var method = Method(module);
        var state = method.Body.Variables[0];
        var opcode = new[] { OpCodes.Conv_I1, OpCodes.Conv_U1, OpCodes.Conv_I2, OpCodes.Conv_U2,
            OpCodes.Conv_I4, OpCodes.Conv_U4 }.Single(o => o.Code == code);
        Add(method, Instruction.CreateLdcI4(input), opcode.ToInstruction(), OpCodes.Stloc.ToInstruction(state),
            OpCodes.Ldloc.ToInstruction(state), OpCodes.Ret.ToInstruction());
        var before = Run(method);
        Assert.Equal(StaticValue.FromInt32(expected), before);
        Assert.Equal(1, LocalConstantPropagation.Fold(method));
        Assert.Equal(before, Run(method));
        Assert.Equal(expected, method.Body.Instructions[3].GetLdcI4Value());
    }

    [Theory]
    [InlineData(Code.Ceq, -1, 1, 0)]
    [InlineData(Code.Clt, -1, 1, 1)]
    [InlineData(Code.Clt_Un, -1, 1, 0)]
    [InlineData(Code.Cgt, -1, 1, 0)]
    [InlineData(Code.Cgt_Un, -1, 1, 1)]
    [InlineData(Code.Div, -7, 3, -2)]
    [InlineData(Code.Rem, -7, 3, -1)]
    [InlineData(Code.Div_Un, -1, 2, int.MaxValue)]
    [InlineData(Code.Rem_Un, -1, 2, 1)]
    [InlineData(Code.Div, 1, 0, null)]
    [InlineData(Code.Rem_Un, 1, 0, null)]
    [InlineData(Code.Div, int.MinValue, -1, null)]
    [InlineData(Code.Rem, int.MinValue, -1, null)]
    public void IntegerOperationsSupplyOnlyNonthrowingConstants(Code code, int left, int right, int? expected)
    {
        using var module = new ModuleDefUser("arithmetic");
        var method = Method(module);
        var opcode = new[] { OpCodes.Ceq, OpCodes.Clt, OpCodes.Clt_Un, OpCodes.Cgt, OpCodes.Cgt_Un,
            OpCodes.Div, OpCodes.Div_Un, OpCodes.Rem, OpCodes.Rem_Un }.Single(o => o.Code == code);
        Add(method, Instruction.CreateLdcI4(left), Instruction.CreateLdcI4(right), opcode.ToInstruction(),
            OpCodes.Stloc.ToInstruction(method.Body.Variables[0]), OpCodes.Ldloc.ToInstruction(method.Body.Variables[0]), OpCodes.Ret.ToInstruction());
        Assert.Equal(expected.HasValue ? 1 : 0, LocalConstantPropagation.Fold(method));
        if (expected.HasValue) Assert.Equal(StaticValue.FromInt32(expected.Value), Run(method));
        else Assert.True(method.Body.Instructions[4].IsLdloc());
        Assert.Equal(opcode, method.Body.Instructions[2].OpCode);
    }

    private static MethodDefUser Method(ModuleDef module)
    {
        var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32))
        { Attributes = MethodAttributes.Static, Body = new CilBody() };
        method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
        module.GlobalType.Methods.Add(method);
        return method;
    }
    private static StaticValue Run(MethodDef method)
    {
        var result = new StaticMachine().Execute(method, []);
        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        return result.Value;
    }
    private static void Add(MethodDef method, params Instruction[] instructions)
    { foreach (var instruction in instructions) method.Body.Instructions.Add(instruction); }
}
