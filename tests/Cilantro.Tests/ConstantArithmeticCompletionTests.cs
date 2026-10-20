using Cilantro.Core.Interpretation;
using Cilantro.Core.Passes;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ConstantArithmeticCompletionTests
{
    [Theory]
    [InlineData(Code.Conv_I1, 255, 0, -1)]
    [InlineData(Code.Conv_U1, -1, 0, 255)]
    [InlineData(Code.Conv_I2, 65535, 0, -1)]
    [InlineData(Code.Conv_U2, -1, 0, 65535)]
    [InlineData(Code.Div, -23, 4, -5)]
    [InlineData(Code.Div_Un, -1, 2, int.MaxValue)]
    [InlineData(Code.Rem, -23, 4, -3)]
    [InlineData(Code.Rem_Un, -1, 2, 1)]
    [InlineData(Code.Ceq, 17, 17, 1)]
    [InlineData(Code.Clt, -1, 1, 1)]
    [InlineData(Code.Clt_Un, -1, 1, 0)]
    [InlineData(Code.Cgt, -1, 1, 0)]
    [InlineData(Code.Cgt_Un, -1, 1, 1)]
    public void ConstantOperationsRetainTheirInterpretedResults(Code operation, int left, int right, int expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var method = new MethodDefUser("Calculate", MethodSig.CreateStatic(module.CorLibTypes.Int32), MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
            module.GlobalType.Methods.Add(method);
            method.Body.Instructions.Add(OpCodes.Ldc_I4.ToInstruction(left));
            var opcode = OpCodes.OneByteOpCodes.Concat(OpCodes.TwoByteOpCodes).Single(code => code?.Code == operation)!;
            if (operation is not (Code.Conv_I1 or Code.Conv_U1 or Code.Conv_I2 or Code.Conv_U2))
                method.Body.Instructions.Add(OpCodes.Ldc_I4.ToInstruction(right));
            method.Body.Instructions.Add(opcode.ToInstruction());
            method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var method = context.Module.GlobalType.Methods.Single(method => method.Name == "Calculate");
        Assert.Equal(expected, new StaticMachine().Execute(method).Value.AsInt32());
        Assert.NotNull(ControlFlowCompletionPass.TryComplete(method));
        Assert.DoesNotContain(method.Body.Instructions, instruction => instruction.OpCode.Code == operation);
        Assert.Equal(expected, new StaticMachine().Execute(method).Value.AsInt32());
    }

    [Theory]
    [InlineData(Code.Div, 1, 0)]
    [InlineData(Code.Rem, 1, 0)]
    [InlineData(Code.Div_Un, 1, 0)]
    [InlineData(Code.Rem_Un, 1, 0)]
    [InlineData(Code.Div, int.MinValue, -1)]
    [InlineData(Code.Rem, int.MinValue, -1)]
    public void PotentiallyThrowingOperationsAreRetained(Code operation, int left, int right)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var method = new MethodDefUser("Calculate", MethodSig.CreateStatic(module.CorLibTypes.Int32), MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
            module.GlobalType.Methods.Add(method);
            method.Body.Instructions.Add(OpCodes.Ldc_I4.ToInstruction(left));
            method.Body.Instructions.Add(OpCodes.Ldc_I4.ToInstruction(right));
            method.Body.Instructions.Add(OpCodes.OneByteOpCodes.Single(code => code.Code == operation).ToInstruction());
            method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var method = context.Module.GlobalType.Methods.Single(method => method.Name == "Calculate");
        ControlFlowCompletionPass.TryComplete(method);
        Assert.Contains(method.Body.Instructions, instruction => instruction.OpCode.Code == operation);
    }
}
