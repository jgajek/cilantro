using Cilantro.Core.Analysis;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class LiteralCallArgumentTests
{
    [Theory]
    [InlineData(-1, true)]
    [InlineData(0, true)]
    [InlineData(1, false)]
    [InlineData(2, false)]
    [InlineData(3, false)]
    public void RefusesBranchesOrExceptionBoundariesInsideTheArgumentSequence(int entry, bool expected)
    {
        Instruction[] il = [OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Nop.ToInstruction(),
            OpCodes.Nop.ToInstruction(), new Instruction(OpCodes.Call)];
        var entries = new HashSet<Instruction>();
        if (entry >= 0) entries.Add(il[entry]);
        Assert.Equal(expected, LiteralCallArgument.Int32(il, 3, entries) == il[0]);
    }

    [Fact]
    public void DoesNotSkipAnInstructionThatCanChangeTheArgument()
    {
        Instruction[] il = [OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Neg.ToInstruction(),
            new Instruction(OpCodes.Call)];
        Assert.Null(LiteralCallArgument.Int32(il, 2, new HashSet<Instruction>()));
    }
}
