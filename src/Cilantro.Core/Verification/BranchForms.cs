using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Verification;

/// <summary>
/// Makes sure every branch still reaches its target in the form it is written in.
/// </summary>
/// <remarks>
/// A short branch carries its displacement in a signed byte, so it reaches 127 bytes forward and 128
/// back and no further. That is a property of the distance rather than of the branch, and a pass that
/// puts instructions between a branch and its target changes the distance without touching the
/// branch. Where the target goes out of reach the metadata writer says so and emits the truncated
/// displacement anyway: the file loads, and the jump goes somewhere else. Three methods of one
/// payload left this way, the sixteen bytes of temporaries that a restored proxy call needed sitting
/// between a `br.s` and the dispatcher head behind it.
///
/// Nothing in a run can be asked to keep track of this as it goes, because a distance depends on
/// every edit between two points and not on the edit being made. So it is settled once, on the way
/// out, and only for the bodies that need it: the long forms always reach, and going back to short
/// where the distance now allows it keeps the encoding of every body that was already correct
/// exactly as it was.
/// </remarks>
public static class BranchForms
{
    /// <summary>
    /// Re-forms the branches of every method whose short forms no longer reach, and says how many
    /// methods needed it.
    /// </summary>
    public static int Reach(ModuleDef module)
    {
        ArgumentNullException.ThrowIfNull(module);
        var reformed = 0;
        foreach (var method in module.GetTypes().SelectMany(type => type.Methods))
        {
            if (method.Body is not { } body || body.Instructions.Count == 0)
                continue;

            body.UpdateInstructionOffsets();
            if (!body.Instructions.Any(OutOfReach))
                continue;

            body.SimplifyBranches();
            body.OptimizeBranches();
            body.UpdateInstructionOffsets();
            reformed++;
        }

        return reformed;
    }

    private static bool OutOfReach(Instruction instruction)
    {
        if (instruction.OpCode.OperandType != OperandType.ShortInlineBrTarget)
            return false;
        // A branch with no target at all is not a distance problem and re-forming would not fix it.
        // The writer reports that one, and what it reports is now recorded.
        if (instruction.Operand is not Instruction target)
            return false;

        var displacement = (long)target.Offset - (instruction.Offset + instruction.GetSize());
        return displacement is < sbyte.MinValue or > sbyte.MaxValue;
    }
}
