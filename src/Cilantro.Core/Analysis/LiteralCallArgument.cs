using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Finds a literal argument without crossing another control-flow entry.</summary>
internal static class LiteralCallArgument
{
    internal static Instruction? Int32(IList<Instruction> instructions, int call,
        ISet<Instruction> entries)
    {
        if (entries.Contains(instructions[call])) return null;
        var index = call - 1;
        while (index >= 0 && instructions[index].OpCode.Code == Code.Nop)
        {
            if (entries.Contains(instructions[index])) return null;
            index--;
        }
        // Entry at the literal itself is safe: every path still pushes the same argument.
        return index >= 0 && instructions[index].IsLdcI4() ? instructions[index] : null;
    }
}
