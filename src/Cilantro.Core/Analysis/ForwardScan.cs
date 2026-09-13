using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>
/// The one thing a verifier asks of a method that a stack analysis does not: that a single forward
/// pass be enough to know what the stack holds everywhere.
/// </summary>
/// <remarks>
/// ECMA-335 III.1.7.5 asks for more than agreement between paths. It asks that the agreed depth be
/// reachable in one pass through the instructions in order, which rules out a block whose only way
/// in is a branch from further down: the pass arrives at the block before it has seen anything that
/// says what the stack is, so the block must be entered holding nothing. A block entered holding
/// something is what ILVerify reports as `BackwardBranch`, and it is invisible to
/// <see cref="EvaluationStackAnalyzer"/>, which follows edges rather than layout and so finds every
/// path in perfect agreement about a depth no verifier will accept.
///
/// Reactor writes this on purpose. A dispatcher whose state arrives on the stack rather than in a
/// local is entered from below with the state still pushed, and the switch pops it on the way in.
/// That is legal as the protector leaves it, because the dispatcher is also fallen into from above,
/// which is where the forward pass learns the depth. Take the fall-in away — which is what
/// redirecting the entry edge does — and the same block becomes unscannable without a single
/// instruction in it having changed.
/// </remarks>
public static class ForwardScan
{
    /// <summary>
    /// How many blocks in the method a single forward pass cannot name the stack at.
    /// </summary>
    /// <remarks>
    /// Counted rather than merely detected, because a protected method arrives with these already
    /// and refusing to touch such a method gives up every rewrite the rest of it wants. The count
    /// only has to not grow: a rewrite may leave the ones it found and may remove them, and one
    /// that adds any is undone. Without asking this, a rewrite can be right about every instruction
    /// it changes and still be wrong about the method, by making a block's only way in a branch
    /// from below it.
    /// </remarks>
    public static int Unnameable(MethodDef method)
    {
        ArgumentNullException.ThrowIfNull(method);
        if (!method.HasBody || method.Body.Instructions.Count == 0)
            return 0;
        var instructions = method.Body.Instructions;
        var depths = EvaluationStackAnalyzer.Analyze(method).Depths;
        var order = new Dictionary<Instruction, int>();
        for (var at = 0; at < instructions.Count; at++)
            order[instructions[at]] = at;

        // Where each instruction is branched to from, by position, so that "only from below" can be
        // asked of it.
        var arrivals = new Dictionary<Instruction, List<int>>();
        foreach (var instruction in instructions)
        {
            var from = order[instruction];
            if (instruction.Operand is Instruction one)
                Note(one, from);
            else if (instruction.Operand is IList<Instruction> many)
                foreach (var target in many)
                    Note(target, from);
        }

        // Exception boundaries are left out: a handler is entered by the runtime rather than by a
        // branch, and what it is entered holding is fixed by the clause.
        var boundaries = new HashSet<Instruction>();
        foreach (var handler in method.Body.ExceptionHandlers)
        {
            Pin(handler.TryStart);
            Pin(handler.TryEnd);
            Pin(handler.HandlerStart);
            Pin(handler.HandlerEnd);
            Pin(handler.FilterStart);
        }

        var unnameable = 0;
        for (var at = 1; at < instructions.Count; at++)
        {
            var instruction = instructions[at];
            if (boundaries.Contains(instruction))
                continue;
            if (Falls(instructions[at - 1].OpCode))
                continue;
            if (!arrivals.TryGetValue(instruction, out var from) || from.Count == 0)
                continue;
            if (from.Any(one => one < at))
                continue;
            if (depths.TryGetValue(instruction, out var depth) && depth != 0)
                unnameable++;
        }

        return unnameable;

        void Note(Instruction target, int from)
        {
            if (!arrivals.TryGetValue(target, out var list))
                arrivals[target] = list = [];
            list.Add(from);
        }

        void Pin(Instruction? boundary)
        {
            if (boundary is not null)
                boundaries.Add(boundary);
        }
    }

    /// <summary>Whether the path can run from an instruction into the one laid out after it.</summary>
    private static bool Falls(OpCode opcode) => opcode.FlowControl is not (
        FlowControl.Branch or FlowControl.Return or FlowControl.Throw);
}
