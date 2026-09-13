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
///
/// What counts as one pass is not a matter of taste, because the metadata writer makes exactly this
/// pass to work out a method's max stack, and a body it cannot make it through gets whatever max
/// stack the body arrived with. That is a fallback nobody asked for and nothing reports: it is right
/// only for as long as a rewrite does not need more stack than the protector's own body did. So the
/// pass modelled here is the writer's, instruction by instruction — heights carried forward, reset
/// to nothing after a jump or a return, compared wherever a branch has already named one — rather
/// than a reading of the standard's prose that agreed with it on three samples and not on a fourth.
/// </remarks>
public static class ForwardScan
{
    /// <summary>
    /// How many places in the method a single forward pass cannot name the stack at.
    /// </summary>
    /// <remarks>
    /// Counted rather than merely detected, because a protected method can arrive with these already
    /// and refusing to touch such a method gives up every rewrite the rest of it wants. The count
    /// only has to not grow: a rewrite may leave the ones it found and may remove them, and one
    /// that adds any is undone. Without asking this, a rewrite can be right about every instruction
    /// it changes and still be wrong about the method, by making a block's only way in a branch
    /// from below it.
    /// </remarks>
    public static int Unnameable(MethodDef method) => Scan(method).Count;

    /// <summary>
    /// The instructions a single forward pass arrives at without being able to say what the stack
    /// holds there, in the order the body lays them out, each named once.
    /// </summary>
    /// <remarks>
    /// What <see cref="Unnameable"/> counts, for a caller that means to do something about it. The
    /// count and the list disagree on purpose: one place can be arrived at wrongly by many edges,
    /// and a guard wants to know that a rewrite added edges while a repair wants to know which
    /// places to repair.
    /// </remarks>
    public static IReadOnlyList<Instruction> Unnamed(MethodDef method)
    {
        var found = new List<Instruction>();
        var seen = new HashSet<Instruction>();
        foreach (var at in Scan(method))
        {
            if (at is not null && seen.Add(at))
                found.Add(at);
        }

        return found;
    }

    /// <summary>
    /// Every arrival the pass cannot name, in order, with a null for a branch that has no target.
    /// </summary>
    private static List<Instruction?> Scan(MethodDef method)
    {
        ArgumentNullException.ThrowIfNull(method);
        var unnameable = new List<Instruction?>();
        if (!method.HasBody || method.Body.Instructions.Count == 0)
            return unnameable;

        var instructions = method.Body.Instructions;
        var heights = new Dictionary<Instruction, int>();

        // A handler is entered by the runtime rather than by a branch, and what it is entered
        // holding is fixed by the clause: nothing, or the exception for a catch or a filter.
        foreach (var handler in method.Body.ExceptionHandlers)
        {
            if (handler is null)
                continue;
            if (handler.TryStart is { } tried)
                heights[tried] = 0;
            if (handler.FilterStart is { } filter)
                heights[filter] = 1;
            if (handler.HandlerStart is { } handled)
                heights[handled] = handler.IsCatch || handler.IsFilter ? 1 : 0;
        }

        var stack = 0;
        var restart = false;
        foreach (var instruction in instructions)
        {
            if (instruction is null)
                continue;

            // After a jump or a return the pass has nothing to carry. What follows is named by an
            // earlier branch to it, or by nothing at all, and nothing at all means empty.
            if (restart)
            {
                heights.TryGetValue(instruction, out stack);
                restart = false;
            }

            stack = Name(instruction, stack);
            if (instruction.OpCode.Code == Code.Jmp)
            {
                if (stack != 0)
                    unnameable.Add(instruction);
            }
            else
            {
                instruction.CalculateStackUsage(out var pushes, out var pops);
                if (pops == -1)
                {
                    // The operation empties the stack rather than popping a known number.
                    stack = 0;
                }
                else
                {
                    stack -= pops;
                    if (stack < 0)
                    {
                        unnameable.Add(instruction);
                        stack = 0;
                    }

                    stack += pushes;
                }
            }

            switch (instruction.OpCode.FlowControl)
            {
                case FlowControl.Branch:
                    Name(instruction.Operand as Instruction, stack);
                    restart = true;
                    break;
                case FlowControl.Cond_Branch when instruction.Operand is IList<Instruction> targets:
                    foreach (var target in targets)
                        Name(target, stack);
                    break;
                case FlowControl.Cond_Branch:
                    Name(instruction.Operand as Instruction, stack);
                    break;
                case FlowControl.Call when instruction.OpCode.Code == Code.Jmp:
                case FlowControl.Return:
                case FlowControl.Throw:
                    restart = true;
                    break;
            }
        }

        return unnameable;

        int Name(Instruction? instruction, int arriving)
        {
            if (instruction is null)
            {
                unnameable.Add(null);
                return arriving;
            }

            if (!heights.TryGetValue(instruction, out var named))
            {
                heights[instruction] = arriving;
                return arriving;
            }

            if (named != arriving)
                unnameable.Add(instruction);
            return named;
        }
    }
}
