using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>
/// Takes a value that one block hands to another on the evaluation stack and puts it in a local.
/// </summary>
/// <remarks>
/// Reactor's dispatchers hand their state over on the stack: the block that decides where to go next
/// pushes a number and branches, and the switch at the head of the dispatcher pops it. That is legal
/// while the dispatcher is also fallen into from above, because a forward pass through the
/// instructions learns the depth there and every branch from below agrees with it. Folding the
/// entry edge — which is most of what this tool does to a dispatcher — takes the fall-in away, and
/// the same instructions become a block whose depth nothing above it names. <see cref="ForwardScan"/>
/// says where; this says what to do about it.
///
/// The repair is the one a compiler would have made in the first place: the value goes into a local,
/// the branch carries nothing, and the head reads the local back. Every edge in then arrives holding
/// nothing, which a forward pass names without being told, and the head reads like a switch on a
/// variable rather than a switch on whatever the last block left lying around.
/// </remarks>
public static class StackHandoff
{
    /// <summary>
    /// Puts the one value arriving at <paramref name="head"/> into a local, or answers false if this
    /// is not a handover it can name.
    /// </summary>
    /// <remarks>
    /// The type has to come from somewhere, and the stack does not carry one that survives being
    /// asked about after the fact. It comes from the instruction that takes the value: a switch
    /// takes an int32 and a store takes whatever the local holds. Anything else is declined rather
    /// than guessed at, because a local of the wrong type is worse than the depth it would fix.
    /// </remarks>
    public static bool Repair(MethodDef method, Instruction head)
    {
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(head);
        if (!method.HasBody)
            return false;

        var body = method.Body;
        var instructions = body.Instructions;
        var at = instructions.IndexOf(head);
        if (at <= 0)
            return false;

        // A handler is entered by the runtime holding what the clause says, so its first
        // instruction is not ours to put anything in front of. Nor is a boundary: everything this
        // repair inserts goes where the edge already was, which keeps each piece in the clause it
        // belongs to and keeps a branch out of a protected region from being invented, and that
        // argument only holds while the head is not itself where a clause begins or ends.
        var boundaries = Boundaries(body);
        if (boundaries.Contains(head))
            return false;

        var analysis = EvaluationStackAnalyzer.Analyze(method);
        if (!analysis.Valid ||
            !analysis.Depths.TryGetValue(head, out var depth) ||
            depth != 1)
        {
            return false;
        }

        if (Handed(head, method) is not { } handed)
            return false;

        // Where the value comes from, gathered before anything moves.
        var branches = instructions.Where(instruction => Targets(instruction, head)).ToArray();
        var before = instructions[at - 1];
        var falls = Falls(before.OpCode) && analysis.Depths.ContainsKey(before);
        if (branches.Length == 0 && !falls)
            return false;
        if (branches.Any(branch => boundaries.Contains(branch) || instructions.IndexOf(branch) < 0))
            return false;

        // A conditional branch is rewritten by putting instructions after it, so it has to have an
        // after: a body ending in one is not one to repair.
        if (branches.Any(branch =>
                branch.OpCode.FlowControl == FlowControl.Cond_Branch &&
                ReferenceEquals(branch, instructions[^1])))
        {
            return false;
        }

        var local = new Local(handed);
        body.Variables.Add(local);
        body.InitLocals = true;

        var reload = OpCodes.Ldloc.ToInstruction(local);
        instructions.Insert(at, reload);

        // The value the block was handed comes off the stack before the branch that hands it over
        // and goes back on at the head, so every edge in arrives holding nothing — which is what a
        // forward pass names without having to be told.
        if (falls)
            instructions.Insert(instructions.IndexOf(reload), OpCodes.Stloc.ToInstruction(local));

        foreach (var branch in branches)
        {
            // An edge no path takes hands nothing over, so it is pointed at the reload and left
            // alone. Storing on it would only be a store a forward pass reads with an empty stack.
            if (!analysis.Depths.ContainsKey(branch))
            {
                Retarget(branch, head, reload);
                continue;
            }

            if (branch.OpCode.FlowControl == FlowControl.Branch)
            {
                // An unconditional branch has nothing above the value on the stack, so the store
                // goes in front of it and reads as part of the block it ends.
                Retarget(branch, head, reload);
                instructions.Insert(instructions.IndexOf(branch), OpCodes.Stloc.ToInstruction(local));
                continue;
            }

            // A conditional branch has its condition above the value and cannot reach under it, so
            // the store goes on the far side of the branch, in a block of its own that the branch
            // now goes to and the path that does not take it jumps over. All of it lands between
            // the branch and what followed it, which is what keeps it inside whatever protected
            // region the edge was already crossing — nowhere new to branch out of.
            var index = instructions.IndexOf(branch);
            var spill = OpCodes.Stloc.ToInstruction(local);
            instructions.Insert(index + 1, OpCodes.Br.ToInstruction(instructions[index + 1]));
            instructions.Insert(index + 2, spill);
            instructions.Insert(index + 3, OpCodes.Br.ToInstruction(reload));
            Retarget(branch, head, spill);
        }

        return true;
    }

    private static HashSet<Instruction> Boundaries(CilBody body)
    {
        var boundaries = new HashSet<Instruction>();
        foreach (var handler in body.ExceptionHandlers)
        {
            if (handler is null)
                continue;
            Pin(handler.TryStart);
            Pin(handler.TryEnd);
            Pin(handler.HandlerStart);
            Pin(handler.HandlerEnd);
            Pin(handler.FilterStart);
        }

        return boundaries;

        void Pin(Instruction? boundary)
        {
            if (boundary is not null)
                boundaries.Add(boundary);
        }
    }

    /// <summary>What the instruction that takes the value says the value is.</summary>
    private static TypeSig? Handed(Instruction head, MethodDef method) => head.OpCode.Code switch
    {
        Code.Switch => method.Module?.CorLibTypes.Int32,
        Code.Stloc or Code.Stloc_S or Code.Stloc_0 or Code.Stloc_1 or Code.Stloc_2 or Code.Stloc_3
            when head.GetLocal(method.Body.Variables) is { } local => local.Type,
        _ => null
    };

    private static bool Targets(Instruction instruction, Instruction head) =>
        ReferenceEquals(instruction.Operand, head) ||
        (instruction.Operand is IList<Instruction> many && many.Contains(head));

    private static void Retarget(Instruction branch, Instruction head, Instruction toward)
    {
        if (ReferenceEquals(branch.Operand, head))
        {
            branch.Operand = toward;
            return;
        }

        if (branch.Operand is not IList<Instruction> many)
            return;
        for (var index = 0; index < many.Count; index++)
        {
            if (ReferenceEquals(many[index], head))
                many[index] = toward;
        }
    }

    private static bool Falls(OpCode opcode) => opcode.FlowControl is not (
        FlowControl.Branch or FlowControl.Return or FlowControl.Throw);
}
