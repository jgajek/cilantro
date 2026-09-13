using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

public sealed record StackAnalysisResult(
    bool Valid,
    int MaximumDepth,
    IReadOnlyList<string> Diagnostics)
{
    /// <summary>
    /// What the stack holds on arrival at each instruction the walk reached.
    /// </summary>
    /// <remarks>
    /// Carried out of the walk rather than recomputed by callers that need to ask about one place
    /// in a method: whether a block only a backward branch reaches is entered holding anything is
    /// a question about a depth, and ECMA-335 III.1.7.5 makes the answer the difference between IL
    /// a verifier accepts and IL it does not.
    /// </remarks>
    public IReadOnlyDictionary<Instruction, int> Depths { get; init; } =
        new Dictionary<Instruction, int>();
}

public static class EvaluationStackAnalyzer
{
    public static StackAnalysisResult Analyze(MethodDef method, int budget = 1_000_000)
    {
        if (!method.HasBody || method.Body.Instructions.Count == 0)
            return new StackAnalysisResult(true, 0, []);
        var instructions = method.Body.Instructions;
        var indices = instructions.Select((instruction, index) => (instruction, index))
            .ToDictionary(item => item.instruction, item => item.index);
        var depths = new Dictionary<Instruction, int>();
        var work = new Queue<(Instruction Instruction, int Depth)>();
        work.Enqueue((instructions[0], 0));
        foreach (var handler in method.Body.ExceptionHandlers)
        {
            if (handler.HandlerStart is not null)
            {
                var depth = handler.HandlerType == ExceptionHandlerType.Catch ? 1 : 0;
                work.Enqueue((handler.HandlerStart, depth));
            }
            if (handler.FilterStart is not null)
                work.Enqueue((handler.FilterStart, 1));
        }

        var diagnostics = new List<string>();
        var maximum = 0;
        var steps = 0;
        while (work.Count > 0 && steps++ < budget)
        {
            var (instruction, incoming) = work.Dequeue();
            if (depths.TryGetValue(instruction, out var existing))
            {
                if (existing != incoming)
                    diagnostics.Add($"IL_{instruction.Offset:X4}: stack merge {existing} versus {incoming}.");
                continue;
            }
            depths[instruction] = incoming;
            var (pops, pushes) = GetStackDelta(method, instruction);
            if (incoming < pops)
            {
                diagnostics.Add($"IL_{instruction.Offset:X4}: stack underflow.");
                continue;
            }

            // Leaving a protected region empties the stack rather than taking a fixed number of
            // values off it (ECMA-335 III.3.55), so what the target is entered with is nothing,
            // whatever stood here. Carrying the depth across instead reports every ordinary
            // try/catch whose guarded expression was mid-evaluation as a method whose paths
            // disagree.
            var outgoing = Empties(instruction.OpCode) ? 0 : incoming - pops + pushes;
            maximum = Math.Max(maximum, outgoing);
            foreach (var successor in Successors(instructions, indices, instruction))
                work.Enqueue((successor, outgoing));
        }

        if (steps >= budget)
            diagnostics.Add($"Stack analysis exceeded its {budget} instruction budget.");
        return new StackAnalysisResult(diagnostics.Count == 0, maximum, diagnostics)
        {
            Depths = depths
        };
    }

    /// <summary>Whether the instruction empties the evaluation stack instead of drawing on it.</summary>
    private static bool Empties(OpCode opcode) =>
        opcode.StackBehaviourPop == StackBehaviour.PopAll;

    private static (int Pops, int Pushes) GetStackDelta(MethodDef owner, Instruction instruction)
    {
        if (instruction.OpCode.FlowControl == FlowControl.Call &&
            instruction.Operand is IMethod method)
        {
            var signature = method.MethodSig;
            var pops = signature?.Params.Count ?? 0;
            if (signature?.HasThis == true && instruction.OpCode != OpCodes.Newobj)
                pops++;
            var pushes = instruction.OpCode == OpCodes.Newobj ||
                signature?.RetType.ElementType != ElementType.Void ? 1 : 0;
            return (pops, pushes);
        }

        if (instruction.OpCode == OpCodes.Ret)
            return (owner.ReturnType.ElementType == ElementType.Void ? 0 : 1, 0);
        return (
            FixedPop(instruction.OpCode.StackBehaviourPop),
            FixedPush(instruction.OpCode.StackBehaviourPush));
    }

    private static int FixedPop(StackBehaviour behavior) => behavior switch
    {
        StackBehaviour.Pop0 => 0,
        StackBehaviour.Pop1 or StackBehaviour.Popi or StackBehaviour.Popref => 1,
        StackBehaviour.Pop1_pop1 or StackBehaviour.Popi_pop1 or
            StackBehaviour.Popi_popi or StackBehaviour.Popi_popi8 or
            StackBehaviour.Popi_popr4 or StackBehaviour.Popi_popr8 or
            StackBehaviour.Popref_pop1 or StackBehaviour.Popref_popi => 2,
        StackBehaviour.Popi_popi_popi or StackBehaviour.Popref_popi_popi or
            StackBehaviour.Popref_popi_popi8 or StackBehaviour.Popref_popi_popr4 or
            StackBehaviour.Popref_popi_popr8 or StackBehaviour.Popref_popi_popref or
            // stelem, which was reaching the fall-through below and so was taken to leave the
            // array, the index and the value all where they were. Every store into an array in
            // every method thereby raised the depth by three, and the loop around it read as a
            // path arriving at its own head three values deeper than the path into it.
            StackBehaviour.Popref_popi_pop1 => 3,
        // Nothing else draws a fixed number of values off the stack: what is left is the two
        // behaviours that depend on something other than the opcode, both handled above — a call's
        // signature, and emptying the stack on the way out of a protected region.
        _ => 0
    };

    private static int FixedPush(StackBehaviour behavior) => behavior switch
    {
        StackBehaviour.Push0 => 0,
        StackBehaviour.Push1 or StackBehaviour.Pushi or StackBehaviour.Pushi8 or
            StackBehaviour.Pushr4 or StackBehaviour.Pushr8 or StackBehaviour.Pushref => 1,
        StackBehaviour.Push1_push1 => 2,
        _ => 0
    };

    private static IEnumerable<Instruction> Successors(
        IList<Instruction> instructions,
        Dictionary<Instruction, int> indices,
        Instruction instruction)
    {
        var index = indices[instruction];
        if (instruction.OpCode.FlowControl == FlowControl.Branch)
        {
            if (instruction.Operand is Instruction target) yield return target;
            yield break;
        }
        if (instruction.OpCode.FlowControl == FlowControl.Cond_Branch)
        {
            if (instruction.Operand is Instruction target) yield return target;
            if (instruction.Operand is IList<Instruction> targets)
                foreach (var switchTarget in targets) yield return switchTarget;
        }
        if (instruction.OpCode.FlowControl is FlowControl.Return or FlowControl.Throw)
            yield break;
        if (index + 1 < instructions.Count)
            yield return instructions[index + 1];
    }
}
