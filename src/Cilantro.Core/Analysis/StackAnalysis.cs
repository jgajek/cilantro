using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

public sealed record StackAnalysisResult(
    bool Valid,
    int MaximumDepth,
    IReadOnlyList<string> Diagnostics);

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
            var outgoing = incoming - pops + pushes;
            maximum = Math.Max(maximum, outgoing);
            foreach (var successor in Successors(instructions, indices, instruction))
                work.Enqueue((successor, outgoing));
        }

        if (steps >= budget)
            diagnostics.Add($"Stack analysis exceeded its {budget} instruction budget.");
        return new StackAnalysisResult(diagnostics.Count == 0, maximum, diagnostics);
    }

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
            StackBehaviour.Popref_popi_popr8 or StackBehaviour.Popref_popi_popref => 3,
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
