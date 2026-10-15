using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Tracks immediate stack producers across normal control-flow joins.
/// Local loads remain producers; this does not infer local values, types or alias safety.</summary>
internal static class EvaluationStackOrigins
{
    internal sealed record Result(bool Valid, IReadOnlyDictionary<Instruction, IReadOnlySet<Instruction?>[]> Inputs);

    internal static Result Analyze(MethodDef method, int budget = 500_000)
    {
        var inputs = new Dictionary<Instruction, IReadOnlySet<Instruction?>[]>();
        Result Failed() => new(false, new Dictionary<Instruction, IReadOnlySet<Instruction?>[]>());
        if (!method.HasBody || method.Body.Instructions.Count == 0) return new(true, inputs);
        var graph = ControlFlowGraph.Build(method);
        var states = new Dictionary<BasicBlock, List<HashSet<Instruction?>>>();
        var pending = new Queue<BasicBlock>();
        var queued = new HashSet<BasicBlock>();
        var invalid = false;
        void Merge(BasicBlock block, List<HashSet<Instruction?>> incoming)
        {
            var changed = false;
            if (!states.TryGetValue(block, out var existing))
            { states[block] = incoming.Select(s => new HashSet<Instruction?>(s)).ToList(); changed = true; }
            else if (existing.Count != incoming.Count) { invalid = true; return; }
            else for (var n = 0; n < existing.Count; n++)
            {
                var old = existing[n].Count;
                existing[n].UnionWith(incoming[n]);
                if (existing[n].Count > 128) { invalid = true; return; }
                changed |= old != existing[n].Count;
            }
            if (changed && queued.Add(block)) pending.Enqueue(block);
        }
        Merge(graph.Entry, []);
        foreach (var handler in method.Body.ExceptionHandlers)
        {
            // Runtime-supplied exception objects have no IL producer. In particular,
            // they must not inherit the interrupted try block's evaluation stack.
            if (handler.HandlerStart is { } start)
                Merge(graph.BlockOf(start), handler.IsCatch || handler.IsFilter ? [new() { null }] : []);
            if (handler.FilterStart is { } filter) Merge(graph.BlockOf(filter), [new() { null }]);
        }
        var steps = 0;
        while (!invalid && pending.TryDequeue(out var block))
        {
            queued.Remove(block);
            var stack = states[block].Select(s => new HashSet<Instruction?>(s)).ToList();
            foreach (var instruction in block.Instructions)
            {
                if (++steps > budget) return Failed();
                int pops, pushes;
                if (instruction.OpCode.Code == Code.Ret)
                { pops = method.ReturnType.ElementType == ElementType.Void ? 0 : 1; pushes = 0; }
                else if (instruction.OpCode.StackBehaviourPop == StackBehaviour.PopAll)
                { pops = stack.Count; pushes = 0; }
                else instruction.CalculateStackUsage(out pushes, out pops);
                if (pops < 0 || pops > stack.Count || pushes < 0) return Failed();
                var consumed = stack.Skip(stack.Count - pops).Select(s => new HashSet<Instruction?>(s)).ToArray();
                inputs[instruction] = consumed;
                stack.RemoveRange(stack.Count - pops, pops);
                for (var n = 0; n < pushes; n++)
                    stack.Add(instruction.OpCode.Code == Code.Dup ? new(consumed[0]) : new() { instruction });
                if (stack.Count > 256) return Failed();
            }
            foreach (var edge in block.Successors.Where(e => e.Kind != ControlFlowEdgeKind.Exception)) Merge(edge.Target, stack);
        }
        return invalid ? Failed() : new(true, inputs);
    }
}
