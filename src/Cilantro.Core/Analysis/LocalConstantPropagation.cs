using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Must-constant analysis: a local is known only when every incoming path agrees.</summary>
internal static class LocalConstantPropagation
{
    internal static int Fold(MethodDef method)
    {
        var body = method.Body;
        // Finally/exception transfers require an exceptional data-flow model. Do not infer
        // normal-flow constants across those transfers, or across an address escape.
        if (body.ExceptionHandlers.Count != 0 || body.Variables.Count == 0)
            return 0;
        var eligible = body.Variables.Where(v => v.Type.ElementType is ElementType.I4 or ElementType.U4).ToHashSet();
        foreach (var i in body.Instructions)
            if (i.OpCode.Code is Code.Ldloca or Code.Ldloca_S && i.GetLocal(body.Variables) is { } escaped)
                eligible.Remove(escaped);
        if (eligible.Count == 0) return 0;
        var graph = ControlFlowGraph.Build(method);
        var inputs = new Dictionary<BasicBlock, Dictionary<Local, int>>();
        inputs[graph.Entry] = body.InitLocals ? eligible.ToDictionary(v => v, _ => 0) : [];
        var queue = new Queue<BasicBlock>();
        var queued = new HashSet<BasicBlock>();
        queue.Enqueue(graph.Entry);
        queued.Add(graph.Entry);
        // Exhaustion means no rewrite, never a partially converged proof.
        var budget = Math.Min(1_000_000L, Math.Max(4096L, body.Instructions.Count * 32L));
        while (queue.TryDequeue(out var block))
        {
            queued.Remove(block);
            budget -= block.Instructions.Count;
            if (budget < 0) return 0;
            var output = Transfer(block, inputs[block], null);
            foreach (var edge in block.Successors)
            {
                var changed = false;
                if (!inputs.TryGetValue(edge.Target, out var target))
                {
                    inputs[edge.Target] = new(output);
                    changed = true;
                }
                else
                {
                    foreach (var local in target.Keys.ToArray())
                        if (!output.TryGetValue(local, out var value) || value != target[local])
                        {
                            target.Remove(local);
                            changed = true;
                        }
                }
                if (changed && queued.Add(edge.Target)) queue.Enqueue(edge.Target);
            }
        }
        var replacements = new Dictionary<Instruction, int>();
        foreach (var (block, state) in inputs) Transfer(block, state, replacements);
        foreach (var (instruction, value) in replacements)
        {
            instruction.OpCode = OpCodes.Ldc_I4;
            instruction.Operand = value;
        }
        return replacements.Count;

        Dictionary<Local, int> Transfer(BasicBlock block, Dictionary<Local, int> input,
            Dictionary<Instruction, int>? replacements)
        {
            var state = new Dictionary<Local, int>(input);
            // Values carried on the evaluation stack across blocks remain unknown.
            var stack = new Stack<int?>();
            int? Pop() => stack.TryPop(out var value) ? value : null;
            foreach (var instruction in block.Instructions)
            {
                if (instruction.IsLdcI4()) { stack.Push(instruction.GetLdcI4Value()); continue; }
                if (instruction.IsLdloc())
                {
                    var local = instruction.GetLocal(body.Variables);
                    if (local is not null && state.TryGetValue(local, out var value))
                    {
                        stack.Push(value);
                        if (replacements is not null) replacements[instruction] = value;
                    }
                    else stack.Push(null);
                    continue;
                }
                if (instruction.IsStloc())
                {
                    var value = Pop();
                    var local = instruction.GetLocal(body.Variables);
                    if (local is not null && eligible.Contains(local))
                    {
                        if (value is { } known) state[local] = known;
                        else state.Remove(local);
                    }
                    continue;
                }
                switch (instruction.OpCode.Code)
                {
                    case Code.Nop: break;
                    case Code.Dup: { var value = Pop(); stack.Push(value); stack.Push(value); break; }
                    case Code.Pop: Pop(); break;
                    case Code.Neg: { var value = Pop(); stack.Push(value is { } n ? unchecked(-n) : null); break; }
                    case Code.Not: { var value = Pop(); stack.Push(value is { } n ? ~n : null); break; }
                    case Code.Add: case Code.Sub: case Code.Mul: case Code.Xor:
                    case Code.And: case Code.Or: case Code.Shl: case Code.Shr: case Code.Shr_Un:
                    {
                        var right = Pop(); var left = Pop();
                        stack.Push(left is { } a && right is { } b ? Evaluate(instruction.OpCode.Code, a, b) : null);
                        break;
                    }
                    default: stack.Clear(); break;
                }
            }
            return state;
        }
    }

    private static int Evaluate(Code code, int a, int b) => code switch
    {
        Code.Add => unchecked(a + b), Code.Sub => unchecked(a - b), Code.Mul => unchecked(a * b),
        Code.Xor => a ^ b, Code.And => a & b, Code.Or => a | b,
        Code.Shl => a << b, Code.Shr => a >> b, Code.Shr_Un => (int)((uint)a >> b),
        _ => throw new ArgumentOutOfRangeException(nameof(code))
    };
}
