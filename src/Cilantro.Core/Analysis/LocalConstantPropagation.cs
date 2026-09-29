using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Must-constant analysis: a local is known only when every incoming path agrees.</summary>
internal static class LocalConstantPropagation
{
    internal static int Fold(MethodDef method) => Analyze(method, true, out _);

    internal static IReadOnlyDictionary<Instruction, int> KnownStores(MethodDef method,
        Dictionary<Instruction, IReadOnlyDictionary<Local, int>>? branchStates = null)
    {
        Analyze(method, false, out var stores, branchStates);
        return stores;
    }

    private static int Analyze(MethodDef method, bool rewrite, out Dictionary<Instruction, int> stores,
        Dictionary<Instruction, IReadOnlyDictionary<Local, int>>? branchStates = null)
    {
        branchStates?.Clear();
        var knownStores = new Dictionary<Instruction, int>();
        stores = knownStores;
        var body = method.Body;
        if (body.Variables.Count == 0 || body.Instructions.Count == 0)
            return 0;
        var eligible = body.Variables.Where(v => v.Type.ElementType is ElementType.I4 or ElementType.U4).ToHashSet();
        foreach (var i in body.Instructions)
            if (i.OpCode.Code is Code.Ldloca or Code.Ldloca_S && i.GetLocal(body.Variables) is { } escaped)
                eligible.Remove(escaped);
        if (eligible.Count == 0) return 0;
        var graph = ControlFlowGraph.Build(method);
        var trackStack = EvaluationStackAnalyzer.Analyze(method).Valid;
        var stacks = new Dictionary<BasicBlock, int?[]?> { [graph.Entry] = [] };
        var inputs = new Dictionary<BasicBlock, Dictionary<Local, int>>();
        inputs[graph.Entry] = body.InitLocals ? eligible.ToDictionary(v => v, _ => 0) : [];
        var queue = new Queue<BasicBlock>();
        var queued = new HashSet<BasicBlock>();
        queue.Enqueue(graph.Entry);
        queued.Add(graph.Entry);
        // An exception can leave a protected block before its last assignment. Filters
        // and unwind handlers can also modify locals before a handler is entered.
        // Seed every exceptional entry independently, including filtered catch bodies.
        foreach (var handler in body.ExceptionHandlers)
            foreach (var entry in new[] { handler.FilterStart, handler.HandlerStart })
                if (entry is not null)
                {
                    var root = graph.BlockOf(entry);
                    inputs[root] = [];
                    stacks[root] = null;
                    if (queued.Add(root)) queue.Enqueue(root);
                }
        // Exhaustion means no rewrite, never a partially converged proof.
        var budget = Math.Min(1_000_000L, Math.Max(4096L, body.Instructions.Count * 32L));
        var unknown = new Dictionary<Local, int>();
        while (queue.TryDequeue(out var block))
        {
            queued.Remove(block);
            budget -= block.Instructions.Count;
            if (budget < 0) return 0;
            var output = Transfer(block, inputs[block], stacks[block], null, out var outputStack);
            foreach (var edge in block.Successors)
            {
                // The CFG's leave edge bypasses finally execution. Until that execution
                // is modeled, no local fact may survive it, even on a normal exit.
                var incoming = edge.Kind == ControlFlowEdgeKind.Exception ||
                    block.Last.OpCode.Code is Code.Leave or Code.Leave_S
                    ? unknown : output;
                var incomingStack = ReferenceEquals(incoming, unknown) || !trackStack ? null : outputStack;
                var changed = false;
                if (!inputs.TryGetValue(edge.Target, out var target))
                {
                    inputs[edge.Target] = new(incoming);
                    stacks[edge.Target] = incomingStack?.ToArray();
                    changed = true;
                }
                else
                {
                    if (stacks[edge.Target] is { } targetStack)
                    {
                        if (incomingStack is null || targetStack.Length != incomingStack.Length)
                        { stacks[edge.Target] = null; changed = true; }
                        else for (var index = 0; index < targetStack.Length; index++)
                            if (targetStack[index] is not null && targetStack[index] != incomingStack[index])
                            { targetStack[index] = null; changed = true; }
                    }
                    foreach (var local in target.Keys.ToArray())
                        if (!incoming.TryGetValue(local, out var value) || value != target[local])
                        {
                            target.Remove(local);
                            changed = true;
                        }
                }
                if (changed && queued.Add(edge.Target)) queue.Enqueue(edge.Target);
            }
        }
        var replacements = new Dictionary<Instruction, int>();
        // Export branch facts only after the worklist converges. A value seen on the
        // first visit may be invalidated by another predecessor or a loop back edge.
        foreach (var (block, state) in inputs)
        {
            var output = Transfer(block, state, stacks[block], replacements, out _);
            if (branchStates is not null && block.Last.OpCode.Code is Code.Br or Code.Br_S && output.Count != 0)
                branchStates[block.Last] = output;
        }
        if (!rewrite) return 0;
        foreach (var (instruction, value) in replacements)
        {
            instruction.OpCode = OpCodes.Ldc_I4;
            instruction.Operand = value;
        }
        return replacements.Count;

        Dictionary<Local, int> Transfer(BasicBlock block, Dictionary<Local, int> input, int?[]? inputStack,
            Dictionary<Instruction, int>? replacements, out int?[] outputStack)
        {
            var state = new Dictionary<Local, int>(input);
            // Bottom-to-top stack facts merge independently of local facts. Exceptional
            // entries and leave edges never carry normal-flow values into handlers.
            var stack = new Stack<int?>(inputStack ?? []);
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
                        if (replacements is not null && value is { } stored) knownStores[instruction] = stored;
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
                    case Code.Conv_I1:
                    case Code.Conv_U1:
                    case Code.Conv_I2:
                    case Code.Conv_U2:
                    case Code.Conv_I4:
                    case Code.Conv_U4:
                        {
                            var value = Pop();
                            stack.Push(value is not { } n ? null : instruction.OpCode.Code switch
                            {
                                Code.Conv_I1 => unchecked((sbyte)n),
                                Code.Conv_U1 => unchecked((byte)n),
                                Code.Conv_I2 => unchecked((short)n),
                                Code.Conv_U2 => unchecked((ushort)n),
                                _ => n
                            });
                            break;
                        }
                    case Code.Add:
                    case Code.Sub:
                    case Code.Mul:
                    case Code.Xor:
                    case Code.And:
                    case Code.Or:
                    case Code.Shl:
                    case Code.Shr:
                    case Code.Shr_Un:
                    case Code.Ceq:
                    case Code.Clt:
                    case Code.Clt_Un:
                    case Code.Cgt:
                    case Code.Cgt_Un:
                    case Code.Div:
                    case Code.Div_Un:
                    case Code.Rem:
                    case Code.Rem_Un:
                        {
                            var right = Pop(); var left = Pop();
                            stack.Push(left is { } a && right is { } b ? Evaluate(instruction.OpCode.Code, a, b) : null);
                            break;
                        }
                    default:
                        if (!trackStack) { stack.Clear(); break; }
                        instruction.CalculateStackUsage(out var pushes, out var pops);
                        if (pops < 0) stack.Clear();
                        else for (var index = 0; index < pops; index++) Pop();
                        for (var index = 0; index < pushes; index++) stack.Push(null);
                        break;
                }
            }
            outputStack = stack.Reverse().ToArray();
            return state;
        }
    }

    internal static int? Evaluate(Code code, int a, int b) => code switch
    {
        Code.Add => unchecked(a + b),
        Code.Sub => unchecked(a - b),
        Code.Mul => unchecked(a * b),
        Code.Xor => a ^ b,
        Code.And => a & b,
        Code.Or => a | b,
        Code.Shl => a << b,
        Code.Shr => a >> b,
        Code.Shr_Un => (int)((uint)a >> b),
        Code.Ceq => a == b ? 1 : 0,
        Code.Clt => a < b ? 1 : 0,
        Code.Clt_Un => (uint)a < (uint)b ? 1 : 0,
        Code.Cgt => a > b ? 1 : 0,
        Code.Cgt_Un => (uint)a > (uint)b ? 1 : 0,
        Code.Div when b != 0 && !(a == int.MinValue && b == -1) => a / b,
        Code.Rem when b != 0 && !(a == int.MinValue && b == -1) => a % b,
        Code.Div_Un when b != 0 => unchecked((int)((uint)a / (uint)b)),
        Code.Rem_Un when b != 0 => unchecked((int)((uint)a % (uint)b)),
        Code.Div or Code.Rem or Code.Div_Un or Code.Rem_Un => null,
        _ => throw new ArgumentOutOfRangeException(nameof(code))
    };
}
