using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Passes;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Analysis;

/// <summary>Specializes a known dispatcher edge without deleting or reordering its effects.</summary>
internal static class EffectfulDispatcherPath
{
    internal static int Rewrite(MethodDef method, ControlFlowGraph graph,
        IReadOnlyDictionary<Instruction, IReadOnlyDictionary<Local, int>> branchStates)
    {
        var eligible = method.Body.Variables.Where(v => v.Type.ElementType is ElementType.I4 or ElementType.U4).ToHashSet();
        foreach (var i in method.Body.Instructions)
            if (i.OpCode.Code is Code.Ldloca or Code.Ldloca_S) eligible.Remove(i.GetLocal(method.Body.Variables));
        // Prefer explicit state updates before inherited facts. Specializing arbitrary
        // constant branches first can obscure dispatcher paths within the round budget.
        foreach (var useIncoming in new[] { false, true })
            foreach (var block in graph.Blocks)
            {
                var il = block.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
                if (il.Length == 0 || il[^1].OpCode.Code is not (Code.Br or Code.Br_S) || il[^1].Operand is not Instruction start)
                    continue;
                var values = branchStates.TryGetValue(il[^1], out var state) ? new Dictionary<Local, int>(state) : [];
                // Calls cannot change these unaliased scalar locals. The converged
                // snapshot already accounts for later stores, joins and loop back edges.
                if (!useIncoming)
                {
                    var written = il.Where(i => i.IsStloc()).Select(i => i.GetLocal(method.Body.Variables)).ToHashSet();
                    foreach (var local in values.Keys.Where(l => !written.Contains(l)).ToArray()) values.Remove(local);
                }
                int? carriedValue = null;
                var carried = il.Length >= 2 && il[^2].IsLdcI4();
                if (carried)
                {
                    var first = graph.BlockOf(start).Instructions.FirstOrDefault(i => i.OpCode.Code != Code.Nop);
                    if (first is null || !first.IsStloc()) continue;
                    var local = first.GetLocal(method.Body.Variables);
                    if (local is null || !eligible.Contains(local)) continue;
                    carriedValue = il[^2].GetLdcI4Value();
                    values[local] = carriedValue.Value;
                }
                if (values.Count == 0) continue;
                if (Trace(graph, il[^1], start, values, carriedValue, eligible) is not { } plan || plan.Target == start) continue;
                using var transaction = new BodyMutationTransaction(method);
                // Keep the original entry value and the complete ordered instruction prefix.
                // In particular, a handler must see writes made BEFORE a throwing call/read,
                // not all final writes eagerly relocated ahead of it.
                var at = method.Body.Instructions.IndexOf(il[^1]);
                foreach (var instruction in plan.Prefix) method.Body.Instructions.Insert(at++, instruction);
                il[^1].Operand = plan.Target;
                method.Body.OptimizeBranches();
                if (!EvaluationStackAnalyzer.Analyze(method).Valid) continue;
                transaction.Commit();
                return 1;
            }
        return 0;
    }

    private sealed record Plan(Instruction Target, IReadOnlyList<Instruction> Prefix);

    private static Plan? Trace(ControlFlowGraph graph, Instruction source, Instruction start, Dictionary<Local, int> values,
        int? carriedValue, HashSet<Local> eligible)
    {
        var stack = new Stack<int?>();
        if (carriedValue is { } value) stack.Push(value);
        var prefix = new List<Instruction>();
        var seen = new HashSet<Instruction>();
        var current = start;
        Plan? best = null;
        var effect = false;
        var examined = 0;
        for (var hops = 0; hops < 16; hops++)
        {
            if (!seen.Add(current) || !graph.HaveIdenticalExceptionRegions(source, current)) return best;
            var block = graph.BlockOf(current);
            if (block.First != current) return best;
            Instruction? next = null;
            foreach (var i in block.Instructions)
            {
                if (examined >= 64) return best;
                if (i.OpCode.Code == Code.Nop) continue;
                if (i.OpCode.Code is Code.Br or Code.Br_S) { next = i.Operand as Instruction; break; }
                if (i.OpCode.FlowControl == FlowControl.Cond_Branch)
                {
                    Instruction? target;
                    int consumed;
                    var fallthrough = block.Successors.FirstOrDefault(e => e.Kind == ControlFlowEdgeKind.FallThrough)?.Target.First;
                    if (i.OpCode.Code == Code.Switch)
                    {
                        if (!stack.TryPop(out var index) || index is null || i.Operand is not IList<Instruction> cases) return best;
                        target = index >= 0 && index < cases.Count ? cases[index.Value] : fallthrough;
                        consumed = 1;
                    }
                    else if (i.OpCode.Code is Code.Brtrue or Code.Brtrue_S or Code.Brfalse or Code.Brfalse_S)
                    {
                        if (!stack.TryPop(out var condition) || condition is null) return best;
                        var taken = i.OpCode.Code is Code.Brtrue or Code.Brtrue_S ? condition != 0 : condition == 0;
                        target = taken ? i.Operand as Instruction : fallthrough;
                        consumed = 1;
                    }
                    else
                    {
                        if (!stack.TryPop(out var right) || !stack.TryPop(out var left) || left is null || right is null) return best;
                        target = ControlFlowCompletionPass.Compares(i.OpCode.Code, left.Value, right.Value) ? i.Operand as Instruction : fallthrough;
                        consumed = 2;
                    }
                    if (!effect || stack.Count != 0 || target is null || !graph.HaveIdenticalExceptionRegions(source, target)) return best;
                    for (var n = 0; n < consumed; n++) prefix.Add(OpCodes.Pop.ToInstruction());
                    if (seen.Contains(target)) return best;
                    var selected = prefix.Select(p => new Instruction(p.OpCode, p.Operand)).ToList();
                    TrimDeadStores(graph, source, target, selected, eligible);
                    TrimDiscardedConstants(selected);
                    best = new Plan(target, selected);
                    next = target;
                    break;
                }
                examined++;
                var copy = new Instruction(i.OpCode, i.Operand);
                if (i.IsLdcI4()) stack.Push(i.GetLdcI4Value());
                else if (i.IsLdloc())
                {
                    var read = i.GetLocal(graph.Method.Body.Variables);
                    if (read is not null && eligible.Contains(read) && values.TryGetValue(read, out var known))
                    {
                        stack.Push(known);
                        copy = Instruction.CreateLdcI4(known);
                    }
                    else stack.Push(null);
                }
                else if (i.IsStloc())
                {
                    if (!stack.TryPop(out var stored)) return best;
                    var written = i.GetLocal(graph.Method.Body.Variables);
                    if (written is null) return best;
                    if (eligible.Contains(written) && stored is { } known) values[written] = known;
                    else values.Remove(written);
                }
                else if (i.OpCode.Code == Code.Dup)
                {
                    if (!stack.TryPeek(out var duplicate)) return best;
                    stack.Push(duplicate);
                }
                else if (i.OpCode.Code == Code.Pop)
                {
                    if (!stack.TryPop(out _)) return best;
                }
                else if (i.OpCode.Code is Code.Neg or Code.Not)
                {
                    if (!stack.TryPop(out var unary)) return best;
                    int? result = unary is not { } n ? null : i.OpCode.Code == Code.Neg ? unchecked(-n) : ~n;
                    stack.Push(result);
                    if (result is { } folded)
                    {
                        prefix.Add(OpCodes.Pop.ToInstruction());
                        copy = Instruction.CreateLdcI4(folded);
                    }
                }
                else if (i.OpCode.Code is Code.Add or Code.Sub or Code.Mul or Code.Xor or Code.And or Code.Or or
                    Code.Shl or Code.Shr or Code.Shr_Un or Code.Ceq or Code.Clt or Code.Clt_Un or Code.Cgt or Code.Cgt_Un or
                    Code.Div or Code.Div_Un or Code.Rem or Code.Rem_Un)
                {
                    if (!stack.TryPop(out var b) || !stack.TryPop(out var a)) return best;
                    var result = a is { } x && b is { } y ? LocalConstantPropagation.Evaluate(i.OpCode.Code, x, y) : null;
                    stack.Push(result);
                    if (result is { } folded)
                    {
                        // Consume the original operands where the operation occurred. Their
                        // producers may enclose calls or throwing reads and must stay ordered.
                        // An unknown or throwing result retains the original operation.
                        prefix.Add(OpCodes.Pop.ToInstruction());
                        prefix.Add(OpCodes.Pop.ToInstruction());
                        copy = Instruction.CreateLdcI4(folded);
                    }
                }
                else
                {
                    // Unknown call/read results remain unknown. Never borrow a host value
                    // or assume that a call is pure. Prefixes, addresses, indirect calls,
                    // writes through pointers and exceptional control flow are excluded.
                    switch (i.OpCode.Code)
                    {
                        case Code.Call:
                        case Code.Callvirt:
                        case Code.Newobj:
                            if (i.Operand is not IMethod { MethodSig: { } signature } || signature.ParamsAfterSentinel?.Count > 0 ||
                                signature.GetCallingConvention() == CallingConvention.VarArg) return best;
                            effect = true;
                            break;
                        case Code.Ldfld:
                        case Code.Ldsfld:
                            effect = true;
                            break;
                        case Code.Ldarg:
                        case Code.Ldarg_S:
                        case Code.Ldarg_0:
                        case Code.Ldarg_1:
                        case Code.Ldarg_2:
                        case Code.Ldarg_3:
                        case Code.Ldnull:
                        case Code.Ldstr:
                        case Code.Ldtoken:
                            break;
                        default: return best;
                    }
                    i.CalculateStackUsage(out var pushes, out var pops);
                    if (pops < 0 || stack.Count < pops) return best;
                    for (var n = 0; n < pops; n++) stack.Pop();
                    for (var n = 0; n < pushes; n++) stack.Push(null);
                }
                prefix.Add(copy);
            }
            next ??= block.Successors.FirstOrDefault(e => e.Kind == ControlFlowEdgeKind.FallThrough)?.Target.First;
            if (next is null) return best;
            current = next;
        }
        return best;
    }

    private static void TrimDiscardedConstants(List<Instruction> prefix)
    {
        // This is a newly copied straight-line sequence: it has no incoming branch
        // targets or exception boundaries. Only remove literal/pop pairs, keeping
        // every intervening effect in place. Dup loses identity to keep both uses.
        var stack = new List<Instruction?>();
        var removed = new HashSet<Instruction>();
        foreach (var instruction in prefix)
        {
            instruction.CalculateStackUsage(out var pushes, out var pops);
            if (instruction.OpCode.Code == Code.Pop && stack.Count > 0 && stack[^1] is { } producer)
            {
                removed.Add(producer);
                removed.Add(instruction);
            }
            var count = Math.Min(pops, stack.Count);
            stack.RemoveRange(stack.Count - count, count);
            for (var n = 0; n < pushes; n++) stack.Add(instruction.IsLdcI4() ? instruction : null);
        }
        prefix.RemoveAll(removed.Contains);
    }

    private static void TrimDeadStores(ControlFlowGraph graph, Instruction source, Instruction target,
        List<Instruction> prefix, HashSet<Local> eligible)
    {
        var written = prefix.Where(i => i.IsStloc()).Select(i => i.GetLocal(graph.Method.Body.Variables))
            .Where(l => l is not null && eligible.Contains(l)).ToHashSet();
        var live = written.Where(l => MayReadBeforeWrite(target, l)).ToHashSet();
        // Be conservative about exception timing: a local observable by any enclosing
        // handler retains every write. Known-value substitution never changes those writes.
        var handlers = graph.RegionsOf(source).SelectMany(r => new[] { r.Handler.FilterStart, r.Handler.HandlerStart })
            .Where(i => i is not null).Distinct().ToArray();
        var observedByHandler = written.Where(l => handlers.Any(h => MayReadBeforeWrite(h, l))).ToHashSet();
        for (var n = prefix.Count - 1; n >= 0; n--)
        {
            var i = prefix[n];
            var local = i.GetLocal(graph.Method.Body.Variables);
            if (local is null || !eligible.Contains(local)) continue;
            if (i.IsLdloc()) live.Add(local);
            else if (i.IsStloc())
            {
                if (!live.Remove(local) && !observedByHandler.Contains(local)) prefix[n] = OpCodes.Pop.ToInstruction();
            }
        }

        bool MayReadBeforeWrite(Instruction entry, Local local)
        {
            var pending = new Stack<BasicBlock>(); pending.Push(graph.BlockOf(entry));
            var seen = new HashSet<BasicBlock>();
            while (pending.TryPop(out var block))
            {
                if (!seen.Add(block)) continue;
                if (seen.Count > 512) return true;
                // Exceptional transfers can occur before a block's first store.
                foreach (var edge in block.Successors.Where(e => e.Kind == ControlFlowEdgeKind.Exception)) pending.Push(edge.Target);
                // A filtered catch body is not a normal successor of endfilter in this
                // CFG. Include it separately; a later try can observe the incoming value.
                foreach (var region in graph.RegionsOf(block.First).Where(r => r.InTry))
                    if (region.Handler.HandlerStart is { } handler) pending.Push(graph.BlockOf(handler));
                var overwritten = false;
                foreach (var i in block.Instructions)
                {
                    if (i.GetLocal(graph.Method.Body.Variables) != local) continue;
                    if (i.IsLdloc()) return true;
                    if (i.IsStloc()) { overwritten = true; break; }
                }
                if (!overwritten)
                    foreach (var edge in block.Successors.Where(e => e.Kind != ControlFlowEdgeKind.Exception)) pending.Push(edge.Target);
            }
            return false;
        }
    }
}
