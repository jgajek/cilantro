using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Passes;

/// <summary>Threads known dispatcher state while preserving local values and ordered effects.</summary>
public class DispatcherPathPass : DeobfuscationPass
{
    public override string Name => "dispatcher-paths";
    public override IReadOnlyCollection<string> Dependencies => ["control-flow-recompletion"];
    public override bool GatesEmission => false;
    protected virtual bool PreserveEffects => false;

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var total = 0;
        foreach (var method in context.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
        {
            var changed = 0;
            for (var round = 0; round < 64; round++)
            {
                var count = Rewrite(method, PreserveEffects);
                if (count == 0) break;
                changed += count;
                ControlFlowCompletionPass.TryComplete(method);
            }
            if (changed == 0) continue;
            total += changed;
            context.AddChange(new ChangeRecord(Name, "thread-dispatcher-path", method.FullName,
                $"Redirected {changed} known-state paths while retaining required local writes, calls and field reads."));
        }
        context.AddEvidence(new Evidence(Name, $"Made {total} dispatcher paths direct across state-update blocks."));
        return (PassStatus.Success, total, [$"Made {total} dispatcher paths direct; calls, unknown state and exception boundaries were preserved."]);
    }

    internal static int Rewrite(MethodDef method, bool preserveEffects = false)
    {
        var graph = ControlFlowGraph.Build(method);
        var eligible = method.Body.Variables.Where(v => v.Type.ElementType is ElementType.I4 or ElementType.U4).ToHashSet();
        foreach (var instruction in method.Body.Instructions)
            if (instruction.OpCode.Code is Code.Ldloca or Code.Ldloca_S)
                eligible.Remove(instruction.GetLocal(method.Body.Variables));
        var plans = new List<(Instruction Value, Instruction Branch, TraceResult Result, Local? Store)>();
        foreach (var block in graph.Blocks)
        {
            var il = block.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
            if (il.Length < 2 ||
                il[^1].OpCode.Code is not (Code.Br or Code.Br_S) || il[^1].Operand is not Instruction target)
                continue;
            // A zero-argument call followed by pop cannot consume the carried state. Keep
            // the call in the source block, and place any relocated store after it.
            var carried = il[^2].IsLdcI4() ? il[^2] :
                il.Length >= 4 && il[^4].IsLdcI4() && il[^3].OpCode.Code == Code.Call &&
                il[^3].Operand is IMethod { MethodSig: { HasThis: false, Params.Count: 0 } signature } &&
                signature.RetType.ElementType != ElementType.Void && (signature.ParamsAfterSentinel?.Count ?? 0) == 0 &&
                il[^2].OpCode.Code == Code.Pop ? il[^4] : null;
            var sharedStore = carried is not null &&
                graph.BlockOf(target).Instructions.FirstOrDefault(i => i.OpCode.Code != Code.Nop) is { } first && first.IsStloc()
                ? first : null;
            if (sharedStore is null && (il.Length < 3 || !il[^3].IsLdcI4() || !il[^2].IsStloc())) continue;
            var constant = sharedStore is null ? il[^3] : carried!;
            var local = (sharedStore ?? il[^2]).GetLocal(method.Body.Variables);
            if (local is null || !eligible.Contains(local))
                continue;
            if (Trace(graph, il[^1], target, local, constant.GetLdcI4Value(), sharedStore is not null, eligible) is { } result && result.Target != target)
            {
                plans.Add((constant, il[^1], result, sharedStore is null ? null : local));
                // Only the first plan is committed before rebuilding the graph. Later
                // candidates would be discarded and recomputed against the changed body.
                break;
            }
        }
        if (plans.Count == 0) return RewriteKnownStore(method, graph, preserveEffects, eligible);
        using var transaction = new BodyMutationTransaction(method);
        var before = EvaluationStackAnalyzer.Analyze(method);
        if (!before.Valid) return 0;
        // Apply one plan at a time across rounds. Another plan could depend on the
        // old value of an assignment this plan changes while bypassing its update.
        var plan = plans[0];
        plan.Value.OpCode = OpCodes.Ldc_I4; plan.Value.Operand = plan.Result.State;
        // This edge used to carry the value to a shared store. Keep its final write at the
        // source when bypassing that store; neither the stack value nor the local may be lost.
        if (plan.Store is { } store)
            method.Body.Instructions.Insert(method.Body.Instructions.IndexOf(plan.Branch), OpCodes.Stloc.ToInstruction(store));
        PreserveTemporaryWrites(method, plan.Branch, plan.Result);
        plan.Branch.Operand = plan.Result.Target;
        method.Body.OptimizeBranches();
        if (!EvaluationStackAnalyzer.Analyze(method).Valid) return 0;
        transaction.Commit();
        return 1;
    }

    private static int RewriteKnownStore(MethodDef method, ControlFlowGraph graph, bool preserveEffects,
        IReadOnlySet<Local> eligible)
    {
        if (!method.Body.Instructions.Any(i => i.OpCode.FlowControl == FlowControl.Cond_Branch) ||
            !EvaluationStackAnalyzer.Analyze(method).Valid) return 0;
        var branchStates = preserveEffects ? new Dictionary<Instruction, IReadOnlyDictionary<Local, int>>() : null;
        var stores = LocalConstantPropagation.KnownStores(method, branchStates);
        foreach (var block in graph.Blocks)
        {
            var il = block.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
            if (il.Length < 2 || !il[^2].IsStloc() || !stores.TryGetValue(il[^2], out var value) ||
                il[^1].OpCode.Code is not (Code.Br or Code.Br_S) || il[^1].Operand is not Instruction target ||
                il[^2].GetLocal(method.Body.Variables) is not { } local) continue;
            if (Trace(graph, il[^1], target, local, value, false, eligible) is not { } result || result.Target == target)
                continue;
            using var transaction = new BodyMutationTransaction(method);
            // Keep the original computation and store at their original sites. Only the
            // following pure dispatcher path is bypassed; guard reads and calls still run.
            if (result.State != value)
            {
                var at = method.Body.Instructions.IndexOf(il[^1]);
                method.Body.Instructions.Insert(at, Instruction.CreateLdcI4(result.State));
                method.Body.Instructions.Insert(at + 1, OpCodes.Stloc.ToInstruction(local));
            }
            PreserveTemporaryWrites(method, il[^1], result);
            il[^1].Operand = result.Target;
            method.Body.OptimizeBranches();
            if (!EvaluationStackAnalyzer.Analyze(method).Valid) continue;
            transaction.Commit();
            return 1;
        }
        return preserveEffects ? EffectfulDispatcherPath.Rewrite(method, graph, branchStates!) : 0;
    }

    private sealed record TraceResult(int State, Instruction Target, IReadOnlyDictionary<Local, int> Writes);

    private static void PreserveTemporaryWrites(MethodDef method, Instruction branch, TraceResult result)
    {
        // Every additional known local was assigned along the bypassed path. Keep even
        // writes not consumed by its branch: the destination may still read them.
        var at = method.Body.Instructions.IndexOf(branch);
        foreach (var (local, value) in result.Writes.OrderBy(p => p.Key.Index))
        {
            method.Body.Instructions.Insert(at++, Instruction.CreateLdcI4(value));
            method.Body.Instructions.Insert(at++, OpCodes.Stloc.ToInstruction(local));
        }
    }

    private static TraceResult? Trace(ControlFlowGraph graph, Instruction source,
        Instruction start, Local local, int value, bool stackCarried, IReadOnlySet<Local> eligible)
    {
        var values = new Dictionary<Local, int> { [local] = value };
        if (!eligible.Contains(local)) return null;
        TraceResult Result(Instruction target) => new(values[local], target,
            values.Where(p => p.Key != local).ToDictionary(p => p.Key, p => p.Value));
        var current = start;
        var stack = new Stack<int>();
        if (stackCarried) stack.Push(value);
        var seen = new HashSet<Instruction>();
        for (var hops = 0; hops < 32; hops++)
        {
            if (!seen.Add(current) || !graph.HaveIdenticalExceptionRegions(source, current)) return null;
            var block = graph.BlockOf(current);
            if (block.First != current || block.Instructions.Count > 128) return null;
            Instruction? next = null;
            foreach (var instruction in block.Instructions)
            {
                if (instruction.IsLdcI4()) { stack.Push(instruction.GetLdcI4Value()); continue; }
                if (instruction.IsLdloc())
                {
                    var read = instruction.GetLocal(graph.Method.Body.Variables);
                    if (!eligible.Contains(read) || !values.TryGetValue(read, out var known)) return null;
                    stack.Push(known); continue;
                }
                if (instruction.IsStloc())
                {
                    var written = instruction.GetLocal(graph.Method.Body.Variables);
                    if (!eligible.Contains(written) || !stack.TryPop(out var stored)) return null;
                    values[written] = stored; continue;
                }
                switch (instruction.OpCode.Code)
                {
                    case Code.Nop: break;
                    case Code.Conv_I1:
                    case Code.Conv_U1:
                    case Code.Conv_I2:
                    case Code.Conv_U2:
                    case Code.Conv_I4:
                    case Code.Conv_U4:
                        if (!stack.TryPop(out var converted)) return null;
                        stack.Push(instruction.OpCode.Code switch
                        {
                            Code.Conv_I1 => unchecked((sbyte)converted),
                            Code.Conv_U1 => unchecked((byte)converted),
                            Code.Conv_I2 => unchecked((short)converted),
                            Code.Conv_U2 => unchecked((ushort)converted),
                            _ => converted
                        });
                        break;
                    case Code.Beq:
                    case Code.Beq_S:
                    case Code.Bne_Un:
                    case Code.Bne_Un_S:
                    case Code.Bge:
                    case Code.Bge_S:
                    case Code.Bge_Un:
                    case Code.Bge_Un_S:
                    case Code.Bgt:
                    case Code.Bgt_S:
                    case Code.Bgt_Un:
                    case Code.Bgt_Un_S:
                    case Code.Ble:
                    case Code.Ble_S:
                    case Code.Ble_Un:
                    case Code.Ble_Un_S:
                    case Code.Blt:
                    case Code.Blt_S:
                    case Code.Blt_Un:
                    case Code.Blt_Un_S:
                        if (!stack.TryPop(out var right) || !stack.TryPop(out var left)) return null;
                        next = ControlFlowCompletionPass.Compares(instruction.OpCode.Code, left, right)
                            ? instruction.Operand as Instruction
                            : block.Successors.FirstOrDefault(e => e.Kind == ControlFlowEdgeKind.FallThrough)?.Target.First;
                        if (next is null) return null;
                        if (stack.Count == 0)
                            return graph.HaveIdenticalExceptionRegions(source, next) ? Result(next) : null;
                        break;
                    case Code.Dup:
                        if (!stack.TryPeek(out var duplicate)) return null;
                        stack.Push(duplicate);
                        break;
                    case Code.Pop:
                        if (!stack.TryPop(out _)) return null;
                        break;
                    case Code.Div:
                    case Code.Div_Un:
                    case Code.Rem:
                    case Code.Rem_Un:
                        if (!stack.TryPop(out var divisor) || !stack.TryPop(out var dividend) || divisor == 0 ||
                            (instruction.OpCode.Code is Code.Div or Code.Rem && dividend == int.MinValue && divisor == -1))
                            return null;
                        stack.Push(instruction.OpCode.Code switch
                        {
                            Code.Div => dividend / divisor,
                            Code.Rem => dividend % divisor,
                            Code.Div_Un => unchecked((int)((uint)dividend / (uint)divisor)),
                            _ => unchecked((int)((uint)dividend % (uint)divisor))
                        });
                        break;
                    case Code.Brtrue:
                    case Code.Brtrue_S:
                    case Code.Brfalse:
                    case Code.Brfalse_S:
                        if (!stack.TryPop(out var condition)) return null;
                        var taken = instruction.OpCode.Code is Code.Brtrue or Code.Brtrue_S ? condition != 0 : condition == 0;
                        next = taken ? instruction.Operand as Instruction :
                            block.Successors.FirstOrDefault(e => e.Kind == ControlFlowEdgeKind.FallThrough)?.Target.First;
                        if (next is null) return null;
                        if (stack.Count == 0)
                            return graph.HaveIdenticalExceptionRegions(source, next) ? Result(next) : null;
                        break;
                    case Code.Neg:
                    case Code.Not:
                        if (!stack.TryPop(out var unary)) return null;
                        stack.Push(instruction.OpCode.Code == Code.Neg ? unchecked(-unary) : ~unary);
                        break;
                    case Code.Add:
                    case Code.Sub:
                    case Code.Xor:
                    case Code.And:
                    case Code.Or:
                    case Code.Mul:
                    case Code.Shl:
                    case Code.Shr:
                    case Code.Shr_Un:
                    case Code.Ceq:
                    case Code.Clt:
                    case Code.Clt_Un:
                    case Code.Cgt:
                    case Code.Cgt_Un:
                        if (!stack.TryPop(out var b) || !stack.TryPop(out var a)) return null;
                        stack.Push(instruction.OpCode.Code switch
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
                            _ => 0
                        });
                        break;
                    case Code.Br:
                    case Code.Br_S:
                        next = instruction.Operand as Instruction;
                        break;
                    case Code.Switch:
                        if (!stack.TryPop(out var index) || stack.Count != 0 || instruction.Operand is not IList<Instruction> cases)
                            return null;
                        var target = index >= 0 && index < cases.Count ? cases[index] :
                            block.Successors.FirstOrDefault(e => e.Kind == ControlFlowEdgeKind.FallThrough)?.Target.First;
                        return target is not null && graph.HaveIdenticalExceptionRegions(source, target)
                            ? Result(target) : null;
                    default: return null;
                }
            }
            next ??= block.Successors.FirstOrDefault(e => e.Kind == ControlFlowEdgeKind.FallThrough)?.Target.First;
            if (next is null) return null;
            current = next;
        }
        return null;
    }
}

/// <summary>Threads paths exposed by the final dispatcher, helper, and generated-body rewrites.</summary>
public sealed class DispatcherPathCompletionPass : DispatcherPathPass
{
    public override string Name => "dispatcher-paths-completion";
    public override IReadOnlyCollection<string> Dependencies => ["emitted-method-reconstruction"];
}

/// <summary>Specializes effectful paths only after shape-based recovery and constant recovery finish.</summary>
public sealed class EffectfulDispatcherCompletionPass : DispatcherPathPass
{
    public override string Name => "dispatcher-effects-completion";
    public override IReadOnlyCollection<string> Dependencies => ["control-flow-table-finalization"];
    protected override bool PreserveEffects => true;
}
