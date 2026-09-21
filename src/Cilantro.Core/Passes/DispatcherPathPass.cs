using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Passes;

/// <summary>Threads known state through pure dispatcher blocks, retaining the final local value.</summary>
public sealed class DispatcherPathPass : DeobfuscationPass
{
    public override string Name => "dispatcher-paths";
    public override IReadOnlyCollection<string> Dependencies => ["control-flow-recompletion"];
    public override bool GatesEmission => false;

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var total = 0;
        foreach (var method in context.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
        {
            var changed = 0;
            for (var round = 0; round < 64; round++)
            {
                var count = Rewrite(method);
                if (count == 0) break;
                changed += count;
                ControlFlowCompletionPass.TryComplete(method);
            }
            if (changed == 0) continue;
            total += changed;
            context.AddChange(new ChangeRecord(Name, "thread-dispatcher-path", method.FullName,
                $"Redirected {changed} known-state paths through pure dispatcher blocks."));
        }
        context.AddEvidence(new Evidence(Name, $"Made {total} dispatcher paths direct across state-update blocks."));
        return (PassStatus.Success, total, [$"Made {total} dispatcher paths direct; calls, unknown state and exception boundaries were preserved."]);
    }

    internal static int Rewrite(MethodDef method)
    {
        var graph = ControlFlowGraph.Build(method);
        var plans = new List<(Instruction Value, Instruction Branch, int State, Instruction Target)>();
        foreach (var block in graph.Blocks)
        {
            var il = block.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
            if (il.Length < 3 || !il[^3].IsLdcI4() || !il[^2].IsStloc() ||
                il[^1].OpCode.Code is not (Code.Br or Code.Br_S) || il[^1].Operand is not Instruction target)
                continue;
            var local = il[^2].GetLocal(method.Body.Variables);
            if (local?.Type.ElementType is not (ElementType.I4 or ElementType.U4) ||
                method.Body.Instructions.Any(i => i.OpCode.Code is Code.Ldloca or Code.Ldloca_S && i.GetLocal(method.Body.Variables) == local))
                continue;
            if (Trace(graph, il[^1], target, local, il[^3].GetLdcI4Value()) is { } result)
                plans.Add((il[^3], il[^1], result.State, result.Target));
        }
        if (plans.Count == 0) return 0;
        using var transaction = new BodyMutationTransaction(method);
        var before = EvaluationStackAnalyzer.Analyze(method);
        if (!before.Valid) return 0;
        // Apply one plan at a time across rounds. Another plan could depend on the
        // old value of an assignment this plan changes while bypassing its update.
        var plan = plans[0];
        plan.Value.OpCode = OpCodes.Ldc_I4; plan.Value.Operand = plan.State;
        plan.Branch.Operand = plan.Target;
        method.Body.OptimizeBranches();
        if (!EvaluationStackAnalyzer.Analyze(method).Valid) return 0;
        transaction.Commit();
        return 1;
    }

    private static (int State, Instruction Target)? Trace(ControlFlowGraph graph, Instruction source,
        Instruction start, Local local, int value)
    {
        var current = start;
        var stack = new Stack<int>();
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
                if (instruction.IsLdloc() && instruction.GetLocal(graph.Method.Body.Variables) == local)
                { stack.Push(value); continue; }
                if (instruction.IsStloc() && instruction.GetLocal(graph.Method.Body.Variables) == local)
                { if (!stack.TryPop(out value)) return null; continue; }
                switch (instruction.OpCode.Code)
                {
                    case Code.Nop: break;
                    case Code.Neg: case Code.Not:
                        if (!stack.TryPop(out var unary)) return null;
                        stack.Push(instruction.OpCode.Code == Code.Neg ? unchecked(-unary) : ~unary);
                        break;
                    case Code.Add: case Code.Sub: case Code.Xor: case Code.And: case Code.Or: case Code.Mul:
                    case Code.Shl: case Code.Shr: case Code.Shr_Un:
                    case Code.Ceq: case Code.Clt: case Code.Clt_Un: case Code.Cgt: case Code.Cgt_Un:
                        if (!stack.TryPop(out var b) || !stack.TryPop(out var a)) return null;
                        stack.Push(instruction.OpCode.Code switch
                        {
                            Code.Add => unchecked(a + b), Code.Sub => unchecked(a - b), Code.Mul => unchecked(a * b),
                            Code.Xor => a ^ b, Code.And => a & b, Code.Or => a | b,
                            Code.Shl => a << b, Code.Shr => a >> b, Code.Shr_Un => (int)((uint)a >> b),
                            Code.Ceq => a == b ? 1 : 0, Code.Clt => a < b ? 1 : 0,
                            Code.Clt_Un => (uint)a < (uint)b ? 1 : 0,
                            Code.Cgt => a > b ? 1 : 0, Code.Cgt_Un => (uint)a > (uint)b ? 1 : 0, _ => 0
                        });
                        break;
                    case Code.Br: case Code.Br_S:
                        next = instruction.Operand as Instruction;
                        break;
                    case Code.Switch:
                        if (!stack.TryPop(out var index) || stack.Count != 0 || instruction.Operand is not IList<Instruction> cases)
                            return null;
                        var target = index >= 0 && index < cases.Count ? cases[index] :
                            block.Successors.FirstOrDefault(e => e.Kind == ControlFlowEdgeKind.FallThrough)?.Target.First;
                        return target is not null && graph.HaveIdenticalExceptionRegions(source, target)
                            ? (value, target) : null;
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
