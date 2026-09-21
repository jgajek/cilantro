using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Passes;

/// <summary>Gives conditional arms separate copies of short, shared dispatcher computations.</summary>
public sealed class DispatcherTailSeparationPass : DeobfuscationPass
{
    public override string Name => "dispatcher-tail-separation";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => ["global-predicate-folding"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var count = 0;
        foreach (var method in context.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
        {
            var changed = Separate(method);
            if (changed == 0) continue;
            count += changed;
            context.AddChange(new ChangeRecord(Name, "separate-dispatcher-tail", method.FullName,
                $"Separated {changed} incoming paths through shared state computations."));
        }
        return (PassStatus.Success, count, [$"Separated {count} shared dispatcher paths before solving their states."]);
    }

    internal static int Separate(MethodDef method)
    {
        if (!method.HasBody || method.Body.Instructions.Count > 40_000)
            return 0;
        var il = method.Body.Instructions;
        var heads = new HashSet<Instruction>();
        for (var i = 6; i < il.Count; i++)
            if (il[i].OpCode.Code == Code.Switch && il[i].Operand is IList<Instruction> cases &&
                il[i - 1].OpCode.Code == Code.Rem_Un && il[i - 2].IsLdcI4() && il[i - 2].GetLdcI4Value() == cases.Count &&
                il[i - 3].IsStloc() && il[i - 4].OpCode.Code == Code.Dup &&
                il[i - 5].OpCode.Code == Code.Xor && il[i - 6].IsLdcI4()) heads.Add(il[i - 6]);
        if (heads.Count == 0) return 0;
        var graph = ControlFlowGraph.Build(method);
        var plans = new List<(Instruction Branch, Instruction[] Tail, Instruction Head)>();
        var added = 0;
        foreach (var branch in il.ToArray())
        {
            if (branch.OpCode.Code is not (Code.Br or Code.Br_S) || branch.Operand is not Instruction target || heads.Contains(target)) continue;
            var block = graph.BlockOf(target);
            if (block.First != target || block.Predecessors.Count < 2) continue;
            var tail = new List<Instruction>();
            var current = il.IndexOf(target);
            while (current < il.Count && tail.Count < 16 && !heads.Contains(il[current]) && Pure(il[current]))
                tail.Add(il[current++]);
            if (current >= il.Count || tail.Count == 0) continue;
            var end = il[current];
            var head = heads.Contains(end) ? end : end.OpCode.Code is Code.Br or Code.Br_S ? end.Operand as Instruction : null;
            if (head is null || !heads.Contains(head) || added + tail.Count + 1 > 2048) continue;
            // Copies are inserted at the branch, whose object retains any EH boundary.
            // Only duplicate paths wholly inside that same protected region.
            if (!graph.HaveIdenticalExceptionRegions(branch, head) ||
                tail.Any(i => !graph.HaveIdenticalExceptionRegions(branch, i))) continue;
            plans.Add((branch, tail.ToArray(), head));
            added += tail.Count + 1;
        }
        if (plans.Count == 0 || !EvaluationStackAnalyzer.Analyze(method).Valid) return 0;
        using var transaction = new BodyMutationTransaction(method);
        foreach (var (branch, tail, head) in plans)
        {
            // Reuse the original branch object as the first copied instruction so any
            // existing entry into it still executes the complete state computation.
            var at = il.IndexOf(branch);
            branch.OpCode = tail[0].OpCode; branch.Operand = tail[0].Operand;
            for (var i = 1; i < tail.Length; i++)
                il.Insert(++at, new Instruction(tail[i].OpCode, tail[i].Operand));
            il.Insert(++at, OpCodes.Br.ToInstruction(head));
        }
        method.Body.OptimizeBranches();
        if (!EvaluationStackAnalyzer.Analyze(method).Valid) return 0;
        transaction.Commit();
        return plans.Count;
    }

    private static bool Pure(Instruction i) => i.IsLdcI4() || i.IsLdloc() || i.OpCode.Code is
        Code.Nop or Code.Dup or Code.Pop or Code.Add or Code.Sub or Code.Mul or Code.Xor or Code.And or Code.Or or
        Code.Shl or Code.Shr or Code.Shr_Un or Code.Neg or Code.Not;
}
