using Cilantro.Core.Passes;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Bounded normalization for private copies of generated runtime bodies.</summary>
internal static class GeneratedRuntimeBodyNormalization
{
    internal static bool TryNormalize(MethodDef method, bool shortLocals, out int shortReads)
        => TryNormalizeCore(method, shortLocals, false, out shortReads);

    internal static bool TryNormalizeStackSafe(MethodDef method, bool shortLocals, out int shortReads)
        => TryNormalizeCore(method, shortLocals, true, out shortReads);

    private static bool TryNormalizeCore(MethodDef method, bool shortLocals, bool stackSafe, out int shortReads)
    {
        shortReads = 0;
        if (!method.HasBody || method.Body.Instructions.Count > 4096 || !EvaluationStackAnalyzer.Analyze(method).Valid) return false;
        for (var round = 0; round < 64; round++)
        {
            if (method.Body.Instructions.Count > 16_384) return false;
            var reads = shortLocals ? Step(() => stackSafe ? DotfuscatorShortLocalFlow.Rewrite(method) : DotfuscatorControlFlowPass.Rewrite(method)) : 0;
            shortReads += reads;
            var dead = stackSafe ? Step(() => ControlFlowCompletionPass.RemoveUnreachable(method)) : 0;
            var completion = Step(() => ControlFlowCompletionPass.TryComplete(method) is { } completed ? completed.Folded + completed.Removed : -1);
            if (completion < 0) return false;
            var edges = Step(() => new DispatcherDeobfuscationPass().Rewrite(method).ChangedEdges);
            var paths = Step(() => DispatcherPathPass.Rewrite(method, preserveEffects: true));
            if (reads + dead + completion + edges + paths == 0) break;
        }
        IlCompactionPass.Compact(method);
        method.Body.SimplifyMacros(method.Parameters);
        var graph = ControlFlowGraph.Build(method);
        var il = method.Body.Instructions;
        var read = il.Where(instruction => instruction.IsLdloc() || instruction.OpCode.Code is Code.Ldloca or Code.Ldloca_S)
            .Select(instruction => instruction.GetLocal(method.Body.Variables)).ToHashSet();
        for (var index = 1; index < il.Count; index++)
        {
            var store = il[index]; var value = il[index - 1];
            if (!store.IsStloc() || read.Contains(store.GetLocal(method.Body.Variables)) || !value.IsLdcI4() ||
                graph.BlockOf(value) != graph.BlockOf(store) || !graph.HaveIdenticalExceptionRegions(value, store)) continue;
            store.OpCode = OpCodes.Nop; store.Operand = null; value.OpCode = OpCodes.Nop; value.Operand = null;
        }
        var used = il.Select(instruction => instruction.Operand).OfType<Local>().ToHashSet();
        foreach (var local in method.Body.Variables.Where(local => !used.Contains(local)).ToArray()) method.Body.Variables.Remove(local);
        if (stackSafe) Step(() => ControlFlowCompletionPass.RemoveUnreachable(method));
        return EvaluationStackAnalyzer.Analyze(method).Valid;

        int Step(Func<int> rewrite)
        {
            if (!stackSafe) return rewrite();
            using var trial = new BodyMutationBatch([method]);
            var changes = rewrite();
            if (changes < 0 || !EvaluationStackAnalyzer.Analyze(method).Valid) return 0;
            trial.Commit();
            return changes;
        }
    }
}
