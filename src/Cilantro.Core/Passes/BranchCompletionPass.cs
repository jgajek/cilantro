using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Passes;

/// <summary>Finishes branch cleanup after late token and receiver rewrites.</summary>
public sealed class BranchCompletionPass : DeobfuscationPass
{
    public override string Name => "branch-completion";
    public override IReadOnlyCollection<string> Dependencies => ["type-recovery-completion"];
    public override bool GatesEmission => false;

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var total = 0;
        var refused = 0;
        foreach (var method in context.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
        {
            using var edit = new BodyMutationTransaction(method);
            var stack = EvaluationStackAnalyzer.Analyze(method).Diagnostics.Count;
            var forward = ForwardScan.Unnameable(method);
            var changes = 0;
            var stable = false;
            for (var round = 0; round < 16; round++)
            {
                var edges = RedundantControlFlow.ThreadBranches(method);
                changes += edges;
                if (edges != 0 && ControlFlowCompletionPass.TryComplete(method) is { } cleanup)
                    changes += cleanup.Folded + cleanup.Removed;
                var compacted = IlCompactionPass.Compact(method);
                changes += compacted;
                if (edges == 0 && compacted == 0) { stable = true; break; }
            }
            if (!stable || EvaluationStackAnalyzer.Analyze(method).Diagnostics.Count > stack ||
                ForwardScan.Unnameable(method) > forward)
            { refused++; continue; }
            edit.Commit();
            total += changes;
            if (changes != 0) context.AddChange(new(Name, "complete-late-branches", method.FullName,
                $"Applied {changes} branch/padding simplifications to a fixed point after late recovery; preserved exception regions and application switch behavior."));
        }
        return (refused == 0 ? PassStatus.Success : PassStatus.Partial, total,
            [$"Applied {total} late branch/padding simplifications; {refused} method(s) retained after verification or convergence refusal."]);
    }
}
