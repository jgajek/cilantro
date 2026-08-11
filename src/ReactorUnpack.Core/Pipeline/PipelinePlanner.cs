using ReactorUnpack.Core.Analysis;

namespace ReactorUnpack.Core.Pipeline;

public enum PipelinePhase
{
    Preflight,
    Analysis,
    OriginalByteRecovery,
    IlTransform,
    Finalize
}

public sealed record PlannedPass(
    IDeobfuscationPass Pass,
    PipelinePhase Phase,
    bool MutatesModule);

public sealed record PassExecutionDecision(bool Execute, string? Reason);

public static class PipelinePlanner
{
    private static readonly HashSet<string> MutatingPasses =
    [
        "boolean-recovery",
        "antitamper-neutralization",
        "constant-predicates",
        "dispatcher-deobfuscation",
        "cfg-dead-code",
        "control-flow-completion",
        "token-recovery",
        "type-restoration",
        "method-inlining",
        "delegate-proxy-analysis",
        "string-recovery",
        "runtime-cleanup",
        "symbol-renaming"
    ];

    public static IReadOnlyList<PlannedPass> Plan(IEnumerable<IDeobfuscationPass> passes) =>
        passes.Select(pass => new PlannedPass(
            pass,
            PhaseOf(pass.Name),
            MutatingPasses.Contains(pass.Name))).ToArray();

    public static PassExecutionDecision Decide(PlannedPass planned, ArtifactContext context)
    {
        if (!planned.MutatesModule)
            return new PassExecutionDecision(true, null);
        if (!context.TryGetFact<ReactorStructureFacts>("reactor.structure", out var facts) ||
            facts is null ||
            facts.Generation != "reactor6-jit-hook")
        {
            return new PassExecutionDecision(true, null);
        }

        if (context.TryGetFact<bool>("method-protection.complete", out var complete) && complete)
            return new PassExecutionDecision(true, null);
        return new PassExecutionDecision(
            false,
            "Skipped because JIT-hook method recovery is incomplete; original IL was preserved.");
    }

    private static PipelinePhase PhaseOf(string pass) => pass switch
    {
        "metadata-preflight" => PipelinePhase.Preflight,
        "reactor-detection" or
        "method-protection" or
        "field-rva-recovery" or
        "resource-analysis" or
        "resource-roles" or
        "control-flow-analysis" => PipelinePhase.Analysis,
        "method-body-recovery" or
        "string-table-recovery" or
        "boolean-recovery" => PipelinePhase.OriginalByteRecovery,
        "antitamper-neutralization" or
        "constant-predicates" or
        "dispatcher-deobfuscation" or
        "cfg-dead-code" or
        "control-flow-completion" or
        "token-recovery" or
        "type-restoration" or
        "method-inlining" or
        "delegate-proxy-analysis" or
        "string-recovery" => PipelinePhase.IlTransform,
        _ => PipelinePhase.Finalize
    };
}
