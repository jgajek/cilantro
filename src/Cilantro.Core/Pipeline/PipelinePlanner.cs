using Cilantro.Core.Analysis;

namespace Cilantro.Core.Pipeline;

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
        "metadata-sanitization",
        "boolean-recovery",
        "antitamper-neutralization",
        "loader-call-elision",
        "constant-predicates",
        "constant-strings",
        "babel-literal-strings",
        "dotfuscator-literal-strings",
        "dotfuscator-native-strings",
        "dotfuscator-resources",
        "dotfuscator-checks",
        "dotfuscator-control-flow",
        "babel-proxies",
        "babel-checks",
        "babel-method-images",
        "babel-resource-restoration",
        "babel-hash-strings",
        "babel-proxy-initialization",
        "babel-proxy-inlining",
        "babel-numeric-arrays",
        "babel-numeric-array-cleanup",
        "global-predicate-folding",
        "global-predicate-recheck",
        "dispatcher-deobfuscation",
        "cfg-dead-code",
        "control-flow-completion",
        "control-flow-finalization",
        "reactor-guards-completion",
        "control-flow-recompletion",
        "token-recovery",
        "type-restoration",
        "delegate-proxy-analysis",
        "string-recovery",
        "method-inlining",
        "method-inlining-recheck",
        "proxy-argument-narrowing",
        "stack-handoff",
        "resource-hook-elision",
        "runtime-cleanup",
        "reactor-trial-guard-removal",
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
            facts.Generation != "jit-hook")
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
        "confuserex-detection" or
        "babel-detection" or
        "dotfuscator-detection" or
        "protector-identity" or
        "method-protection" or
        "field-rva-recovery" or
        "resource-analysis" or
        "resource-roles" or
        "control-flow-analysis" => PipelinePhase.Analysis,
        "confuserex-antitamper" or
        "method-body-recovery" or
        "string-table-recovery" or
        "global-state-capture" or
        "boolean-recovery" or
        "metadata-sanitization" => PipelinePhase.OriginalByteRecovery,
        "antitamper-neutralization" or
        "constant-predicates" or
        "constant-strings" or
        "babel-literal-strings" or
        "dotfuscator-literal-strings" or
        "dotfuscator-native-strings" or
        "dotfuscator-resources" or
        "dotfuscator-checks" or
        "dotfuscator-control-flow" or
        "babel-proxies" or
        "babel-checks" or
        "babel-method-images" or
        "babel-resource-restoration" or
        "babel-hash-strings" or
        "babel-proxy-initialization" or
        "babel-proxy-inlining" or
        "babel-numeric-arrays" or
        "babel-numeric-array-cleanup" or
        "confuserex-constants" or
        "global-predicate-folding" or
        "dispatcher-deobfuscation" or
        "cfg-dead-code" or
        "control-flow-completion" or
        "token-recovery" or
        "type-restoration" or
        "method-inlining" or
        "method-inlining-recheck" or
        "delegate-proxy-analysis" or
        "string-recovery" => PipelinePhase.IlTransform,
        _ => PipelinePhase.Finalize
    };
}
