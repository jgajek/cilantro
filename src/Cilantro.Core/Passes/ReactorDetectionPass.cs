using dnlib.DotNet;
using Cilantro.Core.Analysis;
using Cilantro.Core.Codec;

namespace Cilantro.Core;

public sealed class ReactorDetectionPass : DeobfuscationPass
{
    public override string Name => "reactor-detection";
    public override IReadOnlyCollection<string> Dependencies => ["metadata-preflight"];

    // A detector that finds its protector absent has answered, not failed. Whether the run
    // recognized anything at all is settled once, by protector-identity.
    public override bool GatesEmission => false;

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var facts = ReactorStructureDetector.Analyze(context.Module);
        var strategy = new StructuralReactor6Strategy().Match(context.Module, facts);
        context.SetFact("reactor.structure", facts);
        context.SetFact("reactor.delegateTypes", facts.DelegateProxyCount);
        context.SetFact("reactor.deadPrefixes", facts.DeadCallPrefixCount);
        context.AddEvidence(new Evidence(
            "protector",
            $".NET Reactor {facts.Generation}: {string.Join(", ", strategy.Evidence)}.",
            Confidence: facts.Confidence));
        foreach (var capability in facts.IsReactor ? facts.CapabilityNames : [])
        {
            context.AddEvidence(new Evidence(
                "capability",
                capability,
                Confidence: facts.Confidence));
        }

        // Naming the virtualized methods is worth more than counting them: an analyst who knows
        // which method is missing knows what the report does not cover.
        var virtualized = VirtualizedMethodDetector.Detect(context.Module);
        context.SetFact("virtualization.methods", virtualized);
        foreach (var method in virtualized)
        {
            context.AddEvidence(new Evidence(
                "virtualized-method",
                $"Body replaced by program {method.ProgramId} of the interpreter at " +
                $"{method.Entry.DeclaringType?.Name}::{method.Entry.Name}.",
                $"{method.Stub.MDToken} {method.Stub.FullName}",
                0.95));
        }

        var status = facts.IsReactor ? PassStatus.Success : PassStatus.Unsupported;
        return (status, 0,
        [
            $"Detection confidence: {facts.Confidence:P0}",
            $"Generation: {facts.Generation}",
            $"Capabilities: {string.Join(", ", facts.CapabilityNames)}",
            virtualized.Count == 0
                ? "No method was found to have been replaced by interpreter bytecode."
                : $"{virtualized.Count} method(s) were replaced by interpreter bytecode."
        ]);
    }

    public static bool IsDelegateProxy(TypeDef type) =>
        ReactorStructureDetector.IsDelegateProxy(type);

    internal static bool HasDeadCallPrefix(MethodDef method)
        => ReactorStructureDetector.HasDeadCallPrefix(method);
}
