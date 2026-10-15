using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Exact signature data retired by a verified memory-load integrity rewrite.</summary>
internal sealed class RetiredIntegrityResource
{
    internal const string Fact = "integrity.retiredResourceProofs";
    private readonly MethodDef checker;
    private readonly string signature;
    private readonly MethodBodySnapshot replacement;
    internal RecoveredResourceOrigin Source { get; }

    private RetiredIntegrityResource(MethodDef method, RecoveredResourceOrigin source)
    {
        checker = method; signature = method.FullName;
        replacement = MethodBodySnapshot.Capture(method); Source = source;
    }

    internal static RecoveredResourceOrigin? Candidate(ArtifactContext context, MethodDef method)
    {
        if (!context.TryGetFact<LoaderInterpretationEvidence>("bootstrap.moduleFileRefusalEvidence", out var evidence) ||
            evidence is null || evidence.ObservationsTruncated) return null;
        var reads = evidence.Observations.Where(o => o.Kind == LoaderObservationKind.ManagedResourceRead &&
            o.CallStack.Contains(method.MDToken.Raw)).Select(o =>
                System.Text.Json.JsonSerializer.Deserialize<ManagedResourceRead>(o.Detail)).ToArray();
        if (reads.Length == 0 || reads.Any(r => r is null)) return null;
        var origins = reads.Select(r => new RecoveredResourceOrigin(r!.Name, r.Sha256)).Distinct().ToArray();
        if (origins.Length != 1 || context.Module.Resources.Count(r => r.Name == origins[0].Name) != 1 ||
            !context.Module.Resources.OfType<EmbeddedResource>().Any(origins[0].Matches) ||
            !method.Body.Instructions.Any(i => i.OpCode.Code == Code.Ldstr && Equals(i.Operand, origins[0].Name))) return null;
        return origins[0];
    }

    // Call only after the memory-load rewrite, independent startup comparison and
    // structural verification have committed. Remaining readers still block cleanup.
    internal static void Remember(ArtifactContext context, MethodDef method, RecoveredResourceOrigin? source)
    {
        if (source is null || !method.HasBody || method.Body.Instructions.Any(i => Equals(i.Operand, source.Name))) return;
        context.TryGetFact<IReadOnlyList<RetiredIntegrityResource>>(Fact, out var prior);
        context.SetFact<IReadOnlyList<RetiredIntegrityResource>>(Fact, [.. prior ?? [], new(method, source)]);
        context.AddEvidence(new Evidence("integrity-resource-retirement",
            $"Verified memory-load cleanup retired the observed use of {source.Name} (SHA-256 {source.Sha256}); resource removal still requires the replacement and remaining-reader checks.", method.FullName));
    }

    internal bool IsPreserved(ModuleDef module)
    {
        if (module.Resources.Count(r => r.Name == Source.Name) != 1 ||
            !module.Resources.OfType<EmbeddedResource>().Any(Source.Matches)) return false;
        var surviving = module.GetTypes().SelectMany(t => t.Methods).Contains(checker);
        return !surviving || checker.FullName == signature && replacement.StructurallyEquals(checker);
    }
}
