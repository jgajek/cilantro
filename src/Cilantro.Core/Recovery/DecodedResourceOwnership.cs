using Cilantro.Core.Analysis;
using dnlib.DotNet;

namespace Cilantro.Core.Recovery;

/// <summary>Exact decoded inputs whose resolver family must disappear before metadata retirement.</summary>
internal sealed record DecodedResourceOwnership(RecoveredResourceOrigin Resource,
    IReadOnlyList<MethodDef> Readers, IReadOnlyList<TypeDef> ProxyTypes, RestoredResourceBundle? Bundle)
{
    internal const string Fact = "cleanup.decodedResourceOwners";

    // dnlib clears a method's DeclaringType when cleanup removes it. Preserve the
    // positively observed owner identity before retirement detaches those readers.
    internal IReadOnlyList<TypeDef> ReaderOwners { get; } = Readers
        .Select(m => m.DeclaringType).Where(t => t is not null).Distinct().ToArray();

    internal static void Remember(ArtifactContext context, RecoveredResourceOrigin resource,
        IEnumerable<MethodDef> readers, IEnumerable<TypeDef>? proxyTypes = null, RestoredResourceBundle? bundle = null)
    {
        var methods = readers.Distinct().ToArray();
        var types = proxyTypes?.Distinct().ToArray() ?? [];
        // Publish only after a successful rewrite or complete bundle restoration.
        // Empty/foreign ownership and ambiguous resource identities prove nothing.
        if (methods.Length == 0 || methods.Any(m => m.Module != context.Module) || types.Any(t => t.Module != context.Module) ||
            context.Module.Resources.Count(r => r.Name == resource.Name) != 1 ||
            !context.Module.Resources.OfType<EmbeddedResource>().Any(resource.Matches) ||
            bundle is not null && (bundle.Source != resource || !bundle.IsPreserved(context.Module))) return;
        context.TryGetFact<IReadOnlyList<DecodedResourceOwnership>>(Fact, out var earlier);
        context.SetFact<IReadOnlyList<DecodedResourceOwnership>>(Fact, [.. earlier ?? [], new(resource, methods, types, bundle)]);
    }

    internal static IReadOnlyList<RecoveredResourceOrigin> ObservedOwnedReads(ArtifactContext context,
        Interpretation.LoaderInterpretationEvidence evidence, IReadOnlySet<TypeDef> owners)
    {
        if (!evidence.HasCompleteObservations(Interpretation.LoaderObservationKind.ManagedResourceRead)) return [];
        var tokens = owners.Where(t => t.Module == context.Module).SelectMany(t => t.Methods)
            .Where(m => m.Rid != 0).Select(m => m.MDToken.Raw).ToHashSet();
        var reads = new List<(Interpretation.ManagedResourceRead Read, bool Owned)>();
        foreach (var observation in evidence.Observations.Where(o => o.Kind == Interpretation.LoaderObservationKind.ManagedResourceRead))
        {
            Interpretation.ManagedResourceRead? read;
            try { read = System.Text.Json.JsonSerializer.Deserialize<Interpretation.ManagedResourceRead>(observation.Detail); }
            catch (System.Text.Json.JsonException) { return []; }
            if (read is null) return [];
            reads.Add((read, observation.CallStack.Count != 0 && tokens.Contains(observation.CallStack[^1])));
        }
        return reads.GroupBy(p => p.Read.Name).Where(group => group.All(p => p.Owned))
            .Select(group => (Group: group, Resources: context.Module.Resources.OfType<EmbeddedResource>()
                .Where(r => r.Name == group.Key).ToArray()))
            .Where(p => p.Resources.Length == 1 && context.Module.Resources.Count(r => r.Name == p.Group.Key) == 1 &&
                p.Group.All(r => r.Read.Length == p.Resources[0].CreateReader().Length &&
                    new RecoveredResourceOrigin(r.Read.Name, r.Read.Sha256).Matches(p.Resources[0])))
            .Select(p => RecoveredResourceOrigin.Capture(p.Resources[0])).OrderBy(p => p.Name, StringComparer.Ordinal).ToArray();
    }
    internal static IReadOnlyList<RecoveredResourceOrigin> RemovedOrigins(ArtifactContext context)
    {
        if (!context.TryGetFact<IReadOnlyList<DecodedResourceOwnership>>(Fact, out var owners) || owners is null) return [];
        var types = context.Module.GetTypes().ToHashSet();
        var methods = types.SelectMany(t => t.Methods).ToHashSet();
        // Group repeated observations: one removed reader must not hide a surviving
        // alias/family observed by a different recovery pass for the same source.
        return owners.GroupBy(o => o.Resource).Where(group => group.All(o => o.Readers.Count != 0 &&
            o.Readers.All(m => !methods.Contains(m)) && o.ProxyTypes.All(t => !types.Contains(t)) &&
            (o.Bundle is null || o.Bundle.IsPreserved(context.Module))))
            .Select(group => group.Key).ToArray();
    }
}
