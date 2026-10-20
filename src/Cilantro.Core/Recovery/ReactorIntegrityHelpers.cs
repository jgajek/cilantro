using Cilantro.Core.Analysis;
using dnlib.DotNet;

namespace Cilantro.Core.Recovery;

/// <summary>Attributes self-integrity helpers on independently recovered Reactor runtime owners.</summary>
internal static class ReactorIntegrityHelpers
{
    internal static IReadOnlyList<MethodDef> Find(ArtifactContext context)
        => Owners(context).SelectMany(t => t.Methods).Where(m => !m.IsConstructor &&
            MemoryIntegrityCompletionPass.SelectLocation(m) is not null).ToArray();

    internal static IReadOnlyList<TypeDef> Owners(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("method-protection.complete", out var complete) || !complete ||
            !context.TryGetFact<ReactorStructureFacts>("reactor.structure", out var reactor) || reactor?.IsReactor != true ||
            !context.TryGetFact<IReadOnlyList<DecodedResourceOwnership>>(DecodedResourceOwnership.Fact, out var records) || records is null)
            return [];
        // A generated name alone is insufficient. Require independent successful string
        // and proxy rewrites on the same owner, using different exact input resources.
        // Namespace spelling is not evidence of ownership: Reactor can choose a low-churn name.
        var strings = records.Where(r => !r.IsNumericConstruction && !r.IsMethodImageConstruction && r.Bundle is null && r.ProxyTypes.Count == 0).ToArray();
        var proxies = records.Where(r => r.Bundle is null && r.ProxyTypes.Count != 0).ToArray();
        var owners = strings.SelectMany(s => s.ReaderOwners.Select(owner => (Record: s, Owner: owner)))
            .Where(p => p.Owner is not null && p.Owner.Module == context.Module && !p.Owner.IsGlobalModuleType &&
                ReactorNameHeuristics.IsGeneratedName(p.Owner.Name.String) &&
                proxies.Any(proxy => proxy.Resource != p.Record.Resource && proxy.ReaderOwners.Contains(p.Owner)))
            .Select(p => p.Owner).Distinct();
        // An owner qualifies for further method-specific recognition, not blanket
        // attribution of every sibling. Cleanup independently checks visibility,
        // reachability, handles, accessors and surviving declaration references.
        return owners.ToArray();
    }
}
