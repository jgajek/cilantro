using Cilantro.Core.Analysis;
using dnlib.DotNet;

namespace Cilantro.Core.Recovery;

/// <summary>Exact resources consumed by successfully retired private numeric construction.</summary>
internal sealed record NumericResourceOwnership(TypeDef Owner, RecoveredResourceOrigin Resource)
{
    internal const string Fact = "numeric.resourceOwners";

    internal static IEnumerable<RecoveredResourceOrigin> RemovedOrigins(ArtifactContext context)
    {
        if (!context.TryGetFact<IReadOnlyList<NumericResourceOwnership>>(Fact, out var owners) || owners is null)
            return [];
        var surviving = context.Module.GetTypes().ToHashSet();
        // Retirement alone is insufficient. Keep the resource until cleanup has
        // physically removed its owning holder, then apply the common consumer,
        // application-role and exact-byte checks in resource cleanup.
        return owners.Where(item => !surviving.Contains(item.Owner)).Select(item => item.Resource).Distinct().ToArray();
    }
}
