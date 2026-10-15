using Cilantro.Core.Recovery;
using dnlib.DotNet;

namespace Cilantro.Core.Analysis;

/// <summary>Identified, replaced protector types with no references from surviving declarations.</summary>
internal static class ProtectorIslands
{
    internal const string VmTypesFact = "cleanup.orphanedVmTypes";

    internal static HashSet<TypeDef> Find(ArtifactContext context)
    {
        var candidates = new HashSet<TypeDef>();
        if (context.TryGetFact<IReadOnlySet<uint>>(ReactorRuntimeFallbacks.OwnersFact, out var runtimeOwners) && runtimeOwners is not null)
            candidates.UnionWith(context.Module.GetTypes().Where(type => runtimeOwners.Contains(type.MDToken.Raw)).SelectMany(Nest));
        if (context.TryGetFact<IReadOnlySet<uint>>(SharedInitializationCompletionPass.TypesFact, out var sharedTypes) && sharedTypes is not null)
            candidates.UnionWith(context.Module.GetTypes().Where(type => sharedTypes.Contains(type.MDToken.Raw)));
        if (context.TryGetFact<IReadOnlySet<uint>>(StringLookupCompletionPass.TypesFact, out var stringTypes) && stringTypes is not null)
            candidates.UnionWith(context.Module.GetTypes().Where(type => stringTypes.Contains(type.MDToken.Raw)));
        if (context.TryGetFact<IReadOnlySet<uint>>(VmTypesFact, out var engines) && engines is not null)
            candidates.UnionWith(context.Module.GetTypes().Where(type => engines.Contains(type.MDToken.Raw)));
        var orphans = RecoveryOrphans.Of(context);
        if (context.TryGetFact<IReadOnlyList<ProxyBinding>>("proxy.bindings", out var bindings) && bindings is not null)
        {
            var bound = bindings.Select(binding => binding.FieldToken).ToHashSet();
            candidates.UnionWith(context.Module.GetTypes().Where(type =>
                ReactorDetectionPass.IsDelegateProxy(type) &&
                type.Fields.Any(field => field.IsStatic) &&
                type.Fields.Where(field => field.IsStatic).All(field => bound.Contains(field.MDToken.Raw)) &&
                type.Methods.Any(method => orphans.Contains(method.MDToken.Raw))));
        }
        var rebuilt = RebuiltMethods.CleanupRoots(context).ToHashSet();
        candidates.RemoveWhere(type => type.IsGlobalModuleType || Nest(type).Any(member =>
            MemberVisibility.IsExternallyVisible(member) || member.Methods.Any(rebuilt.Contains)));
        return RuntimeCleanupPass.ComputeUnreferenced(context.Module, candidates);
    }

    internal static IEnumerable<TypeDef> Nest(TypeDef type)
    {
        yield return type;
        foreach (var nested in type.NestedTypes)
            foreach (var member in Nest(nested)) yield return member;
    }

    /// <summary>
    /// Computes reachability without an already isolated protector island. This prevents
    /// unrelated reflective construction from keeping its virtual methods alive by signature.
    /// The caller must still check opaque token consumers in the surviving application.
    /// </summary>
    internal static ModuleReachability Without(ArtifactContext context, HashSet<TypeDef> islands)
    {
        var roots = RebuiltMethods.CleanupRoots(context);
        var detached = islands.Where(type => type.DeclaringType is null || !islands.Contains(type.DeclaringType))
            .Select(type =>
            {
                var owner = type.DeclaringType?.NestedTypes ?? context.Module.Types;
                return (Type: type, Owner: owner, Index: owner.IndexOf(type));
            }).ToArray();
        try
        {
            foreach (var item in detached) item.Owner.Remove(item.Type);
            return ModuleReachability.ComputeWithInstances(context.Module, false, roots);
        }
        finally
        {
            foreach (var group in detached.GroupBy(item => item.Owner))
                foreach (var item in group.OrderBy(item => item.Index)) item.Owner.Insert(item.Index, item.Type);
        }
    }
}
