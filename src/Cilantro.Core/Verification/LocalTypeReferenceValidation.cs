using dnlib.DotNet;

namespace Cilantro.Core.Verification;

internal static class LocalTypeReferenceValidation
{
    internal const string BeforeRenameFact = "rename.unresolvedLocalTypesBefore";

    internal static bool IsLocal(ModuleDef module, TypeRef reference)
    {
        IResolutionScope scope = reference.ResolutionScope;
        var seen = new HashSet<TypeRef>();
        while (scope is TypeRef enclosing && seen.Add(enclosing)) scope = enclosing.ResolutionScope;
        return ReferenceEquals(scope, module) ||
            scope is ModuleRef moduleRef && moduleRef.Module == module && moduleRef.Name == module.Name ||
            scope is AssemblyRef assembly && module.Assembly is { } own && assembly.FullName == own.FullName;
    }

    internal static IEnumerable<string> NewlyUnresolved(ModuleDef module, IReadOnlySet<string> allowed)
    {
        var definitions = module.GetTypes().Select(type => type.FullName).ToHashSet(StringComparer.Ordinal);
        return new MemberFinder().FindAll(module).TypeRefs.Keys
            .Where(reference => IsLocal(module, reference) && !definitions.Contains(reference.FullName) && !allowed.Contains(reference.FullName))
            .Select(reference => reference.FullName).Distinct(StringComparer.Ordinal).ToArray();
    }
}
