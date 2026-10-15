using dnlib.DotNet;

namespace Cilantro.Core.Verification;

internal static class LocalMemberReferenceValidation
{
    internal const string BeforeRenameFact = "rename.unresolvedLocalMembersBefore";

    internal static bool IsLocal(ModuleDef module, MemberRef reference)
    {
        var owner = Owner(reference);
        return owner is TypeDef definition && definition.Module == module ||
            owner is TypeRef type && LocalTypeReferenceValidation.IsLocal(module, type);
    }

    private static ITypeDefOrRef Owner(MemberRef reference) => reference.DeclaringType is
        TypeSpec { TypeSig: GenericInstSig generic } ? generic.GenericType.TypeDefOrRef : reference.DeclaringType;

    internal static bool IsUnresolved(MemberRef reference, IReadOnlyDictionary<string, TypeDef> definitions)
    {
        // Resolve same-module owners directly. A byte-loaded module need not have an
        // assembly resolver capable of opening its ModuleRef from disk.
        var owner = Owner(reference);
        var definition = owner as TypeDef ?? definitions.GetValueOrDefault(owner.FullName);
        var seen = new HashSet<TypeDef>();
        while (definition is not null && seen.Add(definition))
        {
            if (reference.IsMethodRef && definition.FindMethod(reference.Name, reference.MethodSig) is not null ||
                reference.IsFieldRef && definition.FindField(reference.Name, reference.FieldSig) is not null) return false;
            var parent = definition.BaseType;
            definition = parent is null ? null : definitions.GetValueOrDefault(parent.FullName) ?? parent.ResolveTypeDef();
        }
        return reference.IsMethodRef ? reference.ResolveMethod() is null : reference.IsFieldRef && reference.ResolveField() is null;
    }

    internal static IEnumerable<string> NewlyUnresolved(ModuleDef module, IReadOnlySet<string> allowed)
    {
        var definitions = module.GetTypes().GroupBy(type => type.FullName).Where(group => group.Count() == 1)
            .ToDictionary(group => group.Key, group => group.Single());
        return new MemberFinder().FindAll(module).MemberRefs.Keys
            .Where(reference => IsLocal(module, reference) && IsUnresolved(reference, definitions) && !allowed.Contains(reference.FullName))
            .Select(reference => reference.FullName).Distinct(StringComparer.Ordinal).ToArray();
    }
}
