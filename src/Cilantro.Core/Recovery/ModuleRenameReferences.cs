using dnlib.DotNet;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Recovery;

/// <summary>Binds name-based references before their local definitions are renamed.</summary>
internal sealed class ModuleRenameReferences
{
    private readonly Dictionary<TypeRef, TypeDef> types = [];
    private readonly Dictionary<MemberRef, IMemberDef> members = [];
    internal IReadOnlySet<string> UnresolvedBefore => unresolvedBefore;
    private readonly HashSet<string> unresolvedBefore = new(StringComparer.Ordinal);
    private readonly List<MemberRef> unresolvedMembers = [];
    // Read after Apply: enclosing type names may have changed even for an input's
    // already-missing member. Preserve that distinction from newly broken bindings.
    internal IReadOnlySet<string> UnresolvedMembersBefore =>
        unresolvedMembers.Select(reference => reference.FullName).ToHashSet(StringComparer.Ordinal);

    internal ModuleRenameReferences(ModuleDef module)
    {
        var definitions = module.GetTypes().GroupBy(type => type.FullName)
            .Where(group => group.Count() == 1).ToDictionary(group => group.Key, group => group.Single());
        // Include references newly introduced by recovery as well as metadata rows.
        var finder = new MemberFinder().FindAll(module);
        foreach (var reference in finder.TypeRefs.Keys)
        {
            if (!LocalTypeReferenceValidation.IsLocal(module, reference)) continue;
            if (definitions.TryGetValue(reference.FullName, out var definition)) types.Add(reference, definition);
            else unresolvedBefore.Add(reference.FullName);
        }
        foreach (var reference in finder.MemberRefs.Keys)
        {
            if (LocalMemberReferenceValidation.IsLocal(module, reference) &&
                LocalMemberReferenceValidation.IsUnresolved(reference, definitions)) unresolvedMembers.Add(reference);
            var declaring = reference.DeclaringType;
            if (declaring is TypeSpec { TypeSig: GenericInstSig generic }) declaring = generic.GenericType.TypeDefOrRef;
            var owner = declaring is TypeDef definition && definition.Module == module ? definition :
                declaring is TypeRef type ? types.GetValueOrDefault(type) : null;
            if (owner is null) continue;
            IMemberDef? target = reference.IsMethodRef ? owner.FindMethod(reference.Name, reference.MethodSig) :
                reference.IsFieldRef ? owner.FindField(reference.Name, reference.FieldSig) : null;
            // MemberRef can name a derived type while binding an inherited member.
            // Resolve before renaming, and never capture a definition in another module.
            target ??= reference.IsMethodRef ? reference.ResolveMethod() :
                reference.IsFieldRef ? reference.ResolveField() : null;
            if (target?.DeclaringType?.Module != module) continue;
            if (target is not null) members.Add(reference, target);
        }
    }

    internal void Apply()
    {
        foreach (var (reference, definition) in types)
        {
            reference.Name = definition.Name;
            reference.Namespace = definition.Namespace;
        }
        foreach (var (reference, definition) in members) reference.Name = definition.Name;
    }
}
