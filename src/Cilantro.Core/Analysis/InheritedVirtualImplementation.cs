using dnlib.DotNet;

namespace Cilantro.Core.Analysis;

/// <summary>Proves an exact local runtime type inherits a specified virtual body unchanged.
/// Overrides and same-name shadowing conservatively refuse; this does not prove receiver provenance.</summary>
internal static class InheritedVirtualImplementation
{
    internal static bool IsUnchanged(TypeSig exactRuntimeType, MethodDef declaration, TypeSig? expectedDeclaringType = null)
    {
        if (!declaration.IsVirtual || declaration.IsStatic || declaration.IsAbstract || !declaration.HasBody ||
            declaration.HasGenericParameters || exactRuntimeType.ContainsGenericParameter) return false;
        var seen = new HashSet<TypeDef>();
        TypeSig? current = exactRuntimeType;
        while (current is not null)
        {
            if (current is not (ClassSig or GenericInstSig) || current.ToTypeDefOrRef()?.ResolveTypeDef() is not { } type ||
                type.Module != declaration.Module || type.IsInterface || type.IsValueType || !seen.Add(type) || seen.Count > 128) return false;
            var arguments = (current as GenericInstSig)?.GenericArguments;
            if (type.GenericParameters.Count != (arguments?.Count ?? 0)) return false;
            if (type == declaration.DeclaringType) return expectedDeclaringType is null || new SigComparer().Equals(current, expectedDeclaringType);
            // Explicit MethodImpl records may use a different body name. Refuse
            // even unrelated records rather than assume their slot mapping.
            if (type.Methods.Any(m => m.Name == declaration.Name || m.Overrides.Count != 0)) return false;
            if (type.BaseType is null) return false;
            current = new Interpretation.GenericScope(arguments, null).Bind(type.BaseType.ToTypeSig());
            if (current?.ContainsGenericParameter != false) return false;
        }
        return false;
    }
}
