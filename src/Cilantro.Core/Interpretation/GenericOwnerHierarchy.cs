using dnlib.DotNet;

namespace Cilantro.Core.Interpretation;

/// <summary>Bounded local inheritance, ending at Object or an opaque external base.</summary>
internal static class GenericOwnerHierarchy
{
    internal sealed record Layer(TypeDef Definition, TypeSig Type);

    internal static bool TryRead(TypeSig owner, out IReadOnlyList<Layer> layers) => TryRead(owner, out layers, out _);

    internal static bool TryRead(TypeSig owner, out IReadOnlyList<Layer> layers, out TypeSig? externalBase)
    {
        layers = [];
        externalBase = null;
        var root = owner.ToTypeDefOrRef()?.ResolveTypeDef();
        if (root is null) return false;
        var chain = new List<Layer>();
        var seen = new HashSet<TypeDef>();
        var current = owner;
        while (chain.Count < 16)
        {
            var budget = 256;
            if (!WithinBounds(current, 0, ref budget)) return false;
            if (current is not ClassSig && current is not GenericInstSig { GenericType: ClassSig }) return false;
            var definition = current.ToTypeDefOrRef()?.ResolveTypeDef();
            if (definition is null || definition.Module != root.Module || definition.IsValueType || definition.IsInterface ||
                !seen.Add(definition) || definition.GenericParameters.Count > 8 || definition.Fields.Count > 2048 ||
                definition.GenericParameters.Any(parameter => (parameter.Flags & ~GenericParamAttributes.SpecialConstraintMask) != GenericParamAttributes.NonVariant)) return false;
            var arguments = current is GenericInstSig instance ? instance.GenericArguments : Array.Empty<TypeSig>();
            if (arguments.Count != definition.GenericParameters.Count || definition.BaseType is null) return false;
            chain.Add(new(definition, current));
            var parent = definition.BaseType.ToTypeSig();
            if (!Legal(parent, definition.GenericParameters.Count, 0)) return false;
            var bound = new GenericScope(arguments, null).Bind(parent);
            if (bound is null) return false;
            if (new SigComparer().Equals(bound.ToTypeDefOrRef(), root.Module.CorLibTypes.Object.TypeDefOrRef))
            {
                layers = chain;
                return true;
            }
            var nominal = bound is GenericInstSig instanceBase ? instanceBase.GenericType : bound as ClassSig;
            // The existing receiver carries this exact base expression. No external
            // layout, constructor, constraints or ancestry is inferred from it.
            // Same-assembly aliases must still resolve through the local chain.
            if (nominal is ClassSig { TypeDefOrRef: TypeRef reference } && reference.DefinitionAssembly is AssemblyRef assembly &&
                !UTF8String.IsNullOrEmpty(assembly.Name) && assembly.FullName != root.Module.Assembly?.FullName &&
                reference.ResolveTypeDef()?.Module != root.Module)
            {
                var remaining = 256;
                if (!WithinBounds(bound, 0, ref remaining)) return false;
                layers = chain;
                externalBase = bound;
                return true;
            }
            current = bound;
        }
        return false;
    }

    private static bool WithinBounds(TypeSig type, int depth, ref int budget)
    {
        if (depth > 32 || --budget < 0) return false;
        if (type is GenericInstSig instance)
            foreach (var argument in instance.GenericArguments)
                if (!WithinBounds(argument, depth + 1, ref budget)) return false;
        return type.Next is not { } next || WithinBounds(next, depth + 1, ref budget);
    }

    private static bool Legal(TypeSig type, int variables, int depth)
    {
        if (depth > 32) return false;
        return type switch
        {
            GenericVar variable => variable.Number < variables,
            GenericInstSig instance => instance.GenericArguments.Count <= 8 && instance.GenericArguments.All(argument => Legal(argument, variables, depth + 1)),
            SZArraySig array => Legal(array.Next, variables, depth + 1),
            ClassOrValueTypeSig => true,
            CorLibTypeSig primitive => primitive.ElementType is not (ElementType.Void or ElementType.TypedByRef),
            _ => false
        };
    }
}
