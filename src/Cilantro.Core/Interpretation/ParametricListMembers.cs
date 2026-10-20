using dnlib.DotNet;

namespace Cilantro.Core.Interpretation;

/// <summary>Reviewed List metadata, never collection execution or host generic construction.</summary>
internal static class ParametricListMembers
{
    internal static IMethod? Bind(ModuleDef module, GenericInstSig owner, string name, int flags, IReadOnlyList<TypeSig> parameters)
    {
        if (owner.GenericType is not ClassSig || owner.GenericType.FullName != "System.Collections.Generic.List`1" || owner.GenericArguments.Count != 1 ||
            !LoaderFrameworkIntrinsic.GenericArgument(owner.GenericArguments[0], 0) ||
            owner.GenericType.TypeDefOrRef.ResolveTypeDef()?.Module == module ||
            owner.GenericType.TypeDefOrRef.DefinitionAssembly is not AssemblyRef scope || !Framework(scope) ||
            (flags & ~0x7E) != 0 || (flags & 0x14) != 0x14 || name is not (".ctor" or "get_Item" or "set_Item" or "Add")) return null;
        // These APIs have the same single public instance signature in the
        // reviewed Framework 4.8 and CoreCLR targets. No host method is invoked.
        TypeSig returns;
        TypeSig[] unbound;
        if (name == ".ctor") { returns = module.CorLibTypes.Void; unbound = []; }
        else if (name == "get_Item") { returns = new GenericVar(0); unbound = [module.CorLibTypes.Int32]; }
        else if (name == "set_Item") { returns = module.CorLibTypes.Void; unbound = [module.CorLibTypes.Int32, new GenericVar(0)]; }
        else { returns = module.CorLibTypes.Void; unbound = [new GenericVar(0)]; }
        if (unbound.Length != parameters.Count) return null;
        var binding = new GenericScope(owner.GenericArguments, null);
        for (var index = 0; index < parameters.Count; index++)
        {
            var expected = binding.Bind(unbound[index]);
            if (expected is null || !Same(expected, parameters[index])) return null;
        }
        return new MemberRefUser(module, name, MethodSig.CreateInstance(returns, unbound), owner.ToTypeDefOrRef());
    }

    private static bool Same(TypeSig left, TypeSig right)
    {
        if (ReferenceEquals(left, right)) return true;
        if (left is GenericSig || right is GenericSig) return false;
        if (left is GenericInstSig a && right is GenericInstSig b)
            return Same(a.GenericType, b.GenericType) && a.GenericArguments.Count == b.GenericArguments.Count && a.GenericArguments.Zip(b.GenericArguments).All(pair => Same(pair.First, pair.Second));
        if (left is SZArraySig x && right is SZArraySig y) return Same(x.Next, y.Next);
        if (left is CorLibTypeSig && right is CorLibTypeSig) return left.ElementType == right.ElementType;
        return left.ElementType == right.ElementType && left.FullName == right.FullName &&
            left.ToTypeDefOrRef()?.DefinitionAssembly?.FullName == right.ToTypeDefOrRef()?.DefinitionAssembly?.FullName;
    }

    private static bool Framework(AssemblyRef scope) => UTF8String.IsNullOrEmpty(scope.Culture) &&
        (scope.Name.String, scope.PublicKeyOrToken?.Token?.ToString()) is
            ("mscorlib", "b77a5c561934e089") or ("System.Private.CoreLib", "7cec85d7bea7798e") or
            ("System.Collections", "b03f5f7f11d50a3a") or ("System.Runtime", "b03f5f7f11d50a3a") or ("netstandard", "cc7b13ffcd2ddd51");
}
