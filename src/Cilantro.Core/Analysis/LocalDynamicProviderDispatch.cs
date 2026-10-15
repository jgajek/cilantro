using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Closes interface dispatch within a local provider hierarchy. This does not
/// assert that a dynamic call's receiver belongs to that hierarchy or exclude external subclasses.</summary>
internal static class LocalDynamicProviderDispatch
{
    internal static bool IsClosed(MethodDef implementation)
    {
        if (!implementation.HasBody || implementation.IsStatic || !implementation.IsFinal || !implementation.IsVirtual ||
            implementation.Body.HasExceptionHandlers || implementation.Overrides.Count != 1 ||
            implementation.Overrides[0].MethodDeclaration is not { } declaration || declaration.Name != "GetMetaObject" ||
            !Provider(declaration.DeclaringType) || !new SigComparer().Equals(declaration.MethodSig, implementation.MethodSig)) return false;
        var il = implementation.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        if (implementation.MethodSig.Params.Count != 1 || il.Length != 4 ||
            !il[0].IsLdarg() || il[0].GetParameter(implementation.Parameters) != implementation.Parameters[0] ||
            !il[1].IsLdarg() || il[1].GetParameter(implementation.Parameters) != implementation.Parameters[1] ||
            il[2].OpCode.Code != Code.Callvirt || il[2].Operand is not IMethod reference ||
            ReadonlyConstructorValues.ResolveMethod(reference) is not { IsVirtual: true, IsNewSlot: true } slot ||
            slot.DeclaringType != implementation.DeclaringType || !new SigComparer().Equals(slot.MethodSig, implementation.MethodSig) ||
            il[3].OpCode.Code != Code.Ret || !implementation.DeclaringType.Interfaces.Any(i => Provider(i.Interface))) return false;
        var root = implementation.DeclaringType;
        var children = implementation.Module.GetTypes().Where(t => t.BaseType?.ScopeType.ResolveTypeDef()?.Module == implementation.Module)
            .ToLookup(t => t.BaseType!.ScopeType.ResolveTypeDef()!);
        var pending = new Queue<(TypeDef Type, MethodDef Factory)>(); pending.Enqueue((root, slot));
        var seen = new HashSet<TypeDef>(); var proven = new HashSet<MethodDef>();
        while (pending.TryDequeue(out var item))
        {
            if (!seen.Add(item.Type) || seen.Count > 4096 || item.Type.HasGenericParameters) return false;
            var factory = item.Factory;
            if (item.Type != root)
            {
                if (item.Type.Interfaces.Any(i => Provider(i.Interface)) || item.Type.Methods.Any(m => m.Overrides.Any(o =>
                    Provider(o.MethodDeclaration.DeclaringType) || o.MethodDeclaration.Name == slot.Name))) return false;
                var replacements = item.Type.Methods.Where(m => m.Name == slot.Name).ToArray();
                if (replacements.Length > 1) return false;
                if (replacements.Length == 1)
                {
                    factory = replacements[0];
                    if (!factory.IsVirtual || factory.IsNewSlot || factory.IsStatic ||
                        !new SigComparer().Equals(factory.MethodSig, slot.MethodSig)) return false;
                }
            }
            if (proven.Add(factory) && !DirectMetaObjectFactory.IsClosed(factory)) return false;
            foreach (var child in children[item.Type]) pending.Enqueue((child, factory));
        }
        return seen.Count != 0;
    }
    private static bool Provider(ITypeDefOrRef type) => type is TypeRef { FullName: "System.Dynamic.IDynamicMetaObjectProvider", ResolutionScope: AssemblyRef a } &&
        ((a.Name == "System.Core" && a.PublicKeyOrToken?.Token.ToString() == "b77a5c561934e089") ||
         (a.Name == "System.Linq.Expressions" && a.PublicKeyOrToken?.Token.ToString() == "b03f5f7f11d50a3a"));
}
