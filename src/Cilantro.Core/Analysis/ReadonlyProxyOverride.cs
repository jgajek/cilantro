using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Combines observed readonly construction, exact generic inheritance and
/// the checked override query. External/reflection construction remains a caller obligation.</summary>
internal static class ReadonlyProxyOverride
{
    internal static bool RefusesInvokeMember(MethodDef wrapper)
    {
        bool Core(ITypeDefOrRef type, string name) => CoreLibraryIdentity.Matches(wrapper.Module, type, name);
        if (!wrapper.HasBody || wrapper.Body.HasExceptionHandlers || wrapper.IsStatic || wrapper.HasGenericParameters ||
            wrapper.MethodSig.Params.Count != 1 || wrapper.MethodSig.Params[0].ElementType != ElementType.String ||
            wrapper.ReturnType.ElementType != ElementType.Boolean) return false;
        var il = wrapper.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        if (il.Length != 8 || !il[0].IsLdarg() || il[0].GetParameter(wrapper.Parameters) != wrapper.Parameters[0] ||
            il[1].OpCode.Code != Code.Ldfld || il[1].Operand is not IField fieldRef ||
            ReadonlyConstructorValues.ResolveField(fieldRef) is not { } field || field.DeclaringType != wrapper.DeclaringType ||
            il[2].OpCode.Code != Code.Callvirt || il[2].Operand is not IMethod getType || getType.Name != "GetType" ||
            !Core(getType.DeclaringType, "System.Object") || getType.MethodSig is not { HasThis: true, Params.Count: 0 } ||
            !Core(getType.MethodSig.RetType.ToTypeDefOrRef(), "System.Type") ||
            il[3].OpCode.Code != Code.Ldtoken || il[3].Operand is not ITypeDefOrRef baseToken ||
            baseToken.ScopeType.ResolveTypeDef() is not { } baseDefinition || baseDefinition.Module != wrapper.Module ||
            baseDefinition.BaseType is null || !Core(baseDefinition.BaseType, "System.Object") ||
            il[4].OpCode.Code != Code.Call || il[4].Operand is not IMethod fromHandle || fromHandle.Name != "GetTypeFromHandle" ||
            !Core(fromHandle.DeclaringType, "System.Type") || fromHandle.MethodSig is not { HasThis: false, Params.Count: 1 } ||
            !Core(fromHandle.MethodSig.RetType.ToTypeDefOrRef(), "System.Type") ||
            !Core(fromHandle.MethodSig.Params[0].ToTypeDefOrRef(), "System.RuntimeTypeHandle") ||
            !il[5].IsLdarg() || il[5].GetParameter(wrapper.Parameters) != wrapper.Parameters[1] ||
            il[6].OpCode.Code != Code.Call || il[6].Operand is not IMethod queryRef || queryRef.ResolveMethodDef() is not { } query ||
            !InheritedOverrideQuery.IsClosed(query) || il[7].OpCode.Code != Code.Ret) return false;
        // Object has no TryInvokeMember member. Combined with no same-name members
        // in intermediate classes, this closes the query's complete name subset.
        var methods = baseDefinition.Methods.Where(m => m.Name == "TryInvokeMember").ToArray();
        if (methods.Length != 1 || !DecliningDynamicInvocation.IsClosed(methods[0])) return false;
        var construction = ReadonlyConstructorValues.Analyze(field);
        if (!construction.Proven) return false;
        foreach (var site in construction.Constructions)
        {
            var scope = Interpretation.GenericScope.For(site.Constructor, null);
            var expected = scope?.Bind(baseToken.ToTypeSig()) ?? baseToken.ToTypeSig();
            if (expected.ContainsGenericParameter || !InheritedVirtualImplementation.IsUnchanged(site.ValueType, methods[0], expected)) return false;
        }
        return construction.Constructions.Count != 0;
    }
}
