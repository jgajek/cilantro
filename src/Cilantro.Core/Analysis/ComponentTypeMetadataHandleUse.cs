using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Recognizes component-type metadata with no observed application consumer.
/// This scopes private-helper repair to the recovered application, not arbitrary external
/// callers reflecting over a descriptor's publicly returned Type.</summary>
internal static class ComponentTypeMetadataHandleUse
{
    internal static bool IsClosed(MethodDef method, Instruction token)
    {
        var module = method.Module;
        var owner = method.DeclaringType;
        if (!method.HasBody || method.IsStatic || !method.IsPublic || !method.IsVirtual || method.IsNewSlot ||
            method.HasGenericParameters || owner.HasGenericParameters || method.Overrides.Count != 0 ||
            method.Name != "get_ComponentType" || method.CustomAttributes.Count != 0 ||
            method.Body.ExceptionHandlers.Count != 0 ||
            owner.BaseType is not TypeRef { FullName: "System.ComponentModel.PropertyDescriptor", ResolutionScope: AssemblyRef assembly } ||
            assembly.Name != "System" || assembly.Version.Major != 4 ||
            !assembly.FullName.EndsWith(", PublicKeyToken=b77a5c561934e089", StringComparison.OrdinalIgnoreCase)) return false;
        bool Core(ITypeDefOrRef type, string name) => CoreLibraryIdentity.Matches(module, type, name);
        if (method.MethodSig is not { HasThis: true, ExplicitThis: false, GenParamCount: 0, Params.Count: 0, ParamsAfterSentinel: null } signature ||
            (signature.GetCallingConvention() & CallingConvention.Mask) != CallingConvention.Default ||
            !Core(signature.RetType.ToTypeDefOrRef(), "System.Type")) return false;
        var properties = owner.Properties.Where(p => p.GetMethods.Contains(method)).ToArray();
        if (properties.Length != 1 || properties[0].Name != "ComponentType" || properties[0].CustomAttributes.Count != 0 ||
            properties[0].GetMethods.Count != 1 || properties[0].SetMethods.Count != 0 || properties[0].OtherMethods.Count != 0 ||
            properties[0].PropertySig is not { HasThis: true, Params.Count: 0 } property ||
            !Core(property.RetType.ToTypeDefOrRef(), "System.Type")) return false;
        var il = method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        if (il.Length != 3 || il[0] != token || token.OpCode.Code != Code.Ldtoken || token.Operand is not ITypeDefOrRef ||
            il[1].OpCode.Code != Code.Call || il[1].Operand is not IMethod conversion ||
            conversion is MethodSpec || conversion.Name != "GetTypeFromHandle" || !Core(conversion.DeclaringType, "System.Type") ||
            conversion.MethodSig is not { HasThis: false, ExplicitThis: false, GenParamCount: 0, Params.Count: 1, ParamsAfterSentinel: null } convert ||
            (convert.GetCallingConvention() & CallingConvention.Mask) != CallingConvention.Default ||
            !Core(convert.RetType.ToTypeDefOrRef(), "System.Type") || !Core(convert.Params[0].ToTypeDefOrRef(), "System.RuntimeTypeHandle") ||
            il[2].OpCode.Code != Code.Ret) return false;
        foreach (var type in module.GetTypes())
        {
            // A local subclass could use the getter through inherited protected helpers.
            if (type.BaseType?.ScopeType.ResolveTypeDef() == owner) return false;
            foreach (var body in type.Methods.Where(m => m.HasBody))
            foreach (var use in body.Body.Instructions)
            {
                // Explicit readers and handles may route the returned Type to reflection.
                // Refuse even a reader whose result appears harmless rather than assuming
                // the framework metadata contract also constrains application code.
                if (use.Operand is IMethod member && member.Name == "get_ComponentType") return false;
                if (use.OpCode.Code == Code.Ldstr && use.Operand is string name &&
                    (name is "ComponentType" or "get_ComponentType" || name == method.FullName || name == owner.FullName)) return false;
                if (use.OpCode.Code == Code.Ldtoken && use.Operand is ITypeDefOrRef handle && handle.ScopeType.ResolveTypeDef() == owner) return false;
            }
        }
        return true;
    }
}
