using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Recognizes a side-effect-free dynamic invocation refusal, apart from
/// assigning null to its out result. Receiver/override provenance is a separate obligation.</summary>
internal static class DecliningDynamicInvocation
{
    internal static bool IsClosed(MethodDef method)
    {
        if (!method.HasBody || method.IsStatic || method.HasGenericParameters || method.Body.HasExceptionHandlers ||
            method.MethodSig is not { HasThis: true, ExplicitThis: false, GenParamCount: 0, Params.Count: 4, ParamsAfterSentinel: null } sig ||
            (sig.GetCallingConvention() & CallingConvention.Mask) != CallingConvention.Default || sig.RetType.ElementType != ElementType.Boolean ||
            sig.Params[1].ToTypeDefOrRef() is not TypeRef { FullName: "System.Dynamic.InvokeMemberBinder", ResolutionScope: AssemblyRef framework } ||
            !((framework.Name == "System.Core" && framework.PublicKeyOrToken?.Token.ToString() == "b77a5c561934e089") ||
              (framework.Name == "System.Linq.Expressions" && framework.PublicKeyOrToken?.Token.ToString() == "b03f5f7f11d50a3a")) ||
            sig.Params[2] is not SZArraySig { Next.ElementType: ElementType.Object } ||
            sig.Params[3] is not ByRefSig { Next.ElementType: ElementType.Object }) return false;
        var il = method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        return il.Length == 5 && il[0].IsLdarg() && il[0].GetParameter(method.Parameters) == method.Parameters[^1] &&
            il[1].OpCode.Code == Code.Ldnull && il[2].OpCode.Code == Code.Stind_Ref &&
            il[3].IsLdcI4() && il[3].GetLdcI4Value() == 0 && il[4].OpCode.Code == Code.Ret;
    }
}
