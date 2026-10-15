using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>A type passed only to identity comparisons does not expose its members.</summary>
internal static class TypeIdentityHandleUse
{
    internal static bool IsClosed(MethodDef caller, int index)
    {
        bool Core(TypeRef type) => CoreLibraryIdentity.Matches(caller.Module, type, type.FullName);
        var il = caller.Body.Instructions;
        var at = index + 1;
        Skip();
        if (at >= il.Count || il[at].OpCode.Code != Code.Call || il[at].Operand is not IMethod
            { FullName: "System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)", DeclaringType: TypeRef framework } ||
            !Core(framework)) return false;
        at++; Skip();
        var interior = il.Skip(index + 1).Take(at - index).ToHashSet();
        if (il.Any(i => i.Operand is Instruction branch && interior.Contains(branch) ||
                i.Operand is IList<Instruction> branches && branches.Any(interior.Contains)) ||
            caller.Body.ExceptionHandlers.Any(h => new[] { h.TryStart, h.TryEnd, h.HandlerStart, h.HandlerEnd, h.FilterStart }
                .OfType<Instruction>().Any(interior.Contains))) return false;
        // The right operand is a runtime Type from ldtoken/GetTypeFromHandle.
        // Framework Type equality does not dispatch to a custom left.Equals
        // when either operand is a runtime Type. Direct Equals calls are not covered.
        if (at < il.Count && il[at].OpCode.Code == Code.Call && il[at].Operand is IMethod equality &&
            equality.DeclaringType is TypeRef { FullName: "System.Type" } equalityOwner && Core(equalityOwner) &&
            equality.Name.String is "op_Equality" or "op_Inequality" && equality.MethodSig is { } equalitySignature &&
            equalitySignature.GetCallingConvention() == CallingConvention.Default && !equalitySignature.HasThis &&
            !equalitySignature.ExplicitThis && equalitySignature.GenParamCount == 0 && equalitySignature.Params.Count == 2 &&
            equalitySignature.RetType.ElementType == ElementType.Boolean && equalitySignature.Params.All(p =>
                p.ToTypeDefOrRef() is TypeRef { FullName: "System.Type" } parameter && Core(parameter))) return true;
        if (at >= il.Count || il[at].OpCode.Code is not (Code.Call or Code.Callvirt) ||
            il[at].Operand is not IMethod reference || reference.ResolveMethodDef() is not { } target ||
            reference.MethodSig is not { } signature || (signature.GetCallingConvention() & CallingConvention.Mask) != CallingConvention.Default ||
            !new SigComparer().Equals(signature, target.MethodSig) ||
            target.Module != caller.Module || !target.HasBody || target.IsVirtual || target.IsConstructor ||
            target.HasGenericParameters || target.DeclaringType.HasGenericParameters || target.Body.HasExceptionHandlers ||
            target.MethodSig.ExplicitThis || target.MethodSig.Params.Count == 0 ||
            target.MethodSig.Params[^1].ToTypeDefOrRef() is not TypeRef { FullName: "System.Type" } parameterType ||
            !Core(parameterType)) return false;
        var parameter = target.Parameters[^1];
        var reads = 0;
        var body = target.Body.Instructions;
        for (var n = 0; n < body.Count; n++)
        {
            if (body[n].GetParameter(target.Parameters) != parameter) continue;
            if (!body[n].IsLdarg()) return false;
            reads++;
            var next = n + 1;
            while (next < body.Count && body[next].OpCode.Code == Code.Nop) next++;
            if (next >= body.Count || body[next].OpCode.Code != Code.Ceq) return false;
        }
        return reads != 0;

        void Skip() { while (at < il.Count && il[at].OpCode.Code == Code.Nop) at++; }
    }


}
