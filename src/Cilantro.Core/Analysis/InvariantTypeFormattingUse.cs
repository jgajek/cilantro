using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Scopes a runtime type handle to invariant-culture diagnostic formatting.</summary>
internal static class InvariantTypeFormattingUse
{
    internal static bool IsClosed(MethodDef caller, Instruction token)
    {
        if (!caller.HasBody) return false;
        var graph = ControlFlowGraph.Build(caller);
        var code = graph.BlockOf(token).Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        var at = Array.IndexOf(code, token);
        bool Core(IMethod m, string signature) => m.FullName == signature && CoreLibraryIdentity.Matches(caller.Module,m.DeclaringType,m.DeclaringType.FullName);
        if (at < 2 || at + 2 >= code.Length || code[at-2].OpCode.Code != Code.Ldstr ||
            code[at-1].OpCode.Code != Code.Call || code[at-1].Operand is not IMethod culture ||
            !Core(culture,"System.Globalization.CultureInfo System.Globalization.CultureInfo::get_InvariantCulture()") ||
            token.OpCode.Code != Code.Ldtoken || token.Operand is not ITypeDefOrRef ||
            code[at+1].OpCode.Code != Code.Call || code[at+1].Operand is not IMethod convert ||
            !Core(convert,"System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)") ||
            code[at+2].OpCode.Code != Code.Call || code[at+2].Operand is not IMethod reference ||
            reference.ResolveMethodDef() is not {} wrapper || !Local(wrapper) || !new SigComparer().Equals(reference.MethodSig,wrapper.MethodSig)) return false;
        var il = Linear(wrapper);
        if (il is null || il.Length != 10 || wrapper.MethodSig.Params.Count != 3 ||
            !Arg(wrapper,il[0],0) || !Arg(wrapper,il[1],1) || !One(il[2],1) ||
            il[3].OpCode.Code != Code.Newarr || il[3].Operand is not ITypeDefOrRef element || !CoreLibraryIdentity.Matches(caller.Module,element,"System.Object") ||
            il[4].OpCode.Code != Code.Dup || !One(il[5],0) || !Arg(wrapper,il[6],2) || il[7].OpCode.Code != Code.Stelem_Ref ||
            il[8].OpCode.Code != Code.Call || il[8].Operand is not IMethod forward || forward.ResolveMethodDef() is not {} formatter ||
            !Local(formatter) || !new SigComparer().Equals(forward.MethodSig,formatter.MethodSig) || il[9].OpCode.Code != Code.Ret) return false;
        var body = Linear(formatter);
        if (body is null || body.Length != 11 || formatter.MethodSig.Params.Count != 3 ||
            !Arg(formatter,body[0],0) || !Cast(body[1],"System.String") || body[2].OpCode.Code != Code.Ldstr ||
            body[3].OpCode.Code != Code.Call || body[3].Operand is not IMethod validation || validation.ResolveMethodDef() is not {} validator ||
            !Local(validator) || !new SigComparer().Equals(validation.MethodSig,validator.MethodSig) ||
            validator.MethodSig.Params.Count != 2 || validator.ReturnType.ElementType != ElementType.Void ||
            validator.MethodSig.Params[0].ElementType is not (ElementType.Object or ElementType.String) || validator.MethodSig.Params[1].ElementType != ElementType.String ||
            !Arg(formatter,body[4],1) || !Cast(body[5],"System.IFormatProvider") ||
            !Arg(formatter,body[6],0) || !Cast(body[7],"System.String") || !Arg(formatter,body[8],2) ||
            body[9].OpCode.Code != Code.Call || body[9].Operand is not IMethod format ||
            !Core(format,"System.String System.String::Format(System.IFormatProvider,System.String,System.Object[])") || body[10].OpCode.Code != Code.Ret) return false;
        return wrapper.ReturnType.ElementType == ElementType.String && formatter.ReturnType.ElementType == ElementType.String &&
            wrapper.MethodSig.Params[0].ElementType == ElementType.String &&
            CoreLibraryIdentity.Matches(caller.Module,wrapper.MethodSig.Params[1].ToTypeDefOrRef(),"System.IFormatProvider") && wrapper.MethodSig.Params[2].ElementType == ElementType.Object &&
            formatter.MethodSig.Params[0].ElementType is ElementType.Object or ElementType.String &&
            formatter.MethodSig.Params[1].ElementType == ElementType.Object && formatter.MethodSig.Params[2] is SZArraySig {Next.ElementType:ElementType.Object};

        bool Local(MethodDef m) => m.Module == caller.Module && m.HasBody && m.IsStatic && !m.IsConstructor && !m.HasGenericParameters && !m.DeclaringType.HasGenericParameters &&
            !m.MethodSig.ExplicitThis && m.MethodSig.ParamsAfterSentinel is null && m.MethodSig.GetCallingConvention() == CallingConvention.Default;
        bool Cast(Instruction i,string name) => i.OpCode.Code == Code.Castclass && i.Operand is ITypeDefOrRef type && CoreLibraryIdentity.Matches(caller.Module,type,name);
    }
    private static bool Arg(MethodDef method,Instruction i,int n) => i.IsLdarg() && i.GetParameter(method.Parameters) == method.Parameters[n];
    private static bool One(Instruction i,int n) => i.IsLdcI4() && i.GetLdcI4Value() == n;
    private static Instruction[]? Linear(MethodDef method)
    {
        if (method.Body.HasExceptionHandlers) return null;
        var all = method.Body.Instructions;
        var seen = new HashSet<Instruction>(); var result = new List<Instruction>(); var at = 0;
        while (at < all.Count) {
            var i = all[at++]; if (!seen.Add(i) || seen.Count > 64) return null;
            if (i.OpCode.Code == Code.Nop) continue;
            if (i.OpCode.Code is Code.Br or Code.Br_S) { if (i.Operand is not Instruction target || (at=all.IndexOf(target)) < 0) return null; continue; }
            result.Add(i); if (i.OpCode.Code == Code.Ret) return result.ToArray();
            if (i.OpCode.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch or FlowControl.Throw) return null;
        }
        return null;
    }
}
