using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Recognizes a closure-based Any query over instance methods. Callers still
/// must establish that every method with the queried name is declared by the supplied base type.</summary>
internal static class InheritedOverrideQuery
{
    internal static bool IsClosed(MethodDef query)
    {
        bool Core(ITypeDefOrRef type, string name) => CoreLibraryIdentity.Matches(query.Module, type, name);
        if (!query.IsStatic || query.HasGenericParameters || query.MethodSig.Params.Count != 3 ||
            query.ReturnType.ElementType != ElementType.Boolean ||
            !Core(query.MethodSig.Params[0].ToTypeDefOrRef(), "System.Type") ||
            !Core(query.MethodSig.Params[1].ToTypeDefOrRef(), "System.Type") ||
            query.MethodSig.Params[2].ElementType != ElementType.String || Linear(query) is not { } il) return false;
        // The receiver parameter already has the exact framework Type signature.
        // Match both compiler output and recovered output with its redundant Type cast.
        // This normalizes only the pattern array; no method instructions are changed.
        if (il.Length == 16)
        {
            var normalized = il.ToList();
            normalized.Insert(9, OpCodes.Castclass.ToInstruction(query.MethodSig.Params[0].ToTypeDefOrRef()));
            il = normalized.ToArray();
        }
        if (il.Length != 17) return false;
        bool Argument(int i, int argument) => il[i].IsLdarg() && il[i].GetParameter(query.Parameters) == query.Parameters[argument];
        if (il[0].OpCode.Code != Code.Newobj || il[0].Operand is not IMethod ctorRef ||
            ctorRef.ResolveMethodDef() is not { IsInstanceConstructor: true } ctor || ctor.Module != query.Module ||
            ctor.MethodSig.Params.Count != 0 || ctor.DeclaringType.HasGenericParameters ||
            ctor.DeclaringType.Methods.Any(m => m.IsStaticConstructor) || Linear(ctor) is not { Length: 3 } construction ||
            !construction[0].IsLdarg() || construction[0].GetParameter(ctor.Parameters)?.IsHiddenThisParameter != true ||
            construction[1].OpCode.Code != Code.Call || construction[1].Operand is not IMethod baseCtor ||
            baseCtor.Name != ".ctor" || !Core(baseCtor.DeclaringType, "System.Object") ||
            baseCtor.MethodSig is not { HasThis: true, Params.Count: 0, RetType.ElementType: ElementType.Void } ||
            construction[2].OpCode.Code != Code.Ret || !il[1].IsStloc()) return false;
        var local = il[1].GetLocal(query.Body.Variables);
        bool Load(int i) => il[i].IsLdloc() && il[i].GetLocal(query.Body.Variables) == local;
        FieldDef? Store(int i) => il[i].OpCode.Code == Code.Stfld && il[i].Operand is IField f ? f.ResolveFieldDef() : null;
        var name = Store(4); var baseType = Store(7);
        if (!Load(2) || !Argument(3, 2) || name?.DeclaringType != ctor.DeclaringType || name.IsStatic ||
            name.FieldSig.Type.ElementType != ElementType.String || !Load(5) || !Argument(6, 1) ||
            baseType?.DeclaringType != ctor.DeclaringType || baseType.IsStatic ||
            !Core(baseType.FieldSig.Type.ToTypeDefOrRef(), "System.Type") || !Argument(8, 0) ||
            il[9].OpCode.Code != Code.Castclass || il[9].Operand is not ITypeDefOrRef cast || !Core(cast, "System.Type") ||
            !il[10].IsLdcI4() || il[10].GetLdcI4Value() != 52 || il[11].OpCode.Code != Code.Callvirt ||
            il[11].Operand is not IMethod getMethods || !Core(getMethods.DeclaringType, "System.Type") || getMethods.Name != "GetMethods" ||
            getMethods.MethodSig is not { HasThis: true, Params.Count: 1, RetType: SZArraySig array } ||
            !Core(array.Next.ToTypeDefOrRef(), "System.Reflection.MethodInfo") ||
            !Core(getMethods.MethodSig.Params[0].ToTypeDefOrRef(), "System.Reflection.BindingFlags") || !Load(12) ||
            il[13].OpCode.Code != Code.Ldftn || il[13].Operand is not IMethod predicateRef ||
            predicateRef.ResolveMethodDef() is not { } predicate || predicate.DeclaringType != ctor.DeclaringType ||
            !InheritedOverridePredicate.RefusesInherited(predicate, baseType) ||
            !InheritedOverridePredicate.RefusesOtherNames(predicate, baseType, name)) return false;
        bool Func(TypeSig type) => type is GenericInstSig { GenericArguments.Count: 2 } g && Core(g.GenericType.TypeDefOrRef, "System.Func`2") &&
            Core(g.GenericArguments[0].ToTypeDefOrRef(), "System.Reflection.MethodInfo") && g.GenericArguments[1].ElementType == ElementType.Boolean;
        if (il[14].OpCode.Code != Code.Newobj || il[14].Operand is not IMethod createDelegate ||
            createDelegate.Name != ".ctor" || !Func(createDelegate.DeclaringType.ToTypeSig()) ||
            createDelegate.MethodSig is not { HasThis: true, Params.Count: 2, RetType.ElementType: ElementType.Void } delegateSig ||
            delegateSig.Params[0].ElementType != ElementType.Object || delegateSig.Params[1].ElementType != ElementType.I ||
            il[15].OpCode.Code != Code.Call || il[15].Operand is not MethodSpec any || any.Name != "Any" ||
            any.DeclaringType is not TypeRef { FullName: "System.Linq.Enumerable", ResolutionScope: AssemblyRef assembly } ||
            !((assembly.Name == "System.Core" && assembly.PublicKeyOrToken?.Token.ToString() == "b77a5c561934e089") ||
              (assembly.Name == "System.Linq" && assembly.PublicKeyOrToken?.Token.ToString() == "b03f5f7f11d50a3a")) ||
            any.GenericInstMethodSig.GenericArguments.Count != 1 ||
            !Core(any.GenericInstMethodSig.GenericArguments[0].ToTypeDefOrRef(), "System.Reflection.MethodInfo") ||
            any.Method.MethodSig is not { HasThis: false, Params.Count: 2, RetType.ElementType: ElementType.Boolean } sig ||
            il[16].OpCode.Code != Code.Ret) return false;
        var scope = Interpretation.GenericScope.For(any, null)!;
        return scope.Bind(sig.Params[0]) is GenericInstSig { GenericArguments.Count: 1 } enumerable &&
            Core(enumerable.GenericType.TypeDefOrRef, "System.Collections.Generic.IEnumerable`1") &&
            Core(enumerable.GenericArguments[0].ToTypeDefOrRef(), "System.Reflection.MethodInfo") && Func(scope.Bind(sig.Params[1])!);
    }
    private static Instruction[]? Linear(MethodDef method)
    {
        if (!method.HasBody || method.Body.HasExceptionHandlers) return null;
        var result = new List<Instruction>(); var seen = new HashSet<Instruction>();
        var il = method.Body.Instructions; var index = 0;
        while (index >= 0 && index < il.Count && seen.Count < 128)
        {
            var instruction = il[index++]; if (!seen.Add(instruction)) return null;
            if (instruction.OpCode.Code is Code.Br or Code.Br_S)
            { if (instruction.Operand is not Instruction target) return null; index = il.IndexOf(target); continue; }
            if (instruction.OpCode.Code == Code.Nop) continue;
            if (instruction.OpCode.FlowControl == FlowControl.Cond_Branch) return null;
            result.Add(instruction);
            if (instruction.OpCode.Code == Code.Ret) return result.ToArray();
        }
        return null;
    }
}
