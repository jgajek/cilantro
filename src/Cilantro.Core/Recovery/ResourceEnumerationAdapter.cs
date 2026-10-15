using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>A structurally identified adapter, not permission to remove its initializer.</summary>
internal sealed record ResourceEnumerationAdapter(MethodDef Wrapper, MethodDef Initializer,
    FieldDef Initialized, FieldDef Satellite)
{
    internal static ResourceEnumerationAdapter? Match(MethodDef method)
    {
        if (!method.HasBody || !method.IsStatic || method.IsConstructor || method.HasGenericParameters ||
            method.DeclaringType.HasGenericParameters || method.Body.ExceptionHandlers.Count != 0 ||
            method.MethodSig is not { Params.Count: 1 } signature ||
            signature.RetType.FullName != "System.String[]" || signature.Params[0].FullName != "System.Reflection.Assembly") return null;
        var il = method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        if (il.Length != 24) return null;
        bool Arg(int n) => il[n].IsLdarg() && il[n].GetParameter(method.Parameters)?.Index == 0;
        bool Branch(int n, bool whenTrue) =>
            il[n].OpCode.Code == (whenTrue ? Code.Brtrue : Code.Brfalse) ||
            il[n].OpCode.Code == (whenTrue ? Code.Brtrue_S : Code.Brfalse_S);
        Instruction? Target(int n)
        {
            if (il[n].Operand is not Instruction target) return null;
            var at = method.Body.Instructions.IndexOf(target);
            while (at >= 0 && at < method.Body.Instructions.Count && method.Body.Instructions[at].OpCode.Code == Code.Nop) at++;
            return at >= 0 && at < method.Body.Instructions.Count ? method.Body.Instructions[at] : null;
        }
        bool FrameworkType(ITypeDefOrRef? type, string name) => type is TypeRef reference &&
            reference.FullName == name && reference.DefinitionAssembly?.FullName == method.Module.CorLibTypes.AssemblyRef.FullName;
        bool Call(int n, Code code, string name, string owner) => il[n].OpCode.Code == code &&
            il[n].Operand is IMethod call && call is not MethodSpec && call.FullName == name && FrameworkType(call.DeclaringType, owner);
        bool ListCall(int n, Code code, string name) => il[n].OpCode.Code == code && il[n].Operand is IMethod call &&
            call is not MethodSpec && call.FullName == name && call.DeclaringType is TypeSpec { TypeSig: GenericInstSig generic } &&
            FrameworkType(generic.GenericType.TypeDefOrRef, "System.Collections.Generic.List`1") &&
            generic.GenericArguments.Count == 1 && generic.GenericArguments[0].ElementType == ElementType.String;
        const string names = "System.String[] System.Reflection.Assembly::GetManifestResourceNames()";
        const string add = "System.Void System.Collections.Generic.List`1<System.String>::AddRange(System.Collections.Generic.IEnumerable`1<System.String>)";
        if (!Arg(0) || il[1].OpCode.Code != Code.Ldtoken || il[1].Operand != method.DeclaringType ||
            !Call(2, Code.Call, "System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)", "System.Type") ||
            !Call(3, Code.Callvirt, "System.Reflection.Assembly System.Type::get_Assembly()", "System.Type") ||
            !Call(4, Code.Call, "System.Boolean System.Reflection.Assembly::op_Equality(System.Reflection.Assembly,System.Reflection.Assembly)", "System.Reflection.Assembly") ||
            !Branch(5, false) || Target(5) != il[21] || !Branch(7, true) || Target(7) != il[9] ||
            il[6].OpCode.Code != Code.Ldsfld || il[6].Operand is not FieldDef flag || flag.DeclaringType != method.DeclaringType ||
            !flag.IsStatic || flag.FieldType.ElementType != ElementType.Boolean ||
            il[8].OpCode.Code != Code.Call || il[8].Operand is not MethodDef initializer || initializer.DeclaringType != method.DeclaringType ||
            !initializer.IsStatic || !initializer.HasBody || initializer.HasGenericParameters || initializer.IsConstructor ||
            initializer.MethodSig is not { Params.Count: 0 } || initializer.ReturnType.ElementType != ElementType.Void ||
            !ListCall(9, Code.Newobj, "System.Void System.Collections.Generic.List`1<System.String>::.ctor()") ||
            il[10].OpCode.Code != Code.Dup || !Arg(11) || !Call(12, Code.Callvirt, names, "System.Reflection.Assembly") ||
            !ListCall(13, Code.Callvirt, add) || il[14].OpCode.Code != Code.Dup ||
            il[15].OpCode.Code != Code.Ldsfld || il[15].Operand is not FieldDef satellite || satellite.DeclaringType != method.DeclaringType || !satellite.IsStatic ||
            satellite.FieldType.ElementType != ElementType.Object || il[16].OpCode.Code != Code.Castclass ||
            !FrameworkType(il[16].Operand as ITypeDefOrRef, "System.Reflection.Assembly") ||
            !Call(17, Code.Callvirt, names, "System.Reflection.Assembly") || !ListCall(18, Code.Callvirt, add) ||
            !ListCall(19, Code.Callvirt, "System.String[] System.Collections.Generic.List`1<System.String>::ToArray()") ||
            il[20].OpCode.Code != Code.Ret || !Arg(21) || !Call(22, Code.Callvirt, names, "System.Reflection.Assembly") ||
            il[23].OpCode.Code != Code.Ret) return null;
        return new(method, initializer, flag, satellite);
    }
}
