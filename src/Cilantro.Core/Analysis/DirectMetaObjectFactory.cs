using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Checks a direct metaobject factory preserves its expression and receiver
/// and returns the exact type whose invocation fallback was verified. Dispatch to the
/// factory, reflection and external construction are separate caller obligations.</summary>
internal static class DirectMetaObjectFactory
{
    internal static bool IsClosed(MethodDef factory)
    {
        bool Framework(ITypeDefOrRef type, string name) => type is TypeRef { ResolutionScope: AssemblyRef a } && type.FullName == name &&
            ((a.Name == "System.Core" && a.PublicKeyOrToken?.Token.ToString() == "b77a5c561934e089") ||
             (a.Name == "System.Linq.Expressions" && a.PublicKeyOrToken?.Token.ToString() == "b03f5f7f11d50a3a"));
        if (!factory.HasBody || factory.IsStatic || factory.HasGenericParameters || factory.DeclaringType.HasGenericParameters ||
            factory.Body.HasExceptionHandlers || factory.MethodSig.Params.Count != 1 ||
            !Framework(factory.ReturnType.ToTypeDefOrRef(), "System.Dynamic.DynamicMetaObject") ||
            !Framework(factory.MethodSig.Params[0].ToTypeDefOrRef(), "System.Linq.Expressions.Expression")) return false;
        var il = factory.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        bool Arg(Instruction i, MethodDef m, int n) => i.IsLdarg() && i.GetParameter(m.Parameters) == m.Parameters[n];
        if (il.Length != 5 || !Arg(il[0], factory, 1) || !Arg(il[1], factory, 0) ||
            il[2].OpCode.Code != Code.Newobj || il[2].Operand is not IMethod proxy || proxy.MethodSig.Params.Count != 0 ||
            proxy.DeclaringType.ToTypeSig().ContainsGenericParameter ||
            il[3].OpCode.Code != Code.Newobj || il[3].Operand is not IMethod construct ||
            ReadonlyConstructorValues.ResolveMethod(construct) is not { HasBody: true, IsInstanceConstructor: true } ctor ||
            ctor.Module != factory.Module || ctor.Body.HasExceptionHandlers || ctor.MethodSig.Params.Count != 3 ||
            construct.DeclaringType.ToTypeSig().ContainsGenericParameter || il[4].OpCode.Code != Code.Ret) return false;
        var body = ctor.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        var scope = Interpretation.GenericScope.For(construct, null);
        TypeSig Bind(TypeSig type) => scope?.Bind(type) ?? type;
        if (body.Length != 10 || !Arg(body[0], ctor, 0) || !Arg(body[1], ctor, 1) ||
            !Framework(Bind(ctor.MethodSig.Params[0]).ToTypeDefOrRef(), "System.Linq.Expressions.Expression") ||
            !new SigComparer().Equals(Bind(ctor.MethodSig.Params[1]), factory.DeclaringType.ToTypeSig()) ||
            body[2].OpCode.Code != Code.Ldsfld || body[2].Operand is not IField empty || empty.Name != "Empty" ||
            !Framework(empty.DeclaringType, "System.Dynamic.BindingRestrictions") ||
            !Framework(empty.FieldSig.Type.ToTypeDefOrRef(), "System.Dynamic.BindingRestrictions") || !Arg(body[3], ctor, 2) ||
            body[4].OpCode.Code != Code.Box || body[4].Operand is not ITypeDefOrRef boxed ||
            !new SigComparer().Equals(Bind(boxed.ToTypeSig()), factory.DeclaringType.ToTypeSig()) ||
            body[5].OpCode.Code != Code.Call || body[5].Operand is not IMethod baseCtor || baseCtor.Name != ".ctor" ||
            !Framework(baseCtor.DeclaringType, "System.Dynamic.DynamicMetaObject") ||
            baseCtor.MethodSig is not { HasThis: true, Params.Count: 3, RetType.ElementType: ElementType.Void } signature ||
            !Framework(signature.Params[0].ToTypeDefOrRef(), "System.Linq.Expressions.Expression") ||
            !Framework(signature.Params[1].ToTypeDefOrRef(), "System.Dynamic.BindingRestrictions") ||
            signature.Params[2].ElementType != ElementType.Object || !Arg(body[6], ctor, 0) || !Arg(body[7], ctor, 3) ||
            body[8].OpCode.Code != Code.Stfld || body[8].Operand is not IField stored ||
            ReadonlyConstructorValues.ResolveField(stored) is not { IsPrivate: true, IsInitOnly: true, IsStatic: false } field ||
            field.DeclaringType != ctor.DeclaringType || body[9].OpCode.Code != Code.Ret) return false;
        var binders = ctor.DeclaringType.Methods.Where(m => m.Name == "BindInvokeMember").ToArray();
        return binders.Length == 1 && ProxyBinderFallback.IsClosed(binders[0]);
    }
}
