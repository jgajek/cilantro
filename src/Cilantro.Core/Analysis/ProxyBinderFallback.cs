using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Checks the observed proxy construction path reaches the base binder with
/// its original operands. External construction and dynamic receiver closure remain separate.</summary>
internal static class ProxyBinderFallback
{
    private enum Value { This, Binder, Arguments, Closure, InvokeName, False, Result }
    internal static bool IsClosed(MethodDef method)
    {
        bool Framework(ITypeDefOrRef type, string name) => type is TypeRef { ResolutionScope: AssemblyRef assembly } && type.FullName == name &&
            ((assembly.Name == "System.Core" && assembly.PublicKeyOrToken?.Token.ToString() == "b77a5c561934e089") ||
             (assembly.Name == "System.Linq.Expressions" && assembly.PublicKeyOrToken?.Token.ToString() == "b03f5f7f11d50a3a"));
        if (!method.HasBody || method.IsStatic || method.HasGenericParameters || method.Body.HasExceptionHandlers ||
            method.MethodSig.Params.Count != 2 || !Framework(method.ReturnType.ToTypeDefOrRef(), "System.Dynamic.DynamicMetaObject") ||
            !Framework(method.MethodSig.Params[0].ToTypeDefOrRef(), "System.Dynamic.InvokeMemberBinder") ||
            method.MethodSig.Params[1] is not SZArraySig argumentArray || !Framework(argumentArray.Next.ToTypeDefOrRef(), "System.Dynamic.DynamicMetaObject") ||
            method.DeclaringType.BaseType is null || !Framework(method.DeclaringType.BaseType, "System.Dynamic.DynamicMetaObject")) return false;
        var stack = new List<Value>(); var locals = new Dictionary<Local, Value>(); var fields = new Dictionary<FieldDef, Value>();
        TypeDef? closure = null; var querySeen = false; var fallbackSeen = false;
        var il = method.Body.Instructions; var pc = 0; var visited = new HashSet<Instruction>();
        bool Pop(Value expected)
        {
            if (stack.Count == 0 || stack[^1] != expected) return false;
            stack.RemoveAt(stack.Count - 1); return true;
        }
        while (pc >= 0 && pc < il.Count && visited.Count < 512)
        {
            var instruction = il[pc++]; if (!visited.Add(instruction)) return false;
            if (instruction.IsLdarg())
            {
                var p = instruction.GetParameter(method.Parameters);
                if (p == method.Parameters[0]) stack.Add(Value.This);
                else if (p == method.Parameters[1]) stack.Add(Value.Binder);
                else if (p == method.Parameters[2]) stack.Add(Value.Arguments);
                else return false;
            }
            else if (instruction.IsStloc())
            {
                if (stack.Count == 0) return false;
                locals[instruction.GetLocal(method.Body.Variables)!] = stack[^1]; stack.RemoveAt(stack.Count - 1);
            }
            else if (instruction.IsLdloc())
            {
                if (!locals.TryGetValue(instruction.GetLocal(method.Body.Variables)!, out var value)) return false;
                stack.Add(value);
            }
            else switch (instruction.OpCode.Code)
            {
                case Code.Nop: break;
                case Code.Ldstr:
                    if (instruction.Operand is not string name || name != "TryInvokeMember") return false;
                    stack.Add(Value.InvokeName); break;
                case Code.Newobj:
                    if (closure is not null || instruction.Operand is not IMethod ctorRef ||
                        ReadonlyConstructorValues.ResolveMethod(ctorRef) is not { IsInstanceConstructor: true, HasBody: true } ctor ||
                        ctor.Module != method.Module || ctor.MethodSig.Params.Count != 0 || ctor.Body.HasExceptionHandlers ||
                        ctor.DeclaringType.Methods.Any(m => m.IsStaticConstructor)) return false;
                    var body = ctor.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
                    if (body.Length != 3 || !body[0].IsLdarg() || body[0].GetParameter(ctor.Parameters)?.IsHiddenThisParameter != true ||
                        body[1].OpCode.Code != Code.Call || body[1].Operand is not IMethod baseCtor || baseCtor.Name != ".ctor" ||
                        !CoreLibraryIdentity.Matches(method.Module, baseCtor.DeclaringType, "System.Object") ||
                        baseCtor.MethodSig is not { HasThis: true, Params.Count: 0, RetType.ElementType: ElementType.Void } ||
                        body[2].OpCode.Code != Code.Ret) return false;
                    closure = ctor.DeclaringType; stack.Add(Value.Closure); break;
                case Code.Stfld:
                    if (stack.Count == 0 || instruction.Operand is not IField store ||
                        ReadonlyConstructorValues.ResolveField(store) is not { IsStatic: false } written || written.DeclaringType != closure) return false;
                    var stored = stack[^1]; stack.RemoveAt(stack.Count - 1);
                    if (!Pop(Value.Closure)) return false;
                    fields[written] = stored; break;
                case Code.Ldfld:
                    if (!Pop(Value.Closure) || instruction.Operand is not IField read ||
                        ReadonlyConstructorValues.ResolveField(read) is not { } field || !fields.TryGetValue(field, out var loaded)) return false;
                    stack.Add(loaded); break;
                case Code.Call:
                    if (instruction.Operand is not IMethod call) return false;
                    var target = ReadonlyConstructorValues.ResolveMethod(call);
                    if (!querySeen && target?.DeclaringType == method.DeclaringType && !target.IsVirtual &&
                        ReadonlyProxyOverride.RefusesInvokeMember(target))
                    {
                        if (!Pop(Value.InvokeName) || !Pop(Value.This)) return false;
                        querySeen = true; stack.Add(Value.False);
                    }
                    else if (querySeen && !fallbackSeen && call.Name == "BindInvokeMember" &&
                        Framework(call.DeclaringType, "System.Dynamic.DynamicMetaObject") &&
                        new SigComparer().Equals(call.MethodSig, method.MethodSig))
                    {
                        if (!Pop(Value.Arguments) || !Pop(Value.Binder) || !Pop(Value.This)) return false;
                        fallbackSeen = true; stack.Add(Value.Result);
                    }
                    else return false;
                    break;
                case Code.Br:
                case Code.Br_S:
                    if (instruction.Operand is not Instruction jump) return false;
                    pc = il.IndexOf(jump); break;
                case Code.Brfalse:
                case Code.Brfalse_S:
                    if (!Pop(Value.False) || instruction.Operand is not Instruction destination) return false;
                    pc = il.IndexOf(destination); break;
                case Code.Brtrue:
                case Code.Brtrue_S:
                    if (!Pop(Value.False)) return false;
                    break;
                case Code.Ret: return querySeen && fallbackSeen && Pop(Value.Result) && stack.Count == 0;
                default: return false;
            }
        }
        return false;
    }
}
