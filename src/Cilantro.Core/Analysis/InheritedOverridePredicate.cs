using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Proves a predicate returns false for a MethodInfo declared by the runtime
/// type held in one closure field. The caller must prove that field value and method provenance.</summary>
internal static class InheritedOverridePredicate
{
    private enum Value { This, Method, BaseType, Text, MethodName, CapturedName, False, True, Boolean }
    internal static bool RefusesInherited(MethodDef predicate, FieldDef baseTypeField) => Analyze(predicate, baseTypeField, null);
    internal static bool RefusesOtherNames(MethodDef predicate, FieldDef baseTypeField, FieldDef nameField) => Analyze(predicate, baseTypeField, nameField);
    private static bool Analyze(MethodDef predicate, FieldDef baseTypeField, FieldDef? nameField)
    {
        bool Core(ITypeDefOrRef type, string name) => CoreLibraryIdentity.Matches(predicate.Module, type, name);
        if (!predicate.HasBody || predicate.IsStatic || predicate.HasGenericParameters || predicate.Body.HasExceptionHandlers ||
            predicate.MethodSig.Params.Count != 1 || predicate.ReturnType.ElementType != ElementType.Boolean ||
            !Core(predicate.MethodSig.Params[0].ToTypeDefOrRef(), "System.Reflection.MethodInfo") ||
            baseTypeField.IsStatic || baseTypeField.DeclaringType != predicate.DeclaringType ||
            !Core(baseTypeField.FieldSig.Type.ToTypeDefOrRef(), "System.Type")) return false;
        if (nameField is not null && (nameField.IsStatic || nameField.DeclaringType != predicate.DeclaringType ||
            nameField.FieldSig.Type.ElementType != ElementType.String)) return false;
        var il = predicate.Body.Instructions;
        if (il.Count == 0) return false;
        var pending = new Queue<(int Pc, Value[] Stack)>();
        pending.Enqueue((0, []));
        var steps = 0; var returns = 0;
        while (pending.TryDequeue(out var state))
        {
            if (++steps > 2048 || state.Pc < 0 || state.Pc >= il.Count) return false;
            var instruction = il[state.Pc]; var stack = state.Stack.ToList();
            bool Pop(Value expected)
            {
                if (stack.Count == 0 || stack[^1] != expected) return false;
                stack.RemoveAt(stack.Count - 1); return true;
            }
            void Next(int pc) => pending.Enqueue((pc, stack.ToArray()));
            if (instruction.IsLdarg())
            {
                var parameter = instruction.GetParameter(predicate.Parameters);
                if (parameter == predicate.Parameters[0]) stack.Add(Value.This);
                else if (parameter == predicate.Parameters[1]) stack.Add(Value.Method);
                else return false;
            }
            else if (instruction.IsLdcI4() && instruction.GetLdcI4Value() is 0 or 1)
                stack.Add(instruction.GetLdcI4Value() == 0 ? Value.False : Value.True);
            else switch (instruction.OpCode.Code)
            {
                case Code.Nop: break;
                case Code.Castclass:
                    if (stack.Count == 0 || stack[^1] != Value.Method || instruction.Operand is not ITypeDefOrRef cast ||
                        !(Core(cast, "System.Reflection.MemberInfo") || Core(cast, "System.Reflection.MethodInfo"))) return false;
                    break;
                case Code.Ldfld:
                    if (!Pop(Value.This) || instruction.Operand is not IField reference || reference.ResolveFieldDef() is not { } field ||
                        field.DeclaringType != predicate.DeclaringType || field.IsStatic) return false;
                    if (field == baseTypeField) stack.Add(Value.BaseType);
                    else if (field == nameField) stack.Add(Value.CapturedName);
                    else if (field.FieldSig.Type.ElementType == ElementType.String) stack.Add(Value.Text);
                    else return false;
                    break;
                case Code.Call:
                case Code.Callvirt:
                    if (instruction.Operand is not IMethod call || call.MethodSig is not { } signature) return false;
                    if (signature.HasThis && signature.Params.Count == 0 && Core(call.DeclaringType, "System.Reflection.MemberInfo"))
                    {
                        if (!Pop(Value.Method)) return false;
                        if (call.Name == "get_Name" && signature.RetType.ElementType == ElementType.String) stack.Add(nameField is null ? Value.Text : Value.MethodName);
                        else if (nameField is null && call.Name == "get_DeclaringType" && Core(signature.RetType.ToTypeDefOrRef(), "System.Type")) stack.Add(Value.BaseType);
                        else return false;
                    }
                    else if (!signature.HasThis && signature.Params.Count == 2 && signature.RetType.ElementType == ElementType.Boolean &&
                        Core(call.DeclaringType, "System.Type") && signature.Params.All(p => Core(p.ToTypeDefOrRef(), "System.Type")) &&
                        (call.Name == "op_Equality" || call.Name == "op_Inequality"))
                    {
                        if (!Pop(Value.BaseType) || !Pop(Value.BaseType)) return false;
                        stack.Add(call.Name == "op_Equality" ? Value.True : Value.False);
                    }
                    else if (!signature.HasThis && signature.Params.Count == 2 && signature.RetType.ElementType == ElementType.Boolean &&
                        Core(call.DeclaringType, "System.String") && signature.Params.All(p => p.ElementType == ElementType.String) && call.Name == "op_Equality")
                    {
                        if (stack.Count < 2) return false;
                        var right = stack[^1]; var left = stack[^2]; stack.RemoveRange(stack.Count - 2, 2);
                        if (left is not (Value.Text or Value.MethodName or Value.CapturedName) ||
                            right is not (Value.Text or Value.MethodName or Value.CapturedName)) return false;
                        stack.Add(left == Value.MethodName && right == Value.CapturedName ||
                            right == Value.MethodName && left == Value.CapturedName ? Value.False : Value.Boolean);
                    }
                    else return false;
                    break;
                case Code.Br:
                case Code.Br_S:
                    if (instruction.Operand is not Instruction jump) return false;
                    Next(il.IndexOf(jump)); continue;
                case Code.Brtrue:
                case Code.Brtrue_S:
                case Code.Brfalse:
                case Code.Brfalse_S:
                    if (stack.Count == 0 || instruction.Operand is not Instruction destination) return false;
                    var condition = stack[^1]; stack.RemoveAt(stack.Count - 1);
                    if (condition is not (Value.Boolean or Value.True or Value.False)) return false;
                    var whenTrue = instruction.OpCode.Code is Code.Brtrue or Code.Brtrue_S;
                    if (condition == Value.Boolean || (condition == Value.True) == whenTrue) Next(il.IndexOf(destination));
                    if (condition == Value.Boolean || (condition == Value.True) != whenTrue) Next(state.Pc + 1);
                    continue;
                case Code.Ret:
                    if (!Pop(Value.False) || stack.Count != 0) return false;
                    returns++; continue;
                default: return false;
            }
            Next(state.Pc + 1);
        }
        return returns != 0;
    }
}
