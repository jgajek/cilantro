using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;

namespace Cilantro.Core.Recovery;

/// <summary>Checks local array and reference consumers without allowing a managed address to escape.</summary>
internal static class ClosedArrayReferenceUse
{
    private readonly record struct Value(TypeSig? Type = null, bool Address = false, bool Null = false);

    internal static bool TryGetType(MethodDef caller, Instruction address, ControlFlowGraph graph, out TypeSig type, bool references = false)
    {
        type = null!;
        var block = graph.BlockOf(address).Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        var at = Array.IndexOf(block, address);
        if (at < 0) return false;
        // Track this address through argument preparation. Other values (including
        // other field addresses) remain unmarked. Never spill, duplicate or carry
        // the tracked address across a branch/handler boundary.
        var stack = new List<bool> { true };
        for (var n = at + 1; n < block.Length && n - at <= 64; n++)
        {
            var instruction = block[n];
            if (instruction.OpCode.Code == Code.Dup)
            {
                if (stack.Count == 0 || stack[^1]) return false;
                stack.Add(false); continue;
            }
            instruction.CalculateStackUsage(out var pushes, out var pops);
            if (pops < 0) return false;
            var inputs = new bool[pops];
            for (var p = pops - 1; p >= 0; p--)
                if (stack.Count != 0) { inputs[p] = stack[^1]; stack.RemoveAt(stack.Count - 1); }
            if (inputs.Any(marked => marked))
            {
                if (instruction.OpCode.Code is Code.Call or Code.Callvirt && instruction.Operand is IMethod imported &&
                    TryComOutArray(imported, Array.IndexOf(inputs, true), inputs.Length, caller.Module, out type)) return true;
                if (instruction.OpCode.Code != Code.Call || instruction.Operand is not IMethod call ||
                    !LocalCall(call, caller.Module, out var callee) || inputs.Length != callee.Parameters.Count) return false;
                var parameterIndex = Array.IndexOf(inputs, true);
                var parameter = callee.Parameters[parameterIndex];
                if (parameter.IsHiddenThisParameter || parameter.Type is not ByRefSig reference ||
                    (references ? !IsReference(reference.Next) : reference.Next is not (SZArraySig or ArraySig)) ||
                    reference.Next.ContainsGenericParameter || !Check(callee, parameterIndex, reference.Next, [], [])) return false;
                type = reference.Next;
                return true;
            }
            if (instruction.OpCode.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch or FlowControl.Return or FlowControl.Throw)
                return false;
            for (var p = 0; p < pushes; p++) stack.Add(false);
        }
        return false;
    }

    internal static bool IsCoreArray(TypeSig type, ModuleDef module) => type is ClassSig &&
        new SigComparer().Equals(type, module.CorLibTypes.GetTypeRef("System", "Array").ToTypeSig());

    private static bool TryComOutArray(IMethod call, int parameterIndex, int argumentCount, ModuleDef module, out TypeSig type)
    {
        type = null!;
        // Embedded COM metadata declares a marshaler-enforced output contract.
        // This is deliberately narrower than allowing arbitrary external byrefs:
        // no input value escapes, and SAFEARRAY output is always System.Array.
        if (call is MethodSpec || call.ResolveMethodDef() is not { HasBody: false, IsAbstract: true,
                IsRuntime: true, IsInternalCall: true, HasGenericParameters: false } method || method.Module != module ||
            method.DeclaringType is not { IsImport: true, IsInterface: true, HasGenericParameters: false } owner ||
            !owner.CustomAttributes.Any(a => a.TypeFullName == "System.Runtime.InteropServices.GuidAttribute") ||
            !new SigComparer().Equals(call.MethodSig, method.MethodSig) ||
            method.MethodSig is not { HasThis: true, ExplicitThis: false, Generic: false, ParamsAfterSentinel: null } ||
            (method.MethodSig.CallingConvention & CallingConvention.Mask) != CallingConvention.Default ||
            argumentCount != method.Parameters.Count ||
            parameterIndex <= 0 || parameterIndex >= method.Parameters.Count) return false;
        var parameter = method.Parameters[parameterIndex];
        if (parameter.Type is not ByRefSig reference || !IsCoreArray(reference.Next, module) ||
            parameter.ParamDef is not { IsOut: true, IsIn: false, MarshalType: SafeArrayMarshalType }) return false;
        type = reference.Next;
        return true;
    }

    private static bool IsReference(TypeSig type) => type.ElementType == ElementType.String ||
        type is ClassSig || type is GenericInstSig { GenericType: ClassSig };

    private static bool LocalCall(IMethod call, ModuleDef module, out MethodDef callee)
    {
        callee = call.ResolveMethodDef()!;
        return call is not MethodSpec && callee is { HasBody: true, IsVirtual: false, HasGenericParameters: false } &&
            callee.Module == module && !callee.DeclaringType.HasGenericParameters && callee.Body.Instructions.Count != 0 &&
            call.MethodSig is { ExplicitThis: false, Generic: false } signature &&
            (signature.CallingConvention & CallingConvention.Mask) == CallingConvention.Default &&
            signature.ParamsAfterSentinel?.Count is not > 0 && new SigComparer().Equals(signature, callee.MethodSig);
    }

    private static bool Check(MethodDef method, int parameterIndex, TypeSig array,
        HashSet<(MethodDef, int)> visiting, HashSet<(MethodDef, int)> verified)
    {
        var key = (method, parameterIndex);
        if (verified.Contains(key)) return true;
        if (visiting.Count >= 64 || !visiting.Add(key)) return false;
        try
        {
            var parameter = method.Parameters[parameterIndex];
            foreach (var block in ControlFlowGraph.Build(method).Blocks)
            {
                var stack = new List<Value>();
                foreach (var instruction in block.Instructions)
                {
                    var code = instruction.OpCode.Code;
                    if (code == Code.Nop) continue;
                    // jmp forwards the argument list implicitly; arglist can expose arguments.
                    if (code is Code.Jmp or Code.Arglist) return false;
                    if (instruction.GetParameter(method.Parameters) == parameter &&
                        code is Code.Starg or Code.Starg_S or Code.Ldarga or Code.Ldarga_S) return false;
                    if (code == Code.Dup)
                    {
                        var top = stack.Count == 0 ? default : stack[^1];
                        if (top.Address) return false;
                        stack.Add(top); continue;
                    }
                    instruction.CalculateStackUsage(out var pushes, out var pops);
                    if (pops < 0)
                    {
                        if (stack.Any(v => v.Address)) return false;
                        stack.Clear(); continue;
                    }
                    var inputs = new Value[pops];
                    for (var n = pops - 1; n >= 0; n--)
                        if (stack.Count != 0) { inputs[n] = stack[^1]; stack.RemoveAt(stack.Count - 1); }
                    var marked = inputs.Any(v => v.Address);
                    Value output = default;
                    if (instruction.IsLdarg())
                    {
                        var loaded = instruction.GetParameter(method.Parameters);
                        output = new(loaded?.Type, loaded == parameter);
                    }
                    else if (instruction.IsLdloc()) output = new(instruction.GetLocal(method.Body.Variables)?.Type);
                    else if (code == Code.Ldnull) output = new(Null: true);
                    else if (code == Code.Ldstr) output = new(method.Module.CorLibTypes.String);
                    else if (code is Code.Ldfld or Code.Ldsfld && instruction.Operand is IField field) output = new(field.FieldSig.Type);
                    else if (code is Code.Castclass or Code.Isinst && instruction.Operand is ITypeDefOrRef cast) output = new(cast.ToTypeSig());
                    else if (code == Code.Newobj && instruction.Operand is IMethod constructor) output = new(constructor.DeclaringType.ToTypeSig());
                    else if (code == Code.Newarr && instruction.Operand is ITypeDefOrRef element) output = new(new SZArraySig(element.ToTypeSig()));
                    else if (code is Code.Call or Code.Callvirt && instruction.Operand is IMethod called) output = new(ArrayParameterTypingPass.ReturnedType(called));
                    if (marked)
                    {
                        if (code == Code.Ldind_Ref && inputs.Length == 1 && inputs[0].Address) output = new(array);
                        else if (code == Code.Stind_Ref && inputs.Length == 2 && inputs[0].Address && !inputs[1].Address &&
                            (inputs[1].Null || new SigComparer().Equals(inputs[1].Type, array))) { }
                        else if (code == Code.Call && instruction.Operand is IMethod forwarded && LocalCall(forwarded, method.Module, out var next) &&
                            inputs.Length == next.Parameters.Count)
                        {
                            for (var n = 0; n < inputs.Length; n++)
                                if (inputs[n].Address && (next.Parameters[n].IsHiddenThisParameter ||
                                    next.Parameters[n].Type is not ByRefSig nextRef || !new SigComparer().Equals(nextRef.Next, array) ||
                                    !Check(next, n, array, visiting, verified))) return false;
                        }
                        else return false;
                    }
                    for (var n = 0; n < pushes; n++) stack.Add(output);
                }
                if (stack.Any(v => v.Address)) return false;
            }
            verified.Add(key);
            return true;
        }
        finally { visiting.Remove(key); }
    }
}
