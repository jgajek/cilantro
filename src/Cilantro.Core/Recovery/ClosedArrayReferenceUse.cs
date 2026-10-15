using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;

namespace Cilantro.Core.Recovery;

/// <summary>Checks local ref-array consumers without allowing a managed address to escape.</summary>
internal static class ClosedArrayReferenceUse
{
    private readonly record struct Value(TypeSig? Type = null, bool Address = false, bool Null = false);

    internal static bool TryGetType(MethodDef caller, Instruction address, ControlFlowGraph graph, out TypeSig type)
    {
        type = null!;
        var block = graph.BlockOf(address).Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        var at = Array.IndexOf(block, address);
        if (at < 0 || at + 1 >= block.Length || block[at + 1].OpCode.Code != Code.Call ||
            block[at + 1].Operand is not IMethod call || !LocalCall(call, caller.Module, out var callee) ||
            callee.MethodSig.Params.LastOrDefault() is not ByRefSig { Next: SZArraySig array } || array.ContainsGenericParameter) return false;
        var visiting = new HashSet<(MethodDef, int)>();
        var verified = new HashSet<(MethodDef, int)>();
        if (!Check(callee, callee.Parameters.Count - 1, array, visiting, verified)) return false;
        type = array;
        return true;
    }

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
                    else if (code is Code.Ldfld or Code.Ldsfld && instruction.Operand is IField field) output = new(field.FieldSig.Type);
                    else if (code is Code.Castclass or Code.Isinst && instruction.Operand is ITypeDefOrRef cast) output = new(cast.ToTypeSig());
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
