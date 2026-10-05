using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Distinguishes live reflection-member round trips from opaque numeric token uses.</summary>
internal static class NumericTokenUses
{
    private enum Kind { Unknown, Member, Module, Token }
    private readonly record struct Value(Kind Kind, int Origin);

    internal static bool IsResolution(IMethod called) =>
        called.DeclaringType?.FullName is "System.Reflection.Module" or "System.ModuleHandle" &&
        called.Name.String is "ResolveMethod" or "ResolveField" or "ResolveType" or
            "ResolveMember" or "ResolveSignature" or "ResolveString" or
            "ResolveMethodHandle" or "ResolveFieldHandle" or "ResolveTypeHandle";

    internal static IReadOnlySet<Instruction> MemberRoundTrips(MethodDef method)
    {
        var proven = new HashSet<Instruction>();
        if (!method.HasBody) return proven;
        // Local proofs deliberately stop at control-flow and exception boundaries. A value
        // arriving through another edge must not borrow the provenance of a linear predecessor.
        foreach (var block in ControlFlowGraph.Build(method).Blocks)
        {
            var stack = new List<Value>();
            var locals = new Dictionary<Local, Value>();
            var arguments = new Dictionary<int, Value>();
            var nextOrigin = method.Parameters.Count;
            foreach (var instruction in block.Instructions)
            {
                if (instruction.IsLdarg())
                {
                    var index = instruction.GetParameterIndex();
                    stack.Add(arguments.GetValueOrDefault(index, new Value(Kind.Member, index)));
                    continue;
                }
                if (instruction.OpCode.Code is Code.Starg or Code.Starg_S)
                {
                    if (instruction.Operand is Parameter parameter) arguments[parameter.Index] = Pop();
                    else { stack.Clear(); arguments.Clear(); }
                    continue;
                }
                if (instruction.IsLdloc())
                {
                    stack.Add(locals.GetValueOrDefault(instruction.GetLocal(method.Body.Variables)));
                    continue;
                }
                if (instruction.IsStloc())
                {
                    locals[instruction.GetLocal(method.Body.Variables)] = Pop();
                    continue;
                }
                if (instruction.OpCode.Code == Code.Dup) { var value = Pop(); stack.Add(value); stack.Add(value); continue; }
                if (instruction.OpCode.Code == Code.Nop) continue;
                if (instruction.OpCode.Code == Code.Castclass) continue;
                if (instruction.OpCode.Code is Code.Call or Code.Callvirt && instruction.Operand is IMethod called)
                {
                    if (IsResolution(called) && called.DeclaringType.FullName == "System.Reflection.Module" &&
                        called.MethodSig is { HasThis: true, Params.Count: 1 } &&
                        called.Name.String is "ResolveMethod" or "ResolveField" or "ResolveType" or "ResolveMember" &&
                        stack.Count >= 2 && stack[^2] is { Kind: Kind.Module } module &&
                        stack[^1] is { Kind: Kind.Token } token && module.Origin == token.Origin)
                        proven.Add(instruction);

                    if (called.MethodSig is { HasThis: true, Params.Count: 0 } &&
                        called.DeclaringType?.FullName is "System.Reflection.MemberInfo" or "System.Reflection.MethodBase" or
                            "System.Reflection.MethodInfo" or "System.Reflection.FieldInfo" or "System.Type" &&
                        called.Name.String is "get_Module" or "get_MetadataToken")
                    {
                        var receiver = Pop();
                        stack.Add(receiver.Kind == Kind.Member
                            ? new Value(called.Name == "get_Module" ? Kind.Module : Kind.Token, receiver.Origin)
                            : default);
                        continue;
                    }
                }
                instruction.CalculateStackUsage(out var pushes, out var pops);
                if (pops < 0 || pops > stack.Count) stack.Clear();
                else for (var count = 0; count < pops; count++) Pop();
                for (var count = 0; count < pushes; count++) stack.Add(default);
                // A managed address can let a call replace a local or argument behind the scan.
                if (instruction.OpCode.Code is Code.Ldloca or Code.Ldloca_S or Code.Ldarga or Code.Ldarga_S)
                {
                    locals.Clear();
                    foreach (var parameter in method.Parameters) arguments[parameter.Index] = new Value(Kind.Member, nextOrigin++);
                    stack.Clear();
                }
            }
            Value Pop()
            {
                if (stack.Count == 0) return default;
                var value = stack[^1]; stack.RemoveAt(stack.Count - 1); return value;
            }
        }
        return proven;
    }
}
