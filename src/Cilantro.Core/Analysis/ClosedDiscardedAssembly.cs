using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Recognizes an own-type assembly reference used only by casts, copies and pops.</summary>
internal static class ClosedDiscardedAssembly
{
    internal static IReadOnlySet<Instruction> Find(MethodDef method)
    {
        var result = new HashSet<Instruction>();
        if (!method.HasBody || method.Body.Instructions.Count > 8192) return result;
        var cfg = ControlFlowGraph.Build(method);
        foreach (var getter in method.Body.Instructions.Where(i => Framework(i,
            "System.Reflection.Assembly System.Type::get_Assembly()")))
        {
            var il = cfg.BlockOf(getter).Instructions;
            var before = il.TakeWhile(i => i != getter).Where(i => i.OpCode.Code != Code.Nop).ToArray();
            var at = before.Length - 1;
            if (at >= 0 && Cast(before[at], "System.Type")) at--;
            if (at < 1 || !Framework(before[at], "System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)") ||
                before[at - 1].OpCode.Code != Code.Ldtoken || before[at - 1].Operand is not ITypeDefOrRef type ||
                type.ResolveTypeDef()?.Module != method.Module) continue;
            var stack = new List<bool> { true };
            foreach (var instruction in il.SkipWhile(i => i != getter).Skip(1))
            {
                if (instruction.OpCode.Code == Code.Nop) continue;
                if (instruction.OpCode.Code == Code.Dup)
                { if (stack.Count == 0) break; stack.Add(stack[^1]); continue; }
                if (Cast(instruction, "System.Reflection.Assembly") || Cast(instruction, "System.Object"))
                { if (stack.Count == 0) break; continue; }
                instruction.CalculateStackUsage(out var pushes, out var pops);
                if (pops < 0 || pops > stack.Count) break;
                var marked = stack.Skip(stack.Count - pops).Any(v => v);
                if (marked && instruction.OpCode.Code != Code.Pop) break;
                stack.RemoveRange(stack.Count - pops, pops);
                if (!stack.Contains(true)) { result.Add(getter); break; }
                for (var n = 0; n < pushes; n++) stack.Add(false);
            }
        }
        return result;

        bool Framework(Instruction instruction, string signature) => instruction.OpCode.Code is Code.Call or Code.Callvirt &&
            instruction.Operand is IMethod call && call.FullName == signature && call.DeclaringType is TypeRef owner &&
            owner.DefinitionAssembly?.FullName == method.Module.CorLibTypes.AssemblyRef.FullName;
        bool Cast(Instruction instruction, string name) => instruction.OpCode.Code == Code.Castclass && instruction.Operand is TypeRef cast &&
            cast.FullName == name && cast.DefinitionAssembly?.FullName == method.Module.CorLibTypes.AssemblyRef.FullName;
    }
}
