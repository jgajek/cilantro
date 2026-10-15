using System.Collections.Immutable;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Removes unobserved stack copies and literal computations within a basic block.</summary>
internal static class DiscardedStackValues
{
    private sealed record Value(ImmutableStack<Instruction> Recipe, bool Null = false, bool Number = false);
    private static readonly Value Unknown = new(ImmutableStack<Instruction>.Empty);

    internal static int Remove(MethodDef method)
    {
        var read = method.Body.Instructions.Where(i => i.IsLdloc() || i.OpCode.Code is Code.Ldloca or Code.Ldloca_S)
            .Select(i => i.GetLocal(method.Body.Variables)).ToHashSet();
        var addressed = method.Body.Instructions.Where(i => i.OpCode.Code is Code.Ldloca or Code.Ldloca_S)
            .Select(i => i.GetLocal(method.Body.Variables)).ToHashSet();
        var remove = new HashSet<Instruction>();
        foreach (var block in ControlFlowGraph.Build(method).Blocks)
        {
            var stack = new List<Value>();
            var nulls = new HashSet<Local>();
            foreach (var instruction in block.Instructions)
            {
                if (instruction.OpCode.OpCodeType == OpCodeType.Prefix)
                { stack.Clear(); nulls.Clear(); continue; }
                if (instruction.OpCode.Code == Code.Dup)
                {
                    var value = stack.Count == 0 ? Unknown : stack[^1];
                    // The original producer remains necessary unless a later round
                    // sees that this copy has itself disappeared.
                    if (stack.Count == 0) stack.Add(value);
                    else stack[^1] = value with { Recipe = ImmutableStack<Instruction>.Empty };
                    stack.Add(new(ImmutableStack.Create(instruction), value.Null, value.Number));
                    continue;
                }
                instruction.CalculateStackUsage(out var pushes, out var pops);
                if (pops < 0 || pushes < 0) { stack.Clear(); nulls.Clear(); continue; }
                var top = stack.Count == 0 ? Unknown : stack[^1];
                var local = instruction.IsStloc() || instruction.IsLdloc() ? instruction.GetLocal(method.Body.Variables) : null;
                var deadNullStore = instruction.IsStloc() && top.Null && local is not null && !read.Contains(local) &&
                    local.Type.ElementType is ElementType.Object or ElementType.Class or ElementType.String or ElementType.SZArray or ElementType.Array;
                if ((instruction.OpCode.Code == Code.Pop || deadNullStore) && !top.Recipe.IsEmpty)
                { remove.UnionWith(top.Recipe); remove.Add(instruction); }
                if (instruction.IsStloc() && local is not null)
                {
                    nulls.Remove(local);
                    if (top.Null && !addressed.Contains(local)) nulls.Add(local);
                }
                var available = Math.Min(pops, stack.Count);
                stack.RemoveRange(stack.Count - available, available);
                var result = Unknown;
                if (instruction.OpCode.Code == Code.Ldnull) result = new(ImmutableStack.Create(instruction), Null: true);
                else if (instruction.IsLdcI4() || instruction.OpCode.Code == Code.Ldc_I8) result = new(ImmutableStack.Create(instruction), Number: true);
                else if (instruction.IsLdloc() && local is not null && nulls.Contains(local)) result = new(ImmutableStack.Create(instruction), Null: true);
                else if (top.Number && !top.Recipe.IsEmpty && pops == 1 && pushes == 1 &&
                    instruction.OpCode.Code is Code.Conv_I or Code.Conv_U or Code.Conv_I4 or Code.Conv_U4 or Code.Conv_I8 or Code.Conv_U8)
                    result = new(top.Recipe.Push(instruction), Number: true);
                for (var n = 0; n < pushes; n++) stack.Add(result);
            }
        }
        foreach (var instruction in remove) { instruction.OpCode = OpCodes.Nop; instruction.Operand = null; }
        return remove.Count;
    }
}
