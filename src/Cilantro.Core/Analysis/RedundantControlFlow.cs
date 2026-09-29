using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

internal static class RedundantControlFlow
{
    internal static int RemoveCarriedIntegerDiscards(MethodDef method)
    {
        var pairs = new List<(Instruction Producer, Instruction Consumer)>();
        foreach (var block in ControlFlowGraph.Build(method).Blocks)
        {
            // Track only values produced in this block. Incoming values are unknown;
            // exception and branch entries must never inherit producer identities.
            var stack = new List<Instruction?>();
            foreach (var instruction in block.Instructions)
            {
                if (instruction.OpCode.OpCodeType == OpCodeType.Prefix)
                { stack.Clear(); continue; }
                instruction.CalculateStackUsage(out var pushes, out var pops);
                if (pops < 0 || pushes < 0)
                { stack.Clear(); continue; }
                if (instruction.OpCode.Code == Code.Pop && stack.Count > 0 && stack[^1] is { } producer)
                    pairs.Add((producer, instruction));
                var removed = Math.Min(pops, stack.Count);
                stack.RemoveRange(stack.Count - removed, removed);
                // Dup deliberately loses identity: neither copy is independently dead.
                for (var index = 0; index < pushes; index++)
                    stack.Add(instruction.IsLdcI4() ? instruction : null);
            }
        }
        foreach (var (producer, consumer) in pairs)
        {
            producer.OpCode = consumer.OpCode = OpCodes.Nop;
            producer.Operand = consumer.Operand = null;
        }
        return pairs.Count;
    }

    internal static int RemoveUnreadIntegerStores(MethodDef method)
    {
        var variables = method.Body.Variables;
        // Int32 stores have no narrowing, floating-point rounding or object-lifetime
        // effects. Address-taken locals and reads anywhere, including handlers, remain.
        var unused = variables.Where(v => v.Type.ElementType is ElementType.I4 or ElementType.U4).ToHashSet();
        foreach (var instruction in method.Body.Instructions)
            if ((instruction.IsLdloc() || instruction.OpCode.Code is Code.Ldloca or Code.Ldloca_S) &&
                instruction.GetLocal(variables) is { } local) unused.Remove(local);
        var changes = 0;
        foreach (var instruction in method.Body.Instructions)
            if (instruction.IsStloc() && instruction.GetLocal(variables) is { } local && unused.Contains(local))
            {
                instruction.OpCode = OpCodes.Pop;
                instruction.Operand = null;
                changes++;
            }
        return changes;
    }

    internal static int FoldConvergentBranches(MethodDef method)
    {
        var il = method.Body.Instructions;
        if (!il.Any(i => i.OpCode.FlowControl == FlowControl.Cond_Branch)) return 0;
        var graph = ControlFlowGraph.Build(method);
        var indices = il.Select((instruction, index) => (instruction, index)).ToDictionary(p => p.instruction, p => p.index);
        var plans = new List<(Instruction Branch, Instruction Target, int Pops)>();
        for (var index = 0; index + 1 < il.Count; index++)
        {
            var branch = il[index];
            if (branch.OpCode.FlowControl != FlowControl.Cond_Branch) continue;
            var target = Follow(il[index + 1], branch);
            if (target is null) continue;
            var targets = branch.Operand is Instruction single ? [single] :
                branch.Operand as IList<Instruction>;
            if (targets is null || targets.Any(t => Follow(t, branch) != target)) continue;
            branch.CalculateStackUsage(out var pushes, out var pops);
            if (pushes != 0 || pops is not (1 or 2)) continue;
            plans.Add((branch, target.Value.Target, pops + target.Value.Pops));
        }
        foreach (var (branch, target, pops) in plans)
        {
            // Leave the original instruction as the first pop so existing incoming
            // branches still consume their operands. Their evaluation is not discarded.
            branch.OpCode = OpCodes.Pop;
            branch.Operand = null;
            var at = il.IndexOf(branch) + 1;
            for (var count = 1; count < pops; count++) il.Insert(at++, OpCodes.Pop.ToInstruction());
            il.Insert(at, OpCodes.Br.ToInstruction(target));
        }
        return plans.Count;

        (Instruction Target, int Pops)? Follow(Instruction current, Instruction source)
        {
            var seen = new HashSet<Instruction>();
            var pops = 0;
            for (var hops = 0; hops < 128; hops++)
            {
                if (!seen.Add(current) || !graph.HaveIdenticalExceptionRegions(source, current)) return null;
                if (current.OpCode.Code is Code.Br or Code.Br_S && current.Operand is Instruction next)
                { current = next; continue; }
                if (current.OpCode.Code == Code.Nop && indices.TryGetValue(current, out var at) && at + 1 < il.Count)
                { current = il[at + 1]; continue; }
                if (current.OpCode.Code == Code.Pop && indices.TryGetValue(current, out at) && at + 1 < il.Count)
                { pops++; current = il[at + 1]; continue; }
                return (current, pops);
            }
            return null;
        }
    }
}
