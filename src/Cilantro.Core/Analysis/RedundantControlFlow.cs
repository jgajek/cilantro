using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

internal static class RedundantControlFlow
{
    internal static int ThreadBranches(MethodDef method)
    {
        var il = method.Body.Instructions;
        if (!il.Any(i => i.OpCode.Code is Code.Br or Code.Br_S && i.Operand is Instruction)) return 0;
        var graph = ControlFlowGraph.Build(method);
        var positions = il.Select((instruction, index) => (instruction, index)).ToDictionary(p => p.instruction, p => p.index);
        Instruction? Next(Instruction instruction) => instruction.OpCode.Code is Code.Br or Code.Br_S
            ? instruction.Operand as Instruction
            : instruction.OpCode.Code == Code.Nop && instruction.SequencePoint is null &&
              positions[instruction] + 1 < il.Count ? il[positions[instruction] + 1] : null;
        var resolved = new Dictionary<Instruction, Instruction>();
        foreach (var start in il.Where(i => i.OpCode.Code is Code.Br or Code.Br_S or Code.Nop))
        {
            if (resolved.ContainsKey(start)) continue;
            var path = new List<Instruction>();
            var visited = new HashSet<Instruction>();
            var current = start;
            while (!resolved.ContainsKey(current) && Next(current) is { } next &&
                   graph.HaveIdenticalExceptionRegions(current, next))
            {
                if (!visited.Add(current)) break;
                path.Add(current);
                current = next;
            }
            // A branch-only cycle must remain a cycle, not become fall-through.
            if (visited.Contains(current))
            {
                foreach (var member in path) resolved[member] = member;
                continue;
            }
            var destination = resolved.GetValueOrDefault(current, current);
            foreach (var member in path) resolved[member] = destination;
        }
        var changes = 0;
        foreach (var branch in il)
        {
            // Leave and switch have separate semantics. In particular, preserve every
            // application switch target and its ordering exactly as written.
            if (branch.OpCode.Code is Code.Leave or Code.Leave_S ||
                branch.OpCode.FlowControl is not (FlowControl.Branch or FlowControl.Cond_Branch) ||
                branch.Operand is not Instruction target || !resolved.TryGetValue(target, out var destination) ||
                destination == target || !graph.HaveIdenticalExceptionRegions(branch, destination)) continue;
            branch.Operand = destination;
            changes++;
        }
        return changes;
    }

    internal static int FoldBooleanDiamonds(MethodDef method)
    {
        var il = method.Body.Instructions;
        ControlFlowGraph? graph = null;
        var plans = new List<(Instruction Branch, Instruction Taken, Instruction Fallthrough)>();
        // Preserve the original condition and all alternate entries into the diamond.
        // Only this edge pair bypasses the literal materialization and immediate test.
        for (var at = il.Count - 6; at >= 0; at--)
        {
            var branch = il[at];
            if (branch.OpCode.Code is not (Code.Brtrue or Code.Brtrue_S or Code.Brfalse or Code.Brfalse_S) ||
                branch.Operand != il[at + 3] || !il[at + 1].IsLdcI4() || !il[at + 3].IsLdcI4() ||
                il[at + 2].OpCode.Code is not (Code.Br or Code.Br_S) || il[at + 2].Operand != il[at + 4]) continue;
            var test = il[at + 4];
            if (test.OpCode.Code is not (Code.Brtrue or Code.Brtrue_S or Code.Brfalse or Code.Brfalse_S) ||
                test.Operand is not Instruction destination) continue;
            graph ??= ControlFlowGraph.Build(method);
            if (!Enumerable.Range(at, 6).All(index => graph.HaveIdenticalExceptionRegions(branch, il[index])) ||
                !graph.HaveIdenticalExceptionRegions(branch, destination)) continue;
            var taken = Target(il[at + 3].GetLdcI4Value());
            var fallthrough = Target(il[at + 1].GetLdcI4Value());
            // Avoid creating a loop back into the bypassed expression.
            if (Enumerable.Range(at, 5).Any(index => il[index] == taken || il[index] == fallthrough)) continue;
            plans.Add((branch, taken, fallthrough));

            Instruction Target(int value) => (value != 0) == (test.OpCode.Code is Code.Brtrue or Code.Brtrue_S)
                ? destination : il[at + 5];
        }
        foreach (var (branch, taken, fallthrough) in plans)
        {
            branch.Operand = taken;
            il.Insert(il.IndexOf(branch) + 1, OpCodes.Br.ToInstruction(fallthrough));
        }
        return plans.Count;
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
