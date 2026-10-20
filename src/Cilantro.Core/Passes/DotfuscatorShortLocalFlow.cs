using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Passes;

/// <summary>Must-known short storage across normal edges, with no escaping local address.</summary>
internal static class DotfuscatorShortLocalFlow
{
    private readonly record struct Value(bool Known, int Number);

    internal static int Rewrite(MethodDef method)
    {
        using var transaction = new BodyMutationTransaction(method);
        if (!EvaluationStackAnalyzer.Analyze(method).Valid) return 0;
        var changed = DotfuscatorControlFlowPass.Rewrite(method);
        var graph = ControlFlowGraph.Build(method);
        if (graph.Blocks.Count > 4096) return 0;
        var il = method.Body.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop).ToArray();
        var targets = il.SelectMany(instruction => instruction.Operand is Instruction target ? [target] :
            instruction.Operand as IList<Instruction> ?? []).ToHashSet();
        var entries = method.Body.ExceptionHandlers.SelectMany(handler => new[] { handler.HandlerStart, handler.FilterStart })
            .OfType<Instruction>().Select(graph.BlockOf).ToHashSet();
        var positions = il.Select((instruction, index) => (instruction, index)).ToDictionary(item => item.instruction, item => item.index);
        var blocks = graph.Blocks.ToDictionary(block => block, block => block.Instructions.Where(positions.ContainsKey).ToArray());
        foreach (var local in method.Body.Variables.Where(local => local.Type.ElementType == ElementType.I2))
        {
            var addresses = il.Select((instruction, index) => (instruction, index)).Where(item =>
                item.instruction.OpCode.Code is Code.Ldloca or Code.Ldloca_S && item.instruction.GetLocal(method.Body.Variables) == local).ToArray();
            if (addresses.Length == 0 || addresses.Any(item => item.index + 1 >= il.Length ||
                il[item.index + 1].OpCode.Code != Code.Ldind_I2 || targets.Contains(il[item.index + 1]) ||
                graph.BlockOf(item.instruction) != graph.BlockOf(il[item.index + 1]) ||
                !graph.HaveIdenticalExceptionRegions(item.instruction, il[item.index + 1]))) continue;
            var outgoing = graph.Blocks.ToDictionary(block => block, _ => (Value?)null);
            var stable = false;
            for (var round = 0; round <= graph.Blocks.Count * 3; round++)
            {
                var moved = false;
                foreach (var block in graph.Blocks)
                {
                    var value = Incoming(block);
                    if (value is not null)
                        foreach (var instruction in blocks[block])
                            if (instruction.IsStloc() && instruction.GetLocal(method.Body.Variables) == local)
                                value = Stored(instruction);
                    if (outgoing[block] != value) { outgoing[block] = value; moved = true; }
                }
                if (!moved) { stable = true; break; }
            }
            if (!stable) continue;
            foreach (var block in graph.Blocks)
            {
                var value = Incoming(block);
                if (value is null) continue;
                foreach (var instruction in blocks[block])
                {
                    if (instruction.IsStloc() && instruction.GetLocal(method.Body.Variables) == local) value = Stored(instruction);
                    else if (value is { Known: true } known && instruction.OpCode.Code is Code.Ldloca or Code.Ldloca_S &&
                        instruction.GetLocal(method.Body.Variables) == local)
                    {
                        var read = il[positions[instruction] + 1];
                        instruction.OpCode = OpCodes.Ldc_I4; instruction.Operand = known.Number;
                        read.OpCode = OpCodes.Nop; read.Operand = null;
                        changed++;
                    }
                }
            }

            Value? Incoming(BasicBlock block)
            {
                if (block == graph.Entry || entries.Contains(block)) return new Value(false, 0);
                Value? answer = null;
                foreach (var edge in block.Predecessors)
                {
                    if (outgoing[edge.Source] is not { } source) continue;
                    var incoming = edge.Kind == ControlFlowEdgeKind.Exception ? new Value(false, 0) : source;
                    answer = answer is null ? incoming : answer == incoming ? answer : new Value(false, 0);
                }
                return answer;
            }

            Value Stored(Instruction store)
            {
                var at = positions[store];
                if (at > 0 && il[at - 1].IsLdcI4() && graph.BlockOf(il[at - 1]) == graph.BlockOf(store))
                    return new(true, unchecked((short)il[at - 1].GetLdcI4Value()));
                if (at >= 3 && il[at - 1].OpCode.Code is Code.Mul or Code.Div && il[at - 2].IsLdcI4() && il[at - 3].IsLdcI4() &&
                    graph.BlockOf(il[at - 3]) == graph.BlockOf(store))
                {
                    var left = il[at - 3].GetLdcI4Value(); var right = il[at - 2].GetLdcI4Value();
                    if (il[at - 1].OpCode.Code == Code.Mul) return new(true, unchecked((short)(left * right)));
                    if (right != 0 && (left != int.MinValue || right != -1)) return new(true, unchecked((short)(left / right)));
                }
                return new(false, 0);
            }
        }
        if (changed == 0 || !EvaluationStackAnalyzer.Analyze(method).Valid) return 0;
        transaction.Commit();
        return changed;
    }
}
