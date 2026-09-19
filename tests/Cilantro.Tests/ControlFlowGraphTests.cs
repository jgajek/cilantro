using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ControlFlowGraphTests
{
    [Fact]
    public void DuplicateTargetsKeepDistinctKindsAndFirstOccurrenceOrder()
    {
        using var module = new ModuleDefUser("cfg");
        var first = OpCodes.Ldc_I4_0.ToInstruction();
        var exit = OpCodes.Ret.ToInstruction();
        var next = OpCodes.Br.ToInstruction(exit);
        var method = Method(module, first,
            OpCodes.Switch.ToInstruction(new[] { exit, exit, next, first }), next, exit);
        // Multiple clauses can contribute the same conservative exceptional edge.
        for (var i = 0; i < 2; i++)
            method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = first, TryEnd = next, HandlerStart = exit,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef
            });

        var graph = ControlFlowGraph.Build(method);

        Assert.Equal(new[]
        {
            (0, 2, ControlFlowEdgeKind.Switch),
            (0, 1, ControlFlowEdgeKind.Switch),
            (0, 0, ControlFlowEdgeKind.Switch),
            (0, 1, ControlFlowEdgeKind.FallThrough),
            (1, 2, ControlFlowEdgeKind.Branch),
            (0, 2, ControlFlowEdgeKind.Exception)
        }, graph.Edges.Select(edge => (edge.Source.Id, edge.Target.Id, edge.Kind)));
        Assert.Equal(2, graph.RegionsOf(first).Count);
        Assert.All(graph.RegionsOf(first), region => Assert.True(region.InTry));
        AssertAdjacency(graph);
        Assert.Empty(graph.BlockOf(exit).Successors);
    }

    [Fact]
    public void ConditionalBranchToTheNextBlockKeepsBothEdges()
    {
        using var module = new ModuleDefUser("cfg");
        var exit = OpCodes.Ret.ToInstruction();
        var graph = ControlFlowGraph.Build(Method(module,
            OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Brtrue.ToInstruction(exit), exit));

        Assert.Equal(new[] { ControlFlowEdgeKind.Branch, ControlFlowEdgeKind.FallThrough },
            graph.Edges.Select(edge => edge.Kind));
        Assert.All(graph.Edges, edge => Assert.Same(graph.BlockOf(exit), edge.Target));
        AssertAdjacency(graph);
        Assert.Empty(graph.Entry.Predecessors);
    }

    [Fact]
    public void LargeBranchChainHasOnlyItsImmediateNeighbors()
    {
        using var module = new ModuleDefUser("cfg");
        var instructions = Enumerable.Range(0, 16000).Select(_ => OpCodes.Nop.ToInstruction()).ToArray();
        for (var i = 0; i < instructions.Length - 1; i++)
        {
            instructions[i].OpCode = OpCodes.Br;
            instructions[i].Operand = instructions[i + 1];
        }
        instructions[^1].OpCode = OpCodes.Ret;

        var graph = ControlFlowGraph.Build(Method(module, instructions));

        Assert.Equal(instructions.Length, graph.Blocks.Count);
        Assert.Equal(instructions.Length - 1, graph.Edges.Count);
        for (var i = 0; i < graph.Blocks.Count; i++)
        {
            var block = graph.Blocks[i];
            Assert.Same(block, graph.BlockOf(instructions[i]));
            if (i > 0)
                Assert.Same(graph.Edges[i - 1], Assert.Single(block.Predecessors));
            else
                Assert.Empty(block.Predecessors);
            if (i < graph.Blocks.Count - 1)
                Assert.Same(graph.Edges[i], Assert.Single(block.Successors));
            else
                Assert.Empty(block.Successors);
        }
    }

    private static void AssertAdjacency(ControlFlowGraph graph)
    {
        foreach (var block in graph.Blocks)
        {
            var outgoing = graph.Edges.Where(edge => edge.Source == block).ToArray();
            var incoming = graph.Edges.Where(edge => edge.Target == block).ToArray();
            Assert.Equal(outgoing.Length, block.Successors.Count);
            Assert.Equal(incoming.Length, block.Predecessors.Count);
            for (var i = 0; i < outgoing.Length; i++)
                Assert.Same(outgoing[i], block.Successors[i]);
            for (var i = 0; i < incoming.Length; i++)
                Assert.Same(incoming[i], block.Predecessors[i]);
        }
    }

    private static MethodDefUser Method(ModuleDef module, params Instruction[] instructions)
    {
        var method = new MethodDefUser("Entry", MethodSig.CreateStatic(module.CorLibTypes.Void))
        { Body = new CilBody() };
        foreach (var instruction in instructions)
            method.Body.Instructions.Add(instruction);
        return method;
    }
}
