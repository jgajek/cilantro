using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ControlFlowGraphTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void NestedFilterAndOpenEndedRegionsKeepEveryInstructionMembership(bool openEnded)
    {
        using var module = new ModuleDefUser("regions");
        var il = Enumerable.Range(0, 32).Select(_ => OpCodes.Nop.ToInstruction()).ToArray();
        il[^1].OpCode = OpCodes.Ret;
        var method = Method(module, il);
        var ranges = new[]
        {
            (Try: 1, End: 10, Filter: -1, Handler: 10, HandlerEnd: 25),
            (Try: 3, End: 6, Filter: 6, Handler: 8, HandlerEnd: 10),
            (Try: 11, End: 15, Filter: -1, Handler: 15, HandlerEnd: openEnded ? 32 : 28)
        };
        foreach (var range in ranges)
            method.Body.ExceptionHandlers.Add(new ExceptionHandler(
                range.Filter < 0 ? ExceptionHandlerType.Finally : ExceptionHandlerType.Filter)
            {
                TryStart = il[range.Try], TryEnd = il[range.End],
                FilterStart = range.Filter < 0 ? null : il[range.Filter],
                HandlerStart = il[range.Handler], HandlerEnd = range.HandlerEnd == 32 ? null : il[range.HandlerEnd]
            });
        var graph = ControlFlowGraph.Build(method);
        for (var index = 0; index < il.Length; index++)
        {
            var expected = ranges.Select((range, clause) => (
                Handler: method.Body.ExceptionHandlers[clause],
                InTry: index >= range.Try && index < range.End,
                InHandler: index >= range.Handler && index < range.HandlerEnd,
                InFilter: range.Filter >= 0 && index >= range.Filter && index < range.Handler))
                .Where(region => region.InTry || region.InHandler || region.InFilter);
            Assert.Equal(expected, graph.RegionsOf(il[index]).Select(region =>
                (region.Handler, region.InTry, region.InHandler, region.InFilter)));
        }
    }

    [Fact]
    public void LookupScopesNestAndDoNotRetainRenamedTypesAfterDisposal()
    {
        using var module = new ModuleDefUser("lookup");
        var type = new TypeDefUser("Tests", "Original");
        module.Types.Add(type);
        Assert.False(module.EnableTypeDefFindCache);
        using (new TypeDefinitionLookupScope(module))
        {
            Assert.Same(type, module.Find("Tests.Original", false));
            using (new TypeDefinitionLookupScope(module))
                Assert.True(module.EnableTypeDefFindCache);
            Assert.True(module.EnableTypeDefFindCache);
        }
        Assert.False(module.EnableTypeDefFindCache);
        type.Name = "Renamed";
        using (new TypeDefinitionLookupScope(module))
        {
            Assert.Null(module.Find("Tests.Original", false));
            Assert.Same(type, module.Find("Tests.Renamed", false));
        }
        Assert.False(module.EnableTypeDefFindCache);
    }

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
