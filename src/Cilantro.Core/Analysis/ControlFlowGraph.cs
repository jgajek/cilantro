using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

public enum ControlFlowEdgeKind
{
    FallThrough,
    Branch,
    Switch,
    Exception
}

public sealed record ExceptionRegion(
    ExceptionHandler Handler,
    bool InTry,
    bool InHandler,
    bool InFilter);

public sealed record ControlFlowEdge(
    BasicBlock Source,
    BasicBlock Target,
    ControlFlowEdgeKind Kind);

public sealed class BasicBlock
{
    internal BasicBlock(int id, IReadOnlyList<Instruction> instructions)
    {
        Id = id;
        Instructions = instructions;
    }

    public int Id { get; }
    public IReadOnlyList<Instruction> Instructions { get; }
    public Instruction First => Instructions[0];
    public Instruction Last => Instructions[^1];
    public IReadOnlyList<ControlFlowEdge> Successors { get; internal set; } = [];
    public IReadOnlyList<ControlFlowEdge> Predecessors { get; internal set; } = [];
}

/// <summary>
/// A normal-flow CFG whose block boundaries also include all exception-clause boundaries.
/// Exception edges are deliberately conservative roots from protected blocks to their handlers.
/// </summary>
public sealed class ControlFlowGraph
{
    private readonly IReadOnlyDictionary<Instruction, BasicBlock> blockByInstruction;
    private readonly IReadOnlyDictionary<Instruction, IReadOnlyList<ExceptionRegion>> regions;

    private ControlFlowGraph(
        MethodDef method,
        IReadOnlyList<BasicBlock> blocks,
        IReadOnlyList<ControlFlowEdge> edges,
        IReadOnlyDictionary<Instruction, BasicBlock> blockByInstruction,
        IReadOnlyDictionary<Instruction, IReadOnlyList<ExceptionRegion>> regions)
    {
        Method = method;
        Blocks = blocks;
        Edges = edges;
        this.blockByInstruction = blockByInstruction;
        this.regions = regions;
    }

    public MethodDef Method { get; }
    public IReadOnlyList<BasicBlock> Blocks { get; }
    public IReadOnlyList<ControlFlowEdge> Edges { get; }
    public BasicBlock Entry => Blocks[0];

    public BasicBlock BlockOf(Instruction instruction) => blockByInstruction[instruction];

    public IReadOnlyList<ExceptionRegion> RegionsOf(Instruction instruction) =>
        regions.TryGetValue(instruction, out var value) ? value : [];

    public bool HaveIdenticalExceptionRegions(Instruction left, Instruction right)
    {
        var a = RegionsOf(left);
        var b = RegionsOf(right);
        if (ReferenceEquals(a, b)) return true;
        if (a.Count != b.Count) return false;
        for (var index = 0; index < a.Count; index++)
            if (!ReferenceEquals(a[index].Handler, b[index].Handler) ||
                a[index].InTry != b[index].InTry || a[index].InHandler != b[index].InHandler ||
                a[index].InFilter != b[index].InFilter) return false;
        return true;
    }

    public static ControlFlowGraph Build(MethodDef method)
    {
        ArgumentNullException.ThrowIfNull(method);
        if (!method.HasBody || method.Body.Instructions.Count == 0)
            throw new ArgumentException("The method must have a non-empty CIL body.", nameof(method));

        var instructions = method.Body.Instructions;
        var indices = instructions.Select((instruction, index) => (instruction, index))
            .ToDictionary(item => item.instruction, item => item.index);
        var blocks = PartitionBlocks(method, instructions, indices);

        var blockMap = blocks.SelectMany(block => block.Instructions.Select(i => (i, block)))
            .ToDictionary(item => item.i, item => item.block);
        var allEdges = new List<ControlFlowEdge>();
        var edgeKeys = new HashSet<(int Source, int Target, ControlFlowEdgeKind Kind)>();
        var successors = new List<ControlFlowEdge>?[blocks.Count];
        var predecessors = new List<ControlFlowEdge>?[blocks.Count];
        foreach (var block in blocks)
        {
            var last = block.Last;
            if (last.OpCode.Code == Code.Switch && last.Operand is IList<Instruction> cases)
            {
                foreach (var target in cases)
                    AddEdge(block, blockMap[target], ControlFlowEdgeKind.Switch);
                AddNext(block, ControlFlowEdgeKind.FallThrough);
            }
            else if (last.OpCode.FlowControl == FlowControl.Branch)
            {
                if (last.Operand is Instruction target)
                    AddEdge(block, blockMap[target], ControlFlowEdgeKind.Branch);
            }
            else if (last.OpCode.FlowControl == FlowControl.Cond_Branch)
            {
                if (last.Operand is Instruction target)
                    AddEdge(block, blockMap[target], ControlFlowEdgeKind.Branch);
                AddNext(block, ControlFlowEdgeKind.FallThrough);
            }
            else if (last.OpCode.FlowControl is not (FlowControl.Return or FlowControl.Throw))
            {
                AddNext(block, ControlFlowEdgeKind.FallThrough);
            }
        }

        var regionMap = ExceptionRegionMap.BuildRegionMap(method, instructions, indices);
        foreach (var handler in method.Body.ExceptionHandlers)
        {
            var exceptionalTarget = handler.FilterStart ?? handler.HandlerStart;
            if (exceptionalTarget is null)
                continue;
            foreach (var block in blocks.Where(block =>
                         regionMap[block.First].Any(region =>
                             ReferenceEquals(region.Handler, handler) && region.InTry)))
            {
                AddEdge(block, blockMap[exceptionalTarget],
                    ControlFlowEdgeKind.Exception);
            }
        }

        foreach (var block in blocks)
        {
            block.Successors = successors[block.Id]?.ToArray() ?? [];
            block.Predecessors = predecessors[block.Id]?.ToArray() ?? [];
        }
        return new ControlFlowGraph(method, blocks, allEdges, blockMap, regionMap);

        void AddNext(BasicBlock block, ControlFlowEdgeKind kind)
        {
            if (block.Id + 1 < blocks.Count)
                AddEdge(block, blocks[block.Id + 1], kind);
        }

        void AddEdge(BasicBlock source, BasicBlock target, ControlFlowEdgeKind kind)
        {
            // Keep first-occurrence order, including distinct edge kinds between the same pair.
            // Index each accepted edge once instead of rescanning the growing edge list and then
            // scanning it twice more for every block to assemble adjacency.
            if (!edgeKeys.Add((source.Id, target.Id, kind)))
                return;
            var edge = new ControlFlowEdge(source, target, kind);
            allEdges.Add(edge);
            (successors[source.Id] ??= []).Add(edge);
            (predecessors[target.Id] ??= []).Add(edge);
        }
    }

    // Consumers of block boundaries do not need adjacency or exception edges.
    internal static IReadOnlyList<BasicBlock> PartitionBlocks(MethodDef method)
    {
        var instructions = method.Body.Instructions;
        var indices = instructions.Select((instruction, index) => (instruction, index))
            .ToDictionary(item => item.instruction, item => item.index);
        return PartitionBlocks(method, instructions, indices);
    }

    private static List<BasicBlock> PartitionBlocks(MethodDef method, IList<Instruction> instructions,
        Dictionary<Instruction, int> indices)
    {
        var leaders = new HashSet<Instruction> { instructions[0] };

        foreach (var instruction in instructions)
        {
            if (instruction.Operand is Instruction target)
                leaders.Add(target);
            else if (instruction.Operand is IList<Instruction> targets)
                leaders.UnionWith(targets);

            var index = indices[instruction];
            if (EndsBlock(instruction) && index + 1 < instructions.Count)
                leaders.Add(instructions[index + 1]);
        }

        foreach (var handler in method.Body.ExceptionHandlers)
        {
            AddBoundary(handler.TryStart);
            AddBoundary(handler.TryEnd);
            AddBoundary(handler.HandlerStart);
            AddBoundary(handler.HandlerEnd);
            AddBoundary(handler.FilterStart);
        }

        var blocks = new List<BasicBlock>();
        var current = new List<Instruction>();
        foreach (var instruction in instructions)
        {
            if (current.Count != 0 && leaders.Contains(instruction))
            {
                blocks.Add(new BasicBlock(blocks.Count, current.ToArray()));
                current.Clear();
            }
            current.Add(instruction);
        }
        if (current.Count != 0)
            blocks.Add(new BasicBlock(blocks.Count, current.ToArray()));

        return blocks;

        void AddBoundary(Instruction? boundary)
        {
            if (boundary is not null && indices.ContainsKey(boundary))
                leaders.Add(boundary);
        }

    }

    private static bool EndsBlock(Instruction instruction) =>
        instruction.OpCode.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch or
            FlowControl.Return or FlowControl.Throw;

    internal static ExceptionRegionMap BuildExceptionRegions(MethodDef method) =>
        ExceptionRegionMap.Build(method);
}

/// <summary>Clause membership without constructing blocks or edges. Rebuild after body edits.</summary>
internal sealed class ExceptionRegionMap
{
    private readonly IReadOnlyDictionary<Instruction, IReadOnlyList<ExceptionRegion>> regions;

    private ExceptionRegionMap(IReadOnlyDictionary<Instruction, IReadOnlyList<ExceptionRegion>> regions) =>
        this.regions = regions;

    internal bool HaveIdenticalExceptionRegions(Instruction left, Instruction right)
    {
        var a = regions.GetValueOrDefault(left) ?? [];
        var b = regions.GetValueOrDefault(right) ?? [];
        if (ReferenceEquals(a, b)) return true;
        if (a.Count != b.Count) return false;
        for (var index = 0; index < a.Count; index++)
            if (!ReferenceEquals(a[index].Handler, b[index].Handler) ||
                a[index].InTry != b[index].InTry || a[index].InHandler != b[index].InHandler ||
                a[index].InFilter != b[index].InFilter) return false;
        return true;
    }

    internal static ExceptionRegionMap Build(MethodDef method)
    {
        if (method.Body.ExceptionHandlers.Count == 0) return new(new Dictionary<Instruction, IReadOnlyList<ExceptionRegion>>());
        var il = method.Body.Instructions;
        var indices = il.Select((instruction, index) => (instruction, index))
            .ToDictionary(item => item.instruction, item => item.index);
        return new(BuildRegionMap(method, il, indices));
    }

    internal static Dictionary<Instruction, IReadOnlyList<ExceptionRegion>> BuildRegionMap(
        MethodDef method,
        IList<Instruction> instructions,
        Dictionary<Instruction, int> indices)
    {
        if (method.Body.ExceptionHandlers.Count == 0) return [];
        var result = new Dictionary<Instruction, IReadOnlyList<ExceptionRegion>>(instructions.Count);
        // Region membership changes only at clause boundaries. Share one immutable
        // snapshot across each interval instead of allocating and testing every clause
        // again for every instruction (and every CFG rebuilt during simplification).
        var boundaries = new HashSet<int> { 0 };
        foreach (var handler in method.Body.ExceptionHandlers)
        {
            Boundary(handler.TryStart);
            Boundary(handler.TryEnd);
            Boundary(handler.HandlerStart);
            Boundary(handler.HandlerEnd);
            Boundary(handler.FilterStart);
        }
        IReadOnlyList<ExceptionRegion> current = [];
        for (var index = 0; index < instructions.Count; index++)
        {
            if (boundaries.Contains(index))
                current = Memberships(index);
            result[instructions[index]] = current;
        }
        return result;

        void Boundary(Instruction? instruction)
        {
            if (instruction is not null && indices.TryGetValue(instruction, out var index))
                boundaries.Add(index);
        }

        IReadOnlyList<ExceptionRegion> Memberships(int index)
        {
            var memberships = new List<ExceptionRegion>();
            foreach (var handler in method.Body.ExceptionHandlers)
            {
                var inTry = Contains(index, handler.TryStart, handler.TryEnd);
                var inHandler = Contains(index, handler.HandlerStart, handler.HandlerEnd);
                var inFilter = handler.FilterStart is not null &&
                               Contains(index, handler.FilterStart, handler.HandlerStart);
                if (inTry || inHandler || inFilter)
                    memberships.Add(new ExceptionRegion(handler, inTry, inHandler, inFilter));
            }
            return memberships.Count == 0 ? [] : memberships.ToArray();
        }

        bool Contains(int index, Instruction? start, Instruction? end)
        {
            if (start is null || !indices.TryGetValue(start, out var startIndex))
                return false;
            var endIndex = end is not null && indices.TryGetValue(end, out var value)
                ? value
                : instructions.Count;
            return index >= startIndex && index < endIndex;
        }
    }
}
