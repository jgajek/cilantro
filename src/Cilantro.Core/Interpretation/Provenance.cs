namespace Cilantro.Core.Interpretation;

public enum ProvenanceKind
{
    Budget,
    Literal,
    Argument,
    Default,
    Resource,
    Metadata,
    StaticField,
    InstanceField,
    ArrayElement,
    ManagedReference,
    NativeReference,
    Unary,
    Binary,
    Conversion,
    Comparison,
    Call,
    Intrinsic,

    /// <summary>
    /// The value was stated by somebody about the machine, rather than derived from the sample's own
    /// bytes.
    /// </summary>
    Host,

    /// <summary>
    /// The value is what the tool assumes about the machine, nobody having said otherwise.
    /// </summary>
    /// <remarks>
    /// Kept apart from <see cref="Host"/> because the two are answerable in different ways. A stated
    /// fact can be checked against the machine somebody described; an assumed one is the tool's own
    /// portrait of a plausible Windows computer, and a reader tracing a recovered value back to one
    /// has found a place where the reading would change if the real machine differed. Both are
    /// disclosed; only this one is nobody's assertion but the tool's.
    /// </remarks>
    Assumed,

    /// <summary>
    /// The value was declared to be what a call the machine does not model returns.
    /// </summary>
    /// <remarks>
    /// The weakest provenance there is, and kept distinct from <see cref="Host"/> for that reason. A
    /// host fact is a statement about a computer, checkable against one; this is a statement about
    /// what somebody else's code does, made by whoever passed the file in. Anything downstream of it
    /// is only as good as that statement, and a reader following a recovered value back should be
    /// able to see that it rests on one.
    /// </remarks>
    Declared
}

public readonly record struct ProvenanceNode(
    int Id,
    ProvenanceKind Kind,
    string Location,
    string Detail,
    StaticValueKind ValueKind,
    long ValueBits,
    IReadOnlyList<int> Parents,
    int Depth);

public sealed class ProvenanceGraph
{
    private readonly int _maximumNodes;
    private readonly int _maximumDepth;
    private readonly int _maximumRenderedNodes;
    private readonly Dictionary<ProvenanceKey, int> _ids = [];
    private readonly List<ProvenanceNode> _nodes = [];
    private int _budgetId;

    public ProvenanceGraph(
        int maximumNodes,
        int maximumDepth,
        int maximumRenderedNodes)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumNodes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumDepth);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumRenderedNodes);
        _maximumNodes = maximumNodes;
        _maximumDepth = maximumDepth;
        _maximumRenderedNodes = maximumRenderedNodes;
    }

    public int Count => _nodes.Count;

    public StaticValue Origin(
        StaticValue value,
        ProvenanceKind kind,
        string location,
        string detail) =>
        value.WithProvenance(Intern(kind, location, detail, value, []));

    /// <summary>Records a value as having been computed from the values it came from.</summary>
    /// <remarks>
    /// On the hot path of the machine, so it accounts for its inputs without allocating: the inputs
    /// arrive in a span the caller does not have to put on the heap, and the parents are collected
    /// into one small enough to stand on the stack. Distinctness is checked by looking down the few
    /// found so far, an instruction having only ever a handful of operands.
    /// </remarks>
    public StaticValue Operation(
        StaticValue value,
        ProvenanceKind kind,
        string location,
        string detail,
        params ReadOnlySpan<StaticValue> inputs)
    {
        Span<int> parents = inputs.Length <= MostOperandsOnTheStack
            ? stackalloc int[MostOperandsOnTheStack]
            : new int[inputs.Length];
        var found = 0;
        foreach (var input in inputs)
        {
            var id = input.ProvenanceId;
            if (id == 0 || parents[..found].Contains(id))
                continue;
            parents[found++] = id;
        }
        return value.WithProvenance(Intern(kind, location, detail, value, parents[..found]));
    }

    /// <summary>Enough for the operands of any instruction, past which the heap is used instead.</summary>
    private const int MostOperandsOnTheStack = 8;

    public string Render(int id)
    {
        if (id <= 0 || id > _nodes.Count)
            return "provenance unavailable";
        var lines = new List<string>();
        var pending = new Queue<(int Id, int Indent)>();
        var visited = new HashSet<int>();
        pending.Enqueue((id, 0));
        while (pending.Count != 0 && lines.Count < _maximumRenderedNodes)
        {
            var item = pending.Dequeue();
            if (!visited.Add(item.Id) || item.Id <= 0 || item.Id > _nodes.Count)
                continue;
            var node = _nodes[item.Id - 1];
            lines.Add(
                $"{new string(' ', item.Indent * 2)}#{node.Id} {node.Kind} " +
                $"{node.Location} {node.Detail} => {node.ValueKind}:{node.ValueBits}");
            foreach (var parent in node.Parents)
                pending.Enqueue((parent, item.Indent + 1));
        }
        if (pending.Count != 0)
            lines.Add("… provenance render budget reached");
        return string.Join(" | ", lines);
    }

    private int Intern(
        ProvenanceKind kind,
        string location,
        string detail,
        StaticValue value,
        ReadOnlySpan<int> parents)
    {
        var deepest = 0;
        foreach (var parent in parents)
        {
            if (parent > 0 && parent <= _nodes.Count)
                deepest = Math.Max(deepest, _nodes[parent - 1].Depth);
        }
        var depth = parents.Length == 0 ? 1 : deepest + 1;
        if (_nodes.Count >= _maximumNodes - 1 || depth > _maximumDepth)
            return BudgetNode();
        var key = new ProvenanceKey(
            kind,
            location,
            detail,
            value.Kind,
            value.Bits,
            parents.Length > 0 ? parents[0] : 0,
            parents.Length > 1 ? parents[1] : 0,
            // Only an operation with more parents than an instruction has operands pays for a string,
            // and no parent is ever node zero, so the first two stand apart from having none.
            parents.Length > 2 ? string.Join(",", parents[2..].ToArray()) : string.Empty);
        if (_ids.TryGetValue(key, out var existing))
            return existing;
        var id = _nodes.Count + 1;
        _nodes.Add(new ProvenanceNode(
            id, kind, location, detail, value.Kind, value.Bits, parents.ToArray(), depth));
        _ids.Add(key, id);
        return id;
    }

    private int BudgetNode()
    {
        if (_budgetId != 0)
            return _budgetId;
        var id = _nodes.Count + 1;
        _nodes.Add(new ProvenanceNode(
            id,
            ProvenanceKind.Budget,
            "bounded",
            "provenance budget reached",
            StaticValueKind.Unknown,
            0,
            [],
            1));
        _budgetId = id;
        return id;
    }

    private readonly record struct ProvenanceKey(
        ProvenanceKind Kind,
        string Location,
        string Detail,
        StaticValueKind ValueKind,
        long ValueBits,
        int FirstParent,
        int SecondParent,
        string FurtherParents);
}
