namespace ReactorUnpack.Core.Interpretation;

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
    Intrinsic
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

    public StaticValue Operation(
        StaticValue value,
        ProvenanceKind kind,
        string location,
        string detail,
        params StaticValue[] inputs)
    {
        var parents = inputs
            .Select(input => input.ProvenanceId)
            .Where(id => id != 0)
            .Distinct()
            .ToArray();
        return value.WithProvenance(Intern(kind, location, detail, value, parents));
    }

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
        int[] parents)
    {
        var depth = parents.Length == 0
            ? 1
            : parents.Max(id => id > 0 && id <= _nodes.Count ? _nodes[id - 1].Depth : 0) + 1;
        if (_nodes.Count >= _maximumNodes - 1 || depth > _maximumDepth)
            return BudgetNode();
        var key = new ProvenanceKey(
            kind,
            location,
            detail,
            value.Kind,
            value.Bits,
            string.Join(",", parents));
        if (_ids.TryGetValue(key, out var existing))
            return existing;
        var id = _nodes.Count + 1;
        _nodes.Add(new ProvenanceNode(
            id, kind, location, detail, value.Kind, value.Bits, parents, depth));
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
        string Parents);
}
