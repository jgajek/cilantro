using dnlib.DotNet;
using ReactorUnpack.Core.Interpretation;

namespace ReactorUnpack.Core.Recovery;

/// <summary>What a virtualizer's operations were seen to do, and where they were seen to go.</summary>
/// <param name="Watched">How many operations were seen performed, one after another.</param>
/// <param name="Jumps">By opcode, how often the next operation was not the following one.</param>
/// <param name="Targets">By operation, where it was seen to go.</param>
/// <param name="Effects">By opcode, what it did to the stack every time it was seen.</param>
public sealed record VirtualRun(
    int Watched,
    IReadOnlyDictionary<int, (int Taken, int Seen)> Jumps,
    IReadOnlyDictionary<int, int> Targets,
    IReadOnlyDictionary<int, VirtualOperation> Effects)
{
    /// <summary>Whether enough was seen for the counts to mean anything.</summary>
    public bool Learned => Watched >= Enough;

    /// <summary>How many operations must be seen before the counts are believed.</summary>
    /// <remarks>
    /// Low, because what makes a jump believable is having been seen more than once, which is
    /// checked for each kind separately. This only rules out a run that stopped so early that the
    /// order it went in says nothing.
    /// </remarks>
    internal const int Enough = 3;

    /// <summary>The effect an operation had on where the engine went next.</summary>
    /// <remarks>
    /// An operation seen every time to be followed by something other than the next in the list is
    /// an unconditional jump; one that sometimes is and sometimes is not is a conditional one. An
    /// operation seen only once is not called either, since a jump that happened to be taken and a
    /// jump that is always taken look the same from a single sighting.
    /// </remarks>
    public string? Describe(int opcode)
    {
        if (!Jumps.TryGetValue(opcode, out var counted) || counted.Taken == 0)
            return null;
        if (counted.Taken < counted.Seen)
            return "branch if";
        return counted.Seen > 1 ? "branch" : null;
    }
}

/// <summary>
/// Learns what an engine's operations do by watching it run, rather than by asking it questions.
/// </summary>
/// <remarks>
/// Asking has two limits that watching does not. An operation performed on its own cannot jump
/// anywhere, because the engine's position is wherever the last real run left it, so a handler that
/// works out a target from it produces a number nothing can check and the operation is written down
/// as inert — worse than saying nothing, since a reader told an operation is inert takes the code
/// after it for unreachable. And an operation that reaches for something the surrounding program
/// would have prepared faults when handed a stack we arranged, so it cannot be asked at all.
///
/// Watching costs nothing extra, because the program has to be run once anyway for the engine to
/// exist. Where it goes is read from the order it does things in: if the operation performed next
/// is not the next one along, the one before it jumped, and it jumped somewhere that really is
/// another operation of the same program. This needs no view of where the position is kept, which
/// may be an offset, an index, or nowhere addressable at all. What it does is read from the engine's
/// own stack either side of the operation, matched by identity so that what was left untouched
/// underneath is not counted.
///
/// What watching cannot do is see an operation the run never reached, or try values of its own. The
/// two ways of asking are kept apart and reported apart for that reason.
/// </remarks>
internal sealed class VirtualRunWatcher
{
    /// <summary>How many performances of one operation to keep before the rest are ignored.</summary>
    private const int Kept = 64;

    /// <summary>How many performances an operation must be seen through to be counted.</summary>
    private const int Counted = 2;

    /// <summary>How many differing sets of values a meaning must hold across to be named.</summary>
    /// <remarks>
    /// A real run repeats itself, and an operation performed twice on 0 and 0 agrees with almost
    /// any meaning. What separates them is having been seen on values that differ.
    /// </remarks>
    private const int Differing = 4;

    private readonly ModuleDef _module;
    private readonly StaticHeap _heap;
    private readonly MethodDef _dispatcher;
    private readonly FieldDef _opcodeField;
    private readonly FieldDef? _operandField;
    private readonly string _instructionType;
    private readonly Dictionary<long, int> _indices = [];
    private readonly Dictionary<int, (int Taken, int Seen)> _jumps = [];
    private readonly Dictionary<int, int> _targets = [];
    private readonly Dictionary<int, List<Performance>> _performances = [];
    private List<StaticValue>? _stack;
    private List<Held> _before = [];
    private long? _operand;
    private int _watched;
    private int _previous = -1;
    private int _opcode = -1;
    private int _performing = -1;
    private int _performingDepth = -1;
    private int _depth;

    public VirtualRunWatcher(
        ModuleDef module,
        StaticHeap heap,
        MethodDef dispatcher,
        FieldDef opcodeField,
        FieldDef? operandField,
        string instructionType)
    {
        _module = module;
        _heap = heap;
        _dispatcher = dispatcher;
        _opcodeField = opcodeField;
        _operandField = operandField;
        _instructionType = instructionType;
    }

    public VirtualRun Result() => new(_watched, _jumps, _targets, Effects());

    public void Entered(MethodDef method, IReadOnlyList<StaticValue> arguments)
    {
        _depth++;
        if (method != _dispatcher || arguments.Count < 2)
            return;

        var operation = arguments[^1];
        if (_indices.Count == 0 && !Learn(arguments[0]))
            return;
        if (!_indices.TryGetValue(operation.Bits, out var index) ||
            !_heap.TryReadField(operation, _opcodeField, out var code) ||
            code.Kind != StaticValueKind.Int32)
        {
            _previous = -1;
            return;
        }

        _watched++;
        if (_previous >= 0)
        {
            _jumps.TryGetValue(_opcode, out var counted);
            var jumped = index != _previous + 1;
            _jumps[_opcode] = (counted.Taken + (jumped ? 1 : 0), counted.Seen + 1);
            if (jumped)
                _targets[_previous] = index;
        }
        _previous = index;
        _opcode = (int)code.Bits;

        // Which frame is performing it has to be remembered, not just that one is: the handler
        // calls out to other methods, and an operation is only over when its own frame is.
        _performing = _opcode;
        _performingDepth = _depth;
        _operand = VirtualSemantics.Operand(_heap, operation, _operandField);
        _before = Stack();
    }

    public void Exited(MethodDef method)
    {
        var depth = _depth--;
        if (method != _dispatcher || _performing < 0 || depth != _performingDepth)
            return;
        var performing = _performing;
        _performing = -1;

        // With nowhere to read the stack, every operation looks like it did nothing, which is the
        // one answer worse than no answer at all.
        if (_stack is null)
            return;
        if (!_performances.TryGetValue(performing, out var seen))
            _performances[performing] = seen = [];
        if (seen.Count >= Kept)
            return;

        // What was underneath and untouched is not part of the effect, so the two stacks are
        // matched by the identity of what they hold rather than by their depth.
        var after = Stack();
        var kept = 0;
        while (kept < _before.Count && kept < after.Count && _before[kept].Id == after[kept].Id)
            kept++;
        seen.Add(new Performance(
            _before.Skip(kept).Select(held => held.Value).ToList(),
            after.Skip(kept).Select(held => held.Value).ToList(),
            _operand));
    }

    /// <summary>Notes where each operation sits, taken as the first of them begins.</summary>
    private bool Learn(StaticValue engine)
    {
        if (VirtualProgramRecovery.FindProgram(_heap, _module, engine, _instructionType) is not
            { } items)
        {
            return false;
        }
        for (var index = 0; index < items.Count; index++)
            _indices[items[index].Bits] = index;
        if (VirtualSemantics.SlotType(_heap, _module, engine) is { } slotType)
            _stack = VirtualSemantics.FindStack(_heap, _module, engine, slotType);
        return _indices.Count > 0;
    }

    private List<Held> Stack() =>
        _stack is null
            ? []
            : _stack.Select(slot => new Held(
                slot.Bits,
                VirtualSemantics.TryReadNumber(_heap, _module, slot, out var value) ? value : null))
                .ToList();

    /// <summary>One slot of the engine's stack: which slot it is, and the number in it if any.</summary>
    private sealed record Held(long Id, long? Value);

    /// <summary>One performance: what came off the stack, what went on, and what it carried.</summary>
    private sealed record Performance(
        IReadOnlyList<long?> Taken,
        IReadOnlyList<long?> Left,
        long? Operand);

    private Dictionary<int, VirtualOperation> Effects()
    {
        var found = new Dictionary<int, VirtualOperation>();
        foreach (var (opcode, seen) in _performances)
        {
            if (seen.Count < Counted)
                continue;
            var pops = seen[0].Taken.Count;
            var pushes = seen[0].Left.Count;
            if (seen.Any(one => one.Taken.Count != pops || one.Left.Count != pushes))
                continue;
            found[opcode] = new VirtualOperation(opcode, pops, pushes, Name(seen, pops, pushes));
        }
        return found;
    }

    /// <summary>
    /// Names an operation from the values it was really given, where they were varied enough for
    /// one meaning to survive and the others to be ruled out.
    /// </summary>
    private static string? Name(List<Performance> seen, int pops, int pushes) =>
        (pops, pushes) switch
        {
            (0, 1) => seen.All(one => one.Operand is not null && one.Left[0] == one.Operand) &&
                Varied(seen.Select(one => one.Operand))
                    ? "pushes its operand"
                    : null,
            (1, 1) => Only(seen, Unary),
            (2, 1) => Only(seen, Binary),
            _ => null
        };

    private static readonly (string Name, Func<long, long, long> Apply)[] Binary =
    [
        ("add", (left, right) => left + right),
        ("sub", (left, right) => left - right),
        ("multiply", (left, right) => left * right),
        ("xor", (left, right) => left ^ right),
        ("and", (left, right) => left & right),
        ("or", (left, right) => left | right)
    ];

    private static readonly (string Name, Func<long, long, long> Apply)[] Unary =
    [
        ("convert", (value, _) => value),
        ("negate", (value, _) => -value),
        ("not", (value, _) => ~value)
    ];

    /// <summary>
    /// The one meaning that held every time, where the values it held across were not all alike.
    /// </summary>
    private static string? Only(
        List<Performance> seen,
        (string Name, Func<long, long, long> Apply)[] meanings)
    {
        var usable = seen
            .Where(one => one.Taken.All(value => value is not null) && one.Left[0] is not null)
            .ToList();
        if (!Varied(usable.Select(one => one.Taken[0])))
            return null;

        var survived = meanings
            .Where(meaning => usable.All(one => Same(
                meaning.Apply(one.Taken[0]!.Value, one.Taken.Count > 1 ? one.Taken[^1]!.Value : 0),
                one.Left[0]!.Value)))
            .ToList();
        return survived.Count == 1 ? survived[0].Name : null;
    }

    /// <summary>
    /// Whether two numbers are the same, allowing for an engine that keeps 32 bits of them.
    /// </summary>
    private static bool Same(long computed, long left) =>
        computed == left || unchecked((int)computed) == unchecked((int)left);

    private static bool Varied(IEnumerable<long?> values) =>
        values.Where(value => value is not null).Distinct().Count() >= Differing;
}
