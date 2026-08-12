using dnlib.DotNet;
using ReactorUnpack.Core.Interpretation;

namespace ReactorUnpack.Core.Recovery;

/// <summary>Where a virtualizer's operations were seen to send it.</summary>
/// <param name="Watched">How many operations were seen performed, one after another.</param>
/// <param name="Jumps">By opcode, how often the next operation was not the following one.</param>
/// <param name="Targets">By operation, where it was seen to go.</param>
public sealed record VirtualControlFlow(
    int Watched,
    IReadOnlyDictionary<int, (int Taken, int Seen)> Jumps,
    IReadOnlyDictionary<int, int> Targets)
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
/// Learns an engine's control flow by watching it run, rather than by asking it questions.
/// </summary>
/// <remarks>
/// An operation performed in isolation cannot jump anywhere. The engine's position is whatever the
/// last real run left it at, so a handler that computes a target from it produces a number nothing
/// can check, and the operation is recorded as consuming its values and doing nothing — which is
/// not merely incomplete but misleading, since a reader told an operation is inert will take the
/// code after it for unreachable.
///
/// Watching costs nothing extra, because the program has to be run once anyway for the engine to
/// exist. Nor does it require knowing where the engine keeps its position, which it may hold as an
/// offset, an index, or not in a field at all: what is watched is which operation is performed
/// next. If that is not the one after it in the list, the one before it jumped, and it jumped to
/// somewhere that really is another operation of the same program.
/// </remarks>
internal sealed class VirtualControlFlowWatcher
{
    private readonly ModuleDef _module;
    private readonly StaticHeap _heap;
    private readonly MethodDef _dispatcher;
    private readonly FieldDef _opcodeField;
    private readonly string _instructionType;
    private readonly Dictionary<long, int> _indices = [];
    private readonly Dictionary<int, (int Taken, int Seen)> _jumps = [];
    private readonly Dictionary<int, int> _targets = [];
    private int _watched;
    private int _previous = -1;
    private int _opcode = -1;

    public VirtualControlFlowWatcher(
        ModuleDef module,
        StaticHeap heap,
        MethodDef dispatcher,
        FieldDef opcodeField,
        string instructionType)
    {
        _module = module;
        _heap = heap;
        _dispatcher = dispatcher;
        _opcodeField = opcodeField;
        _instructionType = instructionType;
    }

    public VirtualControlFlow Result() => new(_watched, _jumps, _targets);

    public void Entered(MethodDef method, IReadOnlyList<StaticValue> arguments)
    {
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
        return _indices.Count > 0;
    }
}
