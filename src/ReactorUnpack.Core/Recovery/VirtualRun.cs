using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core.Interpretation;

namespace ReactorUnpack.Core.Recovery;

/// <summary>What a virtualizer's operations were seen to do, and where they were seen to go.</summary>
/// <param name="Watched">How many operations were seen performed, one after another.</param>
/// <param name="Jumps">By opcode, how often the next operation was not the following one.</param>
/// <param name="Targets">By operation, where it was seen to go.</param>
/// <param name="Effects">By opcode, what it did to the stack every time it was seen.</param>
/// <param name="Computed">By opcode, what the engine's own code was seen working out.</param>
public sealed record VirtualRun(
    int Watched,
    IReadOnlyDictionary<int, (int Taken, int Seen)> Jumps,
    IReadOnlyDictionary<int, int> Targets,
    IReadOnlyDictionary<int, VirtualOperation> Effects,
    IReadOnlyDictionary<int, IReadOnlyList<string>> Computed)
{
    /// <summary>The operations watched writing a static field, which is the one place outside the
    /// engine a handler could put a value it took.</summary>
    public IReadOnlySet<int> Stores { get; init; } = new HashSet<int>();

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

    /// <summary>How far from the engine a table of its values may sit to be found.</summary>
    private const int Deep = 4;

    /// <summary>How many tables to watch, so that a program's own data does not crowd them out.</summary>
    private const int MostTables = 8;

    /// <summary>How many performances of one operation to watch the engine's working through.</summary>
    private const int Enough = 4;

    /// <summary>How many places in a table an operation must be seen reaching for.</summary>
    private const int Places = 2;

    /// <summary>How many differing sets of values a meaning must hold across to be named.</summary>
    /// <remarks>
    /// A real run repeats itself, and an operation performed twice on 0 and 0 agrees with almost
    /// any meaning. What separates them is having been seen on values that differ.
    /// </remarks>
    private const int Differing = 4;

    private readonly ModuleDef _module;
    private readonly StaticMachineState _state;
    private readonly StaticHeap _heap;
    private readonly Dictionary<long, FieldDef?> _named = [];
    private readonly MethodDef _dispatcher;
    private readonly FieldDef _opcodeField;
    private readonly FieldDef? _operandField;
    private readonly string _instructionType;
    private readonly Dictionary<long, int> _indices = [];
    private readonly Dictionary<int, (int Taken, int Seen)> _jumps = [];
    private readonly Dictionary<int, int> _targets = [];
    private readonly Dictionary<int, List<Performance>> _performances = [];
    private readonly Dictionary<int, List<Dictionary<string, int>>> _worked = [];
    private readonly Dictionary<int, string> _unmeasured = [];
    private readonly HashSet<int> _stores = [];
    private readonly Dictionary<int, (int Methods, int Constructors, int Seen)> _naming = [];
    private readonly Dictionary<long, MethodDef?> _calls = [];
    private Dictionary<string, int>? _working;
    private List<StaticValue>? _stack;
    private List<Table> _tables = [];
    private List<Held> _before = [];
    private Held?[] _was = [];
    private Held? _kept;
    private Held? _element;
    private long? _operand;
    private int _watched;
    private int _previous = -1;
    private int _opcode = -1;
    private int _performing = -1;
    private int _performingDepth = -1;
    private int _depth;

    public VirtualRunWatcher(
        ModuleDef module,
        StaticMachineState state,
        MethodDef dispatcher,
        FieldDef opcodeField,
        FieldDef? operandField,
        string instructionType)
    {
        _module = module;
        _state = state;
        _heap = state.Heap;
        _dispatcher = dispatcher;
        _opcodeField = opcodeField;
        _operandField = operandField;
        _instructionType = instructionType;
    }

    public VirtualRun Result()
    {
        var computed = Computed();
        var effects = Effects();
        foreach (var (opcode, working) in computed)
        {
            effects[opcode] = effects.TryGetValue(opcode, out var known)
                ? known with { Computes = working }
                : new VirtualOperation(opcode, 0, 0, Called(opcode))
                {
                    Computes = working,
                    Measured = false,
                    Unmeasured = _unmeasured.GetValueOrDefault(opcode)
                };
        }

        Making(effects);

        // An operation may have been watched calling without the engine having computed anything
        // worth reporting on its behalf, and it is named all the same.
        foreach (var opcode in _unmeasured.Keys)
        {
            if (!effects.ContainsKey(opcode) && Called(opcode) is { } calling)
            {
                effects[opcode] = new VirtualOperation(opcode, 0, 0, calling)
                {
                    Measured = false,
                    Unmeasured = _unmeasured[opcode]
                };
            }
        }
        return new VirtualRun(_watched, _jumps, _targets, effects, computed) { Stores = _stores };
    }

    /// <summary>
    /// What each operation was seen working out that the others were not.
    /// </summary>
    /// <remarks>
    /// Two filters make this readable, neither of which needs to know what the engine's plumbing
    /// is. An operation is credited only with what it did every time it was performed, which drops
    /// whatever the run happened to be doing around it. Then anything most operations also do is
    /// dropped as housekeeping: taking the top of a stack, comparing two types, stepping a
    /// position. What is left is what one operation does and its neighbours do not, which is the
    /// only part that could be its meaning.
    /// </remarks>
    private Dictionary<int, IReadOnlyList<string>> Computed()
    {
        var always = new Dictionary<int, Dictionary<string, int>>();
        foreach (var (opcode, runs) in _worked)
        {
            if (runs.Count < Counted)
                continue;
            var core = new Dictionary<string, int>(runs[0], StringComparer.Ordinal);
            foreach (var run in runs.Skip(1))
            {
                foreach (var did in core.Keys.ToList())
                    core[did] = Math.Min(core[did], run.GetValueOrDefault(did));
            }
            always[opcode] = core;
        }
        if (always.Count == 0)
            return [];

        var shared = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var did in always.Values.SelectMany(core => core.Keys))
        {
            shared.TryGetValue(did, out var count);
            shared[did] = count + 1;
        }
        var common = Math.Max(2, always.Count / 4);

        var found = new Dictionary<int, IReadOnlyList<string>>();
        foreach (var (opcode, core) in always)
        {
            var residue = core
                .Where(did => shared[did.Key] <= common)
                .OrderByDescending(did => did.Value)
                .ThenBy(did => did.Key, StringComparer.Ordinal)
                .Take(Most)
                .Select(did => did.Value > 1
                    ? $"{Shorten(did.Key)} x{did.Value}"
                    : Shorten(did.Key))
                .ToList();
            if (residue.Count > 0)
                found[opcode] = residue;
        }
        return found;
    }

    /// <summary>A called method said as briefly as it can be and still be recognized.</summary>
    private static string Shorten(string called)
    {
        var cut = called.IndexOf('(', StringComparison.Ordinal);
        var name = cut > 0 ? called[..cut] : called;
        var space = name.LastIndexOf(' ');
        name = space > 0 ? name[(space + 1)..] : name;

        var split = name.IndexOf("::", StringComparison.Ordinal);
        if (split < 0)
            return name;
        var owner = name[..split];
        var generic = owner.IndexOf('`', StringComparison.Ordinal);
        if (generic > 0)
            owner = owner[..generic];
        var dot = owner.LastIndexOf('.');
        return (dot > 0 ? owner[(dot + 1)..] : owner) + name[split..];
    }

    /// <summary>How much of an operation's working to report before it stops being a summary.</summary>
    private const int Most = 4;

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
        Naming(_opcode, VirtualSemantics.Operand(_heap, operation, _operandField));
        _operand = VirtualSemantics.Operand(_heap, operation, _operandField);

        // Watching what the handler computes costs a callback per instruction it runs, so it is
        // only done until each operation has been seen enough times to say what it always does.
        _worked.TryGetValue(_opcode, out var already);
        _working = already is null || already.Count < Enough ? [] : null;
        _before = Stack();
        _was = Indexed();
        _kept = Keeps();
        _element = Element();
    }

    /// <summary>
    /// Notes an instruction the engine really executed while performing an operation.
    /// </summary>
    /// <remarks>
    /// What the handler computes is the operation's meaning stated outright, and it is only
    /// readable this way: in the file the handlers are one method of several thousand instructions,
    /// flattened into blocks threaded together by a state variable, and most of what they call goes
    /// through a proxy whose target is decided as it runs. The machine has already passed through
    /// all of that by the time it gets here.
    /// </remarks>
    public void Stepped(MethodDef method, Instruction instruction)
    {
        // A value taken off the stack and never seen again was discarded, unless it went somewhere
        // outside the engine altogether. The one such place a handler could put it is a static
        // field, and whether it ever writes one is worth knowing for that reason alone.
        if (_performing >= 0 && instruction.OpCode.Code == Code.Stsfld)
            _stores.Add(_performing);
        if (_working is null)
            return;
        if (Computing(instruction) is not { } did)
            return;
        _working.TryGetValue(did, out var count);
        _working[did] = count + 1;
    }

    /// <summary>
    /// What an executed instruction says about meaning, which is nothing unless it computes.
    /// </summary>
    /// <remarks>
    /// Loads, stores, and jumps are how any code is held together and say the same thing in every
    /// handler. Arithmetic, comparison and conversion are what one handler does that another does
    /// not, and a call out of the assembly is the engine asking for something by name.
    /// </remarks>
    private static string? Computing(Instruction instruction)
    {
        var code = instruction.OpCode.Code;
        if (code is Code.Call or Code.Callvirt or Code.Newobj)
        {
            return instruction.Operand is IMethod called && called.DeclaringType?.Scope is AssemblyRef
                ? called.FullName
                : null;
        }
        var name = instruction.OpCode.Name;
        if (name is null)
            return null;
        return Computations.Contains(name.Split('.')[0]) ? name : null;
    }

    /// <summary>The instruction names that say what an operation is rather than how it is built.</summary>
    private static readonly HashSet<string> Computations = new(StringComparer.Ordinal)
    {
        "add", "sub", "mul", "div", "rem", "and", "or", "xor", "shl", "shr", "neg", "not",
        "ceq", "cgt", "clt", "conv", "beq", "bne", "blt", "bgt", "ble", "bge"
    };

    public void Exited(MethodDef method)
    {
        var depth = _depth--;
        if (method != _dispatcher || _performing < 0 || depth != _performingDepth)
            return;
        var performing = _performing;
        _performing = -1;
        if (_working is { Count: > 0 })
        {
            if (!_worked.TryGetValue(performing, out var runs))
                _worked[performing] = runs = [];
            runs.Add(_working);
        }
        _working = null;

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
            _before.Skip(kept).ToList(),
            after.Skip(kept).ToList(),
            _operand,
            _was,
            Indexed(),
            _kept,
            Keeps(),
            _element));
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
        {
            _stack = VirtualSemantics.FindStack(_heap, _module, engine, slotType);
            _tables = Tables(engine, slotType);
        }
        return _indices.Count > 0;
    }

    /// <summary>
    /// The engine's own tables of values, which are where the program keeps whatever the stack is
    /// not holding at the moment.
    /// </summary>
    /// <remarks>
    /// Only tables of the same thing the stack holds are taken. Every engine has to keep its locals
    /// and its arguments somewhere, and wherever that is, it holds the same kind of value the stack
    /// does; a table of anything else is the program's data rather than the engine's state. The
    /// stack itself is left out, being already accounted for. Tables of plain objects are taken as
    /// well, since an engine that keeps its arguments as it received them has them in one.
    /// </remarks>
    private List<Table> Tables(StaticValue engine, string slotType)
    {
        var found = new List<Table>();
        var list = $"System.Collections.Generic.List`1<{slotType}>";
        var objects = "System.Collections.Generic.List`1<System.Object>";
        var queue = new Queue<(StaticValue Value, int Depth)>();
        var visited = new HashSet<long>();
        queue.Enqueue((engine, 0));
        while (queue.Count > 0 && found.Count < MostTables)
        {
            var (value, depth) = queue.Dequeue();
            if (depth > Deep ||
                value.Kind != StaticValueKind.HeapReference ||
                !visited.Add(value.Bits) ||
                !_heap.TryGetRuntimeTypeName(value, out var typeName))
            {
                continue;
            }

            if (_heap.TryGetArrayElementType(value, out var element) &&
                (element == slotType || element == "System.Object"))
            {
                found.Add(new Table(value, IsList: false));
            }
            else if ((typeName == list || typeName == objects) &&
                _heap.TryGetModelValue<List<StaticValue>>(value, "Items", out var items) &&
                items is not null && !ReferenceEquals(items, _stack))
            {
                found.Add(new Table(value, IsList: true));
            }

            foreach (var field in VirtualSemantics.Reachable(_module, typeName))
            {
                if (_heap.TryReadField(value, field, out var stored))
                    queue.Enqueue((stored, depth + 1));
            }
        }
        return found;
    }

    /// <summary>
    /// What an array on the stack holds at the index sitting on top of it, where that is what the
    /// stack looks like.
    /// </summary>
    /// <remarks>
    /// This has to be taken before the operation rather than worked out afterwards: both values are
    /// gone from the stack by then, and the array may have been written to in the meantime.
    /// </remarks>
    private Held? Element()
    {
        if (_before.Count < 2 || _before[^1].Value is not { } index ||
            index < 0 || index > int.MaxValue)
        {
            return null;
        }
        foreach (var inside in _before[^2].Inside)
        {
            if (inside is < int.MinValue or > int.MaxValue)
                continue;
            var array = StaticValue.FromHeapReference((int)inside);
            if (_heap.TryGetLength(array, out var length) && index < length &&
                _heap.TryReadArray(array, (int)index, out var element))
            {
                return Hold(element);
            }
        }
        return null;
    }

    /// <summary>
    /// What the field an operation's operand names is holding, where it names one at all.
    /// </summary>
    /// <remarks>
    /// A token operand says which field, but not whether the operation reads it, writes it, or
    /// merely mentions it. Reading the field either side of the operation settles that, and settles
    /// it by identity where the field holds an object, which no coincidence of numbers can imitate.
    /// </remarks>
    private Held? Keeps()
    {
        if (_operand is not { } token || Named(token) is not { } field)
            return null;
        return Hold(_state.ReadStaticField(field));
    }

    /// <summary>
    /// Names an operation the engine was watched asking the framework to make an array for.
    /// </summary>
    /// <remarks>
    /// One value in and one out says nothing on its own, but an operation that resolves a type and
    /// then has the framework make an array of it has said what it is in as many words. The count
    /// it takes is the length and the one it leaves is the array.
    /// </remarks>
    private static void Making(Dictionary<int, VirtualOperation> effects)
    {
        foreach (var (opcode, operation) in effects)
        {
            if (operation is { Name: null, Measured: true, Pops: 1, Pushes: 1 } &&
                operation.Computes is { } working &&
                working.Any(did => did.StartsWith("Array::CreateInstance", StringComparison.Ordinal)))
            {
                effects[opcode] = operation with { Name = "makes an array of the type it names" };
            }
        }
    }

    /// <summary>Notes whether an operation's operand names a method of the assembly.</summary>
    private void Naming(int opcode, long? operand)
    {
        _naming.TryGetValue(opcode, out var counted);
        var method = operand is { } token ? Calling(token) : null;
        _naming[opcode] = (
            counted.Methods + (method is not null ? 1 : 0),
            counted.Constructors + (method is { IsConstructor: true } ? 1 : 0),
            counted.Seen + 1);
    }

    private MethodDef? Calling(long token)
    {
        if (_calls.TryGetValue(token, out var known))
            return known;
        MethodDef? method = null;
        if (token is >= int.MinValue and <= int.MaxValue)
        {
            try
            {
                method = (_module.ResolveToken((int)token) as IMethod)?.ResolveMethodDef();
            }
            catch (Exception exception) when (
                exception is ArgumentException or InvalidOperationException)
            {
                method = null;
            }
        }
        return _calls[token] = method;
    }

    /// <summary>
    /// An operation whose arity is decided by something other than itself, and whose operand names
    /// a method, is calling that method: what it takes off the stack is that method's arguments.
    /// </summary>
    private string? Called(int opcode)
    {
        if (_unmeasured.GetValueOrDefault(opcode) != Varies ||
            !_naming.TryGetValue(opcode, out var counted) ||
            counted.Seen < Counted || counted.Methods < counted.Seen)
        {
            return null;
        }
        return counted.Constructors == counted.Seen
            ? "makes a new object with the constructor it names"
            : "calls the method it names";
    }

    /// <summary>Why an operation whose arity was not the same twice was not measured.</summary>
    private const string Varies = "taking a different number of values each time it ran";

    private FieldDef? Named(long token)
    {
        if (_named.TryGetValue(token, out var known))
            return known;
        FieldDef? field = null;
        if (token is >= int.MinValue and <= int.MaxValue)
        {
            try
            {
                field = (_module.ResolveToken((int)token) as IField)?.ResolveFieldDef();
            }
            catch (Exception exception) when (
                exception is ArgumentException or InvalidOperationException)
            {
                field = null;
            }
        }
        _named[token] = field = field is { IsStatic: true } ? field : null;
        return field;
    }

    /// <summary>A place the engine keeps values that its operations reach by number.</summary>
    private sealed record Table(StaticValue Reference, bool IsList);

    /// <summary>What each table holds at the place this operation's operand points to.</summary>
    private Held?[] Indexed()
    {
        var read = new Held?[_tables.Count];
        if (_operand is not { } at || at < 0 || at > int.MaxValue)
            return read;
        for (var index = 0; index < _tables.Count; index++)
        {
            var table = _tables[index];
            StaticValue slot;
            if (table.IsList)
            {
                if (!_heap.TryGetModelValue<List<StaticValue>>(table.Reference, "Items", out var items) ||
                    items is null || at >= items.Count)
                {
                    continue;
                }
                slot = items[(int)at];
            }
            else if (!_heap.TryReadArray(table.Reference, (int)at, out slot))
            {
                continue;
            }
            read[index] = Hold(slot);
        }
        return read;
    }

    private List<Held> Stack() =>
        _stack is null ? [] : _stack.Select(Hold).ToList();

    /// <summary>
    /// Takes down what a value is: which one it is, what number it holds if any, and what it has
    /// hold of.
    /// </summary>
    /// <remarks>
    /// The last of those is what lets a value the engine wrapped be recognized as the one it was
    /// given, which is how an operation is caught fetching an object rather than a number.
    /// </remarks>
    private Held Hold(StaticValue slot)
    {
        if (slot.Kind is StaticValueKind.Int32 or StaticValueKind.Int64)
            return new Held(slot.Bits, slot.Bits, Nothing);
        if (slot.Kind != StaticValueKind.HeapReference)
            return new Held(slot.Bits, null, Nothing) { Empty = slot.Kind == StaticValueKind.Null };

        var inside = new HashSet<long>();
        if (_heap.TryGetRuntimeTypeName(slot, out var typeName))
        {
            foreach (var field in VirtualSemantics.Reachable(_module, typeName))
            {
                if (_heap.TryReadField(slot, field, out var stored) &&
                    stored.Kind == StaticValueKind.HeapReference)
                {
                    inside.Add(stored.Bits);
                }
            }
        }
        return new Held(
            slot.Bits,
            VirtualSemantics.TryReadNumber(_heap, _module, slot, out var value) ? value : null,
            inside);
    }

    /// <summary>What a value that has hold of nothing has hold of.</summary>
    private static readonly HashSet<long> Nothing = [];

    /// <summary>One value: which one it is, the number in it if any, and what it holds.</summary>
    private sealed record Held(long Id, long? Value, IReadOnlySet<long> Inside)
    {
        /// <summary>Whether it is nothing at all, which an engine's stack can hold like any other.</summary>
        public bool Empty { get; init; }
    }

    /// <summary>One performance: what came off the stack, what went on, and what it carried.</summary>
    /// <param name="Was">What the engine's tables held at the operand, before.</param>
    /// <param name="Now">What they held after, which is how a write to one is seen.</param>
    /// <param name="Kept">What the field the operand names held, before.</param>
    /// <param name="Keeping">What it held after.</param>
    /// <param name="Element">What the array on the stack held at the index beside it, before.</param>
    private sealed record Performance(
        IReadOnlyList<Held> Taken,
        IReadOnlyList<Held> Left,
        long? Operand,
        Held?[] Was,
        Held?[] Now,
        Held? Kept,
        Held? Keeping,
        Held? Element);

    private Dictionary<int, VirtualOperation> Effects()
    {
        var found = new Dictionary<int, VirtualOperation>();
        foreach (var (opcode, seen) in _performances)
        {
            if (seen.Count < Counted)
            {
                _unmeasured[opcode] = "having been performed only once where it was watched";
                continue;
            }
            var pops = seen[0].Taken.Count;
            var pushes = seen[0].Left.Count;
            if (seen.Exists(one => one.Taken.Count != pops || one.Left.Count != pushes))
            {
                _unmeasured[opcode] = Varies;
                continue;
            }
            found[opcode] = new VirtualOperation(opcode, pops, pushes, Name(seen, pops, pushes));
        }
        return found;
    }

    /// <summary>
    /// Names an operation from the values it was really given, where they were varied enough for
    /// one meaning to survive and the others to be ruled out.
    /// </summary>
    private string? Name(List<Performance> seen, int pops, int pushes)
    {
        if (pushes == 1 && pops == 0 &&
            seen.All(one => one.Operand is not null && one.Left[0].Value == one.Operand) &&
            Varied(seen.Select(one => one.Operand)))
        {
            return "pushes its operand";
        }
        if (Reaching(seen, pops, pushes) is { } reaching)
            return reaching;
        if (Keeping(seen, pops, pushes) is { } keeping)
            return keeping;
        if (pops == 2 && pushes == 1 && Elements(seen) is { } element)
            return element;
        if (pops == 0 && pushes == 1 && Fixed(seen) is { } fixedValue)
            return fixedValue;
        return (pops, pushes) switch
        {
            (1, 1) => Only(seen, VirtualSemantics.UnaryCandidates
                .Select(candidate => (candidate.Name, Apply: (Func<long, long, long>)
                    ((value, _) => candidate.Apply(value))))
                .Prepend(("convert", (value, _) => value))
                .ToArray()),
            (2, 1) => Only(seen, VirtualSemantics.BinaryCandidates),
            _ => null
        };
    }

    /// <summary>
    /// An operation that reaches into one of the engine's tables at the place its operand names,
    /// which is what a local, an argument, or anything else kept by number looks like.
    /// </summary>
    /// <remarks>
    /// The claim is only made where the operation was seen reaching for more than one place, and
    /// where what it carried was varied, so that a table of zeroes read by an operation that pushes
    /// zero does not pass for one. A write additionally has to have changed something, since a
    /// table that already held the value would look the same either way.
    /// </remarks>
    private string? Reaching(List<Performance> seen, int pops, int pushes)
    {
        for (var table = 0; table < _tables.Count; table++)
        {
            var reached = seen
                .Where(one => one.Was.Length > table && one.Was[table] is not null)
                .ToList();
            if (reached.Count < Counted ||
                reached.Select(one => one.Operand).Distinct().Count() < Places)
            {
                continue;
            }

            if (pushes >= 1 && reached.TrueForAll(one => Alike(one.Was[table]!, one.Left[^1])) &&
                Varied(reached.Select(one => one.Was[table]!.Value)))
            {
                return "loads what its operand indexes";
            }
            if (pops >= 1 &&
                reached.TrueForAll(one =>
                    one.Now[table] is not null && Alike(one.Now[table]!, one.Taken[^1])) &&
                reached.Exists(one => !Alike(one.Was[table]!, one.Now[table]!)) &&
                Varied(reached.Select(one => one.Now[table]!.Value)))
            {
                return "stores where its operand indexes";
            }
        }
        return null;
    }

    /// <summary>
    /// An operation that carries away what a field holds, or puts what it takes into one.
    /// </summary>
    /// <remarks>
    /// Where the field holds an object, one sighting of the operation carrying that same object off
    /// is worth more than any number of numeric agreements, so a match by identity is accepted on
    /// its own and a match by number only where the numbers varied.
    /// </remarks>
    private static string? Keeping(List<Performance> seen, int pops, int pushes)
    {
        var named = seen.Where(one => one.Kept is not null).ToList();
        if (named.Count < Counted)
            return null;

        if (pushes >= 1)
        {
            var likeness = named.Select(one => Like(one.Kept!, one.Left[^1])).ToList();
            if (likeness.TrueForAll(like => like != Likeness.No) &&
                (likeness.Contains(Likeness.Same) || Varied(named.Select(one => one.Kept!.Value))))
            {
                return "reads the static field it names";
            }
        }

        if (pops >= 1)
        {
            var written = named.Where(one => one.Keeping is not null).ToList();
            if (written.Count >= Counted &&
                written.TrueForAll(one => Like(one.Keeping!, one.Taken[^1]) != Likeness.No) &&
                written.Exists(one => Like(one.Kept!, one.Keeping!) == Likeness.No))
            {
                return "writes the static field it names";
            }
        }
        return null;
    }

    /// <summary>
    /// An operation handed an array and an index that answers with what is in it there.
    /// </summary>
    private static string? Elements(List<Performance> seen)
    {
        var reached = seen.Where(one => one.Element is not null).ToList();
        return reached.Count >= Counted &&
            reached.TrueForAll(one => Like(one.Element!, one.Left[0]) != Likeness.No) &&
            (reached.Exists(one => Like(one.Element!, one.Left[0]) == Likeness.Same) ||
                Varied(reached.Select(one => one.Element!.Value)))
                ? "reads an array element"
                : null;
    }

    /// <summary>
    /// An operation that produces the same thing every time, which is as much as can be said of one
    /// that takes nothing and carries nothing.
    /// </summary>
    private static string? Fixed(List<Performance> seen)
    {
        if (seen.Count < Counted || !seen.TrueForAll(one => one.Operand is null))
            return null;
        if (seen.TrueForAll(one => one.Left[0].Empty))
            return "pushes nothing at all";
        var first = seen[0].Left[0];
        return seen.TrueForAll(one => Like(first, one.Left[0]) == Likeness.Same)
            ? "pushes the same value every time"
            : null;
    }

    /// <summary>How far two values can be said to be the same one.</summary>
    private enum Likeness
    {
        No,
        Number,
        Same
    }

    private static Likeness Like(Held left, Held right)
    {
        if (left.Id == right.Id || left.Inside.Contains(right.Id) || right.Inside.Contains(left.Id))
            return Likeness.Same;
        return left.Value is not null && left.Value == right.Value ? Likeness.Number : Likeness.No;
    }

    private static bool Alike(Held left, Held right) => Like(left, right) != Likeness.No;

    /// <summary>
    /// The one meaning that held every time, where the values it held across were not all alike.
    /// </summary>
    private static string? Only(
        List<Performance> seen,
        (string Name, Func<long, long, long> Apply)[] meanings)
    {
        var usable = seen
            .Where(one => one.Taken.All(held => held.Value is not null) && one.Left[0].Value is not null)
            .ToList();
        if (usable.Count < Counted || !Varied(usable.Select(one => one.Taken[0].Value)))
            return null;

        var survived = meanings
            .Where(meaning => usable.All(one => Same(
                meaning.Apply(
                    one.Taken[0].Value!.Value,
                    one.Taken.Count > 1 ? one.Taken[^1].Value!.Value : 0),
                one.Left[0].Value!.Value)))
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
