using System.Buffers;
using System.Globalization;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Interpretation;

namespace Cilantro.Core.Recovery;

/// <summary>What was learned about a virtualizer's operations, and what was not.</summary>
/// <param name="Operations">The ones the engine would perform on their own, by opcode.</param>
/// <param name="Refused">
/// Why each operation the trials could not perform was left alone, by opcode rather than in total,
/// because watching the engine run may yet account for some of them.
/// </param>
/// <param name="Summary">The same in one sentence, for the log.</param>
public sealed record VirtualSemanticsReport(
    IReadOnlyDictionary<int, VirtualOperation> Operations,
    IReadOnlyDictionary<int, string> Refused,
    string Summary);

/// <summary>What one of a virtualizer's operations turned out to do.</summary>
/// <param name="Opcode">The number the engine dispatches on, which is assigned per build.</param>
/// <param name="Pops">How many values it took off the engine's stack.</param>
/// <param name="Pushes">How many it left in their place.</param>
/// <param name="Name">The familiar name for it, when the trials agreed on exactly one.</param>
public sealed record VirtualOperation(int Opcode, int Pops, int Pushes, string? Name)
{
    /// <summary>Whether it altered the engine's own state as well as, or instead of, the stack.</summary>
    public bool TouchesState { get; init; }

    /// <summary>
    /// What had to be on the stack before it would run, when plain numbers would not do.
    /// </summary>
    /// <remarks>
    /// This is a finding in its own right. An operation that refuses numbers and accepts an array
    /// beneath an index is indexing an array, whatever else remains unknown about it.
    /// </remarks>
    public string? Needs { get; init; }

    /// <summary>
    /// What the engine's own code was seen computing while it performed this operation, over and
    /// above the working every operation does.
    /// </summary>
    /// <remarks>
    /// This is the operation's meaning stated in the engine's own terms rather than deduced from
    /// the outside, and it is the only reading that says what a conditional branch is conditional
    /// on. It says nothing on its own about what the operation did with the result.
    /// </remarks>
    public IReadOnlyList<string>? Computes { get; init; }

    /// <summary>Which of the engine's own places it was seen writing to, where it wrote one.</summary>
    public IReadOnlyList<string>? Changes { get; init; }

    /// <summary>
    /// The condition a jump was seen to go on, named as the IL branch that goes on the same one.
    /// </summary>
    /// <remarks>
    /// A jump's condition is not in what it consumes, which is two numbers either way, nor in the
    /// comparison the engine was watched computing, which is the same <c>clt</c> for a jump taken
    /// when the one is below the other and for a jump taken when it is not. It is in when the jump
    /// goes, so it is settled by making it decide over values arranged to tell every reading of it
    /// from every other, and reading off which times it went.
    ///
    /// Getting it wrong is not a missing detail. A loop's exit test read as its entry test runs the
    /// body no times instead of every time, and a reading that says so is not partly right.
    /// </remarks>
    public string? Decides { get; init; }

    /// <summary>
    /// Which of the engine's places were given the number the operation carries, or the one before
    /// it, in any trial.
    /// </summary>
    /// <remarks>
    /// An operation that puts its own operand into the place the engine keeps its position has
    /// gone there, which is the whole of what a jump is. The place is reported rather than judged
    /// because which place is the position is not known until the operations are read together.
    /// </remarks>
    public IReadOnlyList<string>? Reached { get; init; }

    /// <summary>
    /// What the rest of the program leaves it no choice but to do to the stack, where nothing
    /// measured it: the number of values it adds, which is negative for one that takes more than
    /// it leaves.
    /// </summary>
    public int? Net { get; init; }

    /// <summary>The type of the value it leaves on top, where every sighting agreed on one.</summary>
    public string? Pushed { get; init; }

    /// <summary>The type of the value it takes off the top, where every sighting agreed.</summary>
    public string? Popped { get; init; }

    /// <summary>How long the table it fetched from is, where it was seen fetching from one.</summary>
    /// <remarks>
    /// A method's arguments are as many as its signature declares. That is what tells the table of
    /// arguments from the table of locals, neither of which says what it is.
    /// </remarks>
    public int? Holding { get; init; }

    /// <summary>
    /// The type of thing it leaves, named as the assembly names it, for a push whose value could
    /// not be read; or <c>nothing at all</c> for a push that left no value.
    /// </summary>
    /// <remarks>
    /// This is the poorest of the readings and is only reached when every better one has failed,
    /// so it is kept apart from the name until then rather than standing in for one. It is kept as
    /// the bare type rather than as the sentence it becomes, because what it is a reading of
    /// depends on the type: an operation that leaves a string and carries a number is loading a
    /// string, and no sentence can be asked that.
    /// </remarks>
    public string? Left { get; init; }

    /// <summary>What kind of thing it leaves, as it is said in the listing.</summary>
    public string? Leaving => Left switch
    {
        null => null,
        "nothing at all" => "pushes nothing at all",
        var kind => $"pushes a{("AEIOU".Contains(Short(kind)[0], StringComparison.Ordinal)
            ? "n"
            : string.Empty)} {Short(kind)}"
    };

    /// <summary>A type's name without the part of it every reader can supply.</summary>
    private static string Short(string kind) => kind.StartsWith("System.", StringComparison.Ordinal)
        ? kind["System.".Length..]
        : kind[(kind.LastIndexOfAny(['/', '.', '+']) + 1)..];

    /// <summary>
    /// Whether its effect on the stack was established at all, as against its working being read
    /// while the effect itself went unmeasured.
    /// </summary>
    public bool Measured { get; init; } = true;

    /// <summary>Why its effect was not established, when it was not.</summary>
    /// <remarks>
    /// This is a finding rather than an apology. An operation that took a different number of
    /// values every time it was performed is one whose arity is decided by something other than
    /// the operation, which is what a call looks like from here.
    /// </remarks>
    public string? Unmeasured { get; init; }

    /// <summary>The effect in the shortest form that is still true.</summary>
    public string Describe()
    {
        var said = Needs is null ? Brief : $"{Brief}, wants {Needs}";
        if (Changes is { Count: > 0 } places)
        {
            said += $" (writes {string.Join(", ", places.Take(4))}" +
                (places.Count > 4 ? ", ..." : string.Empty) + ")";
        }
        if (Unmeasured is not null)
            said += $" ({Unmeasured})";
        return Computes is { Count: > 0 } working
            ? $"{said}; computes {string.Join(", ", working)}"
            : said;
    }

    /// <summary>The effect without what it had to be handed, short enough to sit beside a line.</summary>
    public string Brief
    {
        get
        {
            if (!Measured)
            {
                return Name ?? (Net is { } net
                    ? $"effect not established, {net:+0;-0;0} on the stack by what surrounds it"
                    : "effect not established");
            }
            if (Name == "branch if" && Decides is { } condition)
                return $"branch if {condition}";
            var stack = Name ?? (Pops, Pushes) switch
            {
                (0, 0) => TouchesState ? "changes engine state" : "no effect seen",
                (0, var pushes) => $"pushes {pushes}",
                (var pops, 0) => $"pops {pops}",
                var (pops, pushes) => $"pops {pops}, pushes {pushes}"
            };
            return Name is null && Pops + Pushes > 0 && TouchesState
                ? $"{stack}, changes state"
                : stack;
        }
    }

    /// <summary>Whether the effect was identified rather than merely counted.</summary>
    public bool Identified => Name is not null;
}

/// <summary>
/// Works out what a virtualizer's operations do by asking the engine to perform them.
/// </summary>
/// <remarks>
/// The numbers a virtualizer dispatches on are assigned per build — across the samples here the
/// same operation is 43 in one and 79 in another, and the sets barely overlap — so a table of
/// meanings learned from one sample would misread the next rather than fail on it. Meanings have to
/// be derived from the sample in hand.
///
/// Reading them out of the file is not practical: the executor is one control-flow flattened method
/// of several thousand instructions driven by a switch over a state variable, and most of what it
/// calls goes through a proxy whose target is decided as it runs, so finding the code for an
/// operation means undoing the obfuscator's protection of its own interpreter first. What the
/// engine executes while it runs is another matter, and is read elsewhere; here it is asked
/// questions instead.
///
/// So the engine is asked instead. Its handlers belong to it rather than to any one program, which
/// means an operation can be performed in isolation: seed the engine's stack with values we chose,
/// hand it a single operation, and read back the stack it leaves. What it did is then a question
/// about numbers we picked and numbers we got.
///
/// Every conclusion is drawn from several trials with different values, because one trial does not
/// distinguish between operations that happen to agree on it — a single trial of 7 and 3 reads
/// equally well as subtraction and as exclusive-or, and only a second trial separates them. A name
/// is given only when exactly one candidate matches every trial, and the stack effect alone is
/// reported otherwise.
/// </remarks>
public static class VirtualSemantics
{
    /// <summary>How far to search the engine's state for the stack it works on.</summary>
    private const int SearchDepth = 4;

    /// <summary>How long an array offered to an operation that wants one should be.</summary>
    private const int ArrayLength = 8;

    private static VirtualSemanticsReport Nothing(string summary) =>
        new(new Dictionary<int, VirtualOperation>(), new Dictionary<int, string>(), summary);

    /// <summary>The reasons operations were left alone, gathered so that each is said once.</summary>
    internal static List<string> Counted(IReadOnlyDictionary<int, string> refused) =>
        refused
            .GroupBy(entry => entry.Value, StringComparer.Ordinal)
            .OrderByDescending(group => group.Count())
            .Select(group => $"{group.Count()} because {group.Key}")
            .ToList();

    /// <summary>Puts the refusals into the listing's voice, as a note under the operations.</summary>
    internal static List<string> Wording(List<string> reasons) =>
        reasons.Count == 0
            ? []
            : new[] { string.Empty, "Nothing is said about the rest:" }
                .Concat(reasons.Select(reason => $"  {reason}"))
                .ToList();

    /// <summary>The one refusal that a differently arranged stack might answer.</summary>
    private const string WrongKind = "it wants a value of a kind we did not put on the stack";

    /// <summary>What an operation that throws the value it is handed is called in a reading.</summary>
    internal const string Throwing = "throws what it takes";

    /// <summary>What the operation that ends a finally handler is called in a reading.</summary>
    /// <remarks>
    /// A finally leaves the runtime through <c>endfinally</c>, which takes and leaves nothing and
    /// only decides where control goes next. That is the one shape the trials cannot tell apart
    /// from any other state change, so it is named from where it sits — the last operation of a
    /// guarded region that names no type — rather than from what a trial made it do.
    /// </remarks>
    internal const string Ending = "ends a finally";

    /// <summary>
    /// The type a refusal says the operation insisted on, where one of them named a type by
    /// refusing to treat what it was given as one.
    /// </summary>
    /// <remarks>
    /// A handler that begins by casting reports, in failing, the only thing about itself that could
    /// be learned while the wrong value was on the stack. Nothing is concluded from the name here;
    /// it is used to ask the question again with a value the handler will accept, and the answer to
    /// that question is what the reading rests on.
    /// </remarks>
    private static string? Insisted(List<string> reasons)
    {
        const string cast = "castclass ";
        foreach (var reason in reasons)
        {
            var at = reason.IndexOf(cast, StringComparison.Ordinal);
            if (at < 0)
                continue;
            var rest = reason[(at + cast.Length)..];
            var end = rest.IndexOfAny([' ', ':', ')', '\t']);
            var named = end < 0 ? rest : rest[..end];
            if (named.Contains('.', StringComparison.Ordinal))
                return named;
        }
        return null;
    }

    /// <summary>
    /// Whether an operation refused a stack of numbers by wanting an array and then faulted once
    /// given one, which is what reading an element out of an array looks like from outside.
    /// </summary>
    /// <remarks>
    /// The first half is the operation saying it wants an array where a number was offered; the
    /// second is it accepting one and faulting past the cast, on the work of wrapping what it read.
    /// Neither half alone is the reading — an operation might want an array to measure it, or fault
    /// for a reason of its own — but together, with the walk forcing a net of one taken, there is
    /// nothing left for it to be but a read of one element.
    /// </remarks>
    private static bool WantsArrayThenFaulted(List<string> reasons)
    {
        var wantsArray = reasons.Exists(reason =>
            reason.StartsWith(WrongKind, StringComparison.Ordinal) &&
            reason.Contains("System.Array", StringComparison.Ordinal));
        var faulted = reasons.Exists(reason =>
            reason.StartsWith("it threw", StringComparison.Ordinal) ||
            reason.StartsWith("the machine could not follow", StringComparison.Ordinal));
        return wantsArray && faulted;
    }

    /// <summary>
    /// How much work one operation is allowed before it is taken not to be one.
    /// </summary>
    /// <remarks>
    /// A handler carries out a single operation and returns, so it is short by construction. An
    /// operation that will not run in isolation otherwise wanders until the whole run's budget is
    /// gone, which costs far more than the answer it eventually refuses to give.
    /// </remarks>
    private const int TrialSteps = 200_000;

    /// <summary>What to put on the stack, chosen so that operations that coincide come apart.</summary>
    /// <remarks>
    /// No zeroes, so that division and remainder do not fault instead of answering; no repeats
    /// within a trial, so that an operation reading the wrong depth is visible; and no pair whose
    /// sum, difference, and exclusive-or agree, which is what makes one trial insufficient.
    /// </remarks>
    /// <remarks>
    /// The last set repeats its top pair on purpose. A conditional jump only jumps when its
    /// condition holds, so trials whose values are all different never make one fire, and it would
    /// be recorded as an operation that merely consumes two values — which is how a program's
    /// branches come to look like arithmetic.
    /// </remarks>
    private static readonly int[][] Seeds =
    [
        [13, 11, 7, 3],
        [29, 9, 4, 2],
        [41, 20, 6, 5],
        [37, 23, 8, 8]
    ];

    /// <summary>
    /// What to put on the stack of a jump, chosen so that no two readings of its condition agree.
    /// </summary>
    /// <remarks>
    /// The top pair runs through above, equal to, and below, which separates the six orderings from
    /// each other; a zero on top, which is the only thing that separates a jump on a value being
    /// zero from one on it being anything else; and a negative, which is the only thing that
    /// separates an ordering read as signed from the same ordering read as unsigned. Each is here
    /// because leaving it out leaves two readings indistinguishable, and a jump whose condition is
    /// half known is not worth naming.
    ///
    /// The zero is why these are kept apart from the seeds every other operation is tried with,
    /// where a zero would have division fault instead of answering.
    /// </remarks>
    private static readonly int[][] Deciders =
    [
        [13, 11, 7, 3],
        [13, 11, 8, 8],
        [13, 11, 5, 9],
        [13, 11, 7, 0],
        [13, 11, -1, 3]
    ];

    /// <summary>
    /// Which times a jump goes, for each condition it might be going on, over the values above.
    /// </summary>
    /// <remarks>
    /// Named as the IL branch that decides the same way, because that is a name with one meaning
    /// rather than a sentence a reader has to interpret, and because what reads these next has to
    /// turn them back into behaviour.
    /// </remarks>
    private static readonly (string Name, int Pops, Func<long, long, bool> Holds)[] Conditions =
    [
        ("brtrue", 1, (_, top) => top != 0),
        ("brfalse", 1, (_, top) => top == 0),
        ("beq", 2, (left, right) => left == right),
        ("bne.un", 2, (left, right) => left != right),
        ("blt", 2, (left, right) => left < right),
        ("blt.un", 2, (left, right) => (ulong)left < (ulong)right),
        ("ble", 2, (left, right) => left <= right),
        ("ble.un", 2, (left, right) => (ulong)left <= (ulong)right),
        ("bgt", 2, (left, right) => left > right),
        ("bgt.un", 2, (left, right) => (ulong)left > (ulong)right),
        ("bge", 2, (left, right) => left >= right),
        ("bge.un", 2, (left, right) => (ulong)left >= (ulong)right)
    ];

    /// <summary>How a stack is laid out for a trial: which positions hold an array, not a number.</summary>
    /// <param name="Arrays">Bottom of the stack first, so the last entry is the top.</param>
    private sealed record Shape(string Needs, bool[] Arrays)
    {
        /// <summary>
        /// Whether the stack should hold values of the type the operation's operand names, rather
        /// than numbers.
        /// </summary>
        public bool Named { get; init; }

        /// <summary>Whether the values are plain numbers, which is when an effect can be named.</summary>
        public bool Plain => !Named && !Arrays.Any(item => item);
    }

    /// <remarks>
    /// An operation that indexes an array refuses a stack of numbers, and refusing is all it does —
    /// it does not say what it wanted. So the arrangements it might have wanted are offered in turn,
    /// and the one it accepts is itself worth reporting: an operation that will only run with an
    /// array beneath an index is an operation that reads an array, whatever it is called.
    /// </remarks>
    private static readonly Shape[] Shapes =
    [
        new("values", [false, false, false, false]),
        new("an array beneath an index", [false, false, true, false]),
        new("an array on top", [false, false, false, true]),
        new("an array beneath an index and a value", [false, true, false, false]),

        // A field's type is stated by the field, so an operation that stores into one can be given
        // what it will accept rather than refused four times over. This matters more than it
        // sounds: the protector declares every field as object and the type is put back by an
        // earlier stage, so the operation is being offered a number where the assembly now says a
        // cipher belongs, and it says no.
        new("a value of the kind its operand names", [false, false, false, false]) { Named = true }
    ];

    public static VirtualSemanticsReport Probe(
        StaticMachine machine,
        ModuleDef module,
        MethodDef dispatcher,
        StaticValue engine,
        FieldDef opcodeField,
        FieldDef? operandField,
        List<StaticValue> operations)
    {
        ArgumentNullException.ThrowIfNull(machine);
        ArgumentNullException.ThrowIfNull(module);
        ArgumentNullException.ThrowIfNull(dispatcher);
        ArgumentNullException.ThrowIfNull(opcodeField);
        ArgumentNullException.ThrowIfNull(operations);

        var heap = machine.State.Heap;
        if (SlotType(heap, module, engine) is not { } slotType)
            return Nothing("The engine's value type was not found, so its stack could not be seeded.");
        if (Factory(module, slotType) is not { } factory)
        {
            return Nothing(
                "The engine offered no way to build a value, so nothing could be put on its stack.");
        }
        if (FindStack(heap, module, engine, slotType) is not { } stack)
            return Nothing("The engine's stack was not found among its state.");

        // An operation is performed with an operand the program really gave it, taken from the
        // program itself. Inventing one is what makes an operation that indexes a table fault
        // instead of answering.
        var examples = new Dictionary<int, StaticValue>();
        foreach (var operation in operations)
        {
            if (heap.TryReadField(operation, opcodeField, out var opcode) &&
                opcode.Kind == StaticValueKind.Int32)
            {
                examples.TryAdd((int)opcode.Bits, operation);
            }
        }

        var staging = Staging(dispatcher);
        var derived = new Dictionary<int, VirtualOperation>();
        var declined = new Dictionary<int, string>();
        var undecided = new Dictionary<int, string>();
        foreach (var (opcode, example) in examples.OrderBy(entry => entry.Key))
        {
            var operand = Operand(heap, example, operandField);
            var wanted = Names(module, operand);
            // Every distinct complaint is kept, not just the first. An operation refused four ways
            // has been refused four ways, and reporting only the first hid the arrangement that
            // came closest behind the one that never had a chance.
            var reasons = new List<string>();
            VirtualOperation? found = null;
            foreach (var shape in Shapes)
            {
                if (shape.Named && wanted is null)
                    continue;
                var trials = Trials(
                    machine, module, heap, dispatcher, engine, factory, slotType, stack, example,
                    operand, staging, shape.Named ? wanted : null, shape, out var refused);
                if (trials.Count == 0)
                {
                    if (!reasons.Contains(refused, StringComparer.Ordinal))
                        reasons.Add(refused);

                    // Rearranging the stack only answers a complaint about what is on it. An
                    // operation that reached past the end of a table, or threw, will do the same
                    // again however the values are arranged, and trying costs a run each time.
                    // Only the first refusal decides that: once an arrangement is being looked for,
                    // the wrong one failing some other way says nothing about the rest.
                    if (shape.Plain && !refused.StartsWith(WrongKind, StringComparison.Ordinal))
                        break;
                    continue;
                }
                found = Classify(opcode, operand, trials, shape);
                if (found is not null)
                    break;
            }

            // An operation that throws is refused by every arrangement alike, and says so in the
            // one way that is worth acting on: by naming the type it wanted. Asking again with one
            // of those is the last thing tried, because it is the only reading whose evidence is a
            // refusal rather than a stack.
            if (found is null && Insisted(reasons) is { } insisted &&
                Throws(
                    machine, module, heap, dispatcher, engine, factory, stack, example, staging,
                    insisted))
            {
                found = new VirtualOperation(opcode, 1, 0, Throwing) { Popped = insisted };
            }

            // An operation that refuses a stack of numbers by wanting an array, then runs past that
            // cast when handed an array beneath an index only to fault building what it read, is
            // reading an element of the array. The fault is in wrapping the value it took out, which
            // is work only a read has to do — a write leaves nothing to wrap and is measured where
            // this one throws. The stack effect is left to the walk, which forces the -1 that a read
            // of one element from one array beneath one index has no choice but to be.
            if (found is null && WantsArrayThenFaulted(reasons))
            {
                found = new VirtualOperation(opcode, 0, 0, null)
                {
                    Measured = false,
                    Needs = "an array beneath an index",
                    Unmeasured = "it took an array beneath an index and faulted building what it read"
                };
            }

            if (found is not null)
            {
                // A jump is asked once more, over values that make its condition answerable. This
                // is asked of anything shaped like one and not only of what was already read as a
                // jump: a jump that none of the trials above happened to make fire is written down
                // as an operation that consumes a value and does nothing, which is the reading that
                // severs every block it reaches.
                if (found is { Pushes: 0, Pops: 1 or 2, Name: not Throwing } && operand is not null)
                {
                    var condition = Decides(
                        machine, module, heap, dispatcher, engine, factory, slotType, stack, example,
                        operand, staging, found.Pops, out var why);
                    if (condition is not null)
                    {
                        found = found with
                        {
                            Decides = condition,
                            Name = found.Name ?? "branch if",
                            TouchesState = true
                        };
                    }
                    else if (why.Length > 0 && !why.StartsWith("it went nowhere", StringComparison.Ordinal))
                    {
                        undecided[opcode] = why;
                    }
                }
                derived[opcode] = found;
                continue;
            }
            declined[opcode] = reasons.Count == 0
                ? "its trials did not agree with each other"
                : string.Join(", and ", reasons);
        }

        var named = derived.Values.Count(operation => operation.Name is not null);
        var decided = derived.Values.Count(operation => operation.Decides is not null);
        var summary = derived.Count == 0
            ? "The engine performed none of its operations in isolation, so none were given meaning."
            : $"{derived.Count} of {examples.Count} operation(s) were performed in isolation, " +
                $"{named} of them identified by name.";
        if (decided > 0)
        {
            summary += $" {decided} jump(s) were made to decide over values that separate the " +
                "conditions, which named what each goes on.";
        }
        if (undecided.Count > 0)
        {
            summary += " What the rest of the jumps decide on went unread: " +
                string.Join("; ", undecided
                    .OrderBy(entry => entry.Key)
                    .Select(entry => $"op {entry.Key}, {entry.Value}")) + ".";
        }
        if (declined.Count > 0)
            summary += " The rest were left alone: " + string.Join("; ", Counted(declined)) + ".";
        return new VirtualSemanticsReport(derived, declined, summary);
    }

    /// <summary>
    /// Which condition a jump goes on, by making it decide over values that tell the readings apart.
    /// </summary>
    /// <remarks>
    /// One reading or none. Where two conditions would both account for the times it went, the
    /// values did not separate them and nothing here knows which it is; saying either would be a
    /// coin toss recorded as a measurement. A jump that went every time and one that never went are
    /// both refused for the same reason: neither is a condition, and an operation that always goes
    /// is read as the plain jump it is elsewhere.
    /// </remarks>
    private static string? Decides(
        StaticMachine machine,
        ModuleDef module,
        StaticHeap heap,
        MethodDef dispatcher,
        StaticValue engine,
        MethodDef factory,
        string slotType,
        List<StaticValue> stack,
        StaticValue operation,
        long? operand,
        List<(FieldDef From, FieldDef To)> staging,
        int pops,
        out string why)
    {
        why = string.Empty;
        if (operand is not { } target)
            return null;
        var trials = Trials(
            machine, module, heap, dispatcher, engine, factory, slotType, stack, operation, operand,
            staging, null, Shapes[0], out var refused, Deciders);
        if (trials.Count != Deciders.Length)
        {
            why = refused.Length > 0
                ? refused
                : "it would not decide over the values that separate the conditions";
            return null;
        }

        // Where it went is read the same way it is read elsewhere: an engine that steps its position
        // after performing an operation writes the place before the one it means to reach, so both
        // numbers count as having gone. Reading only the exact one takes every jump of such an
        // engine for an operation that consumes two values and does nothing.
        var went = trials
            .Select(trial => Put(trial, target) || Put(trial, target - 1))
            .ToList();
        if (!went.Any(gone => gone))
        {
            why = "it went nowhere over any of them, so there is no condition to read";
            return null;
        }
        if (went.All(gone => gone))
        {
            why = "it went over all of them, which is a jump rather than a condition";
            return null;
        }

        var fits = Conditions
            .Where(condition => condition.Pops == pops)
            .Where(condition => !Deciders
                .Select((seeds, at) =>
                    condition.Holds(seeds[^2], seeds[^1]) == went[at])
                .Contains(false))
            .Select(condition => condition.Name)
            .ToList();
        if (fits.Count == 1)
            return fits[0];
        why = fits.Count == 0
            ? "when it went matches no condition, so what it decides on is not among them"
            : $"when it went matches {string.Join(" and ", fits)} alike";
        return null;
    }

    /// <summary>Whether the operation throws the very value it was handed.</summary>
    /// <remarks>
    /// An operation that throws cannot be measured the way the rest are. It never returns, so there
    /// is no stack afterwards to read, and every arrangement of values is refused alike — which is
    /// why one would otherwise be left unread however many times it is tried.
    ///
    /// What it does leave is the complaint. A handler that begins by casting what it took to an
    /// exception says, in refusing, what it wanted; hand it one and the run ends the way a throw
    /// ends. The reading is then in the identity of what came back rather than in its type: the
    /// instance thrown has to be the instance we made, or the operation threw something of its own
    /// and merely happened to want an exception to do it. Twice, with two instances, for the same
    /// reason every other reading here is taken more than once.
    /// </remarks>
    private static bool Throws(
        StaticMachine machine,
        ModuleDef module,
        StaticHeap heap,
        MethodDef dispatcher,
        StaticValue engine,
        MethodDef factory,
        List<StaticValue> stack,
        StaticValue operation,
        List<(FieldDef From, FieldDef To)> staging,
        string wanted)
    {
        foreach (var seeds in Seeds.Take(2))
        {
            stack.Clear();
            if (!TryMakeSlot(
                    machine, module, heap, factory, seeds[0], false, wanted, out var slot, out var held))
            {
                return false;
            }
            stack.Add(slot);
            var footprint = Footprint(heap, module, engine, stack);
            Stage(heap, staging, engine, operation);
            var outcome = machine.Execute(
                dispatcher, [engine, operation], new StaticWorkBudget(TrialSteps));
            Restore(heap, footprint);
            if (outcome.Status != StaticExecutionStatus.Threw ||
                outcome.Value.Kind != StaticValueKind.HeapReference ||
                outcome.Value.Bits != held.Bits)
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>One performance of an operation: what was on the stack, and what was left.</summary>
    /// <param name="Moved">
    /// The numbers the engine's own state took on that it did not have before, which is how an
    /// operation that jumps is told apart from one that does nothing.
    /// </param>
    /// <param name="After">
    /// What it left, with an entry for anything that is not a number we can read. Those still count
    /// towards the stack effect, which is measured by position rather than by value.
    /// </param>
    private sealed record Trial(
        IReadOnlyList<long> Before,
        IReadOnlyList<long?> After,
        int Kept,
        IReadOnlyCollection<long> Moved)
    {
        /// <summary>Whether an array offered to it came back holding the value at the index given.</summary>
        public bool Stored { get; init; }

        /// <summary>
        /// The engine's tables that held what it left, at the place its operand names, and how
        /// long each of those tables is.
        /// </summary>
        public IReadOnlyDictionary<string, int> Loaded { get; init; } =
            new Dictionary<string, int>(StringComparer.Ordinal);

        /// <summary>What kind of thing it left, where the value itself could not be read.</summary>
        public List<string> Kinds { get; init; } = [];

        /// <summary>The values put on the stack for it, so that what it kept can be recognized.</summary>
        public IReadOnlyList<long> Identities { get; init; } = [];

        /// <summary>Which of the engine's places changed, said as the walk found them.</summary>
        /// <remarks>
        /// That an operation changed something is the beginning of a reading rather than the end of
        /// one. Where it wrote is what says whether it moved the engine along, put a result
        /// somewhere, or stopped the program.
        /// </remarks>
        public IReadOnlyList<string> Where { get; init; } = [];
    }

    /// <summary>
    /// Records everything the engine holds apart from its stack, so that any change is noticed.
    /// </summary>
    /// <remarks>
    /// Judging an operation by the stack alone is how a jump comes to be reported as doing nothing,
    /// which is worse than declining to name it: a reader told an operation is inert will treat the
    /// code after it as unreachable. Nor is it enough to watch the numbers the engine holds
    /// directly, because an operation that stores into a local writes an array element, and one
    /// that reports no effect while quietly writing a local is just as misleading.
    ///
    /// So the walk covers fields and array elements alike, and remembers a reference by identity, a
    /// replaced element being exactly what a store looks like. The stack is left out on purpose: it
    /// is reseeded for every trial and accounted for separately, so including it would mark every
    /// operation as touching state and the distinction would be lost.
    /// </remarks>
    /// <summary>How long a list may be and still be a table of values rather than the program.</summary>
    private const int Tabular = 64;

    /// <summary>One place the engine keeps something, remembered well enough to put it back.</summary>
    private sealed record Place(
        string Path,
        StaticValue Owner,
        FieldDef? Field,
        int Index,
        StaticValue Value);

    private static List<Place> Footprint(
        StaticHeap heap,
        ModuleDef module,
        StaticValue engine,
        List<StaticValue> stack)
    {
        var held = new List<Place>();
        var visited = new HashSet<long>();
        var queue = new Queue<(StaticValue Value, string Path, int Depth)>();
        queue.Enqueue((engine, string.Empty, 0));
        while (queue.Count > 0)
        {
            var (value, path, depth) = queue.Dequeue();
            if (value.Kind != StaticValueKind.HeapReference || depth > SearchDepth ||
                !visited.Add(value.Bits) ||
                !heap.TryGetRuntimeTypeName(value, out var typeName))
            {
                continue;
            }

            // The engine's stack is the one thing deliberately disturbed, so it is not evidence.
            if (heap.TryGetModelValue<List<StaticValue>>(value, "Items", out var items) &&
                items is not null)
            {
                if (ReferenceEquals(items, stack))
                    continue;

                // A table the engine keeps as a list is as much a place as one it keeps as an
                // array, and an operation that fetches from one is doing what an operation that
                // fetches from the other does. The long ones are left alone: a list of thousands is
                // the program itself rather than a table of values, and walking it every trial
                // costs more than it could ever say.
                if (items.Count <= Tabular)
                {
                    for (var index = 0; index < items.Count; index++)
                    {
                        held.Add(new Place($"{path}[{index}]", value, null, index, items[index]));
                        Follow(queue, $"{path}[{index}]", items[index], depth);
                    }
                }
                continue;
            }

            if (heap.TryGetLength(value, out var length) && heap.TryGetArrayElementType(value, out _))
            {
                for (var index = 0; index < length; index++)
                {
                    if (heap.TryReadArray(value, index, out var element))
                    {
                        held.Add(new Place($"{path}[{index}]", value, null, index, element));
                        Follow(queue, $"{path}[{index}]", element, depth);
                    }
                }
                continue;
            }

            foreach (var field in Fields(module, typeName))
            {
                if (heap.TryReadField(value, field, out var stored))
                {
                    held.Add(new Place($"{path}.{field.Name}", value, field, 0, stored));
                    Follow(queue, $"{path}.{field.Name}", stored, depth);
                }
            }
        }
        return held;
    }

    private static void Follow(
        Queue<(StaticValue Value, string Path, int Depth)> queue,
        string path,
        StaticValue value,
        int depth)
    {
        if (value.Kind == StaticValueKind.HeapReference)
            queue.Enqueue((value, path, depth + 1));
    }

    /// <summary>
    /// Puts the engine back the way it was, so that each trial asks its question of the same state.
    /// </summary>
    /// <remarks>
    /// Without this, an operation that writes the same value every time is seen to change something
    /// on the first trial and nothing afterwards, because the value it writes is already there. A
    /// jump read that way looks conditional — taken once, then not — when it is nothing of the sort.
    /// </remarks>
    private static void Restore(StaticHeap heap, List<Place> footprint)
    {
        foreach (var place in footprint)
            Put(heap, place, place.Value);
    }

    internal static long? Operand(StaticHeap heap, StaticValue operation, FieldDef? operandField)
    {
        if (operandField is null || !heap.TryReadField(operation, operandField, out var stored))
            return null;
        if (stored.Kind is StaticValueKind.Int32 or StaticValueKind.Int64)
            return stored.Bits;
        return stored.Kind == StaticValueKind.HeapReference &&
            heap.TryUnbox(stored, out var unboxed) &&
            unboxed.Kind is StaticValueKind.Int32 or StaticValueKind.Int64
                ? unboxed.Bits
                : null;
    }

    /// <summary>
    /// Where the engine copies parts of an operation before performing it, taken from its own code.
    /// </summary>
    /// <remarks>
    /// Some engines hand the whole operation to the handler and let it read what it needs. Others
    /// unpack it first, so that by the time the handler runs the operand is a field of the engine
    /// and the operation itself is never read again. A handler of the second kind, performed on its
    /// own, reads a field nothing filled in, and every one of them refuses the same way: the operand
    /// it wanted was not a boxed anything, because it was not there at all.
    ///
    /// The unpacking is a pair of instructions in the loop around the handler — read a field of the
    /// operation, write a field of the engine — and nothing else in the engine has that shape, since
    /// the operation type exists only to be unpacked. Reading the pair back out is what lets the
    /// trials put the engine in the state the handler was written to find.
    /// </remarks>
    private static List<(FieldDef From, FieldDef To)> Staging(MethodDef dispatcher)
    {
        var engineType = dispatcher.DeclaringType;
        var operationType = dispatcher.Parameters
            .Where(parameter => !parameter.IsHiddenThisParameter)
            .Select(parameter => parameter.Type.ToTypeDefOrRef().ResolveTypeDef())
            .FirstOrDefault(type => type is not null && type != engineType);
        if (engineType is null || operationType is null)
            return [];

        var found = new Dictionary<FieldDef, FieldDef?>();
        foreach (var method in engineType.Methods.Where(method => method.HasBody))
        {
            var instructions = method.Body.Instructions;
            for (var index = 0; index + 1 < instructions.Count; index++)
            {
                if (instructions[index].OpCode.Code != Code.Ldfld ||
                    instructions[index + 1].OpCode.Code != Code.Stfld ||
                    (instructions[index].Operand as IField)?.ResolveFieldDef() is not { } read ||
                    (instructions[index + 1].Operand as IField)?.ResolveFieldDef() is not { } written ||
                    read.DeclaringType != operationType ||
                    written.DeclaringType != engineType)
                {
                    continue;
                }

                // A field written from two different parts of an operation is not an unpacking of
                // either, so it is struck out rather than guessed at.
                found[written] = found.TryGetValue(written, out var earlier) && earlier != read
                    ? null
                    : read;
            }
        }
        return [.. found
            .Where(pair => pair.Value is not null)
            .Select(pair => (From: pair.Value!, To: pair.Key))];
    }

    /// <summary>The type of the field an operand names, where it names one of reference kind.</summary>
    /// <remarks>
    /// Value types are left out. One is stored by having its number put on the stack, which the
    /// numbered seeding already does, so making an instance to hold it would only be a worse way of
    /// asking the same question.
    /// </remarks>
    private static string? Names(ModuleDef module, long? operand)
    {
        if (operand is not { } token || token is < int.MinValue or > int.MaxValue)
            return null;
        try
        {
            var field = (module.ResolveToken((int)token) as IField)?.ResolveFieldDef();
            return field?.FieldType is { IsValueType: false } type ? type.FullName : null;
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>Unpacks an operation into the engine the way the engine's own loop would.</summary>
    private static bool Stage(
        StaticHeap heap,
        List<(FieldDef From, FieldDef To)> staging,
        StaticValue engine,
        StaticValue operation)
    {
        var staged = false;
        foreach (var (from, to) in staging)
        {
            if (heap.TryReadField(operation, from, out var value) &&
                heap.TryWriteField(engine, to, value))
            {
                staged = true;
            }
        }
        return staged;
    }

    private static List<Trial> Trials(
        StaticMachine machine,
        ModuleDef module,
        StaticHeap heap,
        MethodDef dispatcher,
        StaticValue engine,
        MethodDef factory,
        string slotType,
        List<StaticValue> stack,
        StaticValue operation,
        long? operand,
        List<(FieldDef From, FieldDef To)> staging,
        string? named,
        Shape shape,
        out string refused,
        int[][]? sets = null)
    {
        refused = string.Empty;
        var trials = new List<Trial>();
        foreach (var seeds in sets ?? Seeds)
        {
            stack.Clear();
            var identities = new List<long>(seeds.Length);
            var before = new List<long>(seeds.Length);
            var array = StaticValue.Null;
            var arrayAt = -1;
            for (var position = 0; position < seeds.Length; position++)
            {
                var wantsArray = position < shape.Arrays.Length && shape.Arrays[position];
                if (!TryMakeSlot(
                        machine, module, heap, factory, seeds[position], wantsArray, named,
                        out var slot, out var held))
                {
                    refused = "the engine would not build a value to put on its stack";
                    return [];
                }
                if (wantsArray)
                {
                    array = held;
                    arrayAt = position;
                }
                stack.Add(slot);
                identities.Add(slot.Bits);
                before.Add(seeds[position]);
            }

            var footprint = Footprint(heap, module, engine, stack);
            var staged = Stage(heap, staging, engine, operation);
            var seeded = Sown(
                machine, module, heap, factory, slotType, footprint, operand, trials.Count);
            var was = (seeded.Count == 0 && !staged
                    ? footprint
                    : Footprint(heap, module, engine, stack))
                .ToDictionary(place => place.Path, place => place.Value.Bits);
            var outcome = machine.Execute(
                dispatcher, [engine, operation], new StaticWorkBudget(TrialSteps));
            if (outcome.Status != StaticExecutionStatus.Completed)
            {
                refused = Refusal(outcome.Status, outcome.Diagnostic);
                Restore(heap, footprint);
                return [];
            }

            var settled = Footprint(heap, module, engine, stack);
            var moved = new HashSet<long>();
            var where = new List<string>();
            foreach (var place in settled)
            {
                if (was.TryGetValue(place.Path, out var earlier) && earlier == place.Value.Bits)
                    continue;
                moved.Add(place.Value.Bits);
                where.Add($"{place.Path}={place.Value.Bits}");
            }

            // How many of the values we put there are still where we put them says what the
            // operation consumed, which a count of the stack on its own cannot.
            var kept = 0;
            while (kept < identities.Count && kept < stack.Count &&
                   stack[kept].Kind == StaticValueKind.HeapReference &&
                   stack[kept].Bits == identities[kept])
            {
                kept++;
            }

            // A value we cannot read is still a value, and where it sits is what says how much the
            // operation pushed. Throwing the trial away over it would discard a measurement we have
            // in order to avoid admitting to one we do not.
            var after = new List<long?>();
            var kinds = new List<string>();
            for (var index = kept; index < stack.Count; index++)
            {
                after.Add(TryReadNumber(heap, module, stack[index], out var value)
                    ? value
                    : null);
                kinds.Add(Kind(heap, module, stack[index]));
            }
            // An operation given an array, an index and a value that leaves the value in the array
            // at that index has stored it, which nothing about the stack alone would show: the
            // three values go in and none come out either way.
            var stored = arrayAt >= 0 && arrayAt + 2 < seeds.Length &&
                heap.TryReadArray(array, seeds[arrayAt + 1], out var element) &&
                element.Kind == StaticValueKind.Int32 &&
                element.Bits == seeds[arrayAt + 2];

            trials.Add(new Trial(before, after, kept, moved)
            {
                Loaded = Fetched(heap, module, settled, stack, kept, operand),
                Stored = stored,
                Where = where,
                Kinds = kinds,
                Identities = identities
            });
            Restore(heap, footprint);
        }
        return trials;
    }

    /// <summary>
    /// Puts a value of our own in every table of the engine, at the place the operand names.
    /// </summary>
    /// <remarks>
    /// An operation that fetches from a table cannot be performed against an engine no run has
    /// filled in: it reaches for a place that is not there, or finds something the surrounding
    /// program left half-made, and faults either way. That is what leaves the arguments of a method
    /// unreadable, since nothing but a real call ever puts anything in them.
    ///
    /// So the tables are filled before the operation is asked, and filled differently in each one,
    /// which turns a refusal into a measurement twice over: the operation runs, and the table it
    /// fetched from is the one holding the number that came back. Everything written here is put
    /// back afterwards along with the rest of the trial's disturbance.
    /// </remarks>
    private static Dictionary<string, long> Sown(
        StaticMachine machine,
        ModuleDef module,
        StaticHeap heap,
        MethodDef factory,
        string slotType,
        List<Place> footprint,
        long? operand,
        int trial)
    {
        var written = new Dictionary<string, long>(StringComparer.Ordinal);
        if (operand is not { } index || index < 0 || index > int.MaxValue)
            return written;

        var ending = $"[{index.ToString(CultureInfo.InvariantCulture)}]";
        var number = Sowing + (trial * Sowing / 4);
        foreach (var place in footprint)
        {
            if (place.Field is not null ||
                !place.Path.EndsWith(ending, StringComparison.Ordinal) ||
                !Tabled(heap, place.Owner, slotType) ||
                !TryMakeSlot(
                    machine, module, heap, factory, ++number, false, null, out var slot, out _))
            {
                continue;
            }
            if (Put(heap, place, slot))
                written[place.Path] = number;
        }
        return written;
    }

    /// <summary>Where the numbers sown into the engine's tables start.</summary>
    /// <remarks>
    /// Far from the numbers the stack is seeded with, so that a value fetched from a table is
    /// never mistaken for one taken off the stack, and far from anything small the engine is
    /// likely to be holding already.
    /// </remarks>
    private const int Sowing = 6000;

    /// <summary>Whether something the engine holds is one of its tables of values.</summary>
    private static bool Tabled(StaticHeap heap, StaticValue owner, string slotType) =>
        heap.TryGetArrayElementType(owner, out var element) &&
            string.Equals(element, slotType, StringComparison.Ordinal) ||
        heap.TryGetRuntimeTypeName(owner, out var typeName) &&
            string.Equals(
                typeName,
                $"System.Collections.Generic.List`1<{slotType}>",
                StringComparison.Ordinal);

    /// <summary>Writes one value into a place the engine keeps one, however it keeps it.</summary>
    private static bool Put(StaticHeap heap, Place place, StaticValue value)
    {
        if (place.Field is not null)
            return heap.TryWriteField(place.Owner, place.Field, value);
        if (heap.TryGetModelValue<List<StaticValue>>(place.Owner, "Items", out var items) &&
            items is not null)
        {
            if (place.Index >= items.Count)
                return false;
            items[place.Index] = value;
            return true;
        }
        return heap.TryWriteArray(place.Owner, place.Index, value);
    }

    /// <summary>
    /// Says why an operation would not be performed, in terms of what was asked of it.
    /// </summary>
    /// <remarks>
    /// Grouping these is how the next thing worth building gets chosen: an operation that wanted a
    /// value of a kind we never put on the stack calls for better seeding, whereas one that reached
    /// past the end of a table wants the program's surrounding state and may never be answerable
    /// this way.
    /// </remarks>
    private static string Refusal(StaticExecutionStatus status, string? diagnostic)
    {
        var text = diagnostic ?? string.Empty;
        var cut = text.IndexOf(" | provenance", StringComparison.Ordinal);
        if (cut > 0)
            text = text[..cut];
        if (status == StaticExecutionStatus.Threw)
            return "it threw when performed on its own";
        if (status == StaticExecutionStatus.StepLimitExceeded)
            return "it ran on far longer than one operation should";
        if (text.Contains("out of range", StringComparison.Ordinal) ||
            text.Contains("out of bounds", StringComparison.Ordinal))
        {
            return "it indexes something the surrounding program would have filled in";
        }
        if (text.Contains("cast", StringComparison.OrdinalIgnoreCase))
        {
            // Which kind it wanted is the whole of what makes this reportable: without it the note
            // says only that the seeding was wrong, and gives the reader no way to make it right.
            var refused = text.Split('\n')[0].Trim();
            return $"{WrongKind} ({refused[..Math.Min(refused.Length, 200)]})";
        }

        // Where nothing above recognizes the failure, the machine's own words are the only thing
        // that says where the gap is, and a gap in the tool is worth reporting as precisely as one
        // in the sample.
        var said = text.Split('\n')[0].Trim();
        return said.Length == 0
            ? "the machine could not follow it"
            : $"the machine could not follow it: {said[..Math.Min(said.Length, 300)]}";
    }

    private static VirtualOperation? Classify(
        int opcode,
        long? operand,
        List<Trial> trials,
        Shape shape)
    {
        var pops = trials[0].Before.Count - trials[0].Kept;
        var pushes = trials[0].After.Count;
        if (trials.Any(trial => trial.Before.Count - trial.Kept != pops || trial.After.Count != pushes))
            return null;

        // An operation whose operand turns up in one of the engine's own fields afterwards has
        // jumped to it. That reading comes first, because every other reading of such an operation
        // is wrong. A field of the engine and not a slot of one of its tables: an operation that
        // stores a value at the place its operand names writes the operand's own number into the
        // table whenever the value it was handed happens to be that number, and reading that as a
        // jump takes a store for a branch and severs the program at it.
        var settled = trials.All(trial => trial.Moved.Count == 0);
        if (operand is { } target && trials.Any(trial => Put(trial, target)))
        {
            // A jump that takes nothing has nothing to decide with and goes wherever it points. One
            // that takes values decides with them, and having jumped in every trial does not say
            // otherwise: the values it is tried with are ordered the same way every time, so a jump
            // taken when one exceeds another is taken in all of them.
            var always = trials.All(trial => Put(trial, target));
            return new VirtualOperation(
                opcode, pops, pushes, always && pops == 0 ? "branch" : "branch if")
            {
                TouchesState = true,
                Changes = Changed(trials),
                Reached = Arriving(trials, operand),
                Needs = shape.Plain ? null : shape.Needs
            };
        }

        // Only effects that were positively identified are named. An operation that consumed a value
        // and appeared to do nothing else is reported as exactly that, because what can be watched
        // here is the engine's own state and not, say, a static field it might have written, and
        // "discards it" would be a claim the trials do not support.
        // With an array on the stack the values going in are not all numbers, so the arithmetic
        // candidates have nothing to match against. One reading is still open: an operation handed
        // an array that answers with its length, which the varying lengths are there to establish.
        var name = !shape.Plain
            ? Measuring(shape, pops, pushes, trials)
            : (pops, pushes) switch
            {
                (0, 1) => Nullary(trials) ?? Carried(trials, operand) ??
                    (Fetching(trials) is not null ? "loads what its operand indexes" : null),
                (1, 1) => Unary(trials),
                (2, 1) => Binary(trials),
                _ => null
            };
        return new VirtualOperation(opcode, pops, pushes, name)
        {
            Holding = pushes == 1 && pops == 0 ? Fetching(trials)?.Length : null,
            Left = pushes == 1 && pops == 0 ? Leaves(trials) : null,

            // What kind of value was left is worth keeping even where the value itself was read,
            // because for one operation it is the whole of the reading: a conversion alters how a
            // value is held and not what it is, so which conversion it is can only be told by the
            // type it left the value as. Only a named type is taken; the trials also have words for
            // a value they could not place, and those name no width.
            Pushed = pushes == 1 && Leaves(trials) is { } produced &&
                produced.Contains('.', StringComparison.Ordinal)
                    ? produced
                    : null,
            TouchesState = !settled,
            Changes = settled ? null : Changed(trials),
            Reached = settled ? null : Arriving(trials, operand),
            Needs = shape.Plain ? null : shape.Needs
        };
    }

    /// <summary>
    /// The one table that held what the operation left, every trial, at the place its operand named.
    /// </summary>
    /// <remarks>
    /// One table only. Where two of them hold the same thing at the same place there is nothing to
    /// choose between them, and a reading that picks one is a guess dressed as a measurement.
    /// </remarks>
    private static (string Path, int Length)? Fetching(List<Trial> trials)
    {
        var shared = trials[0].Loaded.Keys.ToHashSet(StringComparer.Ordinal);
        foreach (var trial in trials.Skip(1))
            shared.IntersectWith(trial.Loaded.Keys);
        if (shared.Count != 1)
            return null;
        var path = shared.First();
        var lengths = trials.Select(trial => trial.Loaded[path]).Distinct().ToList();
        return lengths.Count == 1 ? (path, lengths[0]) : null;
    }

    /// <summary>
    /// What an operation that pushes something unreadable pushes, said by kind.
    /// </summary>
    /// <remarks>
    /// Reading the value is the better answer and is tried first. Where it cannot be read, what
    /// kind of thing it is still tells a reader something, and one kind settles the matter: an
    /// operation that leaves nothing at all, every time, whatever it was handed, pushes null.
    /// </remarks>
    private static string? Leaves(List<Trial> trials)
    {
        var kinds = trials
            .Select(trial => trial.Kinds.Count == 1 ? trial.Kinds[0] : null)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        return kinds.Count == 1 ? kinds[0] : null;
    }

    /// <summary>
    /// The engine's own places some trial gave the very number the operation carries.
    /// </summary>
    /// <remarks>
    /// Where a place was given the operand, the operation put its operand there; and where it was
    /// given one less, it put its operand there too, an engine that steps its position after
    /// performing an operation having to write the place before the one it means to reach. Which of
    /// those places is the position is not known here and is known later, so the places are
    /// reported rather than read: a number that is a jump's destination in one field is an
    /// accident of the values we chose in any other, and only the field tells them apart.
    ///
    /// Some trial rather than every one, because a conditional jump not taken writes nothing, and
    /// an operation only taken once is the interesting half of the reading.
    /// </remarks>
    private static List<string>? Arriving(List<Trial> trials, long? operand)
    {
        if (operand is not { } place)
            return null;
        var found = trials
            .SelectMany(trial => trial.Where)
            .Where(one =>
                !Site(one).Contains('[', StringComparison.Ordinal) &&
                long.TryParse(
                    one.Split('=')[^1], NumberStyles.Integer, CultureInfo.InvariantCulture,
                    out var value) &&
                (value == place || value == place - 1))
            .Select(Site)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        return found.Count > 0 ? found : null;
    }

    /// <summary>Where an operation was seen writing, where it wrote the same place every time.</summary>
    /// <remarks>
    /// Only places every trial disturbed are reported. A place one trial changed and another did
    /// not is as likely to be the engine reacting to the values we chose as it is to be the
    /// operation's doing.
    /// </remarks>
    private static List<string>? Changed(List<Trial> trials)
    {
        var everywhere = trials[0].Where.Select(Site).Distinct(StringComparer.Ordinal).ToList();
        foreach (var trial in trials.Skip(1))
        {
            var one = trial.Where.Select(Site).ToHashSet(StringComparer.Ordinal);
            everywhere = everywhere.Where(one.Contains).ToList();
        }
        if (everywhere.Count == 0)
            return null;

        // What it wrote there matters as much as where. A place given the same number whatever it
        // was handed is the engine being set rather than the operation's values being kept, and
        // that is the difference between an operation that goes somewhere and one that returns.
        return everywhere
            .Order(StringComparer.Ordinal)
            .Take(12)
            .Select(place => $"{place}{What(trials, place)}")
            .ToList();
    }

    /// <summary>What a place was given, where the same thing can be said of every trial.</summary>
    /// <remarks>
    /// Two answers are worth having and they mean opposite things. A place given the same number
    /// whatever the operation was handed is the engine being set — a position moved, a flag raised
    /// — and a place given back one of the values the operation took is the operation putting
    /// something away.
    /// </remarks>
    private static string What(List<Trial> trials, string place)
    {
        var written = trials
            .Select(trial => trial.Where.FirstOrDefault(one => Site(one) == place))
            .Select(one => one is null ? null : (long?)long.Parse(
                one.Split('=')[^1], CultureInfo.InvariantCulture))
            .ToList();
        if (written.Exists(value => value is null))
            return string.Empty;

        var taken = trials
            .Select((trial, index) => trial.Identities.Skip(trial.Kept).Contains(written[index]!.Value))
            .ToList();
        if (taken.TrueForAll(one => one))
            return "=what it took";
        var values = written.Distinct().ToList();
        return values.Count == 1
            ? $"={values[0]!.Value.ToString(CultureInfo.InvariantCulture)}"
            : string.Empty;
    }

    private static string Site(string written) => written.Split('=')[0];

    /// <summary>Whether a trial put a number into one of the engine's own fields.</summary>
    /// <remarks>
    /// A field rather than anywhere: the engine's tables hold the program's values, and a value
    /// that happens to equal the operation's operand says nothing about the operation.
    /// </remarks>
    private static bool Put(Trial trial, long number) =>
        trial.Where.Any(one =>
            !Site(one).Contains('[', StringComparison.Ordinal) &&
            long.TryParse(
                one.Split('=')[^1], NumberStyles.Integer, CultureInfo.InvariantCulture,
                out var value) &&
            value == number);

    /// <summary>
    /// The tables of the engine that hold, where the operand says, what the operation left.
    /// </summary>
    /// <remarks>
    /// An operation that pushes something the trials cannot read is not necessarily beyond them.
    /// Where the thing it pushed is sitting in one of the engine's own tables at the very place its
    /// operand names, the operation fetched it from there, and that is a reading however unreadable
    /// the value itself was. It only works against an engine a real run has filled in: in a cold
    /// one the tables are empty and there is nothing to match.
    ///
    /// How long the table is comes back with it, because that is what later tells one table from
    /// another — a method's arguments are as many as it declares, and its locals are not.
    /// </remarks>
    private static Dictionary<string, int> Fetched(
        StaticHeap heap,
        ModuleDef module,
        List<Place> settled,
        List<StaticValue> stack,
        int kept,
        long? operand)
    {
        var found = new Dictionary<string, int>(StringComparer.Ordinal);
        if (operand is not { } index || index < 0 || stack.Count - kept != 1)
            return found;

        var left = stack[^1];
        var ending = $"[{index.ToString(CultureInfo.InvariantCulture)}]";
        var lengths = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var place in settled)
        {
            // An element of a table, and not something kept inside one of its elements: the places
            // under a table run on into whatever its values are made of, and counting those as
            // entries would make every table as long as its contents are deep.
            if (Element(place.Path) is not { } table)
                continue;
            lengths.TryGetValue(table, out var counted);
            lengths[table] = counted + 1;
            if (place.Path.EndsWith(ending, StringComparison.Ordinal) &&
                Holds(heap, module, place.Value, left))
            {
                found[table] = 0;
            }
        }
        foreach (var table in found.Keys.ToList())
            found[table] = lengths[table];
        return found;
    }

    /// <summary>The table a place is an element of, or nothing if it is not one.</summary>
    private static string? Element(string path)
    {
        if (path.Length == 0 || path[^1] != ']')
            return null;
        var cut = path.LastIndexOf('[');
        if (cut < 0)
            return null;
        var index = path.AsSpan(cut + 1, path.Length - cut - 2);
        return index.Length > 0 && !index.ContainsAnyExcept(Digits) ? path[..cut] : null;
    }

    private static readonly SearchValues<char> Digits = SearchValues.Create("0123456789");

    /// <summary>Whether two of the engine's values stand for the same thing.</summary>
    private static bool Holds(
        StaticHeap heap,
        ModuleDef module,
        StaticValue held,
        StaticValue left) =>
        held.Kind == left.Kind && held.Bits == left.Bits ||
        Kind(heap, module, held) is var kind && kind != "nothing at all" &&
        string.Equals(kind, Kind(heap, module, left), StringComparison.Ordinal) &&
        Same(heap, module, held, left);

    /// <summary>Whether two wrappers hold the same thing, looked at through them.</summary>
    /// <remarks>
    /// Two wrappers around one object are the same value however many wrappers there are, so the
    /// object itself is what is compared. Numbers are not shared that way — each wrapper has a
    /// place of its own to keep one in — so for those it is the number that has to agree.
    /// </remarks>
    private static bool Same(
        StaticHeap heap,
        ModuleDef module,
        StaticValue held,
        StaticValue left)
    {
        var one = Unwrapped(heap, module, held);
        var other = Unwrapped(heap, module, left);
        if (one.Kind == other.Kind && one.Bits == other.Bits)
            return true;
        return TryReadNumber(heap, module, held, out var number) &&
            TryReadNumber(heap, module, left, out var alike) &&
            number == alike;
    }

    private static StaticValue Unwrapped(StaticHeap heap, ModuleDef module, StaticValue value)
    {
        var held = value;
        for (var unwrapped = 0; unwrapped < 3; unwrapped++)
        {
            if (held.Kind != StaticValueKind.HeapReference ||
                !heap.TryGetRuntimeTypeName(held, out var wrapper) ||
                Inside(heap, module, held, wrapper) is not { } within)
            {
                break;
            }
            held = within;
        }
        return held;
    }

    /// <summary>
    /// What sort of thing a value is, for saying something about one that cannot be read.
    /// </summary>
    /// <remarks>
    /// The engine keeps its stack in slots, so what is on it is the slot and what matters is what
    /// the slot holds. A value that is no number is still a value of some kind, and naming the kind
    /// is often the whole answer: an operation that always leaves nothing at all is pushing null.
    /// </remarks>
    private static string Kind(StaticHeap heap, ModuleDef module, StaticValue slot)
    {
        var carried = Carrying(heap, module, slot, 0);
        if (carried.Nothing)
            return "nothing at all";
        if (carried.Type is { } named)
            return named;
        return heap.TryGetRuntimeTypeName(slot, out var typeName) ? typeName : "something";
    }

    /// <summary>
    /// What one of the engine's own wrappers holds, where it holds exactly one thing.
    /// </summary>
    /// <remarks>
    /// The engine does not put values on its stack; it puts its own objects there, each holding
    /// one. Saying an operation pushed one of those says nothing, since they all do. What is worth
    /// knowing is what was inside, so a wrapper with a single thing in it is looked through.
    /// </remarks>
    private static StaticValue? Inside(
        StaticHeap heap,
        ModuleDef module,
        StaticValue wrapper,
        string typeName)
    {
        var held = new List<StaticValue>();
        foreach (var field in Fields(module, typeName))
        {
            if (!Describing(field) &&
                heap.TryReadField(wrapper, field, out var stored) &&
                stored.Kind != StaticValueKind.Null)
            {
                held.Add(stored);
            }
        }
        return held.Count == 1 ? held[0] : null;
    }

    /// <summary>
    /// An operation handed an array that answers with how long it is.
    /// </summary>
    /// <remarks>
    /// The arrays offered are a different length in each trial, and the length is a known function
    /// of the seed at that position, so an answer that tracks it is measuring the array rather than
    /// returning something that happened to match once.
    /// </remarks>
    private static string? Measuring(Shape shape, int pops, int pushes, List<Trial> trials)
    {
        if (trials.All(trial => trial.Stored))
            return "writes an array element";

        var at = Array.IndexOf(shape.Arrays, true);
        if (at >= 0 && at == shape.Arrays.Length - 1 && (pops, pushes) == (1, 1))
        {
            return trials.All(trial =>
                trial.After[0] is { } produced && produced == ArrayLength + trial.Before[^1])
                ? "array length"
                : null;
        }

        // Every element was filled with the array's own seed plus its position, so an answer of
        // exactly that is the element at the index it was handed.
        if (at >= 0 && at + 1 < shape.Arrays.Length && (pops, pushes) == (2, 1))
        {
            return trials.All(trial => trial.After[0] is { } produced &&
                produced == trial.Before[at] + trial.Before[at + 1])
                ? "reads an array element"
                : null;
        }
        return null;
    }

    /// <summary>An operation that leaves the very number it carries: a constant.</summary>
    /// <remarks>
    /// This has to be asked before the table reading, and the sowing is what makes it safe to. An
    /// operation that fetches from a table at the place its operand names answers with the number
    /// we put there, which is different in every trial and never the operand; one that pushes its
    /// operand answers with the operand, every trial alike. The two cannot both hold.
    ///
    /// Asking the other way round is what read a constant as a fetch: a table with a zero at the
    /// place a zero was expected matches by coincidence, and the coincidence repeats in every trial
    /// because the operand does not change between them. Nothing downstream survives that. Every
    /// constant in the program becomes a local nobody wrote, and the operations that use them read
    /// as working on values that were never there.
    /// </remarks>
    private static string? Carried(List<Trial> trials, long? operand) =>
        operand is { } number &&
        trials.TrueForAll(trial => trial.After.Count == 1 && trial.After[0] == number)
            ? "pushes its operand"
            : null;

    /// <summary>An operation that takes nothing but reproduces what was already on top: a copy.</summary>
    private static string? Nullary(List<Trial> trials) =>
        trials.All(trial => trial.Kept > 0 &&
            trial.After[0] is { } produced &&
            produced == trial.Before[trial.Kept - 1])
            ? "dup"
            : null;

    internal static readonly (string Name, Func<long, long> Apply)[] UnaryCandidates =
    [
        ("neg", value => -value),
        ("not", value => ~value)
    ];

    private static string? Unary(List<Trial> trials)
    {
        if (Produced(trials) is not { } output)
            return null;
        var input = trials.Select(trial => trial.Before[^1]).ToArray();

        // A value that survives unchanged means the operation altered how it is held rather than
        // what it is, which is what a conversion looks like from the outside.
        if (!input.Where((value, index) => value != output[index]).Any())
            return "convert";
        return Only(UnaryCandidates
            .Where(candidate => !input.Where((value, index) => candidate.Apply(value) != output[index]).Any())
            .Select(candidate => candidate.Name));
    }

    internal static readonly (string Name, Func<long, long, long> Apply)[] BinaryCandidates =
    [
        ("add", (left, right) => left + right),
        ("sub", (left, right) => left - right),
        ("mul", (left, right) => left * right),
        ("div", (left, right) => right == 0 ? long.MinValue : left / right),
        ("rem", (left, right) => right == 0 ? long.MinValue : left % right),
        ("and", (left, right) => left & right),
        ("or", (left, right) => left | right),
        ("xor", (left, right) => left ^ right),
        ("shl", (left, right) => left << (int)(right & 63)),
        ("shr", (left, right) => left >> (int)(right & 63)),
        ("ceq", (left, right) => left == right ? 1 : 0),
        ("cgt", (left, right) => left > right ? 1 : 0),
        ("clt", (left, right) => left < right ? 1 : 0)
    ];

    private static string? Binary(List<Trial> trials)
    {
        if (Produced(trials) is not { } output)
            return null;
        var left = trials.Select(trial => trial.Before[^2]).ToArray();
        var right = trials.Select(trial => trial.Before[^1]).ToArray();
        return Only(BinaryCandidates
            .Where(candidate =>
                !output.Where((value, index) => candidate.Apply(left[index], right[index]) != value).Any())
            .Select(candidate => candidate.Name));
    }

    /// <summary>
    /// The single value each trial produced, when every one of them can be read as a number.
    /// </summary>
    /// <remarks>
    /// An operation whose result we cannot read cannot be matched against anything, so it is left
    /// unnamed. Its stack effect is still reported, having been measured by position.
    /// </remarks>
    private static long[]? Produced(List<Trial> trials)
    {
        var produced = new long[trials.Count];
        for (var index = 0; index < trials.Count; index++)
        {
            if (trials[index].After[0] is not { } value)
                return null;
            produced[index] = value;
        }
        return produced;
    }

    /// <summary>Accepts an answer only when the trials left exactly one standing.</summary>
    private static string? Only(IEnumerable<string> candidates)
    {
        var matched = candidates.Take(2).ToArray();
        return matched.Length == 1 ? matched[0] : null;
    }

    private static bool TryMakeSlot(
        StaticMachine machine,
        ModuleDef module,
        StaticHeap heap,
        MethodDef factory,
        int value,
        bool asArray,
        string? named,
        out StaticValue slot,
        out StaticValue held)
    {
        slot = StaticValue.Null;
        held = StaticValue.Null;
        StaticValue type;
        if (named is not null)
        {
            if (!heap.TryAllocateType(named, out type) ||
                !heap.TryAllocateObject(named, out held))
            {
                return false;
            }
        }
        else if (asArray)
        {
            // Long enough that an index from an adjacent seed falls inside it, and a different
            // length in every trial, so that an operation reporting a length can be told from one
            // reporting a constant.
            var length = ArrayLength + value;
            if (!heap.TryAllocateType("System.Int32[]", out type) ||
                !heap.TryAllocateArray(module.CorLibTypes.Int32, length, out held))
            {
                return false;
            }
            for (var index = 0; index < length; index++)
                heap.TryWriteArray(held, index, StaticValue.FromInt32(value + index));
        }
        else if (!heap.TryAllocateType("System.Int32", out type) ||
                 !heap.TryAllocateBox("System.Int32", StaticValue.FromInt32(value), out held))
        {
            return false;
        }

        var made = machine.Execute(factory, [type, held]);
        if (made.Status != StaticExecutionStatus.Completed ||
            made.Value.Kind != StaticValueKind.HeapReference)
        {
            return false;
        }
        slot = made.Value;
        return true;
    }

    /// <summary>
    /// Reads the number a value on the engine's stack stands for, without knowing how it holds it.
    /// </summary>
    /// <remarks>
    /// A virtualizer keeps a value in a small record with overlapping fields, so that one storage
    /// location can be read as any width. That makes the number the one the fields agree on, and the
    /// fields that disagree with everything — the tags saying which reading is intended — the ones
    /// to ignore. It holds because the values put on the stack are small enough that every width
    /// reads the same, which is also why they are chosen small.
    /// </remarks>
    internal static bool TryReadNumber(
        StaticHeap heap,
        ModuleDef module,
        StaticValue slot,
        out long value)
    {
        value = 0;
        if (slot.Kind != StaticValueKind.HeapReference ||
            !heap.TryGetRuntimeTypeName(slot, out var typeName))
        {
            return false;
        }

        var agreed = new Dictionary<long, int>();
        foreach (var field in Fields(module, typeName))
        {
            if (!heap.TryReadField(slot, field, out var stored) ||
                stored.Kind != StaticValueKind.HeapReference ||
                !heap.TryGetRuntimeTypeName(stored, out var nested))
            {
                continue;
            }
            foreach (var inner in Fields(module, nested))
            {
                if (heap.TryReadField(stored, inner, out var held) &&
                    held.Kind is StaticValueKind.Int32 or StaticValueKind.Int64)
                {
                    agreed.TryGetValue(held.Bits, out var count);
                    agreed[held.Bits] = count + 1;
                }
            }
        }

        if (agreed.Count == 0)
            return false;
        var best = agreed.OrderByDescending(entry => entry.Value).First();
        if (best.Value < 2)
            return false;
        value = best.Key;
        return true;
    }

    /// <summary>
    /// Names the type the engine treats as a value, by what its arguments and locals are made of.
    /// </summary>
    internal static string? SlotType(StaticHeap heap, ModuleDef module, StaticValue engine)
    {
        if (!heap.TryGetRuntimeTypeName(engine, out var stateType))
            return null;
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var field in Fields(module, stateType))
        {
            if (heap.TryReadField(engine, field, out var stored) &&
                stored.Kind == StaticValueKind.HeapReference &&
                heap.TryGetArrayElementType(stored, out var element) &&
                module.Find(element, isReflectionName: false) is not null)
            {
                counts.TryGetValue(element, out var seen);
                counts[element] = seen + 1;
            }
        }
        return counts.Count == 0 ? null : counts.OrderByDescending(entry => entry.Value).First().Key;
    }

    private static MethodDef? Factory(ModuleDef module, string slotType) =>
        module.Find(slotType, isReflectionName: false)?.Methods.FirstOrDefault(method =>
            method.IsStatic &&
            method.Parameters.Count == 2 &&
            method.ReturnType.FullName == slotType &&
            method.Parameters[0].Type.FullName == "System.Type" &&
            method.Parameters[1].Type.FullName == "System.Object");

    /// <summary>The fields a type of this module declares, for walking an engine's state.</summary>
    internal static IEnumerable<FieldDef> Reachable(ModuleDef module, string typeName) =>
        Fields(module, typeName);

    internal static List<StaticValue>? FindStack(
        StaticHeap heap,
        ModuleDef module,
        StaticValue engine,
        string slotType)
    {
        var wanted = $"System.Collections.Generic.List`1<{slotType}>";
        var queue = new Queue<(StaticValue Value, int Depth)>();
        var visited = new HashSet<long>();
        queue.Enqueue((engine, 0));
        while (queue.Count > 0)
        {
            var (value, depth) = queue.Dequeue();
            if (depth > SearchDepth ||
                value.Kind != StaticValueKind.HeapReference ||
                !visited.Add(value.Bits) ||
                !heap.TryGetRuntimeTypeName(value, out var typeName))
            {
                continue;
            }
            if (typeName == wanted &&
                heap.TryGetModelValue<List<StaticValue>>(value, "Items", out var items) &&
                items is not null)
            {
                return items;
            }
            foreach (var field in Fields(module, typeName))
            {
                if (heap.TryReadField(value, field, out var stored))
                    queue.Enqueue((stored, depth + 1));
            }
        }
        return null;
    }

    /// <summary>What a value the engine stacked turns out to be, seen through its wrappers.</summary>
    /// <param name="Nothing">
    /// Whether it is nothing at all. A wrapper whose every place is empty is holding null, and
    /// that is a reading rather than a failure to read one: the operation that leaves it pushes
    /// null, which no amount of looking at the wrapper's own type would ever say.
    /// </param>
    /// <param name="Type">The name of the type it holds, where the wrapping says which.</param>
    internal readonly record struct Carriage(bool Nothing, string? Type);

    /// <summary>How many layers of the engine's wrapping to see through.</summary>
    private const int Wrapping = 4;

    /// <summary>Whether a field says what a value is rather than holding it.</summary>
    /// <remarks>
    /// An engine that stacks values of every type has to record which type each one is, and the
    /// record is not the value. Two kinds of field do that: a small number from an enum whose
    /// members were stripped, and a <see cref="Type"/> the engine kept beside the value. Reading
    /// either as the value is how a slot holding null comes to be reported as holding a number.
    /// </remarks>
    private static bool Describing(FieldDef field)
    {
        if (field.FieldType?.FullName == "System.Type")
            return true;
        var declared = field.FieldType?.ToTypeDefOrRef()?.ResolveTypeDef();
        return declared is { IsEnum: true };
    }

    /// <summary>
    /// What type a value the engine stacked really is, read out of how the engine wrapped it.
    /// </summary>
    /// <remarks>
    /// The wrapper holds a struct that lays every integer width at the same offset — a union — and
    /// the member the engine last wrote is what the value is, a distinction the heap keeps because
    /// writing one member of overlapping storage makes the others stale. So the type comes back as
    /// the name the engine's own code used when it put the value there, which is what a typed
    /// listing needs and what the stripped enum beside it cannot give.
    /// </remarks>
    internal static Carriage Carrying(
        StaticHeap heap,
        ModuleDef module,
        StaticValue value,
        int depth)
    {
        ArgumentNullException.ThrowIfNull(heap);
        ArgumentNullException.ThrowIfNull(module);
        if (depth > Wrapping)
            return new Carriage(false, null);
        switch (value.Kind)
        {
            case StaticValueKind.Null:
                return new Carriage(true, null);
            case StaticValueKind.Int32:
                return new Carriage(false, "System.Int32");
            case StaticValueKind.Int64:
                return new Carriage(false, "System.Int64");
            case StaticValueKind.Float32:
                return new Carriage(false, "System.Single");
            case StaticValueKind.Float64:
                return new Carriage(false, "System.Double");
            case StaticValueKind.HeapReference:
                break;
            default:
                return new Carriage(false, null);
        }

        if (!heap.TryGetRuntimeTypeName(value, out var held))
            return new Carriage(false, null);
        if (module.Find(held, isReflectionName: false) is not { } declared)
            return new Carriage(false, held);

        // A union says which type it holds by which of its members was last written into it.
        if (declared.IsExplicitLayout)
        {
            foreach (var member in declared.Fields)
            {
                if (!member.IsStatic && heap.TryReadAssignedField(value, member, out _))
                    return new Carriage(false, member.FieldType?.FullName);
            }
            return new Carriage(false, null);
        }

        var places = 0;
        var empty = 0;
        foreach (var field in Fields(module, held))
        {
            if (Describing(field) || !heap.TryReadField(value, field, out var within))
                continue;
            places++;
            var carried = Carrying(heap, module, within, depth + 1);
            if (carried.Type is not null)
                return carried;
            if (carried.Nothing)
                empty++;
        }
        return new Carriage(places > 0 && empty == places, null);
    }

    private static IEnumerable<FieldDef> Fields(ModuleDef module, string typeName)
    {
        for (var declaring = module.Find(typeName, isReflectionName: false);
             declaring is not null;
             declaring = declaring.BaseType?.ResolveTypeDef())
        {
            foreach (var field in declaring.Fields)
            {
                if (!field.IsStatic)
                    yield return field;
            }
        }
    }
}
