using dnlib.DotNet;
using ReactorUnpack.Core.Interpretation;

namespace ReactorUnpack.Core.Recovery;

/// <summary>What was learned about a virtualizer's operations, and what was not.</summary>
/// <param name="Operations">The ones the engine would perform on their own, by opcode.</param>
/// <param name="Declined">Why the others were left alone, in the listing's voice.</param>
/// <param name="Summary">The same in one sentence, for the log.</param>
public sealed record VirtualSemanticsReport(
    IReadOnlyDictionary<int, VirtualOperation> Operations,
    IReadOnlyList<string> Declined,
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

    /// <summary>The effect in the shortest form that is still true.</summary>
    public string Describe() => Needs is null ? Brief : $"{Brief}, wants {Needs}";

    /// <summary>The effect without what it had to be handed, short enough to sit beside a line.</summary>
    public string Brief
    {
        get
        {
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
/// Reading them out of the engine is not practical: its executor is one control-flow flattened
/// method of several thousand instructions driven by a switch over a state variable, so finding the
/// code for an operation means unflattening the obfuscator's own interpreter first. Watching the
/// program run does not work either, because a program stops early without the real inputs it was
/// compiled for, and only reaches a handful of its operations.
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
        new(new Dictionary<int, VirtualOperation>(), [], summary);

    /// <summary>Puts the refusals into the listing's voice, as a note under the operations.</summary>
    private static List<string> Wording(List<string> reasons) =>
        reasons.Count == 0
            ? []
            : new[] { string.Empty, "Nothing is said about the rest:" }
                .Concat(reasons.Select(reason => $"  {reason}"))
                .ToList();

    /// <summary>The one refusal that a differently arranged stack might answer.</summary>
    private const string WrongKind = "it wants a value of a kind we did not put on the stack";

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

    /// <summary>How a stack is laid out for a trial: which positions hold an array, not a number.</summary>
    /// <param name="Arrays">Bottom of the stack first, so the last entry is the top.</param>
    private sealed record Shape(string Needs, bool[] Arrays)
    {
        /// <summary>Whether the values are plain numbers, which is when an effect can be named.</summary>
        public bool Plain => !Arrays.Any(item => item);
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
        new("an array beneath an index and a value", [false, true, false, false])
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

        var derived = new Dictionary<int, VirtualOperation>();
        var declined = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var (opcode, example) in examples.OrderBy(entry => entry.Key))
        {
            var operand = Operand(heap, example, operandField);
            var reason = string.Empty;
            VirtualOperation? found = null;
            foreach (var shape in Shapes)
            {
                var trials = Trials(
                    machine, module, heap, dispatcher, engine, factory, stack, example, shape,
                    out var refused);
                if (trials.Count == 0)
                {
                    if (reason.Length == 0)
                        reason = refused;

                    // Rearranging the stack only answers a complaint about what is on it. An
                    // operation that reached past the end of a table, or threw, will do the same
                    // again however the values are arranged, and trying costs a run each time.
                    // Only the first refusal decides that: once an arrangement is being looked for,
                    // the wrong one failing some other way says nothing about the rest.
                    if (shape.Plain && refused != WrongKind)
                        break;
                    continue;
                }
                found = Classify(opcode, operand, trials, shape);
                if (found is not null)
                    break;
            }

            if (found is not null)
            {
                derived[opcode] = found;
                continue;
            }
            if (reason.Length == 0)
                reason = "its trials did not agree with each other";
            declined.TryGetValue(reason, out var seen);
            declined[reason] = seen + 1;
        }

        var named = derived.Values.Count(operation => operation.Name is not null);
        var summary = derived.Count == 0
            ? "The engine performed none of its operations in isolation, so none were given meaning."
            : $"{derived.Count} of {examples.Count} operation(s) were performed in isolation, " +
                $"{named} of them identified by name.";
        var reasons = declined
            .OrderByDescending(entry => entry.Value)
            .Select(entry => $"{entry.Value} because {entry.Key}")
            .ToList();
        if (reasons.Count > 0)
            summary += " The rest were left alone: " + string.Join("; ", reasons) + ".";
        return new VirtualSemanticsReport(derived, Wording(reasons), summary);
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
                ReferenceEquals(items, stack))
            {
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
        {
            if (place.Field is not null)
                heap.TryWriteField(place.Owner, place.Field, place.Value);
            else
                heap.TryWriteArray(place.Owner, place.Index, place.Value);
        }
    }

    private static long? Operand(StaticHeap heap, StaticValue operation, FieldDef? operandField)
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

    private static List<Trial> Trials(
        StaticMachine machine,
        ModuleDef module,
        StaticHeap heap,
        MethodDef dispatcher,
        StaticValue engine,
        MethodDef factory,
        List<StaticValue> stack,
        StaticValue operation,
        Shape shape,
        out string refused)
    {
        refused = string.Empty;
        var trials = new List<Trial>();
        foreach (var seeds in Seeds)
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
                        machine, module, heap, factory, seeds[position], wantsArray, out var slot,
                        out var held))
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
            var was = footprint.ToDictionary(place => place.Path, place => place.Value.Bits);
            var outcome = machine.Execute(
                dispatcher, [engine, operation], new StaticWorkBudget(TrialSteps));
            if (outcome.Status != StaticExecutionStatus.Completed)
            {
                refused = Refusal(outcome.Status, outcome.Diagnostic);
                Restore(heap, footprint);
                return [];
            }

            var moved = new HashSet<long>();
            foreach (var place in Footprint(heap, module, engine, stack))
            {
                if (!was.TryGetValue(place.Path, out var earlier) || earlier != place.Value.Bits)
                    moved.Add(place.Value.Bits);
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
            for (var index = kept; index < stack.Count; index++)
            {
                after.Add(TryReadNumber(heap, module, stack[index], out var value)
                    ? value
                    : null);
            }
            // An operation given an array, an index and a value that leaves the value in the array
            // at that index has stored it, which nothing about the stack alone would show: the
            // three values go in and none come out either way.
            var stored = arrayAt >= 0 && arrayAt + 2 < seeds.Length &&
                heap.TryReadArray(array, seeds[arrayAt + 1], out var element) &&
                element.Kind == StaticValueKind.Int32 &&
                element.Bits == seeds[arrayAt + 2];

            trials.Add(new Trial(before, after, kept, moved) { Stored = stored });
            Restore(heap, footprint);
        }
        return trials;
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
            return WrongKind;
        return "the machine could not follow it";
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

        // An operation whose operand turns up in the engine's state afterwards has jumped to it.
        // That reading comes first, because every other reading of such an operation is wrong.
        var settled = trials.All(trial => trial.Moved.Count == 0);
        if (operand is { } target && trials.Any(trial => trial.Moved.Contains(target)))
        {
            // Always taking the operand means the jump is unconditional; taking it only when the
            // values happen to satisfy something means the jump is the point of the comparison.
            var always = trials.All(trial => trial.Moved.Contains(target));
            return new VirtualOperation(opcode, pops, pushes, always ? "branch" : "branch if")
            {
                TouchesState = true,
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
                (0, 1) => Nullary(trials),
                (1, 1) => Unary(trials),
                (2, 1) => Binary(trials),
                _ => null
            };
        return new VirtualOperation(opcode, pops, pushes, name)
        {
            TouchesState = !settled,
            Needs = shape.Plain ? null : shape.Needs
        };
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

    /// <summary>An operation that takes nothing but reproduces what was already on top: a copy.</summary>
    private static string? Nullary(List<Trial> trials) =>
        trials.All(trial => trial.Kept > 0 &&
            trial.After[0] is { } produced &&
            produced == trial.Before[trial.Kept - 1])
            ? "dup"
            : null;

    private static readonly (string Name, Func<long, long> Apply)[] UnaryCandidates =
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

    private static readonly (string Name, Func<long, long, long> Apply)[] BinaryCandidates =
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
        out StaticValue slot,
        out StaticValue held)
    {
        slot = StaticValue.Null;
        held = StaticValue.Null;
        StaticValue type;
        if (asArray)
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
    private static bool TryReadNumber(
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
    private static string? SlotType(StaticHeap heap, ModuleDef module, StaticValue engine)
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

    private static List<StaticValue>? FindStack(
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
