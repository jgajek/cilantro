using System.Globalization;
using dnlib.DotNet;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Interpretation;

namespace ReactorUnpack.Core.Recovery;

/// <summary>One decoded operation of a virtualized method's program.</summary>
public sealed record VirtualInstruction(int Index, int Opcode, VirtualOperand Operand);

/// <summary>What an operation carries with it, in the form the engine decoded it to.</summary>
public abstract record VirtualOperand
{
    public sealed record None : VirtualOperand;
    public sealed record Number(long Value) : VirtualOperand
    {
        /// <summary>
        /// The type the engine boxed it as, which is the width the constant really has.
        /// </summary>
        /// <remarks>
        /// Read from the operand itself rather than from what the operation was seen doing, so it
        /// holds for the instructions no run ever reached.
        /// </remarks>
        public string? Type { get; init; }
    }
    public sealed record Text(string Value) : VirtualOperand;
    public sealed record Table(IReadOnlyList<long> Values) : VirtualOperand;
    public sealed record Other(string Description) : VirtualOperand;
}

/// <summary>A guarded region of a virtualized program, as the engine parsed it.</summary>
/// <param name="Numbers">The places it spans, in the order the engine keeps them.</param>
/// <param name="Kind">The number the engine writes to tell one sort of handler from another.</param>
/// <param name="Caught">The type it catches, where it names one.</param>
public sealed record VirtualRegion(IReadOnlyList<int> Numbers, int? Kind, string? Caught)
{
    /// <summary>
    /// The region as a line of the listing, said in the engine's own terms.
    /// </summary>
    /// <remarks>
    /// Which number is the start of the try and which the start of the handler is not something
    /// the engine says, so they are given in the order it keeps them rather than under names that
    /// would be a guess. A reader with the listing beside them can see which is which.
    /// </remarks>
    public string Describe()
    {
        var places = string.Join(", ", Numbers);
        var kind = Kind is { } number ? $", kind {number}" : string.Empty;
        var caught = Caught is null ? string.Empty : $", catching {Caught}";
        return $"over operations {places}{kind}{caught}";
    }
}

/// <summary>A virtualized method's program, as the engine itself decoded it.</summary>
public sealed record VirtualProgram(
    VirtualizedMethod Method,
    string InstructionType,
    IReadOnlyList<VirtualInstruction> Instructions)
{
    /// <summary>What each operation does, for those the engine would perform in isolation.</summary>
    public IReadOnlyDictionary<int, VirtualOperation> Operations { get; init; } =
        new Dictionary<int, VirtualOperation>();

    /// <summary>Where each branch was seen to go, by the index of the operation that jumped.</summary>
    public IReadOnlyDictionary<int, int> Targets { get; init; } = new Dictionary<int, int>();

    /// <summary>The jumping operations whose target was, every time it was watched, their operand.</summary>
    public IReadOnlySet<int> TargetIsOperand { get; init; } = new HashSet<int>();

    /// <summary>The guarded regions the engine parsed alongside the operations.</summary>
    /// <remarks>
    /// A method's exception handling is not in its operations — nothing in a stream of stack
    /// operations says where a try begins — so a listing without it is not a reading of the method
    /// but of most of it, and a body built from one would run the wrong code when anything threw.
    /// </remarks>
    public IReadOnlyList<VirtualRegion> Regions { get; init; } = [];

    /// <summary>
    /// What is known about the method's exception handling where no region was recovered.
    /// </summary>
    /// <remarks>
    /// Finding nothing and being unable to look are different answers, and a body rebuilt on the
    /// first when the second is true would be missing handlers nobody knew to look for.
    /// </remarks>
    public string? Guarding { get; init; }

    /// <summary>Why the operations that were not performed in isolation were left alone.</summary>
    /// <remarks>
    /// Saying nothing about an operation and saying nothing about why are different. The reason is
    /// what tells a reader whether the gap is in the method or in the tool.
    /// </remarks>
    public IReadOnlyList<string> Declined { get; init; } = [];

    /// <summary>What an operation leaves and takes, in the types the run found on them.</summary>
    private static string Typed(VirtualOperation operation)
    {
        var takes = operation.Popped is { } popped ? $"takes {Short(popped)}" : null;
        var leaves = operation.Pushed is { } pushed ? $"leaves {Short(pushed)}" : null;
        var said = string.Join(", ", new[] { takes, leaves }.Where(one => one is not null));
        return said.Length == 0 ? string.Empty : $" [{said}]";
    }

    /// <summary>Breaks a sentence into lines a listing can hold.</summary>
    private static IEnumerable<string> Wrapped(string said)
    {
        var line = new System.Text.StringBuilder();
        foreach (var word in said.Split(' '))
        {
            if (line.Length + word.Length + 1 > 84)
            {
                yield return line.ToString();
                line.Clear();
            }
            if (line.Length > 0)
                line.Append(' ');
            line.Append(word);
        }
        if (line.Length > 0)
            yield return line.ToString();
    }

    /// <summary>A type's name as a reader of IL would say it.</summary>
    internal static string Short(string name) => name switch
    {
        "System.Int32" => "int32",
        "System.Int64" => "int64",
        "System.Int16" => "int16",
        "System.SByte" => "int8",
        "System.Byte" => "uint8",
        "System.UInt16" => "uint16",
        "System.UInt32" => "uint32",
        "System.UInt64" => "uint64",
        "System.Single" => "float32",
        "System.Double" => "float64",
        "System.String" => "string",
        "System.Boolean" => "bool",
        "System.Char" => "char",
        "System.IntPtr" => "native int",
        _ => name
    };

    /// <summary>
    /// Writes the program out, naming anything an operand turns out to be a metadata token for.
    /// </summary>
    /// <remarks>
    /// Resolved tokens are most of what makes the listing worth reading: they say which methods,
    /// fields, and types the hidden code touches, which is the question an analyst brings to a
    /// virtualized method even before knowing what its operations mean.
    /// </remarks>
    public IEnumerable<string> Render(ModuleDef module)
    {
        ArgumentNullException.ThrowIfNull(module);
        yield return $"; {Method.Stub.FullName}";
        yield return $"; program {Method.ProgramId} of " +
            $"{Method.Entry.DeclaringType?.Name}::{Method.Entry.Name}, " +
            $"{Instructions.Count} operations";
        if (Operations.Count > 0)
        {
            yield return ";";
            yield return "; The operation numbers below are this build's own and mean nothing in " +
                "another. What";
            yield return "; each one does was established two ways: by having the engine perform " +
                "it on values";
            yield return "; chosen for the purpose, and by watching what it did to the stack while " +
                "the program";
            yield return "; really ran. An effect is named only where one candidate was left " +
                "standing.";
            yield return ";";
            foreach (var operation in Operations.Values.OrderBy(item => item.Opcode))
                yield return $";   op {operation.Opcode,4}  {operation.Describe()}{Typed(operation)}";
            foreach (var line in Declined)
                yield return $"; {line}".TrimEnd();
            if (Targets.Count > 0)
            {
                yield return ";";
                yield return "; Where an operation was watched jumping, -> marks where it went. " +
                    "One run takes one";
                yield return "; path, so most jumps are never watched; ~> marks one read off the " +
                    "operation itself,";
                yield return "; which is how every watched jump of that kind turned out to have " +
                    "been decided.";
            }
        }

        // Said whether or not any operation was named: what a method guards is a fact about the
        // method rather than about how well its operations were read.
        if (Regions.Count > 0)
        {
            yield return ";";
            yield return $"; The engine also parsed {Regions.Count} guarded region(s), which are " +
                "no part of the";
            yield return "; operations and would be invisible in a reading of them alone:";
            foreach (var region in Regions)
                yield return $";   {region.Describe()}";
        }
        else if (Guarding is { } said)
        {
            yield return ";";
            foreach (var line in Wrapped(said))
                yield return $"; {line}";
        }
        yield return string.Empty;
        foreach (var instruction in Instructions)
        {
            // The short form goes beside every operation, because what an operation insisted on
            // being handed is said once in the header rather than three thousand times here.
            var effect = Operations.TryGetValue(instruction.Opcode, out var known)
                ? $" {known.Brief,-18}"
                : new string(' ', 19);
            var went = Targets.TryGetValue(instruction.Index, out var target)
                ? $"   -> {target}"
                : TargetIsOperand.Contains(instruction.Opcode) &&
                    instruction.Operand is VirtualOperand.Number number &&
                    number.Value >= 0 && number.Value < Instructions.Count
                        ? $"   ~> {number.Value}"
                        : string.Empty;
            yield return ($"{instruction.Index,6}: op {instruction.Opcode,4}{effect} " +
                Describe(instruction.Operand, module) + went).TrimEnd();
        }
    }

    private static string Describe(VirtualOperand operand, ModuleDef module) => operand switch
    {
        VirtualOperand.None => string.Empty,
        VirtualOperand.Number number => $"{number.Value}{Named(number.Value, module)}",
        VirtualOperand.Text text => $"\"{text.Value.Replace("\"", "\\\"", StringComparison.Ordinal)}\"",
        VirtualOperand.Table table => $"[{string.Join(", ", table.Values)}]",
        VirtualOperand.Other other => other.Description,
        _ => "?"
    };

    private static string Named(long value, ModuleDef module)
    {
        if (value is < int.MinValue or > int.MaxValue)
            return string.Empty;
        var token = (int)value;
        if ((token >>> 24) is not (0x01 or 0x02 or 0x04 or 0x06 or 0x0A or 0x0B or 0x1B))
            return string.Empty;
        try
        {
            return module.ResolveToken(token) is { } resolved ? $"   ; {resolved}" : string.Empty;
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            return string.Empty;
        }
    }
}

/// <summary>
/// Recovers a virtualized method's program by letting the engine decode it under interpretation.
/// </summary>
/// <remarks>
/// A virtualizer's bytecode is encrypted, position-dependent, and framed however that build felt
/// like framing it, so writing a parser for it means writing one per engine and rewriting it each
/// time the engine changes. The module already contains a parser that is exactly right, and the
/// machine can run it: entering the stub makes the engine decode its own program into ordinary
/// objects on our heap, where the whole of it can be read off. Nothing about the encoding has to be
/// known, and nothing learned here is specific to one engine.
///
/// What is read back is the decoded program and not a trace of one run. The engine decodes the
/// program in full before executing any of it, so the list is complete the first time an operation
/// executes, and that is the moment it is taken. Operations never reached by this particular run
/// are present all the same.
///
/// The engine is never asked to finish. The stub is entered with empty arguments and the run is
/// allowed to fail however it likes, because by then the program has already been decoded. That is
/// deliberate: the hidden code is malware, and the less of it that runs even under interpretation,
/// the smaller the surface for it to notice or exploit.
/// </remarks>
public static class VirtualProgramRecovery
{
    private const int DecodeSteps = 32_000_000;

    /// <summary>How far to search outward from the engine's state for its decoded program.</summary>
    private const int SearchDepth = 4;

    /// <summary>
    /// How much of the program a run must reach before it counts as having got somewhere.
    /// </summary>
    /// <remarks>
    /// Entering again from elsewhere costs another interpretation of the loader, so it is only
    /// worth it for a run that stopped almost immediately, which is what a program reading its
    /// arguments does when handed none.
    /// </remarks>
    private const int StalledShare = 20;

    /// <summary>How many call sites to try before settling for the run we have.</summary>
    private const int CallersTried = 2;

    /// <summary>How many watched jumps of a kind must agree before the rest are read the same way.</summary>
    private const int AgreementsNeeded = 3;

    public static VirtualProgram? Recover(
        ArtifactContext context,
        VirtualizedMethod method,
        out string diagnostic)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(method);

        var attempt = Enter(context, method, method.Stub, out diagnostic);
        if (attempt is null)
            return null;

        // Entering the stub hands it arguments that carry no information, and a program whose first
        // act is to read what it was given stops almost at once. Its own caller has the real ones,
        // so when the run goes nowhere the call site is entered instead and the engine is watched
        // rather than questioned: an operation performed in isolation cannot jump anywhere, but one
        // performed in the middle of a real run moves the engine to somewhere that can be checked.
        var flow = new VirtualRun(0, new Dictionary<int, (int, int)>(),
            new Dictionary<int, int>(), new Dictionary<int, VirtualOperation>(),
            new Dictionary<int, IReadOnlyList<string>>());
        var stalled = attempt.Performed * StalledShare < attempt.Program.Count;
        var roots = stalled
            ? Callers(context.Module, method.Stub).Take(CallersTried)
            : [method.Stub];
        Watched? watched = null;
        foreach (var root in roots)
        {
            if (Watch(context, root, attempt) is { } one)
            {
                watched = one;
                flow = one.Run;
                if (flow.Learned)
                    break;
            }
        }

        var operandField = OperandField(
            context.Module, attempt.OpcodeField, attempt.InstructionType);
        var probed = VirtualSemantics.Probe(
            attempt.Machine, context.Module, attempt.Dispatcher, attempt.Engine, attempt.OpcodeField,
            operandField, attempt.Program);
        probed = Again(context, attempt, watched, operandField, probed);

        // How far the engine got before the run stopped is worth saying: the state left behind is
        // what the operations are asked their meaning in, and an engine that stopped at its first
        // operation leaves a poorer one than one that ran most of the program.
        var operations = Merge(probed.Operations, flow, attempt.Decoded);
        var byOperand = Rules(attempt.Decoded, flow);
        var refused = probed.Refused
            .Where(entry => !operations.TryGetValue(entry.Key, out var known) || !known.Measured)
            .ToDictionary(entry => entry.Key, entry => entry.Value);
        diagnostic = $"The engine decoded {attempt.Decoded.Count} operation(s) of program " +
            $"{method.ProgramId}, read back from its own " +
            $"{attempt.InstructionType.Split('/')[^1]} list. It performed {attempt.Performed} of " +
            $"them before stopping. " + probed.Summary + " " + Say(flow);
        var program = new VirtualProgram(method, attempt.InstructionType, attempt.Decoded)
        {
            Operations = operations,
            Targets = flow.Targets,
            TargetIsOperand = byOperand
        };

        // An operation read from what the program forces on it and what its operand names is read,
        // however the trials fared with it, so the refusals are counted last.
        var regions = Regions(
            (watched?.Machine ?? attempt.Machine).State.Heap,
            context.Module,
            attempt.Decoded.Count,
            out var shapedTypes,
            out var made);
        var guarding = shapedTypes == 0
            ? "The engine has no class shaped like an exception clause, so whether the method " +
                "guards anything could not be established."
            : regions.Count > 0
                ? null
                : made == 0
                    ? $"The engine has {shapedTypes} class(es) shaped like an exception clause and " +
                        "made none of them while running this program, so nothing in this method " +
                        "is guarded."
                    : $"The engine made {made} object(s) shaped like an exception clause while " +
                        "running this program, none of them naming places in it, so they are " +
                        "something else of the engine's and nothing here is known to be guarded.";
        var settled = Settled(program, context.Module);
        var left = refused
            .Where(entry => !settled.TryGetValue(entry.Key, out var known) || !known.Identified)
            .ToDictionary(entry => entry.Key, entry => entry.Value);
        return program with
        {
            Regions = regions,
            Guarding = guarding,
            Operations = settled,
            Declined = VirtualSemantics.Wording(VirtualSemantics.Counted(left))
        };
    }

    /// <summary>
    /// The guarded regions the engine parsed, found by their shape rather than by any name.
    /// </summary>
    /// <remarks>
    /// A clause has to say four things — where the guarded part starts and ends, where the handler
    /// starts and ends — and it has to say what is caught, so a class with several whole numbers
    /// and a type in it is what one looks like from outside. That shape alone would catch other
    /// things too, which is why the numbers are then checked against the program: a clause whose
    /// places are not places in this program is not this program's clause, and nothing is claimed.
    /// </remarks>
    private static List<VirtualRegion> Regions(
        StaticHeap heap,
        ModuleDef module,
        int operations,
        out int shapedTypes,
        out int made)
    {
        made = 0;
        shapedTypes = 0;
        var shaped = module.GetTypes()
            .Where(type => type.Fields.Count(field =>
                    !field.IsStatic && field.FieldType?.FullName == "System.Int32") >= Places &&
                type.Fields.Any(field =>
                    !field.IsStatic && field.FieldType?.FullName == "System.Type"))
            .Select(type => type.FullName)
            .ToHashSet(StringComparer.Ordinal);
        shapedTypes = shaped.Count;
        if (shaped.Count == 0)
            return [];

        var found = new List<VirtualRegion>();
        made = 0;
        foreach (var value in heap.Instances())
        {
            if (!heap.TryGetRuntimeTypeName(value, out var typeName) || !shaped.Contains(typeName))
                continue;
            made++;
            if (Region(heap, module, value, operations) is { } region)
                found.Add(region);
        }
        return found;
    }

    /// <summary>A value read as a clause, where it has the shape of one and the places to match.</summary>
    private static VirtualRegion? Region(
        StaticHeap heap,
        ModuleDef module,
        StaticValue value,
        int operations)
    {
        if (!heap.TryGetRuntimeTypeName(value, out var typeName) ||
            module.Find(typeName, isReflectionName: false) is not { } declared)
        {
            return null;
        }

        var numbers = new List<int>();
        int? kind = null;
        string? caught = null;
        var typed = false;
        foreach (var field in declared.Fields)
        {
            if (field.IsStatic || !heap.TryReadAssignedField(value, field, out var stored))
                continue;
            switch (field.FieldType?.FullName)
            {
                case "System.Int32" when stored.Kind == StaticValueKind.Int32:
                    numbers.Add((int)stored.Bits);
                    break;
                case "System.Byte" when stored.Kind == StaticValueKind.Int32:
                    kind ??= (int)stored.Bits;
                    break;
                case "System.Type":
                    typed = true;
                    caught ??= heap.TryGetModelValue<string>(stored, "Name", out var named)
                        ? named
                        : null;
                    break;
                default:
                    break;
            }
        }

        // Four places and a type is a clause; anything less is some other object of the engine's
        // that happens to hold numbers, and the numbers have to be places in this program besides.
        return typed && numbers.Count >= Places &&
            numbers.TrueForAll(one => one >= 0 && one <= operations)
                ? new VirtualRegion(numbers, kind, caught)
                : null;
    }

    /// <summary>How many places a clause has to name to be read as one.</summary>
    private const int Places = 4;

    /// <summary>
    /// Takes what the program forces on an operation together with what its operand names.
    /// </summary>
    /// <remarks>
    /// Neither half is a reading on its own. That an operation takes one value and leaves none says
    /// nothing about where the value went, and that its operand names a static field says nothing
    /// about what it does with the field — an operation could as easily be reading it. Put
    /// together, with every other reading of the operation already ruled out, there is one thing
    /// left for it to be, and it is the counterpart of an operation the run watched doing the
    /// opposite. The name is the same one watching would have produced, because it is the same
    /// claim.
    /// </remarks>
    internal static Dictionary<int, VirtualOperation> Settled(
        VirtualProgram program,
        ModuleDef module)
    {
        var forced = VirtualLift.Solve(program, module);
        var operations = program.Operations.ToDictionary(entry => entry.Key, entry => entry.Value);

        // Every operation the program uses gets a line, even where that line says nothing. An
        // operation the trials refused and the watching never reached had been appearing in the
        // body of the listing while the table above it made no mention of it, which reads as though
        // the table were complete and the operation ordinary.
        foreach (var instruction in program.Instructions)
        {
            operations.TryAdd(
                instruction.Opcode,
                new VirtualOperation(instruction.Opcode, 0, 0, null)
                {
                    Measured = false,
                    Unmeasured = "nothing asked it and nothing watched it"
                });
        }
        foreach (var (opcode, net) in forced)
        {
            if (!operations.TryGetValue(opcode, out var operation))
                operation = new VirtualOperation(opcode, 0, 0, null) { Measured = false };
            operations[opcode] = operation with { Net = net };
        }

        foreach (var (opcode, operation) in operations)
        {
            var takes = operation.Measured
                ? operation is { Pops: > 0, Pushes: 0 }
                : operation.Net == -1;
            if (operation.Identified || !takes || !Fields(program, module, opcode))
                continue;
            operations[opcode] = operation with { Name = "writes the static field it names" };
        }

        foreach (var (opcode, operation) in operations)
        {
            if (Arguments(program, operation) is { } named)
                operations[opcode] = operation with { Name = named };
        }
        return operations;
    }

    /// <summary>
    /// Whether an operation that reaches into a table of the engine's reaches into the arguments.
    /// </summary>
    /// <remarks>
    /// Nothing about a table says what it is for, and an engine keeps the arguments of the method
    /// it is running in one just like its locals. What tells them apart is the method itself: its
    /// arguments are as many as it declares, so a table of exactly that length, never reached past
    /// the last of them, is the one holding them. A locals table of the same length would be
    /// reached past the moment the method had a local it did not have an argument for, and where
    /// it is not, the two are the same table as far as anything here can tell — so nothing more is
    /// claimed than the length supports.
    /// </remarks>
    private static string? Arguments(VirtualProgram program, VirtualOperation operation)
    {
        var wanted = operation.Name switch
        {
            "loads what its operand indexes" => "loads the argument it indexes",
            "stores where its operand indexes" => "stores into the argument it indexes",
            _ => null
        };
        if (wanted is null || operation.Holding is not { } length)
            return null;

        var declared = program.Method.Stub.Parameters.Count;
        if (declared == 0 || length != declared)
            return null;
        var reached = program.Instructions
            .Where(one => one.Opcode == operation.Opcode)
            .Select(one => one.Operand as VirtualOperand.Number)
            .ToList();
        return reached.Count > 0 &&
            reached.TrueForAll(number => number is not null && number.Value >= 0 &&
                number.Value < declared)
                ? wanted
                : null;
    }

    /// <summary>Whether every operation of a kind carries the token of a static field.</summary>
    private static bool Fields(VirtualProgram program, ModuleDef module, int opcode)
    {
        var carried = program.Instructions.Where(one => one.Opcode == opcode).ToList();
        return carried.Count > 0 && carried.TrueForAll(one =>
            one.Operand is VirtualOperand.Number number &&
            number.Value is >= int.MinValue and <= int.MaxValue &&
            Field(module, (int)number.Value) is { IsStatic: true });
    }

    private static FieldDef? Field(ModuleDef module, int token)
    {
        try
        {
            return (module.ResolveToken(token) as IField)?.ResolveFieldDef();
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>
    /// Asks the operations nothing settled a second time, in the engine a real run left behind.
    /// </summary>
    /// <remarks>
    /// The two ways of asking fail for opposite reasons and the failures do not overlap. A cold
    /// engine can be arranged however the questioning likes but has none of what the program would
    /// have prepared, so an operation that reaches for a table or a resolved member cannot be
    /// performed at all. A real run has all of it but goes one way through the program, so it never
    /// performs the operations on the paths it did not take. Asking the second way in the state the
    /// first way produced has neither limit: the tables are full, the members are resolved, and the
    /// operation is still performed on values chosen to tell its effect apart from its neighbours'.
    ///
    /// Only what is still unsettled is asked again, and an answer is only taken where the first way
    /// had none. A cold engine is the more controlled of the two, so where both answer, the
    /// controlled answer stands.
    /// </remarks>
    private static VirtualSemanticsReport Again(
        ArtifactContext context,
        Attempt attempt,
        Watched? watched,
        FieldDef? operandField,
        VirtualSemanticsReport first)
    {
        if (watched is null || watched.Program.Count == 0)
            return first;
        var wanted = first.Operations
            .Where(entry => !entry.Value.Identified || !entry.Value.Measured)
            .Select(entry => entry.Key)
            .Concat(first.Refused.Keys)
            .ToHashSet();
        if (wanted.Count == 0)
            return first;

        // Only one instruction of each kind is worth asking about, and asking about the rest costs
        // a run of the engine each.
        var asked = new List<StaticValue>();
        var seen = new HashSet<int>();
        foreach (var operation in watched.Program)
        {
            // The run that was watched has a heap of its own, and these are its objects. Reading
            // them out of the first run's heap asks a different heap what is at the same address.
            if (watched.Machine.State.Heap.TryReadField(
                    operation, attempt.OpcodeField, out var code) &&
                code.Kind == StaticValueKind.Int32 &&
                wanted.Contains((int)code.Bits) && seen.Add((int)code.Bits))
            {
                asked.Add(operation);
            }
        }
        if (asked.Count == 0)
            return first;

        var second = VirtualSemantics.Probe(
            watched.Machine, context.Module, attempt.Dispatcher, watched.Engine,
            attempt.OpcodeField, operandField, asked);
        var operations = first.Operations.ToDictionary(entry => entry.Key, entry => entry.Value);
        var refused = first.Refused.ToDictionary(entry => entry.Key, entry => entry.Value);
        var gained = 0;
        foreach (var (opcode, answer) in second.Operations)
        {
            if (operations.TryGetValue(opcode, out var known) &&
                (known.Identified || !answer.Identified && known.Measured))
            {
                continue;
            }
            operations[opcode] = answer;
            refused.Remove(opcode);
            gained++;
        }
        // Where the second asking failed too, its refusal is the one worth reporting: it was made
        // in the state the operation was written for, so what it says is missing really is missing.
        foreach (var (opcode, why) in second.Refused)
        {
            if (!operations.TryGetValue(opcode, out var known) || !known.Identified)
                refused[opcode] = why;
        }
        var summary = first.Summary +
            $" {asked.Count} of them were asked again in the engine a real run left behind, " +
            $"which answered {gained}.";
        return new VirtualSemanticsReport(operations, refused, summary);
    }

    /// <summary>
    /// The jumping operations whose watched targets were, every time, the number they carry.
    /// </summary>
    /// <remarks>
    /// One run takes one path through a program, so most of its jumps are never watched. Where
    /// every watched jump of a kind went to that operation's own operand, the ones that were not
    /// watched can be read the same way — and the rule is only adopted for a kind seen jumping
    /// several times, and abandoned entirely if a single sighting disagrees.
    /// </remarks>
    private static HashSet<int> Rules(
        List<VirtualInstruction> decoded,
        VirtualRun flow)
    {
        var agreed = new Dictionary<int, int>();
        var broken = new HashSet<int>();
        foreach (var (index, target) in flow.Targets)
        {
            if (index >= decoded.Count)
                continue;
            var instruction = decoded[index];
            if (instruction.Operand is VirtualOperand.Number number && number.Value == target)
            {
                agreed.TryGetValue(instruction.Opcode, out var seen);
                agreed[instruction.Opcode] = seen + 1;
            }
            else
            {
                broken.Add(instruction.Opcode);
            }
        }
        return agreed
            .Where(entry => entry.Value >= AgreementsNeeded && !broken.Contains(entry.Key))
            .Select(entry => entry.Key)
            .ToHashSet();
    }

    /// <summary>Adds what watching the engine run showed to what questioning it showed.</summary>
    /// <remarks>
    /// Watching wins where the two disagree. An operation that jumps looks like one that consumes
    /// its values and does nothing when it is performed with the engine standing still, and that
    /// reading is not merely incomplete but misleading.
    /// </remarks>
    private static Dictionary<int, VirtualOperation> Merge(
        IReadOnlyDictionary<int, VirtualOperation> probed,
        VirtualRun flow,
        List<VirtualInstruction> decoded)
    {
        var merged = probed.ToDictionary(entry => entry.Key, entry => entry.Value);

        // An operation the trials could not perform may have been performed by the program itself,
        // and one they could is left as it was: chosen values vary in ways a real run does not.
        foreach (var (opcode, watched) in flow.Effects)
        {
            if (!merged.TryGetValue(opcode, out var known))
                merged[opcode] = watched;
            else
            {
                merged[opcode] = known with
                {
                    Name = known.Name ?? watched.Name,
                    Computes = watched.Computes,
                    Holding = known.Holding ?? watched.Holding,
                    Pushed = known.Pushed ?? watched.Pushed,
                    Popped = known.Popped ?? watched.Popped
                };
            }
        }

        foreach (var (opcode, counted) in flow.Jumps)
        {
            // An operation watched jumping only once is not called a jump on that alone, since one
            // that happened to be taken and one always taken look alike from a single sighting. But
            // an operation that also consumed values decided something with them, and the reading
            // that keeps both ways out of it open is the one that cannot mislead.
            var name = flow.Describe(opcode);
            if (name is null && counted.Taken > 0 &&
                merged.TryGetValue(opcode, out var performed) && performed.Pops > 0)
            {
                name = "branch if";
            }
            if (name is null)
                continue;
            merged.TryGetValue(opcode, out var known);

            // A single sighting overturns nothing that was measured. A program entered twice puts
            // its last operation next to its first, and an engine that leaves and comes back does
            // the same, so one operation not followed by the next is as likely a seam in the
            // watching as a jump. Where the operation was read some other way — a store into the
            // table its operand indexes, say, established by performing it and watching it — that
            // reading was arrived at from what it did, and one crossing is no answer to it.
            if (known?.Name is not null && counted.Taken < 2)
                continue;
            merged[opcode] = known is not null
                ? known with { Name = name, TouchesState = true }
                : new VirtualOperation(opcode, 0, 0, name) { TouchesState = true };
        }

        Reaching(merged);
        Stopping(merged);
        Switching(merged, decoded);
        Deciding(merged, decoded);
        Discarding(merged, flow);

        // The last resort, taken only where the run and the trials both had nothing better: an
        // operation that pushes something is at least pushing something of a particular kind.
        foreach (var (opcode, operation) in merged)
        {
            if (operation is { Name: null, Leaving: { } kind })
                merged[opcode] = operation with { Name = kind };
        }
        return merged;
    }

    /// <summary>
    /// Names the operation that goes where its own operand says, where nothing watched it go.
    /// </summary>
    /// <remarks>
    /// The trials record which of the engine's places were handed the number an operation carries.
    /// One of those places is where the engine keeps its position, which the operations already
    /// named as jumps give away, and an operation that puts its operand there has gone there. Every
    /// other place that took the same number took it by coincidence — an index that happened to
    /// match, a value that happened to be one less — which is why the number alone will not do and
    /// the place has to be named.
    ///
    /// A jump that takes nothing off the stack has nothing to decide with, so it always goes. One
    /// that takes something decides with it, and is called conditional even where every trial saw
    /// it go, since the values the trials use stand in the same order every time.
    /// </remarks>
    private static void Reaching(Dictionary<int, VirtualOperation> merged)
    {
        var position = Position(merged);
        if (position.Count == 0)
            return;

        foreach (var (opcode, operation) in merged)
        {
            if (operation.Name is not null ||
                operation.Reached?.Any(position.Contains) != true)
            {
                continue;
            }
            merged[opcode] = operation with
            {
                Name = operation.Pops > 0 ? "branch if" : "branch",
                TouchesState = true
            };
        }
    }

    /// <summary>
    /// Names the operation that ends the method, by where the jumps showed the position is kept.
    /// </summary>
    /// <remarks>
    /// The jumps give away where the engine keeps its position, being the operations that write it.
    /// An operation that writes the same place a fixed number that is no part of the program is
    /// therefore not going anywhere in it, which is what returning looks like from outside; and if
    /// it also puts what it took somewhere, that is the value it returns. Neither reading is
    /// available to the stack alone, which sees only a value consumed.
    /// </remarks>
    private static void Stopping(Dictionary<int, VirtualOperation> merged)
    {
        var position = Position(merged);
        if (position.Count == 0)
            return;

        foreach (var (opcode, operation) in merged)
        {
            if (operation.Name is not null || operation.Changes is not { } changes)
                continue;
            var moved = changes.FirstOrDefault(written =>
                position.Contains(written.Split('=')[0]) &&
                written.Contains('=', StringComparison.Ordinal));
            if (moved is null || moved.EndsWith("=what it took", StringComparison.Ordinal))
                continue;
            var kept = changes.Any(written =>
                written.EndsWith("=what it took", StringComparison.Ordinal));
            merged[opcode] = operation with
            {
                Name = kept && operation.Pops > 0
                    ? "returns the value it takes"
                    : "stops the program"
            };
        }
    }

    /// <summary>Where the engine keeps its position, as given away by the jumps that write it.</summary>
    private static HashSet<string> Position(Dictionary<int, VirtualOperation> merged) =>
        merged.Values
            .Where(operation => operation.Name is "branch" or "branch if")
            .SelectMany(operation => operation.Changes ?? [])
            .Select(written => written.Split('=')[0])
            .ToHashSet(StringComparer.Ordinal);

    /// <summary>
    /// Names the operation that jumps to whichever of its many places a value chooses.
    /// </summary>
    /// <remarks>
    /// This is the one operation a flattened program cannot be read without. Its blocks are laid out
    /// in no order and each ends by handing a number back to a single dispatching operation, so a
    /// reading that does not know where that operation goes reaches the first block and no further
    /// — which in the sample here was two operations in five, the rest sitting there looking dead.
    ///
    /// It is not named a branch by the trials, and rightly: it takes a value, and every jump they
    /// could name goes to the one place its operand gives. What identifies it is that it writes the
    /// place the jumps write, that it consumes something to decide what to write there, and that
    /// everywhere it appears it carries a whole table of positions rather than one. Nothing else in
    /// a program has all three.
    /// </remarks>
    private static void Switching(
        Dictionary<int, VirtualOperation> merged,
        IReadOnlyList<VirtualInstruction> decoded)
    {
        var position = Position(merged);
        if (position.Count == 0)
            return;
        var tabled = decoded
            .GroupBy(instruction => instruction.Opcode)
            .Where(group => group.All(one => one.Operand is VirtualOperand.Table))
            .Select(group => group.Key)
            .ToHashSet();

        foreach (var (opcode, operation) in merged)
        {
            if (operation.Name is not null || operation.Pops < 1 || !tabled.Contains(opcode))
                continue;
            var moved = operation.Changes?.Any(written =>
                position.Contains(written.Split('=')[0])) ?? false;
            if (moved)
                merged[opcode] = operation with { Name = "branch by table", TouchesState = true };
        }
    }

    /// <summary>
    /// Names the operation that takes a value to decide whether to go somewhere, where the times it
    /// was watched it decided not to.
    /// </summary>
    /// <remarks>
    /// A conditional branch not taken is indistinguishable, from the outside, from a value thrown
    /// away: the value goes, the position does not move, and nothing else happens. So the reading
    /// that a value was discarded is arrived at honestly and is still wrong, and it is wrong in the
    /// way that costs most, since it severs every block the branch reaches.
    ///
    /// Three things together tell them apart, and no two of them would. The operation carries an
    /// operand, and a value thrown away needs none. Everywhere it appears that operand is a
    /// position in this program rather than an index into anything, which is what a jump's operand
    /// is and what nothing else's is. And the engine was watched comparing something while
    /// performing it, which is what a jump is conditional on and what discarding a value has no use
    /// for. Whether the reading is right is then put to the walk: a jump invented where there is
    /// none lands the stack at a depth the other ways in contradict.
    /// </remarks>
    private static void Deciding(
        Dictionary<int, VirtualOperation> merged,
        List<VirtualInstruction> decoded)
    {
        var placed = decoded
            .GroupBy(instruction => instruction.Opcode)
            .Where(group => group.All(one =>
                one.Operand is VirtualOperand.Number number &&
                number.Value >= 0 &&
                number.Value < decoded.Count))
            .Select(group => group.Key)
            .ToHashSet();

        foreach (var (opcode, operation) in merged)
        {
            if (operation is not { Name: null, Measured: true, Pushes: 0 } ||
                operation.Pops < 1 ||
                !placed.Contains(opcode) ||
                operation.Computes?.Any(Compares) != true)
            {
                continue;
            }
            merged[opcode] = operation with { Name = "branch if", TouchesState = true };
        }
    }

    /// <summary>Whether a piece of the engine's working is it comparing two things.</summary>
    private static bool Compares(string working)
    {
        var did = working.Split(' ')[0];
        if (did.EndsWith(".s", StringComparison.Ordinal))
            did = did[..^2];
        if (did.EndsWith(".un", StringComparison.Ordinal))
            did = did[..^3];
        return did is "ceq" or "cgt" or "clt" or "beq" or "bne" or "bgt" or "blt" or "bge" or "ble"
            or "brtrue" or "brfalse";
    }

    /// <summary>
    /// Names the operations that leave nothing behind, which is what is left when nothing kept it.
    /// </summary>
    /// <remarks>
    /// The trials decline this reading on their own, and rightly: an operation that consumed a
    /// value and showed nothing else might have written it somewhere they cannot see. Between the
    /// two readings there is nowhere left for it to have gone. The trials watch everything the
    /// engine can reach and saw nothing change; the run watches the handler execute and never saw
    /// it write a static field, which is the one place outside the engine it could have put
    /// anything. An operation that takes a value, leaves nothing, and touches neither has discarded
    /// it — and one that takes nothing either has done nothing at all, which a program full of
    /// jumps to fixed places has every reason to contain.
    /// </remarks>
    private static void Discarding(Dictionary<int, VirtualOperation> merged, VirtualRun flow)
    {
        foreach (var (opcode, operation) in merged)
        {
            var watched = flow.Effects.ContainsKey(opcode) || flow.Computed.ContainsKey(opcode);
            if (operation is { Name: null, Measured: true, Pushes: 0, TouchesState: false } &&
                watched && !flow.Stores.Contains(opcode))
            {
                merged[opcode] = operation with
                {
                    Name = operation.Pops > 0 ? "discards what it takes" : "does nothing at all"
                };
            }
        }
    }

    private static string Say(VirtualRun flow)
    {
        if (!flow.Learned)
            return "It was not watched running for long enough to see where it goes.";
        var jumping = flow.Jumps.Count(entry => entry.Value.Taken > 0);
        var named = flow.Effects.Values.Count(effect => effect.Name is not null);
        return $"Watching {flow.Watched} operation(s) run measured {flow.Effects.Count} of them, " +
            $"{named} by name, read the working of {flow.Computed.Count}, and showed {jumping} " +
            $"jumping to {flow.Targets.Count} target(s).";
    }

    /// <summary>
    /// Runs the engine again with the watcher attached, using the dispatcher already identified,
    /// since which method performs an operation is not known until a run has been watched once.
    /// Where the first run went nowhere the call site is entered instead, its arguments being the
    /// ones the program itself supplies rather than the nothing the stub was handed.
    /// </summary>
    private static Watched? Watch(
        ArtifactContext context,
        MethodDef root,
        Attempt known)
    {
        if (!BootstrapMachine.TryRunInitializers(context, DecodeSteps, out var machine, out _) ||
            machine is null || !TryBuildArguments(machine, root, out var arguments))
        {
            return null;
        }

        var watcher = new VirtualRunWatcher(
            context.Module, machine.State, known.Dispatcher, known.OpcodeField,
            OperandField(context.Module, known.OpcodeField, known.InstructionType),
            known.InstructionType);
        machine.FrameEntered = watcher.Entered;
        machine.FrameExited = watcher.Exited;
        machine.Stepped = watcher.Stepped;
        machine.Execute(root, arguments);
        machine.FrameEntered = null;
        machine.FrameExited = null;
        machine.Stepped = null;
        return new Watched(watcher.Result(), machine, watcher.Engine, watcher.Program);
    }

    /// <summary>
    /// A run of the program and the engine it left behind, which is worth more than the run.
    /// </summary>
    /// <remarks>
    /// An operation asked its meaning in a cold engine is asked in a state the program never
    /// actually put it in: the tables are empty, nothing has been resolved, and a handler that
    /// reaches for any of it faults or answers wrongly. The engine a real run leaves is the one the
    /// operations were written for, so it is kept rather than discarded with the machine.
    /// </remarks>
    private sealed record Watched(
        VirtualRun Run,
        StaticMachine Machine,
        StaticValue Engine,
        List<StaticValue> Program);

    /// <summary>What one run of the engine left behind, and the program it decoded on the way.</summary>
    private sealed record Attempt(
        MethodDef Root,
        StaticMachine Machine,
        MethodDef Dispatcher,
        StaticValue Engine,
        FieldDef OpcodeField,
        string InstructionType,
        List<StaticValue> Program,
        List<VirtualInstruction> Decoded,
        int Performed);

    /// <summary>
    /// Runs the engine from one entry point and reads back the program it decoded.
    /// </summary>
    private static Attempt? Enter(
        ArtifactContext context,
        VirtualizedMethod method,
        MethodDef root,
        out string diagnostic)
    {
        if (!BootstrapMachine.TryRunInitializers(context, DecodeSteps, out var machine, out var seed) ||
            machine is null)
        {
            diagnostic = $"The loader could not be interpreted, so the engine never ran: {seed}.";
            return null;
        }

        // Which method the engine executes operations with is not known, so every frame is a
        // candidate and the one that turns out to hold a list of what it was passed is the answer.
        var candidates = new Dictionary<MethodDef, (int Count, IReadOnlyList<StaticValue> First)>();
        machine.FrameEntered = (entered, arguments) =>
        {
            if (arguments.Count < 2)
                return;
            if (candidates.TryGetValue(entered, out var running))
                candidates[entered] = (running.Count + 1, running.First);
            else
                candidates[entered] = (1, arguments);
        };

        if (!TryBuildArguments(machine, root, out var arguments))
        {
            diagnostic = "The arguments could not be built, so the engine was not entered.";
            return null;
        }
        var ran = machine.Execute(root, arguments);
        machine.FrameEntered = null;

        var heap = machine.State.Heap;

        // Why each frame was set aside is worth keeping. Every one of them is a guess and nearly
        // all are wrong, but on a build where none is right the reasons are the whole of what is
        // known about the engine, and "the container was not found" is not a place to start from.
        var aside = new List<string>();
        foreach (var candidate in candidates.OrderByDescending(entry => entry.Value.Count))
        {
            var entered = candidate.Value.First;
            var frame = candidate.Key.Name.String;
            if (!heap.TryGetRuntimeTypeName(Safely(entered[^1]), out var instructionType))
            {
                aside.Add($"{frame} was passed nothing whose type could be read");
                continue;
            }
            if (context.Module.Find(instructionType, isReflectionName: false) is null)
            {
                aside.Add($"{frame} was passed a {instructionType}, which this module declares no type of");
                continue;
            }
            if (FindProgram(heap, context.Module, entered[0], instructionType) is not { } items)
            {
                aside.Add($"nothing {frame} was passed holds a list of {instructionType}");
                continue;
            }
            if (OpcodeField(context.Module, instructionType) is not { } opcodeField)
            {
                aside.Add($"{instructionType} has no field a number could be an opcode in");
                continue;
            }
            if (Decode(heap, context.Module, opcodeField, instructionType, items) is not { } decoded)
            {
                aside.Add($"the {items.Count} {instructionType} {frame} was passed would not read as operations");
                continue;
            }

            diagnostic = string.Empty;
            return new Attempt(
                root, machine, candidate.Key, entered[0], opcodeField, instructionType, items,
                decoded, candidate.Value.Count);
        }

        // Where the run itself stopped short, that is the reason the frames say nothing, and it is
        // a reason about this build rather than about the search.
        var stopped = ran.Succeeded
            ? string.Empty
            : $" The run stopped before it finished: {ran.Diagnostic}";
        diagnostic = (candidates.Count == 0
            ? "Entering the stub reached no interpreter frame, so there was no program to read."
            : $"None of the {candidates.Count} frame(s) the engine entered held a decoded program: " +
                string.Join("; ", aside.Take(4)) + (aside.Count > 4 ? "; ..." : string.Empty) + ".") +
            stopped;
        return null;
    }

    /// <summary>
    /// The methods that call the stub and could themselves be entered with nothing in particular.
    /// </summary>
    /// <remarks>
    /// Only static callers taking numbers are offered. An instance method would need a receiver
    /// built out of nothing, which is the same guess that left the stub with no arguments.
    /// </remarks>
    private static IEnumerable<MethodDef> Callers(ModuleDef module, MethodDef stub) =>
        module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(caller => caller.IsStatic && caller.HasBody && caller != stub &&
                caller.Parameters.All(parameter => parameter.Type.IsPrimitive) &&
                caller.Body.Instructions.Any(instruction => instruction.Operand is MethodDef called &&
                    called == stub));

    private static StaticValue Safely(StaticValue value) =>
        value.Kind == StaticValueKind.HeapReference ? value : StaticValue.Null;

    /// <summary>
    /// Supplies the stub with arguments that carry no information, since only decoding matters.
    /// </summary>
    private static bool TryBuildArguments(
        StaticMachine machine,
        MethodDef method,
        out List<StaticValue> arguments)
    {
        arguments = [];
        foreach (var parameter in method.Parameters)
        {
            var type = parameter.Type;
            arguments.Add(type.IsCorLibType && type.ElementType is not ElementType.String and not
                ElementType.Object
                ? StaticValue.FromInt32(0)
                : StaticValue.Null);
        }
        return arguments.Count == method.Parameters.Count;
    }

    internal static List<StaticValue>? FindProgram(
        StaticHeap heap,
        ModuleDef module,
        StaticValue root,
        string instructionType)
    {
        var wanted = $"System.Collections.Generic.List`1<{instructionType}>";
        var queue = new Queue<(StaticValue Value, int Depth)>();
        var visited = new HashSet<long>();
        queue.Enqueue((root, 0));
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
                items is { Count: > 0 })
            {
                return items;
            }
            foreach (var field in Fields(module, typeName))
            {
                if (heap.TryReadField(value, field, out var stored) &&
                    stored.Kind == StaticValueKind.HeapReference)
                {
                    queue.Enqueue((stored, depth + 1));
                }
            }
        }
        return null;
    }

    internal static IEnumerable<FieldDef> Fields(ModuleDef module, string typeName)
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

    /// <summary>
    /// Picks out the field the engine dispatches on, which is a number however it is declared.
    /// </summary>
    private static FieldDef? OpcodeField(ModuleDef module, string instructionType) =>
        Fields(module, instructionType).FirstOrDefault(field =>
            field.FieldType.FullName == "System.Int32" ||
            field.FieldType.ToTypeDefOrRef().ResolveTypeDef()?.IsEnum == true);

    private static FieldDef? OperandField(
        ModuleDef module,
        FieldDef opcodeField,
        string instructionType) =>
        Fields(module, instructionType).FirstOrDefault(field =>
            field != opcodeField && field.FieldType.FullName == "System.Object");

    /// <summary>What width the engine kept a number at, where the number says so itself.</summary>
    private static string? Boxed(StaticValue value) => value.Kind switch
    {
        StaticValueKind.Int32 => "System.Int32",
        StaticValueKind.Int64 => "System.Int64",
        StaticValueKind.Float32 => "System.Single",
        StaticValueKind.Float64 => "System.Double",
        _ => null
    };

    private static List<VirtualInstruction>? Decode(
        StaticHeap heap,
        ModuleDef module,
        FieldDef opcodeField,
        string instructionType,
        List<StaticValue> items)
    {
        var operandField = OperandField(module, opcodeField, instructionType);

        var decoded = new List<VirtualInstruction>(items.Count);
        for (var index = 0; index < items.Count; index++)
        {
            if (items[index].Kind != StaticValueKind.HeapReference ||
                !heap.TryReadField(items[index], opcodeField, out var opcode) ||
                opcode.Kind != StaticValueKind.Int32)
            {
                return null;
            }
            var operand = operandField is not null &&
                heap.TryReadField(items[index], operandField, out var stored)
                    ? Operand(heap, stored)
                    : new VirtualOperand.None();
            decoded.Add(new VirtualInstruction(index, (int)opcode.Bits, operand));
        }
        return decoded;
    }

    private static VirtualOperand Operand(StaticHeap heap, StaticValue value)
    {
        if (value.Kind != StaticValueKind.HeapReference)
        {
            return value.Kind == StaticValueKind.Null
                ? new VirtualOperand.None()
                : new VirtualOperand.Number(value.Bits) { Type = Boxed(value) };
        }
        if (heap.TryGetString(value, out var text))
            return new VirtualOperand.Text(text);
        if (heap.TryUnbox(value, out var unboxed) &&
            unboxed.Kind != StaticValueKind.HeapReference)
        {
            return new VirtualOperand.Number(unboxed.Bits) { Type = Boxed(unboxed) };
        }
        if (heap.GetArraySnapshot(value) is { } elements)
        {
            var values = new List<long>(elements.Count);
            foreach (var element in elements)
            {
                if (element.Kind == StaticValueKind.HeapReference &&
                    heap.TryUnbox(element, out var boxed))
                {
                    values.Add(boxed.Bits);
                }
                else
                {
                    values.Add(element.Bits);
                }
            }
            return new VirtualOperand.Table(values);
        }
        return heap.TryGetRuntimeTypeName(value, out var typeName)
            ? new VirtualOperand.Other(typeName)
            : new VirtualOperand.Other("?");
    }
}
