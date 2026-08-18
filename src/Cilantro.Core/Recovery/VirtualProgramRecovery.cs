using System.Globalization;
using dnlib.DotNet;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;

namespace Cilantro.Core.Recovery;

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
    /// <summary>Where the guarded part begins and ends, where a clause was found held by one.</summary>
    /// <remarks>
    /// A clause on its own says where its handler is and not what the handler guards; the two
    /// belong to different objects, and only the one holding the other says they go together. Both
    /// are needed before anything can be built from a region, which is why they are kept apart from
    /// the numbers: the numbers are what was read, and these are what was worked out from them.
    /// </remarks>
    public (int From, int To)? Guarded { get; init; }

    /// <summary>Where the handler begins and ends, where the same pairing established it.</summary>
    public (int From, int To)? Handled { get; init; }

    /// <summary>
    /// The region as a line of the listing, said in the engine's own terms.
    /// </summary>
    /// <remarks>
    /// Which number is the start of the try and which the start of the handler is not something a
    /// clause says on its own, so where the pairing did not settle it they are given in the order
    /// the engine keeps them rather than under names that would be a guess. A reader with the
    /// listing beside them can see which is which.
    /// </remarks>
    public string Describe()
    {
        var kind = Kind is { } number ? $", kind {number}" : string.Empty;
        var caught = Caught is null ? string.Empty : $", catching {Caught}";
        if (Guarded is { } guarded && Handled is { } handled)
        {
            return $"operations {guarded.From}-{guarded.To} guarded, handled at " +
                $"{handled.From}-{handled.To}{kind}{caught}";
        }
        return $"over operations {string.Join(", ", Numbers)}{kind}{caught}";
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

    /// <summary>
    /// How many runs of the engine are worth watching before another one stops paying for itself.
    /// </summary>
    /// <remarks>
    /// Each one costs an interpretation of the loader and a run of the program, which is the most
    /// expensive thing this pass does. Two is where the return is: one run entered where the program
    /// enters it and one entered at the stub see different parts of the engine, and a third mostly
    /// sees again what the second already showed.
    /// </remarks>
    private const int ViewsWanted = 2;

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
        // Where the stub's own run went nowhere, the call sites are watched as well rather than
        // instead. Neither view is the better one: entering the stub reaches operations the program
        // never asks for, and entering a call site follows jumps the stub's run never takes. What
        // either run sees the engine do is a fact about the engine, so they are put together.
        var stalled = attempt.Performed * StalledShare < attempt.Program.Count;
        List<MethodDef> roots = stalled
            ? [method.Stub, .. Callers(context.Module, method.Stub).Take(CallersTried)]
            : [method.Stub];
        var runs = new List<Watched>();
        foreach (var root in roots)
        {
            if (Watch(context, root, attempt) is { } one)
                runs.Add(one);
            if (runs.Count == ViewsWanted)
                break;
        }

        // The run that got furthest is the one whose engine the operations are questioned in, and
        // the one whose word is taken wherever two runs saw the same operation differently: it saw
        // it more often, under a program doing what it really does.
        runs.Sort((left, right) => right.Run.Watched.CompareTo(left.Run.Watched));
        var watched = runs.Count == 0 ? null : runs[0];
        foreach (var one in runs)
            flow = Merged(flow, one.Run);

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

        // The operations another program of this engine uses are asked about last, once everything
        // this one uses has been read: most of the numbering comes from the program itself, and only
        // what is left over has to be performed on an operation made for the purpose.
        probed = Made(context, attempt, watched, operandField, probed with { Operations = operations });
        operations = new Dictionary<int, VirtualOperation>(probed.Operations);
        var byOperand = Rules(attempt.Decoded, flow);
        var refused = probed.Refused
            .Where(entry => !operations.TryGetValue(entry.Key, out var known) || !known.Measured)
            .ToDictionary(entry => entry.Key, entry => entry.Value);
        diagnostic = $"The engine decoded {attempt.Decoded.Count} operation(s) of program " +
            $"{method.ProgramId}, read back from its own " +
            $"{attempt.InstructionType.Split('/')[^1]} list. It performed {attempt.Performed} of " +
            "them before stopping" +
            // What stopped the run is what limits everything read from it, so it is said here
            // rather than left to be guessed at from the counts.
            (attempt.Stopped.Length == 0 ? ". " : $", because {attempt.Stopped} ") +
            probed.Summary + " " + Say(flow);
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

        var clauses = new List<StaticValue>();
        foreach (var value in heap.Instances())
        {
            if (heap.TryGetRuntimeTypeName(value, out var typeName) && shaped.Contains(typeName))
                clauses.Add(value);
        }
        made = clauses.Count;

        var guarding = Guarding(heap, module, shaped, clauses);
        var found = new List<VirtualRegion>();
        foreach (var value in clauses)
        {
            guarding.TryGetValue(value.Bits, out var guarded);
            if (Region(heap, module, value, operations, guarded) is { } region)
                found.Add(region);
        }
        return found;
    }

    /// <summary>What each clause guards, where something holding it said so.</summary>
    /// <remarks>
    /// A clause names its handler and the exception it is for. What it does not name is the code
    /// the handler is there for, and without that a region cannot be built back: a try whose start
    /// is unknown is a handler attached to nothing. The engine keeps that pair of places on the
    /// object that holds the clause, which is what makes the two readable together — an object with
    /// two places of its own and a clause inside it is a guarded region, whatever it is called.
    ///
    /// A clause held by two such objects is left out rather than attributed to either. Two readings
    /// of where a try begins are no reading at all, and a region built on the wrong one would catch
    /// code that was never guarded.
    /// </remarks>
    private static Dictionary<long, (int From, int To)> Guarding(
        StaticHeap heap,
        ModuleDef module,
        HashSet<string> shaped,
        List<StaticValue> clauses)
    {
        var held = clauses.Select(clause => clause.Bits).ToHashSet();
        var found = new Dictionary<long, (int From, int To)>();
        var twice = new HashSet<long>();
        foreach (var value in heap.Instances())
        {
            if (!heap.TryGetRuntimeTypeName(value, out var typeName) ||
                shaped.Contains(typeName) ||
                module.Find(typeName, isReflectionName: false) is not { } declared)
            {
                continue;
            }

            var numbers = new List<int>();
            var inside = new List<long>();
            foreach (var field in declared.Fields.Where(field => !field.IsStatic))
            {
                if (!heap.TryReadAssignedField(value, field, out var stored))
                    continue;
                if (field.FieldType?.FullName == "System.Int32" &&
                    stored.Kind == StaticValueKind.Int32)
                {
                    numbers.Add((int)stored.Bits);
                }
                else if (stored.Kind == StaticValueKind.HeapReference && held.Contains(stored.Bits))
                {
                    inside.Add(stored.Bits);
                }
            }
            if (numbers.Count < 2)
                continue;
            foreach (var clause in inside.Where(clause => !found.TryAdd(clause, (numbers[0], numbers[1]))))
                twice.Add(clause);
        }
        foreach (var clause in twice)
            found.Remove(clause);
        return found;
    }

    /// <summary>A value read as a clause, where it has the shape of one and the places to match.</summary>
    private static VirtualRegion? Region(
        StaticHeap heap,
        ModuleDef module,
        StaticValue value,
        int operations,
        (int From, int To) guarded)
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
                    caught ??= heap.TryGetModelValue<string>(stored, "TypeName", out var identity)
                        ? identity
                        : heap.TryGetModelValue<string>(stored, "Name", out var named)
                            ? named
                            : null;
                    break;
                default:
                    break;
            }
        }

        // Four places and a type is a clause; anything less is some other object of the engine's
        // that happens to hold numbers, and the numbers have to be places in this program besides.
        if (!typed || numbers.Count < Places ||
            !numbers.TrueForAll(one => one >= 0 && one <= operations))
        {
            return null;
        }

        // The pair of ranges is taken only where both are ranges and neither runs into the other.
        // A handler inside the code it handles, or a place after the end of the program, is the
        // reading of which number is which being wrong, and a region built on it would put a try
        // around the wrong operations rather than fail.
        var handled = (From: numbers[0], To: numbers[1]);
        var apart = guarded.To >= guarded.From && handled.To >= handled.From &&
            guarded.From >= 0 && guarded.To < operations &&
            handled.From >= 0 && handled.To < operations &&
            (handled.From > guarded.To || handled.To < guarded.From);
        return new VirtualRegion(numbers, kind, caught)
        {
            Guarded = apart ? guarded : null,
            Handled = apart ? handled : null
        };
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

        // A jump whose operand is a table of places in this program chooses among them by the value
        // it takes, which is a switch rather than a two-way condition. This overrides the reading
        // that saw its operand reach the engine's position: both come from the same sighting, and a
        // table of places is the more particular of the two — a condition would have one place to go.
        foreach (var (opcode, operation) in operations)
        {
            if (!Chooses(program, operation, opcode))
                continue;
            operations[opcode] = operation with { Name = "branch by table", TouchesState = true };
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

    /// <summary>
    /// Whether every operand it carries is a table of places in this program, which it goes to one of.
    /// </summary>
    /// <remarks>
    /// Every site has to carry one. An operation carrying a table at one site and a number at another
    /// is two things at once, which means the sites are not all the same operation and nothing can be
    /// said about it from them. The places are checked against the program for the same reason a
    /// clause's are: a table of numbers that are not places in this program is not a table of targets.
    /// </remarks>
    private static bool Chooses(VirtualProgram program, VirtualOperation operation, int opcode)
    {
        if (operation.Measured && (operation.Pops, operation.Pushes) is not (1, 0))
            return false;
        var carried = program.Instructions.Where(one => one.Opcode == opcode).ToList();
        return carried.Count > 0 && carried.TrueForAll(one =>
            one.Operand is VirtualOperand.Table { Values.Count: > 1 } table &&
            table.Values.All(place => place >= 0 && place < program.Instructions.Count));
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
    /// Asks about operations no program the engine decoded performs, by making one to order.
    /// </summary>
    /// <remarks>
    /// Every reading so far has taken its operations from a program the engine decoded, which means
    /// the numbering only ever covers what that program uses. Another program of the same engine —
    /// the one that builds the string table, say — uses operations the first does not, and those stay
    /// unnamed however many times the engine is asked, because there is nothing to point at.
    ///
    /// So one is made: an operation object of the engine's own instruction type, carrying the number
    /// and the operand the other program really pairs them with. Nothing about it is invented except
    /// its existence. If the engine refuses to perform it, that is reported like any other refusal;
    /// the alternative is a numbering with holes in it and a reading that stops at the first one.
    /// </remarks>
    private static VirtualSemanticsReport Made(
        ArtifactContext context,
        Attempt attempt,
        Watched? watched,
        FieldDef? operandField,
        VirtualSemanticsReport first)
    {
        if (!context.TryGetFact<IReadOnlyDictionary<int, long?>>(
                "strings.vmOperations", out var elsewhere) ||
            elsewhere is null ||
            elsewhere.Count == 0)
        {
            return first;
        }

        var operations = first.Operations.ToDictionary(entry => entry.Key, entry => entry.Value);
        var refused = first.Refused.ToDictionary(entry => entry.Key, entry => entry.Value);
        var asked = 0;
        var gained = 0;
        var reasons = new Dictionary<int, string>();

        // Both engines are asked, because which of them can perform anything at all varies by build:
        // a cold one has nothing prepared, and a warm one is somewhere the questioning did not put
        // it and may refuse from there. Whichever answers, answers.
        List<(StaticMachine Machine, StaticValue Engine)> views = watched is null
            ? [(attempt.Machine, attempt.Engine)]
            : [(attempt.Machine, attempt.Engine), (watched.Machine, watched.Engine)];
        foreach (var (machine, engine) in views)
        {
            var wanted = elsewhere
                .Where(entry => !operations.TryGetValue(entry.Key, out var known) ||
                    !known.Identified)
                .OrderBy(entry => entry.Key)
                .ToList();
            if (wanted.Count == 0)
                break;

            var made = new List<StaticValue>();
            foreach (var (opcode, operand) in wanted)
            {
                if (!machine.State.Heap.TryAllocateObject(attempt.InstructionType, out var operation) ||
                    !machine.State.Heap.TryWriteField(
                        operation, attempt.OpcodeField, StaticValue.FromInt32(opcode)))
                {
                    break;
                }
                // The operand goes in boxed, because the field is declared as object and the engine
                // unboxes what it finds there. A number written into it plainly is not a box, and the
                // operation faults on its own operand before it does anything worth reading. An
                // operation that carries nothing is left carrying nothing, which is what the engine's
                // own decoder leaves there for one.
                if (operandField is not null && operand is { } carried &&
                    (!Boxed(machine.State.Heap, carried, out var boxed) ||
                        !machine.State.Heap.TryWriteField(operation, operandField, boxed)))
                {
                    break;
                }
                made.Add(operation);
            }
            if (made.Count == 0)
                continue;

            asked = Math.Max(asked, made.Count);
            var answer = VirtualSemantics.Probe(
                machine, context.Module, attempt.Dispatcher, engine, attempt.OpcodeField,
                operandField, made);
            foreach (var (opcode, read) in answer.Operations)
            {
                if (operations.TryGetValue(opcode, out var known) && known.Identified)
                    continue;
                var named = read.Identified ||
                    !elsewhere.TryGetValue(opcode, out var operand) ||
                    operand is not { } names
                        ? read
                        : read with { Name = Holds(context.Module, names, read) ?? read.Name };
                if (operations.TryGetValue(opcode, out known) &&
                    known.Measured && !named.Identified)
                {
                    continue;
                }
                operations[opcode] = named;
                refused.Remove(opcode);
                reasons.Remove(opcode);
                gained++;
            }
            foreach (var (opcode, why) in answer.Refused)
            {
                if (operations.TryGetValue(opcode, out var known) && known.Identified)
                    continue;
                refused[opcode] = why;
                reasons[opcode] = why;
            }
        }
        if (asked == 0)
            return first;

        // Why a made operation was refused is the whole of what stands between a numbering with a
        // hole in it and one without, so it is said rather than counted.
        var refusals = reasons.Count == 0
            ? string.Empty
            : " " + string.Join("; ", reasons
                .OrderBy(entry => entry.Key)
                .Take(3)
                .Select(entry => $"op {entry.Key}, {entry.Value}"));
        return new VirtualSemanticsReport(
            operations,
            refused,
            first.Summary +
            $" {asked} operation(s) this program does not contain were asked about with an " +
            $"operation made to carry them, which answered {gained}.{refusals}");
    }

    /// <summary>
    /// What an operation whose operand names a field does, read from the field and what it took.
    /// </summary>
    /// <remarks>
    /// This is the same reading the program-shaped rules make of the operations a program contains:
    /// an operand that resolves to a field, and a stack effect that fits reaching that field, names
    /// the operation. It is made separately here because those rules work from an operation's sites
    /// in the program, and an operation this program does not contain has none.
    ///
    /// Which field it is settles instance from static, and the count settles read from write: a write
    /// to a static field takes the value alone, and a write to an instance field takes the object it
    /// belongs to underneath. Nothing is named where the two do not agree, because a field reached
    /// with the wrong number of values is not a field access that was understood.
    /// </remarks>
    private static string? Holds(ModuleDef module, long operand, VirtualOperation operation)
    {
        if (!operation.Measured || operand is < int.MinValue or > int.MaxValue)
            return null;
        FieldDef? field;
        try
        {
            field = (module.ResolveToken((int)operand) as IField)?.ResolveFieldDef();
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            return null;
        }
        if (field is null)
            return null;
        return (field.IsStatic, operation.Pops, operation.Pushes) switch
        {
            (true, 1, 0) => "writes the static field it names",
            (false, 2, 0) => "writes the field it names",
            (true, 0, 1) => "reads the static field it names",
            (false, 1, 1) => "reads the field it names",
            _ => null
        };
    }

    /// <summary>
    /// An operand as the engine keeps it: boxed, at the width the number itself asks for.
    /// </summary>
    private static bool Boxed(StaticHeap heap, long operand, out StaticValue reference) =>
        operand is >= int.MinValue and <= int.MaxValue
            ? heap.TryAllocateBox("System.Int32", StaticValue.FromInt32((int)operand), out reference)
            : heap.TryAllocateBox("System.Int64", StaticValue.FromInt64(operand), out reference);

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

        Inert(merged, decoded);
        return merged;
    }

    /// <summary>Names the operations that carry nothing and were seen to do nothing.</summary>
    /// <remarks>
    /// This is the last reading of all, and it is only reached by an operation nothing else could
    /// account for. Every other pass names an operation by what it did; this one names it by what
    /// it cannot be. An operation that carries no operand is not a call, which needs a method to
    /// call, nor a load or a store, which need a place, nor a jump, which needs somewhere to go —
    /// there is no room in it for any of them. Performed on its own it took nothing, left nothing,
    /// and moved nothing the engine holds. What is left is an operation that does nothing, and
    /// saying so is worth more than leaving it unread: an unread operation severs the walk at it
    /// and costs every operation after it in the block.
    ///
    /// Carrying nothing is what makes the reading safe, and it is checked over every instruction
    /// with that number rather than the one the trials used. An operation whose operand is absent
    /// in one place and a token in another is two operations sharing a number, and neither of them
    /// is this one.
    /// </remarks>
    private static void Inert(
        Dictionary<int, VirtualOperation> merged,
        List<VirtualInstruction> decoded)
    {
        var bare = decoded
            .GroupBy(instruction => instruction.Opcode)
            .Where(group => group.All(one => one.Operand is VirtualOperand.None))
            .Select(group => group.Key)
            .ToHashSet();
        foreach (var (opcode, operation) in merged)
        {
            if (operation is { Name: null, Measured: true, Pops: 0, Pushes: 0, TouchesState: false } &&
                bare.Contains(opcode))
            {
                merged[opcode] = operation with { Name = "does nothing at all" };
            }
        }
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
    /// Everything two runs of the engine saw, as one account.
    /// </summary>
    /// <remarks>
    /// Sightings add up. How often an operation was seen to jump and how often it was seen at all
    /// are counts, so they are summed, and an operation seen taken twice in one run and not taken
    /// once in another is a conditional jump on the strength of both. Everything else is what one
    /// run saw and the other did not, so the accounts are unioned, with the run that watched more of
    /// the engine keeping what both of them saw. That matters for where an operation goes, because a
    /// conditional jump really does go to more than one place and only one of them fits in the
    /// reading, so the sighting kept should be the one from the run that saw the engine doing what
    /// the program does rather than what an argument of nothing led it to do.
    /// </remarks>
    private static VirtualRun Merged(VirtualRun watched, VirtualRun also)
    {
        var jumps = new Dictionary<int, (int Taken, int Seen)>(watched.Jumps);
        foreach (var (opcode, counted) in also.Jumps)
        {
            var already = jumps.GetValueOrDefault(opcode);
            jumps[opcode] = (already.Taken + counted.Taken, already.Seen + counted.Seen);
        }

        var targets = new Dictionary<int, int>(watched.Targets);
        foreach (var (index, target) in also.Targets)
            targets.TryAdd(index, target);
        var effects = new Dictionary<int, VirtualOperation>(watched.Effects);
        foreach (var (opcode, effect) in also.Effects)
            effects.TryAdd(opcode, effect);
        var computed = new Dictionary<int, IReadOnlyList<string>>(watched.Computed);
        foreach (var (opcode, working) in also.Computed)
            computed.TryAdd(opcode, working);
        return new VirtualRun(
            watched.Watched + also.Watched, jumps, targets, effects, computed)
        {
            Stores = new HashSet<int>(watched.Stores.Union(also.Stores))
        };
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
        int Performed,
        string Stopped);

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
                decoded, candidate.Value.Count,
                ran.Succeeded ? string.Empty : ran.Diagnostic ?? string.Empty);
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
