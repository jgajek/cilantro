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
    public sealed record Number(long Value) : VirtualOperand;
    public sealed record Text(string Value) : VirtualOperand;
    public sealed record Table(IReadOnlyList<long> Values) : VirtualOperand;
    public sealed record Other(string Description) : VirtualOperand;
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

    /// <summary>Why the operations that were not performed in isolation were left alone.</summary>
    /// <remarks>
    /// Saying nothing about an operation and saying nothing about why are different. The reason is
    /// what tells a reader whether the gap is in the method or in the tool.
    /// </remarks>
    public IReadOnlyList<string> Declined { get; init; } = [];

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
            yield return "; each one does was established by having the engine perform it on values " +
                "chosen for";
            yield return "; the purpose; an effect is named only where repeated trials left one " +
                "candidate.";
            yield return ";";
            foreach (var operation in Operations.Values.OrderBy(item => item.Opcode))
                yield return $";   op {operation.Opcode,4}  {operation.Describe()}";
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
        var flow = new VirtualControlFlow(0, new Dictionary<int, (int, int)>(),
            new Dictionary<int, int>());
        var stalled = attempt.Performed * StalledShare < attempt.Program.Count;
        var roots = stalled
            ? Callers(context.Module, method.Stub).Take(CallersTried)
            : [method.Stub];
        foreach (var root in roots)
        {
            if (Watch(context, root, attempt) is { } watched)
            {
                flow = watched;
                if (flow.Learned)
                    break;
            }
        }

        var report = VirtualSemantics.Probe(
            attempt.Machine, context.Module, attempt.Dispatcher, attempt.Engine, attempt.OpcodeField,
            OperandField(context.Module, attempt.OpcodeField, attempt.InstructionType),
            attempt.Program);

        // How far the engine got before the run stopped is worth saying: the state left behind is
        // what the operations are asked their meaning in, and an engine that stopped at its first
        // operation leaves a poorer one than one that ran most of the program.
        var operations = Merge(report.Operations, flow);
        var byOperand = Rules(attempt.Decoded, flow);
        diagnostic = $"The engine decoded {attempt.Decoded.Count} operation(s) of program " +
            $"{method.ProgramId}, read back from its own " +
            $"{attempt.InstructionType.Split('/')[^1]} list. It performed {attempt.Performed} of " +
            $"them before stopping. " + report.Summary + " " + Say(flow);
        return new VirtualProgram(method, attempt.InstructionType, attempt.Decoded)
        {
            Operations = operations,
            Declined = report.Declined,
            Targets = flow.Targets,
            TargetIsOperand = byOperand
        };
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
        VirtualControlFlow flow)
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
        VirtualControlFlow flow)
    {
        var merged = probed.ToDictionary(entry => entry.Key, entry => entry.Value);
        foreach (var (opcode, _) in flow.Jumps)
        {
            if (flow.Describe(opcode) is not { } name)
                continue;
            merged[opcode] = merged.TryGetValue(opcode, out var known)
                ? known with { Name = name, TouchesState = true }
                : new VirtualOperation(opcode, 0, 0, name) { TouchesState = true };
        }
        return merged;
    }

    private static string Say(VirtualControlFlow flow)
    {
        if (!flow.Learned)
            return "It was not watched running for long enough to see where it goes.";
        var jumping = flow.Jumps.Count(entry => entry.Value.Taken > 0);
        return $"Watching {flow.Watched} operation(s) run showed {jumping} of them jumping, to " +
            $"{flow.Targets.Count} target(s).";
    }

    /// <summary>
    /// Runs the engine again with the watcher attached, using the dispatcher already identified,
    /// since which method performs an operation is not known until a run has been watched once.
    /// Where the first run went nowhere the call site is entered instead, its arguments being the
    /// ones the program itself supplies rather than the nothing the stub was handed.
    /// </summary>
    private static VirtualControlFlow? Watch(
        ArtifactContext context,
        MethodDef root,
        Attempt known)
    {
        if (!BootstrapMachine.TryRunInitializers(context, DecodeSteps, out var machine, out _) ||
            machine is null || !TryBuildArguments(machine, root, out var arguments))
        {
            return null;
        }

        var watcher = new VirtualControlFlowWatcher(
            context.Module, machine.State.Heap, known.Dispatcher, known.OpcodeField,
            known.InstructionType);
        machine.FrameEntered = watcher.Entered;
        machine.Execute(root, arguments);
        machine.FrameEntered = null;
        return watcher.Result();
    }

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
        machine.Execute(root, arguments);
        machine.FrameEntered = null;

        var heap = machine.State.Heap;
        foreach (var candidate in candidates.OrderByDescending(entry => entry.Value.Count))
        {
            var entered = candidate.Value.First;
            if (!heap.TryGetRuntimeTypeName(Safely(entered[^1]), out var instructionType) ||
                context.Module.Find(instructionType, isReflectionName: false) is null ||
                FindProgram(heap, context.Module, entered[0], instructionType) is not { } items ||
                OpcodeField(context.Module, instructionType) is not { } opcodeField ||
                Decode(heap, context.Module, opcodeField, instructionType, items) is not { } decoded)
            {
                continue;
            }

            diagnostic = string.Empty;
            return new Attempt(
                root, machine, candidate.Key, entered[0], opcodeField, instructionType, items,
                decoded, candidate.Value.Count);
        }

        diagnostic = candidates.Count == 0
            ? "Entering the stub reached no interpreter frame, so there was no program to read."
            : "No frame the engine entered held a decoded program, so its container was not found.";
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
                : new VirtualOperand.Number(value.Bits);
        }
        if (heap.TryGetString(value, out var text))
            return new VirtualOperand.Text(text);
        if (heap.TryUnbox(value, out var unboxed) &&
            unboxed.Kind != StaticValueKind.HeapReference)
        {
            return new VirtualOperand.Number(unboxed.Bits);
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
