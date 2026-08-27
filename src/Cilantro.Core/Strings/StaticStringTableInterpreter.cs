using System.Globalization;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Codec;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;

namespace Cilantro.Core.Strings;

public sealed record StaticStringTableCapture(
    string Source,
    byte[] Bytes,
    IReadOnlyList<DecodedStringRecord> Records,
    IReadOnlyDictionary<uint, int> IntegerFields,
    int Steps,
    string FrontEnd);

public static class StaticStringTableInterpreter
{
    private sealed record VmInstruction(byte OpCode, object? Operand);
    private sealed record VmMethod(IReadOnlyList<VmInstruction> Instructions, int LocalCount);

    /// <summary>
    /// What one of the protector's operations does, as distinct from the number it is written with.
    /// </summary>
    /// <remarks>
    /// The numbers belong to the build. Reactor renumbers the operations from one protected file to
    /// the next, so the same list of numbers is a different program in each, and a reading that
    /// takes them as fixed reads one build correctly and misreads the rest — silently, because a
    /// number that means add in one build means exclusive-or in another and both leave a plausible
    /// value behind. Meanings do not move, so everything below is written in terms of these, and
    /// which number carries which meaning is something the run is told rather than something it
    /// assumes.
    /// </remarks>
    internal enum VmMeaning
    {
        PushOperand,
        PushNull,
        LoadLocal,
        StoreLocal,
        LoadArgument,
        LoadStaticField,
        StoreStaticField,
        StoreField,
        LoadElement,
        StoreElement,
        ArrayLength,
        NewArray,
        NewObject,
        Call,
        Branch,
        BranchIfTrue,
        BranchIfFalse,
        BranchIfEqual,
        BranchIfNotEqual,
        BranchIfLessThan,
        BranchIfGreaterOrEqual,
        BranchIfGreaterThan,
        BranchIfLessOrEqual,
        BranchByTable,
        Return,
        Throw,
        Add,
        Subtract,
        Multiply,
        ExclusiveOr,
        ShiftLeft,
        ShiftRight,
        CompareEqual,
        Negate,
        Complement,
        Duplicate,
        Discard,
        PushString,
        PushToken,
        ConvertToByte,
        ConvertToInt32,
        ConvertToUInt32,
        ConvertToInt64,
        Nothing
    }

    /// <summary>
    /// What each reading the semantics probe arrives at means to the evaluator below.
    /// </summary>
    /// <remarks>
    /// The probe's readings are sentences because they are written for a reader; this is the same
    /// readings as behaviour. Only what appears here can be evaluated, and a build using an
    /// operation absent from it is refused rather than guessed at, which is the whole reason the
    /// numbering is learned instead of assumed.
    /// </remarks>
    private static readonly Dictionary<string, VmMeaning> Learned = new(StringComparer.Ordinal)
    {
        ["pushes its operand"] = VmMeaning.PushOperand,
        ["pushes nothing at all"] = VmMeaning.PushNull,
        ["loads what its operand indexes"] = VmMeaning.LoadLocal,
        ["stores where its operand indexes"] = VmMeaning.StoreLocal,
        ["loads the argument it indexes"] = VmMeaning.LoadArgument,
        ["reads the static field it names"] = VmMeaning.LoadStaticField,
        ["writes the static field it names"] = VmMeaning.StoreStaticField,
        ["writes the field it names"] = VmMeaning.StoreField,
        ["reads an array element"] = VmMeaning.LoadElement,
        ["writes an array element"] = VmMeaning.StoreElement,
        ["array length"] = VmMeaning.ArrayLength,
        ["makes an array of the type it names"] = VmMeaning.NewArray,
        ["makes a new object with the constructor it names"] = VmMeaning.NewObject,
        ["calls the method it names"] = VmMeaning.Call,
        ["branch"] = VmMeaning.Branch,
        ["branch by table"] = VmMeaning.BranchByTable,
        ["returns the value it takes"] = VmMeaning.Return,
        ["stops the program"] = VmMeaning.Return,
        [VirtualSemantics.Throwing] = VmMeaning.Throw,
        ["dup"] = VmMeaning.Duplicate,
        ["discards what it takes"] = VmMeaning.Discard,
        ["does nothing at all"] = VmMeaning.Nothing,
        ["add"] = VmMeaning.Add,
        ["sub"] = VmMeaning.Subtract,
        ["mul"] = VmMeaning.Multiply,
        ["xor"] = VmMeaning.ExclusiveOr,
        ["shl"] = VmMeaning.ShiftLeft,
        ["shr"] = VmMeaning.ShiftRight,
        ["ceq"] = VmMeaning.CompareEqual,
        ["neg"] = VmMeaning.Negate,
        ["not"] = VmMeaning.Complement
    };

    /// <summary>What an operation does, together with how wide the value it leaves is.</summary>
    /// <param name="Meaning">What it does.</param>
    /// <param name="Bits">
    /// The width of the value it leaves, where the reading measured one, and 64 where it did not.
    /// </param>
    /// <remarks>
    /// The width belongs with the meaning because the arithmetic is not the same arithmetic without
    /// it. The engine's slots hold a 32-bit value where the program is 32-bit, and a shift left that
    /// carries a bit past the top loses it there and keeps it here; a shift right afterwards then
    /// brings back a bit that never existed, and the result is a number that is wrong in its middle
    /// while looking entirely ordinary. Nothing downstream can catch that: it is only wrong by the
    /// standard of a machine we would not have modelled.
    ///
    /// Sixty-four is the width assumed where none was measured, because that is what this reading
    /// did before it could measure one, and the builds it was written against are read correctly
    /// that way.
    /// </remarks>
    internal readonly record struct VmReading(VmMeaning Meaning, int Bits = 64);

    /// <summary>Which meaning each condition the probe named decides the same way as.</summary>
    private static readonly Dictionary<string, VmMeaning> Conditions = new(StringComparer.Ordinal)
    {
        ["brtrue"] = VmMeaning.BranchIfTrue,
        ["brfalse"] = VmMeaning.BranchIfFalse,
        ["beq"] = VmMeaning.BranchIfEqual,
        ["bne.un"] = VmMeaning.BranchIfNotEqual,
        ["blt"] = VmMeaning.BranchIfLessThan,
        ["blt.un"] = VmMeaning.BranchIfLessThan,
        ["ble"] = VmMeaning.BranchIfLessOrEqual,
        ["ble.un"] = VmMeaning.BranchIfLessOrEqual,
        ["bgt"] = VmMeaning.BranchIfGreaterThan,
        ["bgt.un"] = VmMeaning.BranchIfGreaterThan,
        ["bge"] = VmMeaning.BranchIfGreaterOrEqual,
        ["bge.un"] = VmMeaning.BranchIfGreaterOrEqual
    };

    /// <summary>What a conversion converts to, where the reading says what it leaves.</summary>
    private static readonly Dictionary<string, VmMeaning> Widths = new(StringComparer.Ordinal)
    {
        ["System.Byte"] = VmMeaning.ConvertToByte,
        ["System.Int32"] = VmMeaning.ConvertToInt32,
        ["System.UInt32"] = VmMeaning.ConvertToUInt32,
        ["System.Int64"] = VmMeaning.ConvertToInt64,
        ["System.UInt64"] = VmMeaning.ConvertToInt64
    };

    /// <summary>
    /// This build's numbering, as the semantics probe read it off the engine itself.
    /// </summary>
    /// <remarks>
    /// Nothing is carried over from the numbering the reading was written against. Mixing the two
    /// would put one build's meaning on another build's number, which is the failure this is here
    /// to prevent, so an operation the probe did not name is left out and the evaluation stops at
    /// it if the program uses it.
    ///
    /// The program itself settles two kinds the trials cannot. An operation carrying a method the
    /// assembly names, measured taking and leaving exactly what that method's signature says, is a
    /// call of it; and one that only ever leaves a value of a kind, carrying a number that names
    /// something of that kind in the assembly, is fetching that thing. Both are read off this
    /// build's own program rather than assumed, and both are what the listing already says of the
    /// same operations, so the evaluator and the listing agree by construction.
    /// </remarks>
    internal static Dictionary<int, VmReading> Numbering(
        VirtualProgram program,
        ModuleDef module,
        out IReadOnlyList<string> unnamed)
    {
        ArgumentNullException.ThrowIfNull(program);
        ArgumentNullException.ThrowIfNull(module);
        var calls = VirtualLift.Calling(program, module);
        var numbering = new Dictionary<int, VmReading>();
        var left = new List<string>();
        foreach (var (opcode, operation) in program.Operations.OrderBy(entry => entry.Key))
        {
            var meaning = Meaning(operation) ??
                (calls.Contains(opcode) ? VmMeaning.Call : Fetches(program, operation, opcode, module));
            if (meaning is { } established)
                numbering[opcode] = new VmReading(established, Bits(operation));
            else
                left.Add($"op {opcode}, read as {operation.Brief}");
        }
        unnamed = left;
        return numbering;
    }

    /// <summary>
    /// What an operation nothing named is fetching, where the kind of thing it leaves and the
    /// number it carries agree about what that is.
    /// </summary>
    /// <remarks>
    /// Every sighting has to agree, because one operand that names nothing is enough to say the
    /// number is not what the reading takes it for. The evaluator resolves each operand again when
    /// it performs the operation, so nothing here is relied on twice.
    /// </remarks>
    private static VmMeaning? Fetches(
        VirtualProgram program,
        VirtualOperation operation,
        int opcode,
        ModuleDef module)
    {
        if (operation.Name is null || operation.Name != operation.Leaving)
            return null;
        var fetching = operation.Left switch
        {
            "System.String" => VmMeaning.PushString,
            { } kind when VirtualLift.Reflected.Contains(kind) => VmMeaning.PushToken,
            _ => (VmMeaning?)null
        };
        if (fetching is not { } fetched)
            return null;
        var sightings = 0;
        foreach (var instruction in program.Instructions.Where(one => one.Opcode == opcode))
        {
            if (instruction.Operand is not VirtualOperand.Number number)
                return null;
            var named = fetched == VmMeaning.PushString
                ? VirtualLift.Says(number.Value, module) is not null
                : Resolved(number.Value, module) is not null;
            if (!named)
                return null;
            sightings++;
        }
        return sightings > 0 ? fetched : null;
    }

    /// <summary>What a number names in the assembly, where it names anything at all.</summary>
    private static IMDTokenProvider? Resolved(long value, ModuleDef module)
    {
        if (value is < int.MinValue or > int.MaxValue || module is not ModuleDefMD image)
            return null;
        try
        {
            return image.ResolveToken(unchecked((int)value));
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>How wide the value an operation leaves is, as the trials found it held.</summary>
    /// <remarks>
    /// Only a width that was measured is used. An operation whose result nothing could type is
    /// given the wider one, which is what every operation was given before any of them were
    /// measured: too wide a result is only wrong where the program relies on losing the top of it,
    /// and too narrow a one is wrong wherever the program keeps a number that does not fit.
    /// </remarks>
    private static int Bits(VirtualOperation operation) => operation.Pushed switch
    {
        "System.Byte" or "System.SByte" or "System.Int16" or "System.UInt16" or
            "System.Int32" or "System.UInt32" or "System.Boolean" or "System.Char" => 32,
        _ => 64
    };

    /// <summary>What one learned reading means, where it means anything the evaluator can perform.</summary>
    private static VmMeaning? Meaning(VirtualOperation operation)
    {
        if (operation.Name is not { } name)
            return null;
        if (name == "branch if")
        {
            return operation.Decides is { } condition &&
                Conditions.TryGetValue(condition, out var branch)
                    ? branch
                    : null;
        }
        if (name == "convert")
        {
            return operation.Pushed is { } left && Widths.TryGetValue(left, out var width)
                ? width
                : null;
        }
        return Learned.TryGetValue(name, out var meaning) ? meaning : null;
    }

    /// <summary>
    /// The numbering of the build this reading was written against, used when no other is known.
    /// </summary>
    /// <remarks>
    /// It is worth keeping even though it is only ever right by luck on a build that renumbers,
    /// because a great many builds do not renumber — the numbering is fixed per protector version
    /// rather than per file — and reading a table from the serialized program costs a few thousand
    /// steps where having the module's own interpreter build it costs tens of millions.
    /// </remarks>
    private static readonly Dictionary<int, VmMeaning> WrittenAgainst = new()
    {
        [1] = VmMeaning.StoreElement,
        [6] = VmMeaning.Discard,
        [14] = VmMeaning.Branch,
        [18] = VmMeaning.LoadStaticField,
        [22] = VmMeaning.Call,
        [24] = VmMeaning.ShiftRight,
        [30] = VmMeaning.LoadElement,
        [53] = VmMeaning.PushNull,
        [54] = VmMeaning.ShiftLeft,
        [58] = VmMeaning.ExclusiveOr,
        [60] = VmMeaning.Subtract,
        [66] = VmMeaning.NewArray,
        [67] = VmMeaning.Negate,
        [68] = VmMeaning.Add,
        [75] = VmMeaning.Complement,
        [77] = VmMeaning.BranchByTable,
        [78] = VmMeaning.LoadLocal,
        [79] = VmMeaning.PushOperand,
        [91] = VmMeaning.Return,
        [97] = VmMeaning.BranchIfLessThan,
        [110] = VmMeaning.Branch,
        [116] = VmMeaning.StoreStaticField,
        [127] = VmMeaning.ConvertToInt64,
        [139] = VmMeaning.StoreLocal,
        [143] = VmMeaning.BranchIfTrue,
        [154] = VmMeaning.ConvertToInt32,
        [156] = VmMeaning.BranchIfFalse,
        [157] = VmMeaning.Duplicate,
        [158] = VmMeaning.StoreField,
        [165] = VmMeaning.BranchIfEqual,
        [166] = VmMeaning.NewObject,
        [172] = VmMeaning.ConvertToByte,
        [173] = VmMeaning.ArrayLength,
        [174] = VmMeaning.LoadArgument
    };

    private static readonly StaticMachineLimits Limits = new(
        MaximumSteps: 4_000_000,
        MaximumRecursionDepth: 96,
        MaximumAllocatedBytes: 64 * 1024 * 1024,
        MaximumArrayLength: 16 * 1024 * 1024);

    /// <summary>What decrypting one byte of a table costs, measured.</summary>
    /// <remarks>
    /// The tables are decrypted by a block cipher the module carries, four bytes at a time, and the
    /// one measured spends 306 interpreted steps on each block however large the table is. Eighty a
    /// byte is that figure rounded up.
    /// </remarks>
    private const int StepsPerTableByte = 80;

    /// <summary>How much more than the decryption a reading is allowed, for the rest of the program.
    /// </summary>
    private const int ReadingHeadroom = 2;

    /// <summary>The most a reading may spend however large the table it was pointed at is.</summary>
    private const int MostReadingSteps = 400_000_000;

    /// <summary>What reading a table of this size is allowed to spend.</summary>
    /// <remarks>
    /// What a reading costs is a property of the file rather than of the tool: the table is a
    /// resource the module carries, and at eighty steps a byte a quarter-megabyte of it is twenty-five
    /// million of them. A flat few million therefore stops in the middle of the decryption on any
    /// build that hides more than about fifty kilobytes, and reports its own ceiling rather than
    /// anything about the build — which reads as a protection the tool cannot follow when it is only
    /// a table the tool declined to finish. Sizing the ceiling from the resource being read keeps it
    /// in proportion to the work in front of it, so a module with a small table still stops quickly
    /// on a loop that will not end, and no module is refused for being large. The floor is what every
    /// reading used to get, so nothing that fits today is given less.
    /// </remarks>
    internal static StaticMachineLimits Reading(int tableBytes) =>
        Limits with
        {
            MaximumSteps = (int)Math.Clamp(
                (long)tableBytes * StepsPerTableByte * ReadingHeadroom,
                Limits.MaximumSteps,
                MostReadingSteps)
        };

    /// <summary>
    /// What the reading of last resort is given, which is less than the reading it stands behind.
    /// </summary>
    /// <remarks>
    /// Having the protector's own interpreter build the table is the most faithful reading there is —
    /// it knows the numbering of its own operations by construction — and by a wide margin the most
    /// expensive: a table of a few hundred strings is a few thousand virtual operations, each one a
    /// pass through a dispatcher of several thousand instructions. On the builds where this is the only
    /// reading left it currently stops short of finishing anyway, so granting it the full budget buys
    /// nothing on those and costs it on every other sample that reaches here. The figure is what it
    /// takes to reach a stop worth reading, and anyone who wants to spend more can say so:
    /// <c>"budgets": { "steps": 40000000 }</c>.
    /// </remarks>
    private static readonly StaticMachineLimits LastResort = Limits with { MaximumSteps = 750_000 };

    /// <summary>
    /// The numbering to read a program with when nobody has read the engine, which is a guess.
    /// </summary>
    /// <remarks>
    /// This is what the early reading has to work with: the numbering of the build the reading was
    /// written against, which is right on every build that does not renumber and wrong on the rest.
    /// The reading that has the engine's own numbering does not come through here. One can be stated
    /// instead — <c>CILANTRO_VM_NUMBERING="57=PushOperand,74=LoadLocal,..."</c> — which is how a
    /// numbering is tried out before anything can learn it.
    /// </remarks>
    private static Dictionary<int, VmReading> Numbering()
    {
        var stated = Environment.GetEnvironmentVariable("CILANTRO_VM_NUMBERING");
        if (string.IsNullOrWhiteSpace(stated))
            return WrittenAgainst.ToDictionary(entry => entry.Key, entry => new VmReading(entry.Value));
        var numbering = new Dictionary<int, VmReading>();
        foreach (var entry in stated.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = entry.Split('=');
            numbering[int.Parse(parts[0].Trim(), CultureInfo.InvariantCulture)] =
                new VmReading(Enum.Parse<VmMeaning>(parts[1].Trim()));
        }
        return numbering;
    }

    /// <summary>
    /// Which operations the serialized program performs, and an operand each really carries.
    /// </summary>
    /// <remarks>
    /// The engine's own numbering is learned by making it perform an operation and watching what
    /// happens, and that needs an operation to perform. A program the engine decoded supplies its
    /// own, but this table is built by a different program of the same engine, so it uses operations
    /// no decoded program contains and nothing would name them. This is the list of what it uses,
    /// carried to the reading of the engine so that those can be asked about too, with the operand
    /// taken from the program rather than invented — an operation that names a field only means
    /// anything if it is given a field that exists.
    /// </remarks>
    public static bool TryReadOperations(
        ModuleDefMD module,
        PeImageView image,
        MethodDef resolver,
        RunEnvironment? environment,
        out IReadOnlyDictionary<int, long?> operations,
        out string diagnostic,
        IReadOnlyList<ProxyBinding>? proxies = null)
    {
        operations = new Dictionary<int, long?>();
        var resourceName = FindResourceName(resolver);
        var initializer = FindInitializer(resolver);
        if (resourceName is null || initializer is null || !IsVmBridge(initializer))
        {
            diagnostic = "The resolver has no virtualized initializer, so it runs no program.";
            return false;
        }

        if (!TryPrepare(module, image, initializer, resourceName, environment ?? new RunEnvironment(),
                0, Limits, proxies, out var machine, out _, out diagnostic))
        {
            return false;
        }

        var census = new Dictionary<int, long?>();
        var read = 0;
        foreach (var methodId in new[] { 0, 1 })
        {
            if (!TryParseVmMethod(module, machine, initializer, methodId, out var method, out var why))
            {
                diagnostic = why;
                continue;
            }
            read++;
            foreach (var instruction in method.Instructions)
            {
                // Every operation the program performs is recorded, with or without an operand,
                // because an operation carrying nothing is still one that has to be named. One
                // operand of a kind is enough and the first is as good as any other — what an
                // operation does is not a property of the operand it does it to — but a number is
                // preferred over nothing, so a later sighting fills in an earlier blank.
                var operand = instruction.Operand switch
                {
                    int number => number,
                    long wide => wide,
                    _ => (long?)null
                };
                if (census.TryGetValue(instruction.OpCode, out var recorded) && recorded is not null)
                    continue;
                census[instruction.OpCode] = operand;
            }
        }
        if (read == 0)
            return false;

        operations = census;
        diagnostic = $"The serialized program uses {census.Count} distinct operation(s), " +
            $"{census.Count(entry => entry.Value is not null)} of them carrying a number.";
        return true;
    }

    public static bool TryCapture(
        ModuleDefMD module,
        PeImageView image,
        MethodDef resolver,
        out StaticStringTableCapture? capture,
        out string diagnostic,
        RunEnvironment? environment = null,
        VirtualProgram? learned = null,
        IReadOnlyList<ProxyBinding>? proxies = null)
    {
        capture = null;

        // Where the caller has had the engine read, this build's own numbering is used and nothing
        // is carried over from the numbering this reading was written against.
        IReadOnlyList<string> unnamed = [];
        var numbering = learned is null ? null : Numbering(learned, module, out unnamed);
        var resourceName = FindResourceName(resolver);
        var initializer = FindInitializer(resolver);
        if (resourceName is null || initializer is null)
        {
            diagnostic = "The resolver's resource-backed static initializer was not structurally identified.";
            return false;
        }

        if (module.Resources.OfType<EmbeddedResource>()
                .SingleOrDefault(resource => resource.Name == resourceName) is not { } resource)
        {
            diagnostic = $"The initializer resource '{resourceName}' is missing or ambiguous.";
            return false;
        }

        var runs = new List<(byte[] Bytes, IReadOnlyList<DecodedStringRecord> Records,
            IReadOnlyDictionary<uint, int> IntegerFields, int Steps, string FrontEnd)>();
        foreach (var offset in new[] { 0, 1 })
        {
            if (!TryRun(module, image, initializer, resourceName,
                    resource.CreateReader().ToArray(), offset, environment, numbering, proxies,
                    out var run, out diagnostic))
            {
                // What the engine did not say is the first thing to look at when a reading that had
                // the engine's own numbering still stopped, so it is said here rather than left to
                // be worked out from the listing.
                if (unnamed.Count > 0)
                {
                    diagnostic += " The engine left these operations unnamed, so nothing would " +
                        $"perform them: {string.Join("; ", unnamed.Take(8))}" +
                        (unnamed.Count > 8 ? ", ..." : string.Empty) + ".";
                }
                return false;
            }
            runs.Add(run);
        }
        if (!runs[0].Bytes.AsSpan().SequenceEqual(runs[1].Bytes))
        {
            diagnostic =
                "The pristine table depended on the resolver offset in two bounded interpretations.";
            return false;
        }
        if (runs[0].IntegerFields.Count != runs[1].IntegerFields.Count ||
            runs[0].IntegerFields.Any(field =>
                !runs[1].IntegerFields.TryGetValue(field.Key, out var value) ||
                value != field.Value))
        {
            diagnostic =
                "VM-initialized integer fields depended on the resolver offset.";
            return false;
        }

        // Which reading produced the table is reported rather than inferred from the initializer's
        // shape, because a virtualized one can be read two ways and the answer to "how do you know"
        // differs between them.
        var frontEnd = runs[0].FrontEnd;
        if (!string.Equals(frontEnd, runs[1].FrontEnd, StringComparison.Ordinal))
        {
            diagnostic =
                $"Two bounded interpretations agreed on the table but were read differently " +
                $"({runs[0].FrontEnd} and {runs[1].FrontEnd}).";
            return false;
        }
        capture = new StaticStringTableCapture(
            $"{initializer.MDToken} {initializer.FullName}",
            runs[0].Bytes,
            runs[0].Records,
            runs[0].IntegerFields,
            runs[0].Steps,
            frontEnd);
        diagnostic =
            $"Bounded {frontEnd} interpretation captured one offset-independent table.";
        return true;
    }

    private static bool TryRun(
        ModuleDefMD module,
        PeImageView image,
        MethodDef initializer,
        string resourceName,
        byte[] resourceBytes,
        int offset,
        RunEnvironment? environment,
        IReadOnlyDictionary<int, VmReading>? numbering,
        IReadOnlyList<ProxyBinding>? proxies,
        out (byte[] Bytes, IReadOnlyList<DecodedStringRecord> Records,
            IReadOnlyDictionary<uint, int> IntegerFields, int Steps, string FrontEnd) run,
        out string diagnostic)
    {
        run = default;
        environment ??= new RunEnvironment();

        if (!TryPrepare(module, image, initializer, resourceName, environment, offset,
                Reading(resourceBytes.Length), proxies, out var machine, out var arguments,
                out diagnostic))
        {
            return false;
        }

        if (IsVmBridge(initializer))
        {
            if (TryReadSerialized(
                    module, machine, initializer, arguments, numbering ?? Numbering(), out run,
                    out diagnostic))
                return true;

            // The serialized reading knows the framing of a program and the numbering of its
            // operations, and a build that numbers them differently defeats it. The module's own
            // interpreter knows both by construction, so where the first reading cannot be had the
            // machine runs the bridge and lets the protector's own code do the reading. Neither is
            // preferred on principle: the first is tried first because it is the one the corpus is
            // pinned to, and this one answers where it stops rather than replacing it.
            var serialized = diagnostic;
            if (!TryPrepare(module, image, initializer, resourceName, environment, offset, LastResort,
                    proxies, out var interpreting, out var again, out diagnostic))
            {
                return false;
            }
            if (TryReadDirectly(interpreting, initializer, again, module,
                    "reactor-vm-run-by-its-own-interpreter", out run, out diagnostic))
            {
                return true;
            }
            diagnostic =
                $"Reading the serialized program: {serialized} Running the module's own " +
                $"interpreter instead, within the {LastResort.MaximumSteps} steps that reading is " +
                $"given: {diagnostic}";
            return false;
        }

        return TryReadDirectly(machine, initializer, arguments, module, "managed-cil",
            out run, out diagnostic);
    }

    /// <summary>
    /// A machine with the module's resources and identity in place, and the initializer's arguments.
    /// </summary>
    /// <remarks>
    /// Each reading gets its own, because one that stopped part way has already written whatever it
    /// wrote, and a table captured from a machine another attempt has been over would be evidence
    /// about the attempts rather than about the module.
    /// </remarks>
    private static bool TryPrepare(
        ModuleDefMD module,
        PeImageView image,
        MethodDef initializer,
        string resourceName,
        RunEnvironment environment,
        int offset,
        StaticMachineLimits limits,
        IReadOnlyList<ProxyBinding>? known,
        out StaticMachine machine,
        out IReadOnlyList<StaticValue> arguments,
        out string diagnostic)
    {
        var proxies = ProxyIntrinsicRegistry.Create(module, known);
        machine = new StaticMachine(
            environment.Declarations.Budgets.Over(limits),
            proxies);
        arguments = [];
        proxies.Bind(machine);
        machine.State.RegisterRunEnvironment(environment);
        foreach (var resource in module.Resources.OfType<EmbeddedResource>())
            machine.State.RegisterResource(resource.Name, resource.CreateReader().ToArray());
        machine.State.RegisterAssemblyIdentity(
            module.Assembly?.Name ?? module.Name,
            module.Assembly?.PublicKeyToken?.Data ?? []);
        machine.State.RegisterPointerSize(image.IsPe32Plus ? 8 : 4);
        // Without this the machine is running the module's code while unable to look anything up in
        // it, and the first thing that costs is the type hierarchy: every cast to one of the module's
        // own types answers null, because the walk has no metadata to walk. A protector's engine
        // casts constantly — each instruction is handed about as its abstract kind and taken back
        // out again — so the nulls accumulate silently and the run dies at some later field read,
        // looking for all the world like the engine rejecting its own state.
        machine.State.RegisterModuleMetadata(module);

        if (!machine.State.TryOpenResource(resourceName, out var stream))
        {
            diagnostic = $"Could not model resource stream '{resourceName}'.";
            return false;
        }
        var built = BuildArguments(machine, initializer, stream, offset);
        if (built is null)
        {
            diagnostic =
                $"Initializer {initializer.MDToken} does not have the supported (stream, int32) contract.";
            return false;
        }

        arguments = built;
        diagnostic = string.Empty;
        return true;
    }

    /// <summary>
    /// Runs the initializer and takes the one strictly framed table it leaves behind, if it leaves one.
    /// </summary>
    private static bool TryReadDirectly(
        StaticMachine machine,
        MethodDef initializer,
        IReadOnlyList<StaticValue> arguments,
        ModuleDefMD module,
        string frontEnd,
        out (byte[] Bytes, IReadOnlyList<DecodedStringRecord> Records,
            IReadOnlyDictionary<uint, int> IntegerFields, int Steps, string FrontEnd) run,
        out string diagnostic)
    {
        run = default;
        var result = machine.Execute(initializer, arguments);
        if (!result.Succeeded)
        {
            diagnostic =
                $"Bounded initializer {initializer.MDToken} stopped as {result.Status} " +
                $"after {result.Steps} steps: {result.Diagnostic}";
            return false;
        }

        var candidates = CaptureFramedTables(machine);
        if (candidates.Length != 1)
        {
            diagnostic = candidates.Length == 0
                ? $"Initializer {initializer.MDToken} completed but exposed no strictly framed UTF-16 table."
                : $"Initializer {initializer.MDToken} exposed {candidates.Length} distinct strictly framed tables.";
            return false;
        }

        run = (candidates[0].Bytes, candidates[0].Records,
            CaptureIntegerFields(module, machine), result.Steps, frontEnd);
        diagnostic = string.Empty;
        return true;
    }

    /// <summary>
    /// Reads the table by framing the serialized program itself and evaluating operations 0 and 1.
    /// </summary>
    private static bool TryReadSerialized(
        ModuleDefMD module,
        StaticMachine machine,
        MethodDef initializer,
        IReadOnlyList<StaticValue> arguments,
        IReadOnlyDictionary<int, VmReading> numbering,
        out (byte[] Bytes, IReadOnlyList<DecodedStringRecord> Records,
            IReadOnlyDictionary<uint, int> IntegerFields, int Steps, string FrontEnd) run,
        out string diagnostic)
    {
        run = default;
        if (!TryParseVmMethod(module, machine, initializer, 0, out var vmMethod,
                out var vmDiagnostic))
        {
            diagnostic = vmDiagnostic;
            return false;
        }
        if (!TryParseVmMethod(module, machine, initializer, 1, out var vmMethodOne,
                out var vmMethodOneDiagnostic))
        {
            diagnostic = vmMethodOneDiagnostic;
            return false;
        }
        var reversed = Environment.GetEnvironmentVariable("CILANTRO_VM_ORDER") == "10";
        if (reversed)
        {
            var first = EvaluateVmMethodZero(module, machine, vmMethodOne, [], numbering);
            if (!first.Success)
            {
                diagnostic = $"Serialized VM ID 1: {first.Diagnostic}";
                return false;
            }
        }
        var evaluation = EvaluateVmMethodZero(module, machine, vmMethod, arguments, numbering);
        if (!evaluation.Success)
        {
            diagnostic = evaluation.Diagnostic;
            return false;
        }
        var methodOneEvaluation = reversed
            ? (Success: true, Steps: 0, Diagnostic: string.Empty)
            : EvaluateVmMethodZero(module, machine, vmMethodOne, [], numbering);
        if (!methodOneEvaluation.Success)
        {
            diagnostic = $"Serialized VM ID 1: {methodOneEvaluation.Diagnostic}";
            return false;
        }
        var vmCandidates = CaptureFramedTables(machine);
        if (vmCandidates.Length != 1)
        {
            diagnostic = vmCandidates.Length == 0
                ? $"VM ID 0 completed after {evaluation.Steps} steps but exposed no strictly framed UTF-16 table."
                : $"VM ID 0 exposed {vmCandidates.Length} distinct strictly framed tables.";
            return false;
        }

        run = (vmCandidates[0].Bytes, vmCandidates[0].Records,
            CaptureIntegerFields(module, machine), evaluation.Steps,
            "reactor-vm-method-0-serialized");
        diagnostic = string.Empty;
        return true;
    }

    private static (byte[] Bytes, IReadOnlyList<DecodedStringRecord> Records)[] CaptureFramedTables(
        StaticMachine machine)
    {
        if (Environment.GetEnvironmentVariable("CILANTRO_VM_DUMP") is { Length: > 0 } where)
        {
            File.AppendAllLines(Path.Combine(where, "statics.txt"),
                machine.State.StaticFields
                    .Where(field => field.Value.Kind == StaticValueKind.HeapReference)
                    .Select(field =>
                    {
                        var bytes = machine.State.Heap.GetBytesSnapshot(field.Value);
                        machine.State.Heap.TryGetRuntimeTypeName(field.Value, out var typeName);
                        var text = bytes is null
                            ? "not bytes"
                            : $"{bytes.Length} bytes {Convert.ToHexString(bytes)}";
                        return $"{field.Key:X8} {typeName} {text}";
                    }));
        }
        return Framed(machine);
    }

    private static (byte[] Bytes, IReadOnlyList<DecodedStringRecord> Records)[] Framed(
        StaticMachine machine) =>
        machine.State.StaticFields
            .Where(field => field.Value.Kind == StaticValueKind.HeapReference)
            .Select(field => (field.Key, Bytes: machine.State.Heap.GetBytesSnapshot(field.Value)))
            .Where(item => item.Bytes is { Length: > 0 })
            .Select(item => (item.Key, Bytes: item.Bytes!,
                Valid: StrictStringTable.TryDecodeComplete(item.Bytes!, out var records),
                Records: records))
            .Where(item => item.Valid)
            .GroupBy(item => Convert.ToHexString(item.Bytes), StringComparer.Ordinal)
            .Select(group => (group.First().Bytes, group.First().Records))
            .ToArray();

    private static Dictionary<uint, int> CaptureIntegerFields(
        ModuleDefMD module,
        StaticMachine machine) =>
        InitializedFieldCapture.CaptureInstanceIntegers(module, machine.State);

    private static bool TryParseVmMethod(
        ModuleDefMD module,
        StaticMachine machine,
        MethodDef initializer,
        int methodId,
        out VmMethod method,
        out string diagnostic)
    {
        method = new VmMethod([], 0);
        var bridge = initializer.Body.Instructions
            .Select(instruction => (instruction.Operand as IMethod)?.ResolveMethodDef())
            .SingleOrDefault(method => method?.MethodSig?.Params.Count == 3 &&
                method.MethodSig.RetType is SZArraySig
                    { Next: { ElementType: ElementType.Object } });
        if (bridge is null)
        {
            diagnostic = "No unique VM bridge was found.";
            return false;
        }

        var loaders = bridge.DeclaringType.Methods.Where(method =>
            method.HasBody && method.IsStatic &&
            method.MethodSig?.Params.Count == 0 &&
            method.ReturnType.ElementType == ElementType.Void &&
            method.Body.Instructions.Any(instruction =>
                instruction.OpCode.Code == Code.Ldstr &&
                instruction.Operand is string name &&
                module.Resources.OfType<EmbeddedResource>().Any(resource => resource.Name == name)) &&
            method.Body.Instructions.Any(instruction =>
                instruction.Operand is IMethod called &&
                called.DeclaringType.FullName == "System.IO.BinaryReader" &&
                called.Name == ".ctor")).ToArray();
        if (loaders.Length != 1)
        {
            diagnostic = $"Expected one VM resource loader, found {loaders.Length}.";
            return false;
        }
        var loader = loaders[0];
        var resourceNames = loader.Body.Instructions
            .Where(instruction => instruction.OpCode.Code == Code.Ldstr)
            .Select(instruction => instruction.Operand as string)
            .Where(name => name is not null && module.Resources.OfType<EmbeddedResource>()
                .Any(resource => resource.Name == name))
            .Cast<string>()
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        var parsers = loader.Body.Instructions
            .Select(instruction => (instruction.Operand as IMethod)?.ResolveMethodDef())
            .Select(method => method is null ? null : StandsFor(module, method))
            .Where(method => method?.DeclaringType == bridge.DeclaringType &&
                method.IsStatic &&
                method.ReturnType.ElementType == ElementType.Void &&
                method.MethodSig?.Params.Count == 1)
            .Distinct()
            .Cast<MethodDef>()
            .ToArray();
        if (resourceNames.Length != 1 || parsers.Length != 1 ||
            module.Resources.OfType<EmbeddedResource>()
                .SingleOrDefault(resource => resource.Name == resourceNames[0]) is not { } resource)
        {
            var called = string.Join(" | ", loader.Body.Instructions
                .Select(instruction => (instruction.Operand as IMethod)?.ResolveMethodDef())
                .Where(method => method is not null)
                .Distinct()
                .Select(method =>
                    $"{method!.DeclaringType.Name}::{method.Name}" +
                    $"({string.Join(",", method.MethodSig?.Params.Select(p => p.TypeName) ?? [])})" +
                    $"->{method.ReturnType.TypeName} static={method.IsStatic} " +
                    $"sameType={method.DeclaringType == bridge.DeclaringType}"));
            diagnostic = resourceNames.Length != 1
                ? $"Its loader names {resourceNames.Length} embedded resource(s), not one."
                : $"Its loader calls {parsers.Length} method(s) shaped like the one that parses " +
                    $"the table, not one. DIAGNOSTIC loader={loader.MDToken} {loader.FullName} " +
                    $"calls: {called}";
            return false;
        }

        var serialized = resource.CreateReader().ToArray();
        if (!machine.State.Heap.TryAllocateByteArray(serialized, out var serializedArray))
        {
            diagnostic = "VM serialized IR exceeded the allocation budget.";
            return false;
        }
        var parseResult = machine.Execute(parsers[0], [serializedArray]);
        if (!parseResult.Succeeded)
        {
            diagnostic =
                $"VM IR loader stopped as {parseResult.Status} after {parseResult.Steps} steps: " +
                parseResult.Diagnostic;
            return false;
        }

        var readers = machine.State.StaticFields.Values
            .Where(value => value.Kind == StaticValueKind.HeapReference &&
                machine.State.Heap.TryGetRuntimeTypeName(value, out var typeName) &&
                typeName == "System.IO.BinaryReader" &&
                machine.State.Heap.TryGetModelValue(value, "Stream", out StaticValue stream) &&
                stream.Kind == StaticValueKind.HeapReference &&
                machine.State.Heap.TryGetModelValue(stream, "Buffer", out StaticValue buffer) &&
                buffer.Kind == StaticValueKind.HeapReference)
            .Select(value =>
            {
                machine.State.Heap.TryGetModelValue(value, "Stream", out StaticValue stream);
                machine.State.Heap.TryGetModelValue(stream, "Buffer", out StaticValue buffer);
                return machine.State.Heap.GetBytesSnapshot(buffer);
            })
            .Where(bytes => bytes is { Length: > 0 })
            .Cast<byte[]>()
            .Distinct(ByteArrayComparer.Instance)
            .ToArray();
        if (readers.Length != 1)
        {
            diagnostic = $"VM IR loader exposed {readers.Length} distinct reader buffers.";
            return false;
        }
        var bufferBytes = readers[0];

        var arrays = machine.State.StaticFields.Values
            .Where(value => value.Kind == StaticValueKind.HeapReference)
            .Select(value => machine.State.Heap.GetArraySnapshot(value))
            .Where(values => values is { Count: > 0 })
            .Cast<IReadOnlyList<StaticValue>>()
            .ToArray();
        var operandKinds = arrays
            .Where(values => values.Count > 32 &&
                values.All(value => value.IsInteger && (uint)value.AsInt32() <= 5))
            .Select(values => values.Select(value => checked((byte)value.AsInt32())).ToArray())
            .Distinct(ByteArrayComparer.Instance)
            .ToArray();
        var offsets = arrays
            .Where(values => values.Count >= 2 &&
                values.All(value => value.IsInteger &&
                    (uint)value.AsInt32() < (uint)bufferBytes.Length))
            .Select(values => values.Select(value => value.AsInt32()).ToArray())
            .Where(values => values.Distinct().Count() == values.Length)
            .ToArray();
        if (operandKinds.Length != 1 || offsets.Length != 1)
        {
            diagnostic =
                $"VM IR metadata was ambiguous ({operandKinds.Length} operand maps, {offsets.Length} offset maps).";
            return false;
        }

        try
        {
            if ((uint)methodId >= (uint)offsets[0].Length)
                throw new InvalidDataException($"VM method ID {methodId} has no offset.");
            var cursor = offsets[0][methodId];
            _ = ReadVmInteger(bufferBytes, ref cursor);
            var localCount = ReadVmInteger(bufferBytes, ref cursor);
            var exceptionCount = ReadVmInteger(bufferBytes, ref cursor);
            var instructionCount = ReadVmInteger(bufferBytes, ref cursor);
            if (localCount < 0 || exceptionCount < 0 || instructionCount <= 0 ||
                instructionCount > 1_000_000)
                throw new InvalidDataException("VM method header counts are outside bounds.");
            for (var index = 0; index < localCount; index++)
                _ = ReadVmInteger(bufferBytes, ref cursor);
            for (var index = 0; index < exceptionCount; index++)
            {
                for (var field = 0; field < 6; field++)
                    _ = ReadVmInteger(bufferBytes, ref cursor);
            }

            var decoded = new List<VmInstruction>(instructionCount);
            for (var index = 0; index < instructionCount; index++)
            {
                if ((uint)cursor >= (uint)bufferBytes.Length)
                    throw new EndOfStreamException();
                var opcode = bufferBytes[cursor++];
                if ((uint)opcode >= (uint)operandKinds[0].Length)
                    throw new InvalidDataException($"VM opcode {opcode} exceeds its operand map.");
                object? operand = operandKinds[0][opcode] switch
                {
                    0 => null,
                    1 => ReadVmInteger(bufferBytes, ref cursor),
                    2 => ReadFixedInt64(bufferBytes, ref cursor),
                    3 => BitConverter.Int32BitsToSingle(
                        checked((int)ReadFixedUInt32(bufferBytes, ref cursor))),
                    4 => BitConverter.Int64BitsToDouble(ReadFixedInt64(bufferBytes, ref cursor)),
                    5 => ReadVmIntegerArray(bufferBytes, ref cursor),
                    _ => throw new InvalidDataException("Unsupported VM operand kind.")
                };
                decoded.Add(new VmInstruction(opcode, operand));
            }
            method = new VmMethod(decoded, localCount);
            if (Environment.GetEnvironmentVariable("CILANTRO_VM_DUMP") is { Length: > 0 } dump)
            {
                File.WriteAllLines(
                    Path.Combine(dump, $"program{methodId}.txt"),
                    decoded.Select((item, index) =>
                        $"{index}: op {item.OpCode} {FormatVmOperand(item.Operand)} " +
                        $"{DescribeVmOperand(module, item.Operand)}"));
            }
            diagnostic =
                $"Loader={loader.MDToken}; parser={parsers[0].MDToken}; " +
                $"buffer={bufferBytes.Length}; methodId={methodId}; " +
                $"methodOffset={offsets[0][methodId]}.";
            return true;
        }
        catch (Exception exception) when (
            exception is InvalidDataException or EndOfStreamException or
                OverflowException or ArgumentOutOfRangeException)
        {
            diagnostic = $"Serialized VM method-ID {methodId} framing failed: {exception.Message}";
            return false;
        }
    }

    /// <summary>
    /// The method a call names, after any of Reactor's proxy thunks standing in front of it.
    /// </summary>
    /// <remarks>
    /// Reactor can route a call through a static method it adds to a delegate type, taking the real
    /// arguments plus the delegate itself, so a call that reads as
    /// <c>SomeProxy::Thunk(byte[], SomeProxy)</c> in the metadata is a call to whatever that
    /// delegate was bound to. Builds differ in how much they route this way, and one that routes the
    /// string table's parser leaves nothing on the caller's side with the parser's shape. Looking
    /// only at what a call literally names would therefore make the table unreadable on those
    /// builds, which is not a fact about the protection but about where we chose to look.
    ///
    /// Where a thunk cannot be tied to exactly one target the method is returned unchanged, so a
    /// caller applying a shape test still decides for itself and an ambiguous proxy layer cannot
    /// silently redirect one.
    /// </remarks>
    private static MethodDef StandsFor(ModuleDefMD module, MethodDef method) =>
        Thunks(module).TryGetValue(method.MDToken.Raw, out var target) ? target : method;

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<
        ModuleDefMD, Dictionary<uint, MethodDef>> ThunkCache = new();

    /// <summary>
    /// Each proxy thunk in the module against the single method it was bound to.
    /// </summary>
    /// <remarks>
    /// The bindings come from the same structural discovery the interpreter's proxy intrinsics use,
    /// so a thunk resolved here and a proxy call followed there cannot disagree about what a
    /// delegate stands for. Discovery reads a resource and decodes it, which is worth doing once per
    /// module rather than once per capture attempt.
    /// </remarks>
    private static Dictionary<uint, MethodDef> Thunks(ModuleDefMD module)
    {
        if (ThunkCache.TryGetValue(module, out var cached))
            return cached;

        var thunks = new Dictionary<uint, MethodDef>();
        var facts = ReactorStructureDetector.Analyze(module);
        if (StructuralStreamDiscovery.TryDiscoverProxyProfile(module, facts, out var profile) &&
            profile is not null)
        {
            foreach (var binding in profile.Bindings)
            {
                if (module.ResolveToken(binding.FieldToken) is not FieldDef field ||
                    module.ResolveToken(binding.TargetToken) is not IMethod target ||
                    target.ResolveMethodDef() is not { } definition)
                {
                    continue;
                }

                var proxy = field.DeclaringType;
                foreach (var thunk in proxy.Methods.Where(method =>
                    method.IsStatic &&
                    method.HasBody &&
                    method.MethodSig?.Params.Count > 0 &&
                    method.MethodSig.Params[^1].FullName == proxy.FullName))
                {
                    // A proxy type carries one binding, so two thunks on it standing for different
                    // methods would mean the discovery disagreed with itself. Dropping the entry
                    // leaves the caller reading the metadata as written.
                    if (thunks.TryGetValue(thunk.MDToken.Raw, out var existing) &&
                        existing != definition)
                    {
                        thunks.Remove(thunk.MDToken.Raw);
                        continue;
                    }
                    thunks[thunk.MDToken.Raw] = definition;
                }
            }
        }

        ThunkCache.Add(module, thunks);
        return thunks;
    }

    private static (bool Success, int Steps, string Diagnostic) EvaluateVmMethodZero(
        ModuleDefMD module,
        StaticMachine machine,
        VmMethod method,
        IReadOnlyList<StaticValue> arguments,
        IReadOnlyDictionary<int, VmReading> numbering)
    {
        var steps = 0;
        var locals = Enumerable.Repeat(StaticValue.Unknown, method.LocalCount).ToArray();
        var stack = new List<StaticValue>();
        var trail = new Queue<int>();
        var walked = new List<string>();
        var pc = 0;
        const int maximumSteps = 1_000_000;
        while ((uint)pc < (uint)method.Instructions.Count && steps++ < maximumSteps)
        {
            var instruction = method.Instructions[pc];
            trail.Enqueue(pc);
            if (trail.Count > 24)
                trail.Dequeue();
            var next = pc + 1;
            walked.Add(
                $"{pc}:{instruction.OpCode}:" +
                $"{(instruction.Operand is int[] table ? $"[{table.Length} targets]" : FormatVmOperand(instruction.Operand))}" +
                $" depth={stack.Count}");
            bool Pop(out StaticValue value)
            {
                value = StaticValue.Unknown;
                if (stack.Count == 0)
                    return false;
                value = stack[^1];
                stack.RemoveAt(stack.Count - 1);
                return true;
            }
            bool Target(object? operand, out int target)
            {
                target = operand is int value ? value : -1;
                return (uint)target < (uint)method.Instructions.Count;
            }

            if (!numbering.TryGetValue(instruction.OpCode, out var reading))
                return VmFailure("nothing established what this operation means.");
            var meaning = reading.Meaning;

            // A result is kept as wide as the operation that produced it keeps it. The engine's own
            // slot is what decides that, and where the reading measured a thirty-two bit one, a
            // result that does not fit is cut down here exactly as the engine cuts it down there.
            StaticValue Held(long value) => reading.Bits == 32
                ? StaticValue.FromInt32(unchecked((int)value))
                : StaticValue.FromInt64(value);

            switch (meaning)
            {
                case VmMeaning.PushOperand:
                    if (instruction.Operand is not int constant)
                        return VmFailure("ldc.i4 operand is not an integer.");
                    stack.Add(StaticValue.FromInt32(constant));
                    break;
                case VmMeaning.PushNull:
                    stack.Add(StaticValue.Null);
                    break;
                case VmMeaning.PushString:
                    if (instruction.Operand is not int said ||
                        VirtualLift.Says(said, module) is not { } literal ||
                        !machine.State.Heap.TryAllocateString(literal, out var pushedText))
                        return VmFailure("ldstr operand does not name a string of this assembly.");
                    stack.Add(pushedText);
                    break;
                case VmMeaning.PushToken:
                    // The machine's own ldtoken hands on the metadata itself and lets the framework
                    // method that follows turn it into the class the program wanted, so this hands on
                    // the same thing rather than a second modelling of the same idea.
                    if (instruction.Operand is not int named ||
                        Resolved(named, module) is not { } member ||
                        !machine.State.Heap.TryAllocateMetadataHandle(member, out var handle))
                        return VmFailure("ldtoken operand does not name a member of this assembly.");
                    stack.Add(handle);
                    break;
                case VmMeaning.ShiftRight:
                    if (!Pop(out var shiftSignedRight) || !Pop(out var shiftSignedLeft) ||
                        !shiftSignedLeft.IsInteger || !shiftSignedRight.IsInteger ||
                        !TryEvaluateVmIntegerBinary(
                            meaning, shiftSignedLeft.AsInt64(),
                            shiftSignedRight.AsInt64(), out var shiftSignedResult))
                        return VmFailure("shr requires two known integers.");
                    stack.Add(Held(shiftSignedResult));
                    break;
                case VmMeaning.ShiftLeft:
                    if (!Pop(out var shiftRight) || !Pop(out var shiftLeft) ||
                        !shiftLeft.IsInteger || !shiftRight.IsInteger ||
                        !TryEvaluateVmIntegerBinary(
                            meaning, shiftLeft.AsInt64(), shiftRight.AsInt64(),
                            out var shiftResult))
                        return VmFailure("shl requires two known integers.");
                    stack.Add(Held(shiftResult));
                    break;
                case VmMeaning.Return:
                    if (!TryEvaluateVmControlFlow(
                            meaning, out var handlerPointer, out var returns) ||
                        !returns || handlerPointer + 1 > -2)
                        return VmFailure("ret sentinel did not terminate the current VM frame.");
                    stack.Clear();
                    DumpWalk(walked);
                    DumpLocals(machine, locals);
                    return (true, steps, string.Empty);
                case VmMeaning.Throw:
                    // A program that throws where it is walked has not built a table, and saying so
                    // is the whole finding: the operation was performed correctly and what it did
                    // was end the run. What it threw is on the stack and named by its type.
                    return VmFailure(
                        Pop(out var thrown) &&
                        machine.State.Heap.TryGetRuntimeTypeName(thrown, out var kind)
                            ? $"the program threw {kind}."
                            : "the program threw.");
                case VmMeaning.LoadLocal:
                    if (instruction.Operand is not int loadLocal ||
                        (uint)loadLocal >= (uint)locals.Length)
                        return VmFailure("ldloc index is outside the local array.");
                    stack.Add(locals[loadLocal]);
                    break;
                case VmMeaning.StoreLocal:
                    if (instruction.Operand is not int storeLocal ||
                        (uint)storeLocal >= (uint)locals.Length || !Pop(out locals[storeLocal]))
                        return VmFailure("stloc has an invalid index or empty stack.");
                    break;
                case VmMeaning.LoadArgument:
                    if (instruction.Operand is not int argument ||
                        (uint)argument >= (uint)arguments.Count)
                        return VmFailure("ldarg index is outside the argument array.");
                    stack.Add(arguments[argument]);
                    break;
                case VmMeaning.Branch:
                    if (!Target(instruction.Operand, out next))
                        return VmFailure("unconditional branch target is outside the method.");
                    break;
                case VmMeaning.BranchIfLessThan:
                case VmMeaning.BranchIfGreaterOrEqual:
                case VmMeaning.BranchIfGreaterThan:
                case VmMeaning.BranchIfLessOrEqual:
                    if (!Target(instruction.Operand, out var orderedTarget) ||
                        !Pop(out var orderedRight) || !Pop(out var orderedLeft) ||
                        !orderedLeft.IsInteger || !orderedRight.IsInteger)
                        return VmFailure("an ordering branch requires two known integers and a valid target.");
                    if (meaning switch
                        {
                            VmMeaning.BranchIfLessThan => orderedLeft.AsInt64() < orderedRight.AsInt64(),
                            VmMeaning.BranchIfGreaterOrEqual => orderedLeft.AsInt64() >= orderedRight.AsInt64(),
                            VmMeaning.BranchIfGreaterThan => orderedLeft.AsInt64() > orderedRight.AsInt64(),
                            _ => orderedLeft.AsInt64() <= orderedRight.AsInt64()
                        })
                    {
                        next = orderedTarget;
                    }
                    break;
                case VmMeaning.BranchByTable:
                    if (instruction.Operand is not int[] targets || !Pop(out var selector) ||
                        !selector.IsInteger)
                        return VmFailure("switch requires an integer selector.");
                    var selected = selector.AsInt32();
                    if ((uint)selected < (uint)targets.Length)
                    {
                        next = targets[selected];
                        if ((uint)next >= (uint)method.Instructions.Count)
                            return VmFailure("switch target is outside the method.");
                    }
                    break;
                case VmMeaning.BranchIfTrue:
                case VmMeaning.BranchIfFalse:
                    if (!Target(instruction.Operand, out var conditionalTarget) ||
                        !Pop(out var condition) || !TryVmTruth(condition, out var truth))
                        return VmFailure("conditional branch requires a known truth value.");
                    if (meaning == VmMeaning.BranchIfFalse)
                        truth = !truth;
                    if (truth)
                        next = conditionalTarget;
                    break;
                case VmMeaning.Discard:
                    if (!Pop(out _))
                        return VmFailure("pop requires a stack value.");
                    break;
                case VmMeaning.Nothing:
                    break;
                case VmMeaning.BranchIfEqual:
                case VmMeaning.BranchIfNotEqual:
                    if (!Target(instruction.Operand, out var equalTarget) ||
                        !Pop(out var right) || !Pop(out var left) ||
                        !left.IsInteger || !right.IsInteger)
                        return VmFailure("a comparing branch requires two known integers.");
                    if (left.AsInt64() == right.AsInt64() ==
                        (meaning == VmMeaning.BranchIfEqual))
                        next = equalTarget;
                    break;
                case VmMeaning.NewArray:
                    if (instruction.Operand is not int typeToken ||
                        module.ResolveToken(unchecked((uint)typeToken)) is not ITypeDefOrRef arrayType ||
                        !Pop(out var arrayLength) || !arrayLength.IsInteger ||
                        !machine.State.Heap.TryAllocateArray(
                            arrayType.ToTypeSig(), unchecked((int)arrayLength.AsInt64()),
                            out var allocatedArray))
                        return VmFailure("newarr requires a type token and known bounded length.");
                    stack.Add(allocatedArray);
                    break;
                case VmMeaning.Negate:
                    if (!Pop(out var negate) || !negate.IsInteger)
                        return VmFailure("neg requires one known integer.");
                    stack.Add(Held(unchecked(-negate.AsInt64())));
                    break;
                case VmMeaning.LoadStaticField:
                    if (instruction.Operand is not int fieldToken ||
                        module.ResolveToken(unchecked((uint)fieldToken)) is not IField loadedField)
                        return VmFailure("ldsfld token did not resolve to a field.");
                    stack.Add(machine.State.ReadStaticField(loadedField));
                    break;
                case VmMeaning.StoreStaticField:
                    if (instruction.Operand is not int storedFieldToken ||
                        module.ResolveToken(unchecked((uint)storedFieldToken)) is not IField storedField ||
                        !Pop(out var storedValue))
                        return VmFailure("stsfld token or stack value is invalid.");
                    machine.State.WriteStaticField(storedField, storedValue);
                    break;
                case VmMeaning.Duplicate:
                    if (stack.Count == 0)
                        return VmFailure("dup requires a stack value.");
                    stack.Add(stack[^1]);
                    break;
                case VmMeaning.StoreField:
                    if (instruction.Operand is not int instanceFieldToken ||
                        module.ResolveToken(unchecked((uint)instanceFieldToken)) is not IField instanceField ||
                        !Pop(out var instanceFieldValue) || !Pop(out var instanceValue) ||
                        !machine.State.Heap.TryWriteField(
                            instanceValue, instanceField, instanceFieldValue))
                        return VmFailure("stfld requires a modeled instance, field, and value.");
                    break;
                case VmMeaning.ConvertToInt64:
                    if (!Pop(out var converted) || !converted.IsInteger)
                        return VmFailure("conv.i8 requires a known integer.");
                    stack.Add(StaticValue.FromInt64(converted.AsInt64()));
                    break;
                case VmMeaning.Subtract:
                    if (!Pop(out var subtractRight) || !Pop(out var subtractLeft) ||
                        !subtractLeft.IsInteger || !subtractRight.IsInteger ||
                        !TryEvaluateVmIntegerBinary(
                            meaning, subtractLeft.AsInt64(),
                            subtractRight.AsInt64(), out var subtractResult))
                        return VmFailure("sub requires two known integers.");
                    stack.Add(Held(subtractResult));
                    break;
                case VmMeaning.ConvertToInt32:
                    if (!Pop(out var converted32) || !converted32.IsInteger)
                        return VmFailure("conv.i4 requires a known integer.");
                    stack.Add(StaticValue.FromInt32(unchecked((int)converted32.AsInt64())));
                    break;
                case VmMeaning.ConvertToUInt32:
                    if (!Pop(out var convertedUnsigned) || !convertedUnsigned.IsInteger)
                        return VmFailure("conv.u4 requires a known integer.");
                    stack.Add(StaticValue.FromInt64(
                        unchecked((uint)convertedUnsigned.AsInt64())));
                    break;
                case VmMeaning.ArrayLength:
                    if (!Pop(out var sizedValue) ||
                        !machine.State.Heap.TryGetLength(sizedValue, out var length))
                        return VmFailure("ldlen requires a modeled array.");
                    stack.Add(StaticValue.FromInt32(length));
                    break;
                case VmMeaning.StoreElement:
                    if (!Pop(out var element) || !Pop(out var storeIndex) ||
                        !Pop(out var storeArray))
                        return VmFailure(
                            "stelem.i1 requires a modeled array, integer index, and value.");
                    walked[^1] +=
                        $" array={Brief(storeArray)} index={Brief(storeIndex)} value={Brief(element)}";
                    if (!storeIndex.IsInteger ||
                        !machine.State.Heap.TryGetArrayElementReference(
                            storeArray, unchecked((int)storeIndex.AsInt64()), out var storeCell) ||
                        !machine.State.Heap.TryWriteManaged(storeCell, element))
                    {
                        machine.State.Heap.TryGetLength(storeArray, out var storeLength);
                        return VmFailure(
                            $"stelem.i1 rejected array={storeArray.Kind}, " +
                            $"length={storeLength}, index={storeIndex.Kind}/" +
                            $"{(storeIndex.IsInteger ? storeIndex.AsInt64() : -1)}, " +
                            $"value={element.Kind}.");
                    }
                    break;
                case VmMeaning.LoadElement:
                    if (!Pop(out var loadIndex) || !Pop(out var loadArray))
                        return VmFailure(
                            "ldelem.u1 requires a modeled array and integer index.");
                    if (!loadIndex.IsInteger ||
                        !machine.State.Heap.TryGetArrayElementReference(
                            loadArray, unchecked((int)loadIndex.AsInt64()), out var loadCell) ||
                        !machine.State.Heap.TryReadManaged(loadCell, out var loadedElement))
                    {
                        machine.State.Heap.TryGetLength(loadArray, out var loadLength);
                        return VmFailure(
                            $"ldelem.u1 rejected array={loadArray.Kind}, length={loadLength}, " +
                            $"index={loadIndex.Kind}/" +
                            $"{(loadIndex.IsInteger ? loadIndex.AsInt64() : -1)}.");
                    }
                    stack.Add(loadedElement);
                    break;
                case VmMeaning.ExclusiveOr:
                    if (!Pop(out var xorRight) || !Pop(out var xorLeft) ||
                        !xorLeft.IsInteger || !xorRight.IsInteger ||
                        !TryEvaluateVmIntegerBinary(
                            meaning, xorLeft.AsInt64(), xorRight.AsInt64(),
                            out var xorResult))
                        return VmFailure("xor requires two known integers.");
                    stack.Add(Held(xorResult));
                    break;
                case VmMeaning.Add:
                    if (!Pop(out var addRight) || !Pop(out var addLeft) ||
                        !addLeft.IsInteger || !addRight.IsInteger ||
                        !TryEvaluateVmIntegerBinary(
                            meaning, addLeft.AsInt64(), addRight.AsInt64(),
                            out var addResult))
                        return VmFailure("add requires two known integers.");
                    stack.Add(Held(addResult));
                    break;
                case VmMeaning.Multiply:
                    if (!Pop(out var productRight) || !Pop(out var productLeft) ||
                        !productLeft.IsInteger || !productRight.IsInteger ||
                        !TryEvaluateVmIntegerBinary(
                            meaning, productLeft.AsInt64(), productRight.AsInt64(),
                            out var product))
                        return VmFailure("mul requires two known integers.");
                    stack.Add(Held(product));
                    break;
                case VmMeaning.CompareEqual:
                    if (!Pop(out var equalRight) || !Pop(out var equalLeft))
                        return VmFailure("ceq requires two values.");
                    if (!TrySettleSameness(equalLeft, equalRight, out var same))
                    {
                        return VmFailure(
                            $"ceq cannot settle {equalLeft.Kind} against {equalRight.Kind}.");
                    }
                    stack.Add(StaticValue.FromInt32(same ? 1 : 0));
                    break;
                case VmMeaning.Complement:
                    if (!Pop(out var complement) || !complement.IsInteger)
                        return VmFailure("not requires one known integer.");
                    stack.Add(Held(~complement.AsInt64()));
                    break;
                case VmMeaning.ConvertToByte:
                    if (!Pop(out var convertedByte) || !convertedByte.IsInteger)
                        return VmFailure("conv.u1 requires a known integer.");
                    stack.Add(StaticValue.FromInt32(unchecked((byte)convertedByte.AsInt64())));
                    break;
                case VmMeaning.Call:
                    if (instruction.Operand is not int token ||
                        module.ResolveToken(unchecked((uint)token)) is not IMethod called ||
                        called.MethodSig is not { } signature)
                        return VmFailure("call token did not resolve to a method.");
                    var callArguments = new StaticValue[
                        signature.Params.Count + (signature.HasThis ? 1 : 0)];
                    for (var callIndex = callArguments.Length - 1; callIndex >= 0; callIndex--)
                    {
                        if (!Pop(out callArguments[callIndex]))
                            return VmFailure("call consumed more values than the VM stack contains.");
                    }
                    var call = machine.Invoke(called, callArguments);
                    if (!call.Succeeded)
                        return VmFailure(
                            $"call {called.FullName} failed as {call.Status}: {call.Diagnostic}");
                    if (signature.RetType.ElementType != ElementType.Void)
                        stack.Add(call.Value);
                    break;
                case VmMeaning.NewObject:
                    if (instruction.Operand is not int constructorToken ||
                        module.ResolveToken(unchecked((uint)constructorToken)) is not IMethod constructor ||
                        constructor.Name != ".ctor" ||
                        constructor.MethodSig is not { } constructorSignature ||
                        !machine.State.Heap.TryAllocateObject(
                            constructor.DeclaringType.FullName, out var constructed))
                        return VmFailure(
                            "newobj token did not resolve to a constructor of a type that can be made.");
                    var constructorArguments =
                        new StaticValue[constructorSignature.Params.Count + 1];
                    constructorArguments[0] = constructed;
                    for (var constructorIndex = constructorArguments.Length - 1;
                         constructorIndex >= 1;
                         constructorIndex--)
                    {
                        if (!Pop(out constructorArguments[constructorIndex]))
                            return VmFailure(
                                "newobj consumed more values than the VM stack contains.");
                    }
                    var construction = machine.Invoke(constructor, constructorArguments);
                    if (!construction.Succeeded)
                        return VmFailure(
                            $"constructor {constructor.FullName} failed as " +
                            $"{construction.Status}: {construction.Diagnostic}");
                    stack.Add(constructed);
                    break;
                default:
                    return VmFailure($"{meaning} has no evaluator here.");
            }
            if (stack.Count > 0)
                walked[^1] += $" -> {Brief(stack[^1])}";
            pc = next;
            continue;

            (bool Success, int Steps, string Diagnostic) VmFailure(string reason)
            {
                DumpWalk(walked);
                var operand = instruction.Operand is int metadataToken &&
                    (metadataToken & unchecked((int)0xFF000000)) != 0
                        ? module.ResolveToken(unchecked((uint)metadataToken))?.ToString()
                        : null;
                var message =
                    $"Serialized VM ID 0 stopped at instruction {pc}/{method.Instructions.Count}, " +
                    $"opcode {instruction.OpCode} operand " +
                    $"{FormatVmOperand(instruction.Operand)}{(operand is null ? null : $" ({operand})")}" +
                    $", stackDepth={stack.Count}, steps={steps}: {reason} " +
                    $"Trail={string.Join(" ", trail.Select(index =>
                        $"{index}:{method.Instructions[index].OpCode}"))} " +
                    $"Window={string.Join(" ", method.Instructions.Skip(Math.Max(0, pc - 6)).Take(13)
                        .Select((item, relative) =>
                            $"{Math.Max(0, pc - 6) + relative}:{item.OpCode}:" +
                            $"{DescribeVmOperand(module, item.Operand)}"))}";
                return (false, steps, message);
            }
        }

        DumpWalk(walked);
        if (steps >= maximumSteps)
            return (false, steps,
                $"Serialized VM ID 0 exceeded {maximumSteps} evaluator steps.");
        return (true, steps, string.Empty);
    }

    // EXPERIMENT: one value, short enough to sit at the end of a line of the walk.
    private static string Brief(StaticValue value) => value.Kind switch
    {
        StaticValueKind.Int32 or StaticValueKind.Int64 => $"{value.AsInt64()}",
        StaticValueKind.HeapReference => $"heap{value.HeapId}",
        _ => $"{value.Kind}"
    };

    // EXPERIMENT, alongside CILANTRO_VM_NUMBERING: the walk of a reading that stopped is the
    // only way to see which operation it misread, so every exit writes one where asked to.
    private static void DumpWalk(List<string> walked)
    {
        if (Environment.GetEnvironmentVariable("CILANTRO_VM_DUMP") is { Length: > 0 } where)
            File.AppendAllLines(Path.Combine(where, "walked.txt"), walked);
    }

    // EXPERIMENT: the key and the initialization vector are locals of the virtual frame, so the
    // frame at the end of a reading is where a wrong one shows itself.
    private static void DumpLocals(StaticMachine machine, StaticValue[] locals)
    {
        if (Environment.GetEnvironmentVariable("CILANTRO_VM_DUMP") is not { Length: > 0 } where)
            return;
        File.AppendAllLines(Path.Combine(where, "locals.txt"),
            locals.Select((local, index) =>
            {
                var bytes = local.Kind == StaticValueKind.HeapReference
                    ? machine.State.Heap.GetBytesSnapshot(local)
                    : null;
                return $"loc{index} {local.Kind}" +
                    (local.IsInteger ? $" {local.AsInt64()}" : null) +
                    (bytes is null ? null : $" {bytes.Length} bytes {Convert.ToHexString(bytes)}");
            }));
    }

    private static bool TryVmTruth(StaticValue value, out bool truth)
    {
        if (value.IsInteger)
        {
            truth = value.AsInt64() != 0;
            return true;
        }
        if (value.Kind == StaticValueKind.Null)
        {
            truth = false;
            return true;
        }
        if (value.Kind is StaticValueKind.HeapReference or StaticValueKind.NativePointer or
            StaticValueKind.ManagedReference)
        {
            truth = true;
            return true;
        }
        truth = false;
        return false;
    }

    internal static bool TryEvaluateVmIntegerBinary(
        VmMeaning meaning,
        long left,
        long right,
        out long result)
    {
        result = meaning switch
        {
            VmMeaning.ShiftRight => left >> ((int)right & 0x3F),
            VmMeaning.ShiftLeft => unchecked(left << ((int)right & 0x3F)),
            VmMeaning.ExclusiveOr => left ^ right,
            VmMeaning.Subtract => unchecked(left - right),
            VmMeaning.Add => unchecked(left + right),
            VmMeaning.Multiply => unchecked(left * right),
            _ => 0
        };
        return meaning is VmMeaning.ShiftRight or VmMeaning.ShiftLeft or VmMeaning.ExclusiveOr
            or VmMeaning.Subtract or VmMeaning.Add or VmMeaning.Multiply;
    }

    /// <summary>
    /// Whether two values are the same value, where being the same is a question this can answer.
    /// </summary>
    /// <remarks>
    /// Two numbers are the same when they are equal, and two references when they are the same
    /// reference — which for the objects modelled here they are exactly when they were allocated
    /// together, since nothing folds two allocations into one. Anything unknown makes the answer
    /// unknown rather than false: a comparison of something we could not read is not a comparison
    /// that failed.
    /// </remarks>
    private static bool TrySettleSameness(StaticValue left, StaticValue right, out bool same)
    {
        same = false;
        if (left.IsInteger && right.IsInteger)
        {
            same = left.AsInt64() == right.AsInt64();
            return true;
        }
        if (left.Kind == StaticValueKind.Unknown || right.Kind == StaticValueKind.Unknown)
            return false;
        if (left.Kind is StaticValueKind.Null or StaticValueKind.HeapReference &&
            right.Kind is StaticValueKind.Null or StaticValueKind.HeapReference)
        {
            same = left.Kind == right.Kind &&
                (left.Kind == StaticValueKind.Null || left.HeapId == right.HeapId);
            return true;
        }
        return false;
    }

    internal static bool TryEvaluateVmControlFlow(
        VmMeaning meaning,
        out int handlerInstructionPointer,
        out bool returns)
    {
        var ends = meaning == VmMeaning.Return;
        handlerInstructionPointer = ends ? -3 : 0;
        returns = ends && handlerInstructionPointer + 1 <= -2;
        return ends;
    }

    private static int ReadVmInteger(byte[] bytes, ref int cursor)
    {
        if ((uint)cursor >= (uint)bytes.Length)
            throw new EndOfStreamException();
        var first = bytes[cursor++];
        var negative = (first & 0x40) != 0;
        var value = first & 0x3F;
        var shift = 6;
        var current = first;
        while ((current & 0x80) != 0)
        {
            if ((uint)cursor >= (uint)bytes.Length || shift > 27)
                throw new InvalidDataException("Invalid signed VM integer.");
            current = bytes[cursor++];
            value |= (current & 0x7F) << shift;
            shift += 7;
        }
        return negative ? ~value : value;
    }

    private static long ReadFixedInt64(byte[] bytes, ref int cursor)
    {
        if (cursor < 0 || cursor > bytes.Length - sizeof(long))
            throw new EndOfStreamException();
        var value = BitConverter.ToInt64(bytes, cursor);
        cursor += sizeof(long);
        return value;
    }

    private static uint ReadFixedUInt32(byte[] bytes, ref int cursor)
    {
        if (cursor < 0 || cursor > bytes.Length - sizeof(uint))
            throw new EndOfStreamException();
        var value = BitConverter.ToUInt32(bytes, cursor);
        cursor += sizeof(uint);
        return value;
    }

    private static int[] ReadVmIntegerArray(byte[] bytes, ref int cursor)
    {
        var count = ReadVmInteger(bytes, ref cursor);
        if (count < 0 || count > 1_000_000)
            throw new InvalidDataException("VM integer-array length is outside bounds.");
        var values = new int[count];
        for (var index = 0; index < count; index++)
            values[index] = ReadVmInteger(bytes, ref cursor);
        return values;
    }

    private static string FormatVmOperand(object? operand) => operand switch
    {
        null => "-",
        int[] values => $"[{string.Join(",", values)}]",
        _ => Convert.ToString(operand, System.Globalization.CultureInfo.InvariantCulture) ?? "-"
    };

    private static string DescribeVmOperand(ModuleDefMD module, object? operand)
    {
        if (operand is int token && (token & unchecked((int)0xFF000000)) != 0)
            return $"{token}<{module.ResolveToken(unchecked((uint)token))}>";
        return FormatVmOperand(operand);
    }

    private sealed class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        public static ByteArrayComparer Instance { get; } = new();
        public bool Equals(byte[]? x, byte[]? y) =>
            x is not null && y is not null && x.AsSpan().SequenceEqual(y);
        public int GetHashCode(byte[] obj)
        {
            var hash = new HashCode();
            foreach (var value in obj)
                hash.Add(value);
            return hash.ToHashCode();
        }
    }

    private static IReadOnlyList<StaticValue>? BuildArguments(
        StaticMachine machine,
        MethodDef initializer,
        StaticValue stream,
        int offset)
    {
        var parameters = initializer.MethodSig?.Params;
        if (parameters is null || parameters.Count != 2 || !initializer.IsStatic ||
            parameters[1].ElementType != ElementType.I4)
            return null;
        return [stream, StaticValue.FromInt32(offset)];
    }

    private static MethodDef? FindInitializer(MethodDef resolver)
    {
        var instructions = resolver.Body.Instructions;
        for (var index = 0; index < instructions.Count; index++)
        {
            if (instructions[index].Operand is not IMethod called ||
                called.ResolveMethodDef() is not { } definition ||
                definition.Module != resolver.Module ||
                !definition.IsStatic ||
                definition.MethodSig?.Params.Count != 2 ||
                definition.MethodSig.Params[1].ElementType != ElementType.I4 ||
                definition.ReturnType.ElementType != ElementType.Void)
                continue;
            if (index > 0 && instructions[index - 1].OpCode.Code is
                    Code.Ldarg or Code.Ldarg_S or Code.Ldarg_0)
                return definition;
        }
        return null;
    }

    private static string? FindResourceName(MethodDef resolver)
    {
        var instructions = resolver.Body.Instructions;
        for (var index = 0; index < instructions.Count; index++)
        {
            if (instructions[index].Operand is not IMethod method ||
                method.Name != "GetManifestResourceStream")
                continue;
            for (var previous = index - 1; previous >= Math.Max(0, index - 4); previous--)
            {
                if (instructions[previous].OpCode.Code == Code.Ldstr)
                    return instructions[previous].Operand as string;
            }
        }
        return null;
    }

    private static bool IsVmBridge(MethodDef initializer) =>
        initializer.Body.Instructions.Any(instruction =>
            instruction.Operand is IMethod method &&
            method.MethodSig?.Params.Count == 3 &&
            method.MethodSig.RetType is SZArraySig { Next: { ElementType: ElementType.Object } });

    private sealed class ProxyIntrinsicRegistry : IStaticIntrinsicRegistry
    {
        private readonly IStaticIntrinsicRegistry _defaults;
        private readonly IReadOnlyDictionary<string, IMethod> _targets;
        private readonly IReadOnlyList<(FieldDef Field, IMethod Target)> _bindings;
        private readonly ModuleDefMD _module;

        private ProxyIntrinsicRegistry(
            IStaticIntrinsicRegistry defaults,
            IReadOnlyDictionary<string, IMethod> targets,
            IReadOnlyList<(FieldDef Field, IMethod Target)> bindings,
            ModuleDefMD module)
        {
            _defaults = defaults;
            _targets = targets;
            _bindings = bindings;
            _module = module;
        }

        /// <summary>
        /// A registry knowing every proxy binding the caller could account for.
        /// </summary>
        /// <param name="known">
        /// Bindings the caller already has, which on a build the structural search cannot read is
        /// the only way it has them: the map was read out of the table the loader built rather than
        /// decoded from the resource behind it. Used in preference to nothing, and ignored where
        /// decoding the resource worked, because then the two say the same thing.
        /// </param>
        public static ProxyIntrinsicRegistry Create(
            ModuleDefMD module,
            IReadOnlyList<ProxyBinding>? known = null)
        {
            var targets = new Dictionary<string, IMethod>(StringComparer.Ordinal);
            var bindings = new List<(FieldDef, IMethod)>();
            var facts = ReactorStructureDetector.Analyze(module);
            var accounted =
                StructuralStreamDiscovery.TryDiscoverProxyProfile(module, facts, out var profile) &&
                profile is not null
                    ? profile.Bindings
                    : known ?? [];
            foreach (var binding in accounted)
            {
                if (module.ResolveToken(binding.FieldToken) is not FieldDef field ||
                    module.ResolveToken(binding.TargetToken) is not IMethod target)
                    continue;
                bindings.Add((field, target));
                var delegateType = field.FieldSig?.Type.RemovePinnedAndModifiers().FullName;
                if (!string.IsNullOrEmpty(delegateType))
                    targets.TryAdd(delegateType, target);
            }
            return new ProxyIntrinsicRegistry(
                StaticIntrinsicRegistry.CreateDefault(), targets, bindings, module);
        }

        /// <summary>
        /// Puts each decoded proxy delegate in the field the module reads it from.
        /// </summary>
        /// <remarks>
        /// A build gives one delegate type to every call of a given signature and one field to every
        /// call site, so a hundred fields can share a type and stand for a hundred different methods.
        /// The field is therefore the only thing that says which method a call meant, and it is known
        /// here: the proxy resource was decoded before the run started. Seeding the fields lets the
        /// object a call site loads carry its own answer, so the delegate the module invokes and the
        /// method the machine runs are the same one.
        ///
        /// Without this the run would have to guess the target from the delegate's type, which is
        /// right only for a type used once and silently wrong the rest of the time. Nothing about the
        /// module is assumed: a field left unseeded is one the decoder did not account for, and a call
        /// through it still stops rather than being sent somewhere plausible.
        /// </remarks>
        public void Bind(StaticMachine machine)
        {
            foreach (var (field, target) in _bindings)
            {
                if (!machine.State.Heap.TryAllocateObject(
                        field.FieldSig?.Type.RemovePinnedAndModifiers().FullName ?? "System.Delegate",
                        out var bound))
                {
                    return;
                }

                machine.State.Heap.TrySetModelValue(bound, ProxyTargetKey, target);
                machine.State.WriteStaticField(field, bound);
            }
        }

        /// <summary>What a seeded proxy delegate remembers about the method it stands for.</summary>
        /// <remarks>
        /// Deliberately not the key the machine puts on delegates it watched being constructed. Those
        /// carry a receiver and are called with it prepended; these are what
        /// <c>Delegate.CreateDelegate</c> returns for a method resolved from a token, where the
        /// instance, if there is one, is the first of the invocation's own arguments. Sharing a key
        /// would invite the machine to call one as though it were the other.
        /// </remarks>
        internal const string ProxyTargetKey = "ReactorProxyTarget";

        public bool TryResolve(IMethod method, out IStaticIntrinsic intrinsic)
        {
            if (method.Name == "Invoke" &&
                _targets.TryGetValue(method.DeclaringType.FullName, out var target))
            {
                intrinsic = new ProxyIntrinsic(_defaults, target, _module);
                return true;
            }
            if (method.DeclaringType.FullName.StartsWith(
                    "System.Collections.Generic.List`1", StringComparison.Ordinal) ||
                method.DeclaringType.FullName.StartsWith(
                    "System.Collections.Generic.Dictionary`2", StringComparison.Ordinal))
            {
                intrinsic = new CollectionIntrinsic();
                return true;
            }
            if (method.DeclaringType.FullName.StartsWith(
                    "System.Comparison`1", StringComparison.Ordinal) &&
                method.Name == ".ctor")
            {
                intrinsic = new DelegateConstructionIntrinsic();
                return true;
            }
            if (method.DeclaringType.FullName == "System.Reflection.Assembly" &&
                method.Name == "get_EntryPoint")
            {
                intrinsic = new AssemblyEntryPointIntrinsic(_module);
                return true;
            }
            if (method.DeclaringType.FullName == "System.Reflection.MethodInfo" &&
                method.Name == "op_Equality")
            {
                intrinsic = new MethodInfoEqualityIntrinsic();
                return true;
            }
            return _defaults.TryResolve(method, out intrinsic);
        }
    }

    private sealed class MethodInfoEqualityIntrinsic : IStaticIntrinsic
    {
        public bool Matches(IMethod method) => true;

        public IntrinsicResult Invoke(
            IntrinsicContext context,
            IMethod method,
            IReadOnlyList<StaticValue> arguments)
        {
            if (arguments.Count != 2)
                return IntrinsicResult.Invalid("MethodInfo equality arguments are invalid.");
            if (arguments[0].Kind == StaticValueKind.Null ||
                arguments[1].Kind == StaticValueKind.Null)
                return IntrinsicResult.Completed(StaticValue.FromInt32(
                    arguments[0].Kind == arguments[1].Kind ? 1 : 0));
            if (!context.State.Heap.TryGetMetadataHandle(arguments[0], out var left) ||
                !context.State.Heap.TryGetMetadataHandle(arguments[1], out var right))
                return IntrinsicResult.Invalid(
                    "MethodInfo equality requires modeled metadata handles.");
            return IntrinsicResult.Completed(
                StaticValue.FromInt32(Equals(left, right) ? 1 : 0));
        }
    }

    private sealed class AssemblyEntryPointIntrinsic(ModuleDefMD module) : IStaticIntrinsic
    {
        public bool Matches(IMethod method) => true;

        public IntrinsicResult Invoke(
            IntrinsicContext context,
            IMethod method,
            IReadOnlyList<StaticValue> arguments)
        {
            if (arguments.Count != 1)
                return IntrinsicResult.Invalid("Assembly.EntryPoint arguments are invalid.");
            if (module.EntryPoint is null)
                return IntrinsicResult.Completed(StaticValue.Null);
            return context.State.Heap.TryAllocateMetadataHandle(
                module.EntryPoint, out var entryPoint)
                ? IntrinsicResult.Completed(entryPoint)
                : new IntrinsicResult(
                    StaticExecutionStatus.AllocationLimitExceeded,
                    StaticValue.Unknown,
                    "Assembly entry-point metadata exceeded the allocation budget.");
        }
    }

    private sealed class DelegateConstructionIntrinsic : IStaticIntrinsic
    {
        public bool Matches(IMethod method) => true;

        public IntrinsicResult Invoke(
            IntrinsicContext context,
            IMethod method,
            IReadOnlyList<StaticValue> arguments)
        {
            if (arguments.Count != 3)
                return IntrinsicResult.Invalid("Delegate constructor arguments are invalid.");
            context.State.Heap.TrySetModelValue(arguments[0], "Target", arguments[1]);
            context.State.Heap.TrySetModelValue(arguments[0], "Method", arguments[2]);
            return IntrinsicResult.Completed();
        }
    }

    private sealed class CollectionIntrinsic : IStaticIntrinsic
    {
        public bool Matches(IMethod method) => true;

        public IntrinsicResult Invoke(
            IntrinsicContext context,
            IMethod method,
            IReadOnlyList<StaticValue> arguments)
        {
            if (arguments.Count == 0)
                return IntrinsicResult.Invalid("A collection invocation has no instance.");
            var heap = context.State.Heap;
            var dictionary = method.DeclaringType.FullName.StartsWith(
                "System.Collections.Generic.Dictionary`2", StringComparison.Ordinal);
            var name = method.Name.String;
            if (name == ".ctor")
            {
                heap.TrySetModelValue(arguments[0], "Items",
                    dictionary ? new Dictionary<StaticValue, StaticValue>() : new List<StaticValue>());
                return IntrinsicResult.Completed();
            }
            if (dictionary &&
                heap.TryGetModelValue(arguments[0], "Items",
                    out Dictionary<StaticValue, StaticValue>? map) &&
                map is not null)
            {
                if (name == "get_Count")
                    return IntrinsicResult.Completed(StaticValue.FromInt32(map.Count));
                if (name == "Add" && arguments.Count == 3)
                {
                    map.Add(arguments[1], arguments[2]);
                    return IntrinsicResult.Completed();
                }
                if (name == "set_Item" && arguments.Count == 3)
                {
                    map[arguments[1]] = arguments[2];
                    return IntrinsicResult.Completed();
                }
                if (name == "get_Item" && arguments.Count == 2 &&
                    map.TryGetValue(arguments[1], out var value))
                    return IntrinsicResult.Completed(value);
                if (name == "ContainsKey" && arguments.Count == 2)
                    return IntrinsicResult.Completed(StaticValue.FromInt32(
                        map.ContainsKey(arguments[1]) ? 1 : 0));
                if (name == "TryGetValue" && arguments.Count == 3)
                {
                    var found = map.TryGetValue(arguments[1], out value);
                    if (!heap.TryWriteManaged(
                            arguments[2], found ? value : StaticValue.Unknown))
                        return IntrinsicResult.Invalid("Dictionary out argument is invalid.");
                    return IntrinsicResult.Completed(StaticValue.FromInt32(found ? 1 : 0));
                }
                if (name == "Clear")
                {
                    map.Clear();
                    return IntrinsicResult.Completed();
                }
            }
            if (!dictionary &&
                heap.TryGetModelValue(arguments[0], "Items", out List<StaticValue>? list) &&
                list is not null)
            {
                if (name == "get_Count")
                    return IntrinsicResult.Completed(StaticValue.FromInt32(list.Count));
                if (name == "Add" && arguments.Count == 2)
                {
                    list.Add(arguments[1]);
                    return IntrinsicResult.Completed();
                }
                if (name == "get_Item" && arguments.Count == 2 &&
                    (uint)arguments[1].AsInt32() < (uint)list.Count)
                    return IntrinsicResult.Completed(list[arguments[1].AsInt32()]);
                if (name == "set_Item" && arguments.Count == 3 &&
                    (uint)arguments[1].AsInt32() < (uint)list.Count)
                {
                    list[arguments[1].AsInt32()] = arguments[2];
                    return IntrinsicResult.Completed();
                }
                if (name == "Clear")
                {
                    list.Clear();
                    return IntrinsicResult.Completed();
                }
                if (name == "RemoveAt" && arguments.Count == 2 &&
                    (uint)arguments[1].AsInt32() < (uint)list.Count)
                {
                    list.RemoveAt(arguments[1].AsInt32());
                    return IntrinsicResult.Completed();
                }
                if (name == "Remove" && arguments.Count == 2)
                    return IntrinsicResult.Completed(StaticValue.FromInt32(
                        list.Remove(arguments[1]) ? 1 : 0));
                if (name == "Insert" && arguments.Count == 3 &&
                    (uint)arguments[1].AsInt32() <= (uint)list.Count)
                {
                    list.Insert(arguments[1].AsInt32(), arguments[2]);
                    return IntrinsicResult.Completed();
                }
                if (name == "Sort" && arguments.Count == 2)
                    return IntrinsicResult.Completed();
            }
            return IntrinsicResult.Invalid($"Unsupported collection operation {method.FullName}.");
        }
    }

    private sealed class ProxyIntrinsic(
        IStaticIntrinsicRegistry defaults,
        IMethod fallback,
        ModuleDefMD module) : IStaticIntrinsic
    {
        public bool Matches(IMethod method) => true;

        /// <summary>
        /// Which reflection type the runtime would hand back for a resolved token.
        /// </summary>
        /// <remarks>
        /// <c>ResolveMethod</c> is declared as returning a <c>MethodBase</c> and never returns one:
        /// what comes back is a <c>ConstructorInfo</c> or a <c>MethodInfo</c>, and the caller casts to
        /// whichever it expects. Modelling the declared type instead of the real one makes every such
        /// cast fail, which is worse than it sounds — the failure is a null the program then works
        /// with, so the run continues and breaks somewhere with no connection to this call. The token
        /// says which of the two it is, so there is nothing to guess.
        /// </remarks>
        private static string Reflected(object resolved) => resolved switch
        {
            TypeDef or TypeRef or TypeSpec => "System.Type",
            FieldDef or MemberRef { IsFieldRef: true } => "System.Reflection.FieldInfo",
            MethodDef { IsConstructor: true } or
                MemberRef { IsMethodRef: true, Name.String: ".ctor" or ".cctor" } =>
                "System.Reflection.ConstructorInfo",
            MethodDef or MethodSpec or MemberRef { IsMethodRef: true } =>
                "System.Reflection.MethodInfo",
            _ => "System.Reflection.MemberInfo"
        };

        public IntrinsicResult Invoke(
            IntrinsicContext context,
            IMethod method,
            IReadOnlyList<StaticValue> arguments)
        {
            if (arguments.Count == 0)
                return IntrinsicResult.Invalid("A proxy invocation has no delegate instance.");
            var forwarded = arguments.Skip(1).ToArray();
            // The delegate itself knows what it was bound to whenever it came from a seeded field,
            // which is the only account of this call that distinguishes it from every other call of
            // the same signature. Its type is a last resort, and correct only where the build gave
            // that type a single binding.
            var target =
                context.State.Heap.TryGetModelValue<IMethod>(
                    arguments[0], ProxyIntrinsicRegistry.ProxyTargetKey, out var declared) &&
                declared is not null
                    ? declared
                    : fallback;
            if (target.DeclaringType.FullName == "System.Threading.Monitor")
            {
                if (target.Name == "Enter" && forwarded.Length == 2 &&
                    context.State.Heap.TryWriteManaged(
                        forwarded[1], StaticValue.FromInt32(1)))
                    return IntrinsicResult.Completed();
                if (target.Name == "Exit" && forwarded.Length == 1)
                    return IntrinsicResult.Completed();
                return IntrinsicResult.Invalid(
                    $"Unsupported Monitor proxy target {target.FullName}.");
            }
            if (target.DeclaringType.FullName == "System.Type" &&
                target.Name == "get_Assembly" && forwarded.Length == 1)
            {
                return context.State.Heap.TryAllocateObject(
                    "System.Reflection.Assembly", out var assembly)
                    ? IntrinsicResult.Completed(assembly)
                    : new IntrinsicResult(
                        StaticExecutionStatus.AllocationLimitExceeded,
                        StaticValue.Unknown,
                        "Assembly model exceeded the allocation budget.");
            }
            if (target.DeclaringType.FullName == "System.Type" &&
                target.Name == "get_Module" && forwarded.Length == 1)
            {
                if (!context.State.Heap.TryAllocateObject(
                        "System.Reflection.Module", out var moduleObject))
                    return new IntrinsicResult(
                        StaticExecutionStatus.AllocationLimitExceeded,
                        StaticValue.Unknown,
                        "Module model exceeded the allocation budget.");
                context.State.Heap.TrySetModelValue(moduleObject, "ModuleDef", module);
                return IntrinsicResult.Completed(moduleObject);
            }
            var targetName = target.Name.String;
            if (target.DeclaringType.FullName == "System.Reflection.Module" &&
                (targetName == "op_Equality" || targetName == "op_Inequality") &&
                forwarded.Length == 2)
            {
                var equal = forwarded[0].Kind == forwarded[1].Kind &&
                    forwarded[0].Bits == forwarded[1].Bits;
                if (targetName == "op_Inequality")
                    equal = !equal;
                return IntrinsicResult.Completed(StaticValue.FromInt32(equal ? 1 : 0));
            }
            if (target.DeclaringType.FullName == "System.Reflection.Module" &&
                targetName is not null &&
                targetName.StartsWith("Resolve", StringComparison.Ordinal) &&
                forwarded.Length >= 2 &&
                forwarded[1].IsInteger)
            {
                var resolved = module.ResolveToken(unchecked((uint)forwarded[1].AsInt32()));
                if (resolved is null)
                    return IntrinsicResult.Invalid(
                        $"Metadata token 0x{forwarded[1].AsInt32():X8} did not resolve.");
                var runtimeType = targetName switch
                {
                    "ResolveMethod" or "ResolveMember" => Reflected(resolved),
                    "ResolveField" => "System.Reflection.FieldInfo",
                    "ResolveType" => "System.Type",
                    _ => string.Empty
                };
                if (runtimeType.Length == 0 ||
                    !context.State.Heap.TryAllocateObject(runtimeType, out var member))
                    return IntrinsicResult.Invalid(
                        $"Unsupported module resolution operation {target.FullName}.");
                context.State.Heap.TrySetModelValue(member, "Metadata", resolved);
                return IntrinsicResult.Completed(member);
            }
            if (target.DeclaringType.FullName == "System.Reflection.MethodBase" &&
                targetName == "GetParameters" && forwarded.Length == 1 &&
                context.State.Heap.TryGetModelValue(
                    forwarded[0], "Metadata", out object? methodMetadata) &&
                methodMetadata is IMethod reflectedMethod)
            {
                var parameters = reflectedMethod.MethodSig?.Params ?? [];
                if (!context.State.Heap.TryAllocateArray(
                        null, parameters.Count, out var parameterArray))
                    return new IntrinsicResult(
                        StaticExecutionStatus.AllocationLimitExceeded,
                        StaticValue.Unknown,
                        "Parameter array exceeded the allocation budget.");
                for (var index = 0; index < parameters.Count; index++)
                {
                    if (!context.State.Heap.TryAllocateObject(
                            "System.Reflection.ParameterInfo", out var parameter))
                        return new IntrinsicResult(
                            StaticExecutionStatus.AllocationLimitExceeded,
                            StaticValue.Unknown,
                            "Parameter model exceeded the allocation budget.");
                    context.State.Heap.TrySetModelValue(
                        parameter, "ParameterType", parameters[index]);
                    context.State.Heap.TryWriteArray(parameterArray, index, parameter);
                }
                return IntrinsicResult.Completed(parameterArray);
            }
            if (target.DeclaringType.FullName == "System.Reflection.MethodBase" &&
                targetName == "get_IsStatic" && forwarded.Length == 1 &&
                context.State.Heap.TryGetModelValue(
                    forwarded[0], "Metadata", out object? staticMetadata) &&
                staticMetadata is IMethod staticMethod)
            {
                return IntrinsicResult.Completed(StaticValue.FromInt32(
                    staticMethod.ResolveMethodDef()?.IsStatic == true ? 1 : 0));
            }
            if (target.DeclaringType.FullName == "System.Reflection.ParameterInfo" &&
                targetName == "get_ParameterType" && forwarded.Length == 1 &&
                context.State.Heap.TryGetModelValue(
                    forwarded[0], "ParameterType", out TypeSig? parameterType) &&
                parameterType is not null)
                return AllocateRuntimeType(context, parameterType);
            if (target.DeclaringType.FullName == "System.Type" &&
                forwarded.Length == 1 &&
                context.State.Heap.TryGetModelValue(
                    forwarded[0], "Metadata", out object? typeMetadata) &&
                typeMetadata is TypeSig typeSignature)
            {
                if (targetName == "get_IsByRef")
                    return IntrinsicResult.Completed(StaticValue.FromInt32(
                        typeSignature is ByRefSig ? 1 : 0));
                if (targetName == "get_IsValueType")
                    return IntrinsicResult.Completed(StaticValue.FromInt32(
                        typeSignature.IsValueType ? 1 : 0));
                if (targetName == "get_IsEnum")
                    return IntrinsicResult.Completed(StaticValue.FromInt32(
                        typeSignature.ToTypeDefOrRef()?.ResolveTypeDef()?.IsEnum == true ? 1 : 0));
                if (targetName == "get_IsArray")
                    return IntrinsicResult.Completed(StaticValue.FromInt32(
                        typeSignature is ArraySig or SZArraySig ? 1 : 0));
                if (targetName == "get_IsPointer")
                    return IntrinsicResult.Completed(StaticValue.FromInt32(
                        typeSignature is PtrSig ? 1 : 0));
                if (targetName == "get_IsPrimitive")
                    return IntrinsicResult.Completed(StaticValue.FromInt32(
                        typeSignature.ElementType is >= ElementType.Boolean and <= ElementType.R8
                            or ElementType.I or ElementType.U ? 1 : 0));
                if (targetName is "get_FullName" or "get_Name")
                {
                    var typeName = targetName == "get_Name"
                        ? typeSignature.TypeName
                        : typeSignature.FullName;
                    return context.State.Heap.TryAllocateString(typeName, out var nameValue)
                        ? IntrinsicResult.Completed(nameValue)
                        : new IntrinsicResult(
                            StaticExecutionStatus.AllocationLimitExceeded,
                            StaticValue.Unknown,
                            "Type name exceeded the allocation budget.");
                }
                if (targetName == "GetElementType" &&
                    typeSignature.Next is { } elementType)
                    return AllocateRuntimeType(context, elementType);
            }
            if (target.DeclaringType.FullName == "System.Type" &&
                forwarded.Length == 1 &&
                context.State.Heap.TryGetModelValue(
                    forwarded[0], "TypeName", out string? modeledTypeName) &&
                modeledTypeName is not null)
            {
                if (targetName is "get_IsByRef" or "get_IsValueType" or
                    "get_IsEnum" or "get_IsArray" or "get_IsPointer" or
                    "get_IsPrimitive")
                    return IntrinsicResult.Completed(StaticValue.FromInt32(0));
                if (targetName is "get_FullName" or "get_Name")
                {
                    var value = targetName == "get_Name"
                        ? modeledTypeName[(modeledTypeName.LastIndexOf('.') + 1)..]
                        : modeledTypeName;
                    return context.State.Heap.TryAllocateString(value, out var typeNameValue)
                        ? IntrinsicResult.Completed(typeNameValue)
                        : new IntrinsicResult(
                            StaticExecutionStatus.AllocationLimitExceeded,
                            StaticValue.Unknown,
                            "Type name exceeded the allocation budget.");
                }
                if (targetName == "GetElementType")
                    return IntrinsicResult.Completed(StaticValue.Null);
            }
            if (target.DeclaringType.FullName == "System.Nullable" &&
                targetName == "GetUnderlyingType" &&
                forwarded.Length == 1)
            {
                if (context.State.Heap.TryGetModelValue(
                        forwarded[0], "Metadata", out object? nullableMetadata) &&
                    nullableMetadata is GenericInstSig nullable &&
                    nullable.GenericType.TypeDefOrRef.FullName == "System.Nullable`1" &&
                    nullable.GenericArguments.Count == 1)
                {
                    return AllocateRuntimeType(context, nullable.GenericArguments[0]);
                }
                return IntrinsicResult.Completed(StaticValue.Null);
            }
            if (!defaults.TryResolve(target, out var intrinsic))
            {
                // Not every proxy stands in front of the framework. A build can route one of its
                // own methods through the same delegate, and that method is not something to model:
                // it is in the file, so the machine runs it as it would any other call — including
                // when the delegate names an abstract method and the object decides what runs.
                if (target.ResolveMethodDef() is not null && context.Call is { } call)
                    return call(target, forwarded);
                return IntrinsicResult.Invalid(
                    $"Proxy target {target.FullName} is not a supported static intrinsic.");
            }
            return intrinsic.Invoke(context, target, forwarded);
        }

        private static IntrinsicResult AllocateRuntimeType(
            IntrinsicContext context,
            TypeSig signature)
        {
            if (!context.State.Heap.TryAllocateObject("System.Type", out var type))
                return new IntrinsicResult(
                    StaticExecutionStatus.AllocationLimitExceeded,
                    StaticValue.Unknown,
                    "Runtime type model exceeded the allocation budget.");
            context.State.Heap.TrySetModelValue(type, "Metadata", signature);
            return IntrinsicResult.Completed(type);
        }
    }
}
