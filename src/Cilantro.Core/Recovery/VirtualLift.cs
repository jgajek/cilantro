using System.Globalization;
using dnlib.DotNet;

namespace Cilantro.Core.Recovery;

/// <summary>
/// Writes a virtualized program out as the IL it stands for, as far as that is established.
/// </summary>
/// <remarks>
/// This is a reading rather than a decompilation, and it is deliberately kept to a report. A
/// method body that is nearly right is worse than none: an analyst who is told a program does
/// something it does not will act on it, whereas one who is told an operation is unknown will go
/// and look. So every operation whose meaning was not established is written as <c>??</c> with
/// whatever was counted about it, and nothing here is ever put back into the cleaned assembly.
/// <see cref="VirtualBody"/> will build these readings into a body on request, into an assembly of
/// its own that is marked for what it is.
///
/// What can be said is said in the assembly's own terms. The operations that were named map onto
/// ordinary IL, and the operands that turned out to be metadata tokens name the methods, fields and
/// types the hidden code reaches for. Depths are walked alongside, since a listing whose stack does
/// not add up is a listing with a mistake in it, and it is better for the file to say so than for a
/// reader to find out later.
/// </remarks>
public static class VirtualLift
{
    /// <summary>How the named effects appear in IL, where they have an ordinary name there.</summary>
    private static readonly Dictionary<string, string> Mnemonics = new(StringComparer.Ordinal)
    {
        ["pushes its operand"] = "ldc.i4",
        ["loads what its operand indexes"] = "ldloc",
        ["stores where its operand indexes"] = "stloc",
        ["loads the argument it indexes"] = "ldarg",
        ["stores into the argument it indexes"] = "starg",
        ["reads the static field it names"] = "ldsfld",
        ["writes the static field it names"] = "stsfld",
        ["reads the field it names"] = "ldfld",
        ["writes the field it names"] = "stfld",
        ["reads an array element"] = "ldelem",
        ["writes an array element"] = "stelem",
        ["array length"] = "ldlen",
        ["makes an array of the type it names"] = "newarr",
        ["calls the method it names"] = "call",
        ["makes a new object with the constructor it names"] = "newobj",
        ["branch"] = "br",
        ["branch if"] = "br.cond",
        ["branch by table"] = "switch",
        ["dup"] = "dup",
        ["convert"] = "conv.?",
        ["pushes nothing at all"] = "ldnull",
        ["discards what it takes"] = "pop",
        ["does nothing at all"] = "nop",
        ["returns the value it takes"] = "ret",
        ["stops the program"] = "ret",
        [VirtualSemantics.Throwing] = "throw",
        [VirtualSemantics.Ending] = "endfinally",
        ["add"] = "add",
        ["sub"] = "sub",
        ["mul"] = "mul",
        ["div"] = "div",
        ["rem"] = "rem",
        ["and"] = "and",
        ["or"] = "or",
        ["xor"] = "xor",
        ["shl"] = "shl",
        ["shr"] = "shr",
        ["neg"] = "neg",
        ["not"] = "not",
        ["ceq"] = "ceq",
        ["cgt"] = "cgt",
        ["clt"] = "clt"
    };

    /// <summary>
    /// The IL each named effect becomes once the type of the value it makes is known.
    /// </summary>
    /// <remarks>
    /// A constant and a conversion are the two places where the listing would otherwise throw away
    /// what the recovery established. Every other operation's types follow from these and from the
    /// signatures of the methods it calls, so these are the two worth spelling out.
    /// </remarks>
    private static readonly Dictionary<string, string> Widths = new(StringComparer.Ordinal)
    {
        ["System.SByte"] = "i1",
        ["System.Byte"] = "u1",
        ["System.Int16"] = "i2",
        ["System.UInt16"] = "u2",
        ["System.Char"] = "u2",
        ["System.Int32"] = "i4",
        ["System.UInt32"] = "u4",
        ["System.Int64"] = "i8",
        ["System.UInt64"] = "u8",
        ["System.Single"] = "r4",
        ["System.Double"] = "r8",
        ["System.IntPtr"] = "i",
        ["System.UIntPtr"] = "u"
    };

    /// <summary>Says a constant or a conversion in the width the recovery established for it.</summary>
    private static string? Widened(
        VirtualProgram program,
        VirtualInstruction instruction,
        string? mnemonic)
    {
        if (mnemonic is not ("ldc.i4" or "conv.?"))
            return mnemonic;

        // What the instruction itself carries beats what the operation was seen doing, being a fact
        // about this one place in the program rather than about the operations of its kind.
        var carried = instruction.Operand is VirtualOperand.Number { Type: { } written }
            ? written
            : null;
        if (!program.Operations.TryGetValue(instruction.Opcode, out var operation) ||
            (carried ?? operation.Pushed) is not { } pushed)
        {
            return mnemonic;
        }
        if (mnemonic == "ldc.i4")
        {
            return pushed switch
            {
                "System.String" => "ldstr",
                "System.Int64" or "System.UInt64" => "ldc.i8",
                "System.Single" => "ldc.r4",
                "System.Double" => "ldc.r8",
                _ => mnemonic
            };
        }
        return Widths.TryGetValue(pushed, out var width) ? $"conv.{width}" : mnemonic;
    }

    /// <summary>The mnemonics whose operand is a place in the program rather than a value.</summary>
    private static readonly HashSet<string> Jumps =
        new(StringComparer.Ordinal) { "br", "br.cond", "switch" };

    /// <summary>Whether an operation hands the path on to somewhere other than the next operation.</summary>
    private static bool Leaps(string? name) =>
        name is "branch" or "branch if" or "branch by table";

    /// <summary>Whether the operation after it is one of the places it can hand the path to.</summary>
    /// <remarks>
    /// Every jump but the unconditional one falls through as well, the table jump included: a value
    /// its table has no place for leaves the position where it was, which is the next operation.
    /// </remarks>
    private static bool Falls(string? name) => name is not "branch";

    /// <summary>One operation of a program, as everything established about it leaves it.</summary>
    /// <param name="Index">Where it sits in the program, which is what a jump names.</param>
    /// <param name="Mnemonic">The IL it stands for, or null where nothing established one.</param>
    /// <param name="Operand">What it carries, in the form the engine decoded it to.</param>
    /// <param name="Targets">Everywhere it can hand the path to, for an operation that jumps.</param>
    /// <param name="Conjectured">Whether those places were read off it rather than watched.</param>
    /// <param name="Pops">How many values it takes here, which a call decides per site.</param>
    /// <param name="Pushes">How many it leaves here.</param>
    /// <param name="Condition">The comparison a conditional jump goes on, where one was settled.</param>
    /// <param name="Depth">
    /// How deep the stack is when it begins. Null where no path arrives at it at all, which says
    /// nothing against the reading — a program has dead operations like any other.
    /// </param>
    /// <param name="Disputed">
    /// Whether two paths arrive at it at two different depths, which is the reading contradicting
    /// itself and means one of the operations before it is read wrong.
    /// </param>
    public sealed record Line(
        int Index,
        string? Mnemonic,
        VirtualOperand Operand,
        IReadOnlyList<int>? Targets,
        bool Conjectured,
        int? Pops,
        int? Pushes,
        string? Condition,
        int? Depth,
        bool Disputed);

    /// <summary>
    /// The whole of what was established about a program, in the form something other than a
    /// listing can act on.
    /// </summary>
    /// <remarks>
    /// The renderer and anything that would build a method body have to agree exactly about what
    /// each operation was found to be, or the file an analyst reads and the code they run are two
    /// different readings wearing one name. So the conclusions are drawn once, here, and the
    /// listing becomes one way of printing them.
    /// </remarks>
    public static IReadOnlyList<Line> Plan(VirtualProgram program, ModuleDef module)
    {
        ArgumentNullException.ThrowIfNull(program);
        ArgumentNullException.ThrowIfNull(module);

        var conjectured = new HashSet<int>();
        var going = Destinations(program, conjectured);
        var calling = Calling(program, module);
        var arity = Arities(program, module, calling);
        var forced = Forced(program, going, arity, Bounds(program, module));
        var depths = Depths(
            program, going, arity, forced,
            new Dictionary<string, List<int>>(StringComparer.Ordinal), []);

        var lines = new List<Line>(program.Instructions.Count);
        foreach (var instruction in program.Instructions)
        {
            var mnemonic = Widened(
                program, instruction, Mnemonic(program, instruction, module, calling));
            var known = program.Operations.GetValueOrDefault(instruction.Opcode);
            var counted = arity.TryGetValue(instruction.Index, out var measured)
                ? ((int?)measured.Pops, (int?)measured.Pushes)
                : (null, null);
            lines.Add(new Line(
                instruction.Index,
                mnemonic,
                instruction.Operand,
                going.GetValueOrDefault(instruction.Index),
                conjectured.Contains(instruction.Index),
                counted.Item1,
                counted.Item2,
                known?.Decides,
                depths.TryGetValue(instruction.Index, out var depth) && depth != Disagreed
                    ? depth
                    : null,
                depths.GetValueOrDefault(instruction.Index, 0) == Disagreed));
        }
        return lines;
    }

    /// <summary>
    /// What a place in a program holds: a value of a named type, an object, or nothing settled yet.
    /// </summary>
    /// <remarks>
    /// The engine keeps everything as an object, and a body written that way is faithful but nearly
    /// unreadable: a number put in a slot is boxed on the way in and converted on the way out, so a
    /// jump table over a state reads as <c>switch (Convert.ToInt32(obj))</c> and adding two numbers
    /// reads as four instructions of packing around one that adds. The type is not a guess in either
    /// case — the reading already established that the operation makes an int32 — it was simply
    /// thrown away by the time the body was written.
    ///
    /// So it is carried instead. A type is claimed only where every path agrees on it; two paths
    /// meeting with different types leave an object, which is what the engine had and what the
    /// earlier body wrote everywhere.
    /// </remarks>
    /// <param name="Settled">Whether anything has reached this place at all.</param>
    /// <param name="Held">
    /// The type the place holds as itself, or null for an object, which covers both a reference and
    /// a value the engine boxed.
    /// </param>
    public readonly record struct VirtualKind(bool Settled, string? Held)
    {
        /// <summary>Nothing has reached here yet, so nothing is claimed.</summary>
        public static VirtualKind Unreached => default;

        /// <summary>Boxed or a reference, which is what the engine holds everything as.</summary>
        public static VirtualKind Boxed => new(true, null);

        /// <summary>A value of the named type, held as itself.</summary>
        public static VirtualKind Value(string type) => new(true, type);

        /// <summary>What two paths arriving here agree on.</summary>
        public VirtualKind Meeting(VirtualKind other)
        {
            if (!Settled)
                return other;
            if (!other.Settled)
                return this;
            return string.Equals(Held, other.Held, StringComparison.Ordinal) ? this : Boxed;
        }
    }

    /// <summary>
    /// What every place in a program holds, for a body that would rather hold a number as a number.
    /// </summary>
    /// <param name="Entering">The stack where each operation begins, bottom of the stack first.</param>
    /// <param name="Leaving">
    /// What the program wants of the value an operation makes. It differs from the type the
    /// operation naturally makes wherever the value meets one of another type further on, and that
    /// is the one place a box still has to be written.
    /// </param>
    /// <param name="Slots">The slots that hold a value of one type throughout, and which.</param>
    /// <param name="Types">The type each name stands for, so a body can write it.</param>
    /// <param name="Refused">
    /// Why nothing was settled, where nothing was. A body is still written in that case, holding
    /// everything as an object the way the engine did, so this is not a failure — but it is the
    /// difference between a readable rebuilt method and an unreadable one, and a run that hits it
    /// should say so rather than quietly hand over the worse of the two.
    /// </param>
    public sealed record Typing(
        IReadOnlyDictionary<int, IReadOnlyList<VirtualKind>> Entering,
        IReadOnlyDictionary<int, VirtualKind> Leaving,
        IReadOnlyDictionary<int, TypeSig> Slots,
        IReadOnlyDictionary<string, TypeSig> Types,
        string? Refused = null,
        int Distrusted = 0)
    {
        /// <summary>
        /// Nothing settled, which asks a body to hold everything as an object exactly as before.
        /// </summary>
        public static Typing None(string why) => new(
            new Dictionary<int, IReadOnlyList<VirtualKind>>(),
            new Dictionary<int, VirtualKind>(),
            new Dictionary<int, TypeSig>(),
            new Dictionary<string, TypeSig>(StringComparer.Ordinal),
            why);
    }

    /// <summary>
    /// Works out what each place in a program holds, from what the operations were read as.
    /// </summary>
    /// <remarks>
    /// This is an ordinary forward walk to a fixed point, with one turn that is worth spelling out.
    /// The usual direction is enough to say what arrives somewhere: a place holds what every path
    /// into it holds, and an int32 meeting a string is an object. But a body has to be written, and
    /// a body cannot hand two different things to one jump. An operation whose table sends the path
    /// to three hundred places has to leave the stack in one shape, so if any one of those places is
    /// reached from somewhere else carrying an object, all three hundred take an object.
    ///
    /// So agreement is pushed backwards as well as forwards. What the program wants of a value is
    /// the sum of what everything it can reach wants, and that flows back through the operation that
    /// made it and on to the operations that fed it. Both directions only ever widen a type towards
    /// an object, so the walk still settles, and it settles on the one assignment a body can be
    /// written from.
    ///
    /// A slot's type comes from what is written to it, and not from whether it is written before it
    /// is read. That distinction is worth stating because the other choice was tried first and it
    /// cost almost everything: in a flattened program every block is entered from the dispatcher, so
    /// as far as the control flow can tell, any slot a block reads at its start might not have been
    /// written yet, and thirteen slots came out as one. What the looser rule gives up is small and
    /// bounded — a slot declared as a number reads zero where the engine's object slot read null —
    /// and the engine's own conversions turn that null into the same zero at every use that converts
    /// it. A body built from a reading was never a proof of anything, and this is a reading that
    /// says what the slot holds instead of leaving a reader to work it out at every use.
    ///
    /// A slot nothing writes is a separate matter and has to be said out loud rather than left
    /// unsaid, which is what the grounding below is for. Saying nothing about such a slot is not
    /// neutral once agreement is pushed backwards: a load of it would take on whatever its readers
    /// wanted, while the body has nothing to declare the slot as but an object, and the two do not
    /// meet.
    /// </remarks>
    public static Typing Types(
        VirtualProgram program, ModuleDef module, MethodDef stub, IReadOnlyList<Line> lines)
    {
        ArgumentNullException.ThrowIfNull(program);
        ArgumentNullException.ThrowIfNull(module);
        ArgumentNullException.ThrowIfNull(stub);
        ArgumentNullException.ThrowIfNull(lines);

        var named = new Dictionary<string, TypeSig>(StringComparer.Ordinal);

        // Only the edges between two operations the walk reached are worth anything: an operation
        // it gave no depth is written as a throw, so it hands nothing on, and nothing that arrives
        // at one means anything either.
        var after = new Dictionary<int, List<int>>();
        foreach (var line in lines)
        {
            if (line.Depth is null || Terminal(program, program.Instructions[line.Index]))
                continue;
            var name = program.Operations.GetValueOrDefault(
                program.Instructions[line.Index].Opcode)?.Name;
            var going = new List<int>();
            if (Falls(name) && line.Index + 1 < lines.Count && lines[line.Index + 1].Depth is not null)
                going.Add(line.Index + 1);
            if (Leaps(name) && line.Targets is { } targets)
            {
                going.AddRange(targets.Where(target =>
                    target >= 0 && target < lines.Count && lines[target].Depth is not null));
            }
            if (going.Count > 0)
                after[line.Index] = going;
        }

        // A place no walked operation hands the path to is a place the walk started from: the first
        // operation, and every handler the guarded regions were read as. What arrives at one of
        // those is whatever threw, so nothing is claimed about it.
        var reached = after.Values.SelectMany(going => going).ToHashSet();
        var entering = new Dictionary<int, VirtualKind[]>();
        foreach (var line in lines)
        {
            if (line.Depth is not { } depth)
                continue;
            var stack = new VirtualKind[depth];
            if (!reached.Contains(line.Index))
                Array.Fill(stack, VirtualKind.Boxed);
            entering[line.Index] = stack;
        }

        var slots = Slotted(lines);
        if (slots is null)
            return Typing.None("an operation read as a slot access names no slot");

        var leaving = new Dictionary<int, VirtualKind>();
        var distrusted = new HashSet<int>();
        for (var settling = 0; ; settling++)
        {
            for (var round = 0; round <= Rounds; round++)
            {
                if (round == Rounds)
                    return Typing.None($"the types did not settle after {Rounds} rounds");
                var moved = false;
                foreach (var line in lines)
                {
                    if (!entering.TryGetValue(line.Index, out var stack))
                        continue;
                    if (!after.TryGetValue(line.Index, out var going))
                        continue;
                    if (Effect(line, module) is not var (pops, pushes))
                    {
                        return Typing.None(
                            $"nothing says what operation {line.Index} " +
                            $"({line.Mnemonic ?? "unread"}) takes and leaves");
                    }
                    if (pops > stack.Length || (pushes > 1 && line.Mnemonic != "dup"))
                    {
                        // What the operation was read as does not fit where the walk has it. Nothing
                        // is claimed about it or about anywhere it goes, and the rest of the program
                        // carries on being typed around it.
                        if (Distrust(line, stack, going, entering, leaving))
                            moved = true;
                        distrusted.Add(line.Index);
                        continue;
                    }

                    var kept = stack.Length - pops;
                    var made = pushes == 0
                        ? VirtualKind.Unreached
                        : Produces(program, line, module, stub, stack, slots, named);

                    // What everything downstream wants of this operation's work, which is what it has
                    // to leave: one shape for every place the path can go from here.
                    var wanted = made;
                    var mismatched = false;
                    foreach (var target in going)
                    {
                        var arriving = entering[target];
                        if (arriving.Length != kept + pushes)
                        {
                            // The same disagreement, seen from the edge rather than the operation:
                            // the stack the operation leaves is not the depth the walk arrives at
                            // the next one with, so one of the two readings is wrong and neither is
                            // built on.
                            mismatched = true;
                            break;
                        }
                        for (var at = 0; at < kept; at++)
                        {
                            if (Raise(ref stack[at], arriving[at]))
                                moved = true;
                        }
                        for (var at = kept; at < arriving.Length; at++)
                            wanted = wanted.Meeting(arriving[at]);
                    }
                    if (mismatched)
                    {
                        if (Distrust(line, stack, going, entering, leaving))
                            moved = true;
                        distrusted.Add(line.Index);
                        continue;
                    }
                    if (pushes > 0)
                    {
                        var was = leaving.GetValueOrDefault(line.Index);
                        var now = was.Meeting(wanted);
                        if (now != was)
                        {
                            leaving[line.Index] = now;
                            moved = true;
                        }
                    }

                    foreach (var target in going)
                    {
                        var arriving = entering[target];
                        for (var at = 0; at < kept; at++)
                        {
                            if (Raise(ref arriving[at], stack[at]))
                                moved = true;
                        }
                        for (var at = kept; at < arriving.Length; at++)
                        {
                            if (Raise(ref arriving[at], wanted))
                                moved = true;
                        }
                    }

                    if (line.Mnemonic == "stloc" &&
                        line.Operand is VirtualOperand.Number stored &&
                        slots.TryGetValue((int)stored.Value, out var slot))
                    {
                        var now = slot.Meeting(stack[^1]);
                        if (now != slot)
                        {
                            slots[(int)stored.Value] = now;
                            moved = true;
                        }
                    }
                }
                if (!moved)
                    break;
            }

            // A slot nothing the walk reached ever wrote is a slot the body declares as an object,
            // because that is all there is to declare it as. Until that is said, a load of one
            // claims nothing at all, and claiming nothing is not neutral here: the walk pushes
            // agreement backwards, so a load that claims nothing takes on whatever its readers
            // wanted, and the body ends up loading an object where a number was promised. So the
            // slots are grounded and the walk settles again over what that changed. It only ever
            // widens, so there is a bounded number of times round.
            if (settling == Settlings)
                return Typing.None($"the slots did not ground after {Settlings} settlings");
            var grounded = false;
            foreach (var slot in slots.Where(slot => !slot.Value.Settled).Select(slot => slot.Key)
                .ToList())
            {
                slots[slot] = VirtualKind.Boxed;
                grounded = true;
            }
            if (!grounded)
                break;
        }

        // A place nothing ever reached holds an object, which claims the least and is what the
        // engine held. The same goes for a value nothing downstream ever asked for.
        foreach (var stack in entering.Values)
        {
            for (var at = 0; at < stack.Length; at++)
            {
                if (!stack[at].Settled)
                    stack[at] = VirtualKind.Boxed;
            }
        }

        return new Typing(
            entering.ToDictionary(
                place => place.Key, place => (IReadOnlyList<VirtualKind>)place.Value),
            leaving.ToDictionary(
                place => place.Key,
                place => place.Value.Settled ? place.Value : VirtualKind.Boxed),
            slots
                .Where(slot => slot.Value.Held is { } held && named.ContainsKey(held))
                .ToDictionary(slot => slot.Key, slot => named[slot.Value.Held!]),
            named,
            Distrusted: distrusted.Count);
    }

    /// <summary>
    /// Gives up on one operation and its neighbours without giving up on the program.
    /// </summary>
    /// <remarks>
    /// Everywhere the operation touches goes back to holding an object, which is what the engine
    /// held and what the untyped body wrote. Widening rather than refusing is what keeps the rest
    /// of the method readable: one contradictory operation in four thousand used to cost the whole
    /// program its types, and these programs have one.
    /// </remarks>
    private static bool Distrust(
        Line line,
        VirtualKind[] stack,
        List<int> going,
        Dictionary<int, VirtualKind[]> entering,
        Dictionary<int, VirtualKind> leaving)
    {
        var moved = false;
        for (var at = 0; at < stack.Length; at++)
        {
            if (Raise(ref stack[at], VirtualKind.Boxed))
                moved = true;
        }
        if (Doubt(going, entering))
            moved = true;
        if (leaving.GetValueOrDefault(line.Index) != VirtualKind.Boxed)
        {
            leaving[line.Index] = VirtualKind.Boxed;
            moved = true;
        }
        return moved;
    }

    /// <summary>Puts everywhere the path can go from somewhere back to holding objects.</summary>
    private static bool Doubt(List<int> going, Dictionary<int, VirtualKind[]> entering)
    {
        var moved = false;
        foreach (var arriving in going.Select(target => entering[target]))
        {
            for (var at = 0; at < arriving.Length; at++)
            {
                if (Raise(ref arriving[at], VirtualKind.Boxed))
                    moved = true;
            }
        }
        return moved;
    }

    /// <summary>How many times to settle and ground the slots before giving up on doing so.</summary>
    private const int Settlings = 4;

    /// <summary>How many times to go round before deciding the walk is not settling.</summary>
    private const int Rounds = 64;

    /// <summary>
    /// What an operation takes and leaves, read off what it was established to be.
    /// </summary>
    /// <remarks>
    /// Deliberately not the arity the trials measured. Some operations were never measured at all —
    /// their effect was worked out from the depths around them — and one of those anywhere in a
    /// program would leave the whole program untyped, which is what happened: a single unmeasured
    /// array read cost an entire method its types. What is used instead is the arity of the IL the
    /// operation was read as, which is the same thing the body is about to write, so the two cannot
    /// disagree. Where they would have, the walk says so: the stack ends up a different depth from
    /// the one the reading arrived at, and that operation and its neighbours are left untyped.
    /// </remarks>
    private static (int Pops, int Pushes)? Effect(Line line, ModuleDef module) => line.Mnemonic switch
    {
        "nop" or "br" => (0, 0),
        "ldnull" or "ldc.i4" or "ldc.i8" or "ldstr" or "ldloc" or "ldarg" or "ldsfld" or "ldtoken"
            => (0, 1),
        "dup" => (1, 2),
        "pop" or "stloc" or "starg" or "stsfld" or "switch" => (1, 0),
        "ldfld" or "ldlen" or "newarr" or "neg" or "not" => (1, 1),
        "stfld" => (2, 0),
        "ldelem" => (2, 1),
        "stelem" => (3, 0),
        "add" or "sub" or "mul" or "div" or "rem" or "and" or "or" or "xor" or "shl" or "shr" or
            "ceq" or "cgt" or "clt" => (2, 1),
        "br.cond" => (line.Condition is "brtrue" or "brfalse" ? 1 : 2, 0),
        "call" or "newobj" => Signature(line, module),
        var name when name?.StartsWith("conv.", StringComparison.Ordinal) == true => (1, 1),
        _ => line.Pops is { } pops && line.Pushes is { } pushes ? (pops, pushes) : null
    };

    private static (int Pops, int Pushes)? Signature(Line line, ModuleDef module) =>
        line.Operand is VirtualOperand.Number number &&
        Called(number.Value, module) is { MethodSig: { } signature } called
            ? Takes(called, signature)
            : null;

    private static bool Raise(ref VirtualKind place, VirtualKind arriving)
    {
        var met = place.Meeting(arriving);
        if (met == place)
            return false;
        place = met;
        return true;
    }

    /// <summary>The slots the program uses, with nothing claimed about any of them yet.</summary>
    private static Dictionary<int, VirtualKind>? Slotted(IReadOnlyList<Line> lines)
    {
        var used = new HashSet<int>();
        foreach (var line in lines)
        {
            if (line.Mnemonic is not ("ldloc" or "stloc"))
                continue;
            if (line.Operand is not VirtualOperand.Number number ||
                number.Value is < 0 or > Slots)
            {
                // An operation read as a slot access that names no slot cannot be written at all,
                // so there is no body to type.
                return null;
            }
            used.Add((int)number.Value);
        }
        return used.ToDictionary(slot => slot, _ => VirtualKind.Unreached);
    }

    /// <summary>How many slots to believe in, past which the operand is not a slot at all.</summary>
    private const int Slots = 512;

    /// <summary>The type an operation naturally makes, before anything asks for it as an object.</summary>
    private static VirtualKind Produces(
        VirtualProgram program,
        Line line,
        ModuleDef module,
        MethodDef stub,
        VirtualKind[] entering,
        Dictionary<int, VirtualKind> slots,
        Dictionary<string, TypeSig> named)
    {
        switch (line.Mnemonic)
        {
            case "ldc.i4":
                return Of(module.CorLibTypes.Int32, named);
            case "ldc.i8":
                return Of(module.CorLibTypes.Int64, named);
            case "ldlen":
            case "ceq":
            case "cgt":
            case "clt":
                return Of(module.CorLibTypes.Int32, named);
            case "add":
            case "sub":
            case "mul":
            case "div":
            case "rem":
            case "and":
            case "or":
            case "xor":
            case "shl":
            case "shr":
            case "neg":
            case "not":
                return Of(
                    Wide(program, line) ? module.CorLibTypes.Int64 : module.CorLibTypes.Int32,
                    named);
            case "dup":
                return entering.Length > 0 ? entering[^1] : VirtualKind.Boxed;
            case "ldloc":
                return line.Operand is VirtualOperand.Number slot &&
                    slots.TryGetValue((int)slot.Value, out var held)
                        ? held
                        : VirtualKind.Boxed;
            case "ldarg":
                return line.Operand is VirtualOperand.Number index &&
                    index.Value >= 0 && index.Value < stub.Parameters.Count
                        ? Of(stub.Parameters[(int)index.Value].Type, named)
                        : VirtualKind.Boxed;
            case "ldsfld":
            case "ldfld":
                return line.Operand is VirtualOperand.Number field &&
                    Resolved(field.Value, module) is IField { FieldSig.Type: { } holds }
                        ? Of(holds, named)
                        : VirtualKind.Boxed;
            case "ldtoken":
                return Resolved(
                    (line.Operand as VirtualOperand.Number)?.Value ?? 0, module) switch
                {
                    ITypeDefOrRef => Of(Handle(module, "RuntimeTypeHandle"), named),
                    IField => Of(Handle(module, "RuntimeFieldHandle"), named),
                    IMethod => Of(Handle(module, "RuntimeMethodHandle"), named),
                    _ => VirtualKind.Boxed
                };
            case "call":
                return line.Operand is VirtualOperand.Number called &&
                    Resolved(called.Value, module) is IMethod { MethodSig: { } signature }
                        ? Of(Returned(signature), named)
                        : VirtualKind.Boxed;
            case "newobj":
                return line.Operand is VirtualOperand.Number made &&
                    Resolved(made.Value, module) is IMethod { DeclaringType: { } owner } &&
                    owner.IsValueType
                        ? Of(owner.ToTypeSig(), named)
                        : VirtualKind.Boxed;
            case var conversion when conversion?.StartsWith("conv.", StringComparison.Ordinal) == true:
                return Of(Converted(module, conversion), named);
            default:
                return VirtualKind.Boxed;
        }
    }

    /// <remarks>
    /// A generic method's own type parameter is no type to hold a value as, so a call that answers
    /// with one leaves an object. The body puts the instantiation's arguments in where it writes
    /// the call, which is a conversion it would have written anyway.
    /// </remarks>
    private static TypeSig? Returned(MethodSig signature) =>
        signature.RetType.ElementType == ElementType.Void ? null : signature.RetType;

    /// <summary>The width a conversion was read at, as a type.</summary>
    internal static TypeSig? Converted(ModuleDef module, string mnemonic) => mnemonic switch
    {
        "conv.i1" => module.CorLibTypes.SByte,
        "conv.u1" => module.CorLibTypes.Byte,
        "conv.i2" => module.CorLibTypes.Int16,
        "conv.u2" => module.CorLibTypes.UInt16,
        "conv.i4" => module.CorLibTypes.Int32,
        "conv.u4" => module.CorLibTypes.UInt32,
        "conv.i8" => module.CorLibTypes.Int64,
        "conv.u8" => module.CorLibTypes.UInt64,
        _ => null
    };

    /// <summary>One of the runtime's own handles, as a value type this module can name.</summary>
    internal static TypeSig Handle(ModuleDef module, string named) =>
        new ValueTypeSig(module.CorLibTypes.GetTypeRef("System", named));

    /// <summary>Whether an operation was established to work at sixty-four bits.</summary>
    internal static bool Wide(VirtualProgram program, Line line) =>
        program.Operations.TryGetValue(program.Instructions[line.Index].Opcode, out var known) &&
        (known.Pushed ?? known.Popped) is "System.Int64" or "System.UInt64";

    /// <summary>
    /// A type as a kind: itself where a value of it can be held as one, an object otherwise.
    /// </summary>
    private static VirtualKind Of(TypeSig? type, Dictionary<string, TypeSig> named)
    {
        if (type is null ||
            type.ElementType == ElementType.Void ||
            !type.IsValueType ||
            type.IsGenericParameter ||
            type.IsByRef ||
            type.IsPointer)
        {
            return VirtualKind.Boxed;
        }
        var name = type.FullName;
        named.TryAdd(name, type);
        return VirtualKind.Value(name);
    }

    private static IMDTokenProvider? Resolved(long value, ModuleDef module)
    {
        if (value is < int.MinValue or > int.MaxValue)
            return null;
        try
        {
            return module.ResolveToken((int)value);
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>What a reading of a program came to, in the numbers a gate can be set on.</summary>
    /// <param name="Operations">How many operations the program has.</param>
    /// <param name="Read">How many of them were read as IL.</param>
    /// <param name="Walked">How many the stack walk arrives at.</param>
    /// <param name="Disagreed">
    /// How many it arrives at twice at two different depths, which is how a reading says one of its
    /// parts is wrong. Anything above zero means the listing contradicts itself.
    /// </param>
    public sealed record Reading(int Operations, int Read, int Walked, int Disagreed);

    /// <summary>Reads a program and reports what the reading came to rather than how it looks.</summary>
    public static Reading Measure(VirtualProgram program, ModuleDef module)
    {
        ArgumentNullException.ThrowIfNull(program);
        ArgumentNullException.ThrowIfNull(module);
        var going = Destinations(program, []);
        var calling = Calling(program, module);
        var arity = Arities(program, module, calling);
        var depths = Depths(
            program, going, arity, Forced(program, going, arity, Bounds(program, module)),
            new Dictionary<string, List<int>>(StringComparer.Ordinal), []);
        return new Reading(
            program.Instructions.Count,
            program.Instructions.Count(
                instruction => Mnemonic(program, instruction, module, calling) is not null),
            depths.Count,
            depths.Values.Count(depth => depth == Disagreed));
    }

    public static IEnumerable<string> Render(VirtualProgram program, ModuleDef module)
    {
        ArgumentNullException.ThrowIfNull(program);
        ArgumentNullException.ThrowIfNull(module);

        var conjectured = new HashSet<int>();
        var going = Destinations(program, conjectured);
        var calling = Calling(program, module);
        var arity = Arities(program, module, calling);
        var stopped = new Dictionary<string, List<int>>(StringComparer.Ordinal);
        var forced = Forced(program, going, arity, Bounds(program, module));
        var handlers = new HashSet<int>();
        var depths = Depths(program, going, arity, forced, stopped, handlers);
        var lifted = program.Instructions.Count(
            instruction => Mnemonic(program, instruction, module, calling) is not null);

        yield return $"; {program.Method.Stub.FullName}";
        yield return $"; program {program.Method.ProgramId}, read as IL";
        yield return ";";
        yield return "; This is what the operations were established to mean, written in the " +
            "assembly's own";
        yield return "; terms. It is a reading and not a decompilation: an operation whose " +
            "meaning was not";
        yield return "; established is written ?? with what was counted about it, rather than " +
            "guessed at, and";
        yield return "; nothing here has been put back into the assembly. The header of the " +
            "program listing";
        yield return "; beside this file says how each meaning was arrived at.";
        yield return ";";
        yield return $"; {lifted} of {program.Instructions.Count} operations read as IL, " +
            $"{program.Instructions.Count - lifted} left unread.";
        if (conjectured.Count > 0)
        {
            yield return $"; {conjectured.Count} jump target(s) are marked ?, being read off the " +
                "operation itself where its kind";
            yield return "; was never watched jumping. The walk below follows them, so a wrong " +
                "one should show up";
            yield return "; there as a disagreement about the depth of the stack.";
        }
        if (calling.Count > 0)
        {
            yield return $"; {calling.Count} operation(s) are read as calls of the method they " +
                "name, nothing having named them:";
            yield return "; every operand of theirs names a method of this assembly, and one of " +
                "those methods accounts";
            yield return "; for the effect measured of them.";
        }
        foreach (var line in Reached(program, depths, forced, stopped, handlers))
            yield return $"; {line}";
        yield return string.Empty;

        foreach (var instruction in program.Instructions)
        {
            var mnemonic = Widened(
                program, instruction, Mnemonic(program, instruction, module, calling));
            var operand = Operand(program, instruction, mnemonic, module, going, conjectured);
            var said = mnemonic is null
                ? $"??         op {instruction.Opcode} {operand}".TrimEnd() +
                    (forced.TryGetValue(instruction.Opcode, out var net)
                        ? $"        ; {net:+0;-0;0} on the stack, forced by the program"
                        : Counted(program, instruction))
                : $"{mnemonic,-10} {operand}";
            yield return $"  {instruction.Index,5}:  {said}".TrimEnd();
        }
    }

    /// <summary>The IL name for an operation, where it was established to have one.</summary>
    /// <remarks>
    /// A jump carrying a table of places rather than one is a switch, whatever else was worked out
    /// about it, and saying so is worth more than the reading it replaces: it is the only operation
    /// that turns a flattened program back into a set of blocks.
    /// </remarks>
    private static string? Mnemonic(
        VirtualProgram program,
        VirtualInstruction instruction,
        ModuleDef module,
        HashSet<int> calling)
    {
        if (!program.Operations.TryGetValue(instruction.Opcode, out var known) ||
            known.Name is not { } name)
        {
            return calling.Contains(instruction.Opcode) ? "call" : null;
        }
        if (name is "branch" or "branch if" && instruction.Operand is VirtualOperand.Table)
            return "switch";
        return Mnemonics.GetValueOrDefault(name) ?? Fetches(known, instruction, module);
    }

    /// <summary>
    /// What an operation nothing named can still be read as, from the kind of thing it leaves and
    /// what its operand turns out to name.
    /// </summary>
    /// <remarks>
    /// An operation that takes nothing, leaves one value, and carries a number is loading a
    /// constant of some sort, and which sort the number itself answers. A number that is an offset
    /// into the assembly's string heap, in an operation that leaves a string, is that string; a
    /// number that is a metadata token, in an operation that leaves something the reflection
    /// classes describe, is the member the token names. Neither reading is available to the trials,
    /// which see a value appear and cannot say where it came from, and both are exact: the string
    /// is printed as the assembly holds it, and the member as the assembly names it.
    /// </remarks>
    private static string? Fetches(
        VirtualOperation known,
        VirtualInstruction instruction,
        ModuleDef module)
    {
        if (known.Name != known.Leaving || instruction.Operand is not VirtualOperand.Number number)
            return null;
        if (known.Left == "System.String")
            return Says(number.Value, module) is null ? null : "ldstr";
        return Reflected.Contains(known.Left ?? string.Empty) && Token(number.Value, module) is not null
            ? "ldtoken"
            : null;
    }

    /// <summary>The classes an assembly's own metadata arrives in when a program reaches for it.</summary>
    internal static readonly HashSet<string> Reflected = new(StringComparer.Ordinal)
    {
        "System.Type",
        "System.RuntimeType",
        "System.RuntimeTypeHandle",
        "System.Reflection.MethodBase",
        "System.Reflection.MethodInfo",
        "System.Reflection.ConstructorInfo",
        "System.RuntimeMethodHandle",
        "System.Reflection.FieldInfo",
        "System.RuntimeFieldHandle"
    };

    /// <summary>What the assembly's string heap holds at an offset, where it holds anything.</summary>
    internal static string? Says(long value, ModuleDef module)
    {
        if (value is < 0 or > uint.MaxValue || module is not ModuleDefMD image)
            return null;
        try
        {
            return image.ReadUserString((uint)value);
        }
        catch (Exception exception) when (exception is ArgumentException or IOException)
        {
            return null;
        }
    }

    /// <summary>What was counted about an operation that could not be read, if anything was.</summary>
    private static string Counted(VirtualProgram program, VirtualInstruction instruction) =>
        program.Operations.TryGetValue(instruction.Opcode, out var known)
            ? $"        ; {known.Brief}"
            : string.Empty;

    private static string Operand(
        VirtualProgram program,
        VirtualInstruction instruction,
        string? mnemonic,
        ModuleDef module,
        Dictionary<int, List<int>> going,
        HashSet<int> conjectured)
    {
        if (mnemonic is not null && Jumps.Contains(mnemonic))
        {
            if (!going.TryGetValue(instruction.Index, out var targets))
                return "?";
            var mark = conjectured.Contains(instruction.Index) ? "?" : string.Empty;
            if (targets.Count == 1)
                return $"{targets[0].ToString(CultureInfo.InvariantCulture)}{mark}";
            var shown = string.Join(", ", targets.Take(Listed));
            return targets.Count > Listed
                ? $"({shown}, ... {targets.Count} in all){mark}"
                : $"({shown}){mark}";
        }
        if (instruction.Operand is not VirtualOperand.Number number)
            return string.Empty;
        if (mnemonic == "ldstr" && Says(number.Value, module) is { } text)
            return Quoted(text);
        return Token(number.Value, module) is { } named
            ? named
            : number.Value.ToString(CultureInfo.InvariantCulture);
    }

    /// <summary>A string as a listing can carry it: on one line, and plainly a string.</summary>
    private static string Quoted(string text)
    {
        var shown = text.Length > Quotable ? text[..Quotable] + "..." : text;
        return "\"" + shown
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal)
            .Replace("\r", "\\r", StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal)
            .Replace("\t", "\\t", StringComparison.Ordinal) + "\"";
    }

    /// <summary>How much of a string to print before the line stops being readable.</summary>
    private const int Quotable = 120;

    /// <summary>What a metadata token names, said as briefly as it can be and still be found.</summary>
    private static string? Token(long value, ModuleDef module)
    {
        if (value is < int.MinValue or > int.MaxValue)
            return null;
        var token = (int)value;
        if ((token >>> 24) is not (0x01 or 0x02 or 0x04 or 0x06 or 0x0A or 0x0B))
            return null;
        try
        {
            return module.ResolveToken(token)?.ToString();
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>
    /// Where each jumping operation goes: what was watched, what follows a rule the run confirmed,
    /// and failing both, what the operation carries.
    /// </summary>
    /// <remarks>
    /// The last of those is a conjecture and is marked as one wherever it appears, but leaving it
    /// out costs more than it saves. A single jump of an unconfirmed kind severs everything beyond
    /// it, and in the sample here that one break was the difference between walking thirty
    /// operations and walking the program. Following it is also how it gets tested: a wrong target
    /// lands the stack at a depth that contradicts the way in from somewhere else, and the walk
    /// says so.
    /// </remarks>
    private static Dictionary<int, List<int>> Destinations(
        VirtualProgram program,
        HashSet<int> conjectured)
    {
        var going = program.Targets.ToDictionary(
            seen => seen.Key, seen => new List<int> { seen.Value });
        foreach (var instruction in program.Instructions)
        {
            var name = program.Operations.TryGetValue(instruction.Opcode, out var known)
                ? known.Name
                : null;
            if (!Leaps(name))
                continue;

            if (instruction.Operand is VirtualOperand.Table table)
            {
                // A jump watched going somewhere its own table names is a jump that goes where its
                // table says, and the rest of the table can be read the same way. Where none was
                // watched, the same shape is taken as a conjecture and marked as one.
                var places = table.Values
                    .Where(place => place >= 0 && place < program.Instructions.Count)
                    .Select(place => (int)place)
                    .ToList();
                if (places.Count == 0)
                    continue;
                if (going.TryGetValue(instruction.Index, out var watched) &&
                    places.Contains(watched[0]))
                {
                    going[instruction.Index] = places;
                }
                else if (!going.ContainsKey(instruction.Index))
                {
                    going[instruction.Index] = places;
                    conjectured.Add(instruction.Index);
                }
                continue;
            }

            if (going.ContainsKey(instruction.Index) ||
                instruction.Operand is not VirtualOperand.Number number ||
                number.Value < 0 || number.Value >= program.Instructions.Count)
            {
                continue;
            }
            going[instruction.Index] = [(int)number.Value];
            if (!program.TargetIsOperand.Contains(instruction.Opcode))
                conjectured.Add(instruction.Index);
        }
        return going;
    }

    /// <summary>How much of a jump table to print before the listing stops being one.</summary>
    private const int Listed = 12;

    /// <summary>
    /// How many values each operation takes and leaves, where that is known for it.
    /// </summary>
    /// <remarks>
    /// A call has no fixed arity, which is how it was recognized in the first place, but at any one
    /// place in the program it has a perfectly definite one: the method its operand names says how
    /// many arguments it wants and whether it answers with anything. So the operations that could
    /// not be measured in general are still known here in particular.
    ///
    /// The signature is taken over a measurement rather than after it. A trial performs one call
    /// site and measures the arity of that site, which is a true measurement of a thing that
    /// differs everywhere else; used as the arity of the operation it makes every other call in the
    /// program wrong, and the stack depths downstream of them with it.
    /// </remarks>
    private static Dictionary<int, (int Pops, int Pushes)> Arities(
        VirtualProgram program,
        ModuleDef module,
        HashSet<int> calling)
    {
        var found = new Dictionary<int, (int, int)>();
        foreach (var instruction in program.Instructions)
        {
            if (!program.Operations.TryGetValue(instruction.Opcode, out var known))
                continue;
            if (!calling.Contains(instruction.Opcode) &&
                known.Name is not ("calls the method it names" or
                "makes a new object with the constructor it names"))
            {
                if (known.Measured)
                    found[instruction.Index] = (known.Pops, known.Pushes);
                continue;
            }
            if (instruction.Operand is not VirtualOperand.Number number ||
                Called(number.Value, module) is not { } called)
            {
                continue;
            }
            if (called.MethodSig is not { } signature)
                continue;
            found[instruction.Index] = Takes(called, signature);
        }
        return found;
    }

    /// <summary>What a call of a method leaves the stack, from how the method is written down.</summary>
    private static (int Pops, int Pushes) Takes(IMethod called, MethodSig signature)
    {
        var arguments = signature.Params.Count;
        return called.Name == ".ctor"
            ? (arguments, 1)
            : (arguments + (signature.HasThis ? 1 : 0),
                signature.RetType.ElementType == ElementType.Void ? 0 : 1);
    }

    /// <summary>
    /// The operations that are calls of the method they name, worked out rather than watched.
    /// </summary>
    /// <remarks>
    /// What a call takes off the stack is decided by the method it names, so an engine watched
    /// performing one has measured that method rather than the operation, and carrying the
    /// measurement to the operation's other sites reads every one of them wrong. It is worth working
    /// out which operations these are, because the protector's own signature check is written in
    /// them: a program that hashes a file and verifies it does so by calling methods with three and
    /// four arguments, and reading each of those as the one-argument call that was watched leaves the
    /// walk contradicting itself in the middle of the very code worth reading.
    ///
    /// Two things have to hold. Every operand the operation carries has to name a method this
    /// assembly knows, which an operation carrying local slots or constants will fail. And what was
    /// measured of the operation has to be exactly what one of those methods' signatures says, which
    /// is the test rather than the premise: an operation watched taking one value and leaving one,
    /// whose operands name a property getter and a four-argument method, is a call if the getter
    /// accounts for the measurement, and if none of them does then it is something else and stays
    /// unread.
    /// </remarks>
    internal static HashSet<int> Calling(VirtualProgram program, ModuleDef module)
    {
        var named = new Dictionary<int, List<(int Pops, int Pushes)>>();
        var refused = new HashSet<int>();
        foreach (var instruction in program.Instructions)
        {
            var opcode = instruction.Opcode;
            if (refused.Contains(opcode))
                continue;
            if (!program.Operations.TryGetValue(opcode, out var known) ||
                known.Name is not null ||
                !known.Measured ||
                instruction.Operand is not VirtualOperand.Number number ||
                Called(number.Value, module) is not { MethodSig: { } signature } called)
            {
                refused.Add(opcode);
                named.Remove(opcode);
                continue;
            }
            if (!named.TryGetValue(opcode, out var arities))
                named[opcode] = arities = [];
            arities.Add(Takes(called, signature));
        }

        return
        [
            .. named.Where(one =>
                    one.Value.Contains(
                        (program.Operations[one.Key].Pops, program.Operations[one.Key].Pushes)))
                .Select(one => one.Key)
        ];
    }

    /// <remarks>
    /// A method the program calls in another assembly has no definition here to resolve to, only a
    /// reference, and the reference carries the signature — which is all that is wanted, since what
    /// a call takes off the stack is decided by how it was written down, not by where it lives.
    /// </remarks>
    private static IMethod? Called(long value, ModuleDef module)
    {
        if (value is < int.MinValue or > int.MaxValue)
            return null;
        try
        {
            return module.ResolveToken((int)value) switch
            {
                MemberRef reference => reference.IsMethodRef ? reference : null,
                IMethod method => method,
                _ => null
            };
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>
    /// What the program leaves each unmeasured operation no choice but to do, by opcode.
    /// </summary>
    /// <remarks>
    /// Offered separately from the listing because it is a finding about the program rather than a
    /// way of printing it: an effect settled this way can be put together with what the operand
    /// names to reach a reading neither would support alone.
    /// </remarks>
    public static Dictionary<int, int> Solve(VirtualProgram program, ModuleDef module)
    {
        ArgumentNullException.ThrowIfNull(program);
        var going = Destinations(program, []);
        return Forced(
            program,
            going,
            Arities(program, module, Calling(program, module)),
            Bounds(program, module));
    }

    /// <summary>
    /// What an operation nothing could measure must do, given everything around it.
    /// </summary>
    /// <remarks>
    /// A program whose every other operation is known is a system of equations with one unknown in
    /// it. The depth of the stack where an operation begins is fixed by the path in, the depth
    /// where the next one begins is fixed by the path out, and the difference is the operation's
    /// effect whether it was ever watched or not. In a flattened program the paths out are
    /// plentiful, since every block ends by rejoining the dispatcher at a depth the dispatcher
    /// fixes, so the unknowns are pinned from both sides.
    ///
    /// This gives a net effect and not a reading: it says an operation takes one more than it
    /// leaves, not what it did with it. Nothing is named on the strength of it. What it does is
    /// let the walk carry on through, which is what turns a check of most of the program into a
    /// check of all of it.
    /// </remarks>
    /// <summary>
    /// The net effects an operation could possibly have, where its operand rules the rest out.
    /// </summary>
    /// <remarks>
    /// An operation whose operand names a field is one of the six that name a field, and which six
    /// depends on whether the field is static. A static one can be read, written, or have its
    /// address taken, leaving one more, one fewer, or one more on the stack; an instance one takes
    /// the object as well, leaving the same, two fewer, or the same. So -2 is impossible for a
    /// static field however the depths around it are read, and +1 impossible for an instance one.
    ///
    /// This is worth stating because the solver otherwise believes whatever the depths tell it, and
    /// a single depth arrived at wrongly earlier in the program will have it conclude that a write
    /// to a static field consumes two values. That conclusion then spreads, and the walk that was
    /// meant to check the reading fails somewhere else entirely, blaming an operation that was
    /// right all along.
    /// </remarks>
    private static Dictionary<int, HashSet<int>> Bounds(VirtualProgram program, ModuleDef module)
    {
        var possible = new Dictionary<int, HashSet<int>?>();
        foreach (var instruction in program.Instructions)
        {
            if (possible.TryGetValue(instruction.Opcode, out var narrowed) && narrowed is null)
                continue;
            var allowed = instruction.Operand is VirtualOperand.Number number
                ? Held(number.Value, module) switch
                {
                    { } field when field.IsStatic => new HashSet<int> { 1, -1 },
                    { } => new HashSet<int> { 0, -2 },
                    _ => null
                }
                : null;
            if (allowed is null)
            {
                possible[instruction.Opcode] = null;
                continue;
            }
            if (narrowed is not null)
                allowed.IntersectWith(narrowed);
            possible[instruction.Opcode] = allowed.Count > 0 ? allowed : null;
        }
        return possible
            .Where(pair => pair.Value is not null)
            .ToDictionary(pair => pair.Key, pair => pair.Value!);
    }

    private static FieldDef? Held(long value, ModuleDef module)
    {
        if (value is < int.MinValue or > int.MaxValue)
            return null;
        try
        {
            return (module.ResolveToken((int)value) as IField)?.ResolveFieldDef();
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    private static Dictionary<int, int> Forced(
        VirtualProgram program,
        Dictionary<int, List<int>> going,
        Dictionary<int, (int Pops, int Pushes)> arity,
        Dictionary<int, HashSet<int>> bounds)
    {
        var edges = new List<(int From, int To, int? Net)>();
        foreach (var instruction in program.Instructions)
        {
            var index = instruction.Index;
            if (Terminal(program, instruction))
                continue;
            int? net = arity.TryGetValue(index, out var counted)
                ? counted.Pushes - counted.Pops
                : null;
            var name = program.Operations.TryGetValue(instruction.Opcode, out var known)
                ? known.Name
                : null;
            if (Falls(name) && index + 1 < program.Instructions.Count)
                edges.Add((index, index + 1, net));
            if (Leaps(name) && going.TryGetValue(index, out var targets))
            {
                foreach (var target in targets)
                    edges.Add((index, target, net));
            }
        }

        // Depths spread along every edge whose effect is known, in both directions, since an
        // operation's depth says as much about what comes before it as about what comes after.
        // A solved effect is then used as if it were known, which is how one answer unlocks the
        // next; but it has to answer for itself. If carrying it through the rest of the program
        // contradicts a depth arrived at another way, the guess was wrong, and it is withdrawn and
        // the whole thing solved again without it rather than left to spread.
        var banned = new HashSet<int>();
        for (var attempt = 0; attempt <= Withdrawals; attempt++)
        {
            if (Solve(program, edges, banned, bounds, []) is { } solved)
                return Narrowed(program, edges, banned, bounds, solved);
        }
        return [];
    }

    /// <summary>
    /// Settles an operation the depths could not reach by trying what its operand allows it to be.
    /// </summary>
    /// <remarks>
    /// The solver works forwards: it only learns an effect where the depths on both sides of the
    /// operation are already known, so an operation early in the program, with nothing solved before
    /// it, is never reached however plain it is. Where the operand narrows the possibilities to a
    /// handful, each can be put to the program instead, and a possibility that contradicts a depth
    /// arrived at some other way is not the one. Adopting the survivor when there is exactly one is
    /// the same standard the rest of the solving is held to — the program left it no choice — and
    /// where two survive, nothing is claimed.
    /// </remarks>
    private static Dictionary<int, int> Narrowed(
        VirtualProgram program,
        List<(int From, int To, int? Net)> edges,
        HashSet<int> banned,
        Dictionary<int, HashSet<int>> bounds,
        Dictionary<int, int> solved)
    {
        foreach (var (opcode, allowed) in bounds)
        {
            if (solved.ContainsKey(opcode) ||
                program.Operations.TryGetValue(opcode, out var known) && known.Measured)
            {
                continue;
            }
            var survivors = allowed
                .Where(net => Solve(
                    program, edges, banned, bounds, new Dictionary<int, int> { [opcode] = net })
                    is not null)
                .Take(2)
                .ToArray();
            if (survivors.Length == 1)
                solved[opcode] = survivors[0];
        }
        return solved.Count == 0
            ? solved
            : Solve(program, edges, banned, bounds, solved) ?? solved;
    }

    /// <summary>How many wrong answers to withdraw before giving up on solving at all.</summary>
    private const int Withdrawals = 4;

    /// <summary>
    /// Works the depths out from what is known, returning nothing if a solved effect turned out to
    /// contradict the program, in which case it is added to what must not be assumed again.
    /// </summary>
    private static Dictionary<int, int>? Solve(
        VirtualProgram program,
        List<(int From, int To, int? Net)> edges,
        HashSet<int> banned,
        Dictionary<int, HashSet<int>> bounds,
        Dictionary<int, int> assumed)
    {
        var depths = new Dictionary<int, int> { [0] = 0 };
        var forced = new Dictionary<int, int>(assumed);
        bool moved;
        do
        {
            moved = false;
            foreach (var (from, to, net) in edges)
            {
                var opcode = program.Instructions[from].Opcode;
                var guessed = net is null && forced.ContainsKey(opcode);
                var known = net ?? (guessed ? forced[opcode] : (int?)null);
                if (known is { } step)
                {
                    if (depths.TryGetValue(from, out var before))
                    {
                        if (depths.TryGetValue(to, out var already))
                        {
                            if (already != before + step && guessed)
                            {
                                // What was put to the program rather than derived from it is
                                // withdrawn for this attempt only, since the next attempt is the
                                // one asking whether it holds.
                                if (!assumed.ContainsKey(opcode))
                                    banned.Add(opcode);
                                return null;
                            }
                        }
                        else
                        {
                            depths[to] = before + step;
                            moved = true;
                        }
                    }
                    if (depths.TryGetValue(to, out var after) && depths.TryAdd(from, after - step))
                        moved = true;
                    continue;
                }
                if (banned.Contains(opcode) ||
                    !depths.TryGetValue(from, out var entering) ||
                    !depths.TryGetValue(to, out var leaving))
                {
                    continue;
                }
                // An answer its operand rules out is not adopted, and that is all. Nothing has been
                // carried anywhere on the strength of it, so there is nothing to withdraw; and the
                // operation is not struck off either, since the pair of depths that produced the
                // impossible answer may itself be what a later attempt withdraws.
                var answer = leaving - entering;
                if (bounds.TryGetValue(opcode, out var allowed) && !allowed.Contains(answer))
                    continue;
                forced[opcode] = answer;
                moved = true;
            }
        }
        while (moved);
        return forced;
    }

    /// <summary>
    /// How deep the stack is at each operation the program can be walked to.
    /// </summary>
    /// <remarks>
    /// This is the listing checking itself. Every path into an operation has to arrive with the
    /// stack at the same depth or one of the readings above is wrong, and a reader is better served
    /// by a file that admits the contradiction than by one that hides it. The walk stops rather
    /// than guesses wherever an arity is unknown, so an operation left unread costs the depths
    /// after it as well.
    /// </remarks>
    private static Dictionary<int, int> Depths(
        VirtualProgram program,
        Dictionary<int, List<int>> going,
        Dictionary<int, (int Pops, int Pushes)> arity,
        Dictionary<int, int> forced,
        Dictionary<string, List<int>> stopped,
        HashSet<int> handlers)
    {
        var depths = new Dictionary<int, int>();
        Spread(program, going, arity, forced, stopped, depths, (0, 0));

        // Then the handlers. A guarded region says which operations it covers but not what each of
        // its numbers means, and nothing has to be assumed about that: a number the ordinary walk
        // never arrives at is tried as a place a throw arrives at instead, with the exception on
        // the stack, and kept only if the program agrees with it. A number that is where the try
        // begins, or an end rather than a beginning, is already walked to and is not tried; one
        // that is neither leaves the walk contradicting itself and is put back.
        bool spread;
        do
        {
            spread = false;
            foreach (var place in program.Regions
                .SelectMany(region => region.Numbers)
                .Distinct()
                .Where(place => place > 0 && place < program.Instructions.Count &&
                    !depths.ContainsKey(place))
                .ToList())
            {
                var kept = new Dictionary<int, int>(depths);
                var keptStops = stopped.ToDictionary(
                    entry => entry.Key, entry => new List<int>(entry.Value), StringComparer.Ordinal);
                Spread(program, going, arity, forced, stopped, depths, (place, 1));
                if (Contradicted(depths, kept, stopped, keptStops))
                {
                    depths.Clear();
                    foreach (var (index, depth) in kept)
                        depths[index] = depth;
                    stopped.Clear();
                    foreach (var (why, where) in keptStops)
                        stopped[why] = where;
                    continue;
                }
                handlers.Add(place);
                spread = true;
            }
        }
        while (spread);
        return depths;
    }

    /// <summary>
    /// Whether walking from somewhere new made the reading disagree with itself where it had not.
    /// </summary>
    /// <remarks>
    /// Only the two answers that mean a mistake count. Running out of stack and reaching the same
    /// operation at two depths are the program saying the place walked from is not a place the
    /// stack arrives at that way. Stopping at an operation nothing established is the reading
    /// admitting a gap, which is as true of the handler as of everywhere else and is no reason to
    /// throw away what was walked before it.
    /// </remarks>
    private static bool Contradicted(
        Dictionary<int, int> depths,
        Dictionary<int, int> before,
        Dictionary<string, List<int>> stopped,
        Dictionary<string, List<int>> stoppedBefore) =>
        depths.Values.Count(depth => depth == Disagreed) >
            before.Values.Count(depth => depth == Disagreed) ||
        stopped.GetValueOrDefault(Shallow)?.Count >
            (stoppedBefore.GetValueOrDefault(Shallow)?.Count ?? 0);

    /// <summary>What the walk says where an operation takes more than the stack is holding.</summary>
    private const string Shallow = "a stack too shallow for what the operation takes";

    private static void Spread(
        VirtualProgram program,
        Dictionary<int, List<int>> going,
        Dictionary<int, (int Pops, int Pushes)> arity,
        Dictionary<int, int> forced,
        Dictionary<string, List<int>> stopped,
        Dictionary<int, int> depths,
        (int Index, int Depth) from)
    {
        var pending = new Queue<(int Index, int Depth)>();
        pending.Enqueue(from);
        while (pending.Count > 0)
        {
            var (index, depth) = pending.Dequeue();
            if (index < 0 || index >= program.Instructions.Count)
                continue;
            if (depths.TryGetValue(index, out var already))
            {
                if (already != depth)
                    depths[index] = Disagreed;
                continue;
            }
            depths[index] = depth;

            var instruction = program.Instructions[index];
            if (Terminal(program, instruction))
                continue;
            int after;
            if (arity.TryGetValue(index, out var counted))
            {
                if (depth - counted.Pops < 0)
                {
                    Stop(stopped, Shallow, index);
                    continue;
                }
                after = depth - counted.Pops + counted.Pushes;
            }
            else if (forced.TryGetValue(instruction.Opcode, out var net))
            {
                after = depth + net;
            }
            else
            {
                Stop(stopped, "an operation whose effect is unknown", index);
                continue;
            }

            var name = program.Operations.TryGetValue(instruction.Opcode, out var known)
                ? known.Name
                : null;
            if (Falls(name))
                pending.Enqueue((index + 1, after));
            if (!Leaps(name))
                continue;
            if (!going.TryGetValue(index, out var targets))
            {
                Stop(stopped, "a jump whose target is unknown", index);
                continue;
            }
            foreach (var target in targets)
                pending.Enqueue((target, after));
        }
    }

    /// <summary>Consecutive numbers said as the stretches they are.</summary>
    private static IEnumerable<string> Runs(List<int> numbers)
    {
        for (var start = 0; start < numbers.Count;)
        {
            var end = start;
            while (end + 1 < numbers.Count && numbers[end + 1] == numbers[end] + 1)
                end++;
            yield return start == end
                ? numbers[start].ToString(CultureInfo.InvariantCulture)
                : $"{numbers[start]}-{numbers[end]}";
            start = end + 1;
        }
    }

    private static void Stop(Dictionary<string, List<int>> stopped, string why, int index)
    {
        if (!stopped.TryGetValue(why, out var where))
            stopped[why] = where = [];
        where.Add(index);
    }

    /// <summary>Whether an operation ends the path it is on rather than handing it onwards.</summary>
    private static bool Terminal(VirtualProgram program, VirtualInstruction instruction) =>
        program.Operations.TryGetValue(instruction.Opcode, out var known) &&
        known.Name is "returns the value it takes" or "stops the program" or
            VirtualSemantics.Throwing or VirtualSemantics.Ending;

    /// <summary>The depth given to an operation two paths disagreed about.</summary>
    private const int Disagreed = int.MinValue;

    private static IEnumerable<string> Reached(
        VirtualProgram program,
        Dictionary<int, int> depths,
        Dictionary<int, int> forced,
        Dictionary<string, List<int>> stopped,
        HashSet<int> handlers)
    {
        var walked = depths.Count;
        var disagreed = depths
            .Where(reached => reached.Value == Disagreed)
            .Select(reached => reached.Key)
            .Order()
            .ToList();
        yield return $"Walking the stack from the first operation reaches {walked} of " +
            $"{program.Instructions.Count}, and " + (disagreed.Count == 0
                ? "every one it reaches twice it reaches at the same depth."
                : $"{disagreed.Count} of them at two different depths, which means one of the " +
                    $"readings is wrong: {string.Join(", ", Runs(disagreed))}.");
        if (handlers.Count > 0)
        {
            yield return $"  {handlers.Count} place(s) a guarded region covers are walked as " +
                "handlers as well, entered with the exception on the stack: " +
                string.Join(", ", handlers.Order());
        }
        if (forced.Count > 0)
        {
            var said = forced
                .OrderBy(entry => entry.Key)
                .Select(entry => $"op {entry.Key} {entry.Value:+0;-0;0}");
            yield return "  Nothing measured what these do, but the rest of the program leaves " +
                $"them no choice: {string.Join(", ", said)} on the stack.";
        }
        foreach (var (why, where) in stopped.OrderByDescending(entry => entry.Value.Count))
        {
            var at = string.Join(", ", where.Take(8));
            yield return $"  It stopped {where.Count} time(s) at {why}: {at}" +
                (where.Count > 8 ? ", ..." : string.Empty);
        }

        // What no path arrives at is worth naming too. In a program whose blocks are all entered
        // from one table, an operation nothing reaches is either dead or reached a way that has
        // not been read, and either is something to look at rather than to leave unsaid.
        var missed = program.Instructions
            .Where(instruction => !depths.ContainsKey(instruction.Index))
            .Select(instruction => instruction.Index)
            .ToList();
        if (missed.Count > 0)
        {
            // Where the walk was never at a loss, everything it could follow it did follow, so
            // what it did not arrive at cannot be arrived at: the operations are dead, which is
            // a fact about the program rather than a limit of the reading.
            var dead = stopped.Count == 0 && disagreed.Count == 0;

            // As runs rather than as numbers, because operations nothing reaches come in stretches
            // — a whole handler, a whole block — and the stretch is the thing to go and look at.
            var runs = Runs(missed).ToList();
            yield return $"  {missed.Count} operation(s) " +
                (dead
                    ? "nothing in the program reaches, the walk having been at no point unable to " +
                        "follow it: "
                    : "no path arrives at: ") +
                string.Join(", ", runs.Take(Listed)) +
                (runs.Count > Listed ? ", ..." : string.Empty);
        }
    }
}
