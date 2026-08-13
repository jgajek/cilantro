using System.Globalization;
using dnlib.DotNet;

namespace ReactorUnpack.Core.Recovery;

/// <summary>
/// Writes a virtualized program out as the IL it stands for, as far as that is established.
/// </summary>
/// <remarks>
/// This is a reading rather than a decompilation, and it is deliberately kept to a report. A
/// method body that is nearly right is worse than none: an analyst who is told a program does
/// something it does not will act on it, whereas one who is told an operation is unknown will go
/// and look. So every operation whose meaning was not established is written as <c>??</c> with
/// whatever was counted about it, and nothing here is ever put back into the assembly.
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
        var arity = Arities(program, module);
        var depths = Depths(
            program, going, arity, Forced(program, going, arity, Bounds(program, module)),
            new Dictionary<string, List<int>>(StringComparer.Ordinal), []);
        return new Reading(
            program.Instructions.Count,
            program.Instructions.Count(
                instruction => Mnemonic(program, instruction, module) is not null),
            depths.Count,
            depths.Values.Count(depth => depth == Disagreed));
    }

    public static IEnumerable<string> Render(VirtualProgram program, ModuleDef module)
    {
        ArgumentNullException.ThrowIfNull(program);
        ArgumentNullException.ThrowIfNull(module);

        var conjectured = new HashSet<int>();
        var going = Destinations(program, conjectured);
        var arity = Arities(program, module);
        var stopped = new Dictionary<string, List<int>>(StringComparer.Ordinal);
        var forced = Forced(program, going, arity, Bounds(program, module));
        var handlers = new HashSet<int>();
        var depths = Depths(program, going, arity, forced, stopped, handlers);
        var lifted = program.Instructions.Count(
            instruction => Mnemonic(program, instruction, module) is not null);

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
        foreach (var line in Reached(program, depths, forced, stopped, handlers))
            yield return $"; {line}";
        yield return string.Empty;

        foreach (var instruction in program.Instructions)
        {
            var mnemonic = Widened(program, instruction, Mnemonic(program, instruction, module));
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
        ModuleDef module)
    {
        if (!program.Operations.TryGetValue(instruction.Opcode, out var known) ||
            known.Name is not { } name)
        {
            return null;
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
    private static readonly HashSet<string> Reflected = new(StringComparer.Ordinal)
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
    private static string? Says(long value, ModuleDef module)
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
        ModuleDef module)
    {
        var found = new Dictionary<int, (int, int)>();
        foreach (var instruction in program.Instructions)
        {
            if (!program.Operations.TryGetValue(instruction.Opcode, out var known))
                continue;
            if (known.Name is not ("calls the method it names" or
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
            var arguments = signature.Params.Count;
            found[instruction.Index] = called.Name == ".ctor"
                ? (arguments, 1)
                : (arguments + (signature.HasThis ? 1 : 0),
                    signature.RetType.ElementType == ElementType.Void ? 0 : 1);
        }
        return found;
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
        return Forced(program, going, Arities(program, module), Bounds(program, module));
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
        known.Name is "returns the value it takes" or "stops the program";

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
        var disagreed = depths.Values.Count(depth => depth == Disagreed);
        yield return $"Walking the stack from the first operation reaches {walked} of " +
            $"{program.Instructions.Count}, and " + (disagreed == 0
                ? "every one it reaches twice it reaches at the same depth."
                : $"{disagreed} of them at two different depths, which means one of the readings " +
                    "is wrong.");
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
            var dead = stopped.Count == 0 && disagreed == 0;

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
