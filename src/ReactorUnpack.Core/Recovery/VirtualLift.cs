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
        ["dup"] = "dup",
        ["convert"] = "conv.?",
        ["pushes nothing at all"] = "ldnull",
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
        ["not"] = "not"
    };

    /// <summary>The mnemonics whose operand is a place in the program rather than a value.</summary>
    private static readonly HashSet<string> Jumps =
        new(StringComparer.Ordinal) { "br", "br.cond", "switch" };

    public static IEnumerable<string> Render(VirtualProgram program, ModuleDef module)
    {
        ArgumentNullException.ThrowIfNull(program);
        ArgumentNullException.ThrowIfNull(module);

        var conjectured = new HashSet<int>();
        var going = Destinations(program, conjectured);
        var arity = Arities(program, module);
        var stopped = new Dictionary<string, List<int>>(StringComparer.Ordinal);
        var depths = Depths(program, going, arity, stopped);
        var lifted = program.Instructions.Count(instruction => Mnemonic(program, instruction) is not null);

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
        foreach (var line in Reached(program, depths, stopped))
            yield return $"; {line}";
        yield return string.Empty;

        foreach (var instruction in program.Instructions)
        {
            var mnemonic = Mnemonic(program, instruction);
            var operand = Operand(program, instruction, mnemonic, module, going, conjectured);
            var said = mnemonic is null
                ? $"??         op {instruction.Opcode}{Counted(program, instruction)}"
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
    private static string? Mnemonic(VirtualProgram program, VirtualInstruction instruction)
    {
        if (!program.Operations.TryGetValue(instruction.Opcode, out var known) ||
            known.Name is not { } name)
        {
            return null;
        }
        return name is "branch" or "branch if" && instruction.Operand is VirtualOperand.Table
            ? "switch"
            : Mnemonics.GetValueOrDefault(name);
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
        return Token(number.Value, module) is { } named
            ? named
            : number.Value.ToString(CultureInfo.InvariantCulture);
    }

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
            if (name is not ("branch" or "branch if"))
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
            if (known.Measured)
            {
                found[instruction.Index] = (known.Pops, known.Pushes);
                continue;
            }
            if (known.Name is not ("calls the method it names" or
                "makes a new object with the constructor it names"))
            {
                continue;
            }
            if (instruction.Operand is not VirtualOperand.Number number ||
                Called(number.Value, module) is not { } called)
            {
                continue;
            }
            var arguments = called.MethodSig?.Params.Count ?? 0;
            found[instruction.Index] = called.IsConstructor
                ? (arguments, 1)
                : (arguments + (called.MethodSig?.HasThis == true ? 1 : 0),
                    called.MethodSig?.RetType.ElementType == ElementType.Void ? 0 : 1);
        }
        return found;
    }

    private static MethodDef? Called(long value, ModuleDef module)
    {
        if (value is < int.MinValue or > int.MaxValue)
            return null;
        try
        {
            return (module.ResolveToken((int)value) as IMethod)?.ResolveMethodDef();
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            return null;
        }
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
        Dictionary<string, List<int>> stopped)
    {
        var depths = new Dictionary<int, int>();
        var pending = new Queue<(int Index, int Depth)>();
        pending.Enqueue((0, 0));
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
            if (!arity.TryGetValue(index, out var counted))
            {
                Stop(stopped, "an operation whose effect is unknown", index);
                continue;
            }
            if (depth - counted.Pops < 0)
            {
                Stop(stopped, "a stack too shallow for what the operation takes", index);
                continue;
            }
            var after = depth - counted.Pops + counted.Pushes;

            var name = program.Operations.TryGetValue(instruction.Opcode, out var known)
                ? known.Name
                : null;
            if (name is not "branch")
                pending.Enqueue((index + 1, after));
            if (name is not ("branch" or "branch if"))
                continue;
            if (!going.TryGetValue(index, out var targets))
            {
                Stop(stopped, "a jump whose target is unknown", index);
                continue;
            }
            foreach (var target in targets)
                pending.Enqueue((target, after));
        }
        return depths;
    }

    private static void Stop(Dictionary<string, List<int>> stopped, string why, int index)
    {
        if (!stopped.TryGetValue(why, out var where))
            stopped[why] = where = [];
        where.Add(index);
    }

    /// <summary>The depth given to an operation two paths disagreed about.</summary>
    private const int Disagreed = int.MinValue;

    private static IEnumerable<string> Reached(
        VirtualProgram program,
        Dictionary<int, int> depths,
        Dictionary<string, List<int>> stopped)
    {
        var walked = depths.Count;
        var disagreed = depths.Values.Count(depth => depth == Disagreed);
        yield return $"Walking the stack from the first operation reaches {walked} of " +
            $"{program.Instructions.Count}, and " + (disagreed == 0
                ? "every one it reaches twice it reaches at the same depth."
                : $"{disagreed} of them at two different depths, which means one of the readings " +
                    "is wrong.");
        foreach (var (why, where) in stopped.OrderByDescending(entry => entry.Value.Count))
        {
            var at = string.Join(", ", where.Take(8));
            yield return $"  It stopped {where.Count} time(s) at {why}: {at}" +
                (where.Count > 8 ? ", ..." : string.Empty);
        }
    }
}
