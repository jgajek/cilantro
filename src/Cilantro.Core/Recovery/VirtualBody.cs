using System.Globalization;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>
/// Builds a method body from a virtualized program, in the shape the engine itself ran it.
/// </summary>
/// <remarks>
/// This is the reading turned back into code, and it is held to a different standard from the rest
/// of the tool. Everything else written into an assembly is the protector's own output, provable
/// byte for byte; a body built from a reading cannot be proved that way and never will be. What is
/// built here goes into the cleaned copy all the same, because a stub in an otherwise readable
/// assembly is where the analyst gets stuck, but every method it goes into is marked as a reading
/// where the reader will see it.
///
/// The lowering assumes nothing about types, because the reading establishes none. The engine keeps
/// its stack and its slots as objects, boxing whatever it computes, and the body written here does
/// the same: every value is an object, every slot is an object, and a value is converted only where
/// the assembly itself says what it must be — the parameter of a call, the type of a field, the
/// element of an array. That makes the body verbose and it makes it faithful, which is the right
/// trade for a first reading. Where an operation is settled to be arithmetic, the conversion is
/// done through <c>System.Convert</c> rather than by unboxing to a width nothing established, so a
/// value that arrives as a different width than expected converts rather than throwing.
///
/// Anything that cannot be lowered refuses the whole program rather than the operation. A body with
/// one wrong instruction in three thousand is a body that runs the wrong code, and there is no way
/// for a reader to know which one it was.
/// </remarks>
public static class VirtualBody
{
    /// <summary>What came of trying to build a body: one of a body or a reason there is none.</summary>
    /// <param name="Distrusted">
    /// How many operations the reading is wrong about somewhere around, being those that leave the
    /// stack a depth the walk does not arrive at the next operation with. Each stands in the body
    /// as a throw, for the same reason an operation the walk never arrived at does: there is no
    /// writing an operation whose effect contradicts the depths it would be written between. A
    /// body with any of these is still worth writing where it is read rather than run — it says
    /// what the program does nearly everywhere — but it is not a body to put in the way of
    /// execution.
    /// </param>
    /// <param name="Unreached">
    /// How many operations the walk never arrived at, and which therefore stand in the body as a
    /// throw rather than as anything the program does. Where the body is read this is an honest
    /// account of how far the reading got. Where it is run it is the opposite of one: a program
    /// whose operations were not reached is a program this body does not perform, and putting it in
    /// the way of execution would quietly replace the work with nothing.
    /// </param>
    public sealed record Attempt(
        CilBody? Body,
        string? Refused,
        IReadOnlyList<string> Notes,
        int Distrusted = 0,
        int Unreached = 0);

    /// <summary>
    /// Builds the body a program stands for, in terms of the module it is to be written into.
    /// </summary>
    /// <param name="program">The program, as the engine's own decoder produced it.</param>
    /// <param name="module">
    /// The module the body will live in. Every token the program carries is resolved against this,
    /// so it has to be a module the program came from, or a copy of one.
    /// </param>
    /// <param name="stub">
    /// The method in that module the body is for, which need not be the one the program was
    /// recovered through: the copy written for reading is not the copy the passes worked on.
    /// </param>
    public static Attempt Build(VirtualProgram program, ModuleDef module, MethodDef stub)
    {
        ArgumentNullException.ThrowIfNull(program);
        ArgumentNullException.ThrowIfNull(module);
        ArgumentNullException.ThrowIfNull(stub);
        var builder = new Builder(program, module, stub);
        return builder.Run();
    }

    /// <summary>
    /// The catch type a region named, or nothing where the name is no type at all.
    /// </summary>
    /// <remarks>
    /// A finally clause still carries a <see cref="System.Type"/> field — the engine's clause class
    /// is one shape for every handler kind — and what lands there when nothing is caught is a
    /// placeholder the machine could not name. Treating that placeholder as a catch type makes the
    /// rebuild refuse a finally it could write. Empty names and names that say they are unnamed are
    /// that placeholder, not a type this module could put on a clause.
    /// </remarks>
    internal static string? CatchName(string? caught)
    {
        if (string.IsNullOrWhiteSpace(caught))
            return null;
        return caught.Contains("unnamed", StringComparison.OrdinalIgnoreCase)
            ? null
            : caught;
    }

    private sealed class Builder(VirtualProgram program, ModuleDef module, MethodDef stub)
    {
        private readonly MethodDef _stub = stub;
        private readonly CilBody _body = new();
        private readonly List<string> _notes = [];

        /// <summary>The engine's slots, one local each, in the numbering the program uses.</summary>
        private readonly Dictionary<int, Local> _slots = [];

        /// <summary>Somewhere to put values while the ones beneath them are converted.</summary>
        private readonly Dictionary<(int At, string Holds), Local> _scratch = [];

        /// <summary>The locals the last spill used, in the order they will be pushed back.</summary>
        private Local[] _spilled = [];

        /// <summary>What each of those locals holds, so a push knows what it is pushing.</summary>
        private VirtualLift.VirtualKind[] _held = [];

        /// <summary>What each place in the program holds, where the reading settled it.</summary>
        private VirtualLift.Typing _typing = VirtualLift.Typing.None("nothing was read yet");

        /// <summary>The first instruction of each operation, which is what a jump has to name.</summary>
        private readonly Dictionary<int, Instruction> _entries = [];

        private readonly List<(Instruction At, IReadOnlyList<int> To, bool Table)> _pending = [];

        /// <summary>The regions to be written as handlers, once they are all readable as such.</summary>
        private readonly List<Guard> _guards = [];

        /// <summary>Every try and every handler, as ranges a jump can leave.</summary>
        private readonly List<Span> _parts = [];

        /// <summary>The first instruction after the last operation, where a range ends at it.</summary>
        private Instruction? _after;

        /// <summary>A stretch of operations, both ends belonging to it.</summary>
        private readonly record struct Span(int From, int To)
        {
            public bool Holds(int index) => index >= From && index <= To;
        }

        private readonly record struct Guard(
            Span Try, Span Handler, ExceptionHandlerType Kind, ITypeDefOrRef? Caught);

        public Attempt Run()
        {
            var lines = VirtualLift.Plan(program, module);
            if (Guards(lines) is { } unguardable)
                return Refuse(unguardable);

            if (lines.FirstOrDefault(line => line.Disputed) is { } disputed)
            {
                return Refuse(
                    $"the walk reaches operation {disputed.Index} at two different depths, so one " +
                    "of the readings before it is wrong");
            }

            _typing = VirtualLift.Types(program, module, _stub, lines);

            var dead = 0;
            var contradicted = 0;
            foreach (var line in lines)
            {
                var start = _body.Instructions.Count;
                if (line.Depth is null)
                {
                    // Nothing in the program arrives here, so there is no stack for the operation
                    // to work on and no way to write one that means anything. What goes in its
                    // place fails loudly if the program ever does arrive, which is the only
                    // honest thing to put where a reading ran out.
                    Add(OpCodes.Ldnull);
                    Add(OpCodes.Throw);
                    dead++;
                }
                else if (_typing.Distrusted.Contains(line.Index))
                {
                    // The walk arrives here at one depth and has the operation leaving a different
                    // one than it arrives at the next with, so what this was read as and what the
                    // depths around it say cannot both be right. Writing it as read anyway used to
                    // put the contradiction into the body: the instructions leave a depth the join
                    // after them is entered at by every other path at another, and a method whose
                    // stack merges disagree is one a decompiler reads by guessing and a reader
                    // cannot trust a line of. So the same thing goes here as where the walk never
                    // arrived — a throw, which takes the depth it is given, hands nothing on, and
                    // leaves every other path into that join agreeing with itself.
                    Add(OpCodes.Ldnull);
                    Add(OpCodes.Throw);
                    contradicted++;
                }
                else if (Lower(line) is { } refusal)
                {
                    return Refuse($"operation {line.Index} ({line.Mnemonic ?? "unread"}): {refusal}");
                }
                if (_body.Instructions.Count == start)
                    Add(OpCodes.Nop);
                _entries[line.Index] = _body.Instructions[start];
            }

            // A body must not run off its own end, whatever the last operation happened to be.
            var tail = _body.Instructions.Count;
            if (_stub.ReturnType.ElementType == ElementType.Void)
            {
                Add(OpCodes.Ret);
            }
            else
            {
                Add(OpCodes.Ldnull);
                Add(OpCodes.Throw);
            }
            _after = _body.Instructions[tail];

            foreach (var (at, to, table) in _pending)
            {
                if (to.FirstOrDefault(place => !_entries.ContainsKey(place), -1) is var missing &&
                    missing >= 0)
                {
                    return Refuse($"a jump names {missing}, which is not an operation of this program");
                }
                at.Operand = table
                    ? to.Select(place => _entries[place]).ToArray()
                    : _entries[to[0]];
            }

            // Innermost first, which is the order the runtime searches them in and the only order
            // that means anything where one region sits inside another.
            foreach (var guard in _guards.OrderBy(guard => guard.Handler.To - guard.Try.From))
            {
                _body.ExceptionHandlers.Add(new ExceptionHandler(guard.Kind)
                {
                    TryStart = _entries[guard.Try.From],
                    TryEnd = Following(guard.Try.To),
                    HandlerStart = _entries[guard.Handler.From],
                    HandlerEnd = Following(guard.Handler.To),
                    CatchType = guard.Kind == ExceptionHandlerType.Catch ? guard.Caught : null
                });
            }

            foreach (var local in _slots.Values.Concat(_scratch.Values))
                _body.Variables.Add(local);
            _body.InitLocals = true;
            _body.MaxStack = (ushort)Math.Min(
                ushort.MaxValue,
                lines.Max(line => line.Depth ?? 0) + Headroom);
            _body.UpdateInstructionOffsets();
            if (_typing.Refused is { } unsettled)
                _notes.Add($"Every value is held as an object, {unsettled}.");
            else if (contradicted > 0)
            {
                _notes.Add(
                    $"{contradicted} operation(s) leave the stack a different depth from the one " +
                    "the walk arrives at the next operation with, so one of the readings around " +
                    "each is wrong and each stands in the body as a throw rather than as code " +
                    "built on the contradiction.");
            }
            var typed = _slots.Count(slot => _typing.Slots.ContainsKey(slot.Key));
            _notes.Add(
                $"{lines.Count} operation(s) became {_body.Instructions.Count} instruction(s) over " +
                $"{_slots.Count} slot(s), " +
                (typed == 0
                    ? "every value carried as an object."
                    : $"{typed} of them holding one settled type rather than an object.") +
                (dead == 0
                    ? string.Empty
                    : $" {dead} of them are places nothing reaches and throw instead.") +
                (_guards.Count == 0
                    ? string.Empty
                    : $" {_guards.Count} guarded region(s) became handlers."));
            return new Attempt(_body, null, _notes, contradicted, dead);
        }

        /// <summary>Where a range of operations ends, as the instruction after the last of them.</summary>
        private Instruction Following(int last) =>
            _entries.TryGetValue(last + 1, out var next) ? next : _after!;

        /// <summary>
        /// Reads the program's guarded regions as handlers, or says why they cannot be written.
        /// </summary>
        /// <remarks>
        /// A region is the one part of a program that cannot be half written. Leave it out and the
        /// body runs code that was guarded as if it were not, so a throw the original swallowed
        /// escapes the method and everything after it is a different program. Every region has to
        /// be readable as a handler, or none of it is written at all.
        ///
        /// What is checked here is what the runtime requires of a handler and would otherwise
        /// reject the body for: ranges that are places in this program, a try and a handler that do
        /// not run into each other, regions that nest rather than overlap, a type to catch, and a
        /// last operation in each part that ends the path rather than falling out of it. Where the
        /// reading of a region does not meet them, the reading is what is wrong, and saying so is
        /// better than writing a body the runtime will not load.
        /// </remarks>
        private string? Guards(IReadOnlyList<VirtualLift.Line> lines)
        {
            foreach (var region in program.Regions)
            {
                if (region is not { Guarded: { } guarded, Handled: { } handled })
                {
                    return $"the program has a guarded region ({region.Describe()}) whose try and " +
                        "handler were not told apart, so the code it guards is not established";
                }
                ExceptionHandlerType kind;
                ITypeDefOrRef? type = null;
                if (CatchName(region.Caught) is { } caught)
                {
                    if (Catching(caught) is not { } named)
                    {
                        return $"the region over {guarded.From}-{guarded.To} catches {caught}, " +
                            "which is not a type this module can name";
                    }
                    type = named;
                    kind = ExceptionHandlerType.Catch;
                }
                else
                {
                    // A clause that names no type is a finally or a fault. The engine keeps the
                    // runtime's own handler-kind flag among the clause's numbers, last of them, so
                    // the two are told apart the way the runtime tells them apart: 4 is a fault and
                    // anything else a finally, both of which end at endfinally and catch no type.
                    kind = region.Numbers is { Count: > 0 } flags &&
                        flags[^1] == (int)ExceptionHandlerType.Fault
                        ? ExceptionHandlerType.Fault
                        : ExceptionHandlerType.Finally;
                }
                if (guarded.To >= lines.Count || handled.To >= lines.Count)
                {
                    return $"the region over {guarded.From}-{guarded.To} reaches past the end of " +
                        "the program";
                }
                _guards.Add(new Guard(new Span(guarded.From, guarded.To),
                    new Span(handled.From, handled.To), kind, type));
            }

            foreach (var guard in _guards)
            {
                foreach (var part in new[] { guard.Try, guard.Handler })
                {
                    // Falling out of a try or a handler is not something the runtime allows, and a
                    // reading in which the code does is a reading that has the ends in the wrong
                    // place rather than a program that does it.
                    if (lines[part.To].Mnemonic is not ("br" or "ret" or "throw" or "endfinally"))
                    {
                        return $"operations {part.From}-{part.To} are guarded or handle what is, " +
                            $"and the last of them ({lines[part.To].Mnemonic ?? "unread"}) runs on " +
                            "into what follows instead of leaving";
                    }
                    _parts.Add(part);
                }
            }

            // Overlapping without nesting is the one arrangement that cannot be written at all, and
            // it means two regions were read from objects that do not go together.
            foreach (var (one, other) in _parts
                .SelectMany(one => _parts.Select(other => (one, other)))
                .Where(pair => !pair.one.Equals(pair.other)))
            {
                var nested = (one.From >= other.From && one.To <= other.To) ||
                    (other.From >= one.From && other.To <= one.To);
                if (!nested && one.Holds(other.From) != one.Holds(other.To))
                {
                    return $"operations {one.From}-{one.To} and {other.From}-{other.To} are " +
                        "guarded regions that overlap without one being inside the other";
                }
            }
            return null;
        }

        /// <summary>The type a region catches, as this module can name it.</summary>
        private ITypeDefOrRef? Catching(string caught)
        {
            if (module.Find(caught, isReflectionName: false) is { } declared)
                return declared;
            if (module.Find(caught, isReflectionName: true) is { } reflected)
                return reflected;
            foreach (var candidate in module.GetTypes())
            {
                if (candidate.FullName.Equals(caught, StringComparison.Ordinal) ||
                    candidate.Name.String.Equals(caught, StringComparison.Ordinal))
                {
                    return candidate;
                }
            }
            var cut = caught.LastIndexOf('.');
            if (cut <= 0)
                return null;
            // A dotted name is a type some assembly already known to this module can spell. Corlib
            // is the usual home; a name that is not System.* is still written as a type ref against
            // it, which is enough for the runtime to load a catch clause of a framework type.
            return module.CorLibTypes.GetTypeRef(caught[..cut], caught[(cut + 1)..]);
        }

        /// <summary>Whether a jump from one operation to another leaves a guarded region.</summary>
        private bool Escapes(int from, int to) =>
            _parts.Exists(part => part.Holds(from) && !part.Holds(to));

        /// <summary>How much stack the lowering itself uses over what the program uses.</summary>
        private const int Headroom = 8;

        private Attempt Refuse(string why) => new(null, why, _notes);

        /// <summary>
        /// Writes one operation, answering with why it could not be written rather than writing
        /// something else.
        /// </summary>
        private string? Lower(VirtualLift.Line line)
        {
            switch (line.Mnemonic)
            {
                case null:
                    return "nothing established what it does";
                case "nop":
                    Add(OpCodes.Nop);
                    return null;
                case "dup":
                    // Both copies have to be the same thing, so where the program wants an object
                    // of them the value is boxed once and the reference duplicated.
                    Leave(line, Holding(Taken(line, 0)));
                    Add(OpCodes.Dup);
                    return null;
                case "pop":
                    Add(OpCodes.Pop);
                    return null;
                case "ldnull":
                    Add(OpCodes.Ldnull);
                    return null;
                case "ldc.i4":
                    return Constant(line, module.CorLibTypes.Int32, OpCodes.Ldc_I4);
                case "ldc.i8":
                    return Constant(line, module.CorLibTypes.Int64, OpCodes.Ldc_I8);
                case "ldstr":
                    return Text(line);
                case "ldloc":
                case "stloc":
                    return Slot(line, line.Mnemonic == "ldloc");
                case "ldarg":
                    return Argument(line);
                case "ldsfld":
                case "stsfld":
                case "ldfld":
                case "stfld":
                    return Field(line);
                case "ldlen":
                    AsObject(Taken(line, 0));
                    Add(OpCodes.Castclass, Arrays);
                    Add(OpCodes.Callvirt, Length);
                    Leave(line, module.CorLibTypes.Int32);
                    return null;
                case "ldelem":
                    Spill(line, 1);
                    // The array is beneath what was spilled, and is now the top of the stack.
                    AsObject(Taken(line, 1));
                    Add(OpCodes.Castclass, Arrays);
                    Push(0, module.CorLibTypes.Int32, ToInt32);
                    Add(OpCodes.Callvirt, GetValue);
                    return null;
                case "stelem":
                    Spill(line, 2);
                    AsObject(Taken(line, 2));
                    Add(OpCodes.Castclass, Arrays);
                    Push(1, null);
                    Push(0, module.CorLibTypes.Int32, ToInt32);
                    Add(OpCodes.Callvirt, SetValue);
                    return null;
                case "newarr":
                    return Array(line);
                case "ldtoken":
                    return Metadata(line);
                case "call":
                case "newobj":
                    return Call(line, line.Mnemonic == "newobj");
                case "br":
                    return Jump(line, OpCodes.Br);
                case "br.cond":
                    return Conditional(line);
                case "switch":
                    Want(Taken(line, 0), module.CorLibTypes.Int32, ToInt32);
                    return Jump(line, OpCodes.Switch);
                case "ret":
                    return Return(line);
                case "throw":
                    // The cast is not a check we are adding. An exception arrives here as whatever
                    // the engine held it as, and IL will not throw a value until it is said to be an
                    // exception, which is what the operation established it is by refusing anything
                    // else.
                    AsObject(Taken(line, 0));
                    Add(OpCodes.Castclass, Exceptions);
                    Add(OpCodes.Throw);
                    return null;
                case "endfinally":
                    Add(OpCodes.Endfinally);
                    return null;
                case "add":
                    return Arithmetic(line, OpCodes.Add);
                case "sub":
                    return Arithmetic(line, OpCodes.Sub);
                case "mul":
                    return Arithmetic(line, OpCodes.Mul);
                case "div":
                    return Arithmetic(line, OpCodes.Div);
                case "rem":
                    return Arithmetic(line, OpCodes.Rem);
                case "and":
                    return Arithmetic(line, OpCodes.And);
                case "or":
                    return Arithmetic(line, OpCodes.Or);
                case "xor":
                    return Arithmetic(line, OpCodes.Xor);
                case "shl":
                    return Shift(line, OpCodes.Shl);
                case "shr":
                    return Shift(line, OpCodes.Shr);
                case "neg":
                    return Unary(line, OpCodes.Neg);
                case "not":
                    return Unary(line, OpCodes.Not);
                case "ceq":
                    // Where both sides are held as the same whole number this is the comparison IL
                    // has for it. Otherwise the reasoning is the jump's: two objects are equal when
                    // they are the same object or hold the same value, and asking them is what
                    // answers both without knowing which is in hand. Either way what comes back is
                    // a number rather than a truth, because the engine leaves a number here and the
                    // next operation is as likely to compare it with one as to jump on it.
                    if (Compares(line))
                    {
                        Add(OpCodes.Ceq);
                    }
                    else
                    {
                        Boxing(line, 2);
                        Add(OpCodes.Call, Same);
                    }
                    Leave(line, module.CorLibTypes.Int32);
                    return null;
                case "cgt":
                case "clt":
                    var ordering = line.Mnemonic == "cgt" ? OpCodes.Cgt : OpCodes.Clt;
                    if (Compares(line))
                    {
                        Add(ordering);
                    }
                    else
                    {
                        Spill(line, 2);
                        Push(0, module.CorLibTypes.Int64, ToInt64);
                        Push(1, module.CorLibTypes.Int64, ToInt64);
                        Add(ordering);
                    }
                    Leave(line, module.CorLibTypes.Int32);
                    return null;
                case var name when name.StartsWith("conv.", StringComparison.Ordinal):
                    return Convert(line, name);
                default:
                    return $"there is no lowering for {line.Mnemonic}";
            }
        }

        private string? Constant(VirtualLift.Line line, CorLibTypeSig type, OpCode load)
        {
            if (line.Operand is not VirtualOperand.Number number)
                return "it carries no number to load";
            if (load == OpCodes.Ldc_I4)
            {
                if (number.Value is < int.MinValue or > int.MaxValue)
                    return "the number it carries does not fit the width it was read at";
                Add(OpCodes.Ldc_I4, (int)number.Value);
            }
            else
            {
                Add(OpCodes.Ldc_I8, number.Value);
            }
            Leave(line, type);
            return null;
        }

        private string? Text(VirtualLift.Line line)
        {
            var said = line.Operand switch
            {
                VirtualOperand.Text text => text.Value,
                VirtualOperand.Number number when number.Value is >= 0 and <= uint.MaxValue &&
                    module is ModuleDefMD image => Read(image, (uint)number.Value),
                _ => null
            };
            if (said is null)
                return "it carries nothing that reads as a string";
            Add(OpCodes.Ldstr, said);
            return null;
        }

        private static string? Read(ModuleDefMD image, uint offset)
        {
            try
            {
                return image.ReadUserString(offset);
            }
            catch (Exception exception) when (exception is ArgumentException or IOException)
            {
                return null;
            }
        }

        /// <summary>
        /// One of the engine's slots, as a local of the type the slot was settled to hold.
        /// </summary>
        /// <remarks>
        /// A slot the reading settled to one type is declared as that type and its name says so, so
        /// a reader sees <c>int stateSlot0</c> rather than an object that every use has to convert.
        /// A slot that holds different things at different times stays an object, which is what the
        /// engine had, and everything about writing it is as it was.
        /// </remarks>
        private string? Slot(VirtualLift.Line line, bool loading)
        {
            if (line.Operand is not VirtualOperand.Number number ||
                number.Value is < 0 or > Slots)
            {
                return "it names no slot";
            }
            var slot = (int)number.Value;
            var holds = _typing.Slots.GetValueOrDefault(slot);
            if (!_slots.TryGetValue(slot, out var local))
            {
                var named = slot.ToString(CultureInfo.InvariantCulture);
                _slots[slot] = local = new Local(holds ?? Objects)
                {
                    Name = holds is null ? $"slot{named}" : $"{Short(holds.FullName)}Slot{named}"
                };
            }
            if (loading)
            {
                Add(OpCodes.Ldloc, local);
                if (holds is not null)
                    Leave(line, holds);
                return null;
            }
            if (holds is null)
                AsObject(Taken(line, 0));
            else
                Want(Taken(line, 0), holds);
            Add(OpCodes.Stloc, local);
            return null;
        }

        /// <summary>How many slots to believe in, past which the operand is not a slot at all.</summary>
        private const int Slots = 512;

        private string? Argument(VirtualLift.Line line)
        {
            if (line.Operand is not VirtualOperand.Number number ||
                number.Value < 0 ||
                number.Value >= _stub.Parameters.Count)
            {
                return "it names no argument of the method";
            }
            var parameter = _stub.Parameters[(int)number.Value];
            Add(OpCodes.Ldarg, parameter);
            Leave(line, parameter.Type);
            return null;
        }

        private string? Field(VirtualLift.Line line)
        {
            if (line.Operand is not VirtualOperand.Number number ||
                Resolve(number.Value) is not IField field ||
                field.FieldSig?.Type is not { } type)
            {
                return "its operand names no field";
            }
            var writing = line.Mnemonic is "stsfld" or "stfld";
            var instance = line.Mnemonic is "ldfld" or "stfld";
            if (writing)
            {
                if (instance)
                {
                    Spill(line, 1);
                    if (Owner(field) is not { } owner)
                        return "the field it writes has no type to reach it through";
                    AsObject(Taken(line, 1));
                    Add(OpCodes.Castclass, owner);
                    Push(0, type);
                }
                else
                {
                    Want(Taken(line, 0), type);
                }
                Add(instance ? OpCodes.Stfld : OpCodes.Stsfld, field);
                return null;
            }
            if (instance)
            {
                if (Owner(field) is not { } owner)
                    return "the field it reads has no type to reach it through";
                AsObject(Taken(line, 0));
                Add(OpCodes.Castclass, owner);
            }
            Add(instance ? OpCodes.Ldfld : OpCodes.Ldsfld, field);
            Leave(line, type);
            return null;
        }

        private static ITypeDefOrRef? Owner(IField field) => field.DeclaringType;

        private string? Array(VirtualLift.Line line)
        {
            if (line.Operand is not VirtualOperand.Number number ||
                Resolve(number.Value) is not ITypeDefOrRef element)
            {
                return "its operand names no type to make an array of";
            }
            Want(Taken(line, 0), module.CorLibTypes.Int32, ToInt32);
            Add(OpCodes.Newarr, element);
            return null;
        }

        /// <summary>
        /// A handle to something in the assembly's own metadata, as the program named it.
        /// </summary>
        /// <remarks>
        /// The engine leaves this on its stack as an object like everything else, and what the
        /// program does with it next is hand it to <c>GetTypeFromHandle</c> or one of its
        /// neighbours. A handle is a value type, so where nothing else meets it the handle goes
        /// straight to the call that wants it, and where something does it makes the same boxed
        /// round trip every other value in this body makes.
        /// </remarks>
        private string? Metadata(VirtualLift.Line line)
        {
            if (line.Operand is not VirtualOperand.Number number)
                return "it carries no token";
            switch (Resolve(number.Value))
            {
                case ITypeDefOrRef type:
                    Add(OpCodes.Ldtoken, type);
                    Leave(line, Handle("RuntimeTypeHandle"));
                    return null;
                case IField field:
                    Add(OpCodes.Ldtoken, field);
                    Leave(line, Handle("RuntimeFieldHandle"));
                    return null;
                case IMethod method:
                    Add(OpCodes.Ldtoken, method);
                    Leave(line, Handle("RuntimeMethodHandle"));
                    return null;
                default:
                    return "its token names nothing this module holds";
            }
        }

        private TypeSig Handle(string named) => VirtualLift.Handle(module, named);

        private string? Call(VirtualLift.Line line, bool constructing)
        {
            if (line.Operand is not VirtualOperand.Number number ||
                Resolve(number.Value) is not IMethod called ||
                called.MethodSig is not { } signature)
            {
                return "its operand names no method";
            }
            // A method spec is a generic method already instantiated: it names its type arguments,
            // so the call can be written as it stands and each parameter converted to the concrete
            // type the instantiation gives it. An open generic method carries no such arguments and
            // is refused, since a body that converts to !!0 is a body the runtime will not load.
            var instantiation = called is MethodSpec { GenericInstMethodSig.GenericArguments: { } args }
                ? args
                : null;
            if ((signature.Generic || called is MethodSpec) && instantiation is null)
                return "the method it names is generic, whose arguments the reading does not carry";

            var parameters = signature.Params;
            var receives = !constructing && signature.HasThis;
            ITypeDefOrRef? through = null;
            if (receives)
            {
                if (called.DeclaringType is not { } owner)
                    return "the method it calls has no type to reach it through";
                if (owner.IsValueType)
                    return "the method it calls belongs to a value type, which needs an address";
                through = owner;
            }

            // What each value on the stack has to be for the call to be written as it stands. The
            // receiver has to be cast whatever it is, since a method is reached through the type
            // that declares it; the arguments only have to be touched where they are not already
            // what they must be.
            var wanted = new List<TypeSig?>();
            if (receives)
                wanted.Add(null);
            wanted.AddRange(parameters.Select(
                parameter => (TypeSig?)Instantiated(parameter, instantiation)));

            var how = constructing ? OpCodes.Newobj : receives ? OpCodes.Callvirt : OpCodes.Call;
            if (through is null && Ready(line, wanted))
            {
                // Every argument already is what the call takes, so there is nothing to reach past
                // and the call is written over the values where they lie.
                Add(how, called);
                return Answered(line, called, signature, instantiation, constructing);
            }

            Spill(line, wanted.Count);
            if (through is not null)
            {
                Push(0, null);
                Add(OpCodes.Castclass, through);
            }
            for (var at = 0; at < parameters.Count; at++)
            {
                var place = at + (receives ? 1 : 0);
                Push(place, wanted[place]);
            }
            Add(how, called);
            return Answered(line, called, signature, instantiation, constructing);
        }

        /// <summary>What a call or a construction leaves, as the program wants to hold it.</summary>
        private string? Answered(
            VirtualLift.Line line,
            IMethod called,
            MethodSig signature,
            IList<TypeSig>? instantiation,
            bool constructing)
        {
            if (constructing)
            {
                if (called.DeclaringType is { IsValueType: true } made)
                    Leave(line, made.ToTypeSig());
                return null;
            }
            if (signature.RetType.ElementType != ElementType.Void)
                Leave(line, Instantiated(signature.RetType, instantiation));
            return null;
        }

        /// <summary>
        /// A method spec's parameter or return type with its type arguments put in, so a value can
        /// be converted to the concrete type the call takes rather than to the <c>!!0</c> the
        /// generic method is written in.
        /// </summary>
        /// <remarks>
        /// Only the method's own type parameters are substituted, which is all a spec supplies. A
        /// type parameter of a generic declaring type is left as it stands, since it is carried by
        /// the type the call reaches through rather than by the spec, and a call on one is reached
        /// through a type spec that already names it.
        /// </remarks>
        private static TypeSig Instantiated(TypeSig type, IList<TypeSig>? methodArgs) =>
            methodArgs is null ? type : Substitute(type, methodArgs) ?? type;

        private static TypeSig? Substitute(TypeSig? type, IList<TypeSig> methodArgs) => type switch
        {
            null => null,
            GenericMVar mvar => mvar.Number < methodArgs.Count
                ? methodArgs[(int)mvar.Number]
                : type,
            SZArraySig array => new SZArraySig(Substitute(array.Next, methodArgs)),
            ArraySig array => new ArraySig(
                Substitute(array.Next, methodArgs), array.Rank, array.Sizes, array.LowerBounds),
            ByRefSig reference => new ByRefSig(Substitute(reference.Next, methodArgs)),
            PtrSig pointer => new PtrSig(Substitute(pointer.Next, methodArgs)),
            PinnedSig pinned => new PinnedSig(Substitute(pinned.Next, methodArgs)),
            GenericInstSig instance => new GenericInstSig(
                instance.GenericType,
                [.. instance.GenericArguments.Select(argument => Substitute(argument, methodArgs))]),
            _ => type
        };

        /// <summary>
        /// A return, which the reading gives in two forms: one that carries a value up and one
        /// that merely stops.
        /// </summary>
        /// <remarks>
        /// The stub these are written into returns nothing — the engine hands the answer back
        /// through the array it was given — so a value returned here has nowhere to go and is
        /// dropped. Dropping it is not a loss: the operation before it put it there, and the
        /// listing beside the body says so.
        ///
        /// Whether there is a value at all is a question about the place and not about the
        /// operation. The same return is reached from blocks that leave something on the stack and
        /// from blocks that leave nothing, which is an engine that returns what it finds rather
        /// than what it was promised, and the depths say which case each site is.
        /// </remarks>
        private string? Return(VirtualLift.Line line)
        {
            var carries = Named(line) == "returns the value it takes" && line.Depth > 0;
            if (carries)
            {
                if (_stub.ReturnType.ElementType == ElementType.Void)
                    Add(OpCodes.Pop);
                else
                    Want(Taken(line, 0), _stub.ReturnType);
            }
            else if (_stub.ReturnType.ElementType != ElementType.Void)
            {
                return "it stops with nothing on the stack where the method returns something";
            }
            Add(OpCodes.Ret);
            return null;
        }

        private string? Named(VirtualLift.Line line) =>
            program.Operations.TryGetValue(program.Instructions[line.Index].Opcode, out var known)
                ? known.Name
                : null;

        private string? Jump(VirtualLift.Line line, OpCode how)
        {
            if (line.Targets is not { Count: > 0 } targets)
                return "nowhere was established for it to go";
            var table = how == OpCodes.Switch;
            if (!table && targets.Count != 1)
                return "it was seen going to more than one place";

            // A jump out of a guarded region is a leave, which is not a nicety: the runtime rejects
            // a body that leaves one any other way. The engine has no such instruction and no need
            // of one — its regions are a table it consults, not a shape its jumps have to respect —
            // so which of its jumps are leaves is read off where they go.
            var leaving = targets.Any(target => Escapes(line.Index, target));
            if (leaving && how != OpCodes.Br)
            {
                return "it leaves a guarded region without being an unconditional jump, and there " +
                    "is no such instruction to write it as";
            }
            if (leaving && line.Depth is not (null or 0))
            {
                return $"it leaves a guarded region with {line.Depth} value(s) on the stack, which " +
                    "a leave would discard";
            }
            var at = Add(leaving ? OpCodes.Leave : how);
            _pending.Add((at, targets, table));
            return null;
        }

        /// <summary>
        /// A conditional jump, in the comparison it was settled to go on.
        /// </summary>
        /// <remarks>
        /// Equality is done by asking the values, because a jump comparing two objects is comparing
        /// what they are and a jump comparing two numbers is comparing what they hold, and
        /// <c>Object.Equals</c> is right for both. Ordering has to be numeric, so it converts.
        /// </remarks>
        private string? Conditional(VirtualLift.Line line)
        {
            if (line.Condition is not { } condition)
                return "nothing settled what it goes on";
            switch (condition)
            {
                case "brtrue":
                case "brfalse":
                    // A number held as itself is already the truth IL jumps on. Only an object
                    // needs asking, and asking is the roundabout business below.
                    if (!Ready(line, [module.CorLibTypes.Int32]) &&
                        !Ready(line, [module.CorLibTypes.Int64]))
                    {
                        Boxing(line, 1);
                        Truth();
                    }
                    return Jump(line, condition == "brtrue" ? OpCodes.Brtrue : OpCodes.Brfalse);
                case "beq":
                case "bne.un":
                    if (Compares(line))
                    {
                        return Jump(
                            line, condition == "beq" ? OpCodes.Beq : OpCodes.Bne_Un);
                    }
                    Boxing(line, 2);
                    Add(OpCodes.Call, Same);
                    return Jump(line, condition == "beq" ? OpCodes.Brtrue : OpCodes.Brfalse);
                case "bge":
                case "bgt":
                case "ble":
                case "blt":
                case "bge.un":
                case "bgt.un":
                case "ble.un":
                case "blt.un":
                    if (!Compares(line))
                    {
                        Spill(line, 2);
                        Push(0, module.CorLibTypes.Int64, ToInt64);
                        Push(1, module.CorLibTypes.Int64, ToInt64);
                    }
                    return Jump(line, Ordered[condition]);
                default:
                    return $"there is no lowering for a jump on {condition}";
            }
        }

        /// <summary>
        /// Turns the object on the stack into the truth of it, the way the runtime would.
        /// </summary>
        /// <remarks>
        /// A jump on one value means two different things depending on what the value is, and both
        /// of them are reached here. Where the engine's slot held a number, the jump is on the
        /// number being other than zero. Where it held a reference — a stream, an array, the result
        /// of a call — the jump is on the reference being there at all, and the number that
        /// reference would convert to is not a question with an answer.
        ///
        /// Carrying everything as an object is what makes the two indistinguishable at the point of
        /// the jump, so the distinction is made where it can be: at run time, by asking whether the
        /// object is a boxed value. Converting unconditionally is what the first version did, and it
        /// threw on the first null check the program reached.
        /// </remarks>
        private void Truth()
        {
            var whenReference = new Instruction(OpCodes.Pop);
            var whenNull = new Instruction(OpCodes.Pop);
            var settled = new Instruction(OpCodes.Nop);
            Add(OpCodes.Dup);
            Add(OpCodes.Brfalse, whenNull);
            Add(OpCodes.Dup);
            Add(OpCodes.Isinst, Values);
            Add(OpCodes.Brfalse, whenReference);
            Add(OpCodes.Call, ToBoolean);
            Add(OpCodes.Br, settled);
            _body.Instructions.Add(whenReference);
            Add(OpCodes.Ldc_I4_1);
            Add(OpCodes.Br, settled);
            _body.Instructions.Add(whenNull);
            Add(OpCodes.Ldc_I4_0);
            _body.Instructions.Add(settled);
        }

        private static readonly Dictionary<string, OpCode> Ordered = new(StringComparer.Ordinal)
        {
            ["bge"] = OpCodes.Bge,
            ["bgt"] = OpCodes.Bgt,
            ["ble"] = OpCodes.Ble,
            ["blt"] = OpCodes.Blt,
            ["bge.un"] = OpCodes.Bge_Un,
            ["bgt.un"] = OpCodes.Bgt_Un,
            ["ble.un"] = OpCodes.Ble_Un,
            ["blt.un"] = OpCodes.Blt_Un
        };

        /// <remarks>
        /// Where both operands are already held as the width the operation works at, this is the
        /// one IL instruction the operation stands for. Where either is an object it is converted,
        /// which means taking the top one off the stack to reach the one beneath it, and the whole
        /// operation costs six instructions instead of one. That difference is most of what makes
        /// an untyped rebuilt body hard to read.
        /// </remarks>
        private string? Arithmetic(VirtualLift.Line line, OpCode how)
        {
            var width = Width(line);
            if (Ready(line, [width, width]))
            {
                Add(how);
            }
            else
            {
                Spill(line, 2);
                Push(0, width, Widened(width));
                Push(1, width, Widened(width));
                Add(how);
            }
            Leave(line, width);
            return null;
        }

        /// <summary>A shift takes its distance as an int whatever width it shifts.</summary>
        private string? Shift(VirtualLift.Line line, OpCode how)
        {
            var width = Width(line);
            if (Ready(line, [width, module.CorLibTypes.Int32]))
            {
                Add(how);
            }
            else
            {
                Spill(line, 2);
                Push(0, width, Widened(width));
                Push(1, module.CorLibTypes.Int32, ToInt32);
                Add(how);
            }
            Leave(line, width);
            return null;
        }

        private string? Unary(VirtualLift.Line line, OpCode how)
        {
            var width = Width(line);
            Want(Taken(line, 0), width, Widened(width));
            Add(how);
            Leave(line, width);
            return null;
        }

        /// <summary>The engine's own way of bringing a value across to a width.</summary>
        private IMethod Widened(CorLibTypeSig width) =>
            width.ElementType == ElementType.I8 ? ToInt64 : ToInt32;

        /// <summary>The width an operation was established to work at.</summary>
        private CorLibTypeSig Width(VirtualLift.Line line) =>
            VirtualLift.Wide(program, line) ? module.CorLibTypes.Int64 : module.CorLibTypes.Int32;

        /// <summary>
        /// Whether both of a comparison's operands are already held as the same whole number, so
        /// the comparison IL has can stand in for the roundabout way of asking.
        /// </summary>
        /// <remarks>
        /// Only the two signed widths count. An unsigned number held as itself compares differently
        /// under <c>cgt</c> than it does after the widening conversion the untyped body used, and
        /// the point here is to write the same comparison more plainly, not a different one.
        /// </remarks>
        private bool Compares(VirtualLift.Line line) =>
            Ready(line, [module.CorLibTypes.Int32, module.CorLibTypes.Int32]) ||
            Ready(line, [module.CorLibTypes.Int64, module.CorLibTypes.Int64]);

        private string? Convert(VirtualLift.Line line, string mnemonic)
        {
            var (call, made) = mnemonic switch
            {
                "conv.i1" => (ToSByte, module.CorLibTypes.SByte),
                "conv.u1" => (ToByte, module.CorLibTypes.Byte),
                "conv.i2" => (ToInt16, module.CorLibTypes.Int16),
                "conv.u2" => (ToUInt16, module.CorLibTypes.UInt16),
                "conv.i4" => (ToInt32, module.CorLibTypes.Int32),
                "conv.u4" => (ToUInt32, module.CorLibTypes.UInt32),
                "conv.i8" => (ToInt64, module.CorLibTypes.Int64),
                "conv.u8" => (ToUInt64, module.CorLibTypes.UInt64),
                _ => (null, null)
            };
            if (call is null || made is null)
                return $"there is no lowering for {mnemonic}";
            // A conversion to the width the value is already held at is the one case where the
            // engine's own call would have answered with what it was given.
            if (!Ready(line, [made]))
            {
                AsObject(Taken(line, 0));
                Add(OpCodes.Call, call);
            }
            Leave(line, made);
            return null;
        }

        /// <summary>Turns a value of a known type into the object the engine would have held.</summary>
        private void Boxed(TypeSig type)
        {
            if (type.IsValueType || type.IsGenericParameter)
                Add(OpCodes.Box, type.ToTypeDefOrRef());
        }

        /// <summary>Turns the object the engine held into the type the assembly says it must be.</summary>
        private void Unboxed(TypeSig type)
        {
            if (type.ElementType == ElementType.Object)
                return;
            Add(type.IsValueType || type.IsGenericParameter
                ? OpCodes.Unbox_Any
                : OpCodes.Castclass, type.ToTypeDefOrRef());
        }

        /// <summary>What the stack holds where an operation begins, bottom of the stack first.</summary>
        private IReadOnlyList<VirtualLift.VirtualKind> Entering(VirtualLift.Line line) =>
            _typing.Entering.TryGetValue(line.Index, out var kinds) ? kinds : [];

        /// <summary>What one of an operation's operands holds, counted down from the top.</summary>
        private VirtualLift.VirtualKind Taken(VirtualLift.Line line, int below)
        {
            var kinds = Entering(line);
            var at = kinds.Count - 1 - below;
            return at >= 0 ? kinds[at] : VirtualLift.VirtualKind.Boxed;
        }

        /// <summary>
        /// Boxes what an operation has just made, where the program wants it as an object.
        /// </summary>
        /// <remarks>
        /// The value stays as itself wherever everything downstream of it agrees on its type, which
        /// is what makes a rebuilt body readable. Where it meets a value of another type, or lands
        /// in a slot that holds more than one kind of thing, the box goes back in: the engine held
        /// an object there and so must this.
        /// </remarks>
        private void Leave(VirtualLift.Line line, TypeSig made)
        {
            if (_typing.Leaving.TryGetValue(line.Index, out var wanted) &&
                wanted.Held is { } held &&
                Already(held, made))
            {
                return;
            }
            Boxed(made);
        }

        /// <summary>Hands a value on as the type something else needs it to be.</summary>
        /// <remarks>
        /// Where the value is already held as that type this writes nothing, which is the whole
        /// point of carrying the types. Where it is not, it is converted exactly as the untyped
        /// body converted it, and that is deliberate: an arithmetic operand went through
        /// <c>System.Convert</c>, which brings a value of another width across rather than
        /// throwing, and a call's argument went through <c>unbox.any</c>, which insists. Which of
        /// those is right is a question about the operation and not about this change, so each site
        /// says which one it has always used.
        /// </remarks>
        private void Want(VirtualLift.VirtualKind kind, TypeSig wanted, IMethod? through = null)
        {
            if (kind.Held is { } held && Suffices(held, wanted))
                return;
            AsObject(kind);
            if (through is null)
                Unboxed(wanted);
            else
                Add(OpCodes.Call, through);
        }

        /// <summary>Whether a value held as one type is exactly what something wants.</summary>
        /// <remarks>
        /// An enumeration and the type it is written in terms of are the same thing on the stack,
        /// and the engine's own boxes crossed between them freely, so they count as one here too.
        /// This is the strict question, and it is the one a box has to be decided by: the type
        /// written on a box is part of what the box is, and a boxed <c>bool</c> is not a boxed
        /// <c>int</c> to anything that unboxes it.
        /// </remarks>
        private bool Already(string held, TypeSig wanted) =>
            wanted.ElementType != ElementType.Object &&
            (string.Equals(held, wanted.FullName, StringComparison.Ordinal) ||
                string.Equals(Beneath(held), Beneath(wanted.FullName), StringComparison.Ordinal));

        /// <summary>Whether a value held as one type will do where another is wanted.</summary>
        /// <remarks>
        /// The looser question, and the one an operation taking a value has to be decided by. IL
        /// has no <c>bool</c> or <c>char</c> or <c>short</c> on its stack — they are all int32
        /// there — so a jump on the truth of a bool, or a sum of two shorts, is written over the
        /// values as they lie. Only the types that fit in an int32 without losing anything count,
        /// so converting one would have answered with the value itself and skipping the conversion
        /// changes nothing. A uint32 is left out for that reason: the engine brought it across
        /// through a wider type, and <c>cgt</c> on it as it lies would compare it as signed.
        /// </remarks>
        private bool Suffices(string held, TypeSig wanted) =>
            Already(held, wanted) ||
            (wanted.ElementType == ElementType.I4 && Narrow.Contains(Beneath(held)));

        /// <summary>The types an int32 on the stack can hold the whole of.</summary>
        private static readonly HashSet<string> Narrow = new(StringComparer.Ordinal)
        {
            "System.Boolean",
            "System.Char",
            "System.SByte",
            "System.Byte",
            "System.Int16",
            "System.UInt16",
            "System.Int32"
        };

        /// <summary>What an enumeration is written in terms of, or the name itself.</summary>
        private string Beneath(string name)
        {
            if (_beneath.TryGetValue(name, out var found))
                return found;
            var type = _typing.Types.GetValueOrDefault(name) ?? module.Find(name, false)?.ToTypeSig();
            var resolved = type?.ToTypeDefOrRef()?.ResolveTypeDef();
            found = resolved is { IsEnum: true } enumeration
                ? enumeration.GetEnumUnderlyingType()?.FullName ?? name
                : name;
            return _beneath[name] = found;
        }

        private readonly Dictionary<string, string> _beneath = new(StringComparer.Ordinal);

        /// <summary>Boxes a value held as itself, so it can go where an object goes.</summary>
        private void AsObject(VirtualLift.VirtualKind kind)
        {
            if (kind.Held is { } held && _typing.Types.TryGetValue(held, out var type))
                Add(OpCodes.Box, type.ToTypeDefOrRef());
        }

        /// <summary>
        /// Puts an operation's operands back as objects, for the ways of asking that need them.
        /// </summary>
        /// <remarks>
        /// Asking two values whether they are equal, or asking one whether it is true, is done by
        /// calling something that takes objects, and a value held as itself is not one. Reaching
        /// the lower of two operands means taking the top one off, which is the same spill the
        /// untyped body did everywhere and is skipped here wherever both are objects already.
        /// </remarks>
        private void Boxing(VirtualLift.Line line, int count)
        {
            if (Ready(line, [.. Enumerable.Repeat((TypeSig?)null, count)]))
                return;
            if (count == 1)
            {
                AsObject(Taken(line, 0));
                return;
            }
            Spill(line, count);
            for (var at = 0; at < count; at++)
                Push(at, null);
        }

        /// <summary>Whether every operand an operation takes is already the type it wants.</summary>
        private bool Ready(VirtualLift.Line line, List<TypeSig?> wanted)
        {
            for (var below = 0; below < wanted.Count; below++)
            {
                var kind = Taken(line, below);
                if (wanted[wanted.Count - 1 - below] is { } type
                        ? kind.Held is not { } held || !Suffices(held, type)
                        : kind.Held is not null)
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>The type a kind stands for, for a local that has to hold it.</summary>
        private TypeSig Holding(VirtualLift.VirtualKind kind) =>
            kind.Held is { } held ? _typing.Types.GetValueOrDefault(held) ?? Objects : Objects;

        private TypeSig Objects => module.CorLibTypes.Object;

        /// <summary>Takes values off the stack so that what is beneath them can be reached.</summary>
        private void Spill(VirtualLift.Line line, int count)
        {
            _spilled = new Local[count];
            _held = new VirtualLift.VirtualKind[count];
            for (var at = count - 1; at >= 0; at--)
            {
                // The deepest of the values spilled is pushed back first, so a local's place in the
                // spill counts up from the bottom while an operand counts down from the top.
                var kind = Taken(line, count - 1 - at);
                _held[at] = kind;
                var holds = kind.Held ?? "object";
                if (!_scratch.TryGetValue((at, holds), out var local))
                {
                    _scratch[(at, holds)] = local = new Local(Holding(kind))
                    {
                        Name = $"held{at.ToString(CultureInfo.InvariantCulture)}" +
                            (kind.Held is null ? string.Empty : $"_{Short(holds)}")
                    };
                }
                _spilled[at] = local;
                Add(OpCodes.Stloc, local);
            }
        }

        private static string Short(string name) =>
            name[(name.LastIndexOf('.') + 1)..];

        private void Push(int held) => Add(OpCodes.Ldloc, _spilled[held]);

        /// <summary>Pushes a spilled value back, as the type something wants it as.</summary>
        private void Push(int held, TypeSig? wanted, IMethod? through = null)
        {
            Push(held);
            if (wanted is null)
                AsObject(_held[held]);
            else
                Want(_held[held], wanted, through);
        }

        private Instruction Add(OpCode code, object? operand = null)
        {
            var instruction = operand is null
                ? new Instruction(code)
                : new Instruction(code, operand);
            _body.Instructions.Add(instruction);
            return instruction;
        }

        private IMDTokenProvider? Resolve(long value)
        {
            if (value is < int.MinValue or > int.MaxValue)
                return null;
            try
            {
                return module.ResolveToken((int)value);
            }
            catch (Exception exception)
                when (exception is ArgumentException or InvalidOperationException)
            {
                return null;
            }
        }

        private ITypeDefOrRef Arrays => _arrays ??= module.CorLibTypes.GetTypeRef("System", "Array");
        private ITypeDefOrRef? _arrays;

        private ITypeDefOrRef Values =>
            _values ??= module.CorLibTypes.GetTypeRef("System", "ValueType");
        private ITypeDefOrRef? _values;

        private ITypeDefOrRef Converts =>
            _converts ??= module.CorLibTypes.GetTypeRef("System", "Convert");
        private ITypeDefOrRef? _converts;

        private ITypeDefOrRef Exceptions =>
            _exceptions ??= module.CorLibTypes.GetTypeRef("System", "Exception");
        private ITypeDefOrRef? _exceptions;

        private IMethod GetValue => _getValue ??= new MemberRefUser(
            module,
            "GetValue",
            MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.Int32),
            Arrays);
        private IMethod? _getValue;

        private IMethod SetValue => _setValue ??= new MemberRefUser(
            module,
            "SetValue",
            MethodSig.CreateInstance(
                module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.Int32),
            Arrays);
        private IMethod? _setValue;

        private IMethod Length => _length ??= new MemberRefUser(
            module,
            "get_Length",
            MethodSig.CreateInstance(module.CorLibTypes.Int32),
            Arrays);
        private IMethod? _length;

        private IMethod Same => _same ??= new MemberRefUser(
            module,
            "Equals",
            MethodSig.CreateStatic(
                module.CorLibTypes.Boolean, module.CorLibTypes.Object, module.CorLibTypes.Object),
            module.CorLibTypes.Object.ToTypeDefOrRef());
        private IMethod? _same;

        private IMethod ToBoolean => Converting("ToBoolean", module.CorLibTypes.Boolean);
        private IMethod ToSByte => Converting("ToSByte", module.CorLibTypes.SByte);
        private IMethod ToByte => Converting("ToByte", module.CorLibTypes.Byte);
        private IMethod ToInt16 => Converting("ToInt16", module.CorLibTypes.Int16);
        private IMethod ToUInt16 => Converting("ToUInt16", module.CorLibTypes.UInt16);
        private IMethod ToInt32 => Converting("ToInt32", module.CorLibTypes.Int32);
        private IMethod ToUInt32 => Converting("ToUInt32", module.CorLibTypes.UInt32);
        private IMethod ToInt64 => Converting("ToInt64", module.CorLibTypes.Int64);
        private IMethod ToUInt64 => Converting("ToUInt64", module.CorLibTypes.UInt64);

        private readonly Dictionary<string, IMethod> _converting = new(StringComparer.Ordinal);

        private IMethod Converting(string name, CorLibTypeSig gives)
        {
            if (_converting.TryGetValue(name, out var found))
                return found;
            return _converting[name] = new MemberRefUser(
                module,
                name,
                MethodSig.CreateStatic(gives, module.CorLibTypes.Object),
                Converts);
        }
    }
}
