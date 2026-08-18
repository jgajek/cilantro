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
    public sealed record Attempt(CilBody? Body, string? Refused, IReadOnlyList<string> Notes);

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

    private sealed class Builder(VirtualProgram program, ModuleDef module, MethodDef stub)
    {
        private readonly MethodDef _stub = stub;
        private readonly CilBody _body = new();
        private readonly List<string> _notes = [];

        /// <summary>The engine's slots, one object local each, in the numbering the program uses.</summary>
        private readonly Dictionary<int, Local> _slots = [];

        /// <summary>Somewhere to put values while the ones beneath them are converted.</summary>
        private readonly List<Local> _scratch = [];

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

        private readonly record struct Guard(Span Try, Span Handler, ITypeDefOrRef Caught);

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

            var dead = 0;
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
                _body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
                {
                    TryStart = _entries[guard.Try.From],
                    TryEnd = Following(guard.Try.To),
                    HandlerStart = _entries[guard.Handler.From],
                    HandlerEnd = Following(guard.Handler.To),
                    CatchType = guard.Caught
                });
            }

            foreach (var local in _slots.Values.Concat(_scratch))
                _body.Variables.Add(local);
            _body.InitLocals = true;
            _body.MaxStack = (ushort)Math.Min(
                ushort.MaxValue,
                lines.Max(line => line.Depth ?? 0) + Headroom);
            _body.UpdateInstructionOffsets();
            _notes.Add(
                $"{lines.Count} operation(s) became {_body.Instructions.Count} instruction(s) over " +
                $"{_slots.Count} slot(s), every value carried as an object." +
                (dead == 0
                    ? string.Empty
                    : $" {dead} of them are places nothing reaches and throw instead.") +
                (_guards.Count == 0
                    ? string.Empty
                    : $" {_guards.Count} guarded region(s) became catch handlers."));
            return new Attempt(_body, null, _notes);
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
                if (region.Caught is not { } caught || Catching(caught) is not { } type)
                {
                    return $"the region over {guarded.From}-{guarded.To} catches " +
                        $"{region.Caught ?? "something unnamed"}, which is not a type this module " +
                        "can name";
                }
                if (guarded.To >= lines.Count || handled.To >= lines.Count)
                {
                    return $"the region over {guarded.From}-{guarded.To} reaches past the end of " +
                        "the program";
                }
                _guards.Add(new Guard(new Span(guarded.From, guarded.To),
                    new Span(handled.From, handled.To), type));
            }

            foreach (var guard in _guards)
            {
                foreach (var part in new[] { guard.Try, guard.Handler })
                {
                    // Falling out of a try or a handler is not something the runtime allows, and a
                    // reading in which the code does is a reading that has the ends in the wrong
                    // place rather than a program that does it.
                    if (lines[part.To].Mnemonic is not ("br" or "ret" or "throw"))
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
            var cut = caught.LastIndexOf('.');
            return cut > 0 && caught.StartsWith("System.", StringComparison.Ordinal)
                ? module.CorLibTypes.GetTypeRef(caught[..cut], caught[(cut + 1)..])
                : null;
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
                    Add(OpCodes.Castclass, Arrays);
                    Add(OpCodes.Callvirt, Length);
                    Add(OpCodes.Box, module.CorLibTypes.Int32.ToTypeDefOrRef());
                    return null;
                case "ldelem":
                    Spill(1);
                    Add(OpCodes.Castclass, Arrays);
                    Push(0);
                    Add(OpCodes.Call, ToInt32);
                    Add(OpCodes.Callvirt, GetValue);
                    return null;
                case "stelem":
                    Spill(2);
                    Add(OpCodes.Castclass, Arrays);
                    Push(1);
                    Push(0);
                    Add(OpCodes.Call, ToInt32);
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
                    Add(OpCodes.Call, ToInt32);
                    return Jump(line, OpCodes.Switch);
                case "ret":
                    return Return(line);
                case "throw":
                    // The cast is not a check we are adding. Everything here is carried as an
                    // object, and IL will not throw one until it is said to be an exception, which
                    // is what the operation established it is by refusing anything else.
                    Add(OpCodes.Castclass, Exceptions);
                    Add(OpCodes.Throw);
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
                    // The same reasoning as the jump that goes on equality: two objects are equal
                    // when they are the same object or hold the same value, and asking them is what
                    // answers both without knowing which is in hand. What comes back is boxed as a
                    // number rather than as a truth, because the engine leaves a number here and
                    // the next operation is as likely to compare it with one as to jump on it.
                    Add(OpCodes.Call, Same);
                    Add(OpCodes.Box, module.CorLibTypes.Int32.ToTypeDefOrRef());
                    return null;
                case "cgt":
                case "clt":
                    Spill(2);
                    Push(0);
                    Add(OpCodes.Call, ToInt64);
                    Push(1);
                    Add(OpCodes.Call, ToInt64);
                    Add(line.Mnemonic == "cgt" ? OpCodes.Cgt : OpCodes.Clt);
                    Add(OpCodes.Box, module.CorLibTypes.Int32.ToTypeDefOrRef());
                    return null;
                case var name when name.StartsWith("conv.", StringComparison.Ordinal):
                    return Convert(name);
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
            Add(OpCodes.Box, type.ToTypeDefOrRef());
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

        private string? Slot(VirtualLift.Line line, bool loading)
        {
            if (line.Operand is not VirtualOperand.Number number ||
                number.Value is < 0 or > Slots)
            {
                return "it names no slot";
            }
            var slot = (int)number.Value;
            if (!_slots.TryGetValue(slot, out var local))
            {
                _slots[slot] = local = new Local(module.CorLibTypes.Object)
                {
                    Name = $"slot{slot.ToString(CultureInfo.InvariantCulture)}"
                };
            }
            Add(loading ? OpCodes.Ldloc : OpCodes.Stloc, local);
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
            Boxed(parameter.Type);
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
                    Spill(1);
                    if (Held(field) is not { } owner)
                        return "the field it writes has no type to reach it through";
                    Add(OpCodes.Castclass, owner);
                    Push(0);
                }
                Unboxed(type);
                Add(instance ? OpCodes.Stfld : OpCodes.Stsfld, field);
                return null;
            }
            if (instance)
            {
                if (Held(field) is not { } owner)
                    return "the field it reads has no type to reach it through";
                Add(OpCodes.Castclass, owner);
            }
            Add(instance ? OpCodes.Ldfld : OpCodes.Ldsfld, field);
            Boxed(type);
            return null;
        }

        private static ITypeDefOrRef? Held(IField field) => field.DeclaringType;

        private string? Array(VirtualLift.Line line)
        {
            if (line.Operand is not VirtualOperand.Number number ||
                Resolve(number.Value) is not ITypeDefOrRef element)
            {
                return "its operand names no type to make an array of";
            }
            Add(OpCodes.Call, ToInt32);
            Add(OpCodes.Newarr, element);
            return null;
        }

        /// <summary>
        /// A handle to something in the assembly's own metadata, as the program named it.
        /// </summary>
        /// <remarks>
        /// The engine leaves this on its stack as an object like everything else, and what the
        /// program does with it next is hand it to <c>GetTypeFromHandle</c> or one of its
        /// neighbours. A handle is a value type, so it is boxed here and unboxed there, which is
        /// the same round trip every other value in this body makes.
        /// </remarks>
        private string? Metadata(VirtualLift.Line line)
        {
            if (line.Operand is not VirtualOperand.Number number)
                return "it carries no token";
            switch (Resolve(number.Value))
            {
                case ITypeDefOrRef type:
                    Add(OpCodes.Ldtoken, type);
                    Add(OpCodes.Box, Handle("RuntimeTypeHandle"));
                    return null;
                case IField field:
                    Add(OpCodes.Ldtoken, field);
                    Add(OpCodes.Box, Handle("RuntimeFieldHandle"));
                    return null;
                case IMethod method:
                    Add(OpCodes.Ldtoken, method);
                    Add(OpCodes.Box, Handle("RuntimeMethodHandle"));
                    return null;
                default:
                    return "its token names nothing this module holds";
            }
        }

        private TypeRef Handle(string named) => module.CorLibTypes.GetTypeRef("System", named);

        private string? Call(VirtualLift.Line line, bool constructing)
        {
            if (line.Operand is not VirtualOperand.Number number ||
                Resolve(number.Value) is not IMethod called ||
                called.MethodSig is not { } signature)
            {
                return "its operand names no method";
            }
            if (signature.Generic || called is MethodSpec)
                return "the method it names is generic, whose arguments the reading does not carry";

            var parameters = signature.Params;
            var receives = !constructing && signature.HasThis;
            var taken = parameters.Count + (receives ? 1 : 0);
            Spill(taken);
            if (receives)
            {
                if (called.DeclaringType is not { } owner)
                    return "the method it calls has no type to reach it through";
                if (owner.IsValueType)
                    return "the method it calls belongs to a value type, which needs an address";
                Push(0);
                Add(OpCodes.Castclass, owner);
            }
            for (var at = 0; at < parameters.Count; at++)
            {
                Push(at + (receives ? 1 : 0));
                Unboxed(parameters[at]);
            }

            if (constructing)
            {
                Add(OpCodes.Newobj, called);
                if (called.DeclaringType is { IsValueType: true } made)
                    Add(OpCodes.Box, made);
                return null;
            }

            Add(receives ? OpCodes.Callvirt : OpCodes.Call, called);
            if (signature.RetType.ElementType != ElementType.Void)
                Boxed(signature.RetType);
            return null;
        }

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
                    Unboxed(_stub.ReturnType);
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
                    Truth();
                    return Jump(line, condition == "brtrue" ? OpCodes.Brtrue : OpCodes.Brfalse);
                case "beq":
                case "bne.un":
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
                    Spill(2);
                    Push(0);
                    Add(OpCodes.Call, ToInt64);
                    Push(1);
                    Add(OpCodes.Call, ToInt64);
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

        private string? Arithmetic(VirtualLift.Line line, OpCode how)
        {
            var wide = Wide(line);
            Spill(2);
            Push(0);
            Add(OpCodes.Call, wide ? ToInt64 : ToInt32);
            Push(1);
            Add(OpCodes.Call, wide ? ToInt64 : ToInt32);
            Add(how);
            Add(OpCodes.Box, (wide ? module.CorLibTypes.Int64 : module.CorLibTypes.Int32)
                .ToTypeDefOrRef());
            return null;
        }

        /// <summary>A shift takes its distance as an int whatever width it shifts.</summary>
        private string? Shift(VirtualLift.Line line, OpCode how)
        {
            var wide = Wide(line);
            Spill(2);
            Push(0);
            Add(OpCodes.Call, wide ? ToInt64 : ToInt32);
            Push(1);
            Add(OpCodes.Call, ToInt32);
            Add(how);
            Add(OpCodes.Box, (wide ? module.CorLibTypes.Int64 : module.CorLibTypes.Int32)
                .ToTypeDefOrRef());
            return null;
        }

        private string? Unary(VirtualLift.Line line, OpCode how)
        {
            var wide = Wide(line);
            Add(OpCodes.Call, wide ? ToInt64 : ToInt32);
            Add(how);
            Add(OpCodes.Box, (wide ? module.CorLibTypes.Int64 : module.CorLibTypes.Int32)
                .ToTypeDefOrRef());
            return null;
        }

        /// <summary>Whether the operation was established to work at sixty-four bits.</summary>
        private bool Wide(VirtualLift.Line line) =>
            program.Operations.TryGetValue(program.Instructions[line.Index].Opcode, out var known) &&
            (known.Pushed ?? known.Popped) is "System.Int64" or "System.UInt64";

        private string? Convert(string mnemonic)
        {
            var (call, boxed) = mnemonic switch
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
            if (call is null || boxed is null)
                return $"there is no lowering for {mnemonic}";
            Add(OpCodes.Call, call);
            Add(OpCodes.Box, boxed.ToTypeDefOrRef());
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

        /// <summary>Takes values off the stack so that what is beneath them can be reached.</summary>
        private void Spill(int count)
        {
            while (_scratch.Count < count)
            {
                _scratch.Add(new Local(module.CorLibTypes.Object)
                {
                    Name = $"held{_scratch.Count.ToString(CultureInfo.InvariantCulture)}"
                });
            }
            for (var at = count - 1; at >= 0; at--)
                Add(OpCodes.Stloc, _scratch[at]);
        }

        private void Push(int held) => Add(OpCodes.Ldloc, _scratch[held]);

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
