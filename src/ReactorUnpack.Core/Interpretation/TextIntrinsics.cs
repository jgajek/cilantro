using System.Globalization;
using System.Text;
using dnlib.DotNet;

namespace ReactorUnpack.Core.Interpretation;

/// <summary>
/// Models <c>System.Text.StringBuilder</c>, which is how obfuscated code assembles a string it did
/// not want written down.
/// </summary>
/// <remarks>
/// <para>
/// A builder is a buffer with append and read on it, so the model is the real class: the machine
/// keeps a <see cref="StringBuilder"/> alongside the object and every modeled call is the same call
/// on it. That makes the answers the framework's answers rather than a reimplementation that agrees
/// with it on the cases somebody thought to check.
/// </para>
/// <para>
/// What a value looks like when appended depends on its static type and not on its bits — appending
/// the number 65 writes two digits, appending the character with that code writes a letter — so the
/// formatting is driven by the parameter type in the call's own signature. Where that type admits
/// something whose text the machine cannot know, such as an arbitrary object whose
/// <c>ToString</c> is its own code, the call is refused rather than guessed at.
/// </para>
/// <para>
/// <c>AppendFormat</c> is deliberately absent. Its result depends on format specifiers and on the
/// culture in force, and a model that ignored either would produce a string that looks right and is
/// wrong, which is worse here than stopping.
/// </para>
/// </remarks>
public sealed class StringBuilderIntrinsic : IStaticIntrinsic
{
    /// <summary>Model slot holding the buffer that stands for the object's contents.</summary>
    private const string Contents = "Text";

    private const string TypeName = "System.Text.StringBuilder";

    /// <summary>
    /// What the machine a sample expects calls a line break. It is stated here rather than taken
    /// from the analysis machine, because a Windows program building a string on Linux would
    /// otherwise build a different string than the one it builds where it runs.
    /// </summary>
    private const string LineBreak = "\r\n";

    public bool Matches(IMethod method) => method?.DeclaringType?.FullName == TypeName;

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(arguments);
        if (arguments.Any(value => !value.IsKnown))
            return IntrinsicResult.Unknown($"{method.FullName} received an unknown value.");

        var heap = context.State.Heap;
        var name = method.Name.String;
        if (arguments.Count == 0)
            return IntrinsicResult.Invalid($"Unsupported builder operation {name}.");
        if (Buffer(heap, arguments[0]) is not { } builder)
            return IntrinsicResult.Invalid($"The receiver of {name} is not a string builder.");
        var receiver = arguments[0];

        switch (name)
        {
            // Constructing with an initial string or a capacity are the two shapes that carry
            // information; the rest differ only in how much room they ask for, which this model
            // does not have to honour because it does not have a fixed buffer.
            case ".ctor":
                if (arguments.Count >= 2 && heap.TryGetString(arguments[1], out var initial))
                    builder.Append(initial);
                return IntrinsicResult.Completed();

            case "Append" or "AppendLine" or "Insert":
                return AppendOrInsert(context, method, arguments, builder, name);

            case "Remove" when arguments.Count == 3:
            {
                var start = arguments[1].AsInt32();
                var count = arguments[2].AsInt32();
                if (start < 0 || count < 0 || start + count > builder.Length)
                    return IntrinsicResult.Invalid("The range to remove is outside the builder.");
                builder.Remove(start, count);
                return IntrinsicResult.Completed(receiver);
            }

            case "Replace" when arguments.Count is 3 or 5:
            {
                if (!TryText(context, method, arguments, 0, out var searched, out var failure) ||
                    !TryText(context, method, arguments, 1, out var replacement, out failure))
                    return failure;
                if (arguments.Count == 5)
                {
                    var start = arguments[3].AsInt32();
                    var count = arguments[4].AsInt32();
                    if (start < 0 || count < 0 || start + count > builder.Length)
                        return IntrinsicResult.Invalid(
                            "The range to replace in is outside the builder.");
                    builder.Replace(searched, replacement, start, count);
                }
                else
                {
                    builder.Replace(searched, replacement);
                }

                return IntrinsicResult.Completed(receiver);
            }

            case "Clear" when arguments.Count == 1:
                builder.Clear();
                return IntrinsicResult.Completed(receiver);

            case "ToString":
            {
                var text = builder.ToString();
                if (arguments.Count == 3)
                {
                    var start = arguments[1].AsInt32();
                    var count = arguments[2].AsInt32();
                    if (start < 0 || count < 0 || start + count > text.Length)
                        return IntrinsicResult.Invalid("The range to read is outside the builder.");
                    text = text.Substring(start, count);
                }
                else if (arguments.Count != 1)
                {
                    return IntrinsicResult.Invalid($"Unsupported builder operation {name}.");
                }

                return heap.TryAllocateString(text, out var allocated)
                    ? IntrinsicResult.Completed(allocated)
                    : Overflowed();
            }

            case "get_Length" when arguments.Count == 1:
                return IntrinsicResult.Completed(StaticValue.FromInt32(builder.Length));

            // Shortening truncates and lengthening pads with the zero character, which is what the
            // framework does, so the one guard is against a length this heap would not hold.
            case "set_Length" when arguments.Count == 2:
            {
                var length = arguments[1].AsInt32();
                if (length < 0 || length > heap.MaximumObjectLength)
                    return IntrinsicResult.Invalid("The length asked for is outside the builder.");
                builder.Length = length;
                return IntrinsicResult.Completed();
            }

            // Capacity is invisible in the result of every other operation, so it is reported as
            // whatever was asked for and otherwise ignored.
            case "get_Capacity" when arguments.Count == 1:
                return IntrinsicResult.Completed(StaticValue.FromInt32(builder.Length));
            case "get_MaxCapacity" when arguments.Count == 1:
                return IntrinsicResult.Completed(
                    StaticValue.FromInt32(heap.MaximumObjectLength));
            case "set_Capacity" when arguments.Count == 2:
                return IntrinsicResult.Completed();
            case "EnsureCapacity" when arguments.Count == 2:
                return IntrinsicResult.Completed(arguments[1]);

            case "get_Chars" when arguments.Count == 2:
            {
                var index = arguments[1].AsInt32();
                return index >= 0 && index < builder.Length
                    ? IntrinsicResult.Completed(StaticValue.FromInt32(builder[index]))
                    : IntrinsicResult.Invalid("The character asked for is outside the builder.");
            }

            case "set_Chars" when arguments.Count == 3:
            {
                var index = arguments[1].AsInt32();
                if (index < 0 || index >= builder.Length)
                    return IntrinsicResult.Invalid("The character written is outside the builder.");
                builder[index] = (char)arguments[2].AsInt32();
                return IntrinsicResult.Completed();
            }

            default:
                return IntrinsicResult.Invalid($"Unsupported builder operation {name}.");
        }
    }

    /// <summary>
    /// Appends or inserts one value, in whichever of the several shapes the call site used.
    /// </summary>
    private static IntrinsicResult AppendOrInsert(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments,
        StringBuilder builder,
        string name)
    {
        var receiver = arguments[0];
        // AppendLine() with nothing to append is the whole call.
        if (name == "AppendLine" && arguments.Count == 1)
            return Grow(context, builder, LineBreak, receiver);

        // Insert takes the position first, so the value it is given sits one place further along.
        var inserting = name == "Insert";
        var valueIndex = inserting ? 1 : 0;
        if (!TryText(context, method, arguments, valueIndex, out var text, out var failure))
            return failure;

        // The trailing count means different things: a repeat for a single character, and a range
        // for a sequence of them. Both are only ever present on Append.
        if (!inserting && arguments.Count > 2)
        {
            var signature = Parameter(method, valueIndex);
            var last = arguments.Count - 1;
            if (arguments.Count == 3 && signature?.ElementType == ElementType.Char)
            {
                var repeat = arguments[last].AsInt32();
                if (repeat < 0 ||
                    (long)repeat * text.Length > context.State.Heap.MaximumObjectLength)
                    return IntrinsicResult.Invalid("The repeat count is out of range.");
                text = string.Concat(Enumerable.Repeat(text, repeat));
            }
            else if (arguments.Count == 4)
            {
                var start = arguments[2].AsInt32();
                var count = arguments[3].AsInt32();
                if (start < 0 || count < 0 || start + count > text.Length)
                    return IntrinsicResult.Invalid("The range appended is outside its source.");
                text = text.Substring(start, count);
            }
            else
            {
                return IntrinsicResult.Invalid($"Unsupported builder operation {name}.");
            }
        }

        if (name == "AppendLine")
            text += LineBreak;
        if (!inserting)
            return Grow(context, builder, text, receiver);

        var position = arguments[1].AsInt32();
        if (position < 0 || position > builder.Length)
            return IntrinsicResult.Invalid("The position inserted at is outside the builder.");
        // Insert(int, string, int) repeats what it inserts.
        if (arguments.Count == 4)
        {
            var repeat = arguments[3].AsInt32();
            if (repeat < 0 ||
                (long)repeat * text.Length > context.State.Heap.MaximumObjectLength)
                return IntrinsicResult.Invalid("The repeat count is out of range.");
            text = string.Concat(Enumerable.Repeat(text, repeat));
        }
        else if (arguments.Count != 3)
        {
            return IntrinsicResult.Invalid($"Unsupported builder operation {name}.");
        }

        if (!Fits(context, builder, text))
            return Overflowed();
        builder.Insert(position, text);
        return IntrinsicResult.Completed(receiver);
    }

    private static IntrinsicResult Grow(
        IntrinsicContext context,
        StringBuilder builder,
        string text,
        StaticValue receiver)
    {
        if (!Fits(context, builder, text))
            return Overflowed();
        builder.Append(text);
        return IntrinsicResult.Completed(receiver);
    }

    /// <summary>
    /// Whether the builder may hold this much more. A builder is not itself an allocation this heap
    /// tracks, so the array limit stands in as the bound on how large one may become; without it a
    /// loop appending inside the interpretation would grow the analysis process without limit.
    /// </summary>
    private static bool Fits(IntrinsicContext context, StringBuilder builder, string text) =>
        (long)builder.Length + text.Length <= context.State.Heap.MaximumObjectLength;

    private static IntrinsicResult Overflowed() => new(
        StaticExecutionStatus.AllocationLimitExceeded,
        StaticValue.Unknown,
        "The string being built outgrew the allocation budget.");

    /// <summary>Hands back the buffer standing for a builder, making it on first use.</summary>
    private static StringBuilder? Buffer(StaticHeap heap, StaticValue receiver)
    {
        if (heap.TryGetModelValue(receiver, Contents, out StringBuilder? existing) &&
            existing is not null)
            return existing;
        if (!heap.TryGetRuntimeTypeName(receiver, out var typeName) || typeName != TypeName)
            return null;
        var created = new StringBuilder();
        return heap.TrySetModelValue(receiver, Contents, created) ? created : null;
    }

    private static TypeSig? Parameter(IMethod method, int index)
    {
        var parameters = method.MethodSig?.Params;
        return parameters is not null && index >= 0 && index < parameters.Count
            ? parameters[index]
            : null;
    }

    /// <summary>
    /// Renders the value passed for one parameter the way the framework would write it.
    /// </summary>
    private static bool TryText(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments,
        int parameterIndex,
        out string text,
        out IntrinsicResult failure)
    {
        text = string.Empty;
        failure = IntrinsicResult.Completed();
        var argumentIndex = parameterIndex + 1;
        if (argumentIndex >= arguments.Count)
        {
            failure = IntrinsicResult.Invalid(
                $"Unsupported builder operation {method.Name.String}.");
            return false;
        }

        var signature = Parameter(method, parameterIndex);
        if (TryRender(context.State.Heap, signature, arguments[argumentIndex], out text))
            return true;
        failure = IntrinsicResult.Invalid(
            $"What {signature?.FullName ?? "the value"} appended would read as is not known.");
        return false;
    }

    private static bool TryRender(
        StaticHeap heap,
        TypeSig? signature,
        StaticValue value,
        out string text)
    {
        text = string.Empty;
        if (value.Kind == StaticValueKind.Null)
            return true;
        switch (signature?.ElementType)
        {
            case ElementType.String:
                return heap.TryGetString(value, out text);
            case ElementType.Char:
                text = ((char)value.AsInt32()).ToString();
                return true;
            case ElementType.Boolean:
                text = value.AsInt32() != 0 ? bool.TrueString : bool.FalseString;
                return true;
            case ElementType.I1:
                return Number((sbyte)value.AsInt32(), out text);
            case ElementType.U1:
                return Number((byte)value.AsInt32(), out text);
            case ElementType.I2:
                return Number((short)value.AsInt32(), out text);
            case ElementType.U2:
                return Number((ushort)value.AsInt32(), out text);
            case ElementType.I4:
                return Number(value.AsInt32(), out text);
            case ElementType.U4:
                return Number((uint)value.AsInt32(), out text);
            case ElementType.I8:
                return Number(value.AsInt64(), out text);
            case ElementType.U8:
                text = ((ulong)value.AsInt64()).ToString(CultureInfo.InvariantCulture);
                return true;
            case ElementType.R4:
                text = value.AsFloat32().ToString(CultureInfo.InvariantCulture);
                return true;
            case ElementType.R8:
                text = value.AsFloat64().ToString(CultureInfo.InvariantCulture);
                return true;
            case ElementType.SZArray when
                signature.Next?.ElementType == ElementType.Char:
                return TryRenderChars(heap, value, out text);
            // An object parameter carries whatever was boxed into it, and that is the thing whose
            // text is wanted. A reference to something with a body of its own is not rendered,
            // because what it writes is that body's business.
            case ElementType.Object:
                if (heap.TryGetString(value, out text))
                    return true;
                if (heap.TryUnbox(value, out var unboxed) &&
                    heap.TryGetRuntimeTypeName(value, out var boxed))
                    return BoxedText.TryRender(boxed, unboxed, out text);
                return false;
            default:
                return false;
        }
    }

    private static bool TryRenderChars(StaticHeap heap, StaticValue value, out string text)
    {
        text = string.Empty;
        if (!heap.TryGetLength(value, out var length))
            return false;
        var characters = new char[length];
        for (var index = 0; index < length; index++)
        {
            if (!heap.TryReadArray(value, index, out var element) || !element.IsInteger)
                return false;
            characters[index] = (char)element.AsInt32();
        }

        text = new string(characters);
        return true;
    }

    private static bool Number(long value, out string text)
    {
        text = value.ToString(CultureInfo.InvariantCulture);
        return true;
    }
}

/// <summary>
/// What a boxed primitive reads as, given the type it was boxed from.
/// </summary>
/// <remarks>
/// The bits alone do not say: the same integer reads as a letter, a digit string, or a truth value
/// depending on the type it wears. Every caller that renders one is asking the same question, so
/// they ask it here rather than each keeping its own table of type names to fall out of step.
/// </remarks>
internal static class BoxedText
{
    public static bool TryRender(string typeName, StaticValue value, out string text)
    {
        text = string.Empty;
        switch (typeName)
        {
            case "System.Char":
                text = ((char)value.AsInt32()).ToString();
                return true;
            case "System.Boolean":
                text = value.AsInt32() != 0 ? bool.TrueString : bool.FalseString;
                return true;
            case "System.SByte":
                return Digits((sbyte)value.AsInt32(), out text);
            case "System.Byte":
                return Digits((byte)value.AsInt32(), out text);
            case "System.Int16":
                return Digits((short)value.AsInt32(), out text);
            case "System.UInt16":
                return Digits((ushort)value.AsInt32(), out text);
            case "System.Int32":
                return Digits(value.AsInt32(), out text);
            case "System.UInt32":
                return Digits((uint)value.AsInt32(), out text);
            case "System.Int64":
                return Digits(value.AsInt64(), out text);
            case "System.UInt64":
                text = ((ulong)value.AsInt64()).ToString(CultureInfo.InvariantCulture);
                return true;
            case "System.Single":
                text = value.AsFloat32().ToString(CultureInfo.InvariantCulture);
                return true;
            case "System.Double":
                text = value.AsFloat64().ToString(CultureInfo.InvariantCulture);
                return true;
            default:
                return false;
        }
    }

    private static bool Digits(long value, out string text)
    {
        text = value.ToString(CultureInfo.InvariantCulture);
        return true;
    }
}
