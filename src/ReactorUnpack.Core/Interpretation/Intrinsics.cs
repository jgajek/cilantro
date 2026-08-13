using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Globalization;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core.Payload;

namespace ReactorUnpack.Core.Interpretation;

public sealed record IntrinsicResult(
    StaticExecutionStatus Status,
    StaticValue Value,
    string? Diagnostic = null)
{
    public static IntrinsicResult Completed(StaticValue value = default) =>
        new(StaticExecutionStatus.Completed, value);
    public static IntrinsicResult Unknown(string diagnostic) =>
        new(StaticExecutionStatus.Unknown, StaticValue.Unknown, diagnostic);
    public static IntrinsicResult Invalid(string diagnostic) =>
        new(StaticExecutionStatus.InvalidProgram, StaticValue.Unknown, diagnostic);
}

/// <summary>
/// Calls a delegate the machine built, so a modeled API can run a callback it was handed.
/// </summary>
/// <remarks>
/// Several framework methods take a function and are meaningless without calling it — sorting with
/// a comparison being the one that turns up in obfuscator runtimes. Modeling those without a way
/// back into the interpreter would mean either refusing them or inventing a result, so the machine
/// lends the intrinsics its own call mechanism. It stays a lending rather than a widening: only
/// delegates whose construction the machine witnessed can be called, and the callee runs on the
/// same budget and depth as everything else.
/// </remarks>
public delegate IntrinsicResult DelegateInvoker(
    StaticValue target,
    IReadOnlyList<StaticValue> arguments);

/// <summary>
/// Runs a method on behalf of a modeled reflection call, whether the body is here or modeled.
/// </summary>
public delegate IntrinsicResult MethodInvoker(
    IMethod method,
    IReadOnlyList<StaticValue> arguments);

public sealed record IntrinsicContext(
    StaticMachineState State,
    DelegateInvoker? Invoke = null,
    MethodInvoker? Call = null,
    IReadOnlyList<MethodDef>? Frames = null);

public interface IStaticIntrinsic
{
    bool Matches(IMethod method);
    IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments);
}

public interface IStaticIntrinsicRegistry
{
    bool TryResolve(IMethod method, out IStaticIntrinsic intrinsic);
}

public sealed class StaticIntrinsicRegistry : IStaticIntrinsicRegistry
{
    private readonly List<IStaticIntrinsic> _intrinsics;

    public StaticIntrinsicRegistry(IEnumerable<IStaticIntrinsic>? intrinsics = null) =>
        _intrinsics = intrinsics?.ToList() ?? [];

    public static StaticIntrinsicRegistry CreateDefault() => new(
    [
        new BitConverterIntrinsic(),
        new ArrayIntrinsic(),
        new ListEnumeratorIntrinsic(),
        new GenericListIntrinsic(),
        new GenericDictionaryIntrinsic(),
        new MonitorIntrinsic(),
        new AmbientIntrinsic(),
        new SequenceIntrinsic(),
        new NumberIntrinsic(),
        new ConversionIntrinsic(),
        new ReflectionEmitIntrinsic(),
        new StackFrameIntrinsic(),
        new DebuggerIntrinsic(),
        new ThreadIntrinsic(),
        new NativeDelegateIntrinsic(),
        new LoaderFrameworkIntrinsic(),
        new VirtualRegionIntrinsic()
    ]);

    public void Register(IStaticIntrinsic intrinsic)
    {
        ArgumentNullException.ThrowIfNull(intrinsic);
        _intrinsics.Add(intrinsic);
    }

    public bool TryResolve(IMethod method, out IStaticIntrinsic intrinsic)
    {
        intrinsic = _intrinsics.FirstOrDefault(candidate => candidate.Matches(method))!;
        return intrinsic is not null;
    }
}

public sealed class NativeDelegateIntrinsic : IStaticIntrinsic
{
    public bool Matches(IMethod method) =>
        method.Name == "Invoke" &&
        method.DeclaringType.ResolveTypeDef()?.BaseType?.FullName is
            "System.MulticastDelegate" or "System.Delegate";

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        if (arguments.Count == 0 ||
            !context.State.Heap.TryGetModelValue(
                arguments[0], "NativeName", out string? nativeName) ||
            string.IsNullOrEmpty(nativeName))
            return IntrinsicResult.Invalid("Native delegate target is not modeled.");
        if (nativeName is "VirtualProtect" or "VirtualProtectEx")
        {
            if (arguments.Count >= 5 &&
                arguments[^1].Kind == StaticValueKind.ManagedReference)
                context.State.Heap.TryWriteManaged(arguments[^1], StaticValue.FromInt32(4));
            return IntrinsicResult.Completed(StaticValue.FromInt32(1));
        }
        if (nativeName == "OpenProcess" && arguments.Count == 4)
        {
            const int modeledProcessId = 1;
            if (arguments[3].AsInt32() != modeledProcessId)
                return IntrinsicResult.Invalid(
                    "OpenProcess may only target the modeled current process.");
            if (!context.State.Heap.TryAllocateObject(
                    "SyntheticProcessHandle",
                    out var handle))
            {
                return new IntrinsicResult(
                    StaticExecutionStatus.AllocationLimitExceeded,
                    StaticValue.Unknown,
                    "Synthetic process handle exceeded the allocation budget.");
            }
            context.State.Heap.TrySetModelValue(handle, "ProcessId", modeledProcessId);
            return IntrinsicResult.Completed(handle);
        }
        if (nativeName == "CloseHandle" &&
            arguments.Count == 2 &&
            context.State.Heap.TryGetModelValue(arguments[1], "ProcessId", out int _))
        {
            return IntrinsicResult.Completed(StaticValue.FromInt32(1));
        }
        if (nativeName == "WriteProcessMemory" && arguments.Count == 6)
        {
            var heap = context.State.Heap;
            if (!heap.TryGetModelValue(arguments[1], "ProcessId", out int processId) ||
                processId != 1)
            {
                return IntrinsicResult.Invalid(
                    "WriteProcessMemory requires the modeled current-process handle.");
            }
            var destination = arguments[2];
            if (destination.IsInteger &&
                heap.TryResolveNativeAddress(destination.AsInt64(), out var resolved))
            {
                destination = resolved;
            }
            var count = arguments[4].AsInt32();
            var bytes = new byte[count < 0 ? 0 : count];
            if (count < 0 ||
                !heap.TryReadBytes(arguments[3], 0, bytes) ||
                !heap.TryWriteBytes(destination, 0, bytes))
            {
                return IntrinsicResult.Invalid(
                    $"WriteProcessMemory range is invalid (destination={destination.Kind}:" +
                    $"{destination.Bits}, count={count}).");
            }
            if (arguments[5].Kind == StaticValueKind.ManagedReference)
                heap.TryWriteManaged(arguments[5], StaticValue.FromInt32(count));
            return IntrinsicResult.Completed(StaticValue.FromInt32(1));
        }
        return IntrinsicResult.Invalid(
            $"Native delegate operation {nativeName} is unsupported.");
    }
}

/// <summary>
/// Models <c>Dictionary&lt;K, V&gt;</c> as the association it is.
/// </summary>
/// <remarks>
/// Keys are matched on their contents rather than on their heap identity whenever the contents are
/// known, because a program that looks something up by a string it just built expects to find what
/// it stored under an equal string. Comparing references instead would turn every such lookup into
/// a miss, which is a wrong answer rather than a refused one.
/// </remarks>
public sealed class GenericDictionaryIntrinsic : IStaticIntrinsic
{
    private const string PairsKey = "Pairs";

    public bool Matches(IMethod method) =>
        method.DeclaringType.FullName.StartsWith(
            "System.Collections.Generic.Dictionary`2<",
            StringComparison.Ordinal);

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        var name = method.Name.String;
        if (name == ".ctor")
        {
            if (!heap.TryAllocateObject(method.DeclaringType.FullName, out var map) ||
                !heap.TrySetModelValue(map, PairsKey, new List<KeyValuePair<StaticValue, StaticValue>>()))
            {
                return IntrinsicResult.Invalid("Could not allocate a modeled Dictionary<K,V>.");
            }

            return IntrinsicResult.Completed(map);
        }
        if (arguments.Count == 0 ||
            !heap.TryGetModelValue<List<KeyValuePair<StaticValue, StaticValue>>>(
                arguments[0], PairsKey, out var pairs) ||
            pairs is null)
        {
            return IntrinsicResult.Invalid($"Dictionary<K,V>.{name} target is not modeled.");
        }

        switch (name)
        {
            case "get_Count" when arguments.Count == 1:
                return IntrinsicResult.Completed(StaticValue.FromInt32(pairs.Count));
            case "set_Item" or "Add" when arguments.Count == 3:
                var at = IndexOf(heap, pairs, arguments[1]);
                if (at >= 0)
                    pairs[at] = new KeyValuePair<StaticValue, StaticValue>(arguments[1], arguments[2]);
                else
                    pairs.Add(new KeyValuePair<StaticValue, StaticValue>(arguments[1], arguments[2]));
                return IntrinsicResult.Completed();
            case "get_Item" when arguments.Count == 2:
                var found = IndexOf(heap, pairs, arguments[1]);
                return found >= 0
                    ? IntrinsicResult.Completed(pairs[found].Value)
                    : IntrinsicResult.Invalid("The dictionary has no entry under that key.");
            case "ContainsKey" when arguments.Count == 2:
                return IntrinsicResult.Completed(
                    StaticValue.FromInt32(IndexOf(heap, pairs, arguments[1]) >= 0 ? 1 : 0));
            case "Remove" when arguments.Count == 2:
                var removing = IndexOf(heap, pairs, arguments[1]);
                if (removing >= 0)
                    pairs.RemoveAt(removing);
                return IntrinsicResult.Completed(StaticValue.FromInt32(removing >= 0 ? 1 : 0));
            case "TryGetValue" when arguments.Count == 3:
                var probed = IndexOf(heap, pairs, arguments[1]);
                if (!heap.TryWriteManaged(
                        arguments[2],
                        probed >= 0 ? pairs[probed].Value : StaticValue.Null))
                {
                    return IntrinsicResult.Invalid("The lookup result could not be stored.");
                }

                return IntrinsicResult.Completed(StaticValue.FromInt32(probed >= 0 ? 1 : 0));
            default:
                return IntrinsicResult.Invalid($"Dictionary<K,V>.{name} is unsupported.");
        }
    }

    private static int IndexOf(
        StaticHeap heap,
        List<KeyValuePair<StaticValue, StaticValue>> pairs,
        StaticValue key)
    {
        var keyed = heap.TryGetString(key, out var text) ? text : null;
        for (var index = 0; index < pairs.Count; index++)
        {
            var candidate = pairs[index].Key;
            if (keyed is not null && heap.TryGetString(candidate, out var other))
            {
                if (string.Equals(keyed, other, StringComparison.Ordinal))
                    return index;
                continue;
            }

            if (candidate.Equals(key))
                return index;
        }

        return -1;
    }
}

/// <summary>
/// Models the enumerator a <c>List&lt;T&gt;</c> hands out, so <c>foreach</c> runs.
/// </summary>
/// <remarks>
/// The enumerator is a value type, so the compiler holds it in a local and calls through its
/// address. The receiver therefore arrives as a reference to the slot rather than as the object,
/// and it is followed to reach the state; without that, every iteration would look like a call on
/// something unmodeled.
/// </remarks>
public sealed class ListEnumeratorIntrinsic : IStaticIntrinsic
{
    internal const string ItemsKey = "EnumeratorItems";
    internal const string IndexKey = "EnumeratorIndex";

    internal const string EnumeratorPrefix = "System.Collections.Generic.List`1/Enumerator<";

    public bool Matches(IMethod method) =>
        method.DeclaringType.FullName.StartsWith(EnumeratorPrefix, StringComparison.Ordinal);

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (arguments.Count == 0)
            return IntrinsicResult.Invalid("The enumerator has no receiver.");
        var self = arguments[0].Kind == StaticValueKind.ManagedReference &&
            heap.TryReadManaged(arguments[0], out var pointed)
                ? pointed
                : arguments[0];
        if (!heap.TryGetModelValue<List<StaticValue>>(self, ItemsKey, out var items) || items is null)
            return IntrinsicResult.Invalid($"Enumerator.{method.Name} target is not modeled.");
        heap.TryGetModelValue<int>(self, IndexKey, out var index);
        switch (method.Name.String)
        {
            case "MoveNext":
                var advanced = index + 1;
                heap.TrySetModelValue(self, IndexKey, advanced);
                return IntrinsicResult.Completed(
                    StaticValue.FromInt32(advanced < items.Count ? 1 : 0));
            case "get_Current":
                return (uint)index < (uint)items.Count
                    ? IntrinsicResult.Completed(items[index])
                    : IntrinsicResult.Invalid("The enumerator is not positioned on an element.");
            case "Reset":
                heap.TrySetModelValue(self, IndexKey, -1);
                return IntrinsicResult.Completed();
            case "Dispose":
                return IntrinsicResult.Completed();
            default:
                return IntrinsicResult.Invalid($"Enumerator.{method.Name} is unsupported.");
        }
    }
}

public sealed class GenericListIntrinsic : IStaticIntrinsic
{
    public bool Matches(IMethod method) =>
        method.DeclaringType.FullName.StartsWith(
            "System.Collections.Generic.List`1<",
            StringComparison.Ordinal);

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        var name = method.Name.String;
        if (name == ".ctor")
        {
            if (!heap.TryAllocateObject(method.DeclaringType.FullName, out var list) ||
                !heap.TrySetModelValue(list, "Items", new List<StaticValue>()))
                return IntrinsicResult.Invalid("Could not allocate modeled List<T>.");
            return IntrinsicResult.Completed(list);
        }
        if (arguments.Count == 0 ||
            !heap.TryGetModelValue<List<StaticValue>>(arguments[0], "Items", out var items) ||
            items is null)
            return IntrinsicResult.Invalid($"List<T>.{name} target is not modeled.");
        if (name == "Add" && arguments.Count == 2)
        {
            items.Add(arguments[1]);
            return IntrinsicResult.Completed();
        }
        if (name == "get_Count" && arguments.Count == 1)
            return IntrinsicResult.Completed(StaticValue.FromInt32(items.Count));
        // Sorting is done by asking the comparison the caller supplied, because the machine has no
        // ordering of its own for modeled values and inventing one would reorder the list into
        // something the program never produced.
        if (name == "Sort" && arguments.Count == 2 && context.Invoke is { } invoke)
        {
            var comparison = arguments[1];
            IntrinsicResult? failure = null;
            var sorted = items.ToList();
            sorted.Sort((left, right) =>
            {
                if (failure is not null)
                    return 0;
                var verdict = invoke(comparison, [left, right]);
                if (verdict.Status != StaticExecutionStatus.Completed ||
                    verdict.Value.Kind != StaticValueKind.Int32)
                {
                    failure = IntrinsicResult.Invalid(
                        $"The sort comparison could not be evaluated: {verdict.Diagnostic}");
                    return 0;
                }

                return verdict.Value.AsInt32();
            });
            if (failure is not null)
                return failure;
            items.Clear();
            items.AddRange(sorted);
            return IntrinsicResult.Completed();
        }
        if (name == "get_Item" && arguments.Count == 2)
        {
            var index = arguments[1].AsInt32();
            return (uint)index < (uint)items.Count
                ? IntrinsicResult.Completed(items[index])
                : IntrinsicResult.Invalid("List<T> index is out of range.");
        }
        if (name == "set_Item" && arguments.Count == 3)
        {
            var index = arguments[1].AsInt32();
            if ((uint)index >= (uint)items.Count)
                return IntrinsicResult.Invalid("List<T> index is out of range.");
            items[index] = arguments[2];
            return IntrinsicResult.Completed();
        }
        if (name == "GetEnumerator" && arguments.Count == 1)
        {
            var element = method.DeclaringType.FullName["System.Collections.Generic.List`1<".Length..];
            if (!heap.TryAllocateObject(
                    ListEnumeratorIntrinsic.EnumeratorPrefix + element, out var enumerator) ||
                !heap.TrySetModelValue(enumerator, ListEnumeratorIntrinsic.ItemsKey, items) ||
                !heap.TrySetModelValue(enumerator, ListEnumeratorIntrinsic.IndexKey, -1))
            {
                return IntrinsicResult.Invalid("Could not allocate a modeled enumerator.");
            }

            return IntrinsicResult.Completed(enumerator);
        }
        if (name == "RemoveAt" && arguments.Count == 2)
        {
            var index = arguments[1].AsInt32();
            if ((uint)index >= (uint)items.Count)
                return IntrinsicResult.Invalid("List<T> index is out of range.");
            items.RemoveAt(index);
            return IntrinsicResult.Completed();
        }
        if (name == "Insert" && arguments.Count == 3)
        {
            var index = arguments[1].AsInt32();
            if ((uint)index > (uint)items.Count)
                return IntrinsicResult.Invalid("List<T> index is out of range.");
            items.Insert(index, arguments[2]);
            return IntrinsicResult.Completed();
        }
        if (name == "Clear" && arguments.Count == 1)
        {
            items.Clear();
            return IntrinsicResult.Completed();
        }
        if (name == "Reverse" && arguments.Count == 1)
        {
            items.Reverse();
            return IntrinsicResult.Completed();
        }
        if (name is "Contains" or "IndexOf" && arguments.Count == 2)
        {
            var at = items.FindIndex(item => item.Equals(arguments[1]));
            return IntrinsicResult.Completed(StaticValue.FromInt32(
                name == "Contains" ? at >= 0 ? 1 : 0 : at));
        }
        if (name == "ToArray" && arguments.Count == 1)
        {
            if (!heap.TryAllocateArray(null, items.Count, out var array))
                return IntrinsicResult.Invalid("Could not allocate List<T> array.");
            for (var index = 0; index < items.Count; index++)
            {
                if (!heap.TryGetArrayElementReference(array, index, out var element) ||
                    !heap.TryWriteManaged(element, items[index]))
                    return IntrinsicResult.Invalid("Could not populate List<T> array.");
            }
            return IntrinsicResult.Completed(array);
        }
        if (name == "Clear" && arguments.Count == 1)
        {
            items.Clear();
            return IntrinsicResult.Completed();
        }
        return IntrinsicResult.Invalid($"Unsupported List<T> operation {name}.");
    }
}

/// <summary>
/// Answers questions about the world outside the program with stable, made-up answers.
/// </summary>
/// <remarks>
/// Loaders ask the clock what time it is and mint identifiers to name a mutex, a pipe, or a
/// temporary file — things that depend on the machine that runs them and mean nothing to a reader.
/// Refusing the call would stop the interpretation on a path the program merely passes through, so
/// the machine answers, and answers the same way every time so that two runs still agree.
///
/// The value is arbitrary, and anything computed from it is arbitrary too. That is safe here only
/// because what this machine is used to recover is checked on its own terms afterwards — a payload
/// has to parse as an assembly, a string table has to decode — so a result that depended on a made
/// up identifier does not survive to be reported as fact.
/// </remarks>
public sealed class AmbientIntrinsic : IStaticIntrinsic
{
    private const string Bytes = "Bytes";
    private const string Ticks = "Ticks";

    /// <summary>An arbitrary fixed instant, so that a run is not a function of when it happened.</summary>
    private static readonly DateTime Fixed = new(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    public bool Matches(IMethod method) =>
        method.DeclaringType.FullName is "System.Guid" or "System.DateTime";

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        var name = method.Name.String;
        if (name is "get_UtcNow" or "get_Now" or "get_Today" && arguments.Count == 0)
        {
            if (!heap.TryAllocateObject("System.DateTime", out var instant))
                return AllocationFailure("instant");
            heap.TrySetModelValue(instant, Ticks, Fixed.Ticks);
            return IntrinsicResult.Completed(instant);
        }
        if (name == "get_Ticks" && arguments.Count == 1 &&
            heap.TryGetModelValue(arguments[0], Ticks, out long reading))
            return IntrinsicResult.Completed(StaticValue.FromInt64(reading));
        if (name is "NewGuid" or "get_Empty" && arguments.Count == 0)
        {
            if (!heap.TryAllocateObject("System.Guid", out var identifier))
                return AllocationFailure("identifier");
            var minted = new byte[16];
            if (name == "NewGuid")
                BinaryPrimitives.WriteInt32LittleEndian(minted, ++_minted);
            heap.TrySetModelValue(identifier, Bytes, minted);
            return IntrinsicResult.Completed(identifier);
        }
        if (name == "ToString" && arguments.Count >= 1 &&
            heap.TryGetModelValue(arguments[0], Ticks, out long shown))
        {
            return heap.TryAllocateString(
                new DateTime(shown, DateTimeKind.Utc).ToString("O", CultureInfo.InvariantCulture),
                out var written)
                ? IntrinsicResult.Completed(written)
                : AllocationFailure("instant text");
        }
        if (name == "ToString" && arguments.Count >= 1 &&
            heap.TryGetModelValue(arguments[0], Bytes, out byte[]? held) && held is not null)
        {
            return heap.TryAllocateString(new Guid(held).ToString(), out var spelled)
                ? IntrinsicResult.Completed(spelled)
                : AllocationFailure("identifier text");
        }
        if (name == "ToByteArray" && arguments.Count == 1 &&
            heap.TryGetModelValue(arguments[0], Bytes, out byte[]? carried) && carried is not null)
        {
            return heap.TryAllocateByteArray(carried, out var copy)
                ? IntrinsicResult.Completed(copy)
                : AllocationFailure("identifier bytes");
        }

        return IntrinsicResult.Invalid($"Unsupported ambient operation {name}.");
    }

    private int _minted;

    private static IntrinsicResult AllocationFailure(string what) =>
        IntrinsicResult.Invalid($"Could not allocate {what}.");
}

/// <summary>
/// Runs the sequence operators, by walking the sequence and calling what it was handed.
/// </summary>
/// <remarks>
/// These read as library calls but are really loops the compiler was asked to write, and a loader
/// that folds a checksum with <c>Aggregate</c> is doing arithmetic, not using a framework feature.
/// Every operator here is evaluated at once rather than lazily. Laziness is observable only through
/// side effects in the callback and through sequences that never end, neither of which a bounded
/// machine can follow anyway, so eager evaluation gives the same answers for the code that reaches
/// here while keeping the model small.
/// </remarks>
public sealed class SequenceIntrinsic : IStaticIntrinsic
{
    public bool Matches(IMethod method) =>
        method.DeclaringType.FullName == "System.Linq.Enumerable" &&
        method.Name.String is "Aggregate" or "ToArray" or "Count" or "Sum" or "First" or "Last"
            or "Reverse" or "Select" or "Where" or "Concat" or "Take" or "Skip" or "Any" or "All";

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        var name = method.Name.String;
        if (arguments.Count == 0 || Walk(heap, arguments[0]) is not { } sequence)
            return IntrinsicResult.Invalid($"Enumerable.{name} was given a sequence it cannot walk.");

        switch (name)
        {
            case "Count":
                return IntrinsicResult.Completed(StaticValue.FromInt32(sequence.Count));
            case "First" when sequence.Count > 0:
                return IntrinsicResult.Completed(sequence[0]);
            case "Last" when sequence.Count > 0:
                return IntrinsicResult.Completed(sequence[^1]);
            case "Reverse":
                sequence.Reverse();
                return Materialize(context, sequence);
            case "ToArray":
                return Materialize(context, sequence);
            case "Take" when arguments.Count == 2:
                return Materialize(context, [.. sequence.Take(arguments[1].AsInt32())]);
            case "Skip" when arguments.Count == 2:
                return Materialize(context, [.. sequence.Skip(arguments[1].AsInt32())]);
            case "Concat" when arguments.Count == 2 && Walk(heap, arguments[1]) is { } rest:
                return Materialize(context, [.. sequence, .. rest]);
        }

        if (context.Invoke is not { } invoke)
            return IntrinsicResult.Invalid($"Enumerable.{name} has no way to call its callback.");
        if (name == "Aggregate" && arguments.Count == 3)
        {
            var carried = arguments[1];
            foreach (var element in sequence)
            {
                var folded = invoke(arguments[2], [carried, element]);
                if (folded.Status != StaticExecutionStatus.Completed)
                    return folded;
                carried = folded.Value;
            }

            return IntrinsicResult.Completed(carried);
        }

        if (name is "Select" or "Where" or "Any" or "All" && arguments.Count == 2)
        {
            var kept = new List<StaticValue>();
            foreach (var element in sequence)
            {
                var answered = invoke(arguments[1], [element]);
                if (answered.Status != StaticExecutionStatus.Completed)
                    return answered;
                if (name == "Select")
                    kept.Add(answered.Value);
                else if (name == "Any" && answered.Value.AsInt32() != 0)
                    return IntrinsicResult.Completed(StaticValue.FromInt32(1));
                else if (name == "All" && answered.Value.AsInt32() == 0)
                    return IntrinsicResult.Completed(StaticValue.FromInt32(0));
                else if (name == "Where" && answered.Value.AsInt32() != 0)
                    kept.Add(element);
            }

            return name switch
            {
                "Any" => IntrinsicResult.Completed(StaticValue.FromInt32(0)),
                "All" => IntrinsicResult.Completed(StaticValue.FromInt32(1)),
                _ => Materialize(context, kept)
            };
        }

        return IntrinsicResult.Invalid($"Unsupported sequence operation {name}.");
    }

    /// <summary>Reads a sequence out of whichever shape the machine is holding it in.</summary>
    private static List<StaticValue>? Walk(StaticHeap heap, StaticValue sequence)
    {
        if (heap.TryGetModelValue<List<StaticValue>>(sequence, "Items", out var held) &&
            held is not null)
            return [.. held];
        if (!heap.TryGetLength(sequence, out var length))
            return null;
        var walked = new List<StaticValue>(length);
        for (var index = 0; index < length; index++)
        {
            if (!heap.TryReadArray(sequence, index, out var element))
                return null;
            walked.Add(element);
        }

        return walked;
    }

    private static IntrinsicResult Materialize(
        IntrinsicContext context,
        List<StaticValue> sequence)
    {
        var heap = context.State.Heap;
        if (!heap.TryAllocateArray(
                context.State.ModuleMetadata?.CorLibTypes.Object,
                sequence.Count,
                out var produced))
        {
            return IntrinsicResult.Invalid("Could not allocate a sequence result.");
        }

        for (var index = 0; index < sequence.Count; index++)
        {
            if (!heap.TryWriteArray(produced, index, sequence[index]))
                return IntrinsicResult.Invalid("Could not fill a sequence result.");
        }

        return IntrinsicResult.Completed(produced);
    }
}

/// <summary>
/// Answers the handful of methods a number has.
/// </summary>
/// <remarks>
/// Rendering a number is the last step of building a name — for a mutex, a file, a registry key —
/// so a loader reaches it on the path to whatever it does next. The rendering is always the
/// invariant one: a machine that read the host's locale would give different answers on different
/// analysts' machines for the same input, which is exactly what a static reading must not do.
/// </remarks>
public sealed class NumberIntrinsic : IStaticIntrinsic
{
    private static readonly HashSet<string> Numbers = new(StringComparer.Ordinal)
    {
        "System.Byte", "System.SByte", "System.Int16", "System.UInt16", "System.Int32",
        "System.UInt32", "System.Int64", "System.UInt64", "System.Boolean", "System.Char"
    };

    public bool Matches(IMethod method) =>
        Numbers.Contains(method.DeclaringType.FullName) &&
        method.Name.String is "ToString" or "Equals" or "GetHashCode" or "CompareTo";

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (arguments.Count == 0 || Read(heap, arguments[0]) is not { } self)
            return IntrinsicResult.Invalid($"{method.FullName} was called on an unreadable value.");

        var declared = method.DeclaringType.FullName;
        switch (method.Name.String)
        {
            case "ToString" when arguments.Count == 1:
                var rendered = declared switch
                {
                    "System.Boolean" => self != 0 ? "True" : "False",
                    "System.Char" => ((char)self).ToString(),
                    "System.UInt32" or "System.UInt64" =>
                        ((ulong)self).ToString(CultureInfo.InvariantCulture),
                    _ => self.ToString(CultureInfo.InvariantCulture)
                };
                return heap.TryAllocateString(rendered, out var text)
                    ? IntrinsicResult.Completed(text)
                    : IntrinsicResult.Invalid("Could not allocate rendered text.");
            case "GetHashCode" when arguments.Count == 1:
                return IntrinsicResult.Completed(
                    StaticValue.FromInt32(unchecked((int)self ^ (int)(self >> 32))));
            case "Equals" or "CompareTo" when
                arguments.Count == 2 && Read(heap, arguments[1]) is { } other:
                return IntrinsicResult.Completed(StaticValue.FromInt32(
                    method.Name == "Equals" ? self == other ? 1 : 0 : self.CompareTo(other)));
            default:
                return IntrinsicResult.Invalid($"Unsupported number operation {method.Name}.");
        }
    }

    /// <summary>Reads a number whether it arrived bare, boxed, or behind a reference.</summary>
    private static long? Read(StaticHeap heap, StaticValue value)
    {
        if (value.Kind is StaticValueKind.Int32 or StaticValueKind.Int64 && value.IsKnown)
            return value.Kind == StaticValueKind.Int32 ? value.AsInt32() : value.AsInt64();
        if (heap.TryReadManaged(value, out var referenced) && referenced.IsInteger)
            return Read(heap, referenced);
        return heap.TryUnbox(value, out var unboxed) && unboxed.IsInteger
            ? Read(heap, unboxed)
            : null;
    }
}

/// <summary>
/// Converts between the shapes a payload is carried in.
/// </summary>
/// <remarks>
/// Base64 is how bytes travel through anything that expects text — a string literal, a resource
/// entry, a configuration value — so a loader that keeps a stage as text decodes it here on the way
/// to running it.
/// </remarks>
public sealed class ConversionIntrinsic : IStaticIntrinsic
{
    public bool Matches(IMethod method) =>
        method.DeclaringType.FullName == "System.Convert" &&
        method.Name.String is "FromBase64String" or "ToBase64String";

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (method.Name == "FromBase64String" && arguments.Count == 1 &&
            heap.TryGetString(arguments[0], out var encoded))
        {
            if (!Convert.TryFromBase64String(encoded, new byte[encoded.Length], out var written))
                return IntrinsicResult.Invalid("Convert.FromBase64String was given invalid text.");
            var decoded = new byte[written];
            Convert.TryFromBase64String(encoded, decoded, out _);
            return heap.TryAllocateByteArray(decoded, out var bytes)
                ? IntrinsicResult.Completed(bytes)
                : IntrinsicResult.Invalid("Could not allocate decoded bytes.");
        }

        if (method.Name == "ToBase64String" && arguments.Count >= 1 &&
            heap.GetBytesSnapshot(arguments[0]) is { } raw)
        {
            return heap.TryAllocateString(Convert.ToBase64String(raw), out var text)
                ? IntrinsicResult.Completed(text)
                : IntrinsicResult.Invalid("Could not allocate encoded text.");
        }

        return IntrinsicResult.Invalid($"Unsupported conversion {method.Name}.");
    }
}

public sealed class MonitorIntrinsic : IStaticIntrinsic
{
    public bool Matches(IMethod method) =>
        method.DeclaringType.FullName == "System.Threading.Monitor" &&
        method.Name.String is "Enter" or "Exit" or "TryEnter";

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        var name = method.Name.String;
        if (name == "Exit" && arguments.Count == 1)
            return IntrinsicResult.Completed();
        if (name == "Enter" && arguments.Count == 1)
            return IntrinsicResult.Completed();
        if (name == "Enter" && arguments.Count == 2 &&
            context.State.Heap.TryWriteManaged(arguments[1], StaticValue.FromInt32(1)))
            return IntrinsicResult.Completed();
        if (name == "TryEnter" && arguments.Count is 1 or 2)
        {
            if (arguments.Count == 2 &&
                !context.State.Heap.TryWriteManaged(arguments[1], StaticValue.FromInt32(1)))
                return IntrinsicResult.Invalid("Monitor.TryEnter lockTaken is not writable.");
            return IntrinsicResult.Completed(StaticValue.FromInt32(1));
        }
        return IntrinsicResult.Invalid($"Unsupported Monitor operation {name}.");
    }
}

/// <summary>
/// Follows code that writes code, by assembling what it emits into a body the machine can run.
/// </summary>
/// <remarks>
/// An obfuscator runtime reaches for <c>Reflection.Emit</c> when it needs a method that did not
/// exist at build time — most often a thunk that adapts one signature to another so a call can be
/// routed through a delegate. Refusing to follow it would stop the machine at the exact point the
/// program starts being interesting.
///
/// Nothing here interprets what the emitted code is for. The instructions are collected as they
/// are handed over, assembled into an ordinary method body once the program asks for a delegate
/// over them, and then run by the same interpreter that runs every other body. That means the
/// model does not depend on the emitted code having any particular shape: a thunk works because a
/// thunk is valid IL, and so would anything else the program chose to emit instead.
/// </remarks>
/// <summary>
/// Answers code that asks whether it is being watched.
/// </summary>
/// <remarks>
/// A protected assembly asks this the way it asks the time: as a fact about the world it is running
/// in. The interpretation is not that world — nothing here is running, and no debugger is attached
/// to the process that is not running — so the answer is no, for the same reason the clock always
/// reads the same instant. Refusing the question instead is not neutrality: it stops the frame that
/// asked, and Reactor asks inside the type initializer that builds the virtual engine, so declining
/// to answer costs the program, its string table, and the payload behind them.
///
/// The question is recorded even so, because a loader that asks is doing something a report should
/// say out loud, and because what may be removed later depends on knowing where it was asked.
/// </remarks>
public sealed class DebuggerIntrinsic : IStaticIntrinsic
{
    public bool Matches(IMethod method) =>
        method.DeclaringType?.FullName == "System.Diagnostics.Debugger";

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        var name = method.Name.String;
        context.State.Observe(
            LoaderObservationKind.DebuggerProbe,
            $"System.Diagnostics.Debugger::{name}",
            verdict: false);
        return name switch
        {
            // Nothing is attached, nothing is listening, and launching one does not succeed.
            "get_IsAttached" or "get_IsLogging" or "Launch" =>
                IntrinsicResult.Completed(StaticValue.FromInt32(0)),
            // Breaking into a debugger that is not there, and telling one that is not listening,
            // both leave the program exactly as they found it.
            "Break" or "Log" or "NotifyOfCrossThreadDependency" =>
                IntrinsicResult.Completed(),
            _ => IntrinsicResult.Invalid($"Unsupported debugger operation {name}.")
        };
    }
}

/// <summary>
/// Lets code wait, which in an interpretation takes no time and changes nothing.
/// </summary>
/// <remarks>
/// Loaders sleep to space out what they do, and a crypter stage often sleeps before unpacking. The
/// interpretation has no clock to advance and no other thread to yield to, so a sleep is the one
/// call that can be modeled by doing nothing without that being an approximation: waiting alters
/// no value the machine can see. Only the waiting is modeled. Anything that starts or touches
/// another thread is still refused, because the machine has nowhere to run it.
/// </remarks>
public sealed class ThreadIntrinsic : IStaticIntrinsic
{
    public bool Matches(IMethod method) =>
        method.DeclaringType?.FullName == "System.Threading.Thread" &&
        method.Name.String is "Sleep" or "SpinWait" or "Yield";

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments) =>
        method.Name.String == "Yield"
            ? IntrinsicResult.Completed(StaticValue.FromInt32(0))
            : IntrinsicResult.Completed();
}

/// <summary>
/// Answers code that looks back up the call stack at whoever called it.
/// </summary>
/// <remarks>
/// Protected code reads its own stack to make a decrypter refuse to work anywhere but the one call
/// site it was generated for, folding the caller's identity into the key. A machine that already
/// knows which methods are running can answer that honestly, and answering it is what lets the
/// decrypter produce the same string it would have produced at run time.
/// </remarks>
public sealed class StackFrameIntrinsic : IStaticIntrinsic
{
    public bool Matches(IMethod method) =>
        method.DeclaringType?.FullName is
            "System.Diagnostics.StackFrame" or "System.Diagnostics.StackTrace";

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(arguments);
        var heap = context.State.Heap;
        var name = method.Name.String;
        if (context.Frames is not { } frames || arguments.Count == 0)
            return IntrinsicResult.Invalid($"Stack operation {name} has nothing to look at.");
        switch (name)
        {
            // The frame the program means is counted from the method that asked, which is the
            // innermost frame the machine is running: skipping none of them means that method.
            case ".ctor":
                var skipped = arguments.Count > 1 && arguments[1].Kind == StaticValueKind.Int32
                    ? arguments[1].AsInt32()
                    : 0;
                heap.TrySetModelValue(arguments[0], "Skipped", skipped);
                return IntrinsicResult.Completed();
            case "GetFrame" when arguments.Count == 2 && arguments[1].Kind == StaticValueKind.Int32:
                if (!heap.TryAllocateObject("System.Diagnostics.StackFrame", out var frame))
                    return IntrinsicResult.Invalid("Could not allocate a stack frame.");
                heap.TrySetModelValue(frame, "Skipped", arguments[1].AsInt32());
                return IntrinsicResult.Completed(frame);
            case "get_FrameCount":
                return IntrinsicResult.Completed(StaticValue.FromInt32(frames.Count));
            case "GetMethod":
                if (!heap.TryGetModelValue(arguments[0], "Skipped", out int away))
                    return IntrinsicResult.Invalid("The stack frame does not say how far back.");
                var at = frames.Count - 1 - away;
                if (at < 0)
                    return IntrinsicResult.Completed(StaticValue.Null);
                var running = frames[at];
                var described = Describing(
                    heap,
                    running.IsConstructor
                        ? "System.Reflection.ConstructorInfo"
                        : "System.Reflection.MethodInfo",
                    running);
                if (described.Status == StaticExecutionStatus.Completed)
                    heap.TrySetModelValue(described.Value, LoaderFrameworkIntrinsic.HomeModuleMark, true);
                return described;
            default:
                return IntrinsicResult.Invalid($"Stack operation {name} is denied.");
        }
    }

    private static IntrinsicResult Describing(StaticHeap heap, string modelType, object metadata) =>
        heap.TryAllocateObject(modelType, out var model) &&
        heap.TrySetModelValue(model, "Metadata", metadata)
            ? IntrinsicResult.Completed(model)
            : IntrinsicResult.Invalid($"Could not allocate a {modelType}.");
}

public sealed class ReflectionEmitIntrinsic : IStaticIntrinsic
{
    /// <summary>
    /// Stands in for a parameter type the machine could not name, keeping the position.
    /// </summary>
    private static readonly TypeSig Placeholder = new ModuleDefUser("<unnamed>").CorLibTypes.Object;

    private const string Emitted = "EmittedInstructions";
    private const string Signature = "EmittedSignature";
    private const string Owner = "EmittingMethod";

    public bool Matches(IMethod method) =>
        method.DeclaringType?.FullName is
            "System.Reflection.Emit.DynamicMethod" or "System.Reflection.Emit.ILGenerator";

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(arguments);
        var heap = context.State.Heap;
        var name = method.Name.String;
        if (arguments.Count == 0)
            return IntrinsicResult.Invalid($"Emit operation {name} has no receiver.");
        switch (name)
        {
            case ".ctor":
                heap.TrySetModelValue(arguments[0], Emitted, new List<(string, object?)>());
                heap.TrySetModelValue(arguments[0], Signature, Describe(heap, arguments));
                return IntrinsicResult.Completed();
            case "GetILGenerator":
                if (!heap.TryAllocateObject("System.Reflection.Emit.ILGenerator", out var generator))
                    return IntrinsicResult.Invalid("Could not allocate an il generator.");
                heap.TrySetModelValue(generator, Owner, arguments[0]);
                return IntrinsicResult.Completed(generator);
            case "Emit":
                return Record(heap, arguments);
            case "CreateDelegate":
                return Bind(context, arguments);
            case "DefineParameter":
                return IntrinsicResult.Completed(StaticValue.Null);
            default:
                return IntrinsicResult.Invalid($"Emit operation {name} is denied.");
        }
    }

    /// <summary>
    /// Notes the return and parameter types a dynamic method was declared with.
    /// </summary>
    private static (TypeSig? Returns, TypeSig[] Takes) Describe(
        StaticHeap heap,
        IReadOnlyList<StaticValue> arguments)
    {
        var returns = arguments.Count > 2 ? Signatures(heap, arguments[2]) : null;
        var takes = new List<TypeSig>();
        if (arguments.Count > 3 && heap.TryGetLength(arguments[3], out var count))
        {
            for (var index = 0; index < count; index++)
            {
                // Every declared parameter gets a slot even when its type cannot be named here.
                // The body loads arguments by position, so dropping one would silently shift every
                // argument after it and hand the callee the wrong values.
                takes.Add(
                    heap.TryReadArray(arguments[3], index, out var element) &&
                    Signatures(heap, element) is { } parameter
                        ? parameter
                        : Placeholder);
            }
        }

        return (returns, [.. takes]);
    }

    /// <summary>
    /// The signature a modeled <c>Type</c> stands for, where it names one this module can see.
    /// </summary>
    /// <summary>
    /// Names the member a reflective lookup asked for, so invoking it later reaches the same code
    /// a direct call would.
    /// </summary>
    /// <remarks>
    /// Looking a method up by name and calling it is how obfuscated code says what a plain call
    /// would say, and the two have to arrive at the same place. Where the type is defined here the
    /// definition is the answer; where it belongs to the framework there is nothing to resolve, so
    /// a reference is built from what the lookup itself supplied — the type, the name, and the
    /// parameter types — which is exactly what the machine's own dispatch matches on.
    /// </remarks>
    internal static IMemberRef? Bind(
        IntrinsicContext context,
        string lookup,
        string memberName,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (context.State.ModuleMetadata is not { } module ||
            Signatures(heap, arguments[0]) is not { } declaring)
        {
            return null;
        }

        if (declaring.ToTypeDefOrRef().ResolveTypeDef() is { } defined)
        {
            return lookup == "GetField"
                ? defined.FindField(memberName)
                : defined.FindMethod(memberName);
        }

        if (lookup == "GetField")
            return null;
        var takes = new List<TypeSig>();
        if (arguments.Count >= 3 && heap.TryGetLength(arguments[2], out var count))
        {
            for (var index = 0; index < count; index++)
            {
                if (!heap.TryReadArray(arguments[2], index, out var parameter) ||
                    Signatures(heap, parameter) is not { } named)
                    return null;
                takes.Add(named);
            }
        }

        return new MemberRefUser(
            module,
            memberName,
            MethodSig.CreateStatic(module.CorLibTypes.Object, [.. takes]),
            declaring.ToTypeDefOrRef());
    }

    internal static TypeSig? Signatures(StaticHeap heap, StaticValue type) =>
        heap.TryGetModelValue<object>(type, "Metadata", out var metadata)
            ? metadata switch
            {
                TypeSig signature => signature,
                ITypeDefOrRef named => named.ToTypeSig(),
                _ => null
            }
            : null;

    /// <summary>
    /// Appends one emitted instruction to the body being built.
    /// </summary>
    private static IntrinsicResult Record(StaticHeap heap, IReadOnlyList<StaticValue> arguments)
    {
        if (!heap.TryGetModelValue<StaticValue>(arguments[0], Owner, out var into) ||
            !heap.TryGetModelValue<List<(string, object?)>>(into, Emitted, out var body) ||
            body is null)
        {
            return IntrinsicResult.Invalid("Emit was called on a generator with no method.");
        }

        if (arguments.Count < 2 ||
            !heap.TryGetModelValue(arguments[1], "OpCode", out string? opcode) ||
            opcode is null)
        {
            return IntrinsicResult.Invalid("Emit was given an opcode the machine does not know.");
        }

        object? operand = null;
        if (arguments.Count > 2)
        {
            operand =
                arguments[2].Kind == StaticValueKind.Int32 ? arguments[2].AsInt32() :
                heap.TryGetModelValue<object>(arguments[2], "Metadata", out var referenced)
                    ? referenced
                    : null;
            if (operand is null)
                return IntrinsicResult.Invalid($"Emit {opcode} was given an unmodeled operand.");
        }

        body.Add((opcode, operand));
        return IntrinsicResult.Completed();
    }

    /// <summary>
    /// Assembles the emitted instructions into a body and hands back a delegate over it.
    /// </summary>
    private static IntrinsicResult Bind(
        IntrinsicContext context,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (!heap.TryGetModelValue<List<(string, object?)>>(arguments[0], Emitted, out var body) ||
            body is null)
            return IntrinsicResult.Invalid("A delegate was asked for over a method with no body.");
        heap.TryGetModelValue<(TypeSig? Returns, TypeSig[] Takes)>(
            arguments[0], Signature, out var signature);
        if (!TryAssemble(body, signature, out var assembled) || assembled is null)
            return IntrinsicResult.Invalid("The emitted instructions do not form a runnable body.");

        var shape =
            arguments.Count > 1 &&
            heap.TryGetModelValue(arguments[1], "TypeName", out string? named) && named is not null
                ? named
                : "System.Delegate";
        if (!heap.TryAllocateObject(shape, out var bound))
            return IntrinsicResult.Invalid("Could not allocate an emitted delegate.");
        heap.TrySetModelValue(bound, StaticMachine.DelegateTargetKey, StaticValue.Null);
        heap.TrySetModelValue(bound, StaticMachine.DelegateMethodKey, (IMethod)assembled);
        return IntrinsicResult.Completed(bound);
    }

    /// <summary>
    /// Builds a real method out of emitted instructions, in a module of its own.
    /// </summary>
    /// <remarks>
    /// The assembled method deliberately does not join the module under analysis. That module is
    /// evidence and the machine never writes to it, so the body lives in a scratch module and the
    /// interpreter is told to treat calls out of it as calls within the subject.
    /// </remarks>
    private static bool TryAssemble(
        List<(string OpCode, object? Operand)> emitted,
        (TypeSig? Returns, TypeSig[] Takes) signature,
        out MethodDef? assembled)
    {
        assembled = null;
        var scratch = new ModuleDefUser("<emitted>");
        var corlib = scratch.CorLibTypes;
        var host = new TypeDefUser("<emitted>", "Method", corlib.Object.TypeDefOrRef);
        scratch.Types.Add(host);
        var method = new MethodDefUser(
            "Invoke",
            MethodSig.CreateStatic(signature.Returns ?? corlib.Void, signature.Takes ?? []),
            MethodImplAttributes.IL,
            MethodAttributes.Public | MethodAttributes.Static);
        host.Methods.Add(method);
        method.Body = new CilBody();
        foreach (var (name, operand) in emitted)
        {
            if (!Opcodes.TryGetValue(name, out var opcode))
                return false;
            var instruction = operand switch
            {
                null => new Instruction(opcode),
                int immediate => new Instruction(opcode, immediate),
                IMethod called => new Instruction(opcode, called),
                IField accessed => new Instruction(opcode, accessed),
                ITypeDefOrRef named => new Instruction(opcode, named),
                TypeSig described => new Instruction(opcode, described.ToTypeDefOrRef()),
                _ => null
            };
            if (instruction is null)
                return false;
            method.Body.Instructions.Add(instruction);
        }

        method.Body.UpdateInstructionOffsets();
        method.Parameters.UpdateParameterTypes();
        assembled = method;
        return true;
    }

    /// <summary>
    /// Every opcode by the name the framework's <c>OpCodes</c> class gives it.
    /// </summary>
    /// <remarks>
    /// Read off the metadata rather than written out, so the table cannot fall behind the set of
    /// opcodes that exist and cannot disagree with the names a program reads them by.
    /// </remarks>
    internal static readonly IReadOnlyDictionary<string, OpCode> Opcodes =
        typeof(OpCodes)
            .GetFields(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)
            .Where(field => field.FieldType == typeof(OpCode))
            .ToDictionary(
                field => field.Name,
                field => (OpCode)field.GetValue(null)!,
                StringComparer.Ordinal);
}

public sealed class BitConverterIntrinsic : IStaticIntrinsic
{
    public bool Matches(IMethod method) =>
        method.DeclaringType.FullName == "System.BitConverter" &&
        method.Name.String is "GetBytes" or "ToInt16" or "ToUInt16" or
            "ToInt32" or "ToUInt32" or "ToInt64" or "ToUInt64" or
            "ToSingle" or "ToDouble";

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        if (arguments.Any(value => !value.IsKnown))
            return IntrinsicResult.Unknown($"{method.FullName} received an unknown value.");

        if (method.Name == "GetBytes" && arguments.Count == 1)
        {
            var type = method.MethodSig?.Params[0].ElementType;
            byte[] bytes = type switch
            {
                ElementType.Boolean => [arguments[0].AsInt64() == 0 ? (byte)0 : (byte)1],
                ElementType.Char or ElementType.I2 or ElementType.U2 =>
                    LittleEndian(unchecked((ushort)arguments[0].AsInt64())),
                ElementType.I4 or ElementType.U4 =>
                    LittleEndian(unchecked((uint)arguments[0].AsInt64())),
                ElementType.I8 or ElementType.U8 =>
                    LittleEndian(unchecked((ulong)arguments[0].AsInt64())),
                ElementType.R4 =>
                    LittleEndian(unchecked((uint)BitConverter.SingleToInt32Bits(
                        (float)arguments[0].AsFloat64()))),
                ElementType.R8 =>
                    LittleEndian(unchecked((ulong)BitConverter.DoubleToInt64Bits(
                        arguments[0].AsFloat64()))),
                _ => []
            };
            if (bytes.Length == 0)
                return IntrinsicResult.Invalid($"Unsupported BitConverter overload {method.FullName}.");
            return context.State.Heap.TryAllocateByteArray(bytes, out var reference)
                ? IntrinsicResult.Completed(reference)
                : new IntrinsicResult(
                    StaticExecutionStatus.AllocationLimitExceeded,
                    StaticValue.Unknown,
                    "BitConverter result exceeded the allocation budget.");
        }

        if (arguments.Count != 2 ||
            !arguments[1].IsInteger ||
            !context.State.Heap.TryGetLength(arguments[0], out _) ||
            !context.State.Heap.TryGetArrayElementType(
                arguments[0],
                out var elementType) ||
            elementType != "System.Byte")
            return IntrinsicResult.Invalid($"Invalid arguments for {method.FullName}.");
        var offset = arguments[1].AsInt32();
        var name = method.Name.String;
        var width = name is "ToInt16" or "ToUInt16" ? 2 :
            name is "ToInt32" or "ToUInt32" or "ToSingle" ? 4 : 8;
        var bytesToRead = new byte[width];
        if (!context.State.Heap.TryReadBytes(arguments[0], offset, bytesToRead))
        {
            context.State.Heap.TryGetLength(arguments[0], out var available);
            return IntrinsicResult.Invalid(
                $"{method.FullName} read {width} bytes at {offset} of {available}.");
        }


        return name switch
        {
            "ToInt16" or "ToUInt16" =>
                IntrinsicResult.Completed(StaticValue.FromInt32(
                    BinaryPrimitives.ReadUInt16LittleEndian(bytesToRead))),
            "ToInt32" or "ToUInt32" =>
                IntrinsicResult.Completed(StaticValue.FromInt32(
                    BinaryPrimitives.ReadInt32LittleEndian(bytesToRead))),
            "ToInt64" or "ToUInt64" =>
                IntrinsicResult.Completed(StaticValue.FromInt64(
                    BinaryPrimitives.ReadInt64LittleEndian(bytesToRead))),
            "ToSingle" =>
                IntrinsicResult.Completed(StaticValue.FromFloat32(
                    BitConverter.Int32BitsToSingle(
                        BinaryPrimitives.ReadInt32LittleEndian(bytesToRead)))),
            "ToDouble" =>
                IntrinsicResult.Completed(StaticValue.FromFloat64(
                    BitConverter.Int64BitsToDouble(
                        BinaryPrimitives.ReadInt64LittleEndian(bytesToRead)))),
            _ => IntrinsicResult.Invalid($"Unsupported BitConverter method {method.FullName}.")
        };
    }

    private static byte[] LittleEndian(ushort value)
    {
        var result = new byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(result, value);
        return result;
    }

    private static byte[] LittleEndian(uint value)
    {
        var result = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(result, value);
        return result;
    }

    private static byte[] LittleEndian(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(result, value);
        return result;
    }
}

public sealed class ArrayIntrinsic : IStaticIntrinsic
{
    /// <summary>
    /// The types the machine keeps as bare values rather than as objects on the heap.
    /// </summary>
    private static readonly HashSet<string> Primitives = new(StringComparer.Ordinal)
    {
        "System.Boolean", "System.Char", "System.SByte", "System.Byte", "System.Int16",
        "System.UInt16", "System.Int32", "System.UInt32", "System.Int64", "System.UInt64",
        "System.IntPtr", "System.UIntPtr", "System.Single", "System.Double"
    };

    public bool Matches(IMethod method) =>
        (method.DeclaringType.FullName == "System.Array" &&
            method.Name.String is "Copy" or "Clear" or "Reverse" or "CreateInstance" or "Clone"
                or "SetValue" or "GetValue" or "get_Length" or "get_LongLength" or "get_Rank") ||
        (method.DeclaringType.FullName == "System.Buffer" &&
            method.Name.String is "BlockCopy" or "ByteLength");

    private static bool AreBytes(StaticHeap heap, StaticValue array) =>
        heap.TryGetRuntimeTypeName(array, out var element) && element == "System.Byte[]";

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        if (arguments.Any(value => !value.IsKnown))
            return IntrinsicResult.Unknown($"{method.FullName} received an unknown value.");

        var heap = context.State.Heap;
        if (method.Name.String is "get_Length" or "get_LongLength" or "get_Rank" &&
            arguments.Count == 1)
        {
            if (method.Name == "get_Rank")
                return IntrinsicResult.Completed(StaticValue.FromInt32(1));
            if (!heap.TryGetLength(arguments[0], out var length))
                return IntrinsicResult.Invalid($"{method.Name} was asked of a non-array.");
            return IntrinsicResult.Completed(method.Name == "get_Length"
                ? StaticValue.FromInt32(length)
                : StaticValue.FromInt64(length));
        }

        // Element access through Array itself goes through object, so a value on its way into an
        // array of numbers arrives boxed and one on its way out has to leave boxed. Storing what
        // the array is declared to hold keeps direct reads of the same element seeing a number.
        if (method.Name.String is "SetValue" or "GetValue" && arguments.Count >= 2 &&
            arguments[^1].Kind == StaticValueKind.Int32 &&
            heap.TryGetRuntimeTypeName(arguments[0], out var arrayType) &&
            arrayType.EndsWith("[]", StringComparison.Ordinal))
        {
            var element = arrayType[..^2];
            var boxes = Primitives.Contains(element);
            var at = arguments[^1].AsInt32();
            if (method.Name.String == "GetValue")
            {
                if (!heap.TryReadArray(arguments[0], at, out var read))
                    return IntrinsicResult.Invalid("Array.GetValue index is out of range.");
                return !boxes || read.Kind == StaticValueKind.HeapReference
                    ? IntrinsicResult.Completed(read)
                    : heap.TryAllocateBox(element, read, out var boxed)
                        ? IntrinsicResult.Completed(boxed)
                        : IntrinsicResult.Invalid("Could not box an array element.");
            }

            var value = arguments[1];
            if (boxes && value.Kind == StaticValueKind.HeapReference &&
                heap.TryUnbox(value, out var unboxed))
                value = unboxed;
            return heap.TryWriteArray(arguments[0], at, value)
                ? IntrinsicResult.Completed()
                : IntrinsicResult.Invalid("Array.SetValue index is out of range.");
        }

        if (method.Name == "Clone" && arguments.Count == 1)
        {
            return heap.TryCloneArray(arguments[0], out var copied)
                ? IntrinsicResult.Completed(copied)
                : IntrinsicResult.Invalid("Array.Clone was asked of a non-array.");
        }

        if (method.Name == "CreateInstance" && arguments.Count == 2 &&
            arguments[1].Kind == StaticValueKind.Int32)
        {
            // The element type is only needed to say what the array holds; the machine stores
            // elements by value either way, so an unrecognized element type is still a real array.
            heap.TryGetModelValue<object>(arguments[0], "Metadata", out var element);
            return heap.TryAllocateArray(
                    element switch
                    {
                        TypeSig described => described,
                        ITypeDefOrRef named => named.ToTypeSig(),
                        _ => null
                    },
                    arguments[1].AsInt32(),
                    out var created)
                ? IntrinsicResult.Completed(created)
                : IntrinsicResult.Invalid("Array.CreateInstance could not allocate the array.");
        }

        if (method.Name == "Clear" && arguments.Count == 3)
        {
            var start = arguments[1].AsInt32();
            var count = arguments[2].AsInt32();
            return heap.TryClearArray(arguments[0], start, count)
                ? IntrinsicResult.Completed()
                : IntrinsicResult.Invalid("Array.Clear range is invalid.");
        }

        if (method.Name == "Reverse" && arguments.Count is 1 or 3)
        {
            var start = arguments.Count == 1 ? 0 : arguments[1].AsInt32();
            if (!heap.TryGetLength(arguments[0], out var total))
                return IntrinsicResult.Invalid("Array.Reverse target is not an array.");
            var count = arguments.Count == 1 ? total : arguments[2].AsInt32();
            if (start < 0 || count < 0 || start > total - count)
                return IntrinsicResult.Invalid("Array.Reverse range is invalid.");
            for (var i = 0; i < count / 2; i++)
            {
                if (!heap.TryReadArray(arguments[0], start + i, out var left) ||
                    !heap.TryReadArray(arguments[0], start + count - i - 1, out var right) ||
                    !heap.TryWriteArray(arguments[0], start + i, right) ||
                    !heap.TryWriteArray(arguments[0], start + count - i - 1, left))
                    return IntrinsicResult.Invalid("Array.Reverse range is invalid.");
            }
            return IntrinsicResult.Completed();
        }

        // BlockCopy counts bytes where Copy counts elements, so the two agree only when the
        // elements are bytes. Anything wider would need the byte offsets translated, and guessing
        // at that would quietly move the wrong bytes.
        if (method.Name.String is "BlockCopy" or "ByteLength")
        {
            if (!AreBytes(heap, arguments[0]) ||
                (method.Name.String == "BlockCopy" && !AreBytes(heap, arguments[2])))
                return IntrinsicResult.Invalid($"{method.FullName} was given non-byte arrays.");
            if (method.Name.String == "ByteLength")
            {
                return heap.TryGetLength(arguments[0], out var measured)
                    ? IntrinsicResult.Completed(StaticValue.FromInt32(measured))
                    : IntrinsicResult.Invalid("Buffer.ByteLength was asked of a non-array.");
            }
        }

        if (method.Name.String is "Copy" or "BlockCopy" && arguments.Count is 3 or 5)
        {
            var source = arguments[0];
            var sourceIndex = arguments.Count == 3 ? 0 : arguments[1].AsInt32();
            var destination = arguments.Count == 3 ? arguments[1] : arguments[2];
            var destinationIndex = arguments.Count == 3 ? 0 : arguments[3].AsInt32();
            var count = arguments[^1].AsInt32();
            var temporary = new StaticValue[count < 0 ? 0 : count];
            for (var i = 0; i < count; i++)
                if (!heap.TryReadArray(source, sourceIndex + i, out temporary[i]))
                    return IntrinsicResult.Invalid("Array.Copy source range is invalid.");
            for (var i = 0; i < count; i++)
                if (!heap.TryWriteArray(destination, destinationIndex + i, temporary[i]))
                    return IntrinsicResult.Invalid("Array.Copy destination range is invalid.");
            return count < 0
                ? IntrinsicResult.Invalid("Array.Copy count is negative.")
                : IntrinsicResult.Completed();
        }

        return IntrinsicResult.Invalid($"Unsupported Array overload {method.FullName}.");
    }
}

public sealed class LoaderFrameworkIntrinsic : IStaticIntrinsic
{
    /// <summary>
    /// Model value marking an assembly or module object as the one being interpreted.
    /// </summary>
    /// <remarks>
    /// Reflection reaches the running module by a chain — take a type's handle, ask it for its
    /// assembly, ask that for its modules — and each step allocates a fresh model that would
    /// otherwise be indistinguishable from a model of somebody else's assembly. A caller that needs
    /// to know a handle addresses this module's metadata, rather than assuming it, has nothing to go
    /// on unless the chain carries the fact along, and the only thing that establishes it is the
    /// seed: a <c>TypeDef</c> is defined here, a <c>TypeRef</c> is not.
    /// </remarks>
    public const string HomeModuleMark = "HomeModule";

    private static readonly HashSet<string> AllowedTypes = new(StringComparer.Ordinal)
    {
        "System.Object",
        "System.String",
        "System.Version",
        "System.Runtime.CompilerServices.RuntimeHelpers",
        "System.IntPtr",
        "System.UIntPtr",
        "System.ModuleHandle",
        "System.Type",
        "System.Nullable",
        "System.Enum",
        "System.Exception",
        "System.SystemException",
        "System.ApplicationException",
        "System.InvalidOperationException",
        "System.Delegate",
        "System.MulticastDelegate",
        "System.Reflection.MethodBase",
        "System.Reflection.MethodInfo",
        "System.Reflection.ConstructorInfo",
        "System.Reflection.MemberInfo",
        "System.Reflection.ParameterInfo",
        "System.Reflection.FieldInfo",
        "System.Resources.ResourceManager",
        "System.Text.Encoding",
        "System.Text.UTF8Encoding",
        "System.Text.UnicodeEncoding",
        "System.IO.Stream",
        "System.IO.MemoryStream",
        "System.IO.BinaryReader",
        "System.IO.Compression.DeflateStream",
        "System.IO.Compression.GZipStream",
        "System.Security.Cryptography.SHA1",
        "System.Security.Cryptography.SHA256",
        "System.Security.Cryptography.MD5",
        "System.Security.Cryptography.Aes",
        "System.Security.Cryptography.Rijndael",
        "System.Security.Cryptography.TripleDES",
        "System.Security.Cryptography.DES",
        "System.Security.Cryptography.RijndaelManaged",
        "System.Security.Cryptography.ICryptoTransform",
        "System.Security.Cryptography.RSACryptoServiceProvider",
        "System.IO.File",
        "System.Security.Cryptography.CryptoStream",
        "System.IO.FileStream",
        "System.Math",
        "System.Security.Cryptography.AsymmetricAlgorithm",
        "System.Security.Cryptography.HashAlgorithm",
        "System.Security.Cryptography.CryptoConfig",
        "System.Reflection.Assembly",
        "System.Reflection.AssemblyName",
        "System.Reflection.Module",
        "System.AppDomain",
        "System.ResolveEventHandler",
        "System.ResolveEventArgs"
        ,"System.Collections.Hashtable"
        ,"System.Collections.SortedList"
        ,"System.Diagnostics.Process"
        ,"System.Diagnostics.ProcessModuleCollection"
        ,"System.Diagnostics.ProcessModule"
        ,"System.Diagnostics.FileVersionInfo"
        ,"System.Collections.ReadOnlyCollectionBase"
        ,"System.Collections.IEnumerator"
        ,"System.IDisposable"
    };

    public bool Matches(IMethod method) =>
        AllowedTypes.Contains(Canonicalize(method.DeclaringType.FullName));

    /// <summary>Folds the concrete cryptography provider classes onto the algorithm they
    /// implement so a single model serves every spelling Reactor emits.</summary>
    private static string Canonicalize(string type) => type switch
    {
        "System.Security.Cryptography.MD5CryptoServiceProvider" =>
            "System.Security.Cryptography.MD5",
        "System.Security.Cryptography.SHA1CryptoServiceProvider" or
        "System.Security.Cryptography.SHA1Managed" =>
            "System.Security.Cryptography.SHA1",
        "System.Security.Cryptography.SHA256CryptoServiceProvider" or
        "System.Security.Cryptography.SHA256Managed" =>
            "System.Security.Cryptography.SHA256",
        "System.Security.Cryptography.AesCryptoServiceProvider" or
        "System.Security.Cryptography.AesManaged" =>
            "System.Security.Cryptography.Aes",
        "System.Security.Cryptography.TripleDESCryptoServiceProvider" =>
            "System.Security.Cryptography.TripleDES",
        "System.Security.Cryptography.DESCryptoServiceProvider" =>
            "System.Security.Cryptography.DES",
        "System.Security.Cryptography.SymmetricAlgorithm" =>
            "System.Security.Cryptography.Rijndael",
        "System.Security.Cryptography.RSA" =>
            "System.Security.Cryptography.RSACryptoServiceProvider",
        _ => type
    };

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        if (arguments.Any(value => !value.IsKnown))
            return IntrinsicResult.Unknown($"{method.FullName} received an unknown value.");

        var type = Canonicalize(method.DeclaringType.FullName);
        var name = method.Name.String;
        if (type == "System.Object" && name == ".ctor")
            return IntrinsicResult.Completed();
        // Every object answers this the same way whatever type the call site spells it through,
        // because GetType cannot be overridden. A program catching by type asks it of an exception
        // rather than of an object, and that is the same question. The static Type.GetType(name) is
        // a different one, and takes no receiver to tell it apart by.
        if (name == "GetType" && method.MethodSig?.HasThis == true && arguments.Count == 1 &&
            context.State.Heap.TryGetRuntimeTypeName(arguments[0], out var runtimeTypeName))
        {
            if (!context.State.Heap.TryAllocateType(runtimeTypeName, out var runtimeType))
                return AllocationFailure("runtime type");
            AttachDefinition(context, runtimeType, runtimeTypeName);
            return IntrinsicResult.Completed(runtimeType);
        }
        // An exception carries a message and nothing else the machine reasons about, so building
        // one succeeds and asking for its message gives back what it was built with. Obfuscator
        // runtimes throw and catch as ordinary control flow, and refusing the constructor would
        // stop interpretation on a path the program takes deliberately.
        if (type is "System.Exception" or "System.SystemException" or
            "System.ApplicationException" or "System.InvalidOperationException")
        {
            var heapState = context.State.Heap;
            if (name == ".ctor" && arguments.Count >= 1)
            {
                if (arguments.Count >= 2 && heapState.TryGetString(arguments[1], out var message))
                    heapState.TrySetModelValue(arguments[0], "Message", message);
                return IntrinsicResult.Completed();
            }
            if (name == "get_Message" && arguments.Count == 1)
            {
                var message = heapState.TryGetModelValue<string>(arguments[0], "Message", out var stored)
                    ? stored ?? string.Empty
                    : string.Empty;
                return heapState.TryAllocateString(message, out var allocated)
                    ? IntrinsicResult.Completed(allocated)
                    : AllocationFailure("exception message");
            }
        }
        // Nullable<T> is answered from the described type's own signature: it either is one, in
        // which case its argument is the answer, or it is not, in which case the runtime says null.
        if (type == "System.Nullable" && name == "GetUnderlyingType" && arguments.Count == 1)
        {
            if (!context.State.Heap.TryGetModelValue<object>(arguments[0], "Metadata", out var asked))
            {
                // A type known only by name is nullable exactly when its name says so, and every
                // other name is a plain type whose answer is the null the runtime would give.
                return context.State.Heap.TryGetModelValue(
                        arguments[0], "TypeName", out string? spelled) &&
                    spelled?.StartsWith("System.Nullable`1", StringComparison.Ordinal) == true
                        ? IntrinsicResult.Invalid("The nullable type being asked about is not modeled.")
                        : IntrinsicResult.Completed(StaticValue.Null);
            }
            var underlying = asked switch
            {
                GenericInstSig { GenericType.TypeName: "Nullable`1" } instance =>
                    instance.GenericArguments.Count == 1 ? instance.GenericArguments[0] : null,
                _ => null
            };
            if (underlying is null)
                return IntrinsicResult.Completed(StaticValue.Null);
            return context.State.Heap.TryAllocateType(underlying.FullName, out var underlyingModel) &&
                context.State.Heap.TrySetModelValue(underlyingModel, "Metadata", underlying)
                ? IntrinsicResult.Completed(underlyingModel)
                : AllocationFailure("underlying type model");
        }
        if (type == "System.Enum" && name == "GetUnderlyingType" && arguments.Count == 1)
            return UnderlyingType(context, arguments[0]);
        // An enum value is its number wearing the enum's name, so the box carries the number and is
        // labelled with the type asked for. Everything downstream reads it as one or the other.
        if (type == "System.Enum" && name == "ToObject" && arguments.Count == 2 &&
            arguments[1].IsInteger)
        {
            var named = context.State.Heap.TryGetModelValue(
                arguments[0], "TypeName", out string? spelled) && spelled is not null
                    ? spelled
                    : "System.Enum";
            return context.State.Heap.TryAllocateBox(named, arguments[1], out var value)
                ? IntrinsicResult.Completed(value)
                : AllocationFailure("enumeration value");
        }
        if (type is "System.Type" or "System.Reflection.MethodBase" or
            "System.Reflection.MethodInfo" or
            "System.Reflection.ConstructorInfo" or
            "System.Reflection.MemberInfo" or
            "System.Reflection.ParameterInfo" or
            "System.Reflection.FieldInfo" or
            "System.Delegate" or "System.MulticastDelegate")
            return InvokeMetadata(context, type, name, arguments);
        if (type == "System.String")
            return InvokeString(context, name, arguments);
        if (type == "System.Version")
            return InvokeVersion(context, name, arguments);
        if (type == "System.Runtime.CompilerServices.RuntimeHelpers")
            return InvokeRuntimeHelpers(context, name, arguments);
        if (type is "System.IntPtr" or "System.UIntPtr")
            return InvokePointer(context, name, arguments);
        if (type == "System.ModuleHandle" &&
            name == "GetRuntimeTypeHandleFromMetadataToken" &&
            arguments.Count == 2)
        {
            return context.State.Heap.TryAllocateMetadataHandle(
                arguments[1].AsInt32(), out var handle)
                ? IntrinsicResult.Completed(handle)
                : AllocationFailure("runtime type handle");
        }
        if (type is "System.Text.Encoding" or "System.Text.UTF8Encoding" or
            "System.Text.UnicodeEncoding")
            return InvokeEncoding(context, type, name, arguments);
        if (type == "System.Math")
            return InvokeMath(name, arguments);
        if (type == "System.Security.Cryptography.CryptoStream")
            return InvokeCryptoStream(context, name, arguments);
        if (type == "System.IO.FileStream")
            return name == ".ctor"
                ? OpenModuleFileStream(context, arguments)
                : InvokeMemoryStream(context, name, arguments);
        if (type is "System.IO.Stream" or "System.IO.MemoryStream")
            return arguments.Count != 0 &&
                context.State.Heap.TryGetRuntimeTypeName(arguments[0], out var streamType) &&
                streamType == "System.Security.Cryptography.CryptoStream"
                ? InvokeCryptoStream(context, name, arguments)
                : InvokeMemoryStream(context, name, arguments);
        if (type == "System.IO.BinaryReader")
            return InvokeBinaryReader(context, name, arguments);
        if (type is "System.IO.Compression.DeflateStream" or
            "System.IO.Compression.GZipStream")
            return InvokeCompression(context, type, name, arguments);
        if (type is "System.Security.Cryptography.SHA1" or
            "System.Security.Cryptography.SHA256" or "System.Security.Cryptography.MD5")
            return InvokeHash(context, type, name, arguments);
        if (type is "System.Security.Cryptography.Aes" or
            "System.Security.Cryptography.Rijndael" or
            "System.Security.Cryptography.RijndaelManaged" or
            "System.Security.Cryptography.TripleDES" or
            "System.Security.Cryptography.DES" or
            "System.Security.Cryptography.ICryptoTransform")
            return InvokeCrypto(context, type, name, arguments);
        if (type is "System.Security.Cryptography.RSACryptoServiceProvider" or
            "System.Security.Cryptography.AsymmetricAlgorithm" or
            "System.Security.Cryptography.CryptoConfig")
        {
            return InvokeAsymmetric(context, type, name, arguments);
        }
        if (type == "System.Security.Cryptography.HashAlgorithm")
            return InvokeHashAlgorithm(context, name, arguments);
        if (type == "System.IO.File")
            return InvokeFile(context, name, arguments);
        if (type == "System.Reflection.Assembly")
            return InvokeAssembly(context, name, arguments);
        if (type == "System.Reflection.AssemblyName")
            return InvokeAssemblyName(context, name, arguments);
        if (type == "System.Reflection.Module")
            return InvokeModule(context, name, arguments);
        if (type == "System.Resources.ResourceManager")
            return InvokeResourceManager(context, name, arguments);
        if (type == "System.AppDomain")
            return InvokeAppDomain(context, name, arguments);
        if (type == "System.ResolveEventArgs" && name == "get_Name" && arguments.Count == 1)
        {
            return context.State.Heap.TryGetModelValue(arguments[0], "Name", out StaticValue asked)
                ? IntrinsicResult.Completed(asked)
                : IntrinsicResult.Invalid("Resolve event carries no name.");
        }
        if (type == "System.ResolveEventHandler" &&
            name == ".ctor" &&
            arguments.Count == 3)
        {
            context.State.Heap.TrySetModelValue(arguments[0], "Target", arguments[1]);
            context.State.Heap.TrySetModelValue(arguments[0], "Method", arguments[2]);
            return IntrinsicResult.Completed();
        }
        if (type is "System.Collections.Hashtable" or "System.Collections.SortedList")
            return InvokeHashtable(context, name, arguments);
        if (type == "System.Diagnostics.Process")
            return InvokeProcess(context, name, arguments);
        if (type is "System.Diagnostics.ProcessModuleCollection" or
            "System.Diagnostics.ProcessModule" or "System.Diagnostics.FileVersionInfo")
        {
            return InvokeProcessModule(context, type, name, arguments);
        }
        if (type is "System.Collections.ReadOnlyCollectionBase" or
            "System.Collections.IEnumerator" or "System.IDisposable")
        {
            return InvokeEnumerator(context, type, name, arguments);
        }
        return IntrinsicResult.Invalid($"Unsupported modeled call {method.FullName}.");
    }

    private static IntrinsicResult InvokeAppDomain(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        if (name == "get_CurrentDomain" && arguments.Count == 0)
        {
            return context.State.TryGetOrAllocateRuntimeSingleton(
                "System.AppDomain",
                out var domain)
                ? IntrinsicResult.Completed(domain)
                : AllocationFailure("current application domain");
        }
        if ((name.StartsWith("add_", StringComparison.Ordinal) ||
             name.StartsWith("remove_", StringComparison.Ordinal)) &&
            arguments.Count == 2)
        {
            var subscribed = name[(name.IndexOf('_') + 1)..];
            if (!context.State.Heap.TrySetModelValue(
                    arguments[0], $"Event:{subscribed}", arguments[1]))
            {
                return IntrinsicResult.Invalid("Application-domain event receiver is not modeled.");
            }
            // Subscribing changes what the program does later without touching anything the
            // interpretation can see afterwards, so it has to be declared rather than inferred.
            context.State.RecordRegistration($"AppDomain.{subscribed}");
            return IntrinsicResult.Completed();
        }
        return IntrinsicResult.Invalid($"Unsupported AppDomain operation {name}.");
    }

    private static IntrinsicResult InvokePointer(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        if (name == "get_Size" && arguments.Count == 0)
            return IntrinsicResult.Completed(StaticValue.FromInt32(context.State.PointerSize));
        if (name is "op_Equality" or "op_Inequality" && arguments.Count == 2)
        {
            var left = NormalizePointerValue(context.State.Heap, arguments[0]);
            var right = NormalizePointerValue(context.State.Heap, arguments[1]);
            var equal = left.Kind == right.Kind && left.Bits == right.Bits;
            return IntrinsicResult.Completed(StaticValue.FromInt32(
                (name == "op_Equality" ? equal : !equal) ? 1 : 0));
        }
        if (name == ".ctor" && arguments.Count == 2)
        {
            if (arguments[0].Kind == StaticValueKind.ManagedReference)
            {
                return context.State.Heap.TryWriteManaged(arguments[0], arguments[1])
                    ? IntrinsicResult.Completed()
                    : IntrinsicResult.Invalid("Managed pointer destination is not writable.");
            }
            return context.State.Heap.TrySetModelValue(arguments[0], "Pointer", arguments[1])
                ? IntrinsicResult.Completed()
                : IntrinsicResult.Invalid("Pointer receiver is not modeled.");
        }
        if (name is "ToInt32" or "ToInt64" &&
            arguments.Count == 1)
        {
            var pointer = arguments[0];
            if (context.State.Heap.TryGetModelValue(
                    pointer,
                    "Pointer",
                    out StaticValue modeled))
            {
                pointer = modeled;
            }
            if (context.State.Heap.TryReadManaged(pointer, out var managed))
                pointer = managed;
            if (pointer.Kind == StaticValueKind.NativePointer &&
                context.State.Heap.TryGetNativeAddress(pointer, out var nativeAddress))
            {
                return IntrinsicResult.Completed(name == "ToInt32"
                    ? StaticValue.FromInt32(unchecked((int)nativeAddress))
                    : StaticValue.FromInt64(nativeAddress));
            }
            return pointer.IsInteger
                ? IntrinsicResult.Completed(name == "ToInt32"
                    ? StaticValue.FromInt32(unchecked((int)pointer.AsInt64()))
                    : StaticValue.FromInt64(pointer.AsInt64()))
                : IntrinsicResult.Unknown("Managed pointer has no synthetic integer address.");
        }
        return IntrinsicResult.Invalid($"Unsupported pointer operation {name}.");
    }

    private static StaticValue NormalizePointerValue(StaticHeap heap, StaticValue value)
    {
        if (heap.TryGetModelValue(value, "Pointer", out StaticValue modeled))
            value = modeled;
        if (heap.TryReadManaged(value, out var managed))
            value = managed;
        return value;
    }

    private static IntrinsicResult InvokeMetadata(
        IntrinsicContext context,
        string type,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        // Reflection models compare by what they denote. The runtime hands out one object per type
        // or member and programs compare them with ==, so two models of the same member have to
        // answer equal even when the machine built them at different moments.
        if (name is "op_Equality" or "op_Inequality" && arguments.Count == 2)
        {
            var equal =
                heap.TryGetModelValue<object>(arguments[0], "Metadata", out var left) &&
                heap.TryGetModelValue<object>(arguments[1], "Metadata", out var right) &&
                left is not null && right is not null
                    ? Denote(left, right)
                    : arguments[0].Equals(arguments[1]);
            return IntrinsicResult.Completed(StaticValue.FromInt32(
                (name == "op_Equality" ? equal : !equal) ? 1 : 0));
        }
        if (type == "System.Type" &&
            name is "get_Module" or "get_Assembly" &&
            arguments.Count == 1)
        {
            var modelType = name == "get_Module"
                ? "System.Reflection.Module"
                : "System.Reflection.Assembly";
            if (!heap.TryAllocateObject(modelType, out var owner))
                return AllocationFailure(modelType);
            // A TypeDef is defined in the module being interpreted, so the assembly and module it
            // reports are that module's own. A TypeRef names something outside it and carries the
            // mark no further.
            if (heap.TryGetModelValue<object>(arguments[0], "Metadata", out var owning) &&
                owning is TypeDef)
            {
                heap.TrySetModelValue(owner, HomeModuleMark, true);
            }
            return IntrinsicResult.Completed(owner);
        }
        if (type == "System.Type" &&
            name == "GetType" &&
            arguments.Count is 1 or 2 &&
            heap.TryGetString(arguments[0], out var typeName))
        {
            if (!heap.TryAllocateType(typeName, out var runtimeType))
                return AllocationFailure("runtime type");
            AttachDefinition(context, runtimeType, typeName);
            return IntrinsicResult.Completed(runtimeType);
        }
        if (type == "System.Type" &&
            name is "GetField" or "GetMethod" &&
            arguments.Count >= 2 &&
            heap.TryGetString(arguments[1], out var memberName))
        {
            var memberType = name == "GetField"
                ? "System.Reflection.FieldInfo"
                : "System.Reflection.MethodInfo";
            if (!heap.TryAllocateObject(memberType, out var member))
                return AllocationFailure("runtime member");
            heap.TrySetModelValue(member, "MemberName", memberName);
            heap.TrySetModelValue(member, "DeclaringType", arguments[0]);
            if (ReflectionEmitIntrinsic.Bind(context, name, memberName, arguments) is { } bound)
                heap.TrySetModelValue(member, "Metadata", bound);
            return IntrinsicResult.Completed(member);
        }
        // Binding a delegate reflectively reaches the same state a delegate constructor would, so
        // it is modeled as what it produces rather than refused for arriving by another route.
        if (type is "System.Delegate" or "System.MulticastDelegate" &&
            name == "CreateDelegate" && arguments.Count is 2 or 3 &&
            heap.TryGetModelValue<object>(arguments[^1], "Metadata", out var boundTo) &&
            boundTo is IMethod boundMethod)
        {
            var delegateType =
                heap.TryGetModelValue(arguments[0], "TypeName", out string? shape) && shape is not null
                    ? shape
                    : "System.Delegate";
            if (!heap.TryAllocateObject(delegateType, out var bound))
                return AllocationFailure("delegate");
            heap.TrySetModelValue(
                bound,
                StaticMachine.DelegateTargetKey,
                arguments.Count == 3 ? arguments[1] : StaticValue.Null);
            heap.TrySetModelValue(bound, StaticMachine.DelegateMethodKey, boundMethod);
            return IntrinsicResult.Completed(bound);
        }
        // A type that is not a constructed generic has no arguments rather than no answer, so the
        // empty array is the honest reply and lets the caller carry on asking about it.
        if (type == "System.Type" && name == "GetGenericArguments" && arguments.Count == 1 &&
            heap.TryGetModelValue<object>(arguments[0], "Metadata", out var parameterized))
        {
            var supplied = parameterized is GenericInstSig constructed
                ? constructed.GenericArguments
                : [];
            if (!heap.TryAllocateArray(null, supplied.Count, out var argumentTypes))
                return AllocationFailure("generic argument array");
            for (var index = 0; index < supplied.Count; index++)
            {
                if (!heap.TryAllocateType(supplied[index].FullName, out var argumentType) ||
                    !heap.TrySetModelValue(argumentType, "Metadata", supplied[index]) ||
                    !heap.TryWriteArray(argumentTypes, index, argumentType))
                {
                    return AllocationFailure("generic argument model");
                }
            }

            return IntrinsicResult.Completed(argumentTypes);
        }
        if (type == "System.Type" && name == "GetFields" && arguments.Count == 2 &&
            arguments[1].Kind == StaticValueKind.Int32 &&
            heap.TryGetModelValue<object>(arguments[0], "Metadata", out var enumerated) &&
            Defined(enumerated!) is { } enumeratedType)
        {
            var selected = enumeratedType.Fields
                .Where(field => Selects(arguments[1].AsInt32(), field))
                .ToArray();
            if (!heap.TryAllocateArray(null, selected.Length, out var fields))
                return AllocationFailure("field array");
            for (var index = 0; index < selected.Length; index++)
            {
                var model = Describing(heap, "System.Reflection.FieldInfo", selected[index]).Value;
                if (!heap.TryWriteArray(fields, index, model))
                    return AllocationFailure("field model");
                heap.TrySetModelValue(model, HomeModuleMark, true);
            }

            return IntrinsicResult.Completed(fields);
        }
        // A runtime that resolved a member by token then asks what shape it is. Every answer is in
        // the metadata the model already carries, so describing the signature is reading the file
        // rather than assuming anything about the machine.
        // Reflective invocation is a call like any other once the target is known, so it is run
        // rather than refused. The argument array is unpacked exactly as the runtime would, and a
        // constructor gets a fresh instance to work on and yields it.
        if (name == "Invoke" && arguments.Count >= 2 && context.Call is { } call &&
            heap.TryGetModelValue<object>(arguments[0], "Metadata", out var invoked) &&
            invoked is IMethod called)
        {
            // The target may be defined here or merely referred to. Where there is a definition it
            // carries the parameter types and the constructor flag; where there is not, the
            // reference's own signature says the same things.
            var invokedMethod = called.ResolveMethodDef();
            var packed = arguments[^1];
            var supplied = new List<StaticValue>();
            if (packed.Kind != StaticValueKind.Null)
            {
                if (!heap.TryGetLength(packed, out var count))
                    return IntrinsicResult.Invalid("The argument array is not modeled.");
                for (var index = 0; index < count; index++)
                {
                    if (!heap.TryReadArray(packed, index, out var element))
                        return IntrinsicResult.Invalid("The argument array could not be read.");
                    supplied.Add(Unwrap(heap, element, Expects(called, invokedMethod, index)));
                }
            }

            if (called.Name.String is ".ctor" or ".cctor")
            {
                if (!heap.TryAllocateObject(called.DeclaringType.FullName, out var fresh))
                    return AllocationFailure("reflectively constructed object");
                var built = call(called, [fresh, .. supplied]);
                return built.Status == StaticExecutionStatus.Completed
                    ? IntrinsicResult.Completed(fresh)
                    : built;
            }

            // MethodBase.Invoke takes the receiver first; a static target ignores it.
            var receiver = arguments.Count >= 3 ? arguments[^2] : StaticValue.Null;
            var unbound = invokedMethod?.IsStatic ?? called.MethodSig?.HasThis != true;
            var returned = call(called, unbound ? supplied : [receiver, .. supplied]);

            // Invoke's own return type is object, so a method that returns a number returns it
            // boxed. The caller goes on to treat it as an object, and handing back a bare number
            // would fail the moment it does.
            var returns = invokedMethod?.ReturnType ?? called.MethodSig?.RetType;
            if (returned.Status != StaticExecutionStatus.Completed ||
                returns?.IsPrimitive != true ||
                returned.Value.Kind == StaticValueKind.HeapReference)
            {
                return returned;
            }

            return heap.TryAllocateBox(returns.FullName, returned.Value, out var boxed)
                ? IntrinsicResult.Completed(boxed)
                : IntrinsicResult.Invalid("Could not allocate a boxed return value.");
        }
        // Reflective field access reaches the same storage the machine already uses for ordinary
        // field access, so a program that sets a field by reflection and reads it directly sees one
        // consistent value rather than two.
        if (name is "SetValue" or "GetValue" && arguments.Count >= 2 &&
            heap.TryGetModelValue<object>(arguments[0], "Metadata", out var accessed) &&
            accessed is FieldDef accessedField)
        {
            var instance = arguments[1];
            if (name == "GetValue")
            {
                return accessedField.IsStatic || instance.Kind == StaticValueKind.Null
                    ? IntrinsicResult.Completed(context.State.ReadStaticField(accessedField))
                    : heap.TryReadField(instance, accessedField, out var read)
                        ? IntrinsicResult.Completed(read)
                        : IntrinsicResult.Invalid("The field could not be read.");
            }

            if (arguments.Count < 3)
                return IntrinsicResult.Invalid("SetValue needs a value to store.");

            // A reflective write is handed its value as an object, but the field holds whatever its
            // own type says it holds. Storing the box would leave arithmetic on that field facing a
            // reference where it expects a number, so the value is unwrapped to match the field.
            var stored = Unwrap(heap, arguments[2], accessedField.FieldType);

            if (accessedField.IsStatic || instance.Kind == StaticValueKind.Null)
            {
                context.State.WriteStaticField(accessedField, stored);
                return IntrinsicResult.Completed();
            }

            return heap.TryWriteField(instance, accessedField, stored)
                ? IntrinsicResult.Completed()
                : IntrinsicResult.Invalid("The field could not be written.");
        }
        if (name is "GetParameters" or "get_ReturnType" or "get_ParameterType" or "get_DeclaringType"
                or "get_Name" or "get_IsStatic" or "get_IsAbstract" or "get_IsVirtual"
                or "get_IsPublic" or "get_IsValueType" or "get_FieldType" or "get_MetadataToken"
                or "get_IsByRef" or "get_IsPointer" or "get_IsArray" or "get_IsEnum"
                or "get_IsInterface" or "get_IsClass" or "get_IsSealed" or "get_IsPrimitive"
                or "get_IsGenericType" or "get_FullName" or "get_Namespace" or "GetElementType" &&
            arguments.Count == 1 &&
            heap.TryGetModelValue<object>(arguments[0], "Metadata", out var described) &&
            described is not null)
        {
            var answered = DescribeMember(heap, name, described);
            return answered.Status == StaticExecutionStatus.Completed ||
                Named(described) is not { } spelled
                    ? answered
                    : DescribeByName(heap, name, spelled, context.State.ModuleMetadata);
        }
        // A handle is the type itself in the form the runtime hands around, and the machine already
        // turns one back into a type. Giving one out asserts nothing new, and a program that makes
        // an instance from a handle rather than from a name cannot be followed without it.
        if (name == "get_TypeHandle" && arguments.Count == 1)
        {
            var behind = heap.TryGetModelValue<object>(arguments[0], "Metadata", out var recorded) &&
                recorded is not null
                    ? recorded
                    : heap.TryGetModelValue(arguments[0], "TypeName", out string? handleName) &&
                        handleName is not null
                        ? handleName
                        : null;
            if (behind is not null && heap.TryAllocateMetadataHandle(behind, out var handle))
                return IntrinsicResult.Completed(handle);
        }
        if (arguments.Count == 1 && type == "System.Type" &&
            heap.TryGetModelValue(arguments[0], "TypeName", out string? shaped) && shaped is not null)
            return DescribeByName(heap, name, shaped, context.State.ModuleMetadata);
        var expected = type switch
        {
            "System.Type" => "GetTypeFromHandle",
            "System.Reflection.MethodBase" => "GetMethodFromHandle",
            _ => "GetFieldFromHandle"
        };
        if (name != expected || arguments.Count is < 1 or > 2 ||
            !context.State.Heap.TryGetMetadataHandle(arguments[0], out var metadata))
        {
            heap.TryGetRuntimeTypeName(arguments.Count > 0 ? arguments[0] : default, out var self);
            return IntrinsicResult.Invalid(
                $"Unsupported metadata operation {type}::{name} on {self ?? "nothing"}.");
        }

        if (type == "System.Type" && metadata is IFullName denoted)
        {
            if (!heap.TryAllocateType(denoted.FullName, out var known))
                return AllocationFailure("runtime type");
            heap.TrySetModelValue(known, "Metadata", metadata);
            return IntrinsicResult.Completed(known);
        }

        // A handle the machine gave out for a type it only knows by name comes back the same way.
        if (type == "System.Type" && metadata is string spelledOut)
        {
            return heap.TryAllocateType(spelledOut, out var named)
                ? IntrinsicResult.Completed(named)
                : AllocationFailure("runtime type");
        }

        if (!heap.TryAllocateObject(type, out var result))
            return AllocationFailure("metadata object");
        heap.TrySetModelValue(result, "Metadata", metadata);
        return IntrinsicResult.Completed(result);
    }

    /// <summary>
    /// Answers a reflection question about a resolved member from the metadata behind it.
    /// </summary>
    /// <remarks>
    /// A type here is modeled by the metadata it came from rather than by a name, so a parameter's
    /// type and a method's return type are handed back as models carrying their own signature. That
    /// is enough for the comparisons a token-driven runtime makes — is this the same type, how many
    /// parameters are there — without the machine having to know what any of the types mean.
    /// </remarks>
    /// <summary>
    /// The integer type an enumeration is represented by.
    /// </summary>
    /// <remarks>
    /// An enum's underlying type is written into it as the type of its one instance field, so a
    /// definition in the file answers this directly. An enum the file only refers to belongs to
    /// another assembly, and there the framework in hand is the same authority the program would
    /// have consulted.
    /// </remarks>
    private static IntrinsicResult UnderlyingType(IntrinsicContext context, StaticValue asked)
    {
        var heap = context.State.Heap;
        heap.TryGetModelValue<object>(asked, "Metadata", out var described);
        var carried = described is not null && Defined(described) is { IsEnum: true } enumeration
            ? enumeration.Fields.FirstOrDefault(field => !field.IsStatic)?.FieldType.FullName
            : null;
        if (carried is null &&
            heap.TryGetModelValue(asked, "TypeName", out string? spelled) && spelled is not null &&
            WellKnown(spelled, context.State.ModuleMetadata) is { IsEnum: true } known)
        {
            carried = known.GetEnumUnderlyingType().FullName;
        }

        if (carried is null)
            return IntrinsicResult.Invalid("The enumeration being asked about is not modeled.");
        return heap.TryAllocateType(carried, out var underlying)
            ? IntrinsicResult.Completed(underlying)
            : AllocationFailure("underlying type model");
    }

    /// <summary>
    /// The type a method's parameter is declared to take, counting from the first real argument.
    /// </summary>
    private static TypeSig? Expects(IMethod referenced, MethodDef? defined, int position)
    {
        if (defined is not null)
        {
            var parameters = defined.Parameters.Where(item => !item.IsHiddenThisParameter).ToList();
            return position < parameters.Count ? parameters[position].Type : null;
        }

        var declared = referenced.MethodSig?.Params;
        return declared is not null && position < declared.Count ? declared[position] : null;
    }

    /// <summary>
    /// Unwraps a reflectively supplied argument to the form the callee is written against.
    /// </summary>
    /// <remarks>
    /// Reflection hands everything over as an object, so a method that takes a number receives a box
    /// around one. The callee's body was compiled for the number, and passing the box would leave
    /// its first arithmetic instruction looking at a reference. Unwrapping here puts the value in
    /// the shape the body expects, which is exactly what the runtime does at the same boundary.
    /// </remarks>
    private static StaticValue Unwrap(StaticHeap heap, StaticValue argument, TypeSig? expected) =>
        expected is not null && !HoldsBoxes.Contains(expected.FullName) &&
        argument.Kind == StaticValueKind.HeapReference &&
        heap.TryUnbox(argument, out var unboxed)
            ? unboxed
            : argument;

    /// <summary>
    /// The types a parameter can be declared as and still mean the box rather than what is in it.
    /// </summary>
    private static readonly HashSet<string> HoldsBoxes = new(StringComparer.Ordinal)
    {
        "System.Object", "System.ValueType", "System.Enum", "System.IComparable",
        "System.IConvertible", "System.IFormattable"
    };

    /// <summary>
    /// Whether two pieces of metadata name the same type or member.
    /// </summary>
    /// <remarks>
    /// A member reached through a reference and the same member reached through its definition are
    /// one member, so each side is resolved as far as it goes before they are compared. Names are
    /// the last resort and carry signatures, which is what keeps two overloads apart.
    /// </remarks>
    private static bool Denote(object left, object right)
    {
        static object Settle(object member) => member switch
        {
            MethodSpec { Method: { } instantiated } =>
                (object?)instantiated.ResolveMethodDef() ?? member,
            MemberRef { IsMethodRef: true } method => (object?)method.ResolveMethod() ?? member,
            MemberRef { IsFieldRef: true } field => (object?)field.ResolveField() ?? member,
            TypeRef named => (object?)named.Resolve() ?? member,
            TypeSig described => (object?)described.ToTypeDefOrRef().ResolveTypeDef() ?? member,
            _ => member
        };
        var (settled, against) = (Settle(left), Settle(right));
        return ReferenceEquals(settled, against) ||
            (settled is IFullName named && against is IFullName other &&
                string.Equals(named.FullName, other.FullName, StringComparison.Ordinal));
    }

    /// <summary>
    /// Answers a question about a type the machine holds only by name.
    /// </summary>
    /// <remarks>
    /// An object asked for its own type yields a name, not metadata, and when that name belongs to
    /// the framework there is no definition in the file to read. The framework this tool runs on
    /// has the same types, so the answer is looked up there rather than guessed. Nothing is loaded
    /// or executed to do it: the question is which shape a well-known type has, and reflection over
    /// a type that is already present answers it exactly.
    ///
    /// Answering these wrongly would be worse than declining. A program branching on whether a type
    /// is an enum takes a different path for each answer, and a plausible-looking guess would put
    /// the machine on a path the program never takes, far from where the guess was made.
    /// </remarks>
    private static IntrinsicResult DescribeByName(
        StaticHeap heap,
        string question,
        string typeName,
        ModuleDef? subject)
    {
        switch (question)
        {
            case "get_IsByRef": return Truth(typeName.EndsWith('&'));
            case "get_IsPointer": return Truth(typeName.EndsWith('*'));
            case "get_IsArray": return Truth(typeName.EndsWith("[]", StringComparison.Ordinal));
            case "get_FullName":
                return heap.TryAllocateString(typeName, out var spelled)
                    ? IntrinsicResult.Completed(spelled)
                    : IntrinsicResult.Invalid("Could not allocate a type name.");
            case "get_Name":
                var separator = typeName.LastIndexOfAny(['.', '/', '+']);
                return heap.TryAllocateString(typeName[(separator + 1)..], out var shortened)
                    ? IntrinsicResult.Completed(shortened)
                    : IntrinsicResult.Invalid("Could not allocate a type name.");
            case "get_Namespace":
                var dot = typeName.LastIndexOf('.');
                return dot > 0 && heap.TryAllocateString(typeName[..dot], out var containing)
                    ? IntrinsicResult.Completed(containing)
                    : IntrinsicResult.Completed(StaticValue.Null);
            case "GetElementType":
                var shape = typeName.EndsWith("[]", StringComparison.Ordinal) ? 2
                    : typeName.EndsWith('&') || typeName.EndsWith('*') ? 1
                    : 0;
                return shape == 0
                    ? IntrinsicResult.Completed(StaticValue.Null)
                    : heap.TryAllocateType(typeName[..^shape], out var held)
                        ? IntrinsicResult.Completed(held)
                        : IntrinsicResult.Invalid("Could not allocate an element type.");
        }

        if (WellKnown(typeName, subject) is not { } known)
            return IntrinsicResult.Invalid($"Nothing is known about the type {typeName}.");
        return question switch
        {
            "get_IsEnum" => Truth(known.IsEnum),
            "get_IsValueType" => Truth(known.IsValueType),
            "get_IsPrimitive" => Truth(known.IsPrimitive),
            "get_IsInterface" => Truth(known.IsInterface),
            "get_IsClass" => Truth(known.IsClass),
            "get_IsSealed" => Truth(known.IsSealed),
            "get_IsAbstract" => Truth(known.IsAbstract),
            "get_IsGenericType" => Truth(known.IsGenericType),
            _ => IntrinsicResult.Invalid($"Unsupported question {question} about {typeName}.")
        };
    }

    private static readonly Dictionary<string, Type?> Recognized = new(StringComparer.Ordinal);

    /// <summary>
    /// The framework type of this name, where the framework in hand has one.
    /// </summary>
    /// <remarks>
    /// A name the file under analysis defines is never answered from here, however framework-like it
    /// looks, because the file's own type is the one the program means. What is left are names in
    /// the framework's own namespaces, and for those the type present in this process is the same
    /// type the protected program would have been using.
    /// </remarks>
    private static Type? WellKnown(string typeName, ModuleDef? subject)
    {
        if (subject?.Find(typeName, isReflectionName: false) is not null)
            return null;
        if (Recognized.TryGetValue(typeName, out var known))
            return known;
        if (!typeName.StartsWith("System.", StringComparison.Ordinal) &&
            !typeName.StartsWith("Microsoft.", StringComparison.Ordinal))
            return Recognized[typeName] = null;
        known = Type.GetType(typeName, throwOnError: false) ??
            AppDomain.CurrentDomain.GetAssemblies()
                .Select(assembly => assembly.GetType(typeName, throwOnError: false))
                .FirstOrDefault(candidate => candidate is not null);
        return Recognized[typeName] = known;
    }

    /// <summary>
    /// The member this reference names, as the framework in hand declares it.
    /// </summary>
    /// <remarks>
    /// A reference into the framework resolves to no definition here, and its signature does not
    /// say whether the method is virtual or static — but the framework does, and it is the same
    /// framework the protected program was built against. A runtime that rebuilds calls from
    /// tokens asks exactly this before deciding how to make the call, so leaving it unanswered
    /// stops the interpretation at the point where the program starts doing its work.
    ///
    /// An overload that cannot be told from its fellows by name and count is not answered, because
    /// the ones that differ could differ in the answer.
    /// </remarks>
    private static System.Reflection.MethodBase? Framework(MemberRef reference)
    {
        if (reference.DeclaringType?.FullName is not { } owner ||
            WellKnown(owner, reference.Module) is not { } present)
        {
            return null;
        }
        const System.Reflection.BindingFlags everything =
            System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic |
            System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.Instance;
        var taken = reference.MethodSig?.Params ?? (IList<TypeSig>)[];
        var named = (reference.Name == ".ctor"
                ? present.GetConstructors(everything).Cast<System.Reflection.MethodBase>()
                : present.GetMethods(everything))
            .Where(candidate => candidate.Name == reference.Name &&
                candidate.GetParameters().Length == taken.Count)
            .ToArray();
        if (named.Length <= 1)
            return named.FirstOrDefault();

        // Overloads are told apart by what they take, which both sides spell the same way.
        var alike = named
            .Where(candidate => candidate.GetParameters()
                .Select(parameter => parameter.ParameterType.FullName)
                .SequenceEqual(taken.Select(held => held.FullName), StringComparer.Ordinal))
            .ToArray();
        return alike.Length == 1 ? alike[0] : null;
    }

    private static IntrinsicResult DescribeMember(StaticHeap heap, string name, object described)
    {
        // A reference and the definition it names describe the same member, so questions are asked
        // of the definition wherever one can be reached. What remains a reference points outside
        // this module, where the signature carried by the reference is all there is and all the
        // answers below need.
        described = described switch
        {
            MethodSpec { Method: { } instantiated } => (object?)instantiated.ResolveMethodDef() ??
                described,
            MemberRef { IsMethodRef: true } method => (object?)method.ResolveMethod() ?? described,
            MemberRef { IsFieldRef: true } field => (object?)field.ResolveField() ?? described,
            _ => described
        };
        switch (name)
        {
            case "get_ParameterType" when described is TypeSig referenced:
                return Describing(heap, "System.Type", referenced);
            case "get_IsStatic" when described is MemberRef { MethodSig: { } signature }:
                return Truth(!signature.HasThis);
            case "get_ReturnType" when described is MemberRef { MethodSig.RetType: { } returned }:
                return Describing(heap, "System.Type", returned);
            case "get_FieldType" when described is MemberRef { FieldSig.Type: { } held }:
                return Describing(heap, "System.Type", held);
            case "get_Name":
                var text = described switch
                {
                    IMemberRef member => member.Name.String,
                    IType declared => declared.TypeName,
                    _ => null
                };
                return text is not null && heap.TryAllocateString(text, out var allocated)
                    ? IntrinsicResult.Completed(allocated)
                    : IntrinsicResult.Invalid("The member has no name to report.");
            case "get_DeclaringType" when described is IMemberRef owned && owned.DeclaringType is { } owner:
                return Describing(heap, "System.Type", owner);
            case "get_IsStatic" when described is MethodDef staticCandidate:
                return Truth(staticCandidate.IsStatic);
            case "get_IsStatic" when described is FieldDef staticField:
                return Truth(staticField.IsStatic);
            case "get_IsAbstract" when described is MethodDef abstractCandidate:
                return Truth(abstractCandidate.IsAbstract);
            case "get_IsAbstract" when described is TypeDef abstractType:
                return Truth(abstractType.IsAbstract);
            case "get_IsVirtual" when described is MethodDef virtualCandidate:
                return Truth(virtualCandidate.IsVirtual);
            case "get_IsPublic" when described is MethodDef publicCandidate:
                return Truth(publicCandidate.IsPublic);
            case "get_IsPublic" when described is FieldDef publicField:
                return Truth(publicField.IsPublic);
            case "get_IsByRef":
                return Truth(described is ByRefSig);
            case "get_IsPointer":
                return Truth(described is PtrSig);
            case "get_IsArray":
                return Truth(described is ArraySigBase);
            case "get_IsGenericType":
                return Truth(described is GenericInstSig);
            case "get_IsPrimitive":
                return Truth(described is CorLibTypeSig { ElementType: >= ElementType.Boolean and <= ElementType.R8 });
            // These read the definition, so they are only answered when there is one to read. A type
            // the file merely refers to belongs to some other assembly, and answering no about it
            // would be a guess dressed as a fact — the caller falls back to asking by name instead.
            case "get_IsValueType" when described is
                CorLibTypeSig { ElementType: not ElementType.String and not ElementType.Object }:
                return Truth(true);
            case "get_IsValueType" when Defined(described) is { } valueCandidate:
                return Truth(valueCandidate.IsValueType);
            case "get_IsEnum" when Defined(described) is { } enumCandidate:
                return Truth(enumCandidate.IsEnum);
            case "get_IsInterface" when Defined(described) is { } contract:
                return Truth(contract.IsInterface);
            case "get_IsSealed" when Defined(described) is { } sealedCandidate:
                return Truth(sealedCandidate.IsSealed);
            case "get_IsClass" when Defined(described) is { } classCandidate:
                return Truth(classCandidate is { IsInterface: false, IsValueType: false });
            case "get_FullName" when Named(described) is { } fullName:
                return heap.TryAllocateString(fullName, out var fullNameValue)
                    ? IntrinsicResult.Completed(fullNameValue)
                    : AllocationFailure("type name");
            case "get_Namespace" when Defined(described) is { } namespaced:
                return heap.TryAllocateString(namespaced.Namespace, out var namespaceValue)
                    ? IntrinsicResult.Completed(namespaceValue)
                    : AllocationFailure("type namespace");
            case "GetElementType" when described is NonLeafSig element:
                return Describing(heap, "System.Type", element.Next);
            case "get_FieldType" when described is FieldDef typedField:
                return Describing(heap, "System.Type", typedField.FieldType);
            case "get_IsVirtual" or "get_IsStatic" or "get_IsAbstract" or "get_IsPublic"
                when described is MemberRef { IsMethodRef: true } outside &&
                    Framework(outside) is { } present:
                return Truth(name switch
                {
                    "get_IsVirtual" => present.IsVirtual,
                    "get_IsStatic" => present.IsStatic,
                    "get_IsAbstract" => present.IsAbstract,
                    _ => present.IsPublic
                });
            case "get_MetadataToken" when described is IMDTokenProvider tokenHolder:
                return IntrinsicResult.Completed(
                    StaticValue.FromInt32((int)tokenHolder.MDToken.Raw));
            case "get_ParameterType" when described is Parameter parameter:
                return Describing(heap, "System.Type", parameter.Type);
            case "get_ReturnType" when described is MethodDef method:
                return Describing(heap, "System.Type", method.ReturnType);
            // A definition names its parameters; a reference only lists their types. Either way the
            // caller is asking how many there are and what they are, which both can answer.
            case "GetParameters" when
                described is MethodDef or MemberRef { IsMethodRef: true }:
                object[] parameters = described is MethodDef target
                    ? [.. target.Parameters.Where(item => !item.IsHiddenThisParameter)]
                    : [.. ((MemberRef)described).MethodSig?.Params ?? []];
                if (!heap.TryAllocateArray(null, parameters.Length, out var array))
                    return AllocationFailure("parameter array");
                for (var index = 0; index < parameters.Length; index++)
                {
                    if (Describing(heap, "System.Reflection.ParameterInfo", parameters[index]) is
                            { Status: StaticExecutionStatus.Completed } item &&
                        heap.TryWriteArray(array, index, item.Value))
                    {
                        continue;
                    }

                    return AllocationFailure("parameter model");
                }

                return IntrinsicResult.Completed(array);
            default:
                // What was asked about matters as much as what was asked: the same question is
                // answerable of a definition and unanswerable of a reference that resolves nowhere.
                return IntrinsicResult.Invalid(
                    $"Metadata question {name} is unmodeled for a {described.GetType().Name}" +
                    $" ({described}).");
        }
    }

    /// <summary>
    /// The definition behind a described type, whether it arrived as a signature or a definition.
    /// </summary>
    /// <remarks>
    /// A type reaches the machine either as a member's signature or as a resolved token, and the
    /// questions asked of it are the same either way. Types defined outside this module resolve to
    /// nothing, which leaves the question unanswered rather than answered wrongly.
    /// </remarks>
    /// <summary>
    /// Gives a type model its definition when the name belongs to this module.
    /// </summary>
    /// <remarks>
    /// A type that arrived as a name can still answer questions about itself if the name is one the
    /// module defines, and attaching the definition is what lets the same code path serve a type
    /// obtained by reflection and one obtained from a token. A name from elsewhere is left as a
    /// name, since there is no definition here to speak for it.
    /// </remarks>
    private static void AttachDefinition(IntrinsicContext context, StaticValue model, string typeName)
    {
        if (context.State.ModuleMetadata?.Find(typeName, false) is { } definition)
            context.State.Heap.TrySetModelValue(model, "Metadata", definition);
    }

    /// <summary>
    /// Whether a field is one of those a reflection query with these binding flags would return.
    /// </summary>
    /// <remarks>
    /// Only the four flags that choose which members are in view are honoured. The rest of
    /// <c>BindingFlags</c> describes how an invocation should behave rather than what a lookup can
    /// see, so they say nothing about whether a field belongs in the answer.
    /// </remarks>
    private static bool Selects(int bindingFlags, FieldDef field)
    {
        const int instance = 0x04;
        const int isStatic = 0x08;
        const int isPublic = 0x10;
        const int nonPublic = 0x20;
        var lifetimeWanted = field.IsStatic ? isStatic : instance;
        var visibilityWanted = field.IsPublic ? isPublic : nonPublic;
        return (bindingFlags & lifetimeWanted) != 0 && (bindingFlags & visibilityWanted) != 0;
    }

    private static TypeDef? Defined(object described) => described switch
    {
        TypeDef definition => definition,
        ITypeDefOrRef reference => reference.ResolveTypeDef(),
        TypeSig signature => signature.ToTypeDefOrRef()?.ResolveTypeDef(),
        _ => null
    };

    private static string? Named(object described) => described switch
    {
        IType named => named.FullName,
        _ => null
    };

    private static IntrinsicResult Truth(bool value) =>
        IntrinsicResult.Completed(StaticValue.FromInt32(value ? 1 : 0));

    /// <summary>
    /// Serves the compiler-generated resource wrappers that hold a program's embedded data.
    /// </summary>
    /// <remarks>
    /// A designer-generated <c>Properties.Resources</c> class is the ordinary way to carry a blob
    /// in an assembly, and packers use it exactly as an application would: a property that hands
    /// back a byte array which then goes through the unpacking chain. Reaching it means going one
    /// level below the manifest, because the manager addresses entries inside a <c>.resources</c>
    /// container rather than the container itself.
    ///
    /// Only strings and byte arrays are answered. The container can also carry serialized objects,
    /// and reconstructing those would mean running a deserializer over attacker-chosen bytes to
    /// build something the machine has no model for anyway.
    /// </remarks>
    /// <summary>Model-value name under which a loaded assembly keeps the bytes it was built from.</summary>
    private const string LoadedImage = "LoadedImage";

    /// <summary>
    /// Reads a named resource out of an assembly, whether that is the subject or one it loaded.
    /// </summary>
    private static byte[]? TryReadResource(
        IntrinsicContext context,
        StaticValue assembly,
        string resourceName)
    {
        if (context.State.Resources.TryGetValue(resourceName, out var registered) &&
            !context.State.Heap.TryGetModelValue(assembly, LoadedImage, out byte[]? _))
        {
            return registered;
        }

        return context.State.Heap.TryGetModelValue(assembly, LoadedImage, out byte[]? image) &&
            image is not null
                ? ReadEmbeddedResource(image, resourceName)
                : TryResolveResource(context, resourceName);
    }

    /// <summary>
    /// Asks the program itself for a resource the assembly does not carry under that name.
    /// </summary>
    /// <remarks>
    /// A protector that encrypts resources renames them and hands the originals back through the
    /// resolve event the runtime raises on a miss, so the name in the metadata and the name the
    /// program asks for never match. Rather than teach the machine that particular scheme, it does
    /// what the runtime does: raise the event and take whatever assembly the handler returns. That
    /// keeps working for any handler the machine can already run, which is the point of having run
    /// the protector's own code this far.
    /// </remarks>
    private static byte[]? TryResolveResource(IntrinsicContext context, string resourceName)
    {
        var heap = context.State.Heap;
        if (context.Invoke is not { } invoke)
            return Declined("no call mechanism");
        if (!context.State.TryGetOrAllocateRuntimeSingleton("System.AppDomain", out var domain))
            return Declined("no application domain");
        if (!heap.TryGetModelValue(domain, "Event:ResourceResolve", out StaticValue handler))
            return Declined("no handler is registered");
        if (!heap.TryAllocateObject("System.ResolveEventArgs", out var raised) ||
            !heap.TryAllocateString(resourceName, out var requested))
        {
            return Declined("event arguments could not be built");
        }

        heap.TrySetModelValue(raised, "Name", requested);
        var answered = invoke(handler, [StaticValue.Null, raised]);
        if (answered.Status != StaticExecutionStatus.Completed)
            return Declined($"handler stopped: {answered.Diagnostic}");
        if (!heap.TryGetModelValue(answered.Value, LoadedImage, out byte[]? image) || image is null)
            return Declined("handler returned no assembly image");
        return ReadEmbeddedResource(image, resourceName) ??
            Declined($"the returned assembly has no '{resourceName}'");

        byte[]? Declined(string reason)
        {
            MachineTrace.Line($"resolve '{resourceName}' declined: {reason}");
            return null;
        }
    }

    /// <summary>Lists the resources an assembly image carries.</summary>
    private static IReadOnlyList<string> ImageResourceNames(byte[] image)
    {
        try
        {
            using var module = ModuleDefMD.Load(image);
            return [.. module.Resources.Select(resource => resource.Name.String)];
        }
        catch (Exception failure) when (ManagedImage.Rejects(failure))
        {
            return [];
        }
    }

    /// <summary>Reads one embedded resource out of an assembly image.</summary>
    private static byte[]? ReadEmbeddedResource(byte[] image, string resourceName)
    {
        try
        {
            using var module = ModuleDefMD.Load(image);
            return module.Resources.FindEmbeddedResource(resourceName) is { } found
                ? found.CreateReader().ToArray()
                : null;
        }
        catch (Exception failure) when (ManagedImage.Rejects(failure))
        {
            return null;
        }
    }

    private static IntrinsicResult InvokeResourceManager(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (name == ".ctor" && arguments.Count >= 2)
        {
            // The base name arrives either literally or as the type whose namespace names the
            // container, depending on which constructor the generated wrapper picked.
            var container =
                heap.TryGetString(arguments[1], out var literal) ? literal :
                heap.TryGetModelValue(arguments[1], "TypeName", out string? named) ? named : null;
            if (container is null)
                return IntrinsicResult.Invalid("ResourceManager was built without a known base name.");
            heap.TrySetModelValue(arguments[0], "BaseName", container);
            return IntrinsicResult.Completed();
        }

        if (name is not ("GetObject" or "GetString" or "GetStream") || arguments.Count < 2)
            return IntrinsicResult.Invalid($"ResourceManager operation {name} is denied.");
        if (!heap.TryGetModelValue(arguments[0], "BaseName", out string? baseName) || baseName is null)
            return IntrinsicResult.Invalid("ResourceManager has no base name to look in.");
        if (!heap.TryGetString(arguments[1], out var entry))
            return IntrinsicResult.Invalid("ResourceManager was asked for a non-constant name.");
        var containerName = baseName + ".resources";
        if (!context.State.Resources.TryGetValue(containerName, out var container2))
        {
            if (TryResolveResource(context, containerName) is not { } resolved)
                return IntrinsicResult.Invalid($"Resource container '{containerName}' is absent.");
            context.State.RegisterResource(containerName, resolved);
            container2 = resolved;
        }

        if (!TryReadResourceEntry(container2, entry, out var value))
            return IntrinsicResult.Invalid($"Resource '{entry}' is absent or of an unmodeled kind.");

        return value switch
        {
            string text => heap.TryAllocateString(text, out var allocated)
                ? IntrinsicResult.Completed(allocated)
                : AllocationFailure("resource string"),
            byte[] bytes when name == "GetStream" =>
                heap.TryAllocateByteArray(bytes, out var backing) &&
                heap.TryAllocateObject("System.IO.MemoryStream", out var stream) &&
                heap.TrySetModelValue(stream, "Buffer", backing)
                    ? IntrinsicResult.Completed(stream)
                    : AllocationFailure("resource stream"),
            byte[] bytes => heap.TryAllocateByteArray(bytes, out var array)
                ? IntrinsicResult.Completed(array)
                : AllocationFailure("resource bytes"),
            _ => IntrinsicResult.Invalid($"Resource '{entry}' is of an unmodeled kind.")
        };
    }

    /// <summary>
    /// Reads one entry out of a <c>.resources</c> container, accepting only what can be modeled.
    /// </summary>
    private static bool TryReadResourceEntry(byte[] container, string entry, out object? value)
    {
        value = null;
        try
        {
            using var reader = new System.Resources.ResourceReader(new MemoryStream(container, false));
            foreach (System.Collections.DictionaryEntry item in reader)
            {
                if (item.Key as string != entry)
                    continue;
                value = item.Value is string or byte[] ? item.Value : null;
                return value is not null;
            }
        }
        catch (Exception failure) when (
            failure is ArgumentException or BadImageFormatException or
                FormatException or IOException or NotSupportedException)
        {
            return false;
        }

        return false;
    }

    private static IntrinsicResult Describing(StaticHeap heap, string modelType, object metadata)
    {
        var model = StaticValue.Unknown;
        var made = modelType == "System.Type" && metadata is IFullName denoted
            ? heap.TryAllocateType(denoted.FullName, out model)
            : heap.TryAllocateObject(modelType, out model);
        if (!made)
            return AllocationFailure("metadata model");
        heap.TrySetModelValue(model, "Metadata", metadata);
        return IntrinsicResult.Completed(model);
    }

    /// <summary>Builds a string the way <c>new string(...)</c> does, from characters.</summary>
    /// <remarks>
    /// Reactor's decoders end in this constructor: they take a literal apart into characters,
    /// undo whatever was done to each one, and put the characters back together. Without it the
    /// work of the whole routine is done and then dropped on its last instruction.
    /// </remarks>
    private static IntrinsicResult MakeString(
        StaticHeap heap,
        IReadOnlyList<StaticValue> arguments)
    {
        // Repeating one character is the only form that does not begin from an array.
        if (arguments.Count == 3 &&
            arguments[1].Kind == StaticValueKind.Int32 &&
            arguments[2].Kind == StaticValueKind.Int32)
        {
            var count = arguments[2].AsInt32();
            if (count < 0)
                return IntrinsicResult.Invalid("String repeat count is negative.");
            return heap.TryAllocateString(
                new string((char)(ushort)arguments[1].AsInt32(), count), out var repeated)
                ? IntrinsicResult.Completed(repeated)
                : AllocationFailure("String..ctor");
        }

        // An array allocated where no metadata was available to name its element type still holds
        // the characters that were put in it, so what it says it holds is not the test.
        if (arguments.Count is not (2 or 4) ||
            !heap.TryGetArrayElementType(arguments[1], out var elementType) ||
            elementType is not ("System.Char" or "?") ||
            !heap.TryGetLength(arguments[1], out var length))
        {
            return IntrinsicResult.Invalid("Unsupported String operation .ctor.");
        }

        var start = arguments.Count == 4 ? arguments[2].AsInt32() : 0;
        var taken = arguments.Count == 4 ? arguments[3].AsInt32() : length;
        if (start < 0 || taken < 0 || start > length - taken)
            return IntrinsicResult.Invalid("String segment is outside the character array.");

        var built = new char[taken];
        for (var index = 0; index < taken; index++)
        {
            if (!heap.TryReadArray(arguments[1], start + index, out var character) ||
                !character.IsKnown)
                return IntrinsicResult.Invalid("A character of the string is not known.");
            built[index] = (char)(ushort)character.AsInt32();
        }

        return heap.TryAllocateString(new string(built), out var made)
            ? IntrinsicResult.Completed(made)
            : AllocationFailure("String..ctor");
    }

    private static IntrinsicResult InvokeString(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        if (name is "op_Equality" or "op_Inequality" && arguments.Count == 2)
        {
            var leftIsNull = arguments[0].Kind == StaticValueKind.Null;
            var rightIsNull = arguments[1].Kind == StaticValueKind.Null;
            var equal = leftIsNull || rightIsNull
                ? leftIsNull == rightIsNull
                : context.State.Heap.TryGetString(arguments[0], out var left) &&
                  context.State.Heap.TryGetString(arguments[1], out var right) &&
                  string.Equals(left, right, StringComparison.Ordinal);
            return IntrinsicResult.Completed(StaticValue.FromInt32(
                (name == "op_Equality" ? equal : !equal) ? 1 : 0));
        }
        if (name == "Concat" && arguments.Count is >= 2 and <= 4)
        {
            var parts = new string[arguments.Count];
            for (var index = 0; index < arguments.Count; index++)
            {
                if (arguments[index].Kind == StaticValueKind.Null)
                    parts[index] = string.Empty;
                else if (!context.State.Heap.TryGetString(arguments[index], out parts[index]!))
                    return IntrinsicResult.Invalid("String.Concat requires concrete strings.");
            }
            return context.State.Heap.TryAllocateString(string.Concat(parts), out var concatenated)
                ? IntrinsicResult.Completed(concatenated)
                : AllocationFailure("String.Concat");
        }
        if (name == "get_Length" && arguments.Count == 1 &&
            context.State.Heap.TryGetString(arguments[0], out var text))
            return IntrinsicResult.Completed(StaticValue.FromInt32(text.Length));
        if (name == "ToCharArray" && arguments.Count == 1 &&
            context.State.Heap.TryGetString(arguments[0], out text))
        {
            // The element type is what makes the array able to hold characters at all: an array
            // allocated without one takes no primitive, so the characters would be dropped here
            // and every later write to the array refused.
            if (!context.State.Heap.TryAllocateArray(
                    context.State.ModuleMetadata?.CorLibTypes.Char,
                    text.Length,
                    out var array))
                return AllocationFailure("String.ToCharArray");
            for (var i = 0; i < text.Length; i++)
            {
                if (!context.State.Heap.TryWriteArray(array, i, StaticValue.FromInt32(text[i])))
                    return AllocationFailure("String.ToCharArray");
            }

            return IntrinsicResult.Completed(array);
        }
        if (name is "ToLower" or "ToLowerInvariant" or "ToUpper" or "ToUpperInvariant" &&
            arguments.Count == 1 &&
            context.State.Heap.TryGetString(arguments[0], out text))
        {
            var transformed = name.StartsWith("ToLower", StringComparison.Ordinal)
                ? text.ToLowerInvariant()
                : text.ToUpperInvariant();
            return context.State.Heap.TryAllocateString(transformed, out var result)
                ? IntrinsicResult.Completed(result)
                : AllocationFailure(name);
        }
        if (name is "Trim" or "TrimStart" or "TrimEnd" &&
            arguments.Count == 1 &&
            context.State.Heap.TryGetString(arguments[0], out text))
        {
            var transformed = name switch
            {
                "TrimStart" => text.TrimStart(),
                "TrimEnd" => text.TrimEnd(),
                _ => text.Trim()
            };
            return context.State.Heap.TryAllocateString(transformed, out var result)
                ? IntrinsicResult.Completed(result)
                : AllocationFailure(name);
        }
        if (name is "Contains" or "StartsWith" or "EndsWith" &&
            arguments.Count >= 2 &&
            context.State.Heap.TryGetString(arguments[0], out text) &&
            context.State.Heap.TryGetString(arguments[1], out var searched))
        {
            var matched = name switch
            {
                "Contains" => text.Contains(searched, StringComparison.Ordinal),
                "StartsWith" => text.StartsWith(searched, StringComparison.Ordinal),
                _ => text.EndsWith(searched, StringComparison.Ordinal)
            };
            return IntrinsicResult.Completed(StaticValue.FromInt32(matched ? 1 : 0));
        }
        if (name == ".ctor")
            return MakeString(context.State.Heap, arguments);
        return IntrinsicResult.Invalid($"Unsupported String operation {name}.");
    }

    private static IntrinsicResult InvokeVersion(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (name == ".ctor" && arguments.Count is >= 3 and <= 5)
        {
            var components = new int[4];
            for (var index = 1; index < arguments.Count; index++)
                components[index - 1] = arguments[index].AsInt32();
            heap.TrySetModelValue(arguments[0], "Components", components);
            return IntrinsicResult.Completed();
        }
        if (arguments.Count == 1 &&
            heap.TryGetModelValue(arguments[0], "Components", out int[]? own) &&
            own is not null)
        {
            var component = name switch
            {
                "get_Major" => 0,
                "get_Minor" => 1,
                "get_Build" => 2,
                "get_Revision" => 3,
                _ => -1
            };
            if (component >= 0)
                return IntrinsicResult.Completed(StaticValue.FromInt32(own[component]));
        }
        if (arguments.Count == 2 &&
            heap.TryGetModelValue(arguments[0], "Components", out int[]? left) &&
            heap.TryGetModelValue(arguments[1], "Components", out int[]? right) &&
            left is not null && right is not null)
        {
            var comparison = CompareVersions(left, right);
            return name switch
            {
                "CompareTo" => IntrinsicResult.Completed(StaticValue.FromInt32(comparison)),
                "op_Equality" => IntrinsicResult.Completed(
                    StaticValue.FromInt32(comparison == 0 ? 1 : 0)),
                "op_Inequality" => IntrinsicResult.Completed(
                    StaticValue.FromInt32(comparison != 0 ? 1 : 0)),
                "op_LessThan" => IntrinsicResult.Completed(
                    StaticValue.FromInt32(comparison < 0 ? 1 : 0)),
                "op_LessThanOrEqual" => IntrinsicResult.Completed(
                    StaticValue.FromInt32(comparison <= 0 ? 1 : 0)),
                "op_GreaterThan" => IntrinsicResult.Completed(
                    StaticValue.FromInt32(comparison > 0 ? 1 : 0)),
                "op_GreaterThanOrEqual" => IntrinsicResult.Completed(
                    StaticValue.FromInt32(comparison >= 0 ? 1 : 0)),
                _ => IntrinsicResult.Invalid($"Version operation {name} is denied.")
            };
        }
        return IntrinsicResult.Invalid($"Version operation {name} is denied.");
    }

    private static int CompareVersions(int[] left, int[] right)
    {
        for (var index = 0; index < 4; index++)
        {
            var comparison = left[index].CompareTo(right[index]);
            if (comparison != 0)
                return comparison;
        }
        return 0;
    }

    private static IntrinsicResult InvokeRuntimeHelpers(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        if (name != "InitializeArray" ||
            arguments.Count != 2 ||
            !context.State.Heap.TryGetMetadataHandle(arguments[1], out var metadata) ||
            metadata is not FieldDef field ||
            field.InitialValue is not { Length: > 0 } bytes)
        {
            return IntrinsicResult.Invalid($"RuntimeHelpers operation {name} is denied.");
        }
        var provenance = context.State.Provenance.Operation(
            StaticValue.FromInt32(bytes.Length),
            ProvenanceKind.Metadata,
            "RuntimeHelpers.InitializeArray",
            field.FullName,
            arguments[1]);
        return (context.State.Heap.TryWriteBytes(arguments[0], 0, bytes) ||
                context.State.Heap.TryInitializePrimitiveArray(
                    arguments[0],
                    bytes,
                    provenance.ProvenanceId))
            ? IntrinsicResult.Completed()
            : IntrinsicResult.Invalid("Initialized-array data does not fit its destination.");
    }

    private static IntrinsicResult InvokeEncoding(
        IntrinsicContext context,
        string type,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (name is ".ctor")
        {
            heap.TrySetModelValue(arguments[0], "Encoding",
                type.Contains("Unicode", StringComparison.Ordinal) ? "Unicode" : "UTF8");
            return IntrinsicResult.Completed();
        }
        if (name is "get_UTF8" or "get_Unicode")
        {
            if (!heap.TryAllocateObject("System.Text.Encoding", out var encodingReference))
                return AllocationFailure(name);
            heap.TrySetModelValue(
                encodingReference,
                "Encoding",
                name == "get_Unicode" ? "Unicode" : "UTF8");
            return IntrinsicResult.Completed(encodingReference);
        }
        if (arguments.Count < 2 ||
            !heap.TryGetModelValue(arguments[0], "Encoding", out string? encodingName))
            return IntrinsicResult.Invalid($"Invalid Encoding receiver for {name}.");
        var encoding = encodingName == "Unicode" ? Encoding.Unicode : Encoding.UTF8;
        if (name == "GetBytes" && arguments.Count == 2 &&
            heap.TryGetString(arguments[1], out var text))
            return heap.TryAllocateByteArray(encoding.GetBytes(text), out var bytes)
                ? IntrinsicResult.Completed(bytes)
                : AllocationFailure("Encoding.GetBytes");
        if (name == "GetString" && arguments.Count is 2 or 4)
        {
            var offset = arguments.Count == 2 ? 0 : arguments[2].AsInt32();
            if (!heap.TryGetLength(arguments[1], out var total))
                return IntrinsicResult.Invalid("Encoding.GetString target is not a byte array.");
            var count = arguments.Count == 2 ? total : arguments[3].AsInt32();
            var bytes = new byte[count < 0 ? 0 : count];
            if (count < 0 || !heap.TryReadBytes(arguments[1], offset, bytes))
                return IntrinsicResult.Invalid("Encoding.GetString range is invalid.");
            return heap.TryAllocateString(encoding.GetString(bytes), out var result)
                ? IntrinsicResult.Completed(result)
                : AllocationFailure("Encoding.GetString");
        }
        return IntrinsicResult.Invalid($"Unsupported Encoding operation {name}.");
    }

    private static IntrinsicResult InvokeMemoryStream(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        var stream = arguments[0];
        if (name == ".ctor")
        {
            StaticValue buffer;
            var origin = 0;
            var length = 0;
            var capacity = 0;
            var writable = true;
            var expandable = true;
            var publiclyVisible = true;
            if (arguments.Count >= 2 &&
                arguments[1].Kind == StaticValueKind.HeapReference)
            {
                buffer = arguments[1];
                if (!heap.TryGetLength(buffer, out var bufferLength) ||
                    !heap.TryGetArrayElementType(buffer, out var elementType) ||
                    elementType != "System.Byte")
                    return IntrinsicResult.Invalid("MemoryStream segment is invalid.");
                origin = arguments.Count >= 4 ? arguments[2].AsInt32() : 0;
                length = arguments.Count >= 4 ? arguments[3].AsInt32() : bufferLength;
                if (origin < 0 || length < 0 || origin > bufferLength - length)
                    return IntrinsicResult.Invalid("MemoryStream segment is invalid.");
                capacity = length;
                writable = arguments.Count switch
                {
                    >= 5 => arguments[4].AsInt32() != 0,
                    3 => arguments[2].AsInt32() != 0,
                    _ => true
                };
                publiclyVisible = arguments.Count >= 6 && arguments[5].AsInt32() != 0;
                expandable = false;
            }
            else
            {
                capacity = arguments.Count == 2 && arguments[1].IsInteger
                    ? arguments[1].AsInt32()
                    : 0;
                if (capacity < 0 ||
                    !heap.TryAllocateByteArray(new byte[capacity], out buffer))
                {
                    return capacity < 0
                        ? IntrinsicResult.Invalid("MemoryStream capacity is negative.")
                        : AllocationFailure("MemoryStream");
                }
            }
            heap.TrySetModelValue(stream, "Buffer", buffer);
            heap.TrySetModelValue(stream, "Position", 0L);
            heap.TrySetModelValue(stream, "Origin", origin);
            heap.TrySetModelValue(stream, "Length", length);
            heap.TrySetModelValue(stream, "Capacity", capacity);
            heap.TrySetModelValue(stream, "Writable", writable);
            heap.TrySetModelValue(stream, "Expandable", expandable);
            heap.TrySetModelValue(stream, "PubliclyVisible", publiclyVisible);
            heap.TrySetModelValue(stream, "Open", true);
            return IntrinsicResult.Completed();
        }
        if (!heap.TryGetModelValue(stream, "Buffer", out StaticValue bufferValue) ||
            !heap.TryGetModelValue(stream, "Position", out long position) ||
            !heap.TryGetModelValue(stream, "Origin", out int originValue) ||
            !heap.TryGetModelValue(stream, "Length", out int lengthValue) ||
            !heap.TryGetModelValue(stream, "Capacity", out int capacityValue) ||
            !heap.TryGetModelValue(stream, "Writable", out bool isWritable) ||
            !heap.TryGetModelValue(stream, "Expandable", out bool isExpandable) ||
            !heap.TryGetModelValue(stream, "Open", out bool isOpen))
            return IntrinsicResult.Invalid("Stream is not initialized.");
        if (name is "Dispose" or "Close")
        {
            heap.TrySetModelValue(stream, "Open", false);
            return IntrinsicResult.Completed();
        }
        if (!isOpen)
            return IntrinsicResult.Invalid("Stream is closed.");
        if (name == "get_Length")
            return IntrinsicResult.Completed(StaticValue.FromInt64(lengthValue));
        if (name == "get_Position")
            return IntrinsicResult.Completed(StaticValue.FromInt64(position));
        if (name == "get_CanRead" || name == "get_CanSeek")
            return IntrinsicResult.Completed(StaticValue.FromInt32(1));
        if (name == "get_CanWrite")
            return IntrinsicResult.Completed(StaticValue.FromInt32(isWritable ? 1 : 0));
        if (name == "set_Position" && arguments.Count == 2)
        {
            var requested = arguments[1].AsInt64();
            if (requested < 0 || requested > int.MaxValue - originValue)
                return IntrinsicResult.Invalid("Stream position is out of range.");
            heap.TrySetModelValue(stream, "Position", requested);
            return IntrinsicResult.Completed();
        }
        if (name == "Seek" && arguments.Count == 3)
        {
            var offset = arguments[1].AsInt64();
            var basis = arguments[2].AsInt32() switch
            {
                0 => 0L,
                1 => position,
                2 => lengthValue,
                _ => -1L
            };
            if (basis < 0 || offset < -basis ||
                offset > int.MaxValue - originValue - basis)
                return IntrinsicResult.Invalid("Stream seek is out of range.");
            var requested = basis + offset;
            heap.TrySetModelValue(stream, "Position", requested);
            return IntrinsicResult.Completed(StaticValue.FromInt64(requested));
        }
        if (name == "ToArray")
        {
            var bytes = new byte[lengthValue];
            return heap.TryReadBytes(bufferValue, originValue, bytes) &&
                heap.TryAllocateByteArray(bytes, out var copy)
                    ? IntrinsicResult.Completed(copy)
                    : AllocationFailure("MemoryStream.ToArray");
        }
        if (name == "ReadByte")
        {
            if (position >= lengthValue)
                return IntrinsicResult.Completed(StaticValue.FromInt32(-1));
            Span<byte> one = stackalloc byte[1];
            heap.TryReadBytes(bufferValue, checked(originValue + (int)position), one);
            heap.TrySetModelValue(stream, "Position", position + 1);
            return IntrinsicResult.Completed(StaticValue.FromInt32(one[0]));
        }
        if (name == "Read" && arguments.Count == 4)
        {
            var offset = arguments[2].AsInt32();
            var requested = arguments[3].AsInt32();
            var available = position >= lengthValue ? 0 : checked(lengthValue - (int)position);
            var count = Math.Min(Math.Max(requested, 0), available);
            var bytes = new byte[count];
            if (requested < 0 ||
                !heap.TryReadBytes(
                    bufferValue,
                    checked(originValue + (int)position),
                    bytes) ||
                !heap.TryWriteBytes(arguments[1], offset, bytes))
                return IntrinsicResult.Invalid("Stream.Read range is invalid.");
            heap.TrySetModelValue(stream, "Position", position + count);
            return IntrinsicResult.Completed(StaticValue.FromInt32(count));
        }
        if (name == "Write" && arguments.Count == 4)
        {
            var sourceOffset = arguments[2].AsInt32();
            var count = arguments[3].AsInt32();
            if (count < 0)
                return IntrinsicResult.Invalid("Stream.Write source range is invalid.");
            var sourceBytes = new byte[count];
            if (!heap.TryReadBytes(arguments[1], sourceOffset, sourceBytes))
                return IntrinsicResult.Invalid("Stream.Write source range is invalid.");
            return WriteMemoryStream(
                heap, stream, bufferValue, originValue, lengthValue, capacityValue,
                position, isWritable, isExpandable, sourceBytes);
        }
        if (name == "WriteByte" && arguments.Count == 2)
        {
            return WriteMemoryStream(
                heap, stream, bufferValue, originValue, lengthValue, capacityValue,
                position, isWritable, isExpandable,
                [unchecked((byte)arguments[1].AsInt32())]);
        }
        if (name == "CopyTo" && arguments.Count >= 2)
        {
            var available = position >= lengthValue ? 0 : checked(lengthValue - (int)position);
            var bytes = new byte[available];
            if (!heap.TryReadBytes(bufferValue, checked(originValue + (int)position), bytes))
                return IntrinsicResult.Invalid("Stream.CopyTo source range is invalid.");
            heap.TrySetModelValue(stream, "Position", position + available);
            return CopyInto(context, arguments[1], bytes);
        }
        if (name is "Flush" or "FlushFinalBlock")
            return IntrinsicResult.Completed();
        return IntrinsicResult.Invalid($"Unsupported MemoryStream operation {name}.");
    }

    /// <summary>
    /// Writes the drained bytes of a <c>CopyTo</c> into whichever stream the destination models.
    /// </summary>
    private static IntrinsicResult CopyInto(
        IntrinsicContext context,
        StaticValue destination,
        byte[] bytes)
    {
        var heap = context.State.Heap;
        if (!heap.TryAllocateByteArray(bytes, out var source))
            return AllocationFailure("Stream.CopyTo");
        StaticValue[] write =
        [
            destination, source, StaticValue.FromInt32(0), StaticValue.FromInt32(bytes.Length)
        ];
        return heap.TryGetRuntimeTypeName(destination, out var destinationType) &&
            destinationType == "System.Security.Cryptography.CryptoStream"
                ? InvokeCryptoStream(context, "Write", write)
                : InvokeMemoryStream(context, "Write", write);
    }

    private static IntrinsicResult WriteMemoryStream(
        StaticHeap heap,
        StaticValue stream,
        StaticValue buffer,
        int origin,
        int length,
        int capacity,
        long position,
        bool writable,
        bool expandable,
        ReadOnlySpan<byte> bytes)
    {
        if (!writable || position > int.MaxValue - origin - bytes.Length)
            return IntrinsicResult.Invalid("Stream is not writable at the requested position.");
        var required = checked((int)position + bytes.Length);
        if (required > capacity)
        {
            if (!expandable)
                return IntrinsicResult.Invalid("MemoryStream capacity is fixed.");
            var expandedBytes = new byte[required];
            if (!heap.TryReadBytes(buffer, origin, expandedBytes.AsSpan(0, length)) ||
                !heap.TryAllocateByteArray(expandedBytes, out buffer))
                return AllocationFailure("MemoryStream expansion");
            origin = 0;
            capacity = required;
            heap.TrySetModelValue(stream, "Buffer", buffer);
            heap.TrySetModelValue(stream, "Origin", origin);
            heap.TrySetModelValue(stream, "Capacity", capacity);
        }
        if (!heap.TryWriteBytes(buffer, checked(origin + (int)position), bytes))
            return IntrinsicResult.Invalid("MemoryStream backing buffer write failed.");
        heap.TrySetModelValue(stream, "Length", Math.Max(length, required));
        heap.TrySetModelValue(stream, "Position", position + bytes.Length);
        return IntrinsicResult.Completed();
    }

    private static IntrinsicResult InvokeBinaryReader(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (name == ".ctor" && arguments.Count >= 2)
        {
            if (!heap.TryGetModelValue(arguments[1], "Buffer", out StaticValue _))
                return IntrinsicResult.Invalid("BinaryReader requires a modeled stream.");
            heap.TrySetModelValue(arguments[0], "Stream", arguments[1]);
            heap.TrySetModelValue(
                arguments[0],
                "LeaveOpen",
                arguments.Count >= 4 && arguments[^1].AsInt32() != 0);
            return IntrinsicResult.Completed();
        }
        if (name is "Dispose" or "Close")
        {
            if (heap.TryGetModelValue(arguments[0], "Stream", out StaticValue ownedStream) &&
                (!heap.TryGetModelValue(arguments[0], "LeaveOpen", out bool leaveOpen) ||
                 !leaveOpen))
            {
                heap.TrySetModelValue(ownedStream, "Open", false);
            }
            return IntrinsicResult.Completed();
        }
        if (name == "get_BaseStream" &&
            arguments.Count == 1 &&
            heap.TryGetModelValue(arguments[0], "Stream", out StaticValue baseStream))
        {
            return IntrinsicResult.Completed(baseStream);
        }
        if (!heap.TryGetModelValue(arguments[0], "Stream", out StaticValue stream) ||
            !heap.TryGetModelValue(stream, "Buffer", out StaticValue buffer) ||
            !heap.TryGetModelValue(stream, "Position", out long position) ||
            !heap.TryGetModelValue(stream, "Origin", out int bufferOrigin) ||
            !heap.TryGetModelValue(stream, "Length", out int length) ||
            !heap.TryGetModelValue(stream, "Open", out bool open) ||
            !open)
            return IntrinsicResult.Invalid("BinaryReader is not initialized.");
        // Read into a caller's array is the bulk form: it fills what it can and says how much
        // that was, where ReadBytes hands back a fresh array. Loader code uses both.
        if (name == "Read" && arguments.Count == 4)
        {
            var start = arguments[2].AsInt32();
            var wanted = arguments[3].AsInt32();
            if (start < 0 || wanted < 0 ||
                !heap.TryGetLength(arguments[1], out var destination) ||
                start > destination - wanted)
                return IntrinsicResult.Invalid("BinaryReader destination range is invalid.");
            var available = position >= length ? 0 : checked(length - (int)position);
            var read = Math.Min(wanted, available);
            var taken = new byte[read];
            if (!heap.TryReadBytes(buffer, checked(bufferOrigin + (int)position), taken) ||
                !heap.TryWriteBytes(arguments[1], start, taken))
                return IntrinsicResult.Invalid("BinaryReader backing range is invalid.");
            heap.TrySetModelValue(stream, "Position", position + read);
            return IntrinsicResult.Completed(StaticValue.FromInt32(read));
        }

        // A string on the wire is a length written seven bits at a time, then that many bytes of
        // UTF-8. The length has no fixed width, so it cannot be expressed as one of the sizes
        // below and is read out here.
        if (name == "ReadString" && arguments.Count == 1)
        {
            var at = (int)position;
            var count = 0;
            var shift = 0;
            while (true)
            {
                if (shift == 35 || at >= length)
                    return IntrinsicResult.Invalid("BinaryReader string length is malformed.");
                var one = new byte[1];
                if (!heap.TryReadBytes(buffer, checked(bufferOrigin + at), one))
                    return IntrinsicResult.Invalid("BinaryReader backing range is invalid.");
                at++;
                count |= (one[0] & 0x7F) << shift;
                shift += 7;
                if ((one[0] & 0x80) == 0)
                    break;
            }

            if (count < 0 || count > length - at)
                return IntrinsicResult.Invalid("BinaryReader string runs past the end.");
            var encoded = new byte[count];
            if (!heap.TryReadBytes(buffer, checked(bufferOrigin + at), encoded))
                return IntrinsicResult.Invalid("BinaryReader backing range is invalid.");
            heap.TrySetModelValue(stream, "Position", (long)at + count);
            return heap.TryAllocateString(
                System.Text.Encoding.UTF8.GetString(encoded), out var spelled)
                ? IntrinsicResult.Completed(spelled)
                : AllocationFailure("BinaryReader.ReadString");
        }

        var width = name switch
        {
            "Read" when arguments.Count == 1 => 1,
            "ReadBoolean" => 1,
            "ReadByte" or "ReadSByte" => 1,
            "ReadInt16" or "ReadUInt16" => 2,
            "ReadInt32" or "ReadUInt32" or "ReadSingle" => 4,
            "ReadInt64" or "ReadUInt64" or "ReadDouble" => 8,
            "ReadBytes" when arguments.Count == 2 => arguments[1].AsInt32(),
            _ => -1
        };
        if (width < 0)
            return IntrinsicResult.Invalid(
                $"Unsupported or out-of-range BinaryReader operation {name} " +
                $"(position={position}, length={length}, width={width}).");
        if (name == "ReadBytes")
            width = Math.Min(width, position >= length ? 0 : checked(length - (int)position));
        else if (position > length - width)
            return IntrinsicResult.Invalid(
                $"Unsupported or out-of-range BinaryReader operation {name} " +
                $"(position={position}, length={length}, width={width}).");
        var bytes = new byte[width];
        if (!heap.TryReadBytes(buffer, checked(bufferOrigin + (int)position), bytes))
            return IntrinsicResult.Invalid("BinaryReader backing range is invalid.");
        heap.TrySetModelValue(stream, "Position", position + width);
        if (MachineTrace.Enabled)
            MachineTrace.Line(
                $"read {name}@{position} len={length} = {Convert.ToHexString(bytes.AsSpan(0, Math.Min(width, 8)))}");
        if (name == "ReadBytes")
        {
            var origin = context.State.Provenance.Operation(
                StaticValue.FromInt32(width),
                ProvenanceKind.Intrinsic,
                "BinaryReader",
                $"{name}@{position}",
                buffer,
                arguments[0],
                arguments[1]);
            return heap.TryAllocateByteArray(bytes, out var result, origin.ProvenanceId)
                ? IntrinsicResult.Completed(result.WithProvenance(origin.ProvenanceId))
                : AllocationFailure("BinaryReader.ReadBytes");
        }
        var scalar = name switch
        {
            "Read" or "ReadByte" => IntrinsicResult.Completed(StaticValue.FromInt32(bytes[0])),
            "ReadBoolean" => IntrinsicResult.Completed(
                StaticValue.FromInt32(bytes[0] != 0 ? 1 : 0)),
            "ReadSByte" => IntrinsicResult.Completed(StaticValue.FromInt32(unchecked((sbyte)bytes[0]))),
            "ReadInt16" => IntrinsicResult.Completed(StaticValue.FromInt32(
                BinaryPrimitives.ReadInt16LittleEndian(bytes))),
            "ReadUInt16" => IntrinsicResult.Completed(StaticValue.FromInt32(
                BinaryPrimitives.ReadUInt16LittleEndian(bytes))),
            "ReadInt32" or "ReadUInt32" => IntrinsicResult.Completed(StaticValue.FromInt32(
                BinaryPrimitives.ReadInt32LittleEndian(bytes))),
            "ReadInt64" or "ReadUInt64" => IntrinsicResult.Completed(StaticValue.FromInt64(
                BinaryPrimitives.ReadInt64LittleEndian(bytes))),
            "ReadSingle" => IntrinsicResult.Completed(StaticValue.FromFloat32(
                BitConverter.Int32BitsToSingle(BinaryPrimitives.ReadInt32LittleEndian(bytes)))),
            "ReadDouble" => IntrinsicResult.Completed(StaticValue.FromFloat64(
                BitConverter.Int64BitsToDouble(BinaryPrimitives.ReadInt64LittleEndian(bytes)))),
            _ => IntrinsicResult.Invalid($"Unsupported BinaryReader operation {name}.")
        };
        if (scalar.Status != StaticExecutionStatus.Completed)
            return scalar;
        var byteInputs = new List<StaticValue>(width + 1) { arguments[0] };
        for (var index = 0; index < width; index++)
        {
            if (heap.TryReadArray(
                    buffer,
                    checked(bufferOrigin + (int)position) + index,
                    out var byteValue))
                byteInputs.Add(byteValue);
        }
        return IntrinsicResult.Completed(context.State.Provenance.Operation(
            scalar.Value,
            ProvenanceKind.Intrinsic,
            "BinaryReader",
            $"{name}@{position}",
            [.. byteInputs]));
    }

    private static IntrinsicResult InvokeCompression(
        IntrinsicContext context,
        string type,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        // The constructor inflates eagerly and leaves the result modeled as a readable memory
        // stream, so every later operation is the memory-stream one over those bytes.
        if (name != ".ctor")
            return InvokeMemoryStream(context, name, arguments);
        if (arguments.Count < 3)
            return IntrinsicResult.Invalid($"Unsupported compression operation {name}.");
        var heap = context.State.Heap;
        if (!heap.TryGetModelValue(arguments[1], "Buffer", out StaticValue source) ||
            !heap.TryGetModelValue(arguments[1], "Position", out long sourcePosition) ||
            !heap.TryGetModelValue(arguments[1], "Origin", out int sourceOrigin) ||
            !heap.TryGetModelValue(arguments[1], "Length", out int length))
            return IntrinsicResult.Invalid("Compression stream source is not modeled.");
        if (sourcePosition < 0 || sourcePosition > length)
            return IntrinsicResult.Invalid("Compression stream position is invalid.");
        var compressed = new byte[length - checked((int)sourcePosition)];
        if (!heap.TryReadBytes(
                source,
                checked(sourceOrigin + (int)sourcePosition),
                compressed))
            return IntrinsicResult.Invalid("Compression source is invalid.");
        try
        {
            using var input = new MemoryStream(compressed, writable: false);
            using Stream inflater = type.EndsWith("GZipStream", StringComparison.Ordinal)
                ? new GZipStream(input, CompressionMode.Decompress)
                : new DeflateStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();
            var chunk = new byte[8192];
            while (true)
            {
                var read = inflater.Read(chunk, 0, chunk.Length);
                if (read == 0)
                    break;
                if (output.Length > heap.MaximumObjectLength - read)
                    return AllocationFailure(type);
                output.Write(chunk, 0, read);
            }
            var outputBytes = output.ToArray();
            if (!heap.TryAllocateByteArray(outputBytes, out var buffer))
                return AllocationFailure(type);
            heap.TrySetModelValue(arguments[0], "Buffer", buffer);
            heap.TrySetModelValue(arguments[0], "Position", 0L);
            heap.TrySetModelValue(arguments[0], "Origin", 0);
            heap.TrySetModelValue(arguments[0], "Length", outputBytes.Length);
            heap.TrySetModelValue(arguments[0], "Capacity", outputBytes.Length);
            heap.TrySetModelValue(arguments[0], "Writable", false);
            heap.TrySetModelValue(arguments[0], "Expandable", false);
            heap.TrySetModelValue(arguments[0], "PubliclyVisible", false);
            heap.TrySetModelValue(arguments[0], "Open", true);
            return IntrinsicResult.Completed();
        }
        catch (InvalidDataException)
        {
            return IntrinsicResult.Invalid("Compressed data is invalid.");
        }
    }

#pragma warning disable CA5350, CA5351
    private static IntrinsicResult InvokeHash(
        IntrinsicContext context,
        string type,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (name == "Create")
        {
            if (!heap.TryAllocateObject(type, out var hash))
                return AllocationFailure(type);
            return IntrinsicResult.Completed(hash);
        }
        if (name is ".ctor" or "Initialize" or "Clear" or "Dispose")
            return IntrinsicResult.Completed();
        if (name is "get_Hash" or "TransformBlock" or "TransformFinalBlock")
            return InvokeHashAlgorithm(context, name, arguments);
        if (name != "ComputeHash" || arguments.Count != 2 ||
            !heap.TryGetLength(arguments[1], out var length) ||
            !heap.TryGetArrayElementType(arguments[1], out var elementType) ||
            elementType != "System.Byte")
            return IntrinsicResult.Invalid($"Unsupported hash operation {name}.");
        var bytes = new byte[length];
        if (!heap.TryReadBytes(arguments[1], 0, bytes))
            return IntrinsicResult.Invalid("Hash input bytes are unavailable.");
        var digest = type switch
        {
            "System.Security.Cryptography.SHA1" => SHA1.HashData(bytes),
            "System.Security.Cryptography.MD5" => MD5.HashData(bytes),
            _ => SHA256.HashData(bytes)
        };
        if (!heap.TryAllocateByteArray(digest, out var result))
            return AllocationFailure("hash result");
        heap.TrySetModelValue(arguments[0], "Hash", result);
        return IntrinsicResult.Completed(result);
    }
#pragma warning restore CA5350, CA5351

    /// <summary>Models a filesystem holding exactly the analysed assembly. Reactor probes its
    /// own location before reading the protected image; any other path is reported absent.</summary>
    private static IntrinsicResult InvokeFile(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var state = context.State;
        if (arguments.Count != 1 || !state.Heap.TryGetString(arguments[0], out var path))
            return IntrinsicResult.Invalid($"Unsupported file operation {name}.");
        var isModule = state.ModulePath.Length != 0 &&
            string.Equals(path, state.ModulePath, StringComparison.OrdinalIgnoreCase);
        if (name == "Exists")
        {
            if (isModule)
                state.Observe(LoaderObservationKind.ModuleFileRead, "File.Exists on the module path");
            return IntrinsicResult.Completed(StaticValue.FromInt32(isModule ? 1 : 0));
        }
        if (name == "ReadAllBytes")
        {
            if (!isModule)
                return IntrinsicResult.Invalid($"File '{path}' is outside the analysed image.");
            state.Observe(
                LoaderObservationKind.ModuleFileRead,
                $"File.ReadAllBytes of {state.ModuleFileBytes.Length} module byte(s)");
            return state.Heap.TryAllocateByteArray(state.ModuleFileBytes, out var bytes)
                ? IntrinsicResult.Completed(bytes)
                : AllocationFailure("module file bytes");
        }
        return IntrinsicResult.Invalid($"Unsupported file operation {name}.");
    }

    /// <summary>Models the Reactor tamper check. The signature is verified for real against
    /// the concrete key and digest so the outcome is proven rather than assumed.</summary>
    private static IntrinsicResult InvokeAsymmetric(
        IntrinsicContext context,
        string type,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (type == "System.Security.Cryptography.CryptoConfig")
        {
            // Reactor picks its algorithm providers from the FIPS policy of the host. The
            // machine models a default host, where the policy is not enforced.
            if (name == "get_AllowOnlyFipsAlgorithms")
                return IntrinsicResult.Completed(StaticValue.FromInt32(0));
            if (name != "MapNameToOID" || arguments.Count != 1 ||
                !heap.TryGetString(arguments[0], out var algorithmName))
                return IntrinsicResult.Invalid($"Unsupported CryptoConfig operation {name}.");
            var oid = MapNameToOid(algorithmName);
            return oid is null
                ? IntrinsicResult.Invalid($"Unmapped hash algorithm '{algorithmName}'.")
                : heap.TryAllocateString(oid, out var mapped)
                    ? IntrinsicResult.Completed(mapped)
                    : AllocationFailure("algorithm oid");
        }
        if (name == ".ctor")
            return IntrinsicResult.Completed();
        if (name is "set_UseMachineKeyStore" or "set_PersistKeyInCsp" or "Clear" or "Dispose")
            return IntrinsicResult.Completed();
        if (name == "FromXmlString" && arguments.Count == 2)
        {
            if (!heap.TryGetString(arguments[1], out var keyXml))
                return IntrinsicResult.Invalid("RSA key material is not concrete.");
            heap.TrySetModelValue(arguments[0], "KeyXml", keyXml);
            return IntrinsicResult.Completed();
        }
        if (name is "VerifyHash" or "VerifyData" && arguments.Count == 4)
        {
            if (!heap.TryGetModelValue(arguments[0], "KeyXml", out string? keyXml) ||
                string.IsNullOrEmpty(keyXml))
                return IntrinsicResult.Invalid("RSA key material was never imported.");
            if (!TryReadByteArray(heap, arguments[1], out var digest) ||
                !TryReadByteArray(heap, arguments[3], out var signature) ||
                !heap.TryGetString(arguments[2], out var algorithm))
                return IntrinsicResult.Invalid("RSA verification inputs are not concrete.");
            if (ResolveHashAlgorithmName(algorithm) is not { } hashName)
                return IntrinsicResult.Invalid($"Unmapped signature algorithm '{algorithm}'.");
            bool verified;
            try
            {
                using var rsa = System.Security.Cryptography.RSA.Create();
                rsa.FromXmlString(keyXml);
                verified = name == "VerifyHash"
                    ? rsa.VerifyHash(digest, signature, hashName, RSASignaturePadding.Pkcs1)
                    : rsa.VerifyData(digest, signature, hashName, RSASignaturePadding.Pkcs1);
            }
            catch (CryptographicException exception)
            {
                return IntrinsicResult.Invalid($"RSA verification failed: {exception.Message}");
            }
            context.State.Observe(
                LoaderObservationKind.SignatureVerification,
                $"{type}::{name} over a {digest.Length}-byte digest with a " +
                $"{signature.Length}-byte signature",
                verified);
            return IntrinsicResult.Completed(StaticValue.FromInt32(verified ? 1 : 0));
        }
        return IntrinsicResult.Invalid($"Unsupported asymmetric operation {type}::{name}.");
    }

    private static string? MapNameToOid(string algorithmName) => algorithmName switch
    {
        "SHA1" or "System.Security.Cryptography.SHA1" => "1.3.14.3.2.26",
        "SHA256" or "System.Security.Cryptography.SHA256" => "2.16.840.1.101.3.4.2.1",
        "SHA384" => "2.16.840.1.101.3.4.2.2",
        "SHA512" => "2.16.840.1.101.3.4.2.3",
        "MD5" or "System.Security.Cryptography.MD5" => "1.2.840.113549.2.5",
        _ => null
    };

#pragma warning disable CA5350, CA5351
    private static HashAlgorithmName? ResolveHashAlgorithmName(string algorithm) => algorithm switch
    {
        "1.3.14.3.2.26" or "SHA1" => HashAlgorithmName.SHA1,
        "2.16.840.1.101.3.4.2.1" or "SHA256" => HashAlgorithmName.SHA256,
        "2.16.840.1.101.3.4.2.2" or "SHA384" => HashAlgorithmName.SHA384,
        "2.16.840.1.101.3.4.2.3" or "SHA512" => HashAlgorithmName.SHA512,
        "1.2.840.113549.2.5" or "MD5" => HashAlgorithmName.MD5,
        _ => null
    };
#pragma warning restore CA5350, CA5351

    private static IntrinsicResult InvokeHashAlgorithm(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (arguments.Count == 0)
            return IntrinsicResult.Invalid($"Unsupported hash algorithm operation {name}.");
        var receiver = arguments[0];
        switch (name)
        {
            case "get_Hash"
                when heap.TryGetModelValue(receiver, "Hash", out StaticValue digest):
                return IntrinsicResult.Completed(digest);
            case "TransformBlock" when arguments.Count == 6:
            {
                if (!TryReadHashSegment(heap, arguments, out var chunk, out var failure))
                    return failure;
                PendingHashBytes(heap, receiver).AddRange(chunk);
                if (arguments[4].Kind == StaticValueKind.HeapReference &&
                    !heap.TryWriteBytes(arguments[4], arguments[5].AsInt32(), chunk))
                    return IntrinsicResult.Invalid("Hash block destination is unavailable.");
                return IntrinsicResult.Completed(StaticValue.FromInt32(chunk.Length));
            }
            case "TransformFinalBlock" when arguments.Count == 4:
            {
                if (!TryReadHashSegment(heap, arguments, out var chunk, out var failure))
                    return failure;
                var pending = PendingHashBytes(heap, receiver);
                pending.AddRange(chunk);
                if (ComputeDigest(heap, receiver, [.. pending]) is not { } digestBytes)
                    return IntrinsicResult.Invalid("Hash algorithm is unknown.");
                pending.Clear();
                if (!heap.TryAllocateByteArray(digestBytes, out var digestValue))
                    return AllocationFailure("hash result");
                heap.TrySetModelValue(receiver, "Hash", digestValue);
                return heap.TryAllocateByteArray(chunk, out var tail)
                    ? IntrinsicResult.Completed(tail)
                    : AllocationFailure("hash tail");
            }
            default:
                return IntrinsicResult.Invalid($"Unsupported hash algorithm operation {name}.");
        }
    }

    private static bool TryReadHashSegment(
        StaticHeap heap,
        IReadOnlyList<StaticValue> arguments,
        out byte[] chunk,
        out IntrinsicResult failure)
    {
        chunk = [];
        var offset = arguments[2].AsInt32();
        var count = arguments[3].AsInt32();
        if (offset < 0 || count < 0)
        {
            failure = IntrinsicResult.Invalid("Hash block range is invalid.");
            return false;
        }
        var buffer = new byte[count];
        if (!heap.TryReadBytes(arguments[1], offset, buffer))
        {
            failure = IntrinsicResult.Invalid("Hash block source is unavailable.");
            return false;
        }
        chunk = buffer;
        failure = IntrinsicResult.Completed();
        return true;
    }

    private static List<byte> PendingHashBytes(StaticHeap heap, StaticValue receiver)
    {
        if (heap.TryGetModelValue(receiver, "Pending", out List<byte>? pending) &&
            pending is not null)
            return pending;
        var created = new List<byte>();
        heap.TrySetModelValue(receiver, "Pending", created);
        return created;
    }

#pragma warning disable CA5350, CA5351
    private static byte[]? ComputeDigest(StaticHeap heap, StaticValue receiver, byte[] data) =>
        heap.TryGetRuntimeTypeName(receiver, out var typeName)
            ? Canonicalize(typeName) switch
            {
                "System.Security.Cryptography.SHA1" => SHA1.HashData(data),
                "System.Security.Cryptography.MD5" => MD5.HashData(data),
                "System.Security.Cryptography.SHA256" => SHA256.HashData(data),
                _ => null
            }
            : null;
#pragma warning restore CA5350, CA5351

    private static bool TryReadByteArray(StaticHeap heap, StaticValue reference, out byte[] bytes)
    {
        bytes = [];
        if (!heap.TryGetLength(reference, out var length) ||
            !heap.TryGetArrayElementType(reference, out var elementType) ||
            elementType != "System.Byte")
            return false;
        var buffer = new byte[length];
        if (!heap.TryReadBytes(reference, 0, buffer))
            return false;
        bytes = buffer;
        return true;
    }

    private static IntrinsicResult InvokeCrypto(
        IntrinsicContext context,
        string type,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (name is "Create" or ".ctor")
        {
            if (name == ".ctor")
                return IntrinsicResult.Completed();
            if (!heap.TryAllocateObject(type, out var algorithm))
                return AllocationFailure(type);
            return IntrinsicResult.Completed(algorithm);
        }
        if (name is "set_Key" or "set_IV" && arguments.Count == 2)
        {
            heap.TrySetModelValue(arguments[0], name[4..], arguments[1]);
            return IntrinsicResult.Completed();
        }
        if (name is "set_Mode" or "set_Padding" && arguments.Count == 2)
        {
            heap.TrySetModelValue(arguments[0], name[4..], arguments[1].AsInt32());
            return IntrinsicResult.Completed();
        }
        if (name is "CreateDecryptor" or "CreateEncryptor")
        {
            var owner = arguments[0];
            if (arguments.Count == 3)
            {
                heap.TrySetModelValue(owner, "Key", arguments[1]);
                heap.TrySetModelValue(owner, "IV", arguments[2]);
            }
            if (!heap.TryAllocateObject("System.Security.Cryptography.ICryptoTransform", out var transform))
                return AllocationFailure("crypto transform");
            heap.TrySetModelValue(transform, "Algorithm", owner);
            heap.TrySetModelValue(transform, "Decrypt", name == "CreateDecryptor");
            return IntrinsicResult.Completed(transform);
        }
        if (name == "TransformFinalBlock" && arguments.Count == 4)
            return TransformFinalBlock(context, arguments);
        if (name is "Dispose" or "Clear")
            return IntrinsicResult.Completed();
        return IntrinsicResult.Invalid($"Unsupported cryptography operation {name}.");
    }

    private static IntrinsicResult TransformFinalBlock(
        IntrinsicContext context,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        var offset = arguments[2].AsInt32();
        var count = arguments[3].AsInt32();
        var input = new byte[count < 0 ? 0 : count];
        if (count < 0 || !heap.TryReadBytes(arguments[1], offset, input))
            return IntrinsicResult.Invalid("Crypto transform range is invalid.");
        if (!TryTransformBytes(heap, arguments[0], input, out var output, out var error))
            return IntrinsicResult.Invalid(error);
        return heap.TryAllocateByteArray(output, out var result)
            ? IntrinsicResult.Completed(result)
            : AllocationFailure("crypto output");
    }

    /// <summary>Builds the cipher the program asked for by name.</summary>
#pragma warning disable CA5350, CA5351
    private static SymmetricAlgorithm? Cipher(string? named) => named switch
    {
        "System.Security.Cryptography.TripleDES" => TripleDES.Create(),
        "System.Security.Cryptography.DES" => DES.Create(),
        "System.Security.Cryptography.Aes" or
        "System.Security.Cryptography.Rijndael" or
        "System.Security.Cryptography.RijndaelManaged" or
        null => Aes.Create(),
        _ => null
    };
#pragma warning restore CA5350, CA5351

    private static bool TryTransformBytes(
        StaticHeap heap,
        StaticValue transform,
        byte[] input,
        out byte[] output,
        out string error)
    {
        output = [];
        if (!heap.TryGetModelValue(transform, "Algorithm", out StaticValue algorithm) ||
            !heap.TryGetModelValue(transform, "Decrypt", out bool decrypt) ||
            !heap.TryGetModelValue(algorithm, "Key", out StaticValue keyReference) ||
            !heap.TryGetModelValue(algorithm, "IV", out StaticValue ivReference) ||
            !heap.TryGetLength(keyReference, out var keyLength) ||
            !heap.TryGetLength(ivReference, out var ivLength))
        {
            error = "Crypto transform is not fully configured.";
            return false;
        }
        var key = new byte[keyLength];
        var iv = new byte[ivLength];
        if (!heap.TryReadBytes(keyReference, 0, key) || !heap.TryReadBytes(ivReference, 0, iv))
        {
            error = "Crypto transform key material is unavailable.";
            return false;
        }
        heap.TryGetRuntimeTypeName(algorithm, out var named);
        try
        {
            // Which cipher runs has to follow the object the program built. Reading the key and
            // then decrypting with the wrong algorithm would produce bytes rather than an error,
            // and bytes that are wrong are worse than a refusal.
            using var cipher = Cipher(named);
            if (cipher is null)
            {
                error = $"Cipher {named} is not modeled.";
                return false;
            }

            var aes = cipher;
            aes.Key = key;
            aes.IV = iv;
            if (heap.TryGetModelValue(algorithm, "Mode", out int mode))
                aes.Mode = (CipherMode)mode;
            if (heap.TryGetModelValue(algorithm, "Padding", out int padding))
                aes.Padding = (PaddingMode)padding;
            using var cryptoTransform = decrypt ? aes.CreateDecryptor() : aes.CreateEncryptor();
            output = cryptoTransform.TransformFinalBlock(input, 0, input.Length);
            error = string.Empty;
            return true;
        }
        catch (CryptographicException exception)
        {
            error = $"Crypto parameters or input are invalid: {exception.Message}";
            return false;
        }
    }

    private static IntrinsicResult InvokeMath(string name, IReadOnlyList<StaticValue> arguments)
    {
        if (arguments.Count == 2 && arguments.All(value => value.IsInteger))
        {
            var wide = arguments.Any(value => value.Kind == StaticValueKind.Int64);
            var left = arguments[0].AsInt64();
            var right = arguments[1].AsInt64();
            long? value = name switch
            {
                "Min" => Math.Min(left, right),
                "Max" => Math.Max(left, right),
                _ => null
            };
            if (value is { } result)
            {
                return IntrinsicResult.Completed(wide
                    ? StaticValue.FromInt64(result)
                    : StaticValue.FromInt32(unchecked((int)result)));
            }
        }
        if (arguments.Count == 2 && arguments.All(value => value.IsFloatingPoint))
        {
            double? value = name switch
            {
                "Min" => Math.Min(arguments[0].AsFloat64(), arguments[1].AsFloat64()),
                "Max" => Math.Max(arguments[0].AsFloat64(), arguments[1].AsFloat64()),
                "Pow" => Math.Pow(arguments[0].AsFloat64(), arguments[1].AsFloat64()),
                _ => null
            };
            if (value is { } result)
                return IntrinsicResult.Completed(StaticValue.FromFloat64(result));
        }
        if (arguments.Count == 1 && name == "Abs")
        {
            if (arguments[0].Kind == StaticValueKind.Int64)
                return IntrinsicResult.Completed(
                    StaticValue.FromInt64(Math.Abs(arguments[0].AsInt64())));
            if (arguments[0].IsInteger)
                return IntrinsicResult.Completed(
                    StaticValue.FromInt32(Math.Abs(arguments[0].AsInt32())));
            if (arguments[0].IsFloatingPoint)
                return IntrinsicResult.Completed(
                    StaticValue.FromFloat64(Math.Abs(arguments[0].AsFloat64())));
        }
        return IntrinsicResult.Invalid($"Unsupported math operation {name}.");
    }

    /// <summary>Opens the analysed assembly as a read-only stream. Reactor reads its own image
    /// back from disk to hash it, so the stream is backed by the original file bytes.</summary>
    private static IntrinsicResult OpenModuleFileStream(
        IntrinsicContext context,
        IReadOnlyList<StaticValue> arguments)
    {
        var state = context.State;
        var heap = state.Heap;
        if (arguments.Count < 2 || !heap.TryGetString(arguments[1], out var path))
            return IntrinsicResult.Invalid("FileStream path is not concrete.");
        if (state.ModulePath.Length == 0 ||
            !string.Equals(path, state.ModulePath, StringComparison.OrdinalIgnoreCase))
            return IntrinsicResult.Invalid($"File '{path}' is outside the analysed image.");
        if (!heap.TryAllocateByteArray(state.ModuleFileBytes, out var buffer))
            return AllocationFailure("module file stream");
        state.Observe(
            LoaderObservationKind.ModuleFileRead,
            $"FileStream over {state.ModuleFileBytes.Length} module byte(s)");
        var stream = arguments[0];
        heap.TrySetModelValue(stream, "Buffer", buffer);
        heap.TrySetModelValue(stream, "Position", 0L);
        heap.TrySetModelValue(stream, "Origin", 0);
        heap.TrySetModelValue(stream, "Length", state.ModuleFileBytes.Length);
        heap.TrySetModelValue(stream, "Capacity", state.ModuleFileBytes.Length);
        heap.TrySetModelValue(stream, "Writable", false);
        heap.TrySetModelValue(stream, "Expandable", false);
        heap.TrySetModelValue(stream, "PubliclyVisible", true);
        heap.TrySetModelValue(stream, "Open", true);
        return IntrinsicResult.Completed();
    }

    /// <summary>Models a write-mode <c>CryptoStream</c>. Reactor pipes its encrypted key
    /// material through one, so the buffered plaintext must reach the backing stream.</summary>
    private static IntrinsicResult InvokeCryptoStream(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (name == ".ctor")
        {
            if (arguments.Count is not (4 or 5))
                return IntrinsicResult.Invalid("Unsupported CryptoStream constructor.");
            heap.TrySetModelValue(arguments[0], "Target", arguments[1]);
            heap.TrySetModelValue(arguments[0], "Transform", arguments[2]);
            heap.TrySetModelValue(arguments[0], "Pending", new List<byte>());
            heap.TrySetModelValue(arguments[0], "Flushed", false);
            heap.TrySetModelValue(arguments[0], "Reading", arguments[3].AsInt32() == 0);
            return IntrinsicResult.Completed();
        }
        if (arguments.Count == 0 ||
            !heap.TryGetModelValue(arguments[0], "Pending", out List<byte>? pending) ||
            pending is null)
            return IntrinsicResult.Invalid("CryptoStream is not initialized.");
        heap.TryGetModelValue(arguments[0], "Reading", out bool reading);
        switch (name)
        {
            case "get_CanWrite":
                return IntrinsicResult.Completed(StaticValue.FromInt32(reading ? 0 : 1));
            case "get_CanRead":
                return IntrinsicResult.Completed(StaticValue.FromInt32(reading ? 1 : 0));
            case "get_CanSeek":
                return IntrinsicResult.Completed(StaticValue.FromInt32(0));
            case "Flush":
                return IntrinsicResult.Completed();
            case "Read" when reading && arguments.Count == 4:
            case "ReadByte" when reading && arguments.Count == 1:
                return ReadCryptoStream(context, name, arguments);
            case "WriteByte" when arguments.Count == 2:
                pending.Add(unchecked((byte)arguments[1].AsInt32()));
                return IntrinsicResult.Completed();
            case "Write" when arguments.Count == 4:
            {
                var offset = arguments[2].AsInt32();
                var count = arguments[3].AsInt32();
                if (offset < 0 || count < 0)
                    return IntrinsicResult.Invalid("CryptoStream write range is invalid.");
                var chunk = new byte[count];
                if (!heap.TryReadBytes(arguments[1], offset, chunk))
                    return IntrinsicResult.Invalid("CryptoStream write source is unavailable.");
                pending.AddRange(chunk);
                return IntrinsicResult.Completed();
            }
            case "FlushFinalBlock":
            case "Close":
            case "Dispose":
                return FlushCryptoStream(
                    context,
                    arguments[0],
                    pending,
                    name == "FlushFinalBlock");
            default:
                return IntrinsicResult.Invalid($"Unsupported CryptoStream operation {name}.");
        }
    }

    /// <summary>
    /// Serves a read-mode <c>CryptoStream</c> out of the plaintext of everything behind it.
    /// </summary>
    /// <remarks>
    /// A read-mode stream is the mirror of the write-mode one above: the program pulls plaintext
    /// through it instead of pushing it. The whole of what remains in the stream underneath is
    /// transformed at the first read rather than block by block, which for a block cipher over a
    /// buffer already in memory produces the same bytes and avoids modeling the padding rules of a
    /// partially consumed final block.
    /// </remarks>
    private static IntrinsicResult ReadCryptoStream(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        var stream = arguments[0];
        if (!heap.TryGetModelValue(stream, "Plain", out byte[]? plain) || plain is null)
        {
            if (!heap.TryGetModelValue(stream, "Target", out StaticValue target) ||
                !heap.TryGetModelValue(stream, "Transform", out StaticValue transform) ||
                !heap.TryGetModelValue(target, "Buffer", out StaticValue buffer) ||
                !heap.TryGetModelValue(target, "Position", out long at) ||
                !heap.TryGetModelValue(target, "Origin", out int origin) ||
                !heap.TryGetModelValue(target, "Length", out int length))
            {
                return IntrinsicResult.Invalid("CryptoStream has no modeled stream behind it.");
            }

            var remaining = at >= length ? 0 : checked(length - (int)at);
            var cipher = new byte[remaining];
            if (!heap.TryReadBytes(buffer, checked(origin + (int)at), cipher))
                return IntrinsicResult.Invalid("CryptoStream source range is invalid.");
            if (!TryTransformBytes(heap, transform, cipher, out plain, out var error))
                return IntrinsicResult.Invalid(error);
            heap.TrySetModelValue(target, "Position", (long)length);
            heap.TrySetModelValue(stream, "Plain", plain);
            heap.TrySetModelValue(stream, "PlainPosition", 0);
        }

        heap.TryGetModelValue(stream, "PlainPosition", out int position);
        if (name == "ReadByte")
        {
            if (position >= plain.Length)
                return IntrinsicResult.Completed(StaticValue.FromInt32(-1));
            heap.TrySetModelValue(stream, "PlainPosition", position + 1);
            return IntrinsicResult.Completed(StaticValue.FromInt32(plain[position]));
        }

        var offset = arguments[2].AsInt32();
        var wanted = arguments[3].AsInt32();
        if (offset < 0 || wanted < 0 ||
            !heap.TryGetLength(arguments[1], out var destination) ||
            offset > destination - wanted)
        {
            return IntrinsicResult.Invalid("CryptoStream read range is invalid.");
        }

        var served = Math.Min(wanted, plain.Length - position);
        if (served <= 0)
            return IntrinsicResult.Completed(StaticValue.FromInt32(0));
        if (!heap.TryWriteBytes(arguments[1], offset, plain.AsSpan(position, served)))
            return IntrinsicResult.Invalid("CryptoStream destination is unavailable.");
        heap.TrySetModelValue(stream, "PlainPosition", position + served);
        return IntrinsicResult.Completed(StaticValue.FromInt32(served));
    }

    private static IntrinsicResult FlushCryptoStream(
        IntrinsicContext context,
        StaticValue stream,
        List<byte> pending,
        bool required)
    {
        var heap = context.State.Heap;
        if (heap.TryGetModelValue(stream, "Flushed", out bool flushed) && flushed)
            return IntrinsicResult.Completed();
        if (!heap.TryGetModelValue(stream, "Transform", out StaticValue transform) ||
            !heap.TryGetModelValue(stream, "Target", out StaticValue target))
            return IntrinsicResult.Invalid("CryptoStream is not initialized.");
        if (!TryTransformBytes(heap, transform, [.. pending], out var output, out var error))
            return required ? IntrinsicResult.Invalid(error) : IntrinsicResult.Completed();
        heap.TrySetModelValue(stream, "Flushed", true);
        if (output.Length == 0)
            return IntrinsicResult.Completed();
        if (!heap.TryAllocateByteArray(output, out var buffer))
            return AllocationFailure("crypto stream output");
        return InvokeMemoryStream(
            context,
            "Write",
            [target, buffer, StaticValue.FromInt32(0), StaticValue.FromInt32(output.Length)]);
    }

    private static IntrinsicResult InvokeAssembly(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        if (name is "GetExecutingAssembly" or "GetCallingAssembly")
        {
            if (!context.State.Heap.TryAllocateObject("System.Reflection.Assembly", out var assembly))
                return AllocationFailure("assembly model");
            context.State.Heap.TrySetModelValue(assembly, HomeModuleMark, true);
            return IntrinsicResult.Completed(assembly);
        }
        // Loading an assembly from a byte array is where a packer stops being a packer: whatever it
        // decrypted, decompressed, or reassembled, this is the call in which it names the result as
        // the thing to run. The bytes are taken and the load is not performed, and the caller gets a
        // model assembly so that interpretation can carry on to whatever the loader does next.
        if (name == "Load" && arguments.Count == 1 &&
            context.State.Heap.GetBytesSnapshot(arguments[0]) is { Length: > 0 } image)
        {
            context.State.CaptureAssemblyLoad(image);
            if (!context.State.Heap.TryAllocateObject("System.Reflection.Assembly", out var loaded))
                return AllocationFailure("loaded assembly model");
            // A loader that decrypts an assembly often goes on to read something out of it rather
            // than only running it, so the model remembers which bytes it stands for.
            context.State.Heap.TrySetModelValue(loaded, LoadedImage, image);
            return IntrinsicResult.Completed(loaded);
        }
        if (name == "get_Location" && arguments.Count == 1)
            return context.State.Heap.TryAllocateString(
                context.State.ModulePath.Length != 0
                    ? context.State.ModulePath
                    : context.State.AssemblyName + ".dll",
                out var location)
                ? IntrinsicResult.Completed(location)
                : AllocationFailure("assembly location");
        if (name == "GetManifestResourceNames" && arguments.Count == 1)
        {
            var carried = context.State.Heap.TryGetModelValue(arguments[0], LoadedImage, out byte[]? held)
                && held is not null
                    ? ImageResourceNames(held)
                    : [.. context.State.Resources.Keys];
            if (!context.State.Heap.TryAllocateArray(
                    context.State.ModuleMetadata?.CorLibTypes.String,
                    carried.Count,
                    out var names))
                return AllocationFailure("resource name array");
            for (var index = 0; index < carried.Count; index++)
            {
                if (!context.State.Heap.TryAllocateString(carried[index], out var spelled) ||
                    !context.State.Heap.TryWriteArray(names, index, spelled))
                    return AllocationFailure("resource name");
            }

            return IntrinsicResult.Completed(names);
        }
        if (name == "GetManifestResourceStream" && arguments.Count == 2 &&
            context.State.Heap.TryGetString(arguments[1], out var resourceName))
        {
            if (TryReadResource(context, arguments[0], resourceName) is not { } contents)
            {
                return IntrinsicResult.Invalid($"Resource '{resourceName}' is not registered.");
            }

            context.State.RegisterResource(resourceName, contents);
            return context.State.TryOpenResource(resourceName, out var stream)
                ? IntrinsicResult.Completed(stream)
                : AllocationFailure("resource stream");
        }
        if (name == "GetName" && arguments.Count is 1 or 2)
            return context.State.Heap.TryAllocateObject(
                "System.Reflection.AssemblyName",
                out var assemblyName)
                ? IntrinsicResult.Completed(assemblyName)
                : AllocationFailure("assembly name model");
        if (name == "GetModules" && arguments.Count is 1 or 2)
        {
            var heap = context.State.Heap;
            if (!heap.TryAllocateObject("System.Reflection.Module", out var assemblyModule) ||
                !heap.TryAllocateArray(null, 1, out var modules) ||
                !heap.TryWriteArray(modules, 0, assemblyModule))
            {
                return AllocationFailure("module model");
            }
            if (heap.TryGetModelValue<bool>(arguments[0], HomeModuleMark, out var home) && home)
                heap.TrySetModelValue(assemblyModule, HomeModuleMark, true);
            return IntrinsicResult.Completed(modules);
        }
        // Two models of the assembly under analysis are the same assembly however they were reached.
        // Protected code compares them to check it is running where it was built to run, and a
        // comparison by object identity would tell it that it is not.
        if (name is "op_Equality" or "op_Inequality" && arguments.Count == 2)
        {
            var heap = context.State.Heap;
            var equal = arguments[0].Equals(arguments[1]) ||
                (heap.TryGetModelValue<bool>(arguments[0], HomeModuleMark, out var left) && left &&
                    heap.TryGetModelValue<bool>(arguments[1], HomeModuleMark, out var right) &&
                    right);
            return IntrinsicResult.Completed(StaticValue.FromInt32(
                (name == "op_Equality" ? equal : !equal) ? 1 : 0));
        }

        // Only the assembly under analysis has an entry point the machine can point at. For any
        // other assembly there is no metadata here to describe, and saying so is better than
        // handing back a null the caller would read as "this assembly has none".
        if (name == "get_EntryPoint" && arguments.Count == 1)
        {
            var heap = context.State.Heap;
            if (!heap.TryGetModelValue<bool>(arguments[0], HomeModuleMark, out var home) || !home)
                return IntrinsicResult.Invalid("The entry point of another assembly is unknown.");
            if (context.State.ModuleMetadata?.EntryPoint is not { } entry)
                return IntrinsicResult.Completed(StaticValue.Null);
            var described = Describing(heap, "System.Reflection.MethodInfo", entry);
            if (described.Status == StaticExecutionStatus.Completed)
                heap.TrySetModelValue(described.Value, HomeModuleMark, true);
            return described;
        }

        return IntrinsicResult.Invalid($"Assembly operation {name} is denied.");
    }

    private static IntrinsicResult InvokeAssemblyName(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;

        // A name built from a string is a name of some other assembly, most often one the loader
        // has just read out of its own table of what it carries. It is a parsed string and nothing
        // more, so it is modeled as the string it was given.
        if (name == ".ctor" && arguments.Count == 2 &&
            heap.TryGetString(arguments[1], out var spelled))
        {
            heap.TrySetModelValue(arguments[0], "FullName", spelled);
            var comma = spelled.IndexOf(',', StringComparison.Ordinal);
            heap.TrySetModelValue(
                arguments[0],
                "Name",
                comma < 0 ? spelled : spelled[..comma].Trim());
            return IntrinsicResult.Completed();
        }
        if (arguments.Count == 1 &&
            name is "get_Name" or "get_FullName" or "ToString" &&
            heap.TryGetModelValue(
                arguments[0],
                name == "get_Name" ? "Name" : "FullName",
                out string? carried) &&
            carried is not null)
        {
            return heap.TryAllocateString(carried, out var value)
                ? IntrinsicResult.Completed(value)
                : AllocationFailure("assembly name");
        }
        if (arguments.Count != 1)
            return IntrinsicResult.Invalid($"AssemblyName operation {name} is denied.");
        if (name == "GetPublicKeyToken")
        {
            context.State.Observe(
                LoaderObservationKind.StrongNameProbe,
                $"AssemblyName.GetPublicKeyToken of {context.State.PublicKeyToken.Length} byte(s)");
            return context.State.Heap.TryAllocateByteArray(
                context.State.PublicKeyToken,
                out var token)
                ? IntrinsicResult.Completed(token)
                : AllocationFailure("public key token");
        }
        if (name == "get_Name")
            return context.State.Heap.TryAllocateString(context.State.AssemblyName, out var value)
                ? IntrinsicResult.Completed(value)
                : AllocationFailure("assembly name");
        return IntrinsicResult.Invalid($"AssemblyName operation {name} is denied.");
    }

    private static IntrinsicResult InvokeModule(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        // Reactor asks whether the module it cached is the one it is running in, and the answer it
        // wants is reference identity, which the models already carry. Comparing them is modeling
        // the operator rather than assuming a verdict: two models are equal when they are the same
        // model, and a null compares equal only to another null, exactly as the runtime would say.
        if (name is "op_Equality" or "op_Inequality" && arguments.Count == 2)
        {
            var equal = arguments[0].Equals(arguments[1]);
            return IntrinsicResult.Completed(StaticValue.FromInt32(
                (name == "op_Equality" ? equal : !equal) ? 1 : 0));
        }
        // Resolving a token against the module's own metadata is a lookup in a table the file
        // already contains, so the answer is read off rather than guessed. A runtime that reaches
        // its members by token instead of by reference — which is how Reactor's proxies and how
        // several packers work — is only interpretable if this is modeled.
        if (name is "ResolveMethod" or "ResolveType" or "ResolveField" or "ResolveMember" &&
            arguments.Count >= 2 &&
            context.State.ModuleMetadata is { } moduleMetadata &&
            arguments[1].Kind == StaticValueKind.Int32)
        {
            var token = arguments[1].AsInt32();
            var member = moduleMetadata.ResolveToken((uint)token);
            if (member is null)
                return IntrinsicResult.Invalid($"Token 0x{token:X8} is not in this module.");
            // A token can name something defined here or something merely referred to from here,
            // and both are ordinary answers. Refusing references would leave the machine unable to
            // follow any code that reaches outside its own module, which obfuscator runtimes do
            // constantly when they rebuild calls into the framework.
            var modelType = member switch
            {
                TypeDef or TypeRef or TypeSpec => "System.Type",
                FieldDef or MemberRef { IsFieldRef: true } => "System.Reflection.FieldInfo",
                MethodDef { IsConstructor: true } or
                    MemberRef { IsMethodRef: true, Name.String: ".ctor" or ".cctor" } =>
                    "System.Reflection.ConstructorInfo",
                MethodDef or MethodSpec or MemberRef { IsMethodRef: true } =>
                    "System.Reflection.MethodInfo",
                _ => null
            };
            if (modelType is null)
                return IntrinsicResult.Invalid($"Token 0x{token:X8} names an unmodeled member kind.");
            var resolved = StaticValue.Unknown;
            var made = modelType == "System.Type" && member is IFullName denoted
                ? context.State.Heap.TryAllocateType(denoted.FullName, out resolved)
                : context.State.Heap.TryAllocateObject(modelType, out resolved);
            if (!made)
                return AllocationFailure("resolved member model");
            context.State.Heap.TrySetModelValue(resolved, "Metadata", member);
            if (member is TypeDef or FieldDef or MethodDef)
                context.State.Heap.TrySetModelValue(resolved, HomeModuleMark, true);
            return IntrinsicResult.Completed(resolved);
        }
        // A literal reached by token is the same literal the file spells out in its user-string
        // heap, and reading it there is the same kind of lookup as resolving a member. A runtime
        // that loads its strings this way — which a virtual machine does, because its program is
        // data rather than IL — cannot be followed at all otherwise.
        if (name == "ResolveString" &&
            arguments.Count >= 2 &&
            context.State.ModuleMetadata is ModuleDefMD spelling &&
            arguments[1].Kind == StaticValueKind.Int32)
        {
            var token = (uint)arguments[1].AsInt32();
            if ((token & 0xFF000000) != 0x70000000)
                return IntrinsicResult.Invalid($"Token 0x{token:X8} does not name a string.");
            string literal;
            try
            {
                literal = spelling.ReadUserString(token);
            }
            catch (Exception failure) when (ManagedImage.Rejects(failure))
            {
                return IntrinsicResult.Invalid($"Token 0x{token:X8} is not in the string heap.");
            }
            return context.State.Heap.TryAllocateString(literal, out var read)
                ? IntrinsicResult.Completed(read)
                : AllocationFailure("resolved string");
        }
        if (arguments.Count == 1 && name == "get_ModuleHandle")
            return IntrinsicResult.Completed(arguments[0]);
        if (arguments.Count == 1 && name is "get_Name" or "get_FullyQualifiedName")
        {
            var value = string.IsNullOrEmpty(context.State.AssemblyName)
                ? "module"
                : context.State.AssemblyName + ".dll";
            return context.State.Heap.TryAllocateString(value, out var result)
                ? IntrinsicResult.Completed(result)
                : AllocationFailure("module name");
        }
        return IntrinsicResult.Invalid($"Module operation {name} is denied.");
    }

    private static IntrinsicResult InvokeHashtable(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (name == ".ctor" && arguments.Count is 1 or 2)
        {
            heap.TrySetModelValue(
                arguments[0],
                "Entries",
                new Dictionary<StaticValue, StaticValue>());
            return IntrinsicResult.Completed();
        }
        if (arguments.Count == 0 ||
            !heap.TryGetModelValue(
                arguments[0],
                "Entries",
                out Dictionary<StaticValue, StaticValue>? entries) ||
            entries is null)
        {
            return IntrinsicResult.Invalid("Hashtable is not initialized.");
        }
        if (name == "get_Count" && arguments.Count == 1)
            return IntrinsicResult.Completed(StaticValue.FromInt32(entries.Count));
        if (name is "Add" or "set_Item" && arguments.Count == 3)
        {
            var key = UnboxKey(heap, arguments[1]);
            if (name == "Add" && entries.ContainsKey(key))
                return IntrinsicResult.Invalid("Hashtable duplicate key.");
            entries[key] = arguments[2];
            return IntrinsicResult.Completed();
        }
        if (name == "get_Item" && arguments.Count == 2)
            return IntrinsicResult.Completed(
                entries.GetValueOrDefault(UnboxKey(heap, arguments[1]), StaticValue.Null));
        if (name is "Contains" or "ContainsKey" && arguments.Count == 2)
            return IntrinsicResult.Completed(StaticValue.FromInt32(
                entries.ContainsKey(UnboxKey(heap, arguments[1])) ? 1 : 0));
        return IntrinsicResult.Invalid($"Hashtable operation {name} is denied.");
    }

    private static StaticValue UnboxKey(StaticHeap heap, StaticValue key) =>
        heap.TryUnbox(key, out var value) ? value : key;

    private static IntrinsicResult InvokeProcess(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        if (name == "GetCurrentProcess" && arguments.Count == 0)
            return context.State.Heap.TryAllocateObject(
                "System.Diagnostics.Process",
                out var process)
                ? IntrinsicResult.Completed(process)
                : AllocationFailure("process model");
        if (name == "get_Id" && arguments.Count == 1)
            return IntrinsicResult.Completed(StaticValue.FromInt32(1));
        if (name == "get_Handle" && arguments.Count == 1)
            return IntrinsicResult.Completed(StaticValue.FromInt64(0));
        if (name == "get_Modules" && arguments.Count == 1)
        {
            var heap = context.State.Heap;
            if (!heap.TryAllocateObject(
                    "System.Diagnostics.ProcessModule",
                    out var runtimeModule) ||
                !heap.TryAllocateObject(
                    "System.Diagnostics.ProcessModuleCollection",
                    out var modules))
            {
                return AllocationFailure("process modules");
            }
            if (!heap.TryAllocateRegion(64 * 1024, "RuntimeModule", out var runtimeBase))
                return AllocationFailure("runtime module image");
            heap.TrySetModelValue(runtimeModule, "BaseAddress", runtimeBase);
            heap.TrySetModelValue(runtimeModule, "ModuleName", "clrjit.dll");
            heap.TrySetModelValue(runtimeModule, "MemorySize", 64 * 1024);

            // The loader locates its own module by scanning for the one whose
            // [BaseAddress, BaseAddress + ModuleMemorySize) range covers a mapped-image
            // address, so the protected assembly must appear as a real process module.
            var count = 0;
            if (TryCreateMappedImageModule(context, out var imageModule))
                heap.TrySetModelValue(modules, $"Module{count++}", imageModule);
            heap.TrySetModelValue(modules, $"Module{count++}", runtimeModule);
            heap.TrySetModelValue(modules, "Count", count);
            heap.TrySetModelValue(modules, "RuntimeModule", runtimeModule);
            return IntrinsicResult.Completed(modules);
        }
        if (name is "Dispose" or "Close" && arguments.Count == 1)
            return IntrinsicResult.Completed();
        return IntrinsicResult.Invalid($"Process operation {name} is denied.");
    }

    private static bool TryCreateMappedImageModule(
        IntrinsicContext context,
        out StaticValue module)
    {
        module = StaticValue.Unknown;
        var heap = context.State.Heap;
        if (!context.State.ImageRegion.IsKnown ||
            !heap.TryGetNativePointer(context.State.ImageRegion, 0, out var imageBase) ||
            !heap.TryGetLength(context.State.ImageRegion, out var imageLength) ||
            imageLength <= 0 ||
            !heap.TryAllocateObject("System.Diagnostics.ProcessModule", out module))
        {
            return false;
        }
        heap.TrySetModelValue(module, "BaseAddress", imageBase);
        heap.TrySetModelValue(module, "MemorySize", imageLength);
        heap.TrySetModelValue(
            module,
            "ModuleName",
            string.IsNullOrEmpty(context.State.AssemblyName)
                ? "module.dll"
                : context.State.AssemblyName + ".dll");
        return true;
    }

    private static IntrinsicResult InvokeProcessModule(
        IntrinsicContext context,
        string type,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (type == "System.Diagnostics.ProcessModuleCollection" &&
            arguments.Count == 1 &&
            name == "get_Count")
        {
            return IntrinsicResult.Completed(StaticValue.FromInt32(
                heap.TryGetModelValue(arguments[0], "Count", out int moduleCount)
                    ? moduleCount
                    : 1));
        }
        if (type == "System.Diagnostics.ProcessModuleCollection" &&
            arguments.Count == 2 &&
            name == "get_Item")
        {
            return heap.TryGetModelValue(
                    arguments[0],
                    $"Module{arguments[1].AsInt32()}",
                    out StaticValue indexedModule)
                ? IntrinsicResult.Completed(indexedModule)
                : IntrinsicResult.Invalid("Process module index is out of range.");
        }
        if (type == "System.Diagnostics.ProcessModule" &&
            arguments.Count == 1 &&
            name is "get_ModuleName" or "get_FileName")
        {
            var value = heap.TryGetModelValue(arguments[0], "ModuleName", out string? stored) &&
                !string.IsNullOrEmpty(stored)
                    ? stored
                    : "clrjit.dll";
            return heap.TryAllocateString(value, out var moduleName)
                ? IntrinsicResult.Completed(moduleName)
                : AllocationFailure("runtime module name");
        }
        if (type == "System.Diagnostics.ProcessModule" &&
            arguments.Count == 1 &&
            name == "get_ModuleMemorySize")
        {
            return heap.TryGetModelValue(arguments[0], "MemorySize", out int memorySize)
                ? IntrinsicResult.Completed(StaticValue.FromInt32(memorySize))
                : IntrinsicResult.Invalid("Process module memory size is not modeled.");
        }
        if (type == "System.Diagnostics.ProcessModule" &&
            arguments.Count == 1 &&
            name == "get_BaseAddress")
        {
            if (heap.TryGetModelValue(arguments[0], "BaseAddress", out StaticValue existing))
                return IntrinsicResult.Completed(existing);
            if (!heap.TryAllocateRegion(64 * 1024, "RuntimeModule", out var moduleBase))
                return AllocationFailure("runtime module image");
            heap.TrySetModelValue(arguments[0], "BaseAddress", moduleBase);
            return IntrinsicResult.Completed(moduleBase);
        }
        if (type == "System.Diagnostics.ProcessModule" &&
            arguments.Count == 1 &&
            name == "get_FileVersionInfo")
        {
            return heap.TryAllocateObject(
                "System.Diagnostics.FileVersionInfo",
                out var version)
                ? IntrinsicResult.Completed(version)
                : AllocationFailure("runtime version");
        }
        if (type == "System.Diagnostics.FileVersionInfo" && arguments.Count == 1)
        {
            if (name is "get_FileMajorPart" or "get_ProductMajorPart")
                return IntrinsicResult.Completed(StaticValue.FromInt32(4));
            if (name is "get_FileMinorPart" or "get_ProductMinorPart")
                return IntrinsicResult.Completed(StaticValue.FromInt32(8));
            if (name is "get_FileBuildPart" or "get_ProductBuildPart")
                return IntrinsicResult.Completed(StaticValue.FromInt32(9037));
            if (name is "get_FilePrivatePart" or "get_ProductPrivatePart")
                return IntrinsicResult.Completed(StaticValue.FromInt32(0));
            if (name is "get_FileVersion" or "get_ProductVersion")
                return heap.TryAllocateString("4.8.9037.0", out var versionText)
                    ? IntrinsicResult.Completed(versionText)
                    : AllocationFailure("runtime version string");
        }
        return IntrinsicResult.Invalid($"Process module operation {name} is denied.");
    }

    private static IntrinsicResult InvokeEnumerator(
        IntrinsicContext context,
        string type,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (type == "System.Collections.ReadOnlyCollectionBase" &&
            name == "GetEnumerator" &&
            arguments.Count == 1 &&
            heap.TryGetModelValue(arguments[0], "Count", out int _))
        {
            if (!heap.TryAllocateObject("System.Collections.IEnumerator", out var enumerator))
                return AllocationFailure("module enumerator");
            heap.TrySetModelValue(enumerator, "Collection", arguments[0]);
            heap.TrySetModelValue(enumerator, "Index", -1);
            return IntrinsicResult.Completed(enumerator);
        }
        if (type == "System.Collections.IEnumerator" &&
            name == "MoveNext" &&
            arguments.Count == 1 &&
            heap.TryGetModelValue(arguments[0], "Index", out int index) &&
            heap.TryGetModelValue(arguments[0], "Collection", out StaticValue source) &&
            heap.TryGetModelValue(source, "Count", out int sourceCount))
        {
            var next = index + 1;
            heap.TrySetModelValue(arguments[0], "Index", next);
            return IntrinsicResult.Completed(StaticValue.FromInt32(next < sourceCount ? 1 : 0));
        }
        if (type == "System.Collections.IEnumerator" &&
            name == "get_Current" &&
            arguments.Count == 1 &&
            heap.TryGetModelValue(arguments[0], "Index", out int current) &&
            heap.TryGetModelValue(arguments[0], "Collection", out StaticValue collection) &&
            heap.TryGetModelValue(collection, $"Module{current}", out StaticValue item))
        {
            return IntrinsicResult.Completed(item);
        }
        if (type == "System.IDisposable" && name == "Dispose")
            return IntrinsicResult.Completed();
        return IntrinsicResult.Invalid($"Enumerator operation {name} is denied.");
    }

    private static IntrinsicResult AllocationFailure(string operation) => new(
        StaticExecutionStatus.AllocationLimitExceeded,
        StaticValue.Unknown,
        $"{operation} exceeded the allocation budget.");
}

public sealed class VirtualRegionIntrinsic : IStaticIntrinsic
{
    public bool Matches(IMethod method) =>
        (method.DeclaringType.FullName == "System.Runtime.InteropServices.Marshal" &&
        method.Name.String is "AllocHGlobal" or "FreeHGlobal" or
            "AllocCoTaskMem" or "FreeCoTaskMem" or "Copy" or
            "GetHINSTANCE" or "GetDelegateForFunctionPointer" or
            "ReadByte" or "ReadInt16" or "ReadInt32" or "ReadInt64" or "ReadIntPtr" or
            "WriteByte" or "WriteInt16" or "WriteInt32" or "WriteInt64" or "WriteIntPtr") ||
        (NativeName(method) ?? method.Name.String) is
            "VirtualAlloc" or "VirtualAllocEx" or "VirtualProtect" or
            "WriteProcessMemory" or "LoadLibrary" or "LoadLibraryA" or "LoadLibraryW" or
            "GetModuleHandle" or "GetModuleHandleA" or "GetModuleHandleW" or "GetProcAddress";

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        if (arguments.Any(value => !value.IsKnown))
            return IntrinsicResult.Unknown($"{method.FullName} received an unknown value.");
        var heap = context.State.Heap;
        var name = NativeName(method) ?? method.Name.String;
        if (name is "LoadLibrary" or "LoadLibraryA" or "LoadLibraryW" or
            "GetModuleHandle" or "GetModuleHandleA" or "GetModuleHandleW")
        {
            return heap.TryAllocateRegion(64 * 1024, "RuntimeModule", out var module)
                ? IntrinsicResult.Completed(module)
                : new IntrinsicResult(
                    StaticExecutionStatus.AllocationLimitExceeded,
                    StaticValue.Unknown,
                    "Runtime module exceeded the allocation budget.");
        }
        if (name == "GetProcAddress" && arguments.Count == 2 &&
            heap.TryGetString(arguments[1], out var procedureName) &&
            heap.TryGetNativePointer(arguments[0], 0, out var procedure))
        {
            if (!heap.TryAllocateObject("System.IntPtr", out var pointer))
                return IntrinsicResult.Invalid("Could not allocate procedure pointer.");
            heap.TrySetModelValue(pointer, "Pointer", procedure);
            heap.TrySetModelValue(pointer, "NativeName", procedureName);
            return IntrinsicResult.Completed(pointer);
        }
        if (name == "GetDelegateForFunctionPointer" && arguments.Count == 2 &&
            heap.TryGetModelValue(arguments[0], "NativeName", out string? nativeName) &&
            !string.IsNullOrEmpty(nativeName))
        {
            if (!heap.TryAllocateObject("System.Delegate", out var nativeDelegate))
                return IntrinsicResult.Invalid("Could not allocate native delegate.");
            heap.TrySetModelValue(nativeDelegate, "NativeName", nativeName);
            return IntrinsicResult.Completed(nativeDelegate);
        }
        if (name == "GetHINSTANCE" && arguments.Count == 1)
            return heap.TryGetNativePointer(context.State.ImageRegion, 0, out var moduleBase)
                ? IntrinsicResult.Completed(moduleBase)
                : IntrinsicResult.Invalid("Synthetic module image is unavailable.");
        if (name is "AllocHGlobal" or "AllocCoTaskMem" &&
            arguments.Count == 1)
            return heap.TryAllocateRegion(arguments[0].AsInt32(), out var region)
                ? IntrinsicResult.Completed(region)
                : new IntrinsicResult(
                    StaticExecutionStatus.AllocationLimitExceeded,
                    StaticValue.Unknown,
                    "Virtual region exceeded the allocation budget.");
        if (name is "FreeHGlobal" or "FreeCoTaskMem" &&
            arguments.Count == 1)
            return IntrinsicResult.Completed();
        if (name is "VirtualAlloc" or "VirtualAllocEx" && arguments.Count >= 2)
        {
            var sizeIndex = name == "VirtualAllocEx" ? 2 : 1;
            return heap.TryAllocateRegion(
                    arguments[sizeIndex].AsInt32(),
                    "VirtualAlloc",
                    out var region)
                ? IntrinsicResult.Completed(region)
                : new IntrinsicResult(
                    StaticExecutionStatus.AllocationLimitExceeded,
                    StaticValue.Unknown,
                    "VirtualAlloc region exceeded the allocation budget.");
        }
        if (name == "VirtualProtect" && arguments.Count >= 3)
            return IntrinsicResult.Completed(StaticValue.FromInt32(1));
        if (name == "WriteProcessMemory" && arguments.Count >= 4)
        {
            var destination = arguments[1];
            var source = arguments[2];
            var count = arguments[3].AsInt32();
            if (count < 0)
                return IntrinsicResult.Invalid("WriteProcessMemory length is negative.");
            var copied = new byte[count];
            return heap.TryReadBytes(source, 0, copied) &&
                heap.TryWriteBytes(destination, 0, copied)
                    ? IntrinsicResult.Completed(StaticValue.FromInt32(1))
                    : IntrinsicResult.Invalid("WriteProcessMemory range is invalid.");
        }
        if (name == "ReadIntPtr" && arguments.Count is 1 or 2)
        {
            var readOffset = arguments.Count == 2 ? arguments[1].AsInt32() : 0;
            var address = NormalizeAddress(context, arguments[0]);
            Span<byte> pointerBytes = stackalloc byte[8];
            if (!heap.TryReadBytes(
                    address,
                    readOffset,
                    pointerBytes[..context.State.PointerSize]))
                return IntrinsicResult.Invalid("Native IntPtr source is out of bounds.");
            var nativeAddress = context.State.PointerSize == 4
                ? BinaryPrimitives.ReadUInt32LittleEndian(pointerBytes)
                : BinaryPrimitives.ReadInt64LittleEndian(pointerBytes);
            if (heap.TryResolveNativeAddress(nativeAddress, out var concrete))
                return IntrinsicResult.Completed(concrete);
            return IntrinsicResult.Completed(context.State.PointerSize == 4
                ? StaticValue.FromInt32(unchecked((int)nativeAddress))
                : StaticValue.FromInt64(nativeAddress));
        }
        if (name == "WriteIntPtr" && arguments.Count is 2 or 3)
        {
            var destination = arguments[0];
            var writeOffset = arguments.Count == 3 ? arguments[1].AsInt32() : 0;
            var source = arguments[^1];
            if (heap.TryGetModelValue(destination, "Pointer", out StaticValue modeled) &&
                modeled.Kind == StaticValueKind.ManagedReference &&
                writeOffset == 0)
            {
                return heap.TryWriteManaged(modeled, source)
                    ? IntrinsicResult.Completed()
                    : IntrinsicResult.Invalid("Managed IntPtr destination is invalid.");
            }
            destination = NormalizeAddress(context, destination);
            var syntheticAddress =
                source.Kind == StaticValueKind.NativePointer &&
                heap.TryGetNativeAddress(source, out var nativeAddress)
                    ? nativeAddress
                    : source.IsInteger ? source.AsInt64() : 0;
            Span<byte> addressBytes = stackalloc byte[8];
            if (context.State.PointerSize == 4)
                BinaryPrimitives.WriteInt32LittleEndian(
                    addressBytes,
                    unchecked((int)syntheticAddress));
            else
                BinaryPrimitives.WriteInt64LittleEndian(addressBytes, syntheticAddress);
            return heap.TryWriteBytes(
                destination,
                writeOffset,
                addressBytes[..context.State.PointerSize])
                ? IntrinsicResult.Completed()
                : IntrinsicResult.Invalid("Native IntPtr destination is out of bounds.");
        }
        if (name == "Copy" && arguments.Count == 4)
        {
            var count = arguments[3].AsInt32();
            if (count < 0)
                return IntrinsicResult.Invalid("Marshal.Copy length is negative.");
            var sourceIsArray = method.MethodSig?.Params[0].ElementType is
                ElementType.SZArray or ElementType.Array;
            var arrayParameter = sourceIsArray
                ? method.MethodSig?.Params[0]
                : method.MethodSig?.Params[2];
            var elementWidth = MarshalArrayElementWidth(arrayParameter);
            if (elementWidth == 0 ||
                count > heap.MaximumObjectLength / elementWidth)
            {
                return IntrinsicResult.Invalid(
                    "Marshal.Copy array element type or length is invalid.");
            }
            var byteCount = checked(count * elementWidth);
            var arrayByteOffset = arguments[1].AsInt32();
            if (arrayByteOffset < 0 ||
                arrayByteOffset > int.MaxValue / elementWidth)
            {
                return IntrinsicResult.Invalid("Marshal.Copy array index is invalid.");
            }
            arrayByteOffset *= elementWidth;
            var temporary = new byte[byteCount];
            if (sourceIsArray)
                return heap.TryReadBytes(arguments[0], arrayByteOffset, temporary) &&
                    heap.TryWriteBytes(
                        NormalizeAddress(context, arguments[2]),
                        0,
                        temporary)
                    ? IntrinsicResult.Completed()
                    : IntrinsicResult.Invalid("Marshal.Copy array-to-native range is invalid.");
            return heap.TryReadBytes(
                    NormalizeAddress(context, arguments[0]),
                    0,
                    temporary) &&
                heap.TryWriteBytes(arguments[2], arrayByteOffset, temporary)
                    ? IntrinsicResult.Completed()
                    : IntrinsicResult.Invalid("Marshal.Copy native-to-array range is invalid.");
        }

        var width = name switch
        {
            "WriteByte" or "ReadByte" => 1,
            "WriteInt16" or "ReadInt16" => 2,
            "WriteInt32" or "ReadInt32" => 4,
            "WriteInt64" or "ReadInt64" => 8,
            _ => 0
        };
        if (name.StartsWith("Read", StringComparison.Ordinal))
        {
            var readOffset = arguments.Count == 1 ? 0 : arguments[1].AsInt32();
            var address = NormalizeAddress(context, arguments[0]);
            Span<byte> readBytes = stackalloc byte[8];
            if (!heap.TryReadBytes(address, readOffset, readBytes[..width]))
                return IntrinsicResult.Invalid(
                    $"Virtual region read is out of bounds (kind={address.Kind}, " +
                    $"value={address.Bits}, offset={readOffset}, width={width}).");
            return width switch
            {
                1 => IntrinsicResult.Completed(StaticValue.FromInt32(readBytes[0])),
                2 => IntrinsicResult.Completed(StaticValue.FromInt32(
                    BinaryPrimitives.ReadInt16LittleEndian(readBytes))),
                4 => IntrinsicResult.Completed(StaticValue.FromInt32(
                    BinaryPrimitives.ReadInt32LittleEndian(readBytes))),
                8 => IntrinsicResult.Completed(StaticValue.FromInt64(
                    BinaryPrimitives.ReadInt64LittleEndian(readBytes))),
                _ => IntrinsicResult.Invalid($"Unsupported region read {method.FullName}.")
            };
        }
        var offset = arguments.Count == 2 ? 0 : arguments[1].AsInt32();
        var value = arguments[^1].AsInt64();
        Span<byte> bytes = stackalloc byte[8];
        switch (width)
        {
            case 1: bytes[0] = unchecked((byte)value); break;
            case 2: BinaryPrimitives.WriteInt16LittleEndian(bytes, unchecked((short)value)); break;
            case 4: BinaryPrimitives.WriteInt32LittleEndian(bytes, unchecked((int)value)); break;
            case 8: BinaryPrimitives.WriteInt64LittleEndian(bytes, value); break;
            default: return IntrinsicResult.Invalid($"Unsupported region write {method.FullName}.");
        }
        var writeAddress = NormalizeAddress(context, arguments[0]);
        return heap.TryWriteBytes(
            writeAddress,
            offset,
            bytes[..width])
            ? IntrinsicResult.Completed()
            : IntrinsicResult.Invalid(
                $"Virtual region write is out of bounds (kind={writeAddress.Kind}, " +
                $"value={writeAddress.Bits}, offset={offset}, width={width}).");
    }

    private static int MarshalArrayElementWidth(TypeSig? arrayType) =>
        arrayType?.Next?.ElementType switch
        {
            ElementType.I1 or ElementType.U1 => 1,
            ElementType.I2 or ElementType.U2 or ElementType.Char => 2,
            ElementType.I4 or ElementType.U4 or ElementType.R4 => 4,
            ElementType.I8 or ElementType.U8 or ElementType.R8 => 8,
            _ => 0
        };

    private static StaticValue NormalizeAddress(IntrinsicContext context, StaticValue value)
    {
        var heap = context.State.Heap;
        for (var depth = 0; depth < 4; depth++)
        {
            if (heap.TryGetModelValue(value, "Pointer", out StaticValue modeled))
            {
                value = modeled;
                continue;
            }
            if (value.Kind == StaticValueKind.ManagedReference)
                break;
            if (heap.TryReadManaged(value, out var managed))
            {
                value = managed;
                continue;
            }
            break;
        }
        if (value.IsInteger &&
            heap.TryResolveNativeAddress(value.AsInt64(), out var nativeAddress))
        {
            return nativeAddress;
        }
        return value;
    }

    private static string? NativeName(IMethod method) =>
        method.ResolveMethodDef()?.ImplMap?.Name.String;
}
