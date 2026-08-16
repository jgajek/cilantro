using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Globalization;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core.Payload;
using BindingFlags = System.Reflection.BindingFlags;
using FieldInfo = System.Reflection.FieldInfo;
using MemberInfo = System.Reflection.MemberInfo;
using MethodBase = System.Reflection.MethodBase;
using MethodInfo = System.Reflection.MethodInfo;
using ParameterInfo = System.Reflection.ParameterInfo;
using PropertyInfo = System.Reflection.PropertyInfo;

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
        new InterlockedIntrinsic(),
        new AmbientIntrinsic(),
        new SequenceIntrinsic(),
        new NumberIntrinsic(),
        new ConversionIntrinsic(),
        new NumberConversionIntrinsic(),
        new ReflectionEmitIntrinsic(),
        new StackFrameIntrinsic(),
        new DebuggerIntrinsic(),
        new ThreadIntrinsic(),
        new StringBuilderIntrinsic(),
        new WeakReferenceIntrinsic(),
        new MutexIntrinsic(),
        new EnvironmentIntrinsic(),
        new RegistryIntrinsic(),
        new ManagementIntrinsic(),
        new NetworkSettingsIntrinsic(),
        new HttpClientIntrinsic(),
        new AsyncIntrinsic(),
        new UriIntrinsic(),
        new SocketIntrinsic(),
        new NativeDelegateIntrinsic(),
        new LoaderFrameworkIntrinsic(),
        new NativeHostIntrinsic(),
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
            case "Clear" when arguments.Count == 1:
                pairs.Clear();
                return IntrinsicResult.Completed();
            case "ContainsValue" when arguments.Count == 2:
                return Held(heap, pairs, arguments[1]);
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

    /// <summary>Whether any entry holds this value, compared the way keys are.</summary>
    private static IntrinsicResult Held(
        StaticHeap heap,
        List<KeyValuePair<StaticValue, StaticValue>> pairs,
        StaticValue value)
    {
        var sought = heap.TryGetString(value, out var text) ? text : null;
        var present = pairs.Any(pair =>
            sought is not null && heap.TryGetString(pair.Value, out var other)
                ? string.Equals(sought, other, StringComparison.Ordinal)
                : pair.Value.Equals(value));
        return IntrinsicResult.Completed(StaticValue.FromInt32(present ? 1 : 0));
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

/// <summary>Models a weak reference as one that is never collected.</summary>
/// <remarks>
/// Nothing is collected during interpretation, because interpretation is one path and it ends. So
/// what a weak reference was given is what it still holds, and a pool that keeps its spare buffers
/// this way finds them all still there. That is the reachable outcome, not a convenient one: a real
/// run that happened to collect nothing would behave the same.
/// </remarks>
public sealed class WeakReferenceIntrinsic : IStaticIntrinsic
{
    private const string Kept = "WeakTarget";

    public bool Matches(IMethod method) =>
        method?.DeclaringType?.FullName is { } declaring &&
        (declaring == "System.WeakReference" ||
            declaring.StartsWith("System.WeakReference`1<", StringComparison.Ordinal));

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
            return IntrinsicResult.Invalid($"WeakReference.{name} has no receiver.");
        switch (name)
        {
            // The second argument says whether the target should survive finalization, which does
            // not arise here, so it is read and dropped.
            case ".ctor" when arguments.Count is 2 or 3:
                heap.TrySetModelValue(arguments[0], Kept, arguments[1]);
                return IntrinsicResult.Completed();
            case "get_Target" or "get_IsAlive" or "TryGetTarget":
                var held = heap.TryGetModelValue<StaticValue>(arguments[0], Kept, out var stored)
                    ? stored
                    : StaticValue.Null;
                if (name == "get_IsAlive")
                    return IntrinsicResult.Completed(
                        StaticValue.FromInt32(held.Kind == StaticValueKind.Null ? 0 : 1));
                if (name == "get_Target")
                    return IntrinsicResult.Completed(held);
                if (arguments.Count < 2 || arguments[1].Kind != StaticValueKind.ManagedReference)
                    return IntrinsicResult.Invalid("TryGetTarget was not given somewhere to write.");
                heap.TryWriteManaged(arguments[1], held);
                return IntrinsicResult.Completed(
                    StaticValue.FromInt32(held.Kind == StaticValueKind.Null ? 0 : 1));
            case "set_Target" or "SetTarget" when arguments.Count == 2:
                heap.TrySetModelValue(arguments[0], Kept, arguments[1]);
                return IntrinsicResult.Completed();
            default:
                return IntrinsicResult.Invalid($"WeakReference.{name} is unsupported.");
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
/// Answers questions about the world outside the program from what the host profile states.
/// </summary>
/// <remarks>
/// Loaders ask the clock what time it is and mint identifiers to name a mutex, a pipe, or a
/// temporary file — things that depend on the machine that runs them and mean nothing to a reader.
/// Refusing the call would stop the interpretation on a path the program merely passes through, so
/// the machine answers, and answers the same way every time so that two runs still agree.
///
/// The value is stated rather than derived, and anything computed from it is stated too. That is
/// safe here only because what this machine is used to recover is checked on its own terms
/// afterwards — a payload has to parse as an assembly, a string table has to decode — so a result
/// that depended on an instant nobody can verify does not survive to be reported as fact. The
/// instant is in the profile so that a report can say which one it was.
/// </remarks>
public sealed class AmbientIntrinsic : IStaticIntrinsic
{
    private const string Bytes = "Bytes";
    private const string Ticks = "Ticks";

    public bool Matches(IMethod method) =>
        method.DeclaringType.FullName is
            "System.Guid" or "System.DateTime" or "System.TimeSpan";

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        var name = method.Name.String;
        if (Duration(context, method, arguments) is { } duration)
            return duration;
        if (name is "get_UtcNow" or "get_Now" or "get_Today" && arguments.Count == 0)
        {
            if (!HostClock.TryRead(context, out var reads))
                return HostFacts.Refuse(context, HostClock.NowKey);
            if (!heap.TryAllocateObject("System.DateTime", out var instant))
                return AllocationFailure("instant");
            heap.TrySetModelValue(
                instant,
                Ticks,
                name == "get_Today" ? reads.Date.Ticks : reads.Ticks);
            return IntrinsicResult.Completed(
                HostFacts.Stated(context, HostClock.NowKey, instant));
        }
        if (name == "get_Ticks" && arguments.Count == 1 &&
            heap.TryGetModelValue(arguments[0], Ticks, out long reading))
            return IntrinsicResult.Completed(StaticValue.FromInt64(reading));
        if (name is "NewGuid" or "get_Empty" && arguments.Count == 0)
        {
            if (name == "NewGuid")
            {
                if (!HostFacts.TryAsk(context, HostClock.SeedKey, out var seed))
                    return HostFacts.Refuse(context, HostClock.SeedKey);
                _minted ??= (int)seed.Number;
            }
            if (!heap.TryAllocateObject("System.Guid", out var identifier))
                return AllocationFailure("identifier");
            var minted = new byte[16];
            if (name == "NewGuid")
                BinaryPrimitives.WriteInt32LittleEndian(minted, (_minted += 1) ?? 0);
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

    /// <summary>
    /// How many identifiers have been minted, counting from what the profile seeded it with.
    /// </summary>
    private int? _minted;

    /// <summary>
    /// Answers instants and durations as arithmetic on ticks, or nothing if this is not one of them.
    /// </summary>
    /// <remarks>
    /// A duration is a count of ticks and an instant is a count of ticks from a fixed origin, so
    /// every operation over them is arithmetic, and none of it depends on anything about the machine.
    /// It is here because the answers a profile does state get compared against these: code that asks
    /// how long ago it was installed reads the clock, subtracts, and branches on the difference, and
    /// stopping at the subtraction would leave the stated instant with nothing to be used for.
    ///
    /// The arithmetic itself is the framework's, on values wearing the framework's own types, so the
    /// rounding is whatever the runtime does rather than a reimplementation of it.
    /// </remarks>
    private static IntrinsicResult? Duration(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        var declared = method.DeclaringType.FullName;
        var name = method.Name.String;
        if (declared == "System.TimeSpan" && arguments.Count == 1 &&
            name.StartsWith("From", StringComparison.Ordinal))
        {
            var measure = arguments[0].IsInteger
                ? arguments[0].AsInt64()
                : arguments[0].AsFloat64();
            TimeSpan? span;
            try
            {
                span = name switch
                {
                    "FromTicks" => TimeSpan.FromTicks(arguments[0].AsInt64()),
                    "FromMilliseconds" => TimeSpan.FromMilliseconds(measure),
                    "FromSeconds" => TimeSpan.FromSeconds(measure),
                    "FromMinutes" => TimeSpan.FromMinutes(measure),
                    "FromHours" => TimeSpan.FromHours(measure),
                    "FromDays" => TimeSpan.FromDays(measure),
                    _ => null
                };
            }
            catch (Exception ex) when (ex is OverflowException or ArgumentException)
            {
                return IntrinsicResult.Invalid($"The duration {name} was asked for is out of range.");
            }

            return span is { } measured
                ? Allocated(heap, "System.TimeSpan", measured.Ticks)
                : IntrinsicResult.Invalid($"Unsupported duration operation {name}.");
        }

        if (declared == "System.TimeSpan" && name == ".ctor" && arguments.Count >= 2)
        {
            var parts = arguments.Skip(1).Select(part => part.AsInt64()).ToArray();
            TimeSpan? span;
            try
            {
                span = parts.Length switch
                {
                    1 => new TimeSpan(parts[0]),
                    3 => new TimeSpan((int)parts[0], (int)parts[1], (int)parts[2]),
                    4 => new TimeSpan((int)parts[0], (int)parts[1], (int)parts[2], (int)parts[3]),
                    5 => new TimeSpan(
                        (int)parts[0], (int)parts[1], (int)parts[2], (int)parts[3], (int)parts[4]),
                    _ => null
                };
            }
            catch (ArgumentOutOfRangeException)
            {
                return IntrinsicResult.Invalid("The duration built is out of range.");
            }

            if (span is not { } built)
                return IntrinsicResult.Invalid("Unsupported duration construction.");
            heap.TrySetModelValue(arguments[0], Ticks, built.Ticks);
            return IntrinsicResult.Completed();
        }

        if (declared == "System.TimeSpan" && arguments.Count == 0)
        {
            return name switch
            {
                "get_Zero" => Allocated(heap, "System.TimeSpan", 0),
                "get_MaxValue" => Allocated(heap, "System.TimeSpan", TimeSpan.MaxValue.Ticks),
                "get_MinValue" => Allocated(heap, "System.TimeSpan", TimeSpan.MinValue.Ticks),
                _ => null
            };
        }

        // Reading a part off either type is reading it off the count of ticks it holds.
        if (arguments.Count == 1 && name.StartsWith("get_", StringComparison.Ordinal) &&
            heap.TryGetModelValue(arguments[0], Ticks, out long held))
        {
            var span = TimeSpan.FromTicks(held);
            var instant = declared == "System.DateTime" && held >= 0 && held <= DateTime.MaxValue.Ticks
                ? new DateTime(held, DateTimeKind.Utc)
                : default;
            return name[4..] switch
            {
                "TotalDays" => IntrinsicResult.Completed(StaticValue.FromFloat64(span.TotalDays)),
                "TotalHours" => IntrinsicResult.Completed(StaticValue.FromFloat64(span.TotalHours)),
                "TotalMinutes" =>
                    IntrinsicResult.Completed(StaticValue.FromFloat64(span.TotalMinutes)),
                "TotalSeconds" =>
                    IntrinsicResult.Completed(StaticValue.FromFloat64(span.TotalSeconds)),
                "TotalMilliseconds" =>
                    IntrinsicResult.Completed(StaticValue.FromFloat64(span.TotalMilliseconds)),
                "Days" => IntrinsicResult.Completed(StaticValue.FromInt32(
                    declared == "System.TimeSpan" ? span.Days : instant.Day)),
                "Hours" => IntrinsicResult.Completed(StaticValue.FromInt32(
                    declared == "System.TimeSpan" ? span.Hours : instant.Hour)),
                "Minutes" => IntrinsicResult.Completed(StaticValue.FromInt32(
                    declared == "System.TimeSpan" ? span.Minutes : instant.Minute)),
                "Seconds" => IntrinsicResult.Completed(StaticValue.FromInt32(
                    declared == "System.TimeSpan" ? span.Seconds : instant.Second)),
                "Milliseconds" => IntrinsicResult.Completed(StaticValue.FromInt32(
                    declared == "System.TimeSpan" ? span.Milliseconds : instant.Millisecond)),
                "Year" when declared == "System.DateTime" =>
                    IntrinsicResult.Completed(StaticValue.FromInt32(instant.Year)),
                "Month" when declared == "System.DateTime" =>
                    IntrinsicResult.Completed(StaticValue.FromInt32(instant.Month)),
                "Day" when declared == "System.DateTime" =>
                    IntrinsicResult.Completed(StaticValue.FromInt32(instant.Day)),
                "DayOfYear" when declared == "System.DateTime" =>
                    IntrinsicResult.Completed(StaticValue.FromInt32(instant.DayOfYear)),
                "Date" when declared == "System.DateTime" =>
                    Allocated(heap, "System.DateTime", instant.Date.Ticks),
                _ => null
            };
        }

        // Two of these compared or combined is their tick counts compared or combined. What comes
        // back depends on which types went in, and the signature says which.
        if (arguments.Count == 2 &&
            heap.TryGetModelValue(arguments[0], Ticks, out long left) &&
            heap.TryGetModelValue(arguments[1], Ticks, out long right))
        {
            switch (name)
            {
                case "op_Equality" or "Equals":
                    return IntrinsicResult.Completed(StaticValue.FromInt32(left == right ? 1 : 0));
                case "op_Inequality":
                    return IntrinsicResult.Completed(StaticValue.FromInt32(left != right ? 1 : 0));
                case "op_GreaterThan":
                    return IntrinsicResult.Completed(StaticValue.FromInt32(left > right ? 1 : 0));
                case "op_GreaterThanOrEqual":
                    return IntrinsicResult.Completed(StaticValue.FromInt32(left >= right ? 1 : 0));
                case "op_LessThan":
                    return IntrinsicResult.Completed(StaticValue.FromInt32(left < right ? 1 : 0));
                case "op_LessThanOrEqual":
                    return IntrinsicResult.Completed(StaticValue.FromInt32(left <= right ? 1 : 0));
                case "CompareTo" or "Compare":
                    return IntrinsicResult.Completed(
                        StaticValue.FromInt32(left.CompareTo(right)));
                case "op_Addition" or "Add" or "op_Subtraction" or "Subtract":
                {
                    var sum = name is "op_Addition" or "Add" ? left + right : left - right;
                    var produced = method.MethodSig?.RetType.FullName ?? declared;
                    return produced is "System.DateTime" or "System.TimeSpan"
                        ? Allocated(heap, produced, sum)
                        : null;
                }

                default:
                    return null;
            }
        }

        return null;
    }

    private static IntrinsicResult Allocated(StaticHeap heap, string type, long ticks)
    {
        if (!heap.TryAllocateObject(type, out var value))
            return AllocationFailure(type == "System.TimeSpan" ? "duration" : "instant");
        heap.TrySetModelValue(value, Ticks, ticks);
        return IntrinsicResult.Completed(value);
    }

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
        method.Name.String is "ToString" or "Equals" or "GetHashCode" or "CompareTo" or "Parse";

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        // A number read back out of its own text is exact wherever the text is known, and a runtime
        // that carries numbers around in a table of names does exactly that with them.
        if (method.Name == "Parse" && arguments.Count == 1 &&
            heap.TryGetString(arguments[0], out var spelled))
        {
            return Parsed(method.DeclaringType.FullName, spelled.Trim(), out var parsed)
                ? IntrinsicResult.Completed(parsed)
                : IntrinsicResult.Invalid(
                    $"\"{spelled}\" does not spell a {method.DeclaringType.FullName}.");
        }

        if (arguments.Count == 0 || Read(heap, arguments[0]) is not { } self)
            return IntrinsicResult.Invalid($"{method.FullName} was called on an unreadable value.");

        var declared = method.DeclaringType.FullName;
        switch (method.Name.String)
        {
            // A number written with a format is how a fingerprint becomes a string: each byte of a
            // digest written as two hex digits and concatenated. The formats answered here are the
            // ones that read the same on every machine, so the answer does not depend on a culture
            // nobody stated.
            case "ToString" when arguments.Count is 2 or 3 &&
                heap.TryGetString(arguments[1], out var format):
                if (Formatted(declared, self, format) is not { } written)
                    return IntrinsicResult.Invalid(
                        $"A {declared} written as \"{format}\" is not the same text on every " +
                        "machine, so it is not answered here.");
                return heap.TryAllocateString(written, out var formatted)
                    ? IntrinsicResult.Completed(formatted)
                    : IntrinsicResult.Invalid("Could not allocate rendered text.");
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

    /// <summary>
    /// The text a number makes under a format string, or null if that text is not knowable here.
    /// </summary>
    /// <remarks>
    /// The formatting itself is the framework's, applied to the value wearing its own type, because
    /// how many hex digits a negative number takes is a property of the type and not of the number.
    /// Only the decimal and hexadecimal families are answered: the others place group separators and
    /// decimal marks taken from the culture the process happens to be running under, and nothing in
    /// a profile states that, so a plausible-looking answer would be a guess in a value that goes on
    /// to be hashed or compared.
    /// </remarks>
    private static string? Formatted(string declared, long value, string format)
    {
        var specifier = format.Length == 0 ? 'G' : char.ToUpperInvariant(format[0]);
        if (specifier is not ('D' or 'X' or 'G') ||
            !format.Skip(1).All(char.IsAsciiDigit))
            return null;
        object typed = declared switch
        {
            "System.SByte" => (sbyte)value,
            "System.Byte" => (byte)value,
            "System.Int16" => (short)value,
            "System.UInt16" => (ushort)value,
            "System.Int32" => (int)value,
            "System.UInt32" => (uint)value,
            "System.Int64" => value,
            "System.UInt64" => (ulong)value,
            _ => null!
        };
        if (typed is null)
            return null;
        try
        {
            return ((IFormattable)typed).ToString(format, CultureInfo.InvariantCulture);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    /// <summary>The value a piece of text spells, in the type that was asked to read it.</summary>
    /// <remarks>
    /// Each type reads its own text, so text that names a number outside the range of the type
    /// reading it is not that number: the framework refuses it, and so does this.
    /// </remarks>
    private static bool Parsed(string declared, string text, out StaticValue value)
    {
        value = StaticValue.Unknown;
        const NumberStyles whole = NumberStyles.Integer;
        var culture = CultureInfo.InvariantCulture;
        switch (declared)
        {
            case "System.Boolean" when bool.TryParse(text, out var truth):
                value = StaticValue.FromInt32(truth ? 1 : 0);
                return true;
            case "System.Char" when text.Length == 1:
                value = StaticValue.FromInt32(text[0]);
                return true;
            case "System.SByte" when sbyte.TryParse(text, whole, culture, out var signedByte):
                value = StaticValue.FromInt32(signedByte);
                return true;
            case "System.Byte" when byte.TryParse(text, whole, culture, out var singleByte):
                value = StaticValue.FromInt32(singleByte);
                return true;
            case "System.Int16" when short.TryParse(text, whole, culture, out var narrow):
                value = StaticValue.FromInt32(narrow);
                return true;
            case "System.UInt16" when ushort.TryParse(text, whole, culture, out var unsignedNarrow):
                value = StaticValue.FromInt32(unsignedNarrow);
                return true;
            case "System.Int32" when int.TryParse(text, whole, culture, out var number):
                value = StaticValue.FromInt32(number);
                return true;
            case "System.UInt32" when uint.TryParse(text, whole, culture, out var unsigned):
                value = StaticValue.FromInt32(unchecked((int)unsigned));
                return true;
            case "System.Int64" when long.TryParse(text, whole, culture, out var wide):
                value = StaticValue.FromInt64(wide);
                return true;
            case "System.UInt64" when ulong.TryParse(text, whole, culture, out var unsignedWide):
                value = StaticValue.FromInt64(unchecked((long)unsignedWide));
                return true;
            default:
                return false;
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

/// <summary>
/// Reads a number out of whatever it arrived in and gives it back at another width.
/// </summary>
/// <remarks>
/// Ordinary code reaches for these whenever a value has been through <c>object</c> — a table of
/// settings, a deserialized field, an argument declared loosely — and so does a method body built
/// back from a virtual program, where every value is boxed because the engine boxed it.
///
/// The overflow behaviour is the real one. <c>Convert.ToInt32</c> of a value too large for an
/// <c>int</c> throws rather than truncating, and a model that quietly truncated would have the
/// machine compute a number the runtime never would, which is the one thing a model must not do.
/// The width the value was boxed at decides whether its top bit is a sign, since that is the whole
/// difference between a conversion that fits and one that does not.
/// </remarks>
public sealed class NumberConversionIntrinsic : IStaticIntrinsic
{
    private static readonly HashSet<string> Widths = new(StringComparer.Ordinal)
    {
        "ToBoolean", "ToByte", "ToSByte", "ToInt16", "ToUInt16", "ToChar",
        "ToInt32", "ToUInt32", "ToInt64", "ToUInt64"
    };

    public bool Matches(IMethod method) =>
        method?.DeclaringType?.FullName == "System.Convert" &&
        Widths.Contains(method.Name.String) &&
        method.MethodSig?.Params.Count == 1;

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(arguments);
        if (arguments.Count != 1)
            return IntrinsicResult.Invalid($"{method.FullName} takes one value.");
        if (!arguments[0].IsKnown)
            return IntrinsicResult.Unknown($"{method.FullName} received an unknown value.");

        var heap = context.State.Heap;

        // A null reference converts to zero, and false, which is what the real one does rather
        // than a special case invented here.
        if (arguments[0].Kind == StaticValueKind.Null)
            return IntrinsicResult.Completed(StaticValue.FromInt32(0));
        if (Held(heap, arguments[0]) is not { } held)
            return IntrinsicResult.Invalid(
                $"{method.FullName} was given something that is not a number.");

        if (method.Name == "ToBoolean")
            return IntrinsicResult.Completed(StaticValue.FromInt32(held != 0M ? 1 : 0));
        (decimal Low, decimal High) range = method.Name.String switch
        {
            "ToByte" => (byte.MinValue, byte.MaxValue),
            "ToSByte" => (sbyte.MinValue, sbyte.MaxValue),
            "ToInt16" => (short.MinValue, short.MaxValue),
            "ToUInt16" => (ushort.MinValue, ushort.MaxValue),
            "ToChar" => (char.MinValue, char.MaxValue),
            "ToUInt32" => (uint.MinValue, uint.MaxValue),
            "ToInt64" => (long.MinValue, long.MaxValue),
            "ToUInt64" => (ulong.MinValue, ulong.MaxValue),
            _ => (int.MinValue, int.MaxValue)
        };
        var (low, high) = range;
        if (held < low || held > high)
            return IntrinsicResult.Invalid(
                $"{method.FullName} was given {held}, which is outside what it can hold, so the " +
                "real call would throw.");
        return IntrinsicResult.Completed(method.Name.String switch
        {
            "ToInt64" => StaticValue.FromInt64((long)held),
            "ToUInt64" => StaticValue.FromInt64(unchecked((long)(ulong)held)),
            "ToUInt32" => StaticValue.FromInt32(unchecked((int)(uint)held)),
            _ => StaticValue.FromInt32((int)held)
        });
    }

    /// <summary>The number a value holds, whatever it arrived in.</summary>
    /// <remarks>
    /// A decimal is the return because it is the one type here that holds every value a
    /// <c>long</c> can and every value a <c>ulong</c> can, and the point of reading a box is to
    /// find out which of those two a run of bits was.
    /// </remarks>
    private static decimal? Held(StaticHeap heap, StaticValue value)
    {
        if (value.Kind == StaticValueKind.Int32 && value.IsKnown)
            return value.AsInt32();
        if (value.Kind == StaticValueKind.Int64 && value.IsKnown)
            return value.AsInt64();
        if (heap.TryGetString(value, out var text))
        {
            return long.TryParse(text.Trim(), CultureInfo.InvariantCulture, out var spelled)
                ? spelled
                : null;
        }
        if (!heap.TryUnbox(value, out var boxed) || !boxed.IsKnown ||
            !heap.TryGetRuntimeTypeName(value, out var was))
            return null;

        // What was boxed decides how its top bit reads. The machine keeps a boxed unsigned number
        // in a signed slot, so the bits of a large uint and of a negative int are the same bits,
        // and only the name the box carries tells them apart.
        return was switch
        {
            "System.UInt32" => unchecked((uint)(int)Held(heap, boxed).GetValueOrDefault()),
            "System.UInt64" or "System.UIntPtr" =>
                unchecked((ulong)(long)Held(heap, boxed).GetValueOrDefault()),
            _ => Held(heap, boxed)
        };
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
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(arguments);
        var name = method.Name.String;
        if (arguments.Count == 0)
            return IntrinsicResult.Invalid($"Unsupported Monitor operation {name}.");
        if (name == "Exit")
            return IntrinsicResult.Completed();

        // There is one thread here, so a lock is always free and taking it always succeeds. What
        // varies between the overloads is only whether they report that through a return value, an
        // out parameter, or both, and how long they were willing to wait for something that never
        // had to wait. Which of the trailing arguments is the report and which is the timeout is
        // read from the signature, because a timeout and a reference are both a number on the stack.
        var taken = method.MethodSig?.Params is { Count: > 0 } parameters &&
            parameters[^1] is ByRefSig { Next.FullName: "System.Boolean" }
                ? arguments[^1]
                : (StaticValue?)null;
        if (taken is { } flag &&
            !context.State.Heap.TryWriteManaged(flag, StaticValue.FromInt32(1)))
            return IntrinsicResult.Invalid($"Monitor.{name} cannot report that the lock was taken.");
        return name == "TryEnter"
            ? IntrinsicResult.Completed(StaticValue.FromInt32(1))
            : IntrinsicResult.Completed();
    }
}

/// <summary>
/// Models the interlocked operations, which are ordinary reads and writes when nothing else runs.
/// </summary>
/// <remarks>
/// These exist to make a read and a write indivisible against other threads. There is one thread
/// here, so every one of them is already indivisible and the model is the operation with the
/// atomicity dropped: add to what is there, swap what is there, or swap it only if it is what the
/// caller expected. Refusing them instead would stop on the lazy-initialization idiom, which is how
/// a library reaches the state it does its work from — a serializer counting how many callers are
/// contending for its type model before it builds one.
/// </remarks>
public sealed class InterlockedIntrinsic : IStaticIntrinsic
{
    public bool Matches(IMethod method) =>
        method?.DeclaringType?.FullName == "System.Threading.Interlocked" &&
        method.Name.String is "CompareExchange" or "Exchange" or "Increment" or "Decrement"
            or "Add" or "Read";

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
        if (arguments.Count == 0 || !heap.TryReadManaged(arguments[0], out var held))
            return IntrinsicResult.Invalid($"Interlocked.{name} was given no storage to work on.");
        if (name == "Read")
            return IntrinsicResult.Completed(held);

        // A number and a reference are both changed here, and only the arithmetic distinguishes
        // them: a swap needs no arithmetic, so it serves both, and adding needs the value.
        StaticValue written;
        switch (name)
        {
            case "Increment" or "Decrement" or "Add":
            {
                var by = name switch
                {
                    "Increment" => 1L,
                    "Decrement" => -1L,
                    _ => arguments.Count >= 2 ? Number(arguments[1]) : 0L
                };
                if (name == "Add" && arguments.Count < 2)
                    return IntrinsicResult.Invalid("Interlocked.Add was given nothing to add.");
                if (!held.IsInteger)
                    return IntrinsicResult.Invalid($"Interlocked.{name} was given a non-number.");
                var sum = Number(held) + by;
                written = held.Kind == StaticValueKind.Int64
                    ? StaticValue.FromInt64(sum)
                    : StaticValue.FromInt32(unchecked((int)sum));
                return heap.TryWriteManaged(arguments[0], written)
                    ? IntrinsicResult.Completed(written)
                    : IntrinsicResult.Invalid($"Interlocked.{name} could not store its result.");
            }

            case "Exchange" when arguments.Count >= 2:
                written = arguments[1];
                break;
            // Comparing is by identity for a reference and by value for a number, and the machine
            // holds both in a value that compares the same way.
            case "CompareExchange" when arguments.Count >= 3:
                if (!held.Equals(arguments[2]))
                    return IntrinsicResult.Completed(held);
                written = arguments[1];
                break;
            default:
                return IntrinsicResult.Invalid($"Unsupported interlocked operation {name}.");
        }

        return heap.TryWriteManaged(arguments[0], written)
            ? IntrinsicResult.Completed(held)
            : IntrinsicResult.Invalid($"Interlocked.{name} could not store its result.");
    }

    private static long Number(StaticValue value) =>
        value.Kind == StaticValueKind.Int64 ? value.AsInt64() : value.AsInt32();
}

/// <summary>
/// Answers code that asks whether it is being watched.
/// </summary>
/// <remarks>
/// A protected assembly asks this the way it asks the time: as a fact about the world it is running
/// in. The interpretation is not that world — nothing here is running, and no debugger is attached
/// to the process that is not running — so the profile answers no, for the same reason the clock
/// always reads the same instant. Refusing the question instead is not neutrality: it stops the
/// frame that asked, and Reactor asks inside the type initializer that builds the virtual engine, so
/// declining to answer costs the program, its string table, and the payload behind them.
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
        var key = name switch
        {
            "get_IsAttached" => "debugger:IsAttached",
            "get_IsLogging" => "debugger:IsLogging",
            "Launch" => "debugger:CanLaunch",
            // Breaking into a debugger that is not there, and telling one that is not listening,
            // both leave the program exactly as they found it, whichever debugger is not there.
            "Break" or "Log" or "NotifyOfCrossThreadDependency" => null,
            _ => string.Empty
        };
        if (key is { Length: 0 })
            return IntrinsicResult.Invalid($"Unsupported debugger operation {name}.");
        if (key is null)
        {
            context.State.Observe(
                LoaderObservationKind.DebuggerProbe,
                $"System.Diagnostics.Debugger::{name}",
                verdict: false);
            return IntrinsicResult.Completed();
        }
        if (!HostFacts.TryAsk(context, key, out var answer))
            return HostFacts.Refuse(context, key);
        context.State.Observe(
            LoaderObservationKind.DebuggerProbe,
            $"System.Diagnostics.Debugger::{name}",
            answer.Flag);
        return HostFacts.Number(context, key, answer.Flag ? 1 : 0);
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

/// <summary>
/// Follows code that writes code, by assembling what it emits into a body the machine can run.
/// </summary>
/// <remarks>
/// An obfuscator runtime reaches for <c>Reflection.Emit</c> when it needs a method that did not
/// exist at build time — a thunk that adapts one signature to another so a call can be routed
/// through a delegate, or, where Reactor decrypts strings, the decoder itself, built an instruction
/// at a time and then called by name. Refusing to follow it would stop the machine at the exact
/// point the program starts being interesting.
///
/// Nothing here interprets what the emitted code is for. The instructions are collected as they are
/// handed over, assembled into an ordinary method body once the program asks to run them, and then
/// run by the same interpreter that runs every other body. That means the model does not depend on
/// the emitted code having any particular shape: a thunk works because a thunk is valid IL, and so
/// does a decoder.
///
/// The scaffolding around the method — a dynamic assembly, the module in it, the type in that — is
/// modeled as the places they are and nothing more, because that is all the program does with them:
/// it asks each one for the next, and asks the last for a method to fill in.
/// </remarks>
public sealed class ReflectionEmitIntrinsic : IStaticIntrinsic
{
    /// <summary>
    /// Stands in for a parameter type the machine could not name, keeping the position.
    /// </summary>
    private static readonly TypeSig Placeholder = new ModuleDefUser("<unnamed>").CorLibTypes.Object;

    private const string Built = "EmittedMethod";
    private const string Owner = "EmittingMethod";
    private const string Members = "EmittedMembers";
    private const string Spelling = "EmittedName";
    private const string Held = "LocalIndex";
    private const string Holds = "LocalType";

    /// <summary>
    /// Marks where a label was placed, in among the instructions it was placed between.
    /// </summary>
    private const string Placed = "<label>";

    /// <summary>
    /// Model value recording that a member reference's shape was read rather than assumed.
    /// </summary>
    internal const string Confirmed = "SignatureConfirmed";

    /// <summary>
    /// Model value holding the reference a call assembled around a member should name.
    /// </summary>
    /// <remarks>
    /// A member found by reflection is described by whatever says the most about it, which for a
    /// framework member is the framework's own reflection. That is not something an instruction can
    /// name, so a reference is built alongside it and kept here, and the two are used for the two
    /// different things rather than one being made to serve both badly.
    /// </remarks>
    internal const string Emitted = "EmitReference";

    /// <summary>
    /// A label, by the number the generator handed out for it.
    /// </summary>
    private sealed record Marker(int Id);

    /// <summary>
    /// A local, by the position the generator gave it.
    /// </summary>
    private sealed record Position(int Index);

    /// <summary>
    /// Where a protected region begins, changes hands, or ends, in among the instructions.
    /// </summary>
    /// <remarks>
    /// A generator says "a try starts here" rather than emitting anything, and the boundary only
    /// becomes part of the method when the body is assembled. So it is recorded in place, the same
    /// way a label is, and turned into a handler once every instruction around it exists.
    /// </remarks>
    private sealed record Region(string Kind, int Ends, ITypeDefOrRef? Caught);

    /// <summary>Marks a boundary of a protected region, in among the instructions.</summary>
    private const string Bounded = "<region>";

    /// <summary>
    /// A method as it is being built up, from the first thing declared about it to the last
    /// instruction emitted into it.
    /// </summary>
    private sealed class Program
    {
        public string Name { get; set; } = "Invoke";
        public bool IsStatic { get; set; } = true;
        public TypeSig? Returns { get; set; }
        public List<TypeSig> Takes { get; set; } = [];
        public List<TypeSig> Locals { get; } = [];
        public int Labels { get; set; }

        /// <summary>The regions begun and not yet ended, innermost last.</summary>
        public Stack<int> Open { get; } = new();

        public List<(string OpCode, object? Operand)> Body { get; } = [];
    }

    public bool Matches(IMethod method) =>
        method.DeclaringType?.FullName is
            "System.Reflection.Emit.DynamicMethod" or
            "System.Reflection.Emit.ILGenerator" or
            "System.Reflection.Emit.AssemblyBuilder" or
            "System.Reflection.Emit.ModuleBuilder" or
            "System.Reflection.Emit.TypeBuilder" or
            "System.Reflection.Emit.MethodBuilder" or
            "System.Reflection.Emit.LocalBuilder" or
            // A local builder is a local like any other, and the slot it was given is asked for
            // through the base class as often as through the builder.
            "System.Reflection.LocalVariableInfo" ||
        (method.DeclaringType?.FullName == "System.AppDomain" &&
            method.Name == "DefineDynamicAssembly");

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
            case "DefineDynamicAssembly":
                return Allocate(heap, "System.Reflection.Emit.AssemblyBuilder");
            case "DefineDynamicModule":
                return Allocate(heap, "System.Reflection.Emit.ModuleBuilder");
            case "DefineType":
                return Open(heap, arguments);
            case "DefineMethod":
                return Declare(heap, arguments, onto: true);
            case ".ctor":
                return Declare(heap, arguments, onto: false);
            case "SetReturnType" when arguments.Count == 2:
            case "SetParameters" when arguments.Count == 2:
                return Shape(heap, name, arguments);
            case "GetILGenerator":
                if (!heap.TryAllocateObject("System.Reflection.Emit.ILGenerator", out var generator))
                    return IntrinsicResult.Invalid("Could not allocate an il generator.");
                heap.TrySetModelValue(generator, Owner, arguments[0]);
                return IntrinsicResult.Completed(generator);
            case "DeclareLocal" when arguments.Count == 2:
                return Reserve(heap, context.State.ModuleMetadata, arguments);
            // A local knows what it holds, and a program that pools locals by type asks it before
            // it decides whether one can be reused.
            case "get_LocalType" when arguments.Count == 1:
                if (!heap.TryGetModelValue<TypeSig>(arguments[0], Holds, out var holding) ||
                    holding is null)
                    return IntrinsicResult.Invalid("The local is not one this machine handed out.");
                if (!heap.TryAllocateType(holding.FullName, out var declaredType))
                    return IntrinsicResult.Invalid("Could not allocate a local's type.");
                heap.TrySetModelValue(declaredType, "Metadata", holding);
                return IntrinsicResult.Completed(declaredType);
            case "get_LocalIndex" when arguments.Count == 1:
                return heap.TryGetModelValue(arguments[0], Held, out int position)
                    ? IntrinsicResult.Completed(StaticValue.FromInt32(position))
                    : IntrinsicResult.Invalid("The local is not one this machine handed out.");
            // A label is the number the generator gave it, which is what the framework's own Label
            // carries and all that a branch to it or a mark of it needs to say which one it means.
            case "DefineLabel" when arguments.Count == 1:
                if (!TryProgram(heap, arguments[0], out var labelling) || labelling is null)
                    return IntrinsicResult.Invalid("A label was asked for with no method to hold it.");
                return IntrinsicResult.Completed(StaticValue.FromInt32(labelling.Labels++));
            case "MarkLabel" when arguments.Count == 2 && arguments[1].IsInteger:
                if (!TryProgram(heap, arguments[0], out var marking) || marking is null)
                    return IntrinsicResult.Invalid("A label was placed with no method to hold it.");
                marking.Body.Add((Placed, new Marker(arguments[1].AsInt32())));
                return IntrinsicResult.Completed();
            // A generator marks out a protected region rather than emitting anything for it, and
            // the marks become a handler when the body is assembled. The normal path through a
            // try and its finally is the same run of instructions either way; what the region adds
            // is where control goes when something is thrown, which the machine reads from the
            // handler it ends up with.
            case "BeginExceptionBlock" when arguments.Count == 1:
                return Mark(heap, arguments[0], "try", null);
            case "BeginFinallyBlock" when arguments.Count == 1:
                return Mark(heap, arguments[0], "finally", null);
            case "BeginCatchBlock" when arguments.Count == 2:
                return Mark(
                    heap,
                    arguments[0],
                    "catch",
                    Signatures(heap, arguments[1], context.State.ModuleMetadata)?.ToTypeDefOrRef());
            case "EndExceptionBlock" when arguments.Count == 1:
                return Mark(heap, arguments[0], "end", null);
            case "Emit":
                return Record(heap, method, arguments);
            // A call written the long way. Only the last argument makes it any different from the
            // instruction above, and a call that names optional parameter types is one this machine
            // has no way to assemble, so it is refused rather than recorded as the plain call it is
            // not.
            case "EmitCall" when arguments.Count == 4:
                return arguments[3].Kind == StaticValueKind.Null
                    ? Record(heap, method, [arguments[0], arguments[1], arguments[2]])
                    : IntrinsicResult.Invalid("A call to a vararg method cannot be assembled.");
            case "CreateType" or "CreateTypeInfo" when arguments.Count == 1:
                return Close(context, arguments[0]);
            case "CreateDelegate":
                return Bind(context, arguments);
            case "DefineParameter":
                return IntrinsicResult.Completed(StaticValue.Null);
            default:
                return IntrinsicResult.Invalid($"Emit operation {name} is denied.");
        }
    }

    /// <summary>
    /// Records where a protected region begins, changes hands, or ends.
    /// </summary>
    /// <remarks>
    /// The label a generator hands back from the beginning of a region is the one it places at the
    /// end, and code inside the region leaves to it, so the two ends are tied together by that
    /// number.
    /// </remarks>
    private static IntrinsicResult Mark(
        StaticHeap heap,
        StaticValue generator,
        string kind,
        ITypeDefOrRef? caught)
    {
        if (!TryProgram(heap, generator, out var program) || program is null)
            return IntrinsicResult.Invalid($"A {kind} was marked with no method to hold it.");
        if (kind == "try")
        {
            var opening = program.Labels++;
            program.Open.Push(opening);
            program.Body.Add((Bounded, new Region("try", opening, null)));
            return IntrinsicResult.Completed(StaticValue.FromInt32(opening));
        }

        if (program.Open.Count == 0)
            return IntrinsicResult.Invalid($"A {kind} was marked outside any protected region.");
        var ends = kind == "end" ? program.Open.Pop() : program.Open.Peek();
        program.Body.Add((Bounded, new Region(kind, ends, caught)));
        return IntrinsicResult.Completed();
    }

    private static IntrinsicResult Allocate(StaticHeap heap, string shape) =>
        heap.TryAllocateObject(shape, out var built)
            ? IntrinsicResult.Completed(built)
            : IntrinsicResult.Invalid($"Could not allocate a {shape}.");

    /// <summary>
    /// Opens a type for the program to define methods on.
    /// </summary>
    private static IntrinsicResult Open(StaticHeap heap, IReadOnlyList<StaticValue> arguments)
    {
        if (!heap.TryAllocateObject("System.Reflection.Emit.TypeBuilder", out var built))
            return IntrinsicResult.Invalid("Could not allocate a type builder.");
        heap.TrySetModelValue(built, Members, new List<StaticValue>());
        heap.TrySetModelValue(
            built,
            Spelling,
            arguments.Count > 1 && heap.TryGetString(arguments[1], out var spelled)
                ? spelled
                : "Emitted");
        return IntrinsicResult.Completed(built);
    }

    /// <summary>
    /// Notes a method the program is about to fill in, and what it has said about it so far.
    /// </summary>
    /// <remarks>
    /// A dynamic method arrives fully described where a method on a type builder does not — its
    /// return and parameter types are set afterwards, a call each — so both are recorded as what is
    /// known now and left open to be told more. The two are told apart by what the program supplied
    /// after the name: attributes for the one, a return type for the other.
    /// </remarks>
    private static IntrinsicResult Declare(
        StaticHeap heap,
        IReadOnlyList<StaticValue> arguments,
        bool onto)
    {
        var program = new Program();
        if (arguments.Count > 1 && heap.TryGetString(arguments[1], out var spelled))
            program.Name = spelled;
        var described = 2;
        if (arguments.Count > 2 && arguments[2].IsInteger)
        {
            program.IsStatic = (arguments[2].AsInt32() & (int)MethodAttributes.Static) != 0;
            described = 3;
        }

        if (arguments.Count > described)
            program.Returns = Signatures(heap, arguments[described]);
        if (arguments.Count > described + 1)
            program.Takes = Taken(heap, arguments[described + 1]);
        if (!onto)
        {
            heap.TrySetModelValue(arguments[0], Built, program);
            return IntrinsicResult.Completed();
        }

        if (!heap.TryAllocateObject("System.Reflection.Emit.MethodBuilder", out var builder))
            return IntrinsicResult.Invalid("Could not allocate a method builder.");
        heap.TrySetModelValue(builder, Built, program);
        if (heap.TryGetModelValue<List<StaticValue>>(arguments[0], Members, out var members) &&
            members is not null)
        {
            members.Add(builder);
        }

        return IntrinsicResult.Completed(builder);
    }

    /// <summary>
    /// Records the return or parameter types a method was given after it was declared.
    /// </summary>
    private static IntrinsicResult Shape(
        StaticHeap heap,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        if (!TryProgram(heap, arguments[0], out var program) || program is null)
            return IntrinsicResult.Invalid($"{name} names no method this machine is building.");
        if (name == "SetReturnType")
            program.Returns = Signatures(heap, arguments[1]);
        else
            program.Takes = Taken(heap, arguments[1]);
        return IntrinsicResult.Completed();
    }

    /// <summary>
    /// Reserves a local in the body being built and hands back the slot it was given.
    /// </summary>
    private static IntrinsicResult Reserve(
        StaticHeap heap,
        ModuleDef? within,
        IReadOnlyList<StaticValue> arguments)
    {
        if (!TryProgram(heap, arguments[0], out var program) || program is null)
            return IntrinsicResult.Invalid("A local was declared with no method to hold it.");
        if (!heap.TryAllocateObject("System.Reflection.Emit.LocalBuilder", out var local))
            return IntrinsicResult.Invalid("Could not allocate a local builder.");
        heap.TrySetModelValue(local, Held, program.Locals.Count);
        var declared = Signatures(heap, arguments[1], within) ?? Placeholder;
        heap.TrySetModelValue(local, Holds, declared);
        program.Locals.Add(declared);
        return IntrinsicResult.Completed(local);
    }

    /// <summary>
    /// The method a builder, or a generator over one, is filling in.
    /// </summary>
    private static bool TryProgram(StaticHeap heap, StaticValue builder, out Program? program) =>
        heap.TryGetModelValue(builder, Built, out program) && program is not null ||
        heap.TryGetModelValue(builder, Owner, out StaticValue owning) &&
            heap.TryGetModelValue(owning, Built, out program) &&
            program is not null;

    /// <summary>
    /// The parameter types an array of types names, keeping a slot for each.
    /// </summary>
    /// <remarks>
    /// Every declared parameter gets a slot even when its type cannot be named here. The body loads
    /// arguments by position, so dropping one would silently shift every argument after it and hand
    /// the callee the wrong values.
    /// </remarks>
    private static List<TypeSig> Taken(StaticHeap heap, StaticValue types)
    {
        var takes = new List<TypeSig>();
        if (!heap.TryGetLength(types, out var count))
            return takes;
        for (var index = 0; index < count; index++)
        {
            takes.Add(
                heap.TryReadArray(types, index, out var element) &&
                Signatures(heap, element) is { } parameter
                    ? parameter
                    : Placeholder);
        }

        return takes;
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
    ///
    /// What the lookup cannot supply is whether the method is called on an instance and whether it
    /// hands anything back, and both of those decide how a call to it leaves the stack. The
    /// framework running this process says so, and is the same framework the protected program was
    /// built against. Where it does not recognize the member the reference is still handed back, but
    /// as one whose shape was assumed rather than read, which is a difference that matters to a
    /// caller assembling a body around it.
    /// </remarks>
    internal static IMemberRef? Bind(
        IntrinsicContext context,
        string lookup,
        string memberName,
        IReadOnlyList<StaticValue> arguments,
        out bool confirmed)
    {
        confirmed = false;
        var heap = context.State.Heap;
        if (context.State.ModuleMetadata is not { } module ||
            Signatures(heap, arguments[0], module) is not { } declaring)
        {
            return null;
        }

        if (declaring.ToTypeDefOrRef().ResolveTypeDef() is { } defined)
        {
            if (lookup == "GetField")
                return defined.FindField(memberName);
            var found = defined.FindMethod(memberName);
            confirmed = found is not null;
            return found;
        }

        if (lookup == "GetField" || !TryTaken(heap, arguments, out var takes))
            return null;
        var assumed = new MemberRefUser(
            module,
            memberName,
            MethodSig.CreateStatic(module.CorLibTypes.Object, [.. takes]),
            declaring.ToTypeDefOrRef());
        if (LoaderFrameworkIntrinsic.Framework(assumed) is not { } present)
            return assumed;
        confirmed = true;
        var returns = present is System.Reflection.MethodInfo answering
            ? Describes(module, answering.ReturnType)
            : module.CorLibTypes.Void;
        return new MemberRefUser(
            module,
            memberName,
            present.IsStatic
                ? MethodSig.CreateStatic(returns, [.. takes])
                : MethodSig.CreateInstance(returns, [.. takes]),
            declaring.ToTypeDefOrRef());
    }

    /// <summary>
    /// The parameter types a lookup narrowed itself by, wherever it put them.
    /// </summary>
    /// <remarks>
    /// The lookup overloads differ in what comes before the parameter types — binding flags, a
    /// binder, modifiers — so the array is found by what it holds rather than by where it sits. A
    /// lookup by name alone narrows itself by nothing, which is not a failure to read it.
    /// </remarks>
    private static bool TryTaken(
        StaticHeap heap,
        IReadOnlyList<StaticValue> arguments,
        out List<TypeSig> takes)
    {
        takes = [];
        for (var index = arguments.Count - 1; index >= 1; index--)
        {
            if (!heap.TryGetArrayElementType(arguments[index], out var element) ||
                element != "System.Type")
                continue;
            if (!heap.TryGetLength(arguments[index], out var count))
                return false;
            for (var at = 0; at < count; at++)
            {
                if (!heap.TryReadArray(arguments[index], at, out var parameter) ||
                    Signatures(heap, parameter) is not { } named)
                    return false;
                takes.Add(named);
            }

            return true;
        }

        return true;
    }

    /// <summary>
    /// The signature this module would use for a type the framework named.
    /// </summary>
    private static TypeSig Describes(ModuleDef module, Type described)
    {
        var corlib = module.CorLibTypes;
        if (described.IsArray && described.GetElementType() is { } element)
            return new SZArraySig(Describes(module, element));
        return described.FullName switch
        {
            "System.Void" => corlib.Void,
            "System.Boolean" => corlib.Boolean,
            "System.Char" => corlib.Char,
            "System.SByte" => corlib.SByte,
            "System.Byte" => corlib.Byte,
            "System.Int16" => corlib.Int16,
            "System.UInt16" => corlib.UInt16,
            "System.Int32" => corlib.Int32,
            "System.UInt32" => corlib.UInt32,
            "System.Int64" => corlib.Int64,
            "System.UInt64" => corlib.UInt64,
            "System.Single" => corlib.Single,
            "System.Double" => corlib.Double,
            "System.String" => corlib.String,
            "System.Object" => corlib.Object,
            "System.IntPtr" => corlib.IntPtr,
            "System.UIntPtr" => corlib.UIntPtr,
            _ => new TypeRefUser(
                    module,
                    described.Namespace ?? string.Empty,
                    described.Name,
                    corlib.AssemblyRef)
                .ToTypeSig()
        };
    }

    internal static TypeSig? Signatures(
        StaticHeap heap,
        StaticValue type,
        ModuleDef? within = null)
    {
        if (heap.TryGetModelValue<object>(type, "Metadata", out var metadata))
        {
            var read = metadata switch
            {
                TypeSig signature => signature,
                ITypeDefOrRef named => named.ToTypeSig(),
                _ => null
            };
            if (read is not null)
                return read;
        }

        // A type the machine holds only by name still names something, and a reference built from
        // the name is what everything downstream matches on. Where the name came from a file the
        // metadata above answered already, so this is the framework's types arriving as text.
        return within is not null &&
            heap.TryGetModelValue(type, "TypeName", out string? spelled) && spelled is not null
                ? Denoting(spelled, within)
                : null;
    }

    /// <summary>
    /// The type a name denotes, as a signature this module can carry.
    /// </summary>
    /// <remarks>
    /// The shape of the name is followed rather than looked up whole: an array of something, a
    /// reference to something, a generic over something. Each part is then a type the file defines
    /// or one it does not, and the second becomes a reference out of the module, which is what the
    /// machine matches calls and casts on.
    /// </remarks>
    internal static TypeSig? Denoting(string spelled, ModuleDef within)
    {
        if (spelled.Length == 0)
            return null;
        if (spelled.EndsWith("[]", StringComparison.Ordinal))
            return Denoting(spelled[..^2], within) is { } element ? new SZArraySig(element) : null;
        if (spelled.EndsWith('&'))
            return Denoting(spelled[..^1], within) is { } referenced
                ? new ByRefSig(referenced)
                : null;
        if (spelled.EndsWith('*'))
            return Denoting(spelled[..^1], within) is { } pointed ? new PtrSig(pointed) : null;
        var open = spelled.IndexOf('<', StringComparison.Ordinal);
        if (open < 0)
            return Denoted(spelled, within);
        if (!spelled.EndsWith('>') || Denoted(spelled[..open], within) is not ClassOrValueTypeSig
            template)
        {
            return null;
        }

        var supplied = new List<TypeSig>();
        var depth = 0;
        var start = open + 1;
        for (var index = start; index < spelled.Length; index++)
        {
            switch (spelled[index])
            {
                case '<':
                    depth++;
                    break;
                case '>' when depth > 0:
                    depth--;
                    break;
                case ',' when depth == 0:
                case '>' when depth == 0:
                    if (Denoting(spelled[start..index], within) is not { } argument)
                        return null;
                    supplied.Add(argument);
                    start = index + 1;
                    break;
                default:
                    break;
            }
        }

        return supplied.Count == 0 ? null : new GenericInstSig(template, supplied);
    }

    /// <summary>
    /// The type of a plain name: the definition where the module has one, and otherwise a
    /// reference out of it.
    /// </summary>
    private static TypeSig? Denoted(string spelled, ModuleDef within)
    {
        if (within.Find(spelled, isReflectionName: false) is { } defined)
            return defined.ToTypeSig();
        TypeRefUser? reference = null;
        foreach (var part in spelled.Split('/'))
        {
            var separator = reference is null ? part.LastIndexOf('.') : -1;
            reference = reference is null
                ? new TypeRefUser(
                    within,
                    separator < 0 ? string.Empty : part[..separator],
                    part[(separator + 1)..],
                    within.CorLibTypes.AssemblyRef)
                : new TypeRefUser(within, string.Empty, part, reference);
        }

        if (reference is null)
            return null;
        return LoaderFrameworkIntrinsic.WellKnown(spelled, within) is { IsValueType: true }
            ? new ValueTypeSig(reference)
            : new ClassSig(reference);
    }

    /// <summary>
    /// Appends one emitted instruction to the body being built.
    /// </summary>
    /// <remarks>
    /// What an operand means is settled by the overload the program called rather than by what the
    /// value looks like, because the same integer stands for a constant in one overload and a
    /// local's position in another.
    /// </remarks>
    private static IntrinsicResult Record(
        StaticHeap heap,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        if (!TryProgram(heap, arguments[0], out var program) || program is null)
            return IntrinsicResult.Invalid("Emit was called on a generator with no method.");
        if (arguments.Count < 2 ||
            !heap.TryGetModelValue(arguments[1], "OpCode", out string? opcode) ||
            opcode is null)
        {
            return IntrinsicResult.Invalid("Emit was given an opcode the machine does not know.");
        }

        if (arguments.Count == 2)
        {
            program.Body.Add((opcode, null));
            return IntrinsicResult.Completed();
        }

        var handed = arguments[2];
        object? operand;
        switch (method.MethodSig?.Params is { Count: 2 } declared ? declared[1].FullName : null)
        {
            case "System.Reflection.Emit.Label" when handed.IsInteger:
                operand = new Marker(handed.AsInt32());
                break;
            case "System.Reflection.Emit.LocalBuilder":
                operand = heap.TryGetModelValue(handed, Held, out int position)
                    ? new Position(position)
                    : null;
                break;
            case "System.String":
                operand = heap.TryGetString(handed, out var literal) ? literal : null;
                break;
            case "System.Int64" when handed.IsInteger:
                operand = handed.AsInt64();
                break;
            case "System.Single" when handed.IsKnown:
                operand = (float)handed.AsFloat64();
                break;
            case "System.Double" when handed.IsKnown:
                operand = handed.AsFloat64();
                break;
            case "System.Byte" or "System.SByte" or "System.Int16" or "System.Int32"
                when handed.IsInteger:
                operand = handed.AsInt32();
                break;
            // An instruction that names a type takes whatever the machine can say the type is: the
            // metadata where the type came out of a file, and a reference built from its name where
            // the program reached it by name alone.
            case "System.Type":
                operand = Signatures(heap, handed, method.Module)?.ToTypeDefOrRef();
                break;
            default:
                operand = heap.TryGetModelValue<object>(handed, Emitted, out var written) &&
                    written is not null
                        ? written
                        : heap.TryGetModelValue<object>(handed, "Metadata", out var referenced)
                            ? referenced
                            : null;
                // What the machine describes a framework member with is not something an
                // instruction can name, so the reference is built from it here.
                var known = false;
                if (operand is not (null or IMethod or IField or ITypeDefOrRef or TypeSig) &&
                    method.Module is { } assembling &&
                    LoaderFrameworkIntrinsic.Referencing(operand, assembling) is { } spelled)
                {
                    operand = spelled;
                    known = true;
                }

                // A call assembled around a reference whose shape the machine had to assume would
                // pop the wrong number of values, and every instruction after it would run on
                // whatever was left underneath them. That is a wrong answer rather than a refused
                // one, so the assumption is refused here instead. A reference built just above out
                // of the framework's own reflection was read rather than assumed.
                if (operand is IMethod and not MethodDef && !known &&
                    !(heap.TryGetModelValue(handed, Confirmed, out bool confirmed) && confirmed))
                {
                    return IntrinsicResult.Invalid(
                        $"Emit {opcode} was given {operand}, whose shape is not confirmed.");
                }

                break;
        }

        if (operand is null)
            return IntrinsicResult.Invalid(
                $"Emit {opcode} was given an unmodeled operand{Naming(heap, handed)}.");
        program.Body.Add((opcode, operand));
        return IntrinsicResult.Completed();
    }

    /// <summary>
    /// What a member model says about itself, for a message about not being able to use it.
    /// </summary>
    private static string Naming(StaticHeap heap, StaticValue model)
    {
        if (!heap.TryGetModelValue(model, "MemberName", out string? member) || member is null)
            return string.Empty;
        heap.TryGetModelValue(model, "DeclaringType", out StaticValue declaring);
        return heap.TryGetModelValue(declaring, "TypeName", out string? owner) && owner is not null
            ? $" ({owner}::{member})"
            : $" ({member})";
    }

    /// <summary>
    /// Assembles the emitted instructions into a body and hands back a delegate over it.
    /// </summary>
    private static IntrinsicResult Bind(
        IntrinsicContext context,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (!heap.TryGetModelValue<Program>(arguments[0], Built, out var program) || program is null)
            return IntrinsicResult.Invalid("A delegate was asked for over a method with no body.");
        var host = Scratch("Method");
        if (!TryAssemble(program, host, out var assembled, out var refusal) || assembled is null)
            return IntrinsicResult.Invalid(
                $"The emitted instructions do not form a runnable body: {refusal}.");

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
    /// Closes a built type, turning every method defined on it into one the machine can run.
    /// </summary>
    /// <remarks>
    /// The created type is what the program calls into afterwards, and it calls in by name, so the
    /// model carries the assembled type as its metadata: a lookup for a member on it then reaches
    /// the same definition a lookup on any other type reaches, and the interpreter runs it the same
    /// way.
    /// </remarks>
    private static IntrinsicResult Close(IntrinsicContext context, StaticValue builder)
    {
        var heap = context.State.Heap;
        if (!heap.TryGetModelValue<List<StaticValue>>(builder, Members, out var members) ||
            members is null)
        {
            return IntrinsicResult.Invalid("A type was created that was never opened.");
        }

        heap.TryGetModelValue(builder, Spelling, out string? spelled);
        var host = Scratch(spelled ?? "Emitted");
        foreach (var member in members)
        {
            if (!heap.TryGetModelValue<Program>(member, Built, out var program) || program is null)
                return IntrinsicResult.Invalid("A method was defined that was never built.");
            if (!TryAssemble(program, host, out _, out var refusal))
                return IntrinsicResult.Invalid(
                    $"The instructions emitted into {program.Name} do not form a runnable body:" +
                    $" {refusal}.");
        }

        if (!heap.TryAllocateObject("System.Type", out var created))
            return IntrinsicResult.Invalid("Could not allocate the created type.");
        heap.TrySetModelValue(created, "TypeName", host.FullName);
        heap.TrySetModelValue(created, "Metadata", host);
        return IntrinsicResult.Completed(created);
    }

    /// <summary>
    /// Turns one boundary of a protected region into the instructions the boundary implies.
    /// </summary>
    /// <remarks>
    /// A generator writes the leaving and the ending of a handler for the program: control that
    /// runs off the end of a try goes to the instruction after the whole region, and a finally
    /// ends by handing control back. Those are real instructions in the body the runtime builds,
    /// so they are real instructions here too, which is what lets the machine walk the normal path
    /// through a using block the way the program's own code would.
    /// </remarks>
    private static bool Bound(
        Region bound,
        CilBody body,
        Stack<(int Ends, int Start)> opened,
        List<(string Kind, ITypeDefOrRef? Caught, int TryStart, int TryEnd, int HandlerStart, int HandlerEnd)> regions,
        List<(Instruction Branch, int Label)> branches,
        Dictionary<int, int> placed)
    {
        switch (bound.Kind)
        {
            case "try":
                opened.Push((bound.Ends, body.Instructions.Count));
                return true;
            case "catch" or "finally":
            {
                if (opened.Count == 0)
                    return false;
                var (ends, start) = opened.Peek();
                // Control that runs off the end of a try leaves the region, and where it lands is
                // the label the region hands out. The handler begins after that instruction, and
                // where it ends is only known once the region is closed.
                body.Instructions.Add(Leaving(branches, ends));
                var handler = body.Instructions.Count;
                regions.Add((bound.Kind, bound.Caught, start, handler, handler, -1));
                return true;
            }

            case "end":
            {
                if (opened.Count == 0)
                    return false;
                var (ends, _) = opened.Pop();
                var at = regions.FindLastIndex(region => region.HandlerEnd < 0);
                if (at < 0)
                    return false;
                body.Instructions.Add(regions[at].Kind == "finally"
                    ? Instruction.Create(OpCodes.Endfinally)
                    : Leaving(branches, ends));
                var after = Instruction.Create(OpCodes.Nop);
                body.Instructions.Add(after);
                placed[ends] = body.Instructions.Count - 1;
                var closing = regions[at];
                regions[at] = closing with { HandlerEnd = body.Instructions.Count - 1 };
                return true;
            }

            default:
                return false;
        }
    }

    /// <summary>A leave whose target is filled in once the label it names is placed.</summary>
    private static Instruction Leaving(List<(Instruction Branch, int Label)> branches, int label)
    {
        var leaving = Instruction.Create(OpCodes.Leave, Instruction.Create(OpCodes.Nop));
        branches.Add((leaving, label));
        return leaving;
    }

    /// <summary>
    /// A type to assemble emitted methods into, in a module of its own.
    /// </summary>
    /// <remarks>
    /// The assembled methods deliberately do not join the module under analysis. That module is
    /// evidence and the machine never writes to it, so the bodies live in a scratch module and the
    /// interpreter is told to treat calls out of it as calls within the subject.
    /// </remarks>
    private static TypeDefUser Scratch(string name)
    {
        var scratch = new ModuleDefUser("<emitted>");
        var host = new TypeDefUser("<emitted>", name, scratch.CorLibTypes.Object.TypeDefOrRef);
        scratch.Types.Add(host);
        return host;
    }

    /// <summary>
    /// Builds a real method out of emitted instructions.
    /// </summary>
    private static bool TryAssemble(
        Program program,
        TypeDef host,
        out MethodDef? assembled,
        out string? refusal)
    {
        assembled = null;
        refusal = null;
        var corlib = host.Module.CorLibTypes;
        var returns = program.Returns ?? corlib.Void;
        TypeSig[] takes = [.. program.Takes];
        var method = new MethodDefUser(
            program.Name,
            program.IsStatic
                ? MethodSig.CreateStatic(returns, takes)
                : MethodSig.CreateInstance(returns, takes),
            MethodImplAttributes.IL,
            program.IsStatic
                ? MethodAttributes.Public | MethodAttributes.Static
                : MethodAttributes.Public);
        host.Methods.Add(method);
        var body = new CilBody { InitLocals = true };
        method.Body = body;
        method.Parameters.UpdateParameterTypes();
        foreach (var declared in program.Locals)
            body.Variables.Add(new Local(declared));

        var placed = new Dictionary<int, int>();
        var branches = new List<(Instruction Branch, int Label)>();
        var opened = new Stack<(int Ends, int Start)>();
        var regions = new List<(string Kind, ITypeDefOrRef? Caught, int TryStart, int TryEnd, int HandlerStart, int HandlerEnd)>();
        foreach (var (name, operand) in program.Body)
        {
            if (name == Placed)
            {
                if (operand is not Marker marker)
                {
                    refusal = "a label was placed that names no label";
                    return false;
                }

                placed[marker.Id] = body.Instructions.Count;
                continue;
            }

            if (name == Bounded)
            {
                if (operand is not Region bound ||
                    !Bound(bound, body, opened, regions, branches, placed))
                {
                    refusal = "a protected region is not marked out in a way that closes";
                    return false;
                }

                continue;
            }

            if (!Opcodes.TryGetValue(name, out var opcode))
            {
                refusal = $"the machine has no {name} to assemble";
                return false;
            }

            if (Assemble(opcode, operand, method, body) is not { } instruction)
            {
                refusal = $"{name} could not be assembled around {operand ?? "nothing"}";
                return false;
            }

            if (operand is Marker branched)
                branches.Add((instruction, branched.Id));
            body.Instructions.Add(instruction);
        }

        // A region that was begun and never ended describes no handler, and a body carrying half a
        // handler is worse than none: the machine would read a try with no way out of it.
        if (opened.Count != 0)
        {
            refusal = "a protected region was begun and never ended";
            return false;
        }

        foreach (var (kind, caught, tryStart, tryEnd, handlerStart, handlerEnd) in regions)
        {
            if (tryEnd >= body.Instructions.Count || handlerEnd >= body.Instructions.Count)
            {
                refusal = "a protected region reaches past the end of the body";
                return false;
            }

            body.ExceptionHandlers.Add(new ExceptionHandler(
                kind == "catch" ? ExceptionHandlerType.Catch : ExceptionHandlerType.Finally)
            {
                TryStart = body.Instructions[tryStart],
                TryEnd = body.Instructions[tryEnd],
                HandlerStart = body.Instructions[handlerStart],
                HandlerEnd = body.Instructions[handlerEnd],
                CatchType = kind == "catch" ? caught : null
            });
        }

        // A branch can only be pointed at its target once every instruction is in place. A label
        // that was branched to but never placed, or placed past the end, leaves the body without
        // anywhere to go, which is not a body.
        foreach (var (branch, label) in branches)
        {
            if (!placed.TryGetValue(label, out var at) || at >= body.Instructions.Count)
            {
                refusal = $"a branch names label {label}, which is nowhere in the body";
                return false;
            }

            branch.Operand = body.Instructions[at];
        }

        body.UpdateInstructionOffsets();
        assembled = method;
        return true;
    }

    /// <summary>
    /// One emitted instruction, holding its operand in the form its own opcode calls for.
    /// </summary>
    /// <remarks>
    /// The program hands an operand over as whatever the <c>Emit</c> overload it called takes, which
    /// is not always the form the instruction holds: a local arrives as a builder or as a bare
    /// position, and both mean the slot at that position in the body being built.
    /// </remarks>
    private static Instruction? Assemble(
        OpCode opcode,
        object? operand,
        MethodDef method,
        CilBody body)
    {
        switch (opcode.OperandType)
        {
            case OperandType.InlineNone:
                return operand is null ? Holding(opcode, null) : null;
            case OperandType.InlineVar:
            case OperandType.ShortInlineVar:
            {
                var index = operand switch
                {
                    Position position => position.Index,
                    int number => number,
                    _ => -1
                };
                if (index < 0)
                    return null;
                if (opcode.Code is Code.Ldloc or Code.Ldloc_S or Code.Ldloca or Code.Ldloca_S or
                    Code.Stloc or Code.Stloc_S)
                {
                    return index < body.Variables.Count
                        ? Holding(opcode, body.Variables[index])
                        : null;
                }

                return index < method.Parameters.Count
                    ? Holding(opcode, method.Parameters[index])
                    : null;
            }

            case OperandType.ShortInlineI:
                return operand is not int narrow
                    ? null
                    : Holding(
                        opcode,
                        opcode.Code == Code.Ldc_I4_S ? (sbyte)narrow : (byte)narrow);
            case OperandType.InlineI:
                return operand is int immediate ? Holding(opcode, immediate) : null;
            case OperandType.InlineI8:
                return operand is long wide ? Holding(opcode, wide) : null;
            case OperandType.ShortInlineR:
                return operand is float single ? Holding(opcode, single) : null;
            case OperandType.InlineR:
                return operand is double real ? Holding(opcode, real) : null;
            case OperandType.InlineString:
                return operand is string literal ? Holding(opcode, literal) : null;
            case OperandType.InlineMethod:
                return operand is IMethod called ? Holding(opcode, called) : null;
            case OperandType.InlineField:
                return operand is IField accessed ? Holding(opcode, accessed) : null;
            case OperandType.InlineType:
            case OperandType.InlineTok:
                return operand switch
                {
                    ITypeDefOrRef named => Holding(opcode, named),
                    TypeSig described => Holding(opcode, described.ToTypeDefOrRef()),
                    IMethod token => Holding(opcode, token),
                    IField field => Holding(opcode, field),
                    _ => null
                };
            case OperandType.InlineBrTarget:
            case OperandType.ShortInlineBrTarget:
                // Where it branches to is filled in once the instruction its label marks is known.
                return operand is Marker ? Holding(opcode, null) : null;
            default:
                return null;
        }
    }

    private static Instruction Holding(OpCode opcode, object? operand) =>
        new(opcode) { Operand = operand };

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
            method.Name.String is "Copy" or "CopyTo" or "Clear" or "Reverse" or "CreateInstance"
                or "Clone" or "SetValue" or "GetValue" or "get_Length" or "get_LongLength"
                or "get_Rank") ||
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

        // Copying is one operation written three ways: as a static call with a count, as a static
        // call with two arrays, and as a method on the array that says where in the destination to
        // start. The last one takes its count from the source, which is the only difference.
        if (method.Name.String is "Copy" or "BlockCopy" or "CopyTo" && arguments.Count is 2 or 3 or 5)
        {
            var wholeArray = method.Name.String == "CopyTo";
            if (wholeArray && arguments.Count != 3)
                return IntrinsicResult.Invalid($"Unsupported Array overload {method.FullName}.");
            var source = arguments[0];
            var sourceIndex = arguments.Count == 3 ? 0 : arguments[1].AsInt32();
            var destination = arguments.Count == 3 ? arguments[1] : arguments[2];
            var destinationIndex = wholeArray
                ? arguments[2].AsInt32()
                : arguments.Count == 3 ? 0 : arguments[3].AsInt32();
            if (wholeArray && !heap.TryGetLength(source, out _))
                return IntrinsicResult.Invalid("Array.CopyTo was asked of a non-array.");
            var count = wholeArray
                ? heap.TryGetLength(source, out var whole) ? whole : -1
                : arguments[^1].AsInt32();
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

    /// <summary>
    /// The profile key naming the runtime library the process is modelled as having loaded.
    /// </summary>
    /// <remarks>
    /// Reactor walks its own process modules looking for the jitter it means to hook, so which
    /// module is there decides whether it finds one. That makes it a fact about the machine rather
    /// than about the sample, which is why the profile holds it.
    /// </remarks>
    private const string RuntimeModuleName = "runtime:ModuleName";

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
        "System.Reflection.PropertyInfo",
        "System.Attribute",
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
        ,"System.Security.Cryptography.X509Certificates.X509Certificate"
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
        "System.Security.Cryptography.X509Certificates.X509Certificate2" =>
            "System.Security.Cryptography.X509Certificates.X509Certificate",
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
        // Two base constructors that do nothing an interpretation can see. An attribute's own
        // constructor chains to the second on its first instruction, so every attribute a program
        // reads about itself arrives here.
        if (type is "System.Object" or "System.Attribute" && name == ".ctor")
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
        // ToString is decided by the receiver too, and a call site holding something as an object
        // spells it through this type. That is the shape a string concatenation takes after the
        // compiler has boxed what it was given, so it is on the ordinary path rather than a corner.
        if (type == "System.Object" && name == "ToString" && arguments.Count == 1)
            return ObjectText(context, method, arguments);
        // Equality asked of an object rather than of a type. What it means depends on the object:
        // the same one is equal to itself, two strings or two boxed numbers are equal when their
        // contents are, a type is equal to a type of the same name, and anything that wrote its own
        // Equals is asked its own question. What is left inherits the default, which is identity,
        // and identity has already been ruled out by this point.
        if (type is "System.Object" or "System.ValueType" &&
            name is "Equals" or "ReferenceEquals" && arguments.Count == 2)
            return ObjectEquality(context, name == "ReferenceEquals", arguments);
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
            "System.Reflection.PropertyInfo" or
            "System.Attribute" or
            "System.Delegate" or "System.MulticastDelegate")
            return InvokeMetadata(context, type, name, arguments);
        if (type == "System.String")
            return InvokeString(context, method, name, arguments);
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
        if (type == "System.Security.Cryptography.X509Certificates.X509Certificate")
            return InvokeCertificate(context, name, arguments);
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

    /// <summary>The intrinsic answering for objects whose text is their buffer's contents.</summary>
    private static readonly StringBuilderIntrinsic Builders = new();

    /// <summary>
    /// What an object reads as, for the objects whose text this machine can know.
    /// </summary>
    /// <remarks>
    /// The default <c>ToString</c> writes a type name, which is a fact about metadata and could be
    /// answered for anything; it is not, because a type that overrides the method has its own body
    /// and answering with the base version would put a plausible wrong string into whatever reads
    /// it next. So only the objects modeled here answer, and the rest stop.
    /// </remarks>
    private static IntrinsicResult ObjectText(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        var receiver = arguments[0];
        if (heap.TryGetString(receiver, out _))
            return IntrinsicResult.Completed(receiver);
        if (!heap.TryGetRuntimeTypeName(receiver, out var runtime))
            return IntrinsicResult.Invalid("The object asked for its text has no known type.");
        if (runtime == "System.Text.StringBuilder")
            return Builders.Invoke(context, method, arguments);
        if (heap.TryUnbox(receiver, out var boxed) &&
            BoxedText.TryRender(runtime, boxed, out var rendered))
        {
            return heap.TryAllocateString(rendered, out var text)
                ? IntrinsicResult.Completed(text)
                : AllocationFailure("rendered text");
        }

        if (runtime == "System.Type" &&
            heap.TryGetModelValue(receiver, "TypeName", out string? spelled) &&
            spelled is not null)
        {
            return heap.TryAllocateString(spelled, out var named)
                ? IntrinsicResult.Completed(named)
                : AllocationFailure("type name");
        }

        return IntrinsicResult.Invalid($"What a {runtime} reads as is not known.");
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
        // The application domain doubles as somewhere to leave a value for later, and a runtime that
        // works something out once and then wants it again uses it as exactly that. Storing a value
        // and reading it back is the whole of the behaviour, so it is modeled as the association it
        // is — and a slot nothing was left in reads as nothing, which is what the framework says too.
        if (name is "SetData" or "GetData" && arguments.Count >= 2 &&
            context.State.Heap.TryGetString(arguments[1], out var slot))
        {
            var heap = context.State.Heap;
            if (name == "GetData")
            {
                return IntrinsicResult.Completed(
                    heap.TryGetModelValue(arguments[0], $"Data:{slot}", out StaticValue stored)
                        ? stored
                        : StaticValue.Null);
            }

            if (arguments.Count < 3)
                return IntrinsicResult.Invalid("AppDomain.SetData was given nothing to store.");
            return heap.TrySetModelValue(arguments[0], $"Data:{slot}", arguments[2])
                ? IntrinsicResult.Completed()
                : IntrinsicResult.Invalid("Application-domain data is not modeled.");
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
            // A name asked for by hand often carries the assembly it lives in, and everything that
            // compares types afterwards compares the type's own name. Keeping the qualification
            // would make the same type answer to two names, so the identity is the name alone.
            var bare = Unqualify(typeName);
            if (!heap.TryAllocateType(bare, out var runtimeType))
                return AllocationFailure("runtime type");
            AttachDefinition(context, runtimeType, bare);
            return IntrinsicResult.Completed(runtimeType);
        }
        // A query written without flags is the same query with the framework's own default: every
        // public member, whether it belongs to an instance or to the type.
        const int publicInstanceAndStatic = 0x1C;
        // A constructor is looked up the same way as any other member, minus the name: there is only
        // one name it could be asking for.
        if (type == "System.Type" &&
            name is "GetField" or "GetMethod" or "GetConstructor" &&
            arguments.Count >= 2 &&
            (name == "GetConstructor"
                ? ".ctor"
                : heap.TryGetString(arguments[1], out var asked) ? asked : null)
                is { } memberName)
        {
            var memberType = name switch
            {
                "GetField" => "System.Reflection.FieldInfo",
                "GetConstructor" => "System.Reflection.ConstructorInfo",
                _ => "System.Reflection.MethodInfo"
            };
            // A type whose members can be read answers for itself, and part of that answer is that
            // it has no such member. Handing back something for a name nothing answers to would
            // tell a program that asked whether a method exists that it does, which is how a
            // serializer comes to look for a hook that was never written.
            var listing = name switch
            {
                "GetField" => "GetFields",
                "GetConstructor" => "GetConstructors",
                _ => "GetMethods"
            };
            var flags = arguments[1].Kind == StaticValueKind.Int32
                ? arguments[1].AsInt32()
                : arguments.Count >= 3 && arguments[2].Kind == StaticValueKind.Int32
                    ? arguments[2].AsInt32()
                    : publicInstanceAndStatic;
            var declared = Members(context, listing, arguments[0], flags);
            var sole = declared is null ? null : Sole(heap, declared, memberName, arguments);
            if (declared is not null && sole is null)
                return IntrinsicResult.Completed(StaticValue.Null);
            if (!heap.TryAllocateObject(memberType, out var member))
                return AllocationFailure("runtime member");
            heap.TrySetModelValue(member, "MemberName", memberName);
            heap.TrySetModelValue(member, "DeclaringType", arguments[0]);
            // What the member is gets described by whatever knows the most about it: the definition
            // where the walk above found one, and otherwise the reference the lookup can be turned
            // into. A definition found in a file is the member itself, so nothing about a call to
            // it is assumed.
            if (sole is not null)
                heap.TrySetModelValue(member, "Metadata", sole);
            if (sole is IMemberDef)
            {
                heap.TrySetModelValue(member, ReflectionEmitIntrinsic.Confirmed, true);
            }
            else if (sole is not null && context.State.ModuleMetadata is { } owning &&
                Referencing(sole, owning) is { } read)
            {
                heap.TrySetModelValue(member, ReflectionEmitIntrinsic.Emitted, read);
                heap.TrySetModelValue(member, ReflectionEmitIntrinsic.Confirmed, true);
            }
            else if (ReflectionEmitIntrinsic.Bind(
                context,
                name,
                memberName,
                arguments,
                out var confirmed) is { } bound)
            {
                heap.TrySetModelValue(
                    member,
                    sole is null ? "Metadata" : ReflectionEmitIntrinsic.Emitted,
                    bound);
                heap.TrySetModelValue(member, ReflectionEmitIntrinsic.Confirmed, confirmed);
            }

            return IntrinsicResult.Completed(member);
        }
        // Binding a delegate reflectively reaches the same state a delegate constructor would, so
        // it is modeled as what it produces rather than refused for arriving by another route.
        if (type is "System.Delegate" or "System.MulticastDelegate" &&
            name == "CreateDelegate" && arguments.Count is 2 or 3 &&
            Callable(heap, arguments[^1]) is { } boundMethod)
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
        if (type == "System.Type" &&
            name is "GetFields" or "GetProperties" or "GetMethods" or "GetConstructors"
                or "GetMembers" or "GetEvents" or "GetNestedTypes" &&
            (arguments.Count == 1 ||
                (arguments.Count == 2 && arguments[1].Kind == StaticValueKind.Int32)) &&
            Members(
                context,
                name,
                arguments[0],
                arguments.Count == 2 ? arguments[1].AsInt32() : publicInstanceAndStatic) is
                { } selected)
        {
            var listed = selected.ToArray();
            if (!heap.TryAllocateArray(null, listed.Length, out var members))
                return AllocationFailure("member array");
            for (var index = 0; index < listed.Length; index++)
            {
                if (!heap.TryWriteArray(
                        members,
                        index,
                        Modeling(context, listed[index], arguments[0])))
                    return AllocationFailure("member model");
            }

            return IntrinsicResult.Completed(members);
        }
        // Asking for one member by name is the same query narrowed, so it is answered from the same
        // walk rather than from a model built out of the name alone: what comes back has to know
        // its own type and the method behind it, which only the metadata can say. A name nothing
        // answers to is null, which is what the framework hands back and what the caller is
        // written to expect.
        if (type == "System.Type" &&
            name is "GetProperty" or "GetEvent" or "GetNestedType" &&
            arguments.Count is 2 or 3 &&
            (arguments.Count == 2 || arguments[2].Kind == StaticValueKind.Int32) &&
            heap.TryGetString(arguments[1], out var soleName))
        {
            if (Members(
                    context,
                    name + (name == "GetProperty" ? "s" : name == "GetEvent" ? "s" : "es"),
                    arguments[0],
                    arguments.Count == 3 ? arguments[2].AsInt32() : publicInstanceAndStatic) is not
                    { } candidates)
            {
                heap.TryGetModelValue(arguments[0], "TypeName", out string? searched);
                return IntrinsicResult.Invalid(
                    $"What {soleName} is on {searched ?? "this type"} cannot be read from what" +
                    " is here.");
            }

            var sole = candidates.FirstOrDefault(
                candidate => Called(candidate) == soleName);
            return IntrinsicResult.Completed(
                sole is null ? StaticValue.Null : Modeling(context, sole, arguments[0]));
        }
        // Reading a property reflectively begins by asking for the method behind it, and whether a
        // non-public one counts is the caller's to say.
        if (name is "GetGetMethod" or "GetSetMethod" && arguments.Count is 1 or 2 &&
            heap.TryGetModelValue<object>(arguments[0], "Metadata", out var accessorOwner))
        {
            var alsoHidden = arguments.Count == 2 && arguments[1].AsInt32() != 0;
            var wanting = name == "GetGetMethod";
            switch (accessorOwner)
            {
                case PropertyDef property:
                    var accessor = wanting ? property.GetMethod : property.SetMethod;
                    return accessor is null || (!alsoHidden && !accessor.IsPublic)
                        ? IntrinsicResult.Completed(StaticValue.Null)
                        : Describing(heap, "System.Reflection.MethodInfo", accessor);
                case PropertyInfo present:
                    var found = wanting
                        ? present.GetGetMethod(alsoHidden)
                        : present.GetSetMethod(alsoHidden);
                    return found is null
                        ? IntrinsicResult.Completed(StaticValue.Null)
                        : Describing(heap, "System.Reflection.MethodInfo", found);
                // The accessor of a property on a generic declaration is reached the same way, and
                // carries the same substitution: what it takes and returns is said in the types the
                // constructed type supplied.
                case Bound(PropertyInfo declared, var supplied):
                    var accessing = wanting
                        ? declared.GetGetMethod(alsoHidden)
                        : declared.GetSetMethod(alsoHidden);
                    return accessing is null
                        ? IntrinsicResult.Completed(StaticValue.Null)
                        : Describing(
                            heap,
                            "System.Reflection.MethodInfo",
                            new Bound(accessing, supplied));
                default:
                    break;
            }
        }
        // Whether one type is a kind of another, asked as a question rather than performed as a
        // cast. It is the same walk the cast does, so the two cannot disagree, and a hierarchy that
        // cannot be read far enough to tell refuses rather than answering no — the program is about
        // to decide something on the strength of this.
        if (type == "System.Type" &&
            name is "IsAssignableFrom" or "IsSubclassOf" or "IsInstanceOfType" &&
            arguments.Count == 2)
        {
            var receiver = Spelling(heap, arguments[0]);
            var other = name == "IsInstanceOfType"
                ? heap.TryGetRuntimeTypeName(arguments[1], out var held) ? held : null
                : Spelling(heap, arguments[1]);
            if (name == "IsInstanceOfType" && arguments[1].Kind == StaticValueKind.Null)
                return Truth(false);
            // IsAssignableFrom and IsInstanceOfType ask whether the other type is under this one;
            // IsSubclassOf asks the reverse, and excludes the type itself.
            var (under, above) = name == "IsSubclassOf"
                ? (receiver, other)
                : (other, receiver);
            if (name == "IsSubclassOf" && string.Equals(under, above, StringComparison.Ordinal))
                return Truth(false);
            var searched = new[] { context.State.ModuleMetadata }
                .Concat(context.State.TrustedModules)
                .Where(module => module is not null)
                .Select(module => module!);
            return Ancestry.Reaches(searched, context.State.ModuleMetadata, under, above) switch
            {
                true => Truth(true),
                false => Truth(false),
                _ => IntrinsicResult.Invalid(
                    $"Whether {under ?? "an unknown type"} is a kind of {above ?? "another"}" +
                    " cannot be read from what is here.")
            };
        }
        // What a member was annotated with is written in the file next to it, and a library that
        // decides what to do by reading annotations cannot be followed without them. A type the
        // machine holds only by name is asked of the framework instead, so the name will do.
        if (name is "GetCustomAttributes" or "IsDefined" && arguments.Count >= 2 &&
            (heap.TryGetModelValue<object>(arguments[0], "Metadata", out var annotated) ||
                (heap.TryGetModelValue(arguments[0], "TypeName", out string? annotatedName) &&
                    (annotated = annotatedName) is not null)) &&
            annotated is not null)
        {
            // The overloads differ in whether a type filters the answer; the flag is last in both.
            var filter = arguments.Count >= 3 &&
                heap.TryGetModelValue<object>(arguments[1], "Metadata", out var only) &&
                only is not null
                    ? Named(only)
                    : arguments.Count >= 3 &&
                        heap.TryGetModelValue(arguments[1], "TypeName", out string? spelledFilter)
                        ? spelledFilter
                        : null;
            if (arguments[^1].Kind != StaticValueKind.Int32)
                return IntrinsicResult.Invalid($"{name} was not told whether to inherit.");
            var inherit = arguments[^1].AsInt32() != 0;
            if (name == "IsDefined")
            {
                return filter is null
                    ? IntrinsicResult.Invalid("IsDefined was not told which attribute to look for.")
                    : AttributeModel.Defines(context, annotated, inherit, filter);
            }

            return AttributeModel.Instances(context, annotated, inherit, filter);
        }
        // A property is a pair of methods, so reading one reflectively is calling its getter. Going
        // through the getter rather than around it means a property that computes something reports
        // what it computes.
        if (name is "GetValue" or "SetValue" && arguments.Count >= 2 &&
            context.Call is { } reflectively &&
            heap.TryGetModelValue<object>(arguments[0], "Metadata", out var reflected) &&
            reflected is PropertyDef viewed)
        {
            var accessor = name == "GetValue" ? viewed.GetMethod : viewed.SetMethod;
            if (accessor is null)
                return IntrinsicResult.Invalid(
                    $"{viewed.FullName} cannot be {(name == "GetValue" ? "read" : "written")}.");
            var receiver = arguments[1];
            var values = name == "GetValue"
                ? []
                : new List<StaticValue> { Unwrap(heap, arguments[2], Expects(accessor, accessor, 0)) };
            var outcome = accessor.IsStatic
                ? reflectively(accessor, values)
                : reflectively(accessor, [receiver, .. values]);
            return name == "SetValue" || outcome.Status != StaticExecutionStatus.Completed
                ? outcome
                : Boxing(heap, outcome.Value, viewed.PropertySig?.RetType);
        }
        // A runtime that resolved a member by token then asks what shape it is. Every answer is in
        // the metadata the model already carries, so describing the signature is reading the file
        // rather than assuming anything about the machine.
        if (name == "Invoke" && arguments.Count >= 2 && context.Call is { } call &&
            Callable(heap, arguments[0]) is { } called)
        {
            // MethodBase.Invoke takes the receiver first; a static target ignores it.
            return Reflectively(
                context,
                call,
                called,
                arguments.Count >= 3 ? arguments[^2] : StaticValue.Null,
                arguments[^1]);
        }
        // A type the program built for itself has no reference anything could call, so it calls in
        // by name. The name is looked up in the type the machine assembled, and from there it is the
        // same call as any other.
        if (type == "System.Type" && name == "InvokeMember" && arguments.Count >= 6 &&
            context.Call is { } through &&
            heap.TryGetString(arguments[1], out var invokedName) &&
            heap.TryGetModelValue<object>(arguments[0], "Metadata", out var hosting) &&
            hosting is TypeDef host)
        {
            return host.FindMethod(invokedName) is { } member
                ? Reflectively(context, through, member, arguments[4], arguments[5])
                : IntrinsicResult.Invalid($"{host.FullName} has no member named {invokedName}.");
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
                if (accessedField.IsStatic || instance.Kind == StaticValueKind.Null)
                    return Boxing(
                        heap,
                        context.State.ReadStaticField(accessedField),
                        accessedField.FieldType);
                return heap.TryReadField(instance, accessedField, out var read)
                    ? Boxing(heap, read, accessedField.FieldType)
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
        // Where a member was found is recorded when it is handed over, and where it was not, the
        // type that declares it is the only answer there is to give.
        if (name == "get_ReflectedType" && arguments.Count == 1)
        {
            if (heap.TryGetModelValue(arguments[0], "ReflectedType", out StaticValue searched))
                return IntrinsicResult.Completed(searched);
            name = "get_DeclaringType";
        }

        if (name is "GetParameters" or "get_ReturnType" or "get_ParameterType" or "get_DeclaringType"
                or "get_Name" or "get_IsStatic" or "get_IsAbstract" or "get_IsVirtual"
                or "get_IsPublic" or "get_IsValueType" or "get_FieldType" or "get_MetadataToken"
                or "get_IsByRef" or "get_IsPointer" or "get_IsArray" or "get_IsEnum"
                or "get_IsInterface" or "get_IsClass" or "get_IsSealed" or "get_IsPrimitive"
                or "get_IsGenericType" or "get_FullName" or "get_Namespace" or "GetElementType"
                or "GetArrayRank"
                or "get_PropertyType" or "get_CanRead" or "get_CanWrite"
                or "get_IsGenericParameter" or "get_BaseType" or "GetInterfaces"
                or "get_IsGenericTypeDefinition" or "get_ContainsGenericParameters"
                or "get_AssemblyQualifiedName" or "get_MemberType" or "GetGenericTypeDefinition"
                or "GetTypeCode"
                or "MakeByRefType" or "MakePointerType" or "MakeArrayType" &&
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
        // A type is a member like any other, and a program asking one what it is called says so
        // through the base class as often as not. What is being asked about is the receiver rather
        // than the name the call was written under, so the receiver decides where it is answered.
        if (arguments.Count == 1 &&
            type is "System.Type" or "System.Reflection.MemberInfo" &&
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
    /// Makes a reflective call, unpacking its arguments exactly as the runtime would.
    /// </summary>
    /// <remarks>
    /// Reflective invocation is a call like any other once the target is known, so it is run rather
    /// than refused. A constructor gets a fresh instance to work on and yields it.
    /// </remarks>
    private static IntrinsicResult Reflectively(
        IntrinsicContext context,
        MethodInvoker call,
        IMethod called,
        StaticValue receiver,
        StaticValue packed)
    {
        var heap = context.State.Heap;
        // The target may be defined here or merely referred to. Where there is a definition it
        // carries the parameter types and the constructor flag; where there is not, the reference's
        // own signature says the same things.
        var invokedMethod = called.ResolveMethodDef();
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

        var unbound = invokedMethod?.IsStatic ?? called.MethodSig?.HasThis != true;
        var returned = call(called, unbound ? supplied : [receiver, .. supplied]);

        return returned.Status == StaticExecutionStatus.Completed
            ? Boxing(heap, returned.Value, invokedMethod?.ReturnType ?? called.MethodSig?.RetType)
            : returned;
    }

    /// <summary>
    /// Wraps a value on its way out of a reflective read, the way the runtime does.
    /// </summary>
    /// <remarks>
    /// Reflection hands everything back as an object, so a member holding a number is read as a box
    /// around one and the caller unboxes it on the next instruction. What decides this is how the
    /// machine holds the value rather than what the member is declared as: a value the machine holds
    /// as a number is a value type whatever its type is called, which is what makes an enumeration
    /// come back boxed too rather than as a bare number the caller cannot unwrap.
    /// </remarks>
    private static IntrinsicResult Boxing(StaticHeap heap, StaticValue value, TypeSig? declared)
    {
        if (value.Kind is not (StaticValueKind.Int32 or StaticValueKind.Int64 or
            StaticValueKind.Float32 or StaticValueKind.Float64))
            return IntrinsicResult.Completed(value);
        var named = declared?.FullName ?? value.Kind switch
        {
            StaticValueKind.Int64 => "System.Int64",
            StaticValueKind.Float32 => "System.Single",
            StaticValueKind.Float64 => "System.Double",
            _ => "System.Int32"
        };
        return heap.TryAllocateBox(named, value, out var boxed)
            ? IntrinsicResult.Completed(boxed)
            : AllocationFailure("boxed value");
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
            // An array of one dimension spells itself "[]" and one of several spells the commas
            // between them, so the rank is there in the name. A type that is no array at all has
            // no rank, and the framework raises where it is asked for one; the interpretation
            // stops for the same reason rather than inventing a number.
            case "GetArrayRank" when typeName.EndsWith(']') &&
                typeName.LastIndexOf('[') is var opened && opened >= 0:
                return IntrinsicResult.Completed(
                    StaticValue.FromInt32(typeName[opened..].Count(at => at == ',') + 1));
            case "GetElementType":
                var shape = typeName.EndsWith("[]", StringComparison.Ordinal) ? 2
                    : typeName.EndsWith('&') || typeName.EndsWith('*') ? 1
                    : 0;
                return shape == 0
                    ? IntrinsicResult.Completed(StaticValue.Null)
                    : heap.TryAllocateType(typeName[..^shape], out var held)
                        ? IntrinsicResult.Completed(held)
                        : IntrinsicResult.Invalid("Could not allocate an element type.");
            // Naming the shape built around a type is the inverse of taking it apart above, and the
            // machine holds a type by its name, so each of these is the suffix the framework itself
            // spells. Code that rebuilds a call from metadata reaches for these whenever a parameter
            // is by reference or an array, and without them a signature with one is unreachable
            // however well the rest of the signature is read.
            case "MakeByRefType":
            case "MakePointerType":
            case "MakeArrayType":
                var suffix = question switch
                {
                    "MakeByRefType" => "&",
                    "MakePointerType" => "*",
                    _ => "[]"
                };
                return heap.TryAllocateType(typeName + suffix, out var built)
                    ? IntrinsicResult.Completed(built)
                    : IntrinsicResult.Invalid("Could not allocate a constructed type.");
        }

        if (WellKnown(typeName, subject) is not { } known)
        {
            return Open(typeName, subject) is var (template, supplied)
                ? DescribeOpen(heap, question, template, supplied)
                : IntrinsicResult.Invalid($"Nothing is known about the type {typeName}.");
        }

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
            "get_IsGenericParameter" => Truth(known.IsGenericParameter),
            "get_IsGenericTypeDefinition" => Truth(known.IsGenericTypeDefinition),
            "get_ContainsGenericParameters" => Truth(known.ContainsGenericParameters),
            "get_BaseType" => known.BaseType is { FullName: { } above }
                ? heap.TryAllocateType(above, out var baseType)
                    ? IntrinsicResult.Completed(baseType)
                    : AllocationFailure("base type")
                : IntrinsicResult.Completed(StaticValue.Null),
            "GetTypeCode" => IntrinsicResult.Completed(
                StaticValue.FromInt32((int)Type.GetTypeCode(known))),
            "GetInterfaces" => Listed(heap, known.GetInterfaces()),
            "GetGenericArguments" => Listed(heap, known.GetGenericArguments()),
            "GetGenericTypeDefinition" when known.IsGenericType =>
                known.GetGenericTypeDefinition().FullName is { } template &&
                    heap.TryAllocateType(template, out var made)
                        ? IntrinsicResult.Completed(made)
                        : AllocationFailure("generic type definition"),
            "get_AssemblyQualifiedName" => known.AssemblyQualifiedName is { } identity &&
                heap.TryAllocateString(identity, out var qualified)
                    ? IntrinsicResult.Completed(qualified)
                    : IntrinsicResult.Invalid("Could not allocate a type name."),
            _ => IntrinsicResult.Invalid($"Unsupported question {question} about {typeName}.")
        };
    }

    /// <summary>
    /// The <c>System.TypeCode</c> a type defined in a supplied file answers to.
    /// </summary>
    /// <remarks>
    /// The numbers are the framework's, and the framework in hand is what maps a name to one, so a
    /// type whose name it does not have is an object — which is what the framework answers for
    /// anything it does not have a code for.
    /// </remarks>
    private static int NumberedCode(TypeDef type)
    {
        const int objectCode = 1;
        var named = type.IsEnum ? type.GetEnumUnderlyingType()?.FullName : type.FullName;
        return named is not null && Type.GetType(named, throwOnError: false) is { } present
            ? (int)Type.GetTypeCode(present)
            : objectCode;
    }

    /// <summary>
    /// A run of framework types handed over as an array of types the machine holds by name.
    /// </summary>
    private static IntrinsicResult Listed(StaticHeap heap, Type[] types)
    {
        if (!heap.TryAllocateArray(null, types.Length, out var listed))
            return AllocationFailure("type array");
        for (var index = 0; index < types.Length; index++)
        {
            if (Spelled(types[index]) is not { } named ||
                !heap.TryAllocateType(named, out var model) ||
                !heap.TryWriteArray(listed, index, model))
            {
                return AllocationFailure("type model");
            }
        }

        return IntrinsicResult.Completed(listed);
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
    internal static Type? WellKnown(string typeName, ModuleDef? subject)
    {
        if (subject?.Find(typeName, isReflectionName: false) is not null)
            return null;
        if (Recognized.TryGetValue(typeName, out var known))
            return known;
        if (!typeName.StartsWith("System.", StringComparison.Ordinal) &&
            !typeName.StartsWith("Microsoft.", StringComparison.Ordinal))
            return Recognized[typeName] = null;
        if (typeName.Contains('<', StringComparison.Ordinal))
            return Recognized[typeName] = Constructed(typeName, subject);
        // Metadata separates a nested type from the one that holds it with a slash and reflection
        // with a plus, and names arrive here in both spellings.
        var asked = typeName.Replace('/', '+');
        known = Type.GetType(asked, throwOnError: false) ??
            AppDomain.CurrentDomain.GetAssemblies()
                .Select(assembly => assembly.GetType(asked, throwOnError: false))
                .FirstOrDefault(candidate => candidate is not null);
        return Recognized[typeName] = known;
    }

    /// <summary>
    /// The framework type a constructed generic name denotes, built from its parts.
    /// </summary>
    /// <remarks>
    /// A name like <c>List`1&lt;String&gt;</c> is not a name the framework can be asked for
    /// directly, and it is also the shape most questions about a collection arrive in — what a list
    /// holds, whether it can be added to. So the name is taken apart, each part looked up the same
    /// way as any other, and the type put back together. A part that belongs to no framework leaves
    /// the whole unanswered, because a list of something the framework has never heard of is not a
    /// type it can hand back.
    /// </remarks>
    private static Type? Constructed(string typeName, ModuleDef? subject)
    {
        if (!TrySplit(typeName, out var definition, out var arguments))
            return null;
        if (WellKnown(definition, subject) is not { IsGenericTypeDefinition: true } template)
            return null;
        var supplied = new List<Type>();
        foreach (var argument in arguments)
        {
            if (WellKnown(argument, subject) is not { } named)
                return null;
            supplied.Add(named);
        }

        return supplied.Count == template.GetGenericArguments().Length
            ? template.MakeGenericType([.. supplied])
            : null;
    }

    /// <summary>
    /// The parts of a constructed generic name: what it was constructed from, and with what.
    /// </summary>
    private static bool TrySplit(
        string typeName,
        out string definition,
        out List<string> arguments)
    {
        definition = typeName;
        arguments = [];
        var open = typeName.IndexOf('<', StringComparison.Ordinal);
        if (!typeName.EndsWith('>') || open <= 0)
            return false;
        definition = typeName[..open];
        var depth = 0;
        var start = open + 1;
        for (var index = start; index < typeName.Length; index++)
        {
            switch (typeName[index])
            {
                case '<':
                    depth++;
                    break;
                case '>' when depth > 0:
                    depth--;
                    break;
                case ',' when depth == 0:
                case '>' when depth == 0:
                    arguments.Add(typeName[start..index]);
                    start = index + 1;
                    break;
                default:
                    break;
            }
        }

        return arguments.Count != 0;
    }

    /// <summary>
    /// A framework generic constructed over something no framework has, as the definition it was
    /// made from and the names it was made with.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A list of a type the file defines is a framework type in every respect except that the
    /// framework in hand cannot be handed one: <c>List&lt;T&gt;</c> is where its members are
    /// declared and what they are declared to do, and the argument only says what <c>T</c> stands
    /// for in them. So the two are kept apart — the definition to ask, the argument to substitute —
    /// and questions about the constructed type are answered from both.
    /// </para>
    /// <para>
    /// This matters wherever a program reflects over a collection of its own types, which is what
    /// a serializer driven by annotations spends its time doing: it finds the item type from the
    /// signature of <c>Add</c> or of the indexer, and an answer naming the parameter rather than
    /// the type it stands for would send it down the wrong path with no sign that it had.
    /// </para>
    /// </remarks>
    /// <summary>
    /// The generic declaration a constructed name was made from, where the framework declares it.
    /// </summary>
    internal static Type? Declaring(string typeName, ModuleDef? subject) =>
        Open(typeName, subject)?.Template;

    private static (Type Template, List<string> Arguments)? Open(string typeName, ModuleDef? subject)
    {
        if (!TrySplit(typeName, out var definition, out var arguments))
            return null;
        return WellKnown(definition, subject) is { IsGenericTypeDefinition: true } template &&
            template.GetGenericArguments().Length == arguments.Count
                ? (template, arguments)
                : null;
    }

    /// <summary>
    /// What a framework type is called in the spelling the machine keeps type names in.
    /// </summary>
    /// <remarks>
    /// Reflection spells a constructed generic with the assembly of every argument written into it,
    /// and everything here compares type names as text. One spelling has to win, and it is the one
    /// the metadata uses, because most names in play were read out of a file.
    /// </remarks>
    private static string? Spelled(Type shape) => Rendered(shape, []);

    /// <summary>
    /// A framework type as a name, with its generic parameters replaced by what a constructed type
    /// supplied for them.
    /// </summary>
    private static string? Rendered(Type shape, IReadOnlyList<string> supplied)
    {
        if (shape.IsGenericParameter)
        {
            return shape.GenericParameterPosition < supplied.Count
                ? supplied[shape.GenericParameterPosition]
                : shape.Name;
        }

        if (shape.HasElementType && shape.GetElementType() is { } element)
        {
            if (Rendered(element, supplied) is not { } inner)
                return null;
            if (shape.IsByRef)
                return inner + "&";
            if (shape.IsPointer)
                return inner + "*";
            var rank = shape.GetArrayRank();
            return inner + "[" + new string(',', rank - 1) + "]";
        }

        // A declaration reached through a constructed type stands for the constructed type: the
        // member was found on a list of something, and the type it belongs to is that list rather
        // than the declaration in the abstract.
        if (shape.IsGenericTypeDefinition)
        {
            var declared = shape.FullName?.Replace('+', '/');
            return declared is not null && supplied.Count == shape.GetGenericArguments().Length
                ? declared + "<" + string.Join(",", supplied) + ">"
                : declared;
        }

        if (!shape.IsGenericType)
            return shape.FullName?.Replace('+', '/');
        var template = shape.GetGenericTypeDefinition().FullName?.Replace('+', '/');
        if (template is null)
            return null;
        var written = shape.GetGenericArguments().Select(argument => Rendered(argument, supplied));
        return written.Any(argument => argument is null)
            ? null
            : template + "<" + string.Join(",", written) + ">";
    }

    /// <summary>
    /// Answers a question about a constructed generic from the definition behind it.
    /// </summary>
    /// <remarks>
    /// What the type is — a class, a value, sealed — is decided by the definition and is the same
    /// whatever it was constructed with. What it names is not, so anything naming another type has
    /// the arguments put back in before it is handed over.
    /// </remarks>
    private static IntrinsicResult DescribeOpen(
        StaticHeap heap,
        string question,
        Type template,
        List<string> supplied)
    {
        IntrinsicResult Types(IEnumerable<string?> names)
        {
            var listed = names.ToArray();
            if (!heap.TryAllocateArray(null, listed.Length, out var array))
                return AllocationFailure("type array");
            for (var index = 0; index < listed.Length; index++)
            {
                if (listed[index] is not { } named ||
                    !heap.TryAllocateType(named, out var model) ||
                    !heap.TryWriteArray(array, index, model))
                {
                    return AllocationFailure("type model");
                }
            }

            return IntrinsicResult.Completed(array);
        }

        const int objectCode = 1;
        return question switch
        {
            "get_IsEnum" => Truth(template.IsEnum),
            "get_IsValueType" => Truth(template.IsValueType),
            "get_IsPrimitive" => Truth(false),
            "get_IsInterface" => Truth(template.IsInterface),
            "get_IsClass" => Truth(template.IsClass),
            "get_IsSealed" => Truth(template.IsSealed),
            "get_IsAbstract" => Truth(template.IsAbstract),
            "get_IsArray" => Truth(false),
            "get_IsGenericType" => Truth(true),
            "get_IsGenericParameter" => Truth(false),
            "get_IsGenericTypeDefinition" => Truth(false),
            "get_ContainsGenericParameters" => Truth(false),
            "GetTypeCode" => IntrinsicResult.Completed(StaticValue.FromInt32(objectCode)),
            "GetGenericArguments" => Types(supplied),
            "GetGenericTypeDefinition" => template.FullName is { } named &&
                heap.TryAllocateType(named, out var made)
                    ? IntrinsicResult.Completed(made)
                    : AllocationFailure("generic type definition"),
            "get_BaseType" => template.BaseType is { } above
                ? Rendered(above, supplied) is { } spelled &&
                    heap.TryAllocateType(spelled, out var baseType)
                        ? IntrinsicResult.Completed(baseType)
                        : AllocationFailure("base type")
                : IntrinsicResult.Completed(StaticValue.Null),
            "GetInterfaces" => Types(
                template.GetInterfaces().Select(contract => Rendered(contract, supplied))),
            _ => IntrinsicResult.Invalid(
                $"Unsupported question {question} about a constructed {template.FullName}.")
        };
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
    internal static System.Reflection.MethodBase? Framework(MemberRef reference)
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
        // A member the framework owns has no metadata in any file here, so it answers from its own
        // reflection rather than from dnlib's.
        if (described is MemberInfo or ParameterInfo or Bound)
            return DescribeFramework(heap, name, described);
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
            // A type parameter is a placeholder rather than a type, and a program that asks this is
            // deciding whether it is looking at one. A frame that knows what its parameters stand
            // for has already replaced them, so what arrives here is a real type and the answer is
            // no; where the parameter survived, the signature still says it is one.
            case "get_IsGenericParameter":
                return Truth(described is GenericSig);
            // Which of the framework's few built-in shapes a type is, if any. An enumeration
            // answers as the number behind it, because that is what it is stored and compared as,
            // and everything the file defines for itself is an object like any other.
            case "GetTypeCode" when Defined(described) is { } coded:
                return IntrinsicResult.Completed(StaticValue.FromInt32(NumberedCode(coded)));
            // The type a constructed generic was made from, which is written into the signature
            // that constructed it.
            case "GetGenericTypeDefinition" when described is GenericInstSig made:
                return Describing(heap, "System.Type", made.GenericType);
            case "get_ContainsGenericParameters" when described is TypeSig parameterized:
                return Truth(parameterized.ContainsGenericParameter);
            case "get_ContainsGenericParameters" when Defined(described) is { } generic:
                return Truth(generic.HasGenericParameters);
            case "get_IsGenericTypeDefinition" when Defined(described) is { } definition:
                return Truth(definition.HasGenericParameters && described is not GenericInstSig);
            // A type with no base is not a type whose base is unknown: only System.Object and the
            // interfaces have none, and saying so is what lets a walk up the chain terminate.
            case "get_BaseType" when Defined(described) is { } derived:
                return derived.BaseType is { } above
                    ? Describing(heap, "System.Type", above)
                    : IntrinsicResult.Completed(StaticValue.Null);
            case "GetInterfaces" when Defined(described) is { } implementing:
            {
                var contracts = implementing.Interfaces
                    .Select(item => item.Interface)
                    .Where(item => item is not null)
                    .ToArray();
                if (!heap.TryAllocateArray(null, contracts.Length, out var listed))
                    return AllocationFailure("interface array");
                for (var index = 0; index < contracts.Length; index++)
                {
                    if (!heap.TryWriteArray(
                            listed,
                            index,
                            Describing(heap, "System.Type", contracts[index]!).Value))
                        return AllocationFailure("interface model");
                }

                return IntrinsicResult.Completed(listed);
            }
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
            // The name with the assembly on it, which is how a program hands a type to something
            // that will look it up later. It is read from the same metadata the plain name is.
            case "get_AssemblyQualifiedName" when described is IType qualified &&
                qualified.AssemblyQualifiedName is { } identity:
                return heap.TryAllocateString(identity, out var qualifiedName)
                    ? IntrinsicResult.Completed(qualifiedName)
                    : AllocationFailure("type name");
            case "get_FullName" when Named(described) is { } fullName:
                return heap.TryAllocateString(fullName, out var fullNameValue)
                    ? IntrinsicResult.Completed(fullNameValue)
                    : AllocationFailure("type name");
            case "get_Namespace" when Defined(described) is { } namespaced:
                return heap.TryAllocateString(namespaced.Namespace, out var namespaceValue)
                    ? IntrinsicResult.Completed(namespaceValue)
                    : AllocationFailure("type namespace");
            case "GetArrayRank" when described is ArraySig ranked:
                return IntrinsicResult.Completed(StaticValue.FromInt32((int)ranked.Rank));
            case "GetArrayRank" when described is SZArraySig:
                return IntrinsicResult.Completed(StaticValue.FromInt32(1));
            case "GetElementType" when described is NonLeafSig element:
                return Describing(heap, "System.Type", element.Next);
            case "get_FieldType" when described is FieldDef typedField:
                return Describing(heap, "System.Type", typedField.FieldType);
            case "get_PropertyType" when described is PropertyDef { PropertySig.RetType: { } value }:
                return Describing(heap, "System.Type", value);
            case "get_CanRead" when described is PropertyDef readable:
                return Truth(readable.GetMethod is not null);
            case "get_CanWrite" when described is PropertyDef writable:
                return Truth(writable.SetMethod is not null);
            case "get_IsStatic" when described is PropertyDef lifetime:
                return Truth(Behind(lifetime)?.IsStatic == true);
            case "get_IsPublic" when described is PropertyDef visibility:
                return Truth(Behind(visibility)?.IsPublic == true);
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
            // Which kind of member this is, as the framework numbers the kinds. A program that
            // walked a type asks it before it asks anything else, because what it may ask next
            // depends on the answer.
            case "get_MemberType" when Kind(described) is { } kind:
                return IntrinsicResult.Completed(StaticValue.FromInt32(kind));
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
    /// <summary>
    /// Gives a type reached by name the metadata a type reached by token would have carried.
    /// </summary>
    /// <remarks>
    /// The two are the same type, and a program that looks a member up on one goes on to use it
    /// exactly as it would have used a member of the other, so the model has to be able to name it
    /// either way. Where this module defines the type its definition is the answer. Where the
    /// framework in hand recognizes the name, a reference to it is — the same thing a token to a
    /// framework type resolves to, and enough to name a member on it.
    /// </remarks>
    private static void AttachDefinition(IntrinsicContext context, StaticValue model, string typeName)
    {
        if (context.State.ModuleMetadata is not { } module)
            return;
        // A name can belong to the subject or to a library that was supplied alongside it, and a
        // type from a library answers questions about itself the same way. Looking in one place only
        // would leave a library's own types as bare names, which is what an attribute an object
        // reports on itself is made of.
        var searched = new[] { module }.Concat(context.State.TrustedModules);
        if (searched.Select(candidate => candidate.Find(typeName, false))
                .FirstOrDefault(found => found is not null) is { } definition)
        {
            context.State.Heap.TrySetModelValue(model, "Metadata", definition);
            return;
        }

        if (WellKnown(typeName, module) is { IsNested: false } present)
        {
            context.State.Heap.TrySetModelValue(
                model,
                "Metadata",
                new TypeRefUser(
                    module,
                    present.Namespace ?? string.Empty,
                    present.Name,
                    module.CorLibTypes.AssemblyRef));
        }
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

    /// <summary>
    /// Answers whether two objects are equal, by whatever equality applies to what they are.
    /// </summary>
    private static IntrinsicResult ObjectEquality(
        IntrinsicContext context,
        bool byIdentity,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        var (left, right) = (arguments[0], arguments[1]);
        // One object is itself, and two primitives the machine holds unboxed are equal when their
        // bits are, which is the same comparison.
        if (left.Equals(right))
            return Truth(true);
        if (byIdentity || left.Kind == StaticValueKind.Null || right.Kind == StaticValueKind.Null)
            return Truth(false);
        if (heap.TryGetString(left, out var oneText) && heap.TryGetString(right, out var otherText))
            return Truth(string.Equals(oneText, otherText, StringComparison.Ordinal));
        if (heap.TryUnbox(left, out var oneValue) && heap.TryUnbox(right, out var otherValue))
        {
            // A box carries its type, and a number of one type is not equal to the same number of
            // another however the two compare as numbers.
            heap.TryGetRuntimeTypeName(left, out var oneType);
            heap.TryGetRuntimeTypeName(right, out var otherType);
            return Truth(oneValue.Equals(otherValue) &&
                string.Equals(oneType, otherType, StringComparison.Ordinal));
        }

        if (Spelling(heap, left) is { } oneName && Spelling(heap, right) is { } otherName &&
            heap.TryGetRuntimeTypeName(left, out var oneShape) && oneShape == "System.Type" &&
            heap.TryGetRuntimeTypeName(right, out var otherShape) && otherShape == "System.Type")
            return Truth(string.Equals(oneName, otherName, StringComparison.Ordinal));
        if (context.Call is { } call && Overriding(context, left, "Equals", 1) is { } written)
            return call(written, [left, right]);
        return Truth(false);
    }

    /// <summary>
    /// The body an object's own type gives a method, found by walking up from what the object is.
    /// </summary>
    /// <remarks>
    /// A call spelled through <c>System.Object</c> reaches whatever the receiver's type wrote, and
    /// which type that is only the receiver knows. Nothing outside the supplied files is searched,
    /// so a framework type's own implementation is not found here and the caller decides what to do
    /// without one.
    /// </remarks>
    private static MethodDef? Overriding(
        IntrinsicContext context,
        StaticValue instance,
        string name,
        int parameters)
    {
        if (!context.State.Heap.TryGetRuntimeTypeName(instance, out var runtime) || runtime is null)
            return null;
        var searched = new[] { context.State.ModuleMetadata }
            .Concat(context.State.TrustedModules)
            .Where(module => module is not null)
            .Select(module => module!.Find(runtime, false))
            .FirstOrDefault(found => found is not null);
        for (var type = searched; type is not null; type = type.BaseType?.ResolveTypeDef())
        {
            if (type.Methods.FirstOrDefault(candidate =>
                    candidate.Name == name && candidate.HasBody && !candidate.IsStatic &&
                    candidate.MethodSig?.Params.Count == parameters) is { } written)
                return written;
        }

        return null;
    }

    /// <summary>
    /// A type name with the assembly it was qualified by removed.
    /// </summary>
    /// <remarks>
    /// The assembly sits after the first comma that is not inside a generic argument list, so the
    /// scan tracks the brackets rather than taking the first comma it sees.
    /// </remarks>
    private static string Unqualify(string spelled)
    {
        var depth = 0;
        for (var index = 0; index < spelled.Length; index++)
        {
            switch (spelled[index])
            {
                case '[':
                    depth++;
                    break;
                case ']':
                    depth--;
                    break;
                case ',' when depth == 0:
                    return spelled[..index].TrimEnd();
                default:
                    break;
            }
        }

        return spelled;
    }

    /// <summary>
    /// What a modeled type calls itself, whether it came from metadata or from a name.
    /// </summary>
    private static string? Spelling(StaticHeap heap, StaticValue model)
    {
        if (heap.TryGetModelValue<object>(model, "Metadata", out var described) &&
            described is not null && Named(described) is { } named)
            return named;
        return heap.TryGetModelValue(model, "TypeName", out string? spelled) ? spelled : null;
    }

    /// <summary>
    /// The members of a type that a reflection query with these binding flags would return.
    /// </summary>
    /// <remarks>
    /// A type is either one some supplied file defines, in which case its members are read from that
    /// file, or one only the framework has, in which case the framework in hand is asked. Both
    /// answers describe members the same way afterwards, so code that walks a type does not have to
    /// know which kind it is walking — which matters because a walk up a base chain crosses from one
    /// to the other at the top.
    /// </remarks>
    private static IEnumerable<object>? Members(
        IntrinsicContext context,
        string question,
        StaticValue asked,
        int wanted)
    {
        const int declaredOnly = 0x02;
        var heap = context.State.Heap;
        if (heap.TryGetModelValue<object>(asked, "Metadata", out var described) &&
            described is not null && Defined(described) is { } definition)
        {
            // Reflection reports what a type inherits alongside what it declares, so the walk goes
            // up the chain unless the caller asked for one type's own members. It can cross out of
            // the supplied files at the top, and a chain that cannot be read to the end refuses
            // rather than offering the part that could be read as if it were the whole answer.
            var collected = new List<object>();
            for (var type = definition; ;)
            {
                collected.AddRange(Owned(type, question, wanted, type != definition));
                if ((wanted & declaredOnly) != 0 ||
                    question is "GetConstructors" or "GetNestedTypes" ||
                    type.BaseType is null)
                    return collected;
                if (type.BaseType.ResolveTypeDef() is { } above)
                {
                    type = above;
                    continue;
                }

                if (WellKnown(type.BaseType.FullName, context.State.ModuleMetadata) is not
                    { } outside)
                    return null;
                collected.AddRange(Present(outside, question, wanted));
                return collected;
            }
        }

        if (!heap.TryGetModelValue(asked, "TypeName", out string? spelled) || spelled is null)
            return null;
        var subject = context.State.ModuleMetadata;
        if (WellKnown(spelled, subject) is { } present)
            return Present(present, question, wanted);
        // A generic the framework declares but was constructed over a type from a file is asked of
        // the declaration, and each member carries what its parameters stand for so that it can say
        // what it takes and returns in the types the program is actually using.
        return Open(spelled, subject) is var (template, supplied)
            ? [.. Present(template, question, wanted)
                .Select(member => (object)new Bound(member, supplied))]
            : null;
    }

    /// <summary>
    /// A member handed over as the kind of reflection object it is.
    /// </summary>
    /// <remarks>
    /// What a member is described as follows the member rather than the question that found it,
    /// because a query for all of them hands back a mixture and the program tells them apart by
    /// asking what each one is.
    /// </remarks>
    private static StaticValue Modeling(
        IntrinsicContext context,
        object member,
        StaticValue? reflected = null)
    {
        var heap = context.State.Heap;
        var model = member switch
        {
            Type outside when heap.TryAllocateType(outside.FullName!, out var named) => named,
            ITypeDefOrRef inside => Describing(heap, "System.Type", inside).Value,
            _ => Describing(heap, Modeled(member), member).Value
        };
        if (member is IMemberDef { Module: { } owner } && owner == context.State.ModuleMetadata)
            heap.TrySetModelValue(model, HomeModuleMark, true);
        // Which type the member was found on, which is not always the type that declares it. A
        // program looking for a hook beside an inherited member searches the type it was reading,
        // so the difference decides where it looks.
        if (reflected is { } asked)
            heap.TrySetModelValue(model, "ReflectedType", asked);
        return model;
    }

    /// <summary>
    /// The one member of a type a lookup by name asked for, or <see langword="null"/> when the type
    /// has none.
    /// </summary>
    /// <remarks>
    /// A lookup that lists the parameter types is asking for one overload and is answered with that
    /// one or with nothing, because a caller that named the types is about to call what comes back
    /// with them. A lookup that lists no types takes the first of whatever the name reaches, which
    /// is where the framework would raise its own complaint about the name being ambiguous.
    /// </remarks>
    private static object? Sole(
        StaticHeap heap,
        IEnumerable<object> candidates,
        string memberName,
        IReadOnlyList<StaticValue> arguments)
    {
        var named = candidates.Where(candidate => Called(candidate) == memberName).ToList();
        if (named.Count == 0 || !TryAsked(heap, arguments, out var asked) || asked is null)
            return named.FirstOrDefault();
        return named.FirstOrDefault(candidate => Takes(candidate, asked));
    }

    /// <summary>
    /// The parameter types a lookup narrowed itself by, as names, wherever they sat among its
    /// arguments.
    /// </summary>
    /// <returns>
    /// <see langword="false"/> when an array is there but cannot be read, which is not the same as
    /// a lookup that narrowed itself by nothing.
    /// </returns>
    private static bool TryAsked(
        StaticHeap heap,
        IReadOnlyList<StaticValue> arguments,
        out List<string>? asked)
    {
        asked = null;
        for (var index = arguments.Count - 1; index >= 1; index--)
        {
            if (!heap.TryGetArrayElementType(arguments[index], out var element) ||
                element != "System.Type")
                continue;
            if (!heap.TryGetLength(arguments[index], out var count))
                return false;
            var listed = new List<string>();
            for (var at = 0; at < count; at++)
            {
                if (!heap.TryReadArray(arguments[index], at, out var parameter) ||
                    !heap.TryGetModelValue(parameter, "TypeName", out string? spelled) ||
                    spelled is null)
                {
                    return false;
                }

                listed.Add(spelled);
            }

            asked = listed;
            return true;
        }

        return true;
    }

    /// <summary>Whether a member takes exactly the parameter types a lookup named.</summary>
    private static bool Takes(object candidate, List<string> asked) => candidate switch
    {
        Bound(MethodBase within, var supplied) => within.GetParameters()
            .Select(parameter => Rendered(parameter.ParameterType, supplied) ?? string.Empty)
            .SequenceEqual(asked, StringComparer.Ordinal),
        MethodDef method => method.Parameters
            .Where(parameter => !parameter.IsHiddenThisParameter)
            .Select(parameter => parameter.Type?.FullName ?? string.Empty)
            .SequenceEqual(asked, StringComparer.Ordinal),
        MethodBase present => present.GetParameters()
            .Select(parameter => parameter.ParameterType.FullName ?? string.Empty)
            .SequenceEqual(asked, StringComparer.Ordinal),
        _ => asked.Count == 0
    };

    /// <summary>
    /// A reference naming a framework member, in the form an instruction can carry.
    /// </summary>
    /// <remarks>
    /// The framework's own reflection says the most about one of its members, and says none of it
    /// in a form a body can be assembled around. So what it says is written out as a reference:
    /// the declaring type, the name, and the types it takes and hands back, with the parameters of
    /// a generic declaration replaced by whatever the type in hand was constructed with. A call
    /// assembled around that reference pops and pushes what the real one would.
    /// </remarks>
    internal static IMemberRef? Referencing(object member, ModuleDef within)
    {
        var (described, supplied) = member is Bound(var inner, var arguments)
            ? (inner, arguments)
            : (member, (IReadOnlyList<string>)[]);
        if (described is not MemberInfo { DeclaringType: { } owner } named)
            return null;
        if (Rendered(owner, supplied) is not { } spelled ||
            ReflectionEmitIntrinsic.Denoting(spelled, within) is not { } declaring)
        {
            return null;
        }

        TypeSig? Standing(Type shape) =>
            Rendered(shape, supplied) is { } written
                ? ReflectionEmitIntrinsic.Denoting(written, within)
                : null;
        switch (named)
        {
            case MethodBase call:
                var returns = call is MethodInfo answering
                    ? Standing(answering.ReturnType)
                    : within.CorLibTypes.Void;
                var takes = call.GetParameters().Select(taken => Standing(taken.ParameterType));
                if (returns is null || takes.Any(taken => taken is null))
                    return null;
                TypeSig[] taking = [.. takes.Select(taken => taken!)];
                return new MemberRefUser(
                    within,
                    call.Name,
                    call.IsStatic
                        ? MethodSig.CreateStatic(returns, taking)
                        : MethodSig.CreateInstance(returns, taking),
                    declaring.ToTypeDefOrRef());
            case FieldInfo held when Standing(held.FieldType) is { } holds:
                return new MemberRefUser(
                    within,
                    held.Name,
                    new FieldSig(holds),
                    declaring.ToTypeDefOrRef());
            default:
                return null;
        }
    }

    /// <summary>
    /// The method a modeled member names, in the form the machine can call.
    /// </summary>
    /// <remarks>
    /// A member is described by whatever knows the most about it, and for one the framework owns
    /// that is the framework's own reflection, which is not something this machine dispatches on.
    /// The reference built alongside it is, so a call goes through that where the description
    /// cannot carry it.
    /// </remarks>
    private static IMethod? Callable(StaticHeap heap, StaticValue member)
    {
        if (heap.TryGetModelValue<object>(member, "Metadata", out var described) &&
            described is IMethod named)
            return named;
        return heap.TryGetModelValue<object>(member, ReflectionEmitIntrinsic.Emitted, out var built)
            ? built as IMethod
            : null;
    }

    /// <summary>What a member found by a query is called.</summary>
    private static string? Called(object member) => member switch
    {
        IMemberDef defined => defined.Name?.String,
        Bound bound => Called(bound.Of),
        MemberInfo present => present.Name,
        _ => null
    };

    /// <summary>
    /// A member of a generic declaration, together with what the parameters stand for where it was
    /// reached from.
    /// </summary>
    private sealed record Bound(object Of, IReadOnlyList<string> Arguments);

    /// <summary>
    /// The members a type declares of its own that a query with these flags would return.
    /// </summary>
    /// <remarks>
    /// A member reached by inheritance is filtered once more: a private one belongs to the type that
    /// declared it and is not part of what a derived type reports, however the query was written.
    /// </remarks>
    private static IEnumerable<object> Owned(
        TypeDef type,
        string question,
        int wanted,
        bool inherited)
    {
        IEnumerable<object> fields = type.Fields
            .Where(item => Selects(wanted, item) && !(inherited && item.IsPrivate));
        IEnumerable<object> properties = type.Properties
            .Where(item => Selects(wanted, Behind(item)) &&
                !(inherited && Behind(item) is { IsPrivate: true }));
        IEnumerable<object> methods = type.Methods
            .Where(item => !item.IsConstructor && Selects(wanted, item) &&
                !(inherited && item.IsPrivate));
        IEnumerable<object> events = type.Events
            .Where(item => Selects(wanted, item.AddMethod ?? item.RemoveMethod));
        return question switch
        {
            "GetFields" => fields,
            "GetProperties" => properties,
            "GetConstructors" => type.FindConstructors().Where(item => Selects(wanted, item)),
            "GetMethods" => methods,
            "GetEvents" => events,
            "GetNestedTypes" => type.NestedTypes,
            _ => [.. methods, .. properties, .. fields, .. events, .. type.NestedTypes]
        };
    }

    /// <summary>
    /// The members of a framework type, as the framework in hand reports them.
    /// </summary>
    /// <remarks>
    /// The flag values are the framework's own, so the query the program built is the query that
    /// runs, inheritance and all.
    /// </remarks>
    private static MemberInfo[] Present(Type present, string question, int wanted)
    {
        var flags = (BindingFlags)wanted;
        return question switch
        {
            "GetFields" => present.GetFields(flags),
            "GetProperties" => present.GetProperties(flags),
            "GetConstructors" => present.GetConstructors(flags),
            "GetMethods" => present.GetMethods(flags),
            "GetEvents" => present.GetEvents(flags),
            "GetNestedTypes" => present.GetNestedTypes(flags),
            _ => present.GetMembers(flags)
        };
    }


    /// <summary>
    /// Which kind of member something is, numbered as <c>System.Reflection.MemberTypes</c> does.
    /// </summary>
    private static int? Kind(object described) => described switch
    {
        MethodDef { IsConstructor: true } => 1,
        EventDef => 2,
        FieldDef => 4,
        MethodDef => 8,
        PropertyDef => 16,
        TypeDef { IsNested: true } => 128,
        TypeDef => 32,
        _ => null
    };

    /// <summary>The kind of reflection object a member is handed over as.</summary>
    private static string Modeled(object member) => member switch
    {
        Bound bound => Modeled(bound.Of),
        FieldDef or FieldInfo => "System.Reflection.FieldInfo",
        PropertyDef or PropertyInfo => "System.Reflection.PropertyInfo",
        EventDef or System.Reflection.EventInfo => "System.Reflection.EventInfo",
        MethodDef { IsConstructor: true } or System.Reflection.ConstructorInfo =>
            "System.Reflection.ConstructorInfo",
        MethodDef or MethodInfo => "System.Reflection.MethodInfo",
        _ => "System.Reflection.MemberInfo"
    };

    /// <summary>
    /// Answers a reflection question about a framework member, from the framework in hand.
    /// </summary>
    /// <remarks>
    /// These arrive only from a walk that reached a type nobody supplied a file for. Nothing is run
    /// to answer them and nothing is handed back that could be run: a member described here can say
    /// what it is called, what it takes and what it returns, and a program that tries to invoke one
    /// is refused where it tries.
    /// </remarks>
    private static IntrinsicResult DescribeFramework(
        StaticHeap heap,
        string question,
        object described)
    {
        static IntrinsicResult Named(StaticHeap heap, Type? named) =>
            named is not null && Spelled(named) is { } spelled &&
                heap.TryAllocateType(spelled, out var model)
                    ? IntrinsicResult.Completed(model)
                    : IntrinsicResult.Completed(StaticValue.Null);
        static IntrinsicResult Standing(
            StaticHeap heap,
            Type? named,
            IReadOnlyList<string> supplied) =>
            named is not null && Rendered(named, supplied) is { } spelled &&
                heap.TryAllocateType(spelled, out var model)
                    ? IntrinsicResult.Completed(model)
                    : IntrinsicResult.Completed(StaticValue.Null);
        static IntrinsicResult Text(StaticHeap heap, string text) =>
            heap.TryAllocateString(text, out var allocated)
                ? IntrinsicResult.Completed(allocated)
                : AllocationFailure("member name");
        switch (described)
        {
            // A member of a generic declaration answers about itself from the declaration, and
            // about the types it mentions from what its parameters were given.
            case Bound(ParameterInfo parameter, var supplied):
                return question switch
                {
                    "get_ParameterType" => Standing(heap, parameter.ParameterType, supplied),
                    "get_Name" => Text(heap, parameter.Name ?? string.Empty),
                    "get_Position" => IntrinsicResult.Completed(
                        StaticValue.FromInt32(parameter.Position)),
                    _ => IntrinsicResult.Invalid(
                        $"Metadata question {question} is unmodeled for a parameter.")
                };
            case Bound(MemberInfo within, var supplied):
                switch (question)
                {
                    case "get_DeclaringType":
                        return Standing(heap, within.DeclaringType, supplied);
                    case "get_FieldType" when within is FieldInfo field:
                        return Standing(heap, field.FieldType, supplied);
                    case "get_PropertyType" when within is PropertyInfo property:
                        return Standing(heap, property.PropertyType, supplied);
                    case "get_ReturnType" when within is MethodInfo method:
                        return Standing(heap, method.ReturnType, supplied);
                    case "GetParameters" when within is MethodBase method:
                    {
                        var taken = method.GetParameters();
                        if (!heap.TryAllocateArray(null, taken.Length, out var array))
                            return AllocationFailure("parameter array");
                        for (var index = 0; index < taken.Length; index++)
                        {
                            var model = Describing(
                                heap,
                                "System.Reflection.ParameterInfo",
                                new Bound(taken[index], supplied));
                            if (model.Status != StaticExecutionStatus.Completed ||
                                !heap.TryWriteArray(array, index, model.Value))
                                return AllocationFailure("parameter model");
                        }

                        return IntrinsicResult.Completed(array);
                    }

                    default:
                        // Everything else about a member is the declaration's to answer.
                        return DescribeFramework(heap, question, within);
                }

            case ParameterInfo parameter:
                return question switch
                {
                    "get_ParameterType" => Named(heap, parameter.ParameterType),
                    "get_Name" => Text(heap, parameter.Name ?? string.Empty),
                    "get_Position" => IntrinsicResult.Completed(
                        StaticValue.FromInt32(parameter.Position)),
                    _ => IntrinsicResult.Invalid(
                        $"Metadata question {question} is unmodeled for a parameter.")
                };
            case MemberInfo member:
                switch (question)
                {
                    case "get_Name":
                        return Text(heap, member.Name);
                    case "get_DeclaringType":
                        return Named(heap, member.DeclaringType);
                    case "get_IsSpecialName" when member is MethodBase special:
                        return Truth(special.IsSpecialName);
                    case "get_MetadataToken":
                        return IntrinsicResult.Completed(
                            StaticValue.FromInt32(member.MetadataToken));
                    case "get_MemberType":
                        return IntrinsicResult.Completed(
                            StaticValue.FromInt32((int)member.MemberType));
                    case "get_FieldType" when member is FieldInfo field:
                        return Named(heap, field.FieldType);
                    case "get_IsStatic" when member is FieldInfo field:
                        return Truth(field.IsStatic);
                    case "get_IsPublic" when member is FieldInfo field:
                        return Truth(field.IsPublic);
                    case "get_PropertyType" when member is PropertyInfo property:
                        return Named(heap, property.PropertyType);
                    case "get_CanRead" when member is PropertyInfo property:
                        return Truth(property.CanRead);
                    case "get_CanWrite" when member is PropertyInfo property:
                        return Truth(property.CanWrite);
                    case "get_ReturnType" when member is MethodInfo method:
                        return Named(heap, method.ReturnType);
                    case "get_IsStatic" when member is MethodBase method:
                        return Truth(method.IsStatic);
                    case "get_IsPublic" when member is MethodBase method:
                        return Truth(method.IsPublic);
                    case "get_IsAbstract" when member is MethodBase method:
                        return Truth(method.IsAbstract);
                    case "get_IsVirtual" when member is MethodBase method:
                        return Truth(method.IsVirtual);
                    case "GetParameters" when member is MethodBase method:
                    {
                        var parameters = method.GetParameters();
                        if (!heap.TryAllocateArray(null, parameters.Length, out var array))
                            return AllocationFailure("parameter array");
                        for (var index = 0; index < parameters.Length; index++)
                        {
                            var model = Describing(
                                heap,
                                "System.Reflection.ParameterInfo",
                                parameters[index]);
                            if (model.Status != StaticExecutionStatus.Completed ||
                                !heap.TryWriteArray(array, index, model.Value))
                                return AllocationFailure("parameter model");
                        }

                        return IntrinsicResult.Completed(array);
                    }

                    default:
                        return IntrinsicResult.Invalid(
                            $"Metadata question {question} is unmodeled for {member.Name}" +
                            " outside any supplied file.");
                }

            default:
                return IntrinsicResult.Invalid($"Nothing is known about {described}.");
        }
    }

    /// <summary>
    /// Whether a property is one a reflection query with these binding flags would return.
    /// </summary>
    /// <remarks>
    /// A property has no lifetime or visibility of its own; both belong to the methods behind it,
    /// which is what the runtime looks at too.
    /// </remarks>
    private static bool Selects(int bindingFlags, MethodDef? accessor)
    {
        const int instance = 0x04;
        const int isStatic = 0x08;
        const int isPublic = 0x10;
        const int nonPublic = 0x20;
        if (accessor is null)
            return false;
        var lifetimeWanted = accessor.IsStatic ? isStatic : instance;
        var visibilityWanted = accessor.IsPublic ? isPublic : nonPublic;
        return (bindingFlags & lifetimeWanted) != 0 && (bindingFlags & visibilityWanted) != 0;
    }

    /// <summary>The method a property's visibility is decided by.</summary>
    private static MethodDef? Behind(PropertyDef property) =>
        property.GetMethod ?? property.SetMethod;

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
        IMethod method,
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
            if (!Comparing(method, arguments, out var how))
                return Culturally(name);
            var matched = name switch
            {
                "Contains" => text.Contains(searched, how),
                "StartsWith" => text.StartsWith(searched, how),
                _ => text.EndsWith(searched, how)
            };
            return IntrinsicResult.Completed(StaticValue.FromInt32(matched ? 1 : 0));
        }
        // Comparison spelled as a call rather than as an operator. The static and instance forms
        // take the two strings in the same order and differ only in where the receiver comes from,
        // so one reading serves both.
        if (name is "Equals" or "Compare" or "CompareTo" && arguments.Count is 2 or 3)
        {
            var (left, right) = (arguments[0], arguments[1]);
            if (!Comparing(method, arguments, out var how))
                return Culturally(name);
            string? one = null;
            string? other = null;
            if (left.Kind != StaticValueKind.Null &&
                !context.State.Heap.TryGetString(left, out one))
                return IntrinsicResult.Invalid($"String.{name} requires concrete strings.");
            if (right.Kind != StaticValueKind.Null &&
                !context.State.Heap.TryGetString(right, out other))
                return IntrinsicResult.Invalid($"String.{name} requires concrete strings.");
            return IntrinsicResult.Completed(StaticValue.FromInt32(name == "Equals"
                ? string.Equals(one, other, how) ? 1 : 0
                : string.Compare(one, other, how)));
        }
        if (name is "IndexOf" or "LastIndexOf" && arguments.Count >= 2 &&
            context.State.Heap.TryGetString(arguments[0], out text))
        {
            if (!Comparing(method, arguments, out var how))
                return Culturally(name);
            // Where to look is given as a start and then a count, both optional, and told apart
            // from a comparison by the signature rather than by the value.
            var bounds = Counted(method, arguments);
            var start = bounds.Count > 0 ? bounds[0] : name == "IndexOf" ? 0 : text.Length - 1;
            var span = bounds.Count > 1
                ? bounds[1]
                : name == "IndexOf" ? text.Length - start : start + 1;
            var needle = context.State.Heap.TryGetString(arguments[1], out var sought)
                ? sought
                : arguments[1].Kind == StaticValueKind.Int32
                    ? ((char)arguments[1].AsInt32()).ToString()
                    : null;
            if (needle is null)
                return IntrinsicResult.Invalid($"String.{name} requires something concrete to find.");
            if (text.Length == 0)
                return IntrinsicResult.Completed(StaticValue.FromInt32(needle.Length == 0 ? 0 : -1));
            if (start < 0 || span < 0 ||
                (name == "IndexOf" ? start + span > text.Length : start >= text.Length || span > start + 1))
                return IntrinsicResult.Invalid($"String.{name} was given a range outside the string.");
            return IntrinsicResult.Completed(StaticValue.FromInt32(name == "IndexOf"
                ? text.IndexOf(needle, start, span, how)
                : text.LastIndexOf(needle, start, span, how)));
        }
        if (name == "Substring" && arguments.Count is 2 or 3 &&
            context.State.Heap.TryGetString(arguments[0], out text))
        {
            var start = arguments[1].AsInt32();
            var span = arguments.Count == 3 ? arguments[2].AsInt32() : text.Length - start;
            if (start < 0 || span < 0 || start + span > text.Length)
                return IntrinsicResult.Invalid("String.Substring range is outside the string.");
            return context.State.Heap.TryAllocateString(text.Substring(start, span), out var part)
                ? IntrinsicResult.Completed(part)
                : AllocationFailure("String.Substring");
        }
        if (name == "Replace" && arguments.Count == 3 &&
            context.State.Heap.TryGetString(arguments[0], out text))
        {
            // Both overloads replace one run of characters with another; a character argument
            // arrives as its code rather than as a string.
            static string? Spelled(StaticHeap heap, StaticValue value) =>
                heap.TryGetString(value, out var spelled)
                    ? spelled
                    : value.Kind == StaticValueKind.Int32
                        ? ((char)value.AsInt32()).ToString()
                        : null;
            if (Spelled(context.State.Heap, arguments[1]) is not { } from ||
                Spelled(context.State.Heap, arguments[2]) is not { } to)
                return IntrinsicResult.Invalid("String.Replace requires concrete arguments.");
            if (from.Length == 0)
                return IntrinsicResult.Invalid("String.Replace was given nothing to replace.");
            return context.State.Heap.TryAllocateString(
                    text.Replace(from, to, StringComparison.Ordinal),
                    out var replaced)
                ? IntrinsicResult.Completed(replaced)
                : AllocationFailure("String.Replace");
        }
        if (name == "get_Chars" && arguments.Count == 2 &&
            context.State.Heap.TryGetString(arguments[0], out text))
        {
            var at = arguments[1].AsInt32();
            return at >= 0 && at < text.Length
                ? IntrinsicResult.Completed(StaticValue.FromInt32(text[at]))
                : IntrinsicResult.Invalid("String index is outside the string.");
        }
        if (name == "Format" && arguments.Count >= 2)
            return FormatString(context, method, arguments);
        if (name == "Split" && arguments.Count == 2 &&
            context.State.Heap.TryGetString(arguments[0], out text))
            return SplitString(context, text, arguments[1]);
        if (name == ".ctor")
            return MakeString(context.State.Heap, arguments);
        // Null is a string the machine knows the whole of, so these two are answerable for it and
        // not only for a string it can read the characters of.
        if (name is "IsNullOrEmpty" or "IsNullOrWhiteSpace" && arguments.Count == 1)
        {
            if (arguments[0].Kind == StaticValueKind.Null)
                return IntrinsicResult.Completed(StaticValue.FromInt32(1));
            if (!context.State.Heap.TryGetString(arguments[0], out var subject))
                return IntrinsicResult.Invalid($"String.{name} requires a concrete string.");
            var empty = name == "IsNullOrEmpty"
                ? string.IsNullOrEmpty(subject)
                : string.IsNullOrWhiteSpace(subject);
            return IntrinsicResult.Completed(StaticValue.FromInt32(empty ? 1 : 0));
        }
        return IntrinsicResult.Invalid($"Unsupported String operation {name}.");
    }

    /// <summary>
    /// Fills a format string with the values it was given.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A stager builds its addresses and its file paths this way, so the text that comes out of here
    /// is usually the thing the recovery is after. The values are handed to the framework as the
    /// types they were boxed from rather than as text, so that a number is filled in as a number.
    /// </para>
    /// <para>
    /// A format item that says how to render its value is refused, because how a number or an instant
    /// reads under a named format is decided by a culture, and which culture belongs to the machine
    /// the sample expects rather than to this one. The values filled in without one — text, integers,
    /// truth values, characters — read the same under every culture, and a fractional number does
    /// not, so it is refused as well.
    /// </para>
    /// </remarks>
    private static IntrinsicResult FormatString(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        var parameters = method.MethodSig?.Params;
        // An overload that takes a culture takes it first, and the format string follows it.
        var at = parameters is { Count: > 0 } &&
            parameters[0].FullName == "System.IFormatProvider"
                ? 1
                : 0;
        if (arguments.Count <= at || !heap.TryGetString(arguments[at], out var format))
            return IntrinsicResult.Invalid("String.Format requires a concrete format string.");
        if (Specified(format))
            return Culturally("Format");

        var supplied = new List<object?>();
        for (var index = at + 1; index < arguments.Count; index++)
        {
            // The overload that takes any number of values takes them as one array.
            if (index == arguments.Count - 1 &&
                parameters is { Count: > 0 } &&
                parameters[^1].FullName == "System.Object[]")
            {
                if (!heap.TryGetLength(arguments[index], out var count))
                    return IntrinsicResult.Invalid("String.Format was given no values to fill in.");
                for (var element = 0; element < count; element++)
                {
                    if (!heap.TryReadArray(arguments[index], element, out var held) ||
                        !Rendering(heap, held, out var value))
                        return Unreadable(element);
                    supplied.Add(value);
                }

                continue;
            }

            if (!Rendering(heap, arguments[index], out var filled))
                return Unreadable(index - at - 1);
            supplied.Add(filled);
        }

        string formatted;
        try
        {
            formatted = string.Format(CultureInfo.InvariantCulture, format, [.. supplied]);
        }
        catch (FormatException ex)
        {
            return IntrinsicResult.Invalid(
                $"String.Format was given a format it cannot fill: {ex.Message}");
        }

        return heap.TryAllocateString(formatted, out var built)
            ? IntrinsicResult.Completed(built)
            : AllocationFailure("String.Format");

        static IntrinsicResult Unreadable(int position) => IntrinsicResult.Invalid(
            $"What String.Format was given to fill {{{position}}} with cannot be read as text here.");
    }

    /// <summary>Whether any format item in the string says how to render its value.</summary>
    private static bool Specified(string format)
    {
        for (var at = format.IndexOf('{', StringComparison.Ordinal); at >= 0;)
        {
            if (at + 1 < format.Length && format[at + 1] == '{')
            {
                at = format.IndexOf('{', at + 2);
                continue;
            }

            var end = format.IndexOf('}', at + 1);
            if (end < 0)
                return false;
            if (format.AsSpan(at + 1, end - at - 1).Contains(':'))
                return true;
            at = format.IndexOf('{', end + 1);
        }

        return false;
    }

    /// <summary>
    /// The value to fill a format item with, as the framework would see it, or nothing when what is
    /// there is something whose text is its own business.
    /// </summary>
    private static bool Rendering(StaticHeap heap, StaticValue value, out object? rendered)
    {
        rendered = null;
        if (value.Kind == StaticValueKind.Null)
            return true;
        if (heap.TryGetString(value, out var text))
        {
            rendered = text;
            return true;
        }

        if (!heap.TryUnbox(value, out var held) ||
            !heap.TryGetRuntimeTypeName(value, out var boxed))
            return false;
        rendered = boxed switch
        {
            "System.Char" => (char)held.AsInt32(),
            "System.Boolean" => held.AsInt32() != 0,
            "System.SByte" => (sbyte)held.AsInt32(),
            "System.Byte" => (byte)held.AsInt32(),
            "System.Int16" => (short)held.AsInt32(),
            "System.UInt16" => (ushort)held.AsInt32(),
            "System.Int32" => held.AsInt32(),
            "System.UInt32" => (uint)held.AsInt32(),
            "System.Int64" => held.AsInt64(),
            "System.UInt64" => (ulong)held.AsInt64(),
            _ => null
        };
        return rendered is not null;
    }

    /// <summary>
    /// How a string operation was asked to compare, when that is something answerable here.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only the two ordinal comparisons are answered. The rest are decided by a culture's collation
    /// rules, which differ between the machine this runs on and the machine the sample expects, and
    /// a comparison answered by the wrong rules is exactly the kind of small wrong answer that sends
    /// the interpretation down a branch the program would not have taken.
    /// </para>
    /// <para>
    /// An argument in the position where a comparison would be but holding something else means
    /// this overload has no comparison at all, and ordinal is what those do.
    /// </para>
    /// </remarks>
    private static bool Comparing(
        IMethod method,
        IReadOnlyList<StaticValue> arguments,
        out StringComparison how)
    {
        const int ordinal = 4;
        const int ordinalIgnoringCase = 5;
        how = StringComparison.Ordinal;
        foreach (var (declared, value) in Declared(method, arguments))
        {
            switch (declared)
            {
                case "System.StringComparison":
                    var stated = value.AsInt32();
                    if (stated == ordinalIgnoringCase)
                        how = StringComparison.OrdinalIgnoreCase;
                    return stated is ordinal or ordinalIgnoringCase;
                // A comparison can also arrive as a culture to use, as a comparer object, or as a
                // bare request to ignore case, which the framework grants using the current
                // culture. None of the three is answerable from here.
                case "System.Globalization.CultureInfo" or "System.StringComparer" or
                    "System.IFormatProvider":
                case "System.Boolean" when method.Name.String is "Compare" or "Equals"
                    or "EndsWith" or "StartsWith" or "IndexOf" or "LastIndexOf":
                    return false;
                default:
                    continue;
            }
        }

        return true;
    }

    /// <summary>
    /// The numbers a string operation was given, as its own signature describes them.
    /// </summary>
    /// <remarks>
    /// A start index and a comparison are both an integer on the stack, so which one an argument is
    /// can only be read from the signature. Reading it from the value instead would turn a search
    /// from position four into a search by the rules of a culture numbered four.
    /// </remarks>
    private static List<int> Counted(IMethod method, IReadOnlyList<StaticValue> arguments) =>
    [
        .. Declared(method, arguments)
            .Where(item => item.Declared == "System.Int32")
            .Select(item => item.Value.AsInt32())
    ];

    /// <summary>
    /// Pairs each argument with the type its parameter is declared as, skipping the receiver.
    /// </summary>
    private static IEnumerable<(string Declared, StaticValue Value)> Declared(
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        var parameters = method.MethodSig?.Params;
        if (parameters is null)
            yield break;
        var receiver = arguments.Count - parameters.Count;
        for (var index = 0; index < parameters.Count; index++)
        {
            if (index + receiver >= 0 && index + receiver < arguments.Count)
                yield return (parameters[index].FullName, arguments[index + receiver]);
        }
    }

    private static IntrinsicResult Culturally(string name) => IntrinsicResult.Invalid(
        $"String.{name} was asked to compare by a culture's rules, which depend on the machine" +
        " it runs on, so what it would answer is not known here.");

    /// <summary>
    /// Splits a string on the separators it was handed.
    /// </summary>
    /// <remarks>
    /// A runtime that carries a list of names in a single string splits it before it can use any of
    /// them, so this stands between the machine reading such a list and the machine reading anything
    /// the list names. Only the overloads whose separators can be read for certain are answered: the
    /// others differ in whether their last argument counts the parts or says what to do with the
    /// empty ones, and the two cannot be told apart from the value alone.
    /// </remarks>
    private static IntrinsicResult SplitString(
        IntrinsicContext context,
        string text,
        StaticValue separator)
    {
        var heap = context.State.Heap;
        var separators = new List<string>();
        if (heap.TryGetLength(separator, out var count))
        {
            for (var index = 0; index < count; index++)
            {
                if (!heap.TryReadArray(separator, index, out var held))
                    return IntrinsicResult.Invalid("A separator to split on could not be read.");
                if (heap.TryGetString(held, out var spelled))
                    separators.Add(spelled);
                else if (held.IsInteger && held.IsKnown)
                    separators.Add(((char)(ushort)held.AsInt32()).ToString());
                else
                    return IntrinsicResult.Invalid("A separator to split on is not known.");
            }
        }
        else if (heap.TryGetString(separator, out var only))
        {
            separators.Add(only);
        }
        else if (separator.IsInteger && separator.IsKnown)
        {
            separators.Add(((char)(ushort)separator.AsInt32()).ToString());
        }
        else if (separator.Kind != StaticValueKind.Null)
        {
            return IntrinsicResult.Invalid("What to split on is not modeled.");
        }

        // No separators at all means whitespace, which is what the framework makes of an empty set.
        var parts = separators.Count == 0
            ? text.Split((char[]?)null)
            : text.Split([.. separators], StringSplitOptions.None);
        if (!heap.TryAllocateArray(
                context.State.ModuleMetadata?.CorLibTypes.String,
                parts.Length,
                out var array))
        {
            return AllocationFailure("String.Split");
        }

        for (var index = 0; index < parts.Length; index++)
        {
            if (!heap.TryAllocateString(parts[index], out var part) ||
                !heap.TryWriteArray(array, index, part))
                return AllocationFailure("String.Split");
        }

        return IntrinsicResult.Completed(array);
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
        // Encoding.Default is deliberately absent: on the framework the sample targets it is the
        // machine's ANSI code page, which is a fact about the host that nothing here knows, and
        // guessing it would quietly produce the wrong bytes rather than stopping.
        if (name is "get_UTF8" or "get_Unicode" or "get_ASCII")
        {
            if (!heap.TryAllocateObject("System.Text.Encoding", out var encodingReference))
                return AllocationFailure(name);
            heap.TrySetModelValue(
                encodingReference,
                "Encoding",
                name switch
                {
                    "get_Unicode" => "Unicode",
                    "get_ASCII" => "ASCII",
                    _ => "UTF8"
                });
            return IntrinsicResult.Completed(encodingReference);
        }
        if (arguments.Count < 2 ||
            !heap.TryGetModelValue(arguments[0], "Encoding", out string? encodingName))
            return IntrinsicResult.Invalid($"Invalid Encoding receiver for {name}.");
        var encoding = encodingName switch
        {
            "Unicode" => Encoding.Unicode,
            "ASCII" => Encoding.ASCII,
            _ => Encoding.UTF8
        };
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
        if (name == ".ctor")
            return IntrinsicResult.Completed();
        // Everything else a hash can be asked is answered in one place, with the call site's own
        // spelling carried along for the rare receiver whose type the machine never witnessed.
        return InvokeHashAlgorithm(context, name, arguments, type);
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
            // Reactor picks its algorithm providers from the FIPS policy of the host, which is a
            // setting of the machine rather than anything the sample carries.
            if (name == "get_AllowOnlyFipsAlgorithms")
            {
                const string enforced = "runtime:FipsEnforced";
                return HostFacts.TryAsk(context, enforced, out var policy)
                    ? HostFacts.Number(context, enforced, policy.Flag ? 1 : 0)
                    : HostFacts.Refuse(context, enforced);
            }
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

    /// <summary>Model slot holding the encoded bytes a certificate was built from.</summary>
    private const string CertificateBytes = "Certificate";

    /// <summary>
    /// Models a certificate as the bytes it was handed, and nothing more.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Loaders and the malware underneath them carry certificates for two reasons: to pin the server
    /// they will talk to, and to check that a file is the one they shipped. Constructing one is
    /// therefore on the startup path of samples that never go on to ask it anything, and refusing the
    /// constructor stops those paths at a step whose result they only store.
    /// </para>
    /// <para>
    /// So the bytes are kept and the questions that are answerable from bytes alone are answered.
    /// The encoding is deliberately not decoded: what a subject line or a public key reads as takes a
    /// full X.509 parse of attacker-supplied bytes, and doing that here would run a parser this tool
    /// does not own over exactly the input it is meant to be safe against. A sample that asks is told
    /// so rather than given a plausible answer.
    /// </para>
    /// </remarks>
    private static IntrinsicResult InvokeCertificate(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (arguments.Count == 0)
            return IntrinsicResult.Invalid($"Unsupported certificate operation {name}.");
        var receiver = arguments[0];
        if (name is ".ctor" or "Import")
        {
            // A file path, a store name, or a password-protected container are all ways of naming a
            // certificate the analysis does not have; only bytes it was given are one it does.
            if (arguments.Count < 2 || !TryReadByteArray(heap, arguments[1], out var encoded))
                return IntrinsicResult.Invalid(
                    "A certificate is only modeled when it is built from bytes in memory.");
            heap.TrySetModelValue(receiver, CertificateBytes, encoded);
            return IntrinsicResult.Completed();
        }

        if (!heap.TryGetModelValue(receiver, CertificateBytes, out byte[]? bytes) || bytes is null)
            return IntrinsicResult.Invalid($"The certificate {name} was asked of has no bytes.");
        switch (name)
        {
            case "get_RawData" or "GetRawCertData" or "Export" when arguments.Count <= 2:
                return heap.TryAllocateByteArray(bytes, out var raw)
                    ? IntrinsicResult.Completed(raw)
                    : AllocationFailure("certificate bytes");
            case "Dispose" or "Reset":
                return IntrinsicResult.Completed();
            case "Equals" when arguments.Count == 2:
                return IntrinsicResult.Completed(StaticValue.FromInt32(
                    heap.TryGetModelValue(arguments[1], CertificateBytes, out byte[]? other) &&
                    other is not null && other.AsSpan().SequenceEqual(bytes)
                        ? 1
                        : 0));
            // The thumbprint is the hash of the encoded certificate, which is the hash of these
            // bytes only when these bytes are that encoding. A container holding a certificate
            // alongside a key hashes to something else entirely, so it is refused rather than
            // hashed: a wrong thumbprint is the kind of wrong answer that gets compared and kept.
            case "get_Thumbprint" or "GetCertHash" or "GetCertHashString":
            {
                if (!IsEncodedCertificate(bytes))
                    return IntrinsicResult.Invalid(
                        "These bytes are not a bare certificate, so their hash is not its hash.");
#pragma warning disable CA5350
                var digest = SHA1.HashData(bytes);
#pragma warning restore CA5350
                if (name == "GetCertHash")
                    return heap.TryAllocateByteArray(digest, out var hash)
                        ? IntrinsicResult.Completed(hash)
                        : AllocationFailure("certificate hash");
                return heap.TryAllocateString(Convert.ToHexString(digest), out var printed)
                    ? IntrinsicResult.Completed(printed)
                    : AllocationFailure("certificate thumbprint");
            }

            default:
                return IntrinsicResult.Invalid(
                    $"Reading {name} off a certificate would take decoding it, which is not done " +
                    "here.");
        }
    }

    /// <summary>
    /// Whether a buffer is a bare encoded certificate rather than a container holding one.
    /// </summary>
    /// <remarks>
    /// Both are a DER sequence, and what follows tells them apart: a certificate opens with the
    /// sequence of its own signed part, while a PKCS#12 container opens with a version number. The
    /// check goes no further than that, because it decides only whether hashing the buffer answers
    /// the question asked, not what the buffer contains.
    /// </remarks>
    private static bool IsEncodedCertificate(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < 4 || bytes[0] != 0x30)
            return false;
        var header = bytes[1] switch
        {
            < 0x80 => 2,
            0x81 => 3,
            0x82 => 4,
            0x83 => 5,
            _ => 0
        };
        return header != 0 && header < bytes.Length && bytes[header] == 0x30;
    }

    private static IntrinsicResult InvokeHashAlgorithm(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments,
        string? spelled = null)
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
            // Which algorithm this is comes from the object rather than from the call site, because
            // code that hashes something through a variable of the base type has spelled the call
            // the same way whatever it created. The concrete spellings route here too, so one
            // implementation answers both and neither can drift from the other.
            case "ComputeHash" when arguments.Count is 2 or 4:
            {
                byte[] data;
                if (arguments.Count == 4)
                {
                    if (!TryReadHashSegment(heap, arguments, out data, out var failure))
                        return failure;
                }
                else if (!TryReadByteArray(heap, arguments[1], out data))
                {
                    return IntrinsicResult.Invalid("Hash input bytes are unavailable.");
                }

                if (ComputeDigest(heap, receiver, data, spelled) is not { } computed)
                    return IntrinsicResult.Invalid(
                        "Hash algorithm is unknown, so what it would return is not known either.");
                if (!heap.TryAllocateByteArray(computed, out var hash))
                    return AllocationFailure("hash result");
                PendingHashBytes(heap, receiver).Clear();
                heap.TrySetModelValue(receiver, "Hash", hash);
                return IntrinsicResult.Completed(hash);
            }
            // Resetting a hash discards what it had accumulated and nothing else.
            case "Initialize" or "Clear" or "Dispose":
                PendingHashBytes(heap, receiver).Clear();
                return IntrinsicResult.Completed();
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
                if (ComputeDigest(heap, receiver, [.. pending], spelled) is not { } digestBytes)
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
    /// <summary>
    /// Hashes with whatever algorithm the object is, or the one the call site named if the object
    /// arrived from somewhere the machine did not watch.
    /// </summary>
    private static byte[]? ComputeDigest(
        StaticHeap heap,
        StaticValue receiver,
        byte[] data,
        string? spelled = null)
    {
        var algorithm = heap.TryGetRuntimeTypeName(receiver, out var typeName)
            ? Canonicalize(typeName)
            : spelled;
        return algorithm switch
        {
            "System.Security.Cryptography.SHA1" => SHA1.HashData(data),
            "System.Security.Cryptography.MD5" => MD5.HashData(data),
            "System.Security.Cryptography.SHA256" => SHA256.HashData(data),
            _ => null
        };
    }
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
        // Nothing started this run. A protected library is loaded by something else, and in an
        // interpretation there is no process for anything to have been the entry point of. The
        // framework answers null in exactly that situation — a run begun from unmanaged code — and
        // code that asks handles null for that reason, so this is an answer rather than a guess at
        // an assembly the machine has never seen.
        if (name == "GetEntryAssembly" && arguments.Count == 0)
            return IntrinsicResult.Completed(StaticValue.Null);
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
        // An assembly loaded from bytes has no location, and the framework says so with an empty
        // string rather than by failing, so that is what the machine says too.
        if (name == "get_Location" && arguments.Count == 1)
            return context.State.Heap.TryAllocateString(
                context.State.ModuleFileIsAbsent
                    ? string.Empty
                    : context.State.ModulePath.Length != 0
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
            // A member reached by token carries the signature this file writes down for it, whether
            // it is defined here or only referred to. That is the shape read rather than assumed, so
            // a call assembled around it is one the machine can pop the right number of values for,
            // and saying so here is what lets a runtime that rebuilds its calls by token be followed
            // through the assembling.
            if (member is IMethod { MethodSig: not null })
            {
                context.State.Heap.TrySetModelValue(
                    resolved, ReflectionEmitIntrinsic.Confirmed, true);
            }

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
        {
            return HostFacts.TryAsk(context, "process:Id", out var processId)
                ? HostFacts.Number(context, "process:Id", processId.Number)
                : HostFacts.Refuse(context, "process:Id");
        }
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
            if (!HostFacts.TryAsk(context, RuntimeModuleName, out var runtimeName))
                return HostFacts.Refuse(context, RuntimeModuleName);
            if (!heap.TryAllocateRegion(64 * 1024, "RuntimeModule", out var runtimeBase))
                return AllocationFailure("runtime module image");
            heap.TrySetModelValue(runtimeModule, "BaseAddress", runtimeBase);
            heap.TrySetModelValue(runtimeModule, "ModuleName", runtimeName.Text);
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
            if (heap.TryGetModelValue(arguments[0], "ModuleName", out string? stored) &&
                !string.IsNullOrEmpty(stored))
            {
                return heap.TryAllocateString(stored, out var moduleName)
                    ? IntrinsicResult.Completed(moduleName)
                    : AllocationFailure("runtime module name");
            }
            return HostFacts.TryAsk(context, RuntimeModuleName, out var named)
                ? HostFacts.Text(context, RuntimeModuleName, named.Text)
                : HostFacts.Refuse(context, RuntimeModuleName);
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
            // Which runtime the process is running under is a fact about the machine, and Reactor
            // reads it to decide which of its own code paths applies.
            var part = name switch
            {
                "get_FileMajorPart" or "get_ProductMajorPart" => "runtime:VersionMajor",
                "get_FileMinorPart" or "get_ProductMinorPart" => "runtime:VersionMinor",
                "get_FileBuildPart" or "get_ProductBuildPart" => "runtime:VersionBuild",
                "get_FilePrivatePart" or "get_ProductPrivatePart" => "runtime:VersionPrivate",
                "get_FileVersion" or "get_ProductVersion" => "runtime:FileVersion",
                _ => null
            };
            if (part is not null)
            {
                if (!HostFacts.TryAsk(context, part, out var stated))
                    return HostFacts.Refuse(context, part);
                return part == "runtime:FileVersion"
                    ? HostFacts.Text(context, part, stated.Text)
                    : HostFacts.Number(context, part, stated.Number);
            }
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
