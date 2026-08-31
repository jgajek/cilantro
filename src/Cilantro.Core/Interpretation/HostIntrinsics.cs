using System.Globalization;
using dnlib.DotNet;

namespace Cilantro.Core.Interpretation;

/// <summary>
/// How an intrinsic asks the host profile a question and turns the answer into a value.
/// </summary>
/// <remarks>
/// Every answer that comes from here is tagged as having come from here, so that a value which
/// traces back to something a person stated is distinguishable from one the sample's own bytes
/// determined. The tagging is in this one place rather than at each call site because an intrinsic
/// author who forgets it produces a value that lies about where it came from, and there is no way to
/// notice that afterwards.
/// </remarks>
internal static class HostFacts
{
    public static bool TryAsk(IntrinsicContext context, string key, out HostAnswer answer) =>
        context.State.TryAskHost(key, out answer);

    /// <summary>The refusal for a question the profile has no answer for.</summary>
    /// <remarks>
    /// Written into the run's ledger as well as into the diagnostic, because this is the refusal with
    /// the plainest remedy of all of them: the run asked something, nobody had said what the answer
    /// is, and saying it is a line in a file.
    /// </remarks>
    public static IntrinsicResult Refuse(IntrinsicContext context, string key)
    {
        context.State.Blockers.Record(
            BlockerKind.UnstatedFact,
            key,
            context.State.Host.Unanswered(key),
            Declaring.Fact(key));
        return new IntrinsicResult(
            StaticExecutionStatus.Unsupported,
            StaticValue.Unknown,
            context.State.Host.Unanswered(key));
    }

    /// <summary>
    /// Tags an answer with where it came from: somebody's statement, or the tool's assumption.
    /// </summary>
    /// <remarks>
    /// Which of the two it is is a property of the answer rather than of the question, so it is read
    /// back off the profile here instead of being passed in by each caller.
    /// </remarks>
    public static StaticValue Stated(IntrinsicContext context, string key, StaticValue value) =>
        context.State.Provenance.Origin(
            value,
            context.State.Host.Assumed(key) ? ProvenanceKind.Assumed : ProvenanceKind.Host,
            "host",
            key);

    public static IntrinsicResult Number(IntrinsicContext context, string key, long number) =>
        IntrinsicResult.Completed(Stated(context, key, StaticValue.FromInt32(
            number is >= int.MinValue and <= int.MaxValue ? (int)number : 0)));

    public static IntrinsicResult Wide(IntrinsicContext context, string key, long number) =>
        IntrinsicResult.Completed(Stated(context, key, StaticValue.FromInt64(number)));

    public static IntrinsicResult Text(IntrinsicContext context, string key, string text) =>
        context.State.Heap.TryAllocateString(text, out var value)
            ? IntrinsicResult.Completed(Stated(context, key, value))
            : new IntrinsicResult(
                StaticExecutionStatus.AllocationLimitExceeded,
                StaticValue.Unknown,
                $"The answer to {key} exceeded the allocation budget.");

    /// <summary>
    /// Answers with whatever kind of thing the profile said, when the caller can take either.
    /// </summary>
    /// <remarks>
    /// A WMI property and a registry value are whatever the machine they describe holds, and the
    /// profile is written by somebody describing that machine rather than filling in a form. So a
    /// serial number stated as text and a count stated as a number both arrive here, and which one
    /// it is is the profile's business rather than the call site's.
    /// </remarks>
    public static IntrinsicResult Answer(IntrinsicContext context, string key, HostAnswer answer) =>
        answer.Kind switch
        {
            HostAnswerKind.Absent => IntrinsicResult.Completed(StaticValue.Null),
            HostAnswerKind.Text => Text(context, key, answer.Text),
            HostAnswerKind.Bytes => Bytes(context, key, answer.Data),
            _ => Number(context, key, answer.Number)
        };

    public static IntrinsicResult Bytes(IntrinsicContext context, string key, byte[] bytes) =>
        context.State.Heap.TryAllocateByteArray(bytes, out var value)
            ? IntrinsicResult.Completed(Stated(context, key, value))
            : new IntrinsicResult(
                StaticExecutionStatus.AllocationLimitExceeded,
                StaticValue.Unknown,
                $"The answer to {key} exceeded the allocation budget.");
}

/// <summary>
/// Answers <c>System.Environment</c>, which is a program asking about the computer directly.
/// </summary>
/// <remarks>
/// Nothing here was modeled before, so every one of these calls used to stop the interpretation at
/// the point it was made. That is the right outcome when nobody has said what the machine looks
/// like, and it stays the outcome: the built-in profile answers none of these. What changes is that
/// the refusal now names the fact that would answer it, and that somebody who knows the answer has
/// somewhere to put it.
/// </remarks>
public sealed class EnvironmentIntrinsic : IStaticIntrinsic
{
    /// <summary>The properties whose names carry straight across into profile keys.</summary>
    private static readonly HashSet<string> Properties = new(StringComparer.Ordinal)
    {
        "MachineName",
        "UserName",
        "UserDomainName",
        "OSVersion",
        "ProcessorCount",
        "Is64BitOperatingSystem",
        "Is64BitProcess",
        "SystemDirectory",
        "CurrentDirectory",
        "CommandLine",
        "TickCount",
        "UserInteractive",
        "ExitCode",
        "ProcessorRevision"
    };

    public bool Matches(IMethod method) =>
        method.DeclaringType?.FullName == "System.Environment";

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

        // A newline is a property of the framework rather than of the machine: every Windows runtime
        // says the same two characters, and a profile asked to state it would only be able to agree.
        if (name == "get_NewLine" && arguments.Count == 0)
            return heap.TryAllocateString("\r\n", out var newLine)
                ? IntrinsicResult.Completed(newLine)
                : IntrinsicResult.Invalid("Could not allocate the line separator.");
        if (name == "GetEnvironmentVariable" && arguments.Count >= 1 &&
            heap.TryGetString(arguments[0], out var variable))
        {
            // A variable nobody has described is not answered with the null a real machine would
            // give for an unset one, because the two are different claims and only one of them is
            // known. A profile that means "unset" says so with null, and then it is an answer.
            var key = $"env:var:{variable}";
            return HostFacts.TryAsk(context, key, out var stated)
                ? HostFacts.Answer(context, key, stated)
                : HostFacts.Refuse(context, key);
        }
        if (name == "GetFolderPath" && arguments.Count >= 1 && arguments[0].IsInteger)
        {
            var key = $"env:folder:{arguments[0].AsInt32()}";
            return HostFacts.TryAsk(context, key, out var folder)
                ? HostFacts.Answer(context, key, folder)
                : HostFacts.Refuse(context, key);
        }
        if (name == "Exit" || name == "FailFast")
        {
            context.State.Observe(
                LoaderObservationKind.Termination,
                $"System.Environment::{name}",
                verdict: true);
            return new IntrinsicResult(
                StaticExecutionStatus.Unsupported,
                StaticValue.Unknown,
                "the program asked to end here, so there is nothing further to interpret");
        }

        var property = name.StartsWith("get_", StringComparison.Ordinal) ? name[4..] : name;
        if (!Properties.Contains(property))
            return IntrinsicResult.Invalid($"Unsupported environment operation {name}.");
        var asked = $"env:{property}";
        return HostFacts.TryAsk(context, asked, out var answer)
            ? HostFacts.Answer(context, asked, answer)
            : HostFacts.Refuse(context, asked);
    }
}

/// <summary>
/// Answers <c>RuntimeInformation.IsOSPlatform</c> and the <c>OSPlatform</c> values it compares
/// against, which is how a CoreCLR loader asks which operating system it is running on.
/// </summary>
/// <remarks>
/// This is the branch that stops a Reactor-protected .NET Core loader within the first couple of
/// hundred steps, and it is not a Reactor 7 problem: a Reactor 6 build targeting .NET Core reaches
/// the same call, because it is the framework rather than the protector that asks. The
/// <c>OSPlatform</c> readers return framework constants, so they carry no host provenance; only the
/// answer to "is this that platform?" comes from the profile, and it is tagged accordingly and
/// refused in a strict run where nobody has said which machine this is. The default workstation
/// profile states Windows, which is the same machine the rest of its facts describe.
/// </remarks>
public sealed class OperatingSystemIntrinsic : IStaticIntrinsic
{
    private const string PlatformKey = "runtime:OSPlatform";
    private const string PlatformModel = "OSPlatform";

    public bool Matches(IMethod method) =>
        method.DeclaringType?.FullName is
            "System.Runtime.InteropServices.OSPlatform" or
            "System.Runtime.InteropServices.RuntimeInformation";

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
        if (method.DeclaringType?.FullName == "System.Runtime.InteropServices.RuntimeInformation")
        {
            if (name == "IsOSPlatform" && arguments.Count == 1)
                return IsOSPlatform(context, arguments[0]);
            return IntrinsicResult.Invalid($"Unsupported RuntimeInformation operation {name}.");
        }
        switch (name)
        {
            case "get_Windows": return Platform(heap, "WINDOWS");
            case "get_Linux": return Platform(heap, "LINUX");
            case "get_OSX": return Platform(heap, "OSX");
            case "get_FreeBSD": return Platform(heap, "FREEBSD");
            case "Create" when arguments.Count == 1 && heap.TryGetString(arguments[0], out var made):
                return Platform(heap, made);
            case "op_Equality" when arguments.Count == 2:
                return Compare(heap, arguments[0], arguments[1], equal: true);
            case "op_Inequality" when arguments.Count == 2:
                return Compare(heap, arguments[0], arguments[1], equal: false);
            case "Equals" when arguments.Count == 2:
                return Compare(heap, arguments[0], arguments[1], equal: true);
            case "ToString" when arguments.Count == 1 &&
                heap.TryGetModelValue(arguments[0], PlatformModel, out string? shown) &&
                shown is not null:
                return heap.TryAllocateString(shown, out var text)
                    ? IntrinsicResult.Completed(text)
                    : IntrinsicResult.Invalid("Could not allocate the OSPlatform name.");
            default:
                return IntrinsicResult.Invalid($"Unsupported OSPlatform operation {name}.");
        }
    }

    private static IntrinsicResult Platform(StaticHeap heap, string platform)
    {
        if (!heap.TryAllocateObject("System.Runtime.InteropServices.OSPlatform", out var value))
            return IntrinsicResult.Invalid("Could not allocate an OSPlatform value.");
        heap.TrySetModelValue(value, PlatformModel, platform);
        return IntrinsicResult.Completed(value);
    }

    private static IntrinsicResult Compare(
        StaticHeap heap,
        StaticValue left,
        StaticValue right,
        bool equal)
    {
        if (!heap.TryGetModelValue(left, PlatformModel, out string? a) || a is null ||
            !heap.TryGetModelValue(right, PlatformModel, out string? b) || b is null)
            return IntrinsicResult.Unknown("An OSPlatform being compared could not be identified.");
        // The framework compares the underlying names ordinally, so the model does too.
        var same = string.Equals(a, b, StringComparison.Ordinal);
        return IntrinsicResult.Completed(StaticValue.FromInt32(same == equal ? 1 : 0));
    }

    private static IntrinsicResult IsOSPlatform(IntrinsicContext context, StaticValue platform)
    {
        if (!context.State.Heap.TryGetModelValue(platform, PlatformModel, out string? want) ||
            string.IsNullOrEmpty(want))
            return IntrinsicResult.Unknown(
                "RuntimeInformation.IsOSPlatform received an OSPlatform this reading could not identify.");
        if (!HostFacts.TryAsk(context, PlatformKey, out var answer))
            return HostFacts.Refuse(context, PlatformKey);
        var isMatch = string.Equals(answer.Text, want, StringComparison.OrdinalIgnoreCase);
        return HostFacts.Number(context, PlatformKey, isMatch ? 1 : 0);
    }
}

/// <summary>
/// Answers the registry, which malware reads to learn where it is and whether it has been here.
/// </summary>
/// <remarks>
/// Only reading is modeled. A write goes nowhere the interpretation can observe and nothing later
/// reads it back, so it is accepted and forgotten, which is what it amounts to; a program that
/// writes a value and reads it again in the same run is the one case this gets wrong, and it stops
/// there rather than answering from the profile as though the write had not happened.
/// </remarks>
public sealed class RegistryIntrinsic : IStaticIntrinsic
{
    private const string SubKey = "SubKey";

    /// <summary>
    /// The hives, by the name they are reached under. Which spelling that is depends on the framework
    /// the sample was built for — a property on one, a static field on the other — so both arrive
    /// here and the "get_" is stripped before the lookup.
    /// </summary>
    private static readonly Dictionary<string, string> Hives = new(StringComparer.Ordinal)
    {
        ["LocalMachine"] = "HKEY_LOCAL_MACHINE",
        ["CurrentUser"] = "HKEY_CURRENT_USER",
        ["ClassesRoot"] = "HKEY_CLASSES_ROOT",
        ["Users"] = "HKEY_USERS",
        ["CurrentConfig"] = "HKEY_CURRENT_CONFIG",
        ["PerformanceData"] = "HKEY_PERFORMANCE_DATA"
    };

    /// <summary>Opens a hive read as a static field rather than called as a property.</summary>
    public static bool TryOpenHive(StaticHeap heap, string field, out StaticValue value)
    {
        ArgumentNullException.ThrowIfNull(heap);
        value = StaticValue.Unknown;
        if (!Hives.TryGetValue(field, out var hive) ||
            !heap.TryAllocateObject("Microsoft.Win32.RegistryKey", out value))
            return false;
        heap.TrySetModelValue(value, SubKey, hive);
        return true;
    }

    public bool Matches(IMethod method) =>
        method.DeclaringType?.FullName is
            "Microsoft.Win32.Registry" or "Microsoft.Win32.RegistryKey";

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
        if (name.StartsWith("get_", StringComparison.Ordinal) &&
            Hives.ContainsKey(name[4..]) && arguments.Count == 0)
            return Key(context, Hives[name[4..]]);
        if (name is "OpenSubKey" or "CreateSubKey" && arguments.Count >= 2 &&
            heap.TryGetModelValue(arguments[0], SubKey, out string? parent) &&
            heap.TryGetString(arguments[1], out var child))
        {
            var path = $"{parent}\\{child}";
            var key = $"registry:{path}";
            // A key is only there if the profile says it is, and the framework reports a key that is
            // not there as null rather than by failing. Opening one therefore asks the profile, and
            // a profile that says nothing about it leaves the program on the branch it wrote for a
            // machine that has never seen it.
            if (name == "OpenSubKey" && HostFacts.TryAsk(context, key, out var stated) &&
                stated.Kind == HostAnswerKind.Absent)
                return IntrinsicResult.Completed(StaticValue.Null);
            return Key(context, path);
        }
        if (name == "GetValue" && arguments.Count >= 2 &&
            heap.TryGetModelValue(arguments[0], SubKey, out string? holder) &&
            heap.TryGetString(arguments[1], out var valueName))
        {
            var key = $"registry:{holder}!{valueName}";
            if (HostFacts.TryAsk(context, key, out var answer))
                return HostFacts.Answer(context, key, answer);
            // The framework answers a missing value with the default the caller supplied, and a
            // caller that supplied one has already said what it wants to happen.
            return arguments.Count >= 3
                ? IntrinsicResult.Completed(arguments[2])
                : HostFacts.Refuse(context, key);
        }
        if (name is "GetSubKeyNames" or "GetValueNames" && arguments.Count == 1)
        {
            // What a key contains is a list, and a profile states single facts. Saying so is better
            // than answering with an empty array that the program would read as an empty machine.
            return heap.TryGetModelValue(arguments[0], SubKey, out string? listed)
                ? HostFacts.Refuse(context, $"registry:{listed}!*")
                : IntrinsicResult.Invalid("The registry key being listed is not modeled.");
        }
        if (name is "SetValue" or "DeleteValue" or "DeleteSubKey" or "DeleteSubKeyTree")
        {
            context.State.RecordRegistration($"Registry.{name}");
            return IntrinsicResult.Completed();
        }
        if (name is "Close" or "Dispose" or "Flush")
            return IntrinsicResult.Completed();
        if (name == "get_Name" && arguments.Count == 1 &&
            heap.TryGetModelValue(arguments[0], SubKey, out string? named))
        {
            return heap.TryAllocateString(named ?? string.Empty, out var text)
                ? IntrinsicResult.Completed(text)
                : IntrinsicResult.Invalid("Could not allocate the registry key name.");
        }
        return IntrinsicResult.Invalid($"Unsupported registry operation {name}.");
    }

    private static IntrinsicResult Key(IntrinsicContext context, string path)
    {
        if (!context.State.Heap.TryAllocateObject("Microsoft.Win32.RegistryKey", out var key))
            return new IntrinsicResult(
                StaticExecutionStatus.AllocationLimitExceeded,
                StaticValue.Unknown,
                "The registry key exceeded the allocation budget.");
        context.State.Heap.TrySetModelValue(key, SubKey, path);
        return IntrinsicResult.Completed(key);
    }
}

/// <summary>
/// Answers WMI, which is how a Windows program asks who and where it is.
/// </summary>
/// <remarks>
/// Malware uses this for two things: deciding whether it is inside a sandbox, by asking for the
/// manufacturer and model of the computer, and building an identifier for the machine out of serial
/// numbers. Both are questions about a machine rather than about the sample, so both are the
/// profile's to answer, and a profile that answers neither leaves the sample's own paths refused
/// where they always were.
///
/// The model is narrow on purpose. A query is read for the class it names, a property is read by
/// name, and enumerating a collection yields one instance, because a profile states one machine.
/// Anything more elaborate is refused rather than approximated.
/// </remarks>
public sealed class ManagementIntrinsic : IStaticIntrinsic
{
    private const string Subject = "WmiClass";
    private const string Visited = "Visited";

    private const string Enumerator =
        "System.Management.ManagementObjectCollection/ManagementObjectEnumerator";

    public bool Matches(IMethod method) =>
        method.DeclaringType?.FullName is
            "System.Management.ManagementClass" or
            "System.Management.ManagementObjectSearcher" or
            "System.Management.ManagementObjectCollection" or
            Enumerator or
            "System.Management.ManagementObject" or
            "System.Management.ManagementBaseObject" or
            "System.Management.PropertyData" or
            "System.Management.PropertyDataCollection" or
            "System.Management.SelectQuery" or
            "System.Management.ObjectQuery";

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(arguments);
        var heap = context.State.Heap;
        var type = method.DeclaringType!.FullName;
        var name = method.Name.String;
        if (name == ".ctor")
        {
            heap.TrySetModelValue(arguments[0], Subject, Named(heap, arguments));
            return IntrinsicResult.Completed();
        }
        if (name is "Get" or "GetInstances" && arguments.Count >= 1)
        {
            if (!heap.TryAllocateObject(
                    "System.Management.ManagementObjectCollection", out var collection))
                return Budget("instance collection");
            heap.TrySetModelValue(collection, Subject, Of(heap, arguments[0]));
            heap.TrySetModelValue(collection, Visited, false);
            return IntrinsicResult.Completed(collection);
        }
        if (name == "GetEnumerator" && arguments.Count == 1)
        {
            if (!heap.TryAllocateObject(Enumerator, out var enumerator))
                return Budget("instance enumerator");
            heap.TrySetModelValue(enumerator, Subject, Of(heap, arguments[0]));
            heap.TrySetModelValue(enumerator, Visited, false);
            return IntrinsicResult.Completed(enumerator);
        }
        // A profile describes one machine, so a query over it yields one instance: the first step
        // of an enumeration finds it and the second finds nothing, which is what a program written
        // to loop over "every processor" gets on a computer that has one.
        if (name == "MoveNext" && arguments.Count == 1)
        {
            var first = heap.TryGetModelValue(arguments[0], Visited, out bool seen) && !seen;
            heap.TrySetModelValue(arguments[0], Visited, true);
            return IntrinsicResult.Completed(StaticValue.FromInt32(first ? 1 : 0));
        }
        if (name == "Reset" && arguments.Count == 1)
        {
            heap.TrySetModelValue(arguments[0], Visited, false);
            return IntrinsicResult.Completed();
        }
        if (name == "get_Current" && arguments.Count == 1)
        {
            if (!heap.TryAllocateObject("System.Management.ManagementObject", out var instance))
                return Budget("instance");
            heap.TrySetModelValue(instance, Subject, Of(heap, arguments[0]));
            return IntrinsicResult.Completed(instance);
        }
        if (name == "get_Count" && arguments.Count == 1)
            return IntrinsicResult.Completed(StaticValue.FromInt32(1));
        if (name is "get_Item" or "GetPropertyValue" && arguments.Count == 2 &&
            heap.TryGetString(arguments[1], out var property))
        {
            var key = $"wmi:{Of(heap, arguments[0])}.{property}";
            return HostFacts.TryAsk(context, key, out var answer)
                ? HostFacts.Answer(context, key, answer)
                : HostFacts.Refuse(context, key);
        }
        if (name is "Dispose" or "Close")
            return IntrinsicResult.Completed();
        return IntrinsicResult.Invalid(
            $"Unsupported management operation {type}::{name}.");
    }

    /// <summary>What this object is carried along as being about.</summary>
    private static string Of(StaticHeap heap, StaticValue value) =>
        heap.TryGetModelValue(value, Subject, out string? subject) ? subject ?? string.Empty : string.Empty;

    /// <summary>
    /// The class a query is about, whether it was named directly or written out as a query.
    /// </summary>
    /// <remarks>
    /// The constructors differ in how many strings they take and in what order — a scope and a
    /// query, a query alone, a class path alone — so the class is found by looking for the thing
    /// that reads like a query and falling back on the last string given, which is where every one
    /// of these overloads puts the interesting argument.
    /// </remarks>
    private static string Named(StaticHeap heap, IReadOnlyList<StaticValue> arguments)
    {
        var given = arguments
            .Skip(1)
            .Select(argument => heap.TryGetString(argument, out var text) ? text : null)
            .Where(text => !string.IsNullOrWhiteSpace(text))
            .ToArray();
        var subject = given.LastOrDefault(text =>
            text!.Contains(" from ", StringComparison.OrdinalIgnoreCase)) ??
            given.LastOrDefault();
        if (string.IsNullOrEmpty(subject))
            return string.Empty;
        var from = subject.IndexOf(" from ", StringComparison.OrdinalIgnoreCase);
        if (from < 0)
            return subject.Trim();
        var rest = subject[(from + 6)..].Trim();
        var end = rest.IndexOf(' ', StringComparison.Ordinal);
        return (end < 0 ? rest : rest[..end]).Trim();
    }

    private static IntrinsicResult Budget(string what) => new(
        StaticExecutionStatus.AllocationLimitExceeded,
        StaticValue.Unknown,
        $"The WMI {what} exceeded the allocation budget.");
}

/// <summary>
/// Answers the native entry points that only ask the host something.
/// </summary>
/// <remarks>
/// A platform call is a boundary rather than a gap, and most of them stay one: the machine has
/// nowhere to run the code behind them and no way to know what it would do. These are the exception,
/// because what they do is report a fact rather than perform an action, and a fact is exactly what a
/// profile holds. <c>SetProcessDPIAware</c> succeeds or does not, <c>GetForegroundWindow</c> hands
/// back a number, <c>GetTickCount</c> reads a clock. Where the profile states the answer the call
/// can be answered without inventing anything; where it does not, the call stops as before, and the
/// diagnostic says which fact would let it through.
/// </remarks>
public sealed class NativeHostIntrinsic : IStaticIntrinsic
{
    /// <summary>
    /// The entry points whose whole effect is to answer a question about the machine.
    /// </summary>
    /// <remarks>
    /// Deliberately a list rather than a rule. "Returns an integer and takes little" describes
    /// plenty of calls that also do something, and answering one of those from a profile would say
    /// the action succeeded when nothing performed it.
    /// </remarks>
    private static readonly HashSet<string> Questions = new(StringComparer.Ordinal)
    {
        "SetProcessDPIAware",
        "SetProcessDpiAwarenessContext",
        "GetForegroundWindow",
        "GetActiveWindow",
        "GetDesktopWindow",
        "GetSystemMetrics",
        "GetDpiForSystem",
        "GetTickCount",
        "GetTickCount64",
        "GetCurrentProcessId",
        "GetCurrentThreadId",
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "GetSystemDefaultLangID",
        "GetUserDefaultLangID",
        "GetLogicalDrives",
        "GetSystemFirmwareTable"
    };

    public bool Matches(IMethod method) =>
        method.ResolveMethodDef()?.ImplMap is { } native && Questions.Contains(native.Name);

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(arguments);
        var native = method.ResolveMethodDef()?.ImplMap;
        if (native is null)
            return IntrinsicResult.Invalid("The platform call being asked about is not modeled.");
        var library = Path.GetFileNameWithoutExtension(native.Module?.Name ?? "unknown")
            .ToLowerInvariant();
        var entry = native.Name.String;

        // A debugger question is one the machine has always answered, and answering it here in a
        // different voice would report the same run two ways. It is recorded as the probe it is.
        if (entry is "IsDebuggerPresent" or "CheckRemoteDebuggerPresent")
        {
            context.State.Observe(
                LoaderObservationKind.DebuggerProbe,
                $"{library}!{entry}",
                verdict: false);
            if (entry == "CheckRemoteDebuggerPresent" && arguments.Count == 2 &&
                arguments[1].Kind == StaticValueKind.ManagedReference)
                context.State.Heap.TryWriteManaged(arguments[1], StaticValue.FromInt32(0));
            return IntrinsicResult.Completed(StaticValue.FromInt32(
                entry == "CheckRemoteDebuggerPresent" ? 1 : 0));
        }

        // Which metric is being asked for is part of the question, because the width of the screen
        // and the number of mouse buttons are not the same fact.
        var key = entry == "GetSystemMetrics" && arguments.Count == 1 && arguments[0].IsInteger
            ? $"native:{library}!{entry}({arguments[0].AsInt32()})"
            : $"native:{library}!{entry}";
        if (!HostFacts.TryAsk(context, key, out var answer))
            return HostFacts.Refuse(context, key);
        if (method.MethodSig?.RetType.ElementType is ElementType.Void)
            return IntrinsicResult.Completed();
        return method.MethodSig?.RetType.ElementType is ElementType.I8 or ElementType.U8
            ? HostFacts.Wide(context, key, answer.Number)
            : HostFacts.Answer(context, key, answer);
    }
}

/// <summary>
/// Models a named mutex, which is how a program asks whether a copy of itself is already running.
/// </summary>
/// <remarks>
/// <para>
/// The question is about the machine and not about the sample, so the profile answers it, and the
/// built-in answer is that nothing else holds the name. That is not a guess: the world this machine
/// models contains one process — it is the process the sample's own probes are answered about — and
/// in a world with one process a name nobody else took is free. A caller reproducing a machine where
/// the sample is already installed and running says so, and then the other branch is the one read.
/// </para>
/// <para>
/// Nothing is actually locked, because there is no second thread to lock against: the interpretation
/// is one path at a time, and a mutex it took would never be contended. So taking one succeeds and
/// releasing it is forgotten, which is what it comes to.
/// </para>
/// </remarks>
public sealed class MutexIntrinsic : IStaticIntrinsic
{
    /// <summary>Whether something on the machine already holds the name being asked for.</summary>
    public const string HeldKey = "process:MutexHeld";

    private const string Held = "Held";

    public bool Matches(IMethod method) =>
        method?.DeclaringType?.FullName is
            "System.Threading.Mutex" or "System.Threading.WaitHandle";

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
            return IntrinsicResult.Invalid($"Unsupported synchronization operation {name}.");

        if (name == ".ctor")
        {
            if (!HostFacts.TryAsk(context, HeldKey, out var answer))
                return HostFacts.Refuse(context, HeldKey);
            var taken = answer.Flag;
            heap.TrySetModelValue(arguments[0], Held, taken);
            // The out parameter says whether this call is what brought the name into being, which is
            // the same question turned around.
            if (arguments.Count >= 4 && arguments[3].Kind == StaticValueKind.ManagedReference)
                heap.TryWriteManaged(
                    arguments[3],
                    HostFacts.Stated(context, HeldKey, StaticValue.FromInt32(taken ? 0 : 1)));
            return IntrinsicResult.Completed();
        }

        switch (name)
        {
            case "WaitOne":
            {
                if (!HostFacts.TryAsk(context, HeldKey, out var answer))
                    return HostFacts.Refuse(context, HeldKey);
                var taken = heap.TryGetModelValue(arguments[0], Held, out bool stored)
                    ? stored
                    : answer.Flag;
                return IntrinsicResult.Completed(HostFacts.Stated(
                    context,
                    HeldKey,
                    StaticValue.FromInt32(taken ? 0 : 1)));
            }

            case "ReleaseMutex" or "Close" or "Dispose" or "SignalAndWait":
                return IntrinsicResult.Completed();
            default:
                return IntrinsicResult.Invalid($"Unsupported synchronization operation {name}.");
        }
    }
}

/// <summary>
/// Models the process-wide network settings a program writes before it talks to anything.
/// </summary>
/// <remarks>
/// <para>
/// A sample that fetches its next stage usually sets these first: it widens the TLS versions it will
/// offer, and it installs a callback that accepts every certificate so that its own inspection
/// proxy, or a self-signed server, is trusted. Neither has an effect anything here can observe,
/// because no connection is made during interpretation — but they sit in a constructor on the way to
/// the payload, so refusing them stops the recovery over something incidental.
/// </para>
/// <para>
/// A setting written during the run reads back as what was written, because the program that wrote
/// it is the authority on it. A setting never written is what the machine's framework was configured
/// to start with, which is a fact about that machine and so a question for the profile, except for
/// the callback: the framework installs none, on every machine, and that is the framework's own
/// documented behaviour rather than anything about where it runs. Installing one is recorded as a
/// registration, since it changes what the program does later while touching nothing visible.
/// </para>
/// </remarks>
public sealed class NetworkSettingsIntrinsic : IStaticIntrinsic
{
    private const string Callback = "ServerCertificateValidationCallback";

    /// <summary>The settings this models, by the name they are reached under.</summary>
    private static readonly HashSet<string> Settings = new(StringComparer.Ordinal)
    {
        "SecurityProtocol",
        Callback,
        "ClientCertificateValidationCallback",
        "DefaultConnectionLimit",
        "Expect100Continue",
        "UseNagleAlgorithm",
        "CheckCertificateRevocationList",
        "MaxServicePointIdleTime",
        "MaxServicePoints",
        "DnsRefreshTimeout",
        "EnableDnsRoundRobin",
        "ReusePort",
        "EncryptionPolicy"
    };

    /// <summary>What this run has written, so that reading it back gives it.</summary>
    private readonly Dictionary<string, StaticValue> _written = new(StringComparer.Ordinal);

    public bool Matches(IMethod method) =>
        method?.DeclaringType?.FullName == "System.Net.ServicePointManager";

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(arguments);
        var name = method.Name.String;
        var setting = name.Length > 4 ? name[4..] : name;
        if (name.StartsWith("set_", StringComparison.Ordinal) && arguments.Count == 1 &&
            Settings.Contains(setting))
        {
            _written[setting] = arguments[0];
            if (setting.EndsWith("Callback", StringComparison.Ordinal) &&
                arguments[0].Kind != StaticValueKind.Null)
                context.State.RecordRegistration($"ServicePointManager.{setting}");
            return IntrinsicResult.Completed();
        }
        if (name.StartsWith("get_", StringComparison.Ordinal) && arguments.Count == 0 &&
            Settings.Contains(setting))
        {
            if (_written.TryGetValue(setting, out var read))
                return IntrinsicResult.Completed(read);
            if (setting.EndsWith("Callback", StringComparison.Ordinal))
                return IntrinsicResult.Completed(StaticValue.Null);
            var key = $"net:{setting}";
            return HostFacts.TryAsk(context, key, out var stated)
                ? HostFacts.Answer(context, key, stated)
                : HostFacts.Refuse(context, key);
        }

        // Keeping a connection alive and finding the endpoint for one are about a connection, and
        // there is none; a program that then asks the endpoint something stops there instead.
        if (name == "SetTcpKeepAlive")
        {
            context.State.RecordRegistration("ServicePointManager.SetTcpKeepAlive");
            return IntrinsicResult.Completed();
        }
        return IntrinsicResult.Invalid($"Unsupported network setting {name}.");
    }
}

/// <summary>
/// Models an HTTP client as one that is configured but never used.
/// </summary>
/// <remarks>
/// <para>
/// A stager builds its client early — in the constructor that reads its configuration — and sends
/// nothing until later, often from a thread this interpretation never starts. Building it touches no
/// network: a client is a handler, a timeout and a set of headers, and all of that is arithmetic on
/// objects. So it is modeled, and the interpretation carries on to whatever the constructor does
/// next, which is where the payload usually is.
/// </para>
/// <para>
/// A request is where this stops. There is no network here and there will not be one, so what a
/// server would have answered is not something this machine can know, and it says so rather than
/// producing an empty response that the program would then treat as the server's reply. Headers are
/// remembered so that a client which reads back what it configured gets it; a header added as
/// something other than a plain string is remembered as present but not as any value, and reading
/// that one back stops rather than guessing at it.
/// </para>
/// </remarks>
public sealed class HttpClientIntrinsic : IStaticIntrinsic
{
    private const string Headers = "RequestHeaders";
    private const string Named = "HeaderValues";
    private const string Settings = "ClientSetting:";

    /// <summary>The client settings that are read back as whatever they were set to.</summary>
    private static readonly HashSet<string> Configured = new(StringComparer.Ordinal)
    {
        "Timeout",
        "BaseAddress",
        "MaxResponseContentBufferSize",
        "DefaultRequestVersion"
    };

    public bool Matches(IMethod method) =>
        method?.DeclaringType?.FullName is
            "System.Net.Http.HttpClient" or
            "System.Net.Http.HttpClientHandler" or
            "System.Net.Http.HttpMessageHandler" or
            "System.Net.Http.Headers.HttpRequestHeaders" or
            "System.Net.Http.Headers.HttpHeaders";

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
            return IntrinsicResult.Invalid($"HTTP operation {name} has no receiver.");
        var self = arguments[0];

        // A request is the one thing here that would need the network, and naming which one was
        // going to be made is more use than saying that something was.
        if (name is "GetAsync" or "PostAsync" or "PutAsync" or "DeleteAsync" or "PatchAsync" or
            "SendAsync" or "Send" or "GetStringAsync" or "GetByteArrayAsync" or "GetStreamAsync" or
            "SendRequest")
        {
            var where = arguments.Count > 1 && heap.TryGetString(arguments[1], out var address)
                ? $" to {address}"
                : string.Empty;
            return new IntrinsicResult(
                StaticExecutionStatus.Unsupported,
                StaticValue.Unknown,
                $"the program makes an HTTP request{where}, and there is no network here, so what " +
                "it would answer with is not known");
        }

        switch (name)
        {
            case ".ctor":
                return IntrinsicResult.Completed();
            case "Dispose" or "CancelPendingRequests":
                return IntrinsicResult.Completed();
            case "get_DefaultRequestHeaders" when arguments.Count == 1:
                if (heap.TryGetModelValue<StaticValue>(self, Headers, out var existing))
                    return IntrinsicResult.Completed(existing);
                if (!heap.TryAllocateObject(
                        "System.Net.Http.Headers.HttpRequestHeaders",
                        out var collection))
                    return IntrinsicResult.Invalid("Could not allocate the request headers.");
                heap.TrySetModelValue(self, Headers, collection);
                return IntrinsicResult.Completed(collection);
            case "Add" or "TryAddWithoutValidation" when arguments.Count >= 2:
            {
                if (!heap.TryGetString(arguments[1], out var header))
                    return IntrinsicResult.Invalid("A header was added under an unreadable name.");
                var held = Held(heap, self);
                held[header] = arguments.Count > 2 && heap.TryGetString(arguments[2], out var value)
                    ? value
                    : null;
                return name == "Add"
                    ? IntrinsicResult.Completed()
                    : IntrinsicResult.Completed(StaticValue.FromInt32(1));
            }

            case "Remove" when arguments.Count == 2:
            {
                if (!heap.TryGetString(arguments[1], out var header))
                    return IntrinsicResult.Invalid("A header was removed under an unreadable name.");
                var held = Held(heap, self);
                return IntrinsicResult.Completed(StaticValue.FromInt32(held.Remove(header) ? 1 : 0));
            }

            case "Clear" when arguments.Count == 1:
                Held(heap, self).Clear();
                return IntrinsicResult.Completed();
            case "Contains" when arguments.Count == 2:
            {
                if (!heap.TryGetString(arguments[1], out var header))
                    return IntrinsicResult.Invalid("A header was asked for by an unreadable name.");
                return IntrinsicResult.Completed(
                    StaticValue.FromInt32(Held(heap, self).ContainsKey(header) ? 1 : 0));
            }

            default:
                var setting = name.Length > 4 ? name[4..] : name;
                if (!Configured.Contains(setting))
                    return IntrinsicResult.Invalid($"Unsupported HTTP operation {name}.");
                if (name.StartsWith("set_", StringComparison.Ordinal) && arguments.Count == 2)
                {
                    heap.TrySetModelValue(self, Settings + setting, arguments[1]);
                    return IntrinsicResult.Completed();
                }
                if (!name.StartsWith("get_", StringComparison.Ordinal))
                    return IntrinsicResult.Invalid($"Unsupported HTTP operation {name}.");
                return heap.TryGetModelValue<StaticValue>(self, Settings + setting, out var read)
                    ? IntrinsicResult.Completed(read)
                    : IntrinsicResult.Invalid(
                        $"The client's {setting} was never set, and what the framework starts it " +
                        "at is not modeled here.");
        }
    }

    /// <summary>The headers a collection holds, made on first use.</summary>
    private static Dictionary<string, string?> Held(StaticHeap heap, StaticValue collection)
    {
        if (heap.TryGetModelValue<Dictionary<string, string?>>(collection, Named, out var held) &&
            held is not null)
            return held;
        held = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        heap.TrySetModelValue(collection, Named, held);
        return held;
    }
}

/// <summary>Reads the clock and the identifier seed a profile states.</summary>
internal static class HostClock
{
    public const string NowKey = "time:UtcNow";
    public const string SeedKey = "guid:Seed";

    /// <summary>
    /// The instant the profile says it is, or nothing if it says something that is not an instant.
    /// </summary>
    public static bool TryRead(IntrinsicContext context, out DateTime instant)
    {
        instant = default;
        if (!HostFacts.TryAsk(context, NowKey, out var answer))
            return false;
        return DateTime.TryParse(
            answer.Text,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal,
            out instant);
    }
}
