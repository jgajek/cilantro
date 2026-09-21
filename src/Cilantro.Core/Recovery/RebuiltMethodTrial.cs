using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text.Json;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Interpretation;

namespace Cilantro.Core.Recovery;

/// <summary>Bounded differential trials against the original interpreter stub, never native execution.</summary>
internal static class RebuiltMethodTrial
{
    internal static int StepLimit(ArtifactContext context) => BootstrapMachine.Limits(
        4_000_000, BootstrapMachine.Environment(context).Declarations.Budgets).MaximumSteps;

    internal sealed record Result(DevirtualizationCheck Verdict, string Detail);
    private sealed record Observation(string? Key, string Why, IReadOnlyList<string>? Names = null,
        IReadOnlyList<string?>? Values = null, int StaticStart = 0);

    internal static Result Compare(ArtifactContext context, MethodDef method, CilBody rebuilt, int scenario,
        uint? engineToken = null, bool warmOriginal = false, HostProfile? hostProfile = null)
    {
        var shipped = method.Body;
        var maximumSteps = StepLimit(context);
        var outcomes = new List<StaticExecutionStatus>();
        // Both trials use the same loaded metadata. Shared reference identities distinguish
        // handles without trusting names/tokens that can collide across different modules.
        var metadata = new Dictionary<object, int>(ReferenceEqualityComparer.Instance);
        try
        {
            var left = Run(shipped);
            var right = Run(rebuilt);
            if (outcomes.Count == 2 && outcomes[0] != outcomes[1])
                return new(DevirtualizationCheck.Disagreed, $"terminal outcomes differ: original {left.Why}; rebuilt {right.Why}");
            if (left.Key is null || right.Key is null)
                return new(DevirtualizationCheck.NotMade, $"original: {left.Why}; rebuilt: {right.Why}");
            if (left.Key == right.Key)
                return new(DevirtualizationCheck.Agreed, "return/exception, arguments, observed static state, modeled network settings and modeled native memory matched");
            var differing = Enumerable.Range(0, left.Values!.Count)
                .First(index => left.Values[index] != right.Values![index]);
            return new(DevirtualizationCheck.Disagreed, left.Names![differing] == "modeled native memory"
                ? "return/exception, arguments, observed static state and modeled network settings matched; modeled native memory differed"
                : left.Names![differing] == "modeled network settings"
                ? "return/exception, arguments and observed static state matched; modeled network settings differed"
                : differing >= left.StaticStart
                ? $"return/exception and argument snapshots matched; observed static state differed at {left.Names![differing]}"
                : $"observed state differed at {left.Names![differing]}");
        }
        finally { method.Body = shipped; }

        Observation Run(CilBody body)
        {
            method.Body = warmOriginal ? shipped : body;
            if (!BootstrapMachine.TrySeed(context, maximumSteps, out var machine, out var why) || machine is null)
                return new(null, why);
            // Keep trials strict and independent, even when the recovery run permits unknown
            // calls. A configured-profile trial imports host facts, not declared call outcomes.
            machine.State.RegisterRunEnvironment(new RunEnvironment(new HostEnvironment(hostProfile ??
                (scenario >= 3 ? HostProfile.Trial(scenario == 4) : HostProfile.Empty))));
            if (!method.IsStatic || method.HasGenericParameters || method.DeclaringType.HasGenericParameters)
                return new(null, "instance or generic receiver requires a supplied fixture");
            var arguments = new List<StaticValue>();
            foreach (var type in method.MethodSig.Params)
            {
                if (!Argument(type, scenario, machine.State.Heap, out var value))
                    return new(null, $"no controlled fixture for {type.FullName}");
                arguments.Add(value);
            }
            // The shared prelude/measurement budget must honor the same declarations as
            // the seeded machine. A fresh hard-coded budget would silently cap raised limits.
            var budget = new StaticWorkBudget(maximumSteps);
            if (warmOriginal)
            {
                // Independent machines execute the same original prelude. A successful
                // repeat-call trial must never erase a cold-start difference.
                var warmup = machine.Execute(method, arguments, budget);
                if (warmup.Status != StaticExecutionStatus.Completed)
                    return new(null, $"original warm-up did not complete: {warmup.Status}: {Short(warmup.Diagnostic)}");
                method.Body = body;
                arguments.Clear();
                foreach (var type in method.MethodSig.Params)
                {
                    if (!Argument(type, scenario, machine.State.Heap, out var value))
                        return new(null, $"no fresh repeat-call fixture for {type.FullName}");
                    arguments.Add(value);
                }
            }
            var stepped = false;
            var enteredEngine = false;
            machine.Stepped = (frame, _) =>
            {
                if (frame == method) stepped = true;
                if (frame.MDToken.Raw == engineToken) enteredEngine = true;
            };
            var answer = machine.Execute(method, arguments, budget);
            if (!stepped || body == shipped && engineToken is not null && !enteredEngine)
                return new(null, $"comparison body/engine was not exercised: {answer.Status}: {Short(answer.Diagnostic)}");
            if (answer.Status is not (StaticExecutionStatus.Completed or StaticExecutionStatus.Threw))
                return new(null, $"{answer.Status}: {Short(answer.Diagnostic)}");
            var effects = machine.State.LoaderEvidence.EffectsOf(method.MDToken.Raw);
            if (effects.Registrations.Count != 0)
                return new(null, "registrations are outside this comparison: " + string.Join(", ", effects.Registrations.Take(4)));
            outcomes.Add(answer.Status);
            var roots = new List<StaticValue>();
            var names = new List<string>();
            if (answer.Status == StaticExecutionStatus.Threw || method.ReturnType.ElementType != ElementType.Void)
            {
                roots.Add(answer.Value);
                names.Add(answer.Status == StaticExecutionStatus.Threw ? "exception" : "return value");
            }
            roots.AddRange(arguments);
            names.AddRange(arguments.Select((_, index) => $"argument {index}"));
            // Include every materialized static, including mutations through a reference. Do not
            // silently ignore VM-private state: an opaque/different state remains inconclusive/different.
            var fields = context.Module.GetTypes().SelectMany(t => t.Fields).Where(f => f.IsStatic)
                .OrderBy(f => f.FullName, StringComparer.Ordinal).ToArray();
            roots.AddRange(fields.Select(machine.State.ReadStaticField));
            names.AddRange(fields.Select(field => field.FullName));
            var snapshot = new Snapshot(machine.State.Heap, metadata);
            var values = roots.Select(snapshot.Read).ToArray();
            values = [.. values, snapshot.ReadNetworkSettings(machine.State), snapshot.ReadNativeState(machine.State)];
            names.Add("modeled network settings");
            names.Add("modeled native memory");
            var opaque = Array.FindIndex(values, v => v is null);
            var outcome = answer.Status == StaticExecutionStatus.Threw && machine.State.Heap.TryGetRuntimeTypeName(answer.Value, out var thrownName)
                ? $"Threw ({thrownName}): {Short(answer.Diagnostic)}" : answer.Status.ToString();
            return opaque >= 0
                ? new(null, $"{outcome}; opaque or over-budget state at {names[opaque]} ({snapshot.Failure ?? "node, depth or text budget exhausted"})")
                : new(JsonSerializer.Serialize(new { answer.Status, Values = values }), outcome, names, values, roots.Count - fields.Length);
        }
    }

    private static string Short(string? text)
    {
        if (text is null) return "no diagnostic";
        text = text.Split(" | provenance", StringSplitOptions.None)[0].Split('\n')[0];
        return text.Length <= 360 ? text : text[..100] + " ... " + text[^240..];
    }

    private static bool Argument(TypeSig type, int scenario, StaticHeap heap, out StaticValue value)
    {
        value = StaticValue.Unknown;
        if (scenario >= 3 && (type.ElementType == ElementType.Object ||
            type.FullName is "System.IO.Stream" or "System.IO.MemoryStream"))
        {
            // A valid modeled stream, not a claim that these bytes satisfy a sample's format.
            if (!heap.TryAllocateByteArray(new byte[32], out var buffer) ||
                !heap.TryAllocateObject("System.IO.MemoryStream", out value)) return false;
            return heap.TrySetModelValue(value, "Buffer", buffer) &&
                heap.TrySetModelValue(value, "Position", 0L) &&
                heap.TrySetModelValue(value, "Origin", 0) &&
                heap.TrySetModelValue(value, "Length", 32) &&
                heap.TrySetModelValue(value, "Capacity", 32) &&
                heap.TrySetModelValue(value, "Writable", true) &&
                heap.TrySetModelValue(value, "Expandable", false) &&
                heap.TrySetModelValue(value, "PubliclyVisible", false) &&
                heap.TrySetModelValue(value, "Open", true);
        }
        var number = scenario switch { 0 or 3 or 4 => 0, 1 => 1, _ => -1 };
        value = type.ElementType switch
        {
            ElementType.Boolean => StaticValue.FromInt32(scenario == 0 ? 0 : 1),
            ElementType.U1 => StaticValue.FromInt32(unchecked((byte)number)),
            ElementType.U2 or ElementType.Char => StaticValue.FromInt32(unchecked((ushort)number)),
            ElementType.I1 or ElementType.I2 or ElementType.I4 or ElementType.U4 => StaticValue.FromInt32(number),
            ElementType.I8 or ElementType.U8 => StaticValue.FromInt64(number),
            ElementType.R4 => StaticValue.FromFloat32(number),
            ElementType.R8 => StaticValue.FromFloat64(number),
            ElementType.Object or ElementType.Class or ElementType.String or ElementType.SZArray => StaticValue.Null,
            _ => StaticValue.Unknown
        };
        if (scenario > 0 && type.ElementType == ElementType.String)
            return heap.TryAllocateString(scenario == 1 ? "" : "CILantro trial", out value);
        if (scenario > 0 && type is SZArraySig { Next.ElementType: ElementType.U1 })
            return heap.TryAllocateByteArray(scenario == 1 ? [] : [0, 1, 127, 255], out value);
        return value.IsKnown;
    }

    // Heap identities differ between machines. Preserve aliases/cycles while normalizing
    // strings, boxes and arrays; refuse opaque models instead of comparing allocation IDs.
    internal sealed class Snapshot(StaticHeap heap, Dictionary<object, int>? metadata = null)
    {
        private readonly Dictionary<int, int> ids = [];
        private readonly Dictionary<object, int> modelIds = new(ReferenceEqualityComparer.Instance);
        internal string? Failure { get; private set; }
        private string? Refuse(string why) { Failure ??= why; return null; }
        // A decoded Reactor program cache can exceed 16K nodes even for a single method.
        // Keep a finite work bound while admitting these ordinary recovered graphs.
        internal const int MaximumNodes = 65536;
        private int remaining = MaximumNodes;
        private int textRemaining = 4 * 1024 * 1024;
        internal const int MaximumBinaryBytes = 32 * 1024 * 1024;
        private int binaryBytesRemaining = MaximumBinaryBytes;
        private static string Digest(string value) => Convert.ToHexString(SHA256.HashData(MemoryMarshal.AsBytes(value.AsSpan())));
        private string? HashText(string value)
        {
            textRemaining -= value.Length;
            return textRemaining < 0 ? Refuse("text budget exhausted") : "text:" + Digest(value);
        }
        internal string? Read(StaticValue value) => Read(value, 0);
        private string? Read(StaticValue value, int depth)
        {
            if (--remaining < 0) return Refuse("node budget exhausted");
            if (depth > 64) return Refuse("depth budget exhausted");
            if (value.Kind is StaticValueKind.Null or StaticValueKind.Int32 or StaticValueKind.Int64 or StaticValueKind.Float32 or StaticValueKind.Float64)
                return value.ToString();
            if (value.Kind == StaticValueKind.NativePointer)
            {
                var region = Read(StaticValue.FromHeapReference(value.NativeRegionId), depth + 1);
                return region is null ? null : $"pointer:{value.NativeOffset}:{region}";
            }
            if (value.Kind != StaticValueKind.HeapReference) return Refuse($"unsupported value kind {value.Kind}");
            if (ids.TryGetValue(value.HeapId, out var seen)) return $"ref:{seen}";
            var id = ids.Count; ids.Add(value.HeapId, id);
            if (heap.TryGetRegionSnapshot(value, out var kind, out var address, out var bytes))
                return HashBytes(bytes.Span) is { } hash && HashText(kind) is { } regionKind
                    ? $"{id}:region:{regionKind}:{address}:{bytes.Length}:{hash}" : null;
            if (heap.TryGetString(value, out var text))
            {
                textRemaining -= text.Length;
                return textRemaining < 0 ? Refuse("text budget exhausted") : $"{id}:string:{Digest(text)}";
            }
            if (heap.TryUnbox(value, out var boxed)) return Read(boxed, depth + 1) is { } inner ? $"{id}:box:{inner}" : null;
            if (heap.TryGetMetadataHandle(value, out var handle))
                return ReadMetadata(handle) is { } identity ? $"{id}:handle:{identity}" : null;
            if (heap.TryGetInstanceSnapshot(value, out var type, out var fields, out var model))
            {
                var contents = new SortedDictionary<string, string>(StringComparer.Ordinal);
                foreach (var field in fields.OrderBy(f => f.Key, StringComparer.Ordinal))
                {
                    if (Read(field.Value, depth + 1) is not { } held) return null;
                    contents["field:" + field.Key] = held;
                }
                foreach (var property in model.OrderBy(p => p.Key, StringComparer.Ordinal))
                {
                    var held = ReadModel(property.Value, depth + 1);
                    if (held is null) return null;
                    contents["model:" + property.Key] = held;
                }
                return $"{id}:object:{type}:{Digest(JsonSerializer.Serialize(contents))}";
            }
            // Reject oversized arrays before cloning their storage.
            if (!heap.TryGetArrayElementType(value, out var elementType) || !heap.TryGetLength(value, out var length))
                return Refuse("unsupported heap object");
            // Byte buffers have no interior references. Hash their complete contents within
            // the binary budget instead of charging a graph node for each decoded byte.
            if (elementType == "System.Byte")
            {
                if (length > binaryBytesRemaining) return Refuse("binary byte budget exhausted");
                if (heap.GetBytesSnapshot(value) is not { } buffer) return Refuse("byte buffer state unavailable");
                return HashBytes(buffer) is { } hash ? $"{id}:System.Byte[]:{length}:{hash}" : null;
            }
            if (length > remaining) return Refuse("array exceeds remaining node budget");
            if (heap.GetArraySnapshot(value) is not { } array) return Refuse("array state unavailable");
            var items = array.Select(item => Read(item, depth + 1)).ToArray();
            return items.Any(i => i is null) || !heap.TryGetRuntimeTypeName(value, out var arrayType) ? null : $"{id}:{arrayType}:{Digest(JsonSerializer.Serialize(items))}";
        }

        private string? HashBytes(ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length > binaryBytesRemaining) return Refuse("binary byte budget exhausted");
            binaryBytesRemaining -= bytes.Length;
            return Convert.ToHexString(SHA256.HashData(bytes));
        }

        internal string? ReadNetworkSettings(StaticMachineState state)
        {
            var settings = new SortedDictionary<string, string>(StringComparer.Ordinal);
            foreach (var pair in state.NetworkSettings.OrderBy(pair => pair.Key, StringComparer.Ordinal))
            {
                if (HashText(pair.Key) is not { } key || Read(pair.Value) is not { } value) return null;
                settings.Add(key, value);
            }
            return Digest(JsonSerializer.Serialize(settings));
        }

        internal string? ReadNativeState(StaticMachineState state)
        {
            // Include unreferenced regions and write history, not just pointers surviving in
            // statics. Keep absolute addresses: raw pointer bytes are not safely relocatable.
            var regions = heap.NativeRegions.Take(4097).ToArray();
            if (regions.Length > 4096 || heap.ImageWrites.Count > 16384)
                return Refuse("native region or write-count budget exhausted");
            // The interpreter stops recording protection changes at 256 entries.
            if (state.ImageProtections.Count >= 256)
                return Refuse("image protection history may be truncated");
            var contents = new List<string>();
            foreach (var region in regions.OrderBy(region =>
                         heap.TryGetRegionSnapshot(region, out _, out var address, out _) ? address : long.MaxValue))
            {
                if (Read(region) is not { } captured) return null;
                contents.Add(captured);
            }
            foreach (var write in heap.ImageWrites)
            {
                // Offset in ImageRegionWrite is already relative to the region base.
                var region = write.Region.Kind == StaticValueKind.NativePointer
                    ? StaticValue.FromHeapReference(write.Region.NativeRegionId) : write.Region;
                if (Read(region) is not { } target || HashBytes(write.Bytes) is not { } data ||
                    HashText(write.RegionKind) is not { } kind) return null;
                contents.Add($"write:{target}:{kind}:{write.Offset}:{write.Bytes.Length}:{data}");
            }
            contents.Add(JsonSerializer.Serialize(state.ImageProtections));
            return Digest(JsonSerializer.Serialize(contents));
        }

        private string? ReadModel(object? value, int depth) => value switch
        {
            null => "null",
            string text => HashText(text),
            float single => StaticValue.FromFloat32(single).ToString(),
            double real => StaticValue.FromFloat64(real).ToString(),
            bool or int or long or uint or ulong => value.GetType().FullName + ":" + JsonSerializer.Serialize(value),
            StaticValue nested => Read(nested, depth),
            IMDTokenProvider member => ReadMetadata(member),
            List<StaticValue> list => ReadCollection(list, list, list.Count, "list", depth),
            List<KeyValuePair<StaticValue, StaticValue>> pairs => ReadCollection(pairs,
                pairs.SelectMany(pair => new[] { pair.Key, pair.Value }), (long)pairs.Count * 2, "pairs", depth),
            Dictionary<StaticValue, StaticValue> map => ReadCollection(map,
                map.SelectMany(pair => new[] { pair.Key, pair.Value }), (long)map.Count * 2, "map", depth),
            _ => Refuse($"unsupported model value {value.GetType().FullName}")
        };

        private string? ReadMetadata(object? value)
        {
            if (--remaining < 0) return Refuse("node budget exhausted");
            if (metadata is null || value is not IMDTokenProvider) return Refuse("metadata identity unavailable");
            if (!metadata.TryGetValue(value, out var id))
            {
                id = metadata.Count;
                metadata.Add(value, id);
            }
            return $"metadata:{id}";
        }

        private string? ReadCollection(object identity, IEnumerable<StaticValue> values, long count,
            string kind, int depth)
        {
            if (--remaining < 0) return Refuse("node budget exhausted");
            if (depth > 64) return Refuse("depth budget exhausted");
            if (modelIds.TryGetValue(identity, out var seen)) return $"model-ref:{seen}";
            if (count > remaining) return Refuse("collection exceeds remaining node budget");
            var id = modelIds.Count;
            modelIds.Add(identity, id);
            // Keep enumeration order and key/value pairing. Different cache contents or
            // aliases remain differences; recognizing a model does not exclude its state.
            var items = values.Select(value => Read(value, depth + 1)).ToArray();
            return items.Any(item => item is null) ? null
                : $"model:{id}:{kind}:{Digest(JsonSerializer.Serialize(items))}";
        }
    }
}
