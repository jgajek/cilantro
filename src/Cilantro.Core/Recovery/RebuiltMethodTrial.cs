using System.Security.Cryptography;
using System.Buffers.Binary;
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

    internal sealed record Result(DevirtualizationCheck Verdict, string Detail,
        bool NonVmStateMatched = false, bool? VmStateShared = null,
        IReadOnlyList<string>? DifferingRoots = null, IReadOnlyList<string>? NonVmDifferingRoots = null,
        bool? NativeMemoryMatched = null);
    private sealed record Observation(string? Key, string Why, IReadOnlyList<string>? Names = null,
        IReadOnlyList<string?>? Values = null, int StaticStart = 0, IReadOnlySet<int>? VmRoots = null,
        string? NonVmKey = null, bool? SharesVmState = null,
        IReadOnlyList<string?>? NonVmValues = null, string? NativeSummary = null, string? NativeKey = null,
        bool ResolverBehaviorUnproven = false);

    private static bool IsResolverRegistration(string effect) =>
        effect is "AppDomain.AssemblyResolve" or "AppDomain.ResourceResolve";

    internal static Result Compare(ArtifactContext context, MethodDef method, CilBody rebuilt, int scenario,
        uint? engineToken = null, bool warmOriginal = false, HostProfile? hostProfile = null,
        uint? rebuiltEntryToken = null, bool initializeModule = false)
    {
        if (initializeModule && warmOriginal)
            throw new ArgumentException("Module initialization and original-call warm-up are separate trials.", nameof(initializeModule));
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
            {
                if (left.ResolverBehaviorUnproven || right.ResolverBehaviorUnproven)
                    return new(DevirtualizationCheck.NotMade,
                        "Captured state, including ordered resolver delegates and their targets, matched; " +
                        "resolver callback behavior remains outside this comparison. Matching registrations do not establish equivalence.");
                return new(DevirtualizationCheck.Agreed, "return/exception, arguments, observed static state, modeled network settings, modeled native memory and application-domain data matched");
            }
            var differences = Enumerable.Range(0, left.Values!.Count)
                .Where(index => left.Values[index] != right.Values![index]).ToArray();
            var differing = differences[0];
            var differingRoots = differences.Select(index => left.Names![index]).ToArray();
            string[]? nonVmDifferences = null;
            if (left.NonVmValues is { } leftNonVm && right.NonVmValues is { } rightNonVm)
            {
                var names = left.Names!.Where((_, index) => !left.VmRoots!.Contains(index)).ToArray();
                nonVmDifferences = Enumerable.Range(0, leftNonVm.Count)
                    .Where(index => leftNonVm[index] != rightNonVm[index]).Select(index => names[index]).ToArray();
            }
            var boundary = left.NonVmKey is not null && left.NonVmKey == right.NonVmKey
                ? ". A separate snapshot excluding VM-owned static roots matched return/exception, arguments, other static roots, " +
                    "modeled network settings, native memory and application-domain data, preserving aliases among those roots. " +
                    "This localizes the difference but does not prove the VM state is unobservable; disagreement is retained"
                : DescribeVmBoundary(differences, left.VmRoots);
            if (left.NonVmKey is not null && left.NonVmKey == right.NonVmKey)
                boundary += left.SharesVmState == false && right.SharesVmState == false
                    ? ". No shared modeled objects were found between VM static roots and the captured non-VM roots on either side; reflection and later calls remain unproven"
                    : left.SharesVmState == true || right.SharesVmState == true
                        ? ". VM static roots share modeled objects with captured non-VM roots; the VM state cannot be treated as isolated"
                        : ". VM-to-application object sharing could not be established within the snapshot limits";
            if (nonVmDifferences is { Length: > 0 })
                boundary += $". The separate non-VM snapshot differs at {nonVmDifferences.Length} root(s): " +
                    string.Join("; ", nonVmDifferences.Take(8)) + (nonVmDifferences.Length > 8 ? "; additional roots omitted" : "") +
                    ". These are snapshot differences, including aliases, not a claim that each root was independently modified";
            if (nonVmDifferences?.Contains("modeled native memory") == true)
            {
                boundary += $". Native memory: original {left.NativeSummary}; rebuilt {right.NativeSummary}";
                boundary += left.NativeKey is not null && right.NativeKey is not null
                    ? left.NativeKey == right.NativeKey
                        ? ". An independent native-memory snapshot matched; cross-root aliases remain covered by the differing combined snapshot"
                        : ". An independent native-memory snapshot also differed"
                    : ". An independent native-memory snapshot was inconclusive";
            }
            if (left.ResolverBehaviorUnproven || right.ResolverBehaviorUnproven)
                boundary += ". Ordered resolver delegates and their targets were included; resolver callback behavior remains unproven";
            return new(DevirtualizationCheck.Disagreed, (left.Names![differing] == "modeled native memory"
                ? "return/exception, arguments, observed static state and modeled network settings matched; modeled native memory differed"
                : left.Names![differing] == "modeled network settings"
                ? "return/exception, arguments and observed static state matched; modeled network settings differed"
                : left.Names![differing] == "modeled application-domain data"
                ? "preceding snapshots matched; modeled application-domain data differed"
                : differing >= left.StaticStart
                ? $"return/exception and argument snapshots matched; observed static state differed at {left.Names![differing]}"
                : $"observed state differed at {left.Names![differing]}") + boundary,
                NonVmStateMatched: left.NonVmKey is not null && left.NonVmKey == right.NonVmKey,
                VmStateShared: left.SharesVmState == true || right.SharesVmState == true ? true
                    : left.SharesVmState == false && right.SharesVmState == false ? false : null,
                DifferingRoots: differingRoots, NonVmDifferingRoots: nonVmDifferences,
                NativeMemoryMatched: left.NativeKey is not null && right.NativeKey is not null ? left.NativeKey == right.NativeKey : null);
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
            var resolverBehaviorUnproven = false;
            if (initializeModule && context.Module.GlobalType.FindStaticConstructor() is { } initializer)
            {
                if (initializer == method)
                    return new(null, "the requested method is the module initializer, so it cannot be measured after its own initialization");
                // Each world initializes with its selected body installed. This is not a
                // common original-method warm-up, which could conceal a startup difference.
                var initialized = machine.Execute(initializer, [], budget);
                if (initialized.Status != StaticExecutionStatus.Completed)
                    return new(null, $"module initialization did not complete: {initialized.Status}: {Short(initialized.Diagnostic)}");
                var initializerEffects = machine.State.LoaderEvidence.EffectsOf(initializer.MDToken.Raw).Registrations;
                resolverBehaviorUnproven |= initializerEffects.Any(IsResolverRegistration);
                var registrations = initializerEffects.Where(effect => effect != "AppDomain.SetData" && !IsResolverRegistration(effect)).ToArray();
                if (registrations.Length != 0)
                    return new(null, "module initialization registrations are outside this comparison: " + string.Join(", ", registrations.Take(4)));
            }
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
            var enteredRebuilt = false;
            machine.Stepped = (frame, _) =>
            {
                if (frame == method) stepped = true;
                if (frame.MDToken.Raw == engineToken) enteredEngine = true;
                if (frame.MDToken.Raw == rebuiltEntryToken) enteredRebuilt = true;
            };
            var answer = machine.Execute(method, arguments, budget);
            if (!stepped || body == shipped && engineToken is not null && !enteredEngine ||
                body == rebuilt && rebuiltEntryToken is not null && !enteredRebuilt)
                return new(null, $"comparison body/engine was not exercised: {answer.Status}: {Short(answer.Diagnostic)}");
            if (answer.Status is not (StaticExecutionStatus.Completed or StaticExecutionStatus.Threw))
                return new(null, $"{answer.Status}: {Short(answer.Diagnostic)}");
            var effects = machine.State.LoaderEvidence.EffectsOf(method.MDToken.Raw);
            resolverBehaviorUnproven |= effects.Registrations.Any(IsResolverRegistration);
            var unmodeled = effects.Registrations.Where(effect => effect != "AppDomain.SetData" && !IsResolverRegistration(effect)).ToArray();
            if (unmodeled.Length != 0)
                return new(null, "registrations are outside this comparison: " + string.Join(", ", unmodeled.Take(4)));
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
            var engineType = engineToken is { } token
                ? (context.Module.ResolveToken(token) as IMethod)?.ResolveMethodDef()?.DeclaringType : null;
            bool VmOwned(TypeDef? owner) => engineType is not null && owner is not null &&
                (owner == engineType || VmOwned(owner.DeclaringType));
            var vmRoots = fields.Select((field, index) => (field, index))
                .Where(pair => VmOwned(pair.field.DeclaringType))
                .Select(pair => roots.Count + pair.index).ToHashSet();
            roots.AddRange(fields.Select(machine.State.ReadStaticField));
            names.AddRange(fields.Select(field => field.FullName));
            var snapshot = new Snapshot(machine.State.Heap, metadata);
            var values = roots.Select(snapshot.Read).ToArray();
            values = [.. values, snapshot.ReadNetworkSettings(machine.State), snapshot.ReadNativeState(machine.State), snapshot.ReadDomainState(machine.State)];
            names.Add("modeled network settings");
            names.Add("modeled native memory");
            names.Add("modeled application-domain data");
            var opaque = Array.FindIndex(values, v => v is null);
            var outcome = answer.Status == StaticExecutionStatus.Threw && machine.State.Heap.TryGetRuntimeTypeName(answer.Value, out var thrownName)
                ? $"Threw ({thrownName}): {Short(answer.Diagnostic)}" : answer.Status.ToString();
            string? nonVmKey = null;
            IReadOnlyList<string?>? nonVmValues = null;
            bool? sharesVmState = null;
            if (opaque < 0 && vmRoots.Count != 0)
            {
                // Independent numbering avoids shifts caused by omitted VM objects. Shared
                // roots still use one snapshot, so application aliases remain observable.
                var nonVm = new Snapshot(machine.State.Heap, metadata);
                var observed = roots.Where((_, index) => !vmRoots.Contains(index)).Select(nonVm.Read).ToList();
                observed.Add(nonVm.ReadNetworkSettings(machine.State));
                observed.Add(nonVm.ReadNativeState(machine.State));
                observed.Add(nonVm.ReadDomainState(machine.State));
                if (observed.All(value => value is not null))
                {
                    nonVmKey = JsonSerializer.Serialize(new { answer.Status, Values = observed });
                    nonVmValues = observed;
                    var vm = new Snapshot(machine.State.Heap, metadata);
                    var vmValues = roots.Where((_, index) => vmRoots.Contains(index)).Select(vm.Read).ToArray();
                    if (vmValues.All(value => value is not null))
                        sharesVmState = vm.SharesCapturedObjectsWith(nonVm);
                }
            }
            return opaque >= 0
                ? new(null, $"{outcome}; opaque or over-budget state at {names[opaque]} ({snapshot.Failure ?? "node, depth or text budget exhausted"})")
                : new(JsonSerializer.Serialize(new { answer.Status, Values = values }), outcome, names, values, roots.Count - fields.Length, vmRoots, nonVmKey, sharesVmState, nonVmValues,
                    $"{machine.State.Heap.NativeRegions.Count()} region(s), {machine.State.Heap.ImageWrites.Count} write(s), " +
                    $"{machine.State.Heap.ImageWrites.Sum(write => (long)write.Bytes.Length)} written byte(s), {machine.State.ImageProtections.Count} protection change(s)",
                    new Snapshot(machine.State.Heap, metadata).ReadNativeState(machine.State), resolverBehaviorUnproven);
        }
    }

    internal static string DescribeVmBoundary(IReadOnlyList<int> differences, IReadOnlySet<int>? vmRoots)
    {
        if (differences.Count == 0 || vmRoots is null || !differences.All(vmRoots.Contains)) return string.Empty;
        return $". All {differences.Count} differing snapshot root(s) are static fields owned by the original VM type hierarchy; " +
            "return/exception, arguments, other static roots, modeled network settings, native memory and application-domain data matched. " +
            "This localizes the difference but does not prove the VM state is unobservable; disagreement is retained";
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
        // Only compare graphs from the same machine; heap IDs have no cross-machine meaning.
        private StaticHeap SourceHeap => heap;
        internal bool SharesCapturedObjectsWith(Snapshot other)
        {
            if (!ReferenceEquals(SourceHeap, other.SourceHeap))
                throw new ArgumentException("Object sharing requires snapshots of the same heap.", nameof(other));
            return ids.Keys.Any(other.ids.ContainsKey) || modelIds.Keys.Any(other.modelIds.ContainsKey);
        }
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
        internal const int MaximumNativeWrites = 262144;
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

        internal string? ReadDomainState(StaticMachineState state)
        {
            // Capture through the same graph as statics/arguments so domain aliases remain visible.
            // An unmaterialized current domain has the same empty model as a newly requested one.
            if (!state.TryGetOrAllocateRuntimeSingleton("System.AppDomain", out var domain) ||
                !heap.TryGetInstanceSnapshot(domain, out _, out _, out var model))
                return Refuse("application-domain state unavailable");
            // Slot names are caller-controlled text too, not just the values stored under them.
            foreach (var key in model.Keys)
                if (HashText(key) is null) return null;
            return Read(domain);
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
            if (regions.Length > 4096)
                return Refuse("native region budget exhausted (more than 4096 regions)");
            if (heap.ImageWrites.Count > MaximumNativeWrites)
                return Refuse($"native write-count budget exhausted ({heap.ImageWrites.Count} writes; limit {MaximumNativeWrites})");
            // The interpreter stops recording protection changes at 256 entries.
            if (state.ImageProtections.Count >= 256)
                return Refuse("image protection history may be truncated");
            // Hash framed records incrementally instead of retaining and serializing the
            // entire history. Byte and write-count bounds still apply to every record.
            using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            void Append(string record)
            {
                var bytes = MemoryMarshal.AsBytes(record.AsSpan());
                Span<byte> length = stackalloc byte[4];
                BinaryPrimitives.WriteInt32LittleEndian(length, bytes.Length);
                digest.AppendData(length);
                digest.AppendData(bytes);
            }
            var targets = new Dictionary<StaticValue, string>();
            foreach (var region in regions.OrderBy(region =>
                         heap.TryGetRegionSnapshot(region, out _, out var address, out _) ? address : long.MaxValue))
            {
                if (Read(region) is not { } captured) return null;
                Append(captured);
                // The region has been fully captured. Repeated writes refer to its
                // canonical identity without spending another graph node per write.
                targets.Add(region, $"ref:{ids[region.HeapId]}");
            }
            foreach (var write in heap.ImageWrites)
            {
                // Offset in ImageRegionWrite is already relative to the region base.
                var region = write.Region.Kind == StaticValueKind.NativePointer
                    ? StaticValue.FromHeapReference(write.Region.NativeRegionId) : write.Region;
                if (!targets.TryGetValue(region, out var target))
                    return Refuse("native write target is not a captured region");
                if (HashBytes(write.Bytes) is not { } data ||
                    HashText(write.RegionKind) is not { } kind) return null;
                Append($"write:{target}:{kind}:{write.Offset}:{write.Bytes.Length}:{data}");
            }
            Append(JsonSerializer.Serialize(state.ImageProtections));
            return Convert.ToHexString(digest.GetHashAndReset());
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
