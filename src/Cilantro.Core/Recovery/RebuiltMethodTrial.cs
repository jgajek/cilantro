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
    internal sealed record Result(DevirtualizationCheck Verdict, string Detail);

    internal static Result Compare(ArtifactContext context, MethodDef method, CilBody rebuilt, int scenario, uint? engineToken = null)
    {
        var shipped = method.Body;
        var outcomes = new List<StaticExecutionStatus>();
        try
        {
            var left = Run(shipped);
            var right = Run(rebuilt);
            if (outcomes.Count == 2 && outcomes[0] != outcomes[1])
                return new(DevirtualizationCheck.Disagreed, $"terminal outcomes differ: original {left.Why}; rebuilt {right.Why}");
            if (left.Key is null || right.Key is null)
                return new(DevirtualizationCheck.NotMade, $"original: {left.Why}; rebuilt: {right.Why}");
            return left.Key == right.Key
                ? new(DevirtualizationCheck.Agreed, "return/exception, arguments and observed static state matched")
                : new(DevirtualizationCheck.Disagreed, "return/exception, arguments or observed static state differed");
        }
        finally { method.Body = shipped; }

        (string? Key, string Why) Run(CilBody body)
        {
            method.Body = body;
            if (!BootstrapMachine.TrySeed(context, 4_000_000, out var machine, out var why) || machine is null)
                return (null, why);
            // Additional fixtures explicitly simulate debugger state; all other host facts remain absent.
            machine.State.RegisterRunEnvironment(new RunEnvironment(new HostEnvironment(scenario >= 3 ? HostProfile.Trial(scenario == 4) : HostProfile.Empty)));
            if (!method.IsStatic || method.HasGenericParameters || method.DeclaringType.HasGenericParameters)
                return (null, "instance or generic receiver requires a supplied fixture");
            var arguments = new List<StaticValue>();
            foreach (var type in method.MethodSig.Params)
            {
                if (!Argument(type, scenario, machine.State.Heap, out var value))
                    return (null, $"no controlled fixture for {type.FullName}");
                arguments.Add(value);
            }
            var stepped = false;
            var enteredEngine = false;
            machine.Stepped = (frame, _) =>
            {
                if (frame == method) stepped = true;
                if (frame.MDToken.Raw == engineToken) enteredEngine = true;
            };
            var answer = machine.Execute(method, arguments);
            if (!stepped || body == shipped && engineToken is not null && !enteredEngine)
                return (null, $"comparison body/engine was not exercised: {answer.Status}: {Short(answer.Diagnostic)}");
            if (answer.Status is not (StaticExecutionStatus.Completed or StaticExecutionStatus.Threw))
                return (null, $"{answer.Status}: {Short(answer.Diagnostic)}");
            var effects = machine.State.LoaderEvidence.EffectsOf(method.MDToken.Raw);
            if (effects.WroteMappedImage || effects.WroteScratchRegion || effects.Registrations.Count != 0)
                return (null, "native-memory writes or registrations are outside this comparison");
            outcomes.Add(answer.Status);
            var roots = new List<StaticValue>();
            if (answer.Status == StaticExecutionStatus.Threw || method.ReturnType.ElementType != ElementType.Void)
                roots.Add(answer.Value);
            roots.AddRange(arguments);
            // Include every materialized static, including mutations through a reference. Do not
            // silently ignore VM-private state: an opaque/different state remains inconclusive/different.
            var fields = context.Module.GetTypes().SelectMany(t => t.Fields).Where(f => f.IsStatic)
                .OrderBy(f => f.FullName, StringComparer.Ordinal).ToArray();
            roots.AddRange(fields.Select(machine.State.ReadStaticField));
            var snapshot = new Snapshot(machine.State.Heap);
            var values = roots.Select(snapshot.Read).ToArray();
            var opaque = Array.FindIndex(values, v => v is null);
            var outcome = answer.Status == StaticExecutionStatus.Threw && machine.State.Heap.TryGetRuntimeTypeName(answer.Value, out var thrownName)
                ? $"Threw ({thrownName})" : answer.Status.ToString();
            var staticStart = roots.Count - fields.Length;
            var rootName = opaque >= staticStart && opaque >= 0 ? fields[opaque - staticStart].FullName : $"return/argument root {opaque}";
            return opaque >= 0
                ? (null, $"{outcome}; opaque or over-budget state at {rootName}")
                : (JsonSerializer.Serialize(new { answer.Status, Values = values }), outcome);
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
    internal sealed class Snapshot(StaticHeap heap)
    {
        private readonly Dictionary<int, int> ids = [];
        private int remaining = 16384;
        private int textRemaining = 4 * 1024 * 1024;
        private static string Digest(string value) => Convert.ToHexString(SHA256.HashData(MemoryMarshal.AsBytes(value.AsSpan())));
        private string? HashText(string value)
        {
            textRemaining -= value.Length;
            return textRemaining < 0 ? null : "text:" + Digest(value);
        }
        internal string? Read(StaticValue value) => Read(value, 0);
        private string? Read(StaticValue value, int depth)
        {
            if (--remaining < 0 || depth > 64) return null;
            if (value.Kind is StaticValueKind.Null or StaticValueKind.Int32 or StaticValueKind.Int64 or StaticValueKind.Float32 or StaticValueKind.Float64)
                return value.ToString();
            if (value.Kind != StaticValueKind.HeapReference) return null;
            if (ids.TryGetValue(value.HeapId, out var seen)) return $"ref:{seen}";
            var id = ids.Count; ids.Add(value.HeapId, id);
            if (heap.TryGetString(value, out var text))
            {
                textRemaining -= text.Length;
                return textRemaining < 0 ? null : $"{id}:string:{Digest(text)}";
            }
            if (heap.TryUnbox(value, out var boxed)) return Read(boxed, depth + 1) is { } inner ? $"{id}:box:{inner}" : null;
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
                    string? held = property.Value switch
                    {
                        null => "null",
                        string textValue => HashText(textValue),
                        float single => StaticValue.FromFloat32(single).ToString(),
                        double real => StaticValue.FromFloat64(real).ToString(),
                        bool or int or long or uint or ulong => property.Value.GetType().FullName + ":" + JsonSerializer.Serialize(property.Value),
                        StaticValue nested => Read(nested, depth + 1),
                        _ => null
                    };
                    if (held is null) return null;
                    contents["model:" + property.Key] = held;
                }
                return $"{id}:object:{type}:{Digest(JsonSerializer.Serialize(contents))}";
            }
            if (heap.GetArraySnapshot(value) is not { } array || array.Count > remaining) return null;
            var items = array.Select(item => Read(item, depth + 1)).ToArray();
            return items.Any(i => i is null) || !heap.TryGetRuntimeTypeName(value, out var arrayType) ? null : $"{id}:{arrayType}:{Digest(JsonSerializer.Serialize(items))}";
        }
    }
}
