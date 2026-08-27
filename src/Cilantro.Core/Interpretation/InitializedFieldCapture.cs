using dnlib.DotNet;

namespace Cilantro.Core.Interpretation;

/// <summary>
/// Captures the concrete integer values a bounded interpretation left in the instance
/// fields of statically rooted objects.
/// </summary>
/// <remarks>
/// Reactor's string and boolean resolvers do not receive literal offsets. Each call site
/// computes <c>constant XOR field</c>, where the field is an <see cref="ElementType.I4"/>
/// instance field on a singleton the loader bootstrap allocates and stores in a static
/// field. Recovering those keys is therefore a precondition for proving any resolver
/// argument, and the values only exist in the machine state of the interpretation that
/// ran the bootstrap.
///
/// A field is captured only when every statically rooted object of its declaring type
/// agrees on one concrete integer. Roots that never received the field are skipped rather
/// than defaulted, so an unwritten field stays absent and its call sites remain unproven
/// instead of silently resolving through an invented zero.
/// </remarks>
public static class InitializedFieldCapture
{
    public static Dictionary<uint, int> CaptureInstanceIntegers(
        ModuleDef module,
        StaticMachineState state)
    {
        var roots = state.StaticFields.Values
            .Where(value => value.Kind == StaticValueKind.HeapReference)
            .ToArray();
        var result = new Dictionary<uint, int>();
        if (roots.Length == 0)
            return result;

        var rootsByTypeName = new Dictionary<string, List<StaticValue>>(StringComparer.Ordinal);
        foreach (var root in roots)
        {
            if (!state.Heap.TryGetRuntimeTypeName(root, out var runtimeType) ||
                runtimeType is null)
                continue;
            if (!rootsByTypeName.TryGetValue(runtimeType, out var bucket))
                rootsByTypeName[runtimeType] = bucket = [];
            bucket.Add(root);
        }
        if (rootsByTypeName.Count == 0)
            return result;

        foreach (var field in module.GetTypes()
                     .SelectMany(type => type.Fields)
                     .Where(field => !field.IsStatic &&
                         field.FieldSig?.Type.ElementType == ElementType.I4))
        {
            if (!rootsByTypeName.TryGetValue(field.DeclaringType.FullName, out var candidates))
                continue;
            var values = new HashSet<int>();
            foreach (var candidate in candidates)
            {
                if (!state.Heap.TryReadAssignedField(candidate, field, out var value) ||
                    !value.IsInteger)
                    continue;
                values.Add(unchecked((int)value.AsInt64()));
            }
            if (values.Count == 1)
                result[field.MDToken.Raw] = values.Single();
        }
        return result;
    }

    /// <summary>
    /// Captures the concrete integer values a bounded interpretation left in static fields.
    /// </summary>
    /// <remarks>
    /// Only fields the interpretation actually wrote are reported. A field the loader never
    /// assigned is absent rather than reported as its zero default, because absence here means the
    /// interpretation proved nothing about it, not that it proved zero.
    /// </remarks>
    public static Dictionary<uint, int> CaptureStaticIntegers(
        ModuleDef module,
        StaticMachineState state)
    {
        var result = new Dictionary<uint, int>();
        foreach (var field in module.GetTypes()
                     .SelectMany(type => type.Fields)
                     .Where(field => field.IsStatic &&
                         field.FieldSig?.Type.ElementType == ElementType.I4))
        {
            if (state.StaticFields.TryGetValue(field.FullName, out var value) &&
                value.Kind == StaticValueKind.Int32)
            {
                result[field.MDToken.Raw] = value.AsInt32();
            }
        }
        return result;
    }

    /// <summary>
    /// Captures the number-to-number tables a bounded interpretation left in static fields.
    /// </summary>
    /// <remarks>
    /// A protector that hides which method a call reaches has to keep the answers somewhere, and
    /// the place it keeps them is a table from one metadata token to another, built once on the way
    /// up and read from every call site afterwards. The table is the loader's own work, so the only
    /// place it exists is the machine state of the run that built it — and reimplementing whatever
    /// decoded it means carrying that build's constants, which is exactly what does not survive the
    /// next build. Reading the table out of the run costs nothing beyond a run already made.
    ///
    /// Only a field the interpretation actually filled is reported, and its contents are reported
    /// only when every key and value is a concrete number. A table holding anything else is not a
    /// token table, and half of one is worse than none.
    /// </remarks>
    public static Dictionary<uint, IReadOnlyDictionary<int, int>> CaptureIntegerMaps(
        ModuleDef module,
        StaticMachineState state)
    {
        const string dictionary = "System.Collections.Generic.Dictionary`2<System.Int32,System.Int32>";
        var result = new Dictionary<uint, IReadOnlyDictionary<int, int>>();
        foreach (var field in module.GetTypes()
                     .SelectMany(type => type.Fields)
                     .Where(field => field.IsStatic &&
                         field.FieldSig?.Type.FullName == dictionary))
        {
            if (!state.StaticFields.TryGetValue(field.FullName, out var held) ||
                held.Kind != StaticValueKind.HeapReference ||
                !state.Heap.TryGetModelValue(
                    held,
                    "Pairs",
                    out List<KeyValuePair<StaticValue, StaticValue>>? pairs) ||
                pairs is null ||
                pairs.Count == 0)
            {
                continue;
            }

            var table = new Dictionary<int, int>(pairs.Count);
            foreach (var pair in pairs)
            {
                if (!pair.Key.IsInteger || !pair.Value.IsInteger)
                {
                    table = null!;
                    break;
                }
                table[pair.Key.AsInt32()] = pair.Value.AsInt32();
            }
            if (table is not null)
                result[field.MDToken.Raw] = table;
        }
        return result;
    }

    /// <summary>
    /// Confirms two independent captures agree, so a key map is only trusted when it does
    /// not depend on interpretation order or on any ambient state.
    /// </summary>
    public static bool CapturesAgree(
        IReadOnlyDictionary<uint, int> first,
        IReadOnlyDictionary<uint, int> second) =>
        first.Count == second.Count &&
        first.All(entry =>
            second.TryGetValue(entry.Key, out var value) && value == entry.Value);

    /// <summary>Confirms two independent captures agree on every table and every entry in it.</summary>
    public static bool MapsAgree(
        IReadOnlyDictionary<uint, IReadOnlyDictionary<int, int>> first,
        IReadOnlyDictionary<uint, IReadOnlyDictionary<int, int>> second) =>
        first.Count == second.Count &&
        first.All(entry =>
            second.TryGetValue(entry.Key, out var table) &&
            table is not null &&
            CapturedTablesAgree(entry.Value, table));

    private static bool CapturedTablesAgree(
        IReadOnlyDictionary<int, int> first,
        IReadOnlyDictionary<int, int> second) =>
        first.Count == second.Count &&
        first.All(entry =>
            second.TryGetValue(entry.Key, out var value) && value == entry.Value);
}
