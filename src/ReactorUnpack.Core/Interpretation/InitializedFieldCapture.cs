using dnlib.DotNet;

namespace ReactorUnpack.Core.Interpretation;

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
    /// Confirms two independent captures agree, so a key map is only trusted when it does
    /// not depend on interpretation order or on any ambient state.
    /// </summary>
    public static bool CapturesAgree(
        IReadOnlyDictionary<uint, int> first,
        IReadOnlyDictionary<uint, int> second) =>
        first.Count == second.Count &&
        first.All(entry =>
            second.TryGetValue(entry.Key, out var value) && value == entry.Value);
}
