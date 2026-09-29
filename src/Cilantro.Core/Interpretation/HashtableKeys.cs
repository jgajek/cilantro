namespace Cilantro.Core.Interpretation;

/// <summary>Live key views and bounded, versioned enumerators over modeled Hashtables.</summary>
internal static class HashtableKeys
{
    internal const string ViewType = "System.Collections.Hashtable/KeyCollection";
    internal const string EnumeratorType = "System.Collections.Hashtable/HashtableEnumerator";
    private const string Source = "HashtableSource";
    private const string Keys = "HashtableKeys";
    private const string Version = "HashtableVersion";
    private const string Originals = "HashtableOriginalKeys";

    internal static void RecordWrite(StaticHeap heap, StaticValue table, StaticValue key, StaticValue original)
    {
        if (!heap.TryGetModelValue(table, Originals, out Dictionary<StaticValue, StaticValue>? keys))
        {
            keys = [];
            heap.TrySetModelValue(table, Originals, keys);
        }
        keys!.TryAdd(key, original); // Replacing a value does not replace its existing key object.
        heap.TryGetModelValue(table, Version, out int version);
        heap.TrySetModelValue(table, Version, unchecked(version + 1));
    }

    internal static IntrinsicResult View(StaticHeap heap, StaticValue table)
    {
        if (heap.TryGetModelValue(table, "HashtableKeyView", out StaticValue existing))
            return IntrinsicResult.Completed(existing);
        if (!heap.TryAllocateObject(ViewType, out var view)) return AllocationFailure();
        heap.TrySetModelValue(view, Source, table);
        heap.TrySetModelValue(table, "HashtableKeyView", view);
        return IntrinsicResult.Completed(view);
    }

    internal static bool TryInvoke(StaticMachineState state, string name, IReadOnlyList<StaticValue> arguments,
        out IntrinsicResult result)
    {
        var heap = state.Heap;
        result = IntrinsicResult.Invalid("Unsupported Hashtable key-collection operation.");
        if (arguments.Count == 0 || !heap.TryGetModelValue(arguments[0], Source, out StaticValue table)) return false;
        if (!heap.TryGetModelValue(table, "Entries", out Dictionary<StaticValue, StaticValue>? entries) || entries is null)
            return true;
        var self = arguments[0];
        heap.TryGetModelValue(table, Version, out int version);
        if (heap.TryGetModelValue(self, Keys, out StaticValue keys))
        {
            if (arguments.Count != 1) return true;
            heap.TryGetModelValue(self, Version, out int capturedVersion);
            heap.TryGetModelValue(self, "Index", out int index);
            if (!heap.TryGetLength(keys, out var length)) return true;
            if (name is "MoveNext" or "Reset" && capturedVersion != version)
                result = InvalidOperation(heap, "Collection was modified during enumeration.");
            else if (name == "MoveNext")
            {
                var next = index < length ? index + 1 : length;
                heap.TrySetModelValue(self, "Index", next);
                result = IntrinsicResult.Completed(StaticValue.FromInt32(next < length ? 1 : 0));
            }
            else if (name == "Reset")
            {
                heap.TrySetModelValue(self, "Index", -1);
                result = IntrinsicResult.Completed();
            }
            else if (name == "get_Current")
                // Current retains its last element even after a table mutation; MoveNext/Reset reject it.
                result = (uint)index < (uint)length && heap.TryReadArray(keys, index, out var current)
                    ? IntrinsicResult.Completed(current) : InvalidOperation(heap, "Enumerator is not positioned on an element.");
            return true;
        }
        if (arguments.Count != 1) return true;
        if (name == "get_Count") result = IntrinsicResult.Completed(StaticValue.FromInt32(entries.Count));
        else if (name == "get_IsSynchronized") result = IntrinsicResult.Completed(StaticValue.FromInt32(0));
        else if (name == "get_SyncRoot") result = IntrinsicResult.Completed(table);
        else if (name == "GetEnumerator")
        {
            if (state.ModuleMetadata is not { } module)
            { result = IntrinsicResult.Unknown("Key enumeration requires module type metadata."); return true; }
            if (!heap.TryAllocateArray(module.CorLibTypes.Object, entries.Count, out var array) ||
                !heap.TryAllocateObject(EnumeratorType, out var enumerator))
            { result = AllocationFailure(); return true; }
            heap.TryGetModelValue(table, Originals, out Dictionary<StaticValue, StaticValue>? originals);
            var index = 0;
            // Use the table model's deterministic order; Hashtable promises no portable key order.
            foreach (var key in entries.Keys)
            {
                var original = originals?.GetValueOrDefault(key, key) ?? key;
                if (original.Kind != StaticValueKind.HeapReference || !heap.TryWriteArray(array, index++, original))
                { result = IntrinsicResult.Unknown("The original Hashtable key object is unavailable."); return true; }
            }
            heap.TrySetModelValue(enumerator, Source, table);
            heap.TrySetModelValue(enumerator, Keys, array);
            heap.TrySetModelValue(enumerator, Version, version);
            heap.TrySetModelValue(enumerator, "Index", -1);
            result = IntrinsicResult.Completed(enumerator);
        }
        return true;
    }

    private static IntrinsicResult InvalidOperation(StaticHeap heap, string message)
    {
        if (!heap.TryAllocateObject("System.InvalidOperationException", out var exception)) return AllocationFailure();
        heap.TrySetModelValue(exception, "Message", message);
        heap.TrySetModelValue(exception, "InnerException", StaticValue.Null);
        return new(StaticExecutionStatus.Threw, exception, message);
    }

    private static IntrinsicResult AllocationFailure() => new(StaticExecutionStatus.AllocationLimitExceeded,
        StaticValue.Unknown, "Hashtable key enumeration exceeded the allocation budget.");
}
