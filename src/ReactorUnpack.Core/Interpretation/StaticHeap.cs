using System.Buffers.Binary;
using dnlib.DotNet;

namespace ReactorUnpack.Core.Interpretation;

public sealed class StaticHeap
{
    private readonly StaticMachineLimits _limits;
    private readonly Dictionary<int, HeapObject> _objects = [];
    private readonly Dictionary<int, ManagedLocation> _managedCells = [];
    private readonly List<ImageRegionWrite> _imageWrites = [];
    private int _nextId = 1;
    private int _nextManagedReferenceId = 1;
    private long _nextSyntheticAddress = 0x1000_0000;

    public StaticHeap(StaticMachineLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        limits.Validate();
        _limits = limits;
    }

    public long AllocatedBytes { get; private set; }
    public int MaximumObjectLength => _limits.MaximumArrayLength;
    public IReadOnlyList<ImageRegionWrite> ImageWrites => _imageWrites;

    /// <summary>
    /// Notified with the region kind of every raw region write, so the owning machine state can
    /// attribute the write to the call stack that performed it.
    /// </summary>
    internal Action<string>? RegionWriteObserver { get; set; }

    public bool TryAllocateString(string value, out StaticValue reference)
    {
        ArgumentNullException.ThrowIfNull(value);
        reference = StaticValue.Unknown;
        if (value.Length > _limits.MaximumArrayLength ||
            !TryReserve(checked((long)value.Length * sizeof(char))))
            return false;
        reference = Add(new HeapString(value));
        return true;
    }

    public bool TryGetString(StaticValue reference, out string value)
    {
        value = string.Empty;
        if (!TryObject(reference, out var item) || item is not HeapString text)
            return false;
        value = text.Value;
        return true;
    }

    public bool TryAllocateMetadataHandle(object metadata, out StaticValue reference)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        reference = Add(new HeapMetadataHandle(metadata));
        return true;
    }

    public bool TryGetMetadataHandle(StaticValue reference, out object? metadata)
    {
        metadata = null;
        if (!TryObject(reference, out var item) || item is not HeapMetadataHandle handle)
            return false;
        metadata = handle.Metadata;
        return true;
    }

    public bool TryAllocateObject(string typeName, out StaticValue reference)
    {
        reference = StaticValue.Unknown;
        if (!TryReserve(16))
            return false;
        reference = Add(new HeapInstance(typeName, new Dictionary<string, StaticValue>(
            StringComparer.Ordinal), new Dictionary<string, object?>(StringComparer.Ordinal)));
        return true;
    }

    private readonly Dictionary<string, StaticValue> _types = new(StringComparer.Ordinal);

    /// <summary>
    /// Hands back the one object standing for a named type, making it on first request.
    /// </summary>
    /// <remarks>
    /// The runtime hands out a single <c>Type</c> per type and programs depend on it: they compare
    /// types with reference equality, key dictionaries on them, and branch on identity. Allocating
    /// a fresh model for every lookup would make <c>typeof(int) == typeof(int)</c> false, which is
    /// not a rounding error in fidelity but a wrong answer that sends the program down a path it
    /// would never have taken, somewhere far from where the model was wrong.
    /// </remarks>
    public bool TryAllocateType(string identity, out StaticValue reference)
    {
        if (_types.TryGetValue(identity, out reference))
            return true;
        if (!TryAllocateObject("System.Type", out reference))
            return false;
        TrySetModelValue(reference, "TypeName", identity);
        _types[identity] = reference;
        return true;
    }

    public bool TryGetObjectType(StaticValue reference, out string typeName)
    {
        typeName = string.Empty;
        if (!TryObject(reference, out var item) || item is not HeapInstance instance)
            return false;
        typeName = instance.TypeName;
        return true;
    }

    public bool TryReadField(StaticValue reference, IField field, out StaticValue value)
    {
        value = StaticValue.Unknown;
        if (!TryObject(reference, out var item) || item is not HeapInstance instance)
            return false;
        if (instance.Fields.TryGetValue(field.FullName, out value))
            return true;
        if (TryReadOverlapping(instance, field, out value))
            return true;
        value = DefaultFieldValue(field.FieldSig?.Type);
        return true;
    }

    /// <summary>
    /// Reads a field that shares its storage with one already written.
    /// </summary>
    /// <remarks>
    /// A type can place several fields at the same offset, and then writing one is writing all of
    /// them: the bytes are the same bytes, read through whichever name the code picks. Storing
    /// fields under their names, as this heap does, loses that — a value written as a long and read
    /// back as an int would come back as the default zero, which is not a near miss but a wrong
    /// number that goes on to be used as a length or an index.
    ///
    /// Obfuscator runtimes lean on this deliberately: a virtual machine that has to hold operands of
    /// any type keeps one union-shaped cell and reads back whichever member matches the operand's
    /// type. So this is not an exotic corner of the format but the ordinary case for the code the
    /// tool exists to read.
    /// </remarks>
    private static bool TryReadOverlapping(HeapInstance instance, IField field, out StaticValue value)
    {
        value = StaticValue.Unknown;
        if (field.ResolveFieldDef() is not { FieldOffset: { } offset } read ||
            read.DeclaringType is not { IsExplicitLayout: true } union)
        {
            return false;
        }

        foreach (var sharing in union.Fields)
        {
            if (sharing == read || sharing.FieldOffset != offset ||
                !instance.Fields.TryGetValue(sharing.FullName, out var written))
            {
                continue;
            }

            if (!TryReinterpret(written, read.FieldType, out value))
                continue;
            return true;
        }

        return false;
    }

    /// <summary>
    /// Reads the bits of a value as another primitive type, the way overlapping storage would.
    /// </summary>
    private static bool TryReinterpret(StaticValue written, TypeSig? asType, out StaticValue value)
    {
        value = StaticValue.Unknown;
        if (!written.IsKnown || !written.IsInteger || asType is null)
            return false;
        var bits = written.Kind == StaticValueKind.Int64 ? written.AsInt64() : written.AsInt32();
        value = asType.ElementType switch
        {
            ElementType.Boolean => StaticValue.FromInt32((bits & 1) != 0 ? 1 : 0),
            ElementType.I1 => StaticValue.FromInt32(unchecked((sbyte)bits)),
            ElementType.U1 => StaticValue.FromInt32(unchecked((byte)bits)),
            ElementType.I2 => StaticValue.FromInt32(unchecked((short)bits)),
            ElementType.U2 or ElementType.Char => StaticValue.FromInt32(unchecked((ushort)bits)),
            ElementType.I4 => StaticValue.FromInt32(unchecked((int)bits)),
            ElementType.U4 => StaticValue.FromInt32(unchecked((int)(uint)bits)),
            ElementType.I8 or ElementType.U8 => StaticValue.FromInt64(bits),
            _ => StaticValue.Unknown
        };
        return value.IsKnown;
    }

    /// <summary>
    /// Reads a field only when the interpretation actually assigned it, unlike
    /// <see cref="TryReadField"/> which substitutes the CLR default for an untouched field.
    /// </summary>
    /// <remarks>
    /// Recovering loader key material must distinguish "the loader stored zero here" from
    /// "this interpretation never reached the store". Defaulting the second case to zero
    /// would turn a modeling gap into a confidently wrong constant.
    /// </remarks>
    public bool TryReadAssignedField(StaticValue reference, IField field, out StaticValue value)
    {
        value = StaticValue.Unknown;
        return TryObject(reference, out var item) &&
            item is HeapInstance instance &&
            instance.Fields.TryGetValue(field.FullName, out value);
    }

    public bool TryWriteField(StaticValue reference, IField field, StaticValue value)
    {
        if (!TryObject(reference, out var item) || item is not HeapInstance instance)
            return false;
        // Writing one member of overlapping storage overwrites the others, so anything previously
        // written at the same offset is now stale and must not answer a later read.
        if (field.ResolveFieldDef() is { FieldOffset: { } offset } written &&
            written.DeclaringType is { IsExplicitLayout: true } union)
        {
            foreach (var sharing in union.Fields)
            {
                if (sharing != written && sharing.FieldOffset == offset)
                    instance.Fields.Remove(sharing.FullName);
            }
        }

        instance.Fields[field.FullName] = value;
        return true;
    }

    public bool TrySetModelValue(StaticValue reference, string name, object? value)
    {
        if (!TryObject(reference, out var item) || item is not HeapInstance instance)
            return false;
        instance.ModelValues[name] = value;
        return true;
    }

    public bool TryGetModelValue<T>(StaticValue reference, string name, out T? value)
    {
        value = default;
        if (!TryObject(reference, out var item) || item is not HeapInstance instance ||
            !instance.ModelValues.TryGetValue(name, out var itemValue) || itemValue is not T typed)
            return false;
        value = typed;
        return true;
    }

    public bool TryGetRuntimeTypeName(StaticValue reference, out string typeName)
    {
        typeName = string.Empty;
        if (!TryObject(reference, out var item))
            return false;
        typeName = item switch
        {
            HeapInstance instance => instance.TypeName,
            HeapArray array => array.ElementType + "[]",
            HeapString => "System.String",
            _ => string.Empty
        };
        return typeName.Length != 0;
    }

    public StaticValue AllocateManagedCell(StaticValue initialValue)
    {
        var id = _nextManagedReferenceId++;
        _managedCells[id] = new CellLocation(this, initialValue);
        return StaticValue.FromManagedReference(id);
    }

    public bool TryGetArrayElementReference(
        StaticValue array,
        int index,
        out StaticValue reference)
    {
        reference = StaticValue.Unknown;
        if (!TryObject(array, out var item) || item is not HeapArray values ||
            (uint)index >= (uint)values.Values.Length)
            return false;
        var id = _nextManagedReferenceId++;
        _managedCells[id] = new ArrayLocation(values, index);
        reference = StaticValue.FromManagedReference(id);
        return true;
    }

    public bool TryGetFieldReference(
        StaticValue instance,
        IField field,
        out StaticValue reference)
    {
        reference = StaticValue.Unknown;
        if (!TryObject(instance, out var item) || item is not HeapInstance value)
            return false;
        if (!value.Fields.ContainsKey(field.FullName))
            value.Fields[field.FullName] = DefaultFieldValue(field.FieldSig?.Type);
        var id = _nextManagedReferenceId++;
        _managedCells[id] = new FieldLocation(value, field.FullName);
        reference = StaticValue.FromManagedReference(id);
        return true;
    }

    /// <summary>Offsets a byte-addressable managed reference, modelling the pointer
    /// arithmetic performed on a pinned array.</summary>
    public bool TryOffsetManagedReference(
        StaticValue reference,
        int byteDelta,
        out StaticValue result)
    {
        result = StaticValue.Unknown;
        if (reference.Kind != StaticValueKind.ManagedReference ||
            !_managedCells.TryGetValue(reference.ManagedReferenceId, out var location))
            return false;
        if (byteDelta == 0)
        {
            result = reference;
            return true;
        }
        if (_managedCells.Count >= _limits.MaximumArrayLength)
            return false;
        if (location.Offset(byteDelta) is not { } offset)
            return false;
        var id = _nextManagedReferenceId++;
        _managedCells[id] = offset;
        result = StaticValue.FromManagedReference(id);
        return true;
    }

    /// <summary>Element width backing a managed reference, or zero when the reference is
    /// not byte-addressable.</summary>
    public bool TryGetManagedElementWidth(StaticValue reference, out int width)
    {
        width = 0;
        if (reference.Kind != StaticValueKind.ManagedReference ||
            !_managedCells.TryGetValue(reference.ManagedReferenceId, out var location))
            return false;
        width = location.ElementWidth;
        return width != 0;
    }

    public bool TryReadManaged(StaticValue reference, out StaticValue value)
    {
        value = StaticValue.Unknown;
        return reference.Kind == StaticValueKind.ManagedReference &&
            _managedCells.TryGetValue(reference.ManagedReferenceId, out var location) &&
            location.TryRead(out value);
    }

    public bool TryWriteManaged(StaticValue reference, StaticValue value) =>
        reference.Kind == StaticValueKind.ManagedReference &&
        _managedCells.TryGetValue(reference.ManagedReferenceId, out var location) &&
        location.TryWrite(value);

    public bool TryAllocateBox(string typeName, StaticValue value, out StaticValue reference)
    {
        if (!TryAllocateObject(typeName, out reference))
            return false;
        return TrySetModelValue(reference, "BoxedValue", value);
    }

    public bool TryUnbox(StaticValue reference, out StaticValue value)
    {
        value = StaticValue.Unknown;
        return TryGetModelValue(reference, "BoxedValue", out value);
    }

    public bool TryAllocateArray(TypeSig? elementType, int length, out StaticValue reference)
    {
        reference = StaticValue.Unknown;
        if (length < 0 || length > _limits.MaximumArrayLength)
            return false;

        var width = ElementWidth(elementType);
        if (!TryReserve(checked((long)length * width)))
            return false;

        var typeName = elementType?.FullName ?? "?";
        var initial = DefaultArrayValue(typeName, IsReferenceType(elementType));
        var values = new StaticValue[length];
        Array.Fill(values, initial);
        reference = Add(new HeapArray(typeName, initial, values));
        return true;
    }

    /// <summary>
    /// Copies an array, keeping what it holds and what it says it holds.
    /// </summary>
    public bool TryCloneArray(StaticValue original, out StaticValue reference)
    {
        reference = StaticValue.Unknown;
        if (!TryObject(original, out var item) || item is not HeapArray array ||
            !TryReserve(array.Values.Length))
        {
            return false;
        }

        reference = Add(new HeapArray(array.ElementType, array.DefaultValue, [.. array.Values]));
        return true;
    }

    public bool TryAllocateByteArray(
        ReadOnlySpan<byte> bytes,
        out StaticValue reference,
        int provenanceId = 0)
    {
        reference = StaticValue.Unknown;
        if (bytes.Length > _limits.MaximumArrayLength || !TryReserve(bytes.Length))
            return false;
        var array = new HeapArray(
            "System.Byte",
            StaticValue.FromInt32(0),
            new StaticValue[bytes.Length]);
        for (var i = 0; i < bytes.Length; i++)
            array.Values[i] = StaticValue.FromInt32(bytes[i]).WithProvenance(provenanceId);
        reference = Add(array).WithProvenance(provenanceId);
        return true;
    }

    public bool TryAllocateRegion(int byteLength, out StaticValue reference)
    {
        reference = StaticValue.Unknown;
        if (byteLength < 0 || byteLength > _limits.MaximumArrayLength || !TryReserve(byteLength))
            return false;
        reference = AddRegion(
            new byte[byteLength],
            "Region",
            AllocateSyntheticAddress(byteLength));
        return true;
    }

    public bool TryAllocateRegion(int byteLength, string kind, out StaticValue reference)
    {
        reference = StaticValue.Unknown;
        if (byteLength < 0 || byteLength > _limits.MaximumArrayLength || !TryReserve(byteLength))
            return false;
        reference = AddRegion(new byte[byteLength], kind, AllocateSyntheticAddress(byteLength));
        return true;
    }

    public bool TryAllocateRegion(
        ReadOnlySpan<byte> bytes,
        string kind,
        out StaticValue reference)
        => TryAllocateRegion(bytes, kind, null, out reference);

    public bool TryAllocateRegion(
        ReadOnlySpan<byte> bytes,
        string kind,
        long? baseAddress,
        out StaticValue reference)
    {
        reference = StaticValue.Unknown;
        if (bytes.Length > _limits.MaximumArrayLength)
            return false;
        var address = baseAddress ?? AllocateSyntheticAddress(bytes.Length);
        if (address < 0 ||
            RegionsOverlap(address, bytes.Length) ||
            !TryReserve(bytes.Length))
            return false;
        reference = AddRegion(bytes.ToArray(), kind, address);
        return true;
    }

    public bool TryGetLength(StaticValue reference, out int length)
    {
        length = 0;
        if (!TryObject(reference, out var value))
            return false;
        length = value switch
        {
            HeapArray array => array.Values.Length,
            HeapRegion region => region.Bytes.Length -
                (reference.Kind == StaticValueKind.NativePointer ? reference.NativeOffset : 0),
            _ => 0
        };
        return true;
    }

    public bool TryGetArrayElementType(StaticValue reference, out string elementType)
    {
        elementType = string.Empty;
        if (!TryObject(reference, out var value) || value is not HeapArray array)
            return false;
        elementType = array.ElementType;
        return true;
    }

    public bool TryReadArray(StaticValue reference, int index, out StaticValue value)
    {
        value = StaticValue.Unknown;
        if (!TryObject(reference, out var item) ||
            item is not HeapArray array ||
            (uint)index >= (uint)array.Values.Length)
            return false;
        value = array.Values[index];
        return true;
    }

    public bool TryWriteArray(StaticValue reference, int index, StaticValue value)
    {
        if (!TryObject(reference, out var item) ||
            item is not HeapArray array ||
            (uint)index >= (uint)array.Values.Length)
            return false;
        if (!TryNormalizeArrayElement(array.ElementType, value, out var normalized))
            return false;
        array.Values[index] = normalized;
        return true;
    }

    public bool TryClearArray(StaticValue reference, int index, int count)
    {
        if (!TryObject(reference, out var item) ||
            item is not HeapArray array ||
            index < 0 ||
            count < 0 ||
            index > array.Values.Length - count)
            return false;
        Array.Fill(array.Values, array.DefaultValue, index, count);
        return true;
    }

    public bool TryReadBytes(StaticValue reference, int offset, Span<byte> destination)
    {
        if (reference.Kind == StaticValueKind.ManagedReference &&
            _managedCells.TryGetValue(reference.ManagedReferenceId, out var managed))
        {
            return managed.TryReadBytes(offset, destination);
        }
        if (TryObject(reference, out var item) && item is HeapRegion region)
        {
            if (region.Kind == "RuntimeModule")
                return false;
            if (reference.Kind == StaticValueKind.NativePointer)
                offset = checked(offset + reference.NativeOffset);
            if (offset < 0 || offset > region.Bytes.Length - destination.Length)
                return false;
            region.Bytes.AsSpan(offset, destination.Length).CopyTo(destination);
            return true;
        }

        return item is HeapArray array &&
            TryReadArrayBytes(array, offset, destination);
    }

    public bool TryWriteBytes(StaticValue reference, int offset, ReadOnlySpan<byte> source)
    {
        if (reference.Kind == StaticValueKind.ManagedReference &&
            _managedCells.TryGetValue(reference.ManagedReferenceId, out var managed))
        {
            return managed.TryWriteBytes(offset, source);
        }
        if (TryObject(reference, out var item) && item is HeapRegion region)
        {
            if (reference.Kind == StaticValueKind.NativePointer)
                offset = checked(offset + reference.NativeOffset);
            if (offset < 0 || offset > region.Bytes.Length - source.Length)
                return false;
            source.CopyTo(region.Bytes.AsSpan(offset, source.Length));
            _imageWrites.Add(new ImageRegionWrite(reference, offset, source.ToArray(), region.Kind));
            RegionWriteObserver?.Invoke(region.Kind);
            return true;
        }

        return item is HeapArray array &&
            TryWriteArrayBytes(array, offset, source);
    }

    public bool TryInitializePrimitiveArray(
        StaticValue reference,
        ReadOnlySpan<byte> bytes,
        int provenanceId)
    {
        if (!TryObject(reference, out var item) || item is not HeapArray array)
            return false;
        var width = array.ElementType switch
        {
            "System.Byte" or "System.SByte" or "System.Boolean" => 1,
            "System.Int16" or "System.UInt16" or "System.Char" => 2,
            "System.Int32" or "System.UInt32" or "System.Single" => 4,
            "System.Int64" or "System.UInt64" or "System.Double" => 8,
            _ => 0
        };
        var required = checked(array.Values.Length * width);
        if (width == 0 || bytes.Length < required)
            return false;
        for (var index = 0; index < array.Values.Length; index++)
        {
            var element = bytes.Slice(index * width, width);
            var value = array.ElementType switch
            {
                "System.Byte" or "System.Boolean" => StaticValue.FromInt32(element[0]),
                "System.SByte" => StaticValue.FromInt32(unchecked((sbyte)element[0])),
                "System.Int16" => StaticValue.FromInt32(
                    BinaryPrimitives.ReadInt16LittleEndian(element)),
                "System.UInt16" or "System.Char" => StaticValue.FromInt32(
                    BinaryPrimitives.ReadUInt16LittleEndian(element)),
                "System.Int32" or "System.UInt32" => StaticValue.FromInt32(
                    BinaryPrimitives.ReadInt32LittleEndian(element)),
                "System.Single" => StaticValue.FromFloat32(
                    BitConverter.Int32BitsToSingle(BinaryPrimitives.ReadInt32LittleEndian(element))),
                "System.Int64" or "System.UInt64" => StaticValue.FromInt64(
                    BinaryPrimitives.ReadInt64LittleEndian(element)),
                _ => StaticValue.FromFloat64(
                    BitConverter.Int64BitsToDouble(BinaryPrimitives.ReadInt64LittleEndian(element)))
            };
            array.Values[index] = value.WithProvenance(provenanceId);
        }
        return true;
    }

    /// <summary>
    /// Every byte array the machine has allocated, in allocation order, with its contents.
    /// </summary>
    /// <remarks>
    /// Recovery passes that run a decryptor for its effect rather than its return value need a way
    /// to find what it produced. Enumerating in allocation order lets a caller prefer the last thing
    /// built, which is the plaintext rather than one of the intermediate buffers behind it.
    /// </remarks>
    public IEnumerable<(int Id, byte[] Bytes)> EnumerateByteArrays()
    {
        foreach (var id in _objects.Keys.Order())
        {
            if (_objects[id] is not HeapArray { ElementType: "System.Byte" } array)
                continue;
            var bytes = new byte[array.Values.Length];
            if (TryReadArrayBytes(array, 0, bytes))
                yield return (id, bytes);
        }
    }

    public IReadOnlyList<StaticValue>? GetArraySnapshot(StaticValue reference) =>
        TryObject(reference, out var item) && item is HeapArray array
            ? Array.AsReadOnly((StaticValue[])array.Values.Clone())
            : null;

    public byte[]? GetBytesSnapshot(StaticValue reference)
    {
        if (!TryGetLength(reference, out var length))
            return null;
        var result = new byte[length];
        return TryReadBytes(reference, 0, result) ? result : null;
    }

    public bool TryGetNativePointer(
        StaticValue reference,
        int additionalOffset,
        out StaticValue result)
    {
        result = StaticValue.Unknown;
        var id = reference.Kind switch
        {
            StaticValueKind.HeapReference => reference.HeapId,
            StaticValueKind.NativePointer => reference.NativeRegionId,
            _ => 0
        };
        if (id == 0 || !_objects.TryGetValue(id, out var item) || item is not HeapRegion region)
            return false;
        var offset = checked(
            (reference.Kind == StaticValueKind.NativePointer ? reference.NativeOffset : 0) +
            additionalOffset);
        if ((uint)offset > (uint)region.Bytes.Length)
            return false;
        result = StaticValue.FromNativePointer(id, offset);
        return true;
    }

    public bool TryGetNativeAddress(StaticValue reference, out long address)
    {
        address = 0;
        if (!TryObject(reference, out var item) || item is not HeapRegion region)
            return false;
        var offset = reference.Kind == StaticValueKind.NativePointer
            ? reference.NativeOffset
            : 0;
        address = checked(region.BaseAddress + offset);
        return true;
    }

    public bool TryResolveNativeAddress(long address, out StaticValue result)
    {
        result = StaticValue.Unknown;
        foreach (var pair in _objects)
        {
            if (pair.Value is not HeapRegion region ||
                address < region.BaseAddress ||
                address > region.BaseAddress + region.Bytes.Length)
            {
                continue;
            }
            result = StaticValue.FromNativePointer(
                pair.Key,
                checked((int)(address - region.BaseAddress)));
            return true;
        }
        return false;
    }

    private StaticValue Add(HeapObject value)
    {
        var id = _nextId++;
        _objects.Add(id, value);
        return StaticValue.FromHeapReference(id);
    }

    private StaticValue AddRegion(byte[] bytes, string kind, long baseAddress) =>
        Add(new HeapRegion(bytes, kind, baseAddress));

    private long AllocateSyntheticAddress(int byteLength)
    {
        const int alignment = 0x10000;
        var address = (_nextSyntheticAddress + alignment - 1) & -alignment;
        _nextSyntheticAddress = checked(address + Math.Max(byteLength, 1));
        return address;
    }

    private bool RegionsOverlap(long baseAddress, int byteLength)
    {
        var end = checked(baseAddress + byteLength);
        return _objects.Values.OfType<HeapRegion>().Any(region =>
        {
            var regionEnd = checked(region.BaseAddress + region.Bytes.Length);
            return baseAddress < regionEnd && region.BaseAddress < end;
        });
    }

    private bool TryObject(StaticValue reference, out HeapObject? value)
    {
        value = null;
        return reference.Kind switch
        {
            StaticValueKind.HeapReference => _objects.TryGetValue(reference.HeapId, out value),
            StaticValueKind.NativePointer =>
                _objects.TryGetValue(reference.NativeRegionId, out value),
            _ => false
        };
    }

    private bool TryReserve(long bytes)
    {
        if (bytes < 0 || bytes > _limits.MaximumAllocatedBytes - AllocatedBytes)
            return false;
        AllocatedBytes += bytes;
        return true;
    }

    private static bool TryReadArrayBytes(
        HeapArray array,
        int offset,
        Span<byte> destination)
    {
        var width = PrimitiveWidth(array.ElementType);
        var byteLength = checked(array.Values.Length * width);
        if (width == 0 || offset < 0 || offset > byteLength - destination.Length)
            return false;
        var bytes = new byte[byteLength];
        for (var index = 0; index < array.Values.Length; index++)
        {
            if (!TryWriteElementBytes(
                    array.ElementType,
                    array.Values[index],
                    bytes.AsSpan(index * width, width)))
            {
                return false;
            }
        }
        bytes.AsSpan(offset, destination.Length).CopyTo(destination);
        return true;
    }

    private static bool TryWriteArrayBytes(
        HeapArray array,
        int offset,
        ReadOnlySpan<byte> source)
    {
        var width = PrimitiveWidth(array.ElementType);
        var byteLength = checked(array.Values.Length * width);
        if (width == 0 || offset < 0 || offset > byteLength - source.Length)
            return false;
        var bytes = new byte[byteLength];
        if (!TryReadArrayBytes(array, 0, bytes))
            return false;
        source.CopyTo(bytes.AsSpan(offset, source.Length));
        for (var index = 0; index < array.Values.Length; index++)
        {
            var provenanceId = array.Values[index].ProvenanceId;
            if (!TryReadElementBytes(
                    array.ElementType,
                    bytes.AsSpan(index * width, width),
                    out var value))
            {
                return false;
            }
            array.Values[index] = value.WithProvenance(provenanceId);
        }
        return true;
    }

    private static bool TryWriteElementBytes(
        string type,
        StaticValue value,
        Span<byte> destination)
    {
        if (!TryNormalizeArrayElement(type, value, out var normalized))
            return false;
        switch (type)
        {
            case "System.Byte":
            case "System.SByte":
            case "System.Boolean":
                destination[0] = unchecked((byte)normalized.AsInt32());
                return true;
            case "System.Int16":
            case "System.UInt16":
            case "System.Char":
                BinaryPrimitives.WriteUInt16LittleEndian(
                    destination,
                    unchecked((ushort)normalized.AsInt32()));
                return true;
            case "System.Int32":
            case "System.UInt32":
                BinaryPrimitives.WriteInt32LittleEndian(destination, normalized.AsInt32());
                return true;
            case "System.Single":
                BinaryPrimitives.WriteInt32LittleEndian(
                    destination,
                    BitConverter.SingleToInt32Bits(normalized.AsFloat32()));
                return true;
            case "System.Int64":
            case "System.UInt64":
                BinaryPrimitives.WriteInt64LittleEndian(destination, normalized.AsInt64());
                return true;
            case "System.Double":
                BinaryPrimitives.WriteInt64LittleEndian(
                    destination,
                    BitConverter.DoubleToInt64Bits(normalized.AsFloat64()));
                return true;
            default:
                return false;
        }
    }

    private static bool TryReadElementBytes(
        string type,
        ReadOnlySpan<byte> source,
        out StaticValue value)
    {
        value = type switch
        {
            "System.Byte" or "System.Boolean" => StaticValue.FromInt32(source[0]),
            "System.SByte" => StaticValue.FromInt32(unchecked((sbyte)source[0])),
            "System.Int16" => StaticValue.FromInt32(
                BinaryPrimitives.ReadInt16LittleEndian(source)),
            "System.UInt16" or "System.Char" => StaticValue.FromInt32(
                BinaryPrimitives.ReadUInt16LittleEndian(source)),
            "System.Int32" or "System.UInt32" => StaticValue.FromInt32(
                BinaryPrimitives.ReadInt32LittleEndian(source)),
            "System.Single" => StaticValue.FromFloat32(BitConverter.Int32BitsToSingle(
                BinaryPrimitives.ReadInt32LittleEndian(source))),
            "System.Int64" or "System.UInt64" => StaticValue.FromInt64(
                BinaryPrimitives.ReadInt64LittleEndian(source)),
            "System.Double" => StaticValue.FromFloat64(BitConverter.Int64BitsToDouble(
                BinaryPrimitives.ReadInt64LittleEndian(source))),
            _ => StaticValue.Unknown
        };
        return value.Kind != StaticValueKind.Unknown;
    }

    private static bool TryNormalizeArrayElement(
        string type,
        StaticValue value,
        out StaticValue normalized)
    {
        normalized = value;
        if (!value.IsKnown)
            return true;
        var provenanceId = value.ProvenanceId;
        normalized = type switch
        {
            "System.Byte" or "System.Boolean" => StaticValue.FromInt32(
                unchecked((byte)value.AsInt64())),
            "System.SByte" => StaticValue.FromInt32(unchecked((sbyte)value.AsInt64())),
            "System.Int16" => StaticValue.FromInt32(unchecked((short)value.AsInt64())),
            "System.UInt16" or "System.Char" => StaticValue.FromInt32(
                unchecked((ushort)value.AsInt64())),
            "System.Int32" or "System.UInt32" => StaticValue.FromInt32(
                unchecked((int)value.AsInt64())),
            "System.Int64" or "System.UInt64" => StaticValue.FromInt64(value.AsInt64()),
            "System.Single" => StaticValue.FromFloat32((float)value.AsFloat64()),
            "System.Double" => StaticValue.FromFloat64(value.AsFloat64()),
            _ when value.Kind is StaticValueKind.HeapReference or
                StaticValueKind.Null => value,
            _ => StaticValue.Unknown
        };
        if (normalized.Kind == StaticValueKind.Unknown)
            return false;
        normalized = normalized.WithProvenance(provenanceId);
        return true;
    }

    private static int PrimitiveWidth(string type) => type switch
    {
        "System.Byte" or "System.SByte" or "System.Boolean" => 1,
        "System.Int16" or "System.UInt16" or "System.Char" => 2,
        "System.Int32" or "System.UInt32" or "System.Single" => 4,
        "System.Int64" or "System.UInt64" or "System.Double" => 8,
        _ => 0
    };

    private static StaticValue DefaultArrayValue(string type, bool isReference) =>
        isReference
            ? StaticValue.Null
            : type switch
            {
                "System.Int64" or "System.UInt64" => StaticValue.FromInt64(0),
                "System.Single" => StaticValue.FromFloat32(0),
                "System.Double" => StaticValue.FromFloat64(0),
                _ => StaticValue.FromInt32(0)
            };

    private static int ElementWidth(TypeSig? type) => type?.ElementType switch
    {
        ElementType.I8 or ElementType.U8 or ElementType.R8 => 8,
        ElementType.I2 or ElementType.U2 or ElementType.Char => 2,
        ElementType.I1 or ElementType.U1 or ElementType.Boolean => 1,
        _ => 4
    };

    private static bool IsReferenceType(TypeSig? type) => type?.ElementType is
        ElementType.Class or ElementType.Object or ElementType.String or
        ElementType.Array or ElementType.SZArray;

    private static StaticValue DefaultFieldValue(TypeSig? type) =>
        IsReferenceType(type)
            ? StaticValue.Null
            : type?.ElementType is ElementType.I8 or ElementType.U8
                ? StaticValue.FromInt64(0)
                : StaticValue.FromInt32(0);

    private abstract record HeapObject;
    private sealed record HeapArray(
        string ElementType,
        StaticValue DefaultValue,
        StaticValue[] Values) : HeapObject;
    private sealed record HeapRegion(byte[] Bytes, string Kind, long BaseAddress) : HeapObject;
    private sealed record HeapString(string Value) : HeapObject;
    private sealed record HeapMetadataHandle(object Metadata) : HeapObject;
    private sealed record HeapInstance(
        string TypeName,
        Dictionary<string, StaticValue> Fields,
        Dictionary<string, object?> ModelValues) : HeapObject;

    private abstract class ManagedLocation
    {
        public abstract bool TryRead(out StaticValue value);
        public abstract bool TryWrite(StaticValue value);
        public virtual bool TryReadBytes(int offset, Span<byte> destination) => false;
        public virtual bool TryWriteBytes(int offset, ReadOnlySpan<byte> source) => false;

        /// <summary>Width of one addressable element, or zero when the storage is not
        /// byte-addressable. Pinned-array pointers read and write across element boundaries.</summary>
        public virtual int ElementWidth => 0;

        public virtual ManagedLocation? Offset(int byteDelta) => null;
    }

    private sealed class CellLocation(StaticHeap heap, StaticValue value) : ManagedLocation
    {
        private StaticValue _value = value;
        public override bool TryRead(out StaticValue value)
        {
            value = _value;
            return true;
        }
        public override bool TryWrite(StaticValue value)
        {
            _value = value;
            return true;
        }
        public override bool TryReadBytes(int offset, Span<byte> destination)
        {
            Span<byte> bytes = stackalloc byte[8];
            if (_value.Kind == StaticValueKind.NativePointer)
            {
                if (!heap.TryGetNativeAddress(_value, out var address))
                    return false;
                BinaryPrimitives.WriteInt64LittleEndian(bytes, address);
            }
            else if (_value.IsInteger)
            {
                BinaryPrimitives.WriteInt64LittleEndian(bytes, _value.AsInt64());
            }
            else
            {
                return false;
            }
            if (offset < 0 || offset > bytes.Length - destination.Length)
                return false;
            bytes.Slice(offset, destination.Length).CopyTo(destination);
            return true;
        }
        public override bool TryWriteBytes(int offset, ReadOnlySpan<byte> source)
        {
            if (offset != 0 || source.Length is not 4 and not 8)
                return false;
            _value = source.Length == 4
                ? StaticValue.FromInt32(BinaryPrimitives.ReadInt32LittleEndian(source))
                : StaticValue.FromInt64(BinaryPrimitives.ReadInt64LittleEndian(source));
            return true;
        }
    }

    private sealed class ArrayLocation(HeapArray array, int index, int byteDelta = 0)
        : ManagedLocation
    {
        public override int ElementWidth => PrimitiveWidth(array.ElementType);

        public override bool TryRead(out StaticValue value)
        {
            value = StaticValue.Unknown;
            if (!TryElementIndex(out var element))
                return false;
            value = array.Values[element];
            return true;
        }
        public override bool TryWrite(StaticValue value)
        {
            if (!TryElementIndex(out var element) ||
                !TryNormalizeArrayElement(array.ElementType, value, out var normalized))
                return false;
            array.Values[element] = normalized;
            return true;
        }
        public override bool TryReadBytes(int offset, Span<byte> destination)
        {
            var width = PrimitiveWidth(array.ElementType);
            return width != 0 &&
                TryReadArrayBytes(
                    array,
                    checked(index * width + byteDelta + offset),
                    destination);
        }
        public override bool TryWriteBytes(int offset, ReadOnlySpan<byte> source)
        {
            var width = PrimitiveWidth(array.ElementType);
            return width != 0 &&
                TryWriteArrayBytes(
                    array,
                    checked(index * width + byteDelta + offset),
                    source);
        }
        public override ManagedLocation? Offset(int delta) =>
            PrimitiveWidth(array.ElementType) == 0
                ? null
                : new ArrayLocation(array, index, checked(byteDelta + delta));

        private bool TryElementIndex(out int element)
        {
            element = index;
            if (byteDelta != 0)
            {
                var width = PrimitiveWidth(array.ElementType);
                if (width == 0)
                    return false;
                var absolute = checked(index * width + byteDelta);
                if (absolute % width != 0)
                    return false;
                element = absolute / width;
            }
            return (uint)element < (uint)array.Values.Length;
        }
    }

    private sealed class FieldLocation(HeapInstance instance, string name) : ManagedLocation
    {
        public override bool TryRead(out StaticValue value) =>
            instance.Fields.TryGetValue(name, out value);
        public override bool TryWrite(StaticValue value)
        {
            instance.Fields[name] = value;
            return true;
        }
    }
}

public sealed record ImageRegionWrite(
    StaticValue Region,
    int Offset,
    byte[] Bytes,
    string RegionKind);

public sealed class StaticMachineState
{
    private readonly Dictionary<string, StaticValue> _staticFields = new(StringComparer.Ordinal);
    private readonly Dictionary<string, StaticValue> _staticFieldReferences =
        new(StringComparer.Ordinal);
    private readonly Dictionary<string, byte[]> _resources = new(StringComparer.Ordinal);
    private readonly Dictionary<string, TypeInitializationStatus> _typeInitialization =
        new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _typeInitializationFailures =
        new(StringComparer.Ordinal);
    private readonly List<TypeInitializationEvent> _typeInitializationEvents = [];
    private readonly Dictionary<string, StaticValue> _runtimeSingletons =
        new(StringComparer.Ordinal);

    public StaticMachineState(StaticMachineLimits limits)
    {
        Heap = new StaticHeap(limits) { RegionWriteObserver = Evidence.RecordRegionWrite };
        Provenance = new ProvenanceGraph(
            limits.MaximumProvenanceNodes,
            limits.MaximumProvenanceDepth,
            limits.MaximumRenderedProvenanceNodes);
    }

    public StaticHeap Heap { get; }
    public ProvenanceGraph Provenance { get; }

    /// <summary>
    /// Records what the loader did and where, so later passes can decide what is removable from
    /// interpretation evidence rather than from pattern guesses.
    /// </summary>
    internal LoaderEvidenceRecorder Evidence { get; } = new();

    public LoaderInterpretationEvidence LoaderEvidence => Evidence.Snapshot();

    /// <summary>
    /// Reports a loader behavior worth proving, such as a signature verdict or a debugger probe.
    /// </summary>
    public void Observe(LoaderObservationKind kind, string detail, bool? verdict = null) =>
        Evidence.Observe(kind, detail, verdict);

    /// <summary>
    /// Reports that the running frame handed the runtime something that outlives it.
    /// </summary>
    public void RecordRegistration(string detail) => Evidence.RecordRegistration(detail);

    /// <summary>
    /// Bytes the interpreted code tried to hand to <c>Assembly.Load</c>, in the order it offered
    /// them.
    /// </summary>
    /// <remarks>
    /// A loader that decrypts an assembly ends by asking the runtime to load it, and that call is
    /// the one place where the thing being loaded is unambiguously the payload rather than an
    /// intermediate. Recording the argument turns the interpretation into an answer without anyone
    /// having to recognise the format it arrived in: whatever chain of ciphers and containers
    /// produced these bytes, the module itself named them as the assembly it wanted.
    ///
    /// The load is recorded rather than performed. Nothing is loaded, resolved, or executed; the
    /// caller is handed a model assembly so that interpretation can continue past the call and
    /// reach any further stages, which is what makes a loader that unpacks more than one payload
    /// recoverable in a single run.
    /// </remarks>
    public IReadOnlyList<byte[]> CapturedAssemblyLoads => _capturedAssemblyLoads;

    private readonly List<byte[]> _capturedAssemblyLoads = [];

    public void CaptureAssemblyLoad(byte[] image) => _capturedAssemblyLoads.Add(image);

    /// <summary>
    /// Where interpreted code threw, in order, so a run that ended in an exception can be read back.
    /// </summary>
    /// <remarks>
    /// Obfuscator runtimes catch their own exceptions and rethrow them somewhere else entirely, so
    /// the place an interpretation finally stops is rarely the place it went wrong. Keeping the
    /// throws in the order they happened is what makes the first one findable, and the first one is
    /// almost always the one that matters. The log is bounded because a program that throws in a
    /// loop should not be able to grow it without limit.
    /// </remarks>
    public IReadOnlyList<string> ThrowSites => _throwSites;

    /// <summary>Whether any execution in this state stopped for want of steps.</summary>
    public bool RanOutOfBudget { get; set; }

    private readonly List<string> _throwSites = [];

    public void RecordThrow(string where)
    {
        const int mostWorthKeeping = 64;
        if (_throwSites.Count < mostWorthKeeping)
            _throwSites.Add(where);
    }

    public IReadOnlyDictionary<string, StaticValue> StaticFields => _staticFields;
    public IReadOnlyDictionary<string, byte[]> Resources => _resources;
    public IReadOnlyList<TypeInitializationEvent> TypeInitializationEvents =>
        _typeInitializationEvents;
    public StaticValue ImageRegion { get; private set; } = StaticValue.Unknown;
    public string AssemblyName { get; private set; } = string.Empty;
    public string ModulePath { get; private set; } = string.Empty;
    public byte[] ModuleFileBytes { get; private set; } = [];
    public byte[] PublicKeyToken { get; private set; } = [];
    public int PointerSize { get; private set; } = 8;

    public StaticValue ReadStaticField(IField field)
    {
        if (_staticFieldReferences.TryGetValue(field.FullName, out var reference) &&
            Heap.TryReadManaged(reference, out var referencedValue))
        {
            return referencedValue;
        }
        return _staticFields.TryGetValue(field.FullName, out var value)
            ? value
            : field.FieldSig?.Type.ElementType switch
            {
                ElementType.Class or ElementType.Object or ElementType.String or
                ElementType.Array or ElementType.SZArray => StaticValue.Null,
                ElementType.I8 or ElementType.U8 => StaticValue.FromInt64(0),
                _ => StaticValue.FromInt32(0)
            };
    }

    public void WriteStaticField(IField field, StaticValue value)
    {
        _staticFields[field.FullName] = value;
        Evidence.RecordStaticFieldWrite(field.FullName);
        if (_staticFieldReferences.TryGetValue(field.FullName, out var reference))
            Heap.TryWriteManaged(reference, value);
    }

    public StaticValue GetStaticFieldReference(IField field)
    {
        if (_staticFieldReferences.TryGetValue(field.FullName, out var reference))
            return reference;
        reference = Heap.AllocateManagedCell(ReadStaticField(field));
        _staticFieldReferences[field.FullName] = reference;
        return reference;
    }

    public void RegisterResource(string name, ReadOnlySpan<byte> bytes)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        if (bytes.Length > Heap.MaximumObjectLength)
            throw new ArgumentOutOfRangeException(nameof(bytes));
        _resources[name] = bytes.ToArray();
    }

    public bool TryOpenResource(string name, out StaticValue stream)
    {
        stream = StaticValue.Unknown;
        var origin = Provenance.Origin(
            StaticValue.FromInt32(_resources.TryGetValue(name, out var registered)
                ? registered.Length
                : 0),
            ProvenanceKind.Resource,
            "resource",
            name);
        if (!_resources.TryGetValue(name, out var bytes) ||
            !Heap.TryAllocateByteArray(bytes, out var buffer, origin.ProvenanceId) ||
            !Heap.TryAllocateObject("System.IO.MemoryStream", out stream))
            return false;
        stream = stream.WithProvenance(origin.ProvenanceId);
        Heap.TrySetModelValue(stream, "Buffer", buffer);
        Heap.TrySetModelValue(stream, "Position", 0L);
        Heap.TrySetModelValue(stream, "Origin", 0);
        Heap.TrySetModelValue(stream, "Length", bytes.Length);
        Heap.TrySetModelValue(stream, "Capacity", bytes.Length);
        Heap.TrySetModelValue(stream, "Writable", false);
        Heap.TrySetModelValue(stream, "Expandable", false);
        Heap.TrySetModelValue(stream, "PubliclyVisible", false);
        Heap.TrySetModelValue(stream, "Open", true);
        return true;
    }

    public bool TryRegisterImage(ReadOnlySpan<byte> mappedImage, ulong imageBase = 0)
    {
        if (imageBase > long.MaxValue ||
            !Heap.TryAllocateRegion(
                mappedImage,
                "MappedImage",
                checked((long)imageBase),
                out var region))
            return false;
        ImageRegion = region;
        return true;
    }

    public void RegisterAssemblyIdentity(string name, ReadOnlySpan<byte> publicKeyToken)
    {
        AssemblyName = name ?? string.Empty;
        PublicKeyToken = publicKeyToken.ToArray();
    }

    /// <summary>
    /// The metadata of the module being interpreted, for the reflection it performs on itself.
    /// </summary>
    /// <remarks>
    /// Everything else in this environment is deliberately absent unless the module can observe it,
    /// and its own metadata is squarely on the observable side: a running assembly can always ask
    /// its module to resolve one of its own tokens, and the answer is fixed by the file rather than
    /// by anything about the machine it runs on. Handing it over is therefore modeling rather than
    /// inventing, and it is what lets a token-driven runtime be interpreted instead of refused.
    ///
    /// Only this module is reachable. A token belonging to somebody else's metadata resolves to
    /// nothing here, which is the same answer the interpretation would be entitled to draw anyway.
    /// </remarks>
    public ModuleDef? ModuleMetadata { get; private set; }

    public void RegisterModuleMetadata(ModuleDef module) => ModuleMetadata = module;

    public void RegisterPointerSize(int pointerSize)
    {
        if (pointerSize is not 4 and not 8)
            throw new ArgumentOutOfRangeException(nameof(pointerSize));
        PointerSize = pointerSize;
    }

    /// <summary>Registers the on-disk path and bytes of the analysed assembly. This is the
    /// only file the machine can observe; every other path is modelled as absent.</summary>
    public void RegisterModuleFile(string path, ReadOnlySpan<byte> bytes)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        ModulePath = path;
        ModuleFileBytes = bytes.ToArray();
    }

    public bool TryGetOrAllocateRuntimeSingleton(string typeName, out StaticValue value)
    {
        if (_runtimeSingletons.TryGetValue(typeName, out value))
            return true;
        if (!Heap.TryAllocateObject(typeName, out value))
            return false;
        _runtimeSingletons.Add(typeName, value);
        return true;
    }

    public TypeInitializationStatus GetTypeInitializationStatus(TypeDef type) =>
        _typeInitialization.GetValueOrDefault(
            type.FullName,
            TypeInitializationStatus.Uninitialized);

    public TypeInitializationStatus TryBeginTypeInitialization(TypeDef type)
    {
        var status = GetTypeInitializationStatus(type);
        if (status != TypeInitializationStatus.Uninitialized)
            return status;
        _typeInitialization[type.FullName] = TypeInitializationStatus.Initializing;
        _typeInitializationEvents.Add(new(
            _typeInitializationEvents.Count,
            type.FullName,
            TypeInitializationStatus.Initializing));
        return TypeInitializationStatus.Initializing;
    }

    public void CompleteTypeInitialization(TypeDef type)
    {
        _typeInitialization[type.FullName] = TypeInitializationStatus.Initialized;
        _typeInitializationEvents.Add(new(
            _typeInitializationEvents.Count,
            type.FullName,
            TypeInitializationStatus.Initialized));
    }

    public void FailTypeInitialization(TypeDef type, string diagnostic)
    {
        _typeInitialization[type.FullName] = TypeInitializationStatus.Failed;
        _typeInitializationFailures[type.FullName] = diagnostic;
        _typeInitializationEvents.Add(new(
            _typeInitializationEvents.Count,
            type.FullName,
            TypeInitializationStatus.Failed));
    }

    public string GetTypeInitializationFailure(TypeDef type) =>
        _typeInitializationFailures.GetValueOrDefault(type.FullName, string.Empty);
}

public enum TypeInitializationStatus
{
    Uninitialized,
    Initializing,
    Initialized,
    Failed
}

public readonly record struct TypeInitializationEvent(
    int Sequence,
    string Type,
    TypeInitializationStatus Status);
