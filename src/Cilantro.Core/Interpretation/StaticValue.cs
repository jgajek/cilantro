namespace Cilantro.Core.Interpretation;

#pragma warning disable CA1720
public enum StaticValueKind
{
    Unknown,
    Null,
    Int32,
    Int64,
    Float32,
    Float64,
    HeapReference,
    ManagedReference,
    NativePointer
}
#pragma warning restore CA1720

public readonly record struct StaticValue
{
    private StaticValue(StaticValueKind kind, long bits, int provenanceId = 0)
    {
        Kind = kind;
        Bits = bits;
        ProvenanceId = provenanceId;
    }

    public StaticValueKind Kind { get; }
    public long Bits { get; }
    public int ProvenanceId { get; }

    public static StaticValue Unknown => new(StaticValueKind.Unknown, 0);
    public static StaticValue Null => new(StaticValueKind.Null, 0);
    public static StaticValue FromInt32(int value) => new(StaticValueKind.Int32, value);
    public static StaticValue FromInt64(long value) => new(StaticValueKind.Int64, value);
    public static StaticValue FromFloat32(float value) =>
        new(StaticValueKind.Float32, BitConverter.SingleToInt32Bits(value));
    public static StaticValue FromFloat64(double value) =>
        new(StaticValueKind.Float64, BitConverter.DoubleToInt64Bits(value));
    public static StaticValue FromHeapReference(int id) =>
        id > 0
            ? new StaticValue(StaticValueKind.HeapReference, id)
            : throw new ArgumentOutOfRangeException(nameof(id));
    public static StaticValue FromManagedReference(int id) =>
        id > 0
            ? new StaticValue(StaticValueKind.ManagedReference, id)
            : throw new ArgumentOutOfRangeException(nameof(id));
    public static StaticValue FromNativePointer(int regionId, int offset = 0) =>
        regionId > 0
            ? new StaticValue(
                StaticValueKind.NativePointer,
                ((long)regionId << 32) | (uint)offset)
            : throw new ArgumentOutOfRangeException(nameof(regionId));

    public StaticValue WithProvenance(int provenanceId) =>
        provenanceId >= 0
            ? new StaticValue(Kind, Bits, provenanceId)
            : throw new ArgumentOutOfRangeException(nameof(provenanceId));

    public bool Equals(StaticValue other) => Kind == other.Kind && Bits == other.Bits;
    public override int GetHashCode() => HashCode.Combine(Kind, Bits);

    public int AsInt32() => Kind == StaticValueKind.Int32
        ? unchecked((int)Bits)
        : throw new InvalidOperationException($"Value is {Kind}, not Int32.");

    public long AsInt64() => Kind switch
    {
        StaticValueKind.Int32 => unchecked((int)Bits),
        StaticValueKind.Int64 => Bits,
        _ => throw new InvalidOperationException($"Value is {Kind}, not an integer.")
    };

    public float AsFloat32() => Kind == StaticValueKind.Float32
        ? BitConverter.Int32BitsToSingle(unchecked((int)Bits))
        : throw new InvalidOperationException($"Value is {Kind}, not Float32.");

    public double AsFloat64() => Kind switch
    {
        StaticValueKind.Float32 => AsFloat32(),
        StaticValueKind.Float64 => BitConverter.Int64BitsToDouble(Bits),
        _ => throw new InvalidOperationException($"Value is {Kind}, not floating point.")
    };

    public int HeapId => Kind == StaticValueKind.HeapReference
        ? checked((int)Bits)
        : throw new InvalidOperationException($"Value is {Kind}, not a heap reference.");

    public int ManagedReferenceId => Kind == StaticValueKind.ManagedReference
        ? checked((int)Bits)
        : throw new InvalidOperationException($"Value is {Kind}, not a managed reference.");

    public int NativeRegionId => Kind == StaticValueKind.NativePointer
        ? checked((int)(Bits >> 32))
        : throw new InvalidOperationException($"Value is {Kind}, not a native pointer.");

    public int NativeOffset => Kind == StaticValueKind.NativePointer
        ? unchecked((int)Bits)
        : throw new InvalidOperationException($"Value is {Kind}, not a native pointer.");

    public bool IsInteger => Kind is StaticValueKind.Int32 or StaticValueKind.Int64;
    public bool IsFloatingPoint => Kind is StaticValueKind.Float32 or StaticValueKind.Float64;
    public bool IsKnown => Kind != StaticValueKind.Unknown;

    /// <summary>
    /// Renders the kind and the bits, and never throws.
    /// </summary>
    /// <remarks>
    /// The accessors above reject a value of the wrong kind, which is what makes a misread loud
    /// rather than silently wrong. A record struct's generated rendering reads every property, so
    /// without this override merely mentioning a value in a diagnostic message throws for all but
    /// one kind — and it throws hardest exactly when something has gone wrong and the value most
    /// needs describing.
    /// </remarks>
    public override string ToString() => $"{Kind}:{Bits}";
}

public enum StaticExecutionStatus
{
    Completed,
    Unknown,
    Unsupported,

    /// <summary>
    /// The frame ended by throwing, and the thrown object is the result value.
    /// </summary>
    /// <remarks>
    /// Obfuscator runtimes throw and catch as ordinary control flow rather than only on error, so a
    /// throw that leaves a frame is a normal outcome that the caller may well handle. Carrying it as
    /// its own status keeps it distinguishable from a frame the machine could not interpret, which
    /// is what lets a caught exception resume instead of ending the interpretation.
    /// </remarks>
    Threw,
    StepLimitExceeded,
    RecursionLimitExceeded,
    AllocationLimitExceeded,
    InvalidProgram
}

public sealed record StaticExecutionResult(
    StaticExecutionStatus Status,
    StaticValue Value,
    string? Diagnostic = null,
    int Steps = 0,
    long AllocatedBytes = 0)
{
    public bool Succeeded => Status == StaticExecutionStatus.Completed;
}

public sealed record StaticMachineLimits(
    int MaximumSteps = 100_000,
    int MaximumRecursionDepth = 32,
    long MaximumAllocatedBytes = 16 * 1024 * 1024,
    int MaximumArrayLength = 4 * 1024 * 1024,
    int MaximumProvenanceNodes = 100_000,
    int MaximumProvenanceDepth = 128,
    int MaximumRenderedProvenanceNodes = 48)
{
    internal void Validate()
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaximumSteps);
        ArgumentOutOfRangeException.ThrowIfNegative(MaximumRecursionDepth);
        ArgumentOutOfRangeException.ThrowIfNegative(MaximumAllocatedBytes);
        ArgumentOutOfRangeException.ThrowIfNegative(MaximumArrayLength);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaximumProvenanceNodes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaximumProvenanceDepth);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaximumRenderedProvenanceNodes);
    }
}

public sealed class StaticWorkBudget
{
    public StaticWorkBudget(int maximumSteps)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumSteps);
        MaximumSteps = maximumSteps;
    }

    public int MaximumSteps { get; }
    public int ConsumedSteps { get; private set; }
    public int RemainingSteps => MaximumSteps - ConsumedSteps;

    public bool TryConsumeStep()
    {
        if (ConsumedSteps >= MaximumSteps)
            return false;
        ConsumedSteps++;
        return true;
    }
}
