using dnlib.DotNet;

namespace ReactorUnpack.Core.Interpretation;

public enum LoaderObservationKind
{
    /// <summary>The loader read its own module file, the hallmark of self-hashing.</summary>
    ModuleFileRead,
    /// <summary>A signature verification completed, with a concrete verdict.</summary>
    SignatureVerification,
    /// <summary>The loader read strong-name identity material.</summary>
    StrongNameProbe,
    /// <summary>The loader asked whether a debugger is present.</summary>
    DebuggerProbe,
    /// <summary>The loader requested process termination.</summary>
    Termination
}

/// <summary>
/// One observation the machine made while interpreting the loader, attributed to the call stack
/// that produced it.
/// </summary>
/// <remarks>
/// The stack is what makes an observation actionable. Reactor buries its verification behind
/// several <c>object</c>-typed wrappers, so the method that literally calls
/// <c>RSACryptoServiceProvider.VerifyHash</c> is a generic helper shared with unrelated code.
/// Deciding what may be removed requires knowing which enclosing frames the check ran under.
/// </remarks>
public sealed record LoaderObservation(
    LoaderObservationKind Kind,
    string Detail,
    bool? Verdict,
    IReadOnlyList<uint> CallStack);

/// <summary>
/// The side effects a method's call subtree produced during interpretation.
/// </summary>
/// <remarks>
/// A <c>static void</c> loader entry point can only communicate with the rest of the program
/// through static fields, the mapped image, or something it hands to the runtime, because it takes
/// no arguments and returns nothing, and any object it allocates is unreachable unless it is stored
/// somewhere durable. Recording those channels per subtree therefore yields a sound removability
/// test. Writes to loader-private scratch regions are tracked separately: that memory is allocated
/// and consumed inside the same interpretation and cannot outlive it.
///
/// Static writes are recorded by field name rather than as a flag because a loader routine that
/// only writes fields nothing else ever reads is still removable, and Reactor's integrity check
/// does exactly that.
///
/// Registrations exist because the machine refuses any call it does not model, which makes the
/// account complete for everything except the calls it does model and treats as succeeding
/// silently. Handing the runtime an event handler is the one such call: it changes what the program
/// does later while touching no field and no memory the interpretation can see. Recording it keeps
/// the account honest, so a caller may treat an empty account as proof that a frame does nothing
/// rather than as proof that nothing was noticed.
/// </remarks>
public sealed record LoaderMethodEffects(
    IReadOnlyList<string> StaticFieldsWritten,
    bool WroteMappedImage,
    bool WroteScratchRegion,
    IReadOnlyList<string> Registrations)
{
    public bool WroteStaticField => StaticFieldsWritten.Count != 0;
}

public sealed record LoaderInterpretationEvidence(
    IReadOnlyList<LoaderObservation> Observations,
    IReadOnlyDictionary<uint, LoaderMethodEffects> Effects)
{
    public static LoaderInterpretationEvidence Empty { get; } =
        new([], new Dictionary<uint, LoaderMethodEffects>());

    public LoaderMethodEffects EffectsOf(uint token) =>
        Effects.TryGetValue(token, out var effects)
            ? effects
            : new LoaderMethodEffects([], false, false, []);

    /// <summary>
    /// Confirms two independent interpretations reached the same conclusions, so nothing is
    /// removed on evidence that depends on interpretation order or ambient state.
    /// </summary>
    public bool Agrees(LoaderInterpretationEvidence other)
    {
        ArgumentNullException.ThrowIfNull(other);
        if (Observations.Count != other.Observations.Count || Effects.Count != other.Effects.Count)
            return false;
        for (var index = 0; index < Observations.Count; index++)
        {
            var left = Observations[index];
            var right = other.Observations[index];
            if (left.Kind != right.Kind ||
                left.Verdict != right.Verdict ||
                !string.Equals(left.Detail, right.Detail, StringComparison.Ordinal) ||
                !left.CallStack.SequenceEqual(right.CallStack))
            {
                return false;
            }
        }
        return Effects.All(entry =>
            other.Effects.TryGetValue(entry.Key, out var effects) &&
            effects.WroteMappedImage == entry.Value.WroteMappedImage &&
            effects.WroteScratchRegion == entry.Value.WroteScratchRegion &&
            effects.StaticFieldsWritten.SequenceEqual(
                entry.Value.StaticFieldsWritten, StringComparer.Ordinal) &&
            effects.Registrations.SequenceEqual(entry.Value.Registrations, StringComparer.Ordinal));
    }
}

/// <summary>
/// Accumulates loader observations and per-subtree effects across one interpretation.
/// </summary>
internal sealed class LoaderEvidenceRecorder
{
    private const int MaximumObservations = 4096;

    private readonly List<uint> _callStack = [];
    private readonly List<LoaderObservation> _observations = [];
    private readonly Dictionary<uint, MutableEffects> _effects = [];

    public void EnterMethod(MethodDef method) => _callStack.Add(method.MDToken.Raw);

    public void LeaveMethod()
    {
        if (_callStack.Count != 0)
            _callStack.RemoveAt(_callStack.Count - 1);
    }

    public void Observe(LoaderObservationKind kind, string detail, bool? verdict = null)
    {
        if (_observations.Count >= MaximumObservations)
            return;
        _observations.Add(new LoaderObservation(kind, detail, verdict, _callStack.ToArray()));
    }

    public void RecordStaticFieldWrite(string fieldFullName) =>
        MarkStack(effects => effects.StaticFields.Add(fieldFullName));

    /// <summary>
    /// Records that the subtree handed something to the runtime that outlives the interpretation.
    /// </summary>
    public void RecordRegistration(string detail) =>
        MarkStack(effects => effects.Registrations.Add(detail));

    public void RecordRegionWrite(string regionKind)
    {
        if (string.Equals(regionKind, "MappedImage", StringComparison.Ordinal))
            MarkStack(static effects => effects.MappedImage = true);
        else
            MarkStack(static effects => effects.ScratchRegion = true);
    }

    public LoaderInterpretationEvidence Snapshot() => new(
        _observations.ToArray(),
        _effects.ToDictionary(
            entry => entry.Key,
            entry => new LoaderMethodEffects(
                entry.Value.StaticFields.Order(StringComparer.Ordinal).ToArray(),
                entry.Value.MappedImage,
                entry.Value.ScratchRegion,
                entry.Value.Registrations.Order(StringComparer.Ordinal).ToArray())));

    // Attributing a write to every frame currently on the stack gives subtree semantics: a
    // caller is responsible for whatever its callees wrote, which is what removability needs.
    private void MarkStack(Action<MutableEffects> mark)
    {
        foreach (var token in _callStack)
        {
            if (!_effects.TryGetValue(token, out var effects))
                _effects[token] = effects = new MutableEffects();
            mark(effects);
        }
    }

    private sealed class MutableEffects
    {
        public HashSet<string> StaticFields { get; } = new(StringComparer.Ordinal);
        public HashSet<string> Registrations { get; } = new(StringComparer.Ordinal);
        public bool MappedImage { get; set; }
        public bool ScratchRegion { get; set; }
    }
}
