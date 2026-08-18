namespace Cilantro.Core.Interpretation;

/// <summary>
/// Everything a run was told and everything it could not get past, in one thing every machine holds.
/// </summary>
/// <remarks>
/// <para>
/// A run interprets the same module in several passes, each building its own machine. Until now each
/// of those machines had its own idea of the world: the first was handed the run's host profile and
/// the other two were not, so a caller who stated a fact found it answered in one pass and refused in
/// the next, with nothing in the report to say why. Passing one environment to all of them is what
/// makes a stated fact a fact about the run rather than about whichever pass happened to ask.
/// </para>
/// <para>
/// It carries the refusals as well as the answers, and for the same reason: a sample stops in four
/// places and they are usually the same place reached four ways, so the account of what stopped it
/// belongs to the run and not to the machine that noticed first.
/// </para>
/// </remarks>
public sealed class RunEnvironment
{
    public RunEnvironment(
        HostEnvironment? host = null,
        RunDeclarations? declarations = null,
        BlockerLedger? blockers = null,
        bool strict = true)
    {
        Declarations = declarations ?? RunDeclarations.None;
        Host = host ?? new HostEnvironment(Declarations.Facts);
        Blockers = blockers ?? new BlockerLedger();
        Strict = strict;
    }

    /// <summary>
    /// Whether the run refuses to go on where it would otherwise assume its way past something.
    /// </summary>
    /// <remarks>
    /// The one knob that changes what the interpreter does rather than what it knows. Turned off, a
    /// call the machine cannot follow is stepped over and its result is unknown, which is what makes an
    /// unfamiliar sample yield something rather than nothing. Turned on, such a call stops the frame as
    /// it always did, which is what somebody wants when the answer is going to be relied on.
    ///
    /// A machine stood up on its own is strict, because it has no run behind it to have chosen. The
    /// choice belongs to whoever is running the tool, and the pipeline makes it explicitly.
    /// </remarks>
    public bool Strict { get; }

    /// <summary>What this run says when interpreted code asks about the computer it is on.</summary>
    public HostEnvironment Host { get; }

    /// <summary>What the run was told, including what it may not use unless asked to.</summary>
    public RunDeclarations Declarations { get; }

    /// <summary>What stopped the run, gathered across every pass of it.</summary>
    public BlockerLedger Blockers { get; }

    /// <summary>
    /// Which pass is interpreting, so that a refusal says where in the run it happened.
    /// </summary>
    public string? Pass
    {
        get => Blockers.Pass;
        set => Blockers.Pass = value;
    }

    /// <summary>
    /// The same run, seen through a different host profile.
    /// </summary>
    /// <remarks>
    /// Kept because machines are handed a profile on their own in places that know nothing about a
    /// run, and doing so should not throw away the ledger they were already writing into.
    /// </remarks>
    public RunEnvironment With(HostEnvironment host) => new(host, Declarations, Blockers, Strict);
}
