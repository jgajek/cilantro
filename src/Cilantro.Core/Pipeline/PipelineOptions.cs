using Cilantro.Core.Recovery;

namespace Cilantro.Core;

public sealed record PipelineOptions(
    bool AnalyzeOnly = false,
    bool PreserveTokens = true,
    bool FailOnPartial = false,
    bool RemoveRuntime = true,

    /// <summary>
    /// Whether to give Reactor's generated names readable placeholders. Null follows the mode.
    /// </summary>
    /// <remarks>
    /// A triage run renames, because the analyst it is for is about to read the result and every
    /// name in it is a machine's. A strict run does not, because the names as they stand are what a
    /// signature is written against and what a second tool's output is compared with, and an expert
    /// who wants them changed can say so.
    /// </remarks>
    bool? RenameSymbols = null,
    string? OutputPath = null,
    string? ReportDirectory = null,
    string? HostProfilePath = null,
    IReadOnlyList<string>? LibraryPaths = null,
    string? DeclarationsPath = null,
    bool AllowDeclaredCalls = false,

    /// <summary>
    /// Whether to refuse wherever the run would otherwise assume its way past something.
    /// </summary>
    /// <remarks>
    /// Off by default, because the commonest reason a run of an unfamiliar sample produced nothing was
    /// a call on the way to the payload whose result nothing used. What the default costs is that some
    /// of what the report says rests on a machine nobody described and on calls nobody read, and the
    /// report says which. What it buys is measured in <c>docs/compatibility.md</c>.
    /// </remarks>
    bool Strict = false,

    /// <summary>
    /// Whether to build the virtualized methods back into code in the cleaned copy. Null follows
    /// the mode.
    /// </summary>
    /// <remarks>
    /// A triage run builds them, because a method nobody can read is the thing the analyst is
    /// stuck on, and a stub sitting in an otherwise readable assembly is exactly where they get
    /// stuck. A strict run does not, because it is the one thing the tool produces that it cannot
    /// prove: everything else in the cleaned assembly is the protector's own output, while a body
    /// built from a reading is the reading itself, and if the reading is wrong the body is wrong
    /// in a way no reader can see.
    ///
    /// Where they are built, each one is marked with an attribute saying so, which a decompiler
    /// shows above the method, and where the module's own work can test the bodies the tool runs
    /// that test and reports the verdict.
    /// </remarks>
    bool? Devirtualize = null,

    /// <summary>
    /// Where to keep a <see cref="RunStatus"/> file current while the run lasts, or null to write
    /// none.
    /// </summary>
    /// <remarks>
    /// Opt-in rather than always, for two reasons. A run whose caller is sitting in front of it has
    /// the summary and does not need a file to find out what is happening; and the file carries a
    /// clock and a process id, so a run that wrote one unconditionally would stop being reproducible
    /// byte for byte, which is a property the corpus leans on.
    /// </remarks>
    string? StatusPath = null,

    /// <summary>Asks the run to stop.</summary>
    /// <remarks>
    /// <para>
    /// Observed between passes rather than within them, which sounds coarse and is not, because the
    /// interpreter's step and allocation budgets already bound how long a single pass can take: a pass
    /// cannot spin forever without exhausting one of them and reporting a blocker. So the wait for a
    /// cancellation to take effect is bounded by the slowest pass rather than by the run.
    /// </para>
    /// <para>
    /// A cancelled run throws <see cref="OperationCanceledException"/> rather than returning a partial
    /// result, because a <see cref="PipelineResult"/> is a claim about an assembly and half a pipeline
    /// has no claim to make. What the run had already written to disk stays written.
    /// </para>
    /// </remarks>
    CancellationToken Cancellation = default)
{
    /// <summary>
    /// Whether this run gives Reactor's generated names readable placeholders.
    /// </summary>
    public bool Renames => RenameSymbols ?? !Strict;

    /// <summary>
    /// Whether this run builds the virtualized methods back into code in the cleaned copy.
    /// </summary>
    public bool Devirtualizes => Devirtualize ?? !Strict;

    /// <summary>
    /// Whether this run reads a field nothing writes as the value it therefore holds. Reflection
    /// can name a field without the module showing which, so this is a reading and a strict run
    /// does not draw it.
    /// </summary>
    public bool FoldsUnwrittenState => !Strict;
}

public sealed record PipelineResult(
    bool Success,
    string AnalysisReportPath,
    string ChangesReportPath,
    string? OutputPath,
    IReadOnlyList<string> ExtractedPayloadPaths,
    ArtifactReport Report)
{
    /// <summary>Listings of the programs behind virtualized methods, two files per method.</summary>
    public IReadOnlyList<string> VirtualProgramPaths { get; init; } = [];

    /// <summary>
    /// Programs the interpreter is asked to run from a method that does work of its own, so no
    /// method stands for the program and no body can be built into one.
    /// </summary>
    public int ProgramsRunElsewhere { get; init; }

    /// <summary>How many methods the protector turned into interpreter bytecode.</summary>
    public int VirtualizedMethods { get; init; }

    /// <summary>Where the account of what stopped the run was written.</summary>
    public string? BlockerReportPath { get; init; }

    /// <summary>
    /// Where the constants the protector hid were written, or null where it hid none.
    /// </summary>
    public string? ConfigReportPath { get; init; }

    /// <summary>Where the old name of everything renamed was written, if anything was.</summary>
    public string? RenameMapPath { get; init; }

    /// <summary>How many virtualized methods the cleaned copy holds as code rather than as a stub.</summary>
    public int RebuiltMethods { get; init; }

    /// <summary>What came of building those bodies, method by method.</summary>
    public IReadOnlyList<string> DevirtualizationNotes { get; init; } = [];

    /// <summary>What running the built copy established about the bodies built into it.</summary>
    public DevirtualizationCheck DevirtualizationCheck { get; init; }
}
