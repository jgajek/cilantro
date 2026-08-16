using ReactorUnpack.Core.Interpretation;
using ReactorUnpack.Core.Recovery;

namespace ReactorUnpack.Core;

/// <summary>
/// One run, said in a single object: what it found, where it put things, and whether another run
/// with more declared to it would do better.
/// </summary>
/// <remarks>
/// <para>
/// The summary the tool prints is written for a person, and reading it with a program means matching
/// English against patterns that were never a promise. The reports on disk are the machine-readable
/// half, but a caller has to know where they are before it can read them, and until now that meant
/// reconstructing <c>NAME.analysis.json</c> from the input path and the naming convention. Working
/// out where the answer is should not be the hard part of asking the question.
/// </para>
/// <para>
/// So this is what <c>--json</c> prints, and it is a manifest rather than a report: everything the
/// run wrote is named here, and the things a caller decides on — did it work, what came out, is
/// there anything left worth declaring — are here rather than distributed across four files. What it
/// deliberately leaves out is depth. The evidence, the changes and the full account of the
/// interpretation stay in the files this points at, because a caller that wants them knows it wants
/// them, and one that does not should not have to page past them.
/// </para>
/// </remarks>
/// <param name="Schema">
/// Which version of this shape the object is. Read it before anything else and refuse a major
/// version you were not written for.
/// </param>
/// <param name="Success">
/// Whether the run finished with something to stand behind. The same answer as the exit code, said
/// here so that a caller reading the object does not also have to have kept the code.
/// </param>
/// <param name="Strict">Whether the run refused rather than assuming anything about the host.</param>
/// <param name="Protections">What the file was found to be protected with, by the tool's names.</param>
/// <param name="Payloads">
/// What was hidden inside the file, each with the path it was written to.
/// </param>
/// <param name="Blockers">
/// What stopped the run, each carrying what to declare to get past it where a declaration would.
/// </param>
/// <param name="ContinuedPast">
/// How many calls a non-strict run walked past rather than stopping at. Named in full in the blocker
/// report; a count here, because it matters only when the result looks wrong.
/// </param>
/// <param name="MoreToDeclare">
/// Whether any stop has a remedy, which is to say whether running again with a fuller declarations
/// file could get further. False with stops still listed means the rest need a change to the tool,
/// and a caller looping on this one should stop.
/// </param>
public sealed record RunManifest(
    string Schema,
    string ToolVersion,
    bool Success,
    string InputPath,
    string InputSha256,
    long InputLength,
    bool Strict,
    IReadOnlyList<string> Protections,
    RunOutputs Wrote,
    IReadOnlyList<PayloadInfo> Payloads,
    RecoveryReportMetrics Recovery,
    int RebuiltMethods,
    DevirtualizationCheck RebuiltCheck,
    bool Verified,
    IReadOnlyList<string> VerificationDiagnostics,
    IReadOnlyList<PassResult> Passes,
    IReadOnlyList<Blocker> Blockers,
    int ContinuedPast,
    bool MoreToDeclare)
{
    /// <summary>
    /// The shape this object is in. The number goes up when something is removed or changes meaning,
    /// and not when something is added.
    /// </summary>
    public const string Current = "reactorunpack.run/1";

    /// <summary>Everything one run of the pipeline produced, as a manifest.</summary>
    public static RunManifest Of(PipelineResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        var report = result.Report;
        return new RunManifest(
            Current,
            report.ToolVersion,
            result.Success,
            report.InputPath,
            report.InputSha256,
            report.InputLength,
            report.Strict,
            [.. report.Evidence
                .Where(evidence => evidence.Category == "capability")
                .Select(evidence => evidence.Message)
                .Distinct(StringComparer.Ordinal)],
            new RunOutputs(
                result.OutputPath,
                result.AnalysisReportPath,
                result.ChangesReportPath,
                result.BlockerReportPath,
                result.RenameMapPath,
                result.VirtualProgramPaths),
            report.Payloads,
            report.Recovery,
            result.RebuiltMethods,
            result.DevirtualizationCheck,
            report.VerificationPassed,
            report.VerificationDiagnostics,
            report.Passes,
            report.Blockers ?? [],
            report.ContinuedPast?.Count ?? 0,
            report.Blockers?.Any(blocker => blocker.Remedy is not null) ?? false);
    }
}

/// <summary>Every file a run wrote, named rather than left to be worked out.</summary>
/// <param name="Cleaned">
/// The readable copy of the assembly, or null where the run had nothing it could stand behind.
/// </param>
/// <param name="Listings">
/// The programs behind virtualized methods, as text: two files per method, the operations as read
/// and the same thing as IL.
/// </param>
public sealed record RunOutputs(
    string? Cleaned,
    string Analysis,
    string Changes,
    string? Blockers,
    string? Renames,
    IReadOnlyList<string> Listings);

/// <summary>Why a run could not be attempted, in the same channel as the run itself.</summary>
/// <remarks>
/// A caller reading JSON on stdout should not have to switch to scraping stderr for the one case
/// where the tool was handed something it could not work with. The exit code still says what it said
/// before.
/// </remarks>
public sealed record RunFailure(string Error)
{
    /// <summary>The shape this object is in.</summary>
    public const string Current = "reactorunpack.error/1";

    public string Schema { get; init; } = Current;
}
