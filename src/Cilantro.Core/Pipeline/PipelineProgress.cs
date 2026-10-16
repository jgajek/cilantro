namespace Cilantro.Core;

/// <summary>The work currently being performed on one input or recovered child.</summary>
public enum PipelineStage
{
    Loading,
    Unpacking,
    Recovery,
    Verification,
    Extraction,
    Emission,
    Reporting,
    EmbeddedRecovery,
    Finished
}

/// <summary>
/// Synchronous progress, independent of console output and the optional status file.
/// Pass numbers are local to InputPath; a completed or skipped pass includes its result.
/// </summary>
public sealed record PipelineProgress(
    string InputPath,
    PipelineStage Stage,
    string? Pass = null,
    int PassNumber = 0,
    int PassesTotal = 0,
    PassResult? Result = null,
    bool Skipped = false);
