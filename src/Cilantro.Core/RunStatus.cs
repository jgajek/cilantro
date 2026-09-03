using System.Diagnostics;
using System.Text.Json;

namespace Cilantro.Core;

/// <summary>How far along a run is, as one of the few answers a watcher acts on differently.</summary>
/// <remarks>
/// Deliberately coarse. A watcher does one of three things — keep waiting, read the manifest, or give
/// up — and a phase set finer than that would invite callers to branch on distinctions the tool does
/// not promise to keep.
/// </remarks>
public enum RunPhase
{
    /// <summary>The run exists and has not yet reached its first pass.</summary>
    Starting,

    /// <summary>A pass is running. The only phase in which the pass name means anything.</summary>
    Running,

    /// <summary>The run finished and the manifest is here.</summary>
    Finished,

    /// <summary>The run threw. What it threw is in the error.</summary>
    Failed,

    /// <summary>The run was asked to stop and did.</summary>
    Cancelled
}

/// <summary>
/// Where a run has got to, written to disk while it runs so that something other than the caller
/// holding the call can find out.
/// </summary>
/// <remarks>
/// <para>
/// A run on a protected assembly of any size takes minutes, and the tool's only way of reporting that
/// until now was to return. Any caller with a timeout shorter than the run therefore learned nothing:
/// not that it had nearly finished, not which pass it was in, and not — the expensive part — that the
/// payloads had already been written and were sitting on disk. Killing the call threw away work that
/// was complete.
/// </para>
/// <para>
/// So the run says where it is in a file rather than only in its return value. The file is the
/// contract: whoever wants to know reads it, and does not need to be the process that started the run,
/// or to have been running when it started, or to still be running when it ends. That is what makes a
/// status check cheap enough to poll and what lets a run outlive the thing that asked for it.
/// </para>
/// <para>
/// It lands beside the reports, under the sample's stem, for the same reason they do: a directory of
/// samples can share one report folder without two runs colliding.
/// </para>
/// </remarks>
/// <param name="Schema">
/// Which version of this shape the object is. Read it before anything else and refuse a major version
/// you were not written for.
/// </param>
/// <param name="Phase">What the run is doing, and the first thing to branch on.</param>
/// <param name="Pass">
/// The pass now running, or null where the run is not in one. A name, not a number, because the pass
/// list is not a stable numbering and a caller showing progress should show what the tool is doing.
/// </param>
/// <param name="PassesDone">
/// How many passes have been decided — run, skipped or refused. Skipped passes count, because a
/// caller watching this wants a fraction that advances, not one that stalls on passes the plan left
/// out.
/// </param>
/// <param name="PassesTotal">How many passes the plan has, known before the first one starts.</param>
/// <param name="ObservedUtc">
/// When the run last said anything. The field that separates a slow run from a dead one: a process
/// killed mid-pass leaves its last phase behind forever, and only the staleness of this gives it
/// away.
/// </param>
/// <param name="ProcessId">
/// Which process is doing the work, so that a watcher which finds a stale heartbeat can confirm what
/// it suspects rather than guess.
/// </param>
/// <param name="Result">
/// The full manifest, once there is one. Present exactly when the phase is <see cref="RunPhase.Finished"/>,
/// so that a caller polling this file never has to go and read a second one.
/// </param>
/// <param name="Error">Why the run stopped, where it stopped for a reason worth stating.</param>
public sealed record RunStatus(
    string Schema,
    string ToolVersion,
    RunPhase Phase,
    string InputPath,
    string? Pass,
    int PassesDone,
    int PassesTotal,
    DateTimeOffset StartedUtc,
    DateTimeOffset ObservedUtc,
    int ProcessId,
    double ElapsedSeconds,
    RunManifest? Result,
    string? Error)
{
    /// <summary>
    /// The shape this object is in. The number goes up when something is removed or changes meaning,
    /// and not when something is added.
    /// </summary>
    public const string Current = "cilantro.status/1";

    /// <summary>The name of the file, under the sample's stem.</summary>
    public const string Suffix = ".status.json";

    /// <summary>
    /// Whether the run is over, whatever the outcome. The one question a polling loop asks every time
    /// round, said here so that three phases do not have to be enumerated at every call site.
    /// </summary>
    public bool Ended => Phase is RunPhase.Finished or RunPhase.Failed or RunPhase.Cancelled;

    /// <summary>
    /// The folder a run puts its reports in when nobody said otherwise, beside the input.
    /// </summary>
    public const string ReportsFolder = "cilantro";

    /// <summary>
    /// What that folder is called when <see cref="ReportsFolder"/> is already a file where the
    /// sample sits — which is what happens when someone unpacks the tool next to the sample and
    /// the binary is itself named <c>cilantro</c>.
    /// </summary>
    public const string ReportsFolderWhenTaken = "cilantro.out";

    /// <summary>
    /// Where a run on this input with these options puts the things it writes.
    /// </summary>
    /// <remarks>
    /// The pipeline resolves the same folder from the same two arguments, and calls this to do it, so
    /// that a caller can work out where a run's output will be before starting it. Two copies of this
    /// convention would eventually name two different directories.
    ///
    /// The default is a folder named <see cref="ReportsFolder"/> beside the input. When that name
    /// is already taken by a file — the usual case being the tool's own binary, which is published
    /// as <c>cilantro</c> — the folder is <see cref="ReportsFolderWhenTaken"/> instead. Creating a
    /// directory over a file is what .NET refuses with "already exists", and the refusal used to be
    /// the first thing a Linux user saw when they ran the tool on a sample in the same directory
    /// they unpacked it into. An explicit report directory is left alone: the caller named it.
    /// </remarks>
    public static string DirectoryFor(string inputPath, string? reportDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(inputPath);
        if (reportDirectory is not null)
            return Path.GetFullPath(reportDirectory);

        var beside = Path.GetDirectoryName(Path.GetFullPath(inputPath))!;
        var preferred = Path.Combine(beside, ReportsFolder);
        return Path.GetFullPath(
            File.Exists(preferred)
                ? Path.Combine(beside, ReportsFolderWhenTaken)
                : preferred);
    }

    /// <summary>Where a run on this input with these options writes its status.</summary>
    public static string PathFor(string inputPath, string? reportDirectory) =>
        Path.Combine(
            DirectoryFor(inputPath, reportDirectory),
            Path.GetFileNameWithoutExtension(inputPath) + Suffix);

    /// <summary>
    /// Reads a status file, or returns null where no run has written one there.
    /// </summary>
    /// <remarks>
    /// A reader and a writer race by construction here, and the writer replaces the file rather than
    /// rewriting it in place so that the loser of that race sees the previous status rather than half
    /// of the next one. The retry covers the one window that replacement leaves open, which is the
    /// moment between the old file going and the new one arriving.
    /// </remarks>
    public static RunStatus? Read(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                return File.Exists(path)
                    ? JsonSerializer.Deserialize<RunStatus>(
                        File.ReadAllText(path),
                        CilantroPipeline.ReportJsonOptions)
                    : null;
            }
            catch (Exception exception) when (
                attempt < 3 && exception is IOException or JsonException)
            {
                Thread.Sleep(20);
            }
        }
    }
}

/// <summary>
/// Keeps a run's <see cref="RunStatus"/> file current for as long as the run lasts.
/// </summary>
/// <remarks>
/// <para>
/// Two things write here and they answer different questions. The run itself writes when it enters a
/// pass, which is what tells a watcher how far along it is. A timer writes on its own every few
/// seconds, which is what tells a watcher the run is still alive — and it has to be a timer, because
/// the pipeline's slowest single pass takes minutes and a heartbeat that only beat at pass boundaries
/// would be indistinguishable from a hang for exactly as long as the pass took.
/// </para>
/// <para>
/// The last write wins and there is only ever one of it: once a terminal phase is recorded the timer
/// is stopped and further writes are refused, so a heartbeat that was already in flight cannot land
/// on top of the finished manifest and reopen a run that is over.
/// </para>
/// </remarks>
internal sealed class RunStatusWriter : IDisposable
{
    private static readonly TimeSpan HeartbeatInterval = TimeSpan.FromSeconds(5);

    private readonly string _path;
    private readonly string _stagingPath;
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private readonly object _gate = new();
    private readonly Timer _heartbeat;
    private RunStatus _status;
    private bool _ended;

    private RunStatusWriter(string path, RunStatus status)
    {
        _path = path;
        // Beside the file it replaces, because a rename is only atomic within one volume and a
        // temporary directory is not guaranteed to be on the same one.
        _stagingPath = path + ".tmp";
        _status = status;
        _heartbeat = new Timer(
            _ => Beat(),
            null,
            HeartbeatInterval,
            HeartbeatInterval);
    }

    /// <summary>Declares a run started and writes its first status.</summary>
    public static RunStatusWriter Begin(string path, string inputPath, int passesTotal)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        var now = DateTimeOffset.UtcNow;
        var writer = new RunStatusWriter(path, new RunStatus(
            RunStatus.Current,
            CilantroPipeline.Version,
            RunPhase.Starting,
            Path.GetFullPath(inputPath),
            null,
            0,
            passesTotal,
            now,
            now,
            Environment.ProcessId,
            0,
            null,
            null));
        writer.Flush();
        return writer;
    }

    /// <summary>Records that the run is about to run a pass, with the passes decided so far.</summary>
    public void Entering(string pass, int passesDone) => Update(status => status with
    {
        Phase = RunPhase.Running,
        Pass = pass,
        PassesDone = passesDone
    });

    /// <summary>Records the run as finished, with the manifest a watcher was waiting for.</summary>
    public void Finished(RunManifest manifest) => Update(status => status with
    {
        Phase = RunPhase.Finished,
        Pass = null,
        PassesDone = status.PassesTotal,
        Result = manifest
    });

    /// <summary>Records the run as having thrown, naming what it threw.</summary>
    public void Failed(string error) => Update(status => status with
    {
        Phase = RunPhase.Failed,
        Error = error
    });

    /// <summary>Records the run as stopped on request, naming the pass it stopped in.</summary>
    public void Cancelled() => Update(status => status with
    {
        Phase = RunPhase.Cancelled,
        Error = status.Pass is { } pass
            ? $"The run was cancelled during {pass}."
            : "The run was cancelled."
    });

    public void Dispose()
    {
        // A run that reached neither a manifest nor a throw has been killed from outside, and the
        // heartbeat is what will say so. Nothing is written here, because there is nothing true to
        // write: claiming a phase on the way out would turn a killed run into one that reported.
        _heartbeat.Dispose();
    }

    private void Beat()
    {
        lock (_gate)
        {
            if (_ended)
            {
                return;
            }

            Flush();
        }
    }

    private void Update(Func<RunStatus, RunStatus> change)
    {
        lock (_gate)
        {
            if (_ended)
            {
                return;
            }

            _status = change(_status);
            if (_status.Ended)
            {
                // Stopped before the write rather than after, so that the terminal status is the last
                // thing to reach the file.
                _ended = true;
                _heartbeat.Change(Timeout.Infinite, Timeout.Infinite);
            }

            Flush();
        }
    }

    /// <summary>
    /// Replaces the file with the current status, stamped with the time and elapsed seconds.
    /// </summary>
    /// <remarks>
    /// Staged and renamed rather than written in place: a reader polling this file at any moment must
    /// see one whole status or the previous one, never a truncated object. A failure to write is
    /// swallowed because the run is the point and the report of it is not — a full disk should not
    /// lose an analysis that otherwise succeeded.
    /// </remarks>
    private void Flush()
    {
        _status = _status with
        {
            ObservedUtc = DateTimeOffset.UtcNow,
            ElapsedSeconds = Math.Round(_clock.Elapsed.TotalSeconds, 3)
        };
        try
        {
            File.WriteAllText(
                _stagingPath,
                JsonSerializer.Serialize(_status, CilantroPipeline.ReportJsonOptions));
            File.Move(_stagingPath, _path, overwrite: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }
}
