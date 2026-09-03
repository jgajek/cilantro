using Cilantro.Core;
using dnlib.DotNet;

namespace Cilantro.Tests;

/// <summary>
/// Covers the file a run writes about itself while it runs.
/// </summary>
/// <remarks>
/// The reason this exists at all is that the pipeline takes minutes and used to have no way of saying
/// anything until it returned, so a caller with a shorter timeout than the run learned nothing and
/// threw away work that was finished. These tests are therefore about the two properties that make the
/// file worth having: something is written before the run ends, and something terminal is written
/// however the run ends. A file that only appeared on success would be no better than the return value
/// it was meant to replace.
/// </remarks>
public sealed class RunStatusTests
{
    /// <summary>
    /// The status lands with the reports, under the sample's stem, and the pipeline works the location
    /// out the same way a caller does. Two copies of that convention would eventually disagree, and the
    /// caller would poll a path nothing was writing to.
    /// </summary>
    [Fact]
    public void TheStatusIsNamedTheSameWayByTheCallerAndTheRun()
    {
        Assert.Equal(
            Path.Combine("/reports", "sample.status.json"),
            RunStatus.PathFor("/samples/sample.exe", "/reports"));
        // Told nowhere, a run puts its reports in a folder beside the input, and this goes with them.
        Assert.Equal(
            Path.Combine("/samples", "cilantro", "sample.status.json"),
            RunStatus.PathFor("/samples/sample.exe", null));
    }

    /// <summary>
    /// When the default report folder name is already a file beside the sample, the reports go
    /// somewhere else rather than failing to create a directory over that file.
    /// </summary>
    /// <remarks>
    /// The published Linux binary is itself named <c>cilantro</c>. Unpacking the release and running
    /// a sample from the same directory used to fail immediately with "The file .../cilantro already
    /// exists", which is .NET refusing to create a directory on top of the binary. The fallback is
    /// only for the default: an explicit report directory that happens to be a file is still the
    /// caller's mistake.
    /// </remarks>
    [Fact]
    public void ReportsGoBesideTheBinaryWhenItsNameIsTheDefaultFolder()
    {
        var directory = Directory.CreateTempSubdirectory("cilantro-beside-binary");
        try
        {
            var binary = Path.Combine(directory.FullName, RunStatus.ReportsFolder);
            File.WriteAllBytes(binary, [0x7F, (byte)'E', (byte)'L', (byte)'F']);
            var sample = Synthetic(directory.FullName);

            var reports = RunStatus.DirectoryFor(sample, reportDirectory: null);

            Assert.Equal(
                Path.Combine(directory.FullName, RunStatus.ReportsFolderWhenTaken),
                reports);
            Assert.Equal(
                Path.Combine(reports, "plain.status.json"),
                RunStatus.PathFor(sample, reportDirectory: null));

            // And a real run lands there rather than dying on CreateDirectory.
            var result = new CilantroPipeline().Run(sample, new PipelineOptions(AnalyzeOnly: true));
            Assert.StartsWith(reports, result.AnalysisReportPath, StringComparison.Ordinal);
            Assert.True(File.Exists(result.AnalysisReportPath));
            Assert.True(File.Exists(binary), "the binary stand-in must be left alone");
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    /// <summary>
    /// A finished run says so, and carries the manifest, so that a caller polling this file never
    /// has to go and read a second one to find out what came of it.
    /// </summary>
    [Fact]
    public void AFinishedRunLeavesItsWholeManifestInTheStatus()
    {
        var directory = Directory.CreateTempSubdirectory("cilantro-status");
        try
        {
            var sample = Synthetic(directory.FullName);
            var statusPath = RunStatus.PathFor(sample, directory.FullName);

            var result = new CilantroPipeline().Run(sample, new PipelineOptions(
                AnalyzeOnly: true,
                ReportDirectory: directory.FullName,
                StatusPath: statusPath));

            var status = RunStatus.Read(statusPath);
            Assert.NotNull(status);
            Assert.Equal(RunStatus.Current, status.Schema);
            Assert.Equal(RunPhase.Finished, status.Phase);
            Assert.True(status.Ended);
            Assert.Null(status.Error);
            // The count reaches the total rather than stopping one short of it, which is what a caller
            // showing a fraction would otherwise display forever.
            Assert.Equal(status.PassesTotal, status.PassesDone);
            Assert.True(status.PassesTotal > 0);
            Assert.Equal(Environment.ProcessId, status.ProcessId);
            Assert.NotNull(status.Result);
            Assert.Equal(result.Report.InputSha256, status.Result.InputSha256);
            Assert.Equal(result.AnalysisReportPath, status.Result.Wrote.Analysis);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    /// <summary>
    /// Asked to stop, a run stops, says it was stopped, and does not hand back a result.
    /// </summary>
    /// <remarks>
    /// The refusal to return a partial result is the point. A <see cref="PipelineResult"/> is a claim
    /// about an assembly, and half a pipeline has no claim to make: a caller handed one would take the
    /// absence of findings for a finding. What the run had already written to disk is a different
    /// matter and stays where it is.
    /// </remarks>
    [Fact]
    public void ARunAskedToStopStopsAndSaysThatIsWhyItEnded()
    {
        var directory = Directory.CreateTempSubdirectory("cilantro-status");
        try
        {
            var sample = Synthetic(directory.FullName);
            var statusPath = RunStatus.PathFor(sample, directory.FullName);
            using var stopping = new CancellationTokenSource();
            stopping.Cancel();

            Assert.Throws<OperationCanceledException>(() =>
                new CilantroPipeline().Run(sample, new PipelineOptions(
                    AnalyzeOnly: true,
                    ReportDirectory: directory.FullName,
                    StatusPath: statusPath,
                    Cancellation: stopping.Token)));

            var status = RunStatus.Read(statusPath);
            Assert.NotNull(status);
            Assert.Equal(RunPhase.Cancelled, status.Phase);
            Assert.True(status.Ended);
            Assert.Null(status.Result);
            Assert.Contains("cancelled", status.Error!, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    /// <summary>
    /// A run nobody asked to report on writes no status file.
    /// </summary>
    /// <remarks>
    /// Which is not tidiness. The file carries a clock and a process id, so a run that wrote one
    /// unconditionally would stop producing the same bytes twice, and producing the same bytes twice is
    /// what <see cref="CorpusTests.CorpusOutcomesAreDeterministic"/> exists to check.
    /// </remarks>
    [Fact]
    public void ARunNobodyIsWatchingWritesNoStatusAtAll()
    {
        var directory = Directory.CreateTempSubdirectory("cilantro-status");
        try
        {
            var sample = Synthetic(directory.FullName);

            new CilantroPipeline().Run(sample, new PipelineOptions(
                AnalyzeOnly: true,
                ReportDirectory: directory.FullName));

            Assert.False(File.Exists(RunStatus.PathFor(sample, directory.FullName)));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    /// <summary>Reading where nothing has been written is an absence, not a failure.</summary>
    [Fact]
    public void ReadingAStatusThatIsNotThereIsNotAnError() =>
        Assert.Null(RunStatus.Read("/nonexistent/sample.status.json"));

    /// <summary>
    /// The smallest thing the pipeline will accept: a real assembly with nothing in it, so that these
    /// tests measure the reporting rather than the recovery.
    /// </summary>
    private static string Synthetic(string directory)
    {
        var module = new ModuleDefUser("plain.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser("plain", new Version(1, 0));
        assembly.Modules.Add(module);
        var path = Path.Combine(directory, "plain.dll");
        module.Write(path);
        return path;
    }
}
