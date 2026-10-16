using Cilantro.Core;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class PipelineProgressTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ProgressPrecedesWorkAndCompletesAfterArtifactsWithOrWithoutStatus(bool status)
    {
        var directory = Directory.CreateTempSubdirectory("cilantro-progress-");
        try
        {
            var sample = WritePlain(directory.FullName);
            var events = new List<PipelineProgress>();
            var pass = new ObservedPass("observed", () =>
            {
                Assert.Equal("observed", events[^1].Pass);
                Assert.Null(events[^1].Result);
            });
            var result = new CilantroPipeline([pass]).Run(sample, new PipelineOptions(
                ReportDirectory: directory.FullName,
                StatusPath: status ? RunStatus.PathFor(sample, directory.FullName) : null)
            {
                Progress = update =>
                {
                    if (update.Stage == PipelineStage.Finished)
                    {
                        Assert.True(File.Exists(Path.Combine(directory.FullName, "plain.report.html")));
                    }
                    events.Add(update);
                }
            });
            Assert.True(result.Success);
            Assert.Equal(PipelineStage.Loading, events[0].Stage);
            Assert.Equal(PipelineStage.Finished, events[^1].Stage);
            var completed = Assert.Single(events, e => e.Result is not null);
            Assert.False(completed.Skipped);
            Assert.Equal(1, completed.PassNumber);
            Assert.Equal(1, completed.PassesTotal);
            Assert.Equal(PassStatus.Success, completed.Result!.Status);
            Assert.Contains(events, e => e.Stage == PipelineStage.Emission);
            Assert.True(events.FindIndex(e => e.Stage == PipelineStage.Verification) <
                events.FindIndex(e => e.Stage == PipelineStage.Emission));
            Assert.True(File.Exists(result.OutputPath));
            if (status) Assert.Equal(RunPhase.Finished, RunStatus.Read(RunStatus.PathFor(sample, directory.FullName))!.Phase);
        }
        finally { directory.Delete(recursive: true); }
    }

    [Fact]
    public void FailedDependenciesAreSkippedAndNoEmissionIsAnnounced()
    {
        var directory = Directory.CreateTempSubdirectory("cilantro-progress-failure-");
        try
        {
            var events = new List<PipelineProgress>();
            var failed = new ObservedPass("failed", () => { }, PassStatus.Failed);
            var skipped = new ObservedPass("dependent", () => Assert.Fail("Skipped pass executed"),
                Dependencies: ["failed"]);
            var result = new CilantroPipeline([failed, skipped]).Run(WritePlain(directory.FullName),
                new PipelineOptions(ReportDirectory: directory.FullName) { Progress = events.Add });
            Assert.False(result.Success);
            Assert.Null(result.OutputPath);
            var outcomes = events.Where(e => e.Result is not null).ToArray();
            Assert.Equal(PassStatus.Failed, outcomes[0].Result!.Status);
            Assert.True(outcomes[1].Skipped);
            Assert.Equal(PassStatus.Unsupported, outcomes[1].Result!.Status);
            Assert.DoesNotContain(events, e => e.Stage == PipelineStage.Emission);
            Assert.Equal(PipelineStage.Finished, events[^1].Stage);
        }
        finally { directory.Delete(recursive: true); }
    }

    internal static string WritePlain(string directory)
    {
        using var module = new ModuleDefUser("plain.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser("plain", new Version(1, 0));
        assembly.Modules.Add(module);
        var path = Path.Combine(directory, "plain.dll");
        module.Write(path);
        return path;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void EmbeddedChildrenKeepTheObserverAndRestartTheirPassCounts(bool analyzeOnly)
    {
        var directory = Directory.CreateTempSubdirectory("cilantro-child-progress-");
        try
        {
            var child = WritePlain(directory.FullName);
            var parent = Path.Combine(directory.FullName, "parent.dll");
            using (var module = ModuleDefMD.Load(child))
            {
                module.Name = "parent.dll";
                module.Assembly.Name = "parent";
                module.Resources.Add(new EmbeddedResource("costura.plain.dll",
                    File.ReadAllBytes(child), ManifestResourceAttributes.Private));
                module.Write(parent);
            }
            var events = new List<PipelineProgress>();
            var result = new CilantroPipeline().Run(parent, new PipelineOptions(
                AnalyzeOnly: analyzeOnly, GenericRecovery: true, RecoverEmbeddedAssemblies: true,
                ReportDirectory: Path.Combine(directory.FullName, "reports")) { Progress = events.Add });
            Assert.True(result.Success);
            var recovered = Assert.Single(result.EmbeddedRecovery!.Nodes, n => n.Depth == 1);
            var loading = Assert.Single(events, e => e.InputPath == recovered.InputPath && e.Stage == PipelineStage.Loading);
            Assert.NotNull(loading);
            var first = events.First(e => e.InputPath == recovered.InputPath && e.Pass is not null);
            Assert.Equal(1, first.PassNumber);
            Assert.Null(first.Result);
            Assert.Contains(events, e => e.InputPath == parent && e.Stage == PipelineStage.EmbeddedRecovery);
            Assert.Equal(parent, events[^1].InputPath);
            Assert.Equal(PipelineStage.Finished, events[^1].Stage);
            if (analyzeOnly) Assert.DoesNotContain(events, e => e.Stage == PipelineStage.Emission);
            else Assert.Contains(events, e => e.InputPath == recovered.InputPath && e.Stage == PipelineStage.Emission);
        }
        finally { directory.Delete(recursive: true); }
    }

    private sealed record ObservedPass(string Name, Action Observe, PassStatus Status = PassStatus.Success,
        IReadOnlyCollection<string>? Dependencies = null) : IDeobfuscationPass
    {
        IReadOnlyCollection<string> IDeobfuscationPass.Dependencies => Dependencies ?? [];
        public bool GatesEmission => true;
        public PassResult Run(ArtifactContext context)
        {
            Observe();
            return new(Name, Status, 0, [], TimeSpan.Zero);
        }
    }
}
