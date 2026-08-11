using ReactorUnpack.Core;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Codec;
using ReactorUnpack.Core.Corpus;

namespace ReactorUnpack.Tests;

public sealed class CorpusTests
{
    [Fact]
    public void ManifestDefinesUniqueHashVerifiedTiers()
    {
        var root = FindRepositoryRoot();
        var manifest = CorpusRunner.LoadManifest(
            Path.Combine(root, "corpus", "reactor-6-nonvirt.manifest.json"));

        Assert.Equal(1, manifest.ManifestVersion);
        Assert.Equal(9, manifest.Samples.Count);
        Assert.Equal(manifest.Samples.Count,
            manifest.Samples.Select(sample => sample.Sha256).Distinct().Count());
        Assert.Contains(manifest.Samples, sample => sample.Tier == "profiled");
        Assert.Contains(manifest.Samples, sample => sample.Tier == "detected");
        Assert.Contains(manifest.Samples, sample => sample.Tier == "negative");
        Assert.Contains(manifest.Samples, sample => sample.Tier == "exploratory");
        Assert.All(manifest.Samples,
            sample => Assert.Matches("^[a-f0-9]{64}$", sample.Sha256));
    }

    [Fact]
    public void StructuralDiscoveryDerivesQbjuefProxyCodec()
    {
        using var context = ArtifactContext.Load(FindSample("Qbjuef.exe"));
        var facts = ReactorStructureDetector.Analyze(context.Module);

        Assert.True(facts.IsReactor6);
        Assert.Equal("reactor6-delegate-runtime", facts.Generation);
        Assert.Contains("delegate-proxy", facts.CapabilityNames);
        Assert.True(StructuralStreamDiscovery.TryDiscoverProxyProfile(
            context.Module,
            facts,
            out var profile));
        Assert.NotNull(profile);
        Assert.Equal(0x64875CD0u, profile.A);
        Assert.Equal(0x7511923Au, profile.D);
        Assert.Equal(146, profile.Bindings.Count);
    }

    [Fact]
    public void MethodProtectedGenerationIsDetectedAndFullyRecovered()
    {
        var sample = FindSample("Reason.PAC.dll");
        var outputDirectory = Path.Combine(
            Path.GetTempPath(),
            $"ReactorUnpack.CorpusTests.{Guid.NewGuid():N}");
        try
        {
            var result = new ReactorPipeline().Run(sample, new PipelineOptions(
                AnalyzeOnly: true,
                ReportDirectory: outputDirectory));

            Assert.True(result.Success);
            Assert.Null(result.OutputPath);
            var protection = Assert.Single(
                result.Report.Passes,
                pass => pass.Pass == "method-protection");
            Assert.Equal(PassStatus.Success, protection.Status);
            var recovery = Assert.Single(
                result.Report.Passes,
                pass => pass.Pass == "method-body-recovery");
            Assert.Equal(PassStatus.Success, recovery.Status);
            Assert.Equal(312, result.Report.Recovery.RestoredMethodBodies);
            Assert.Equal(0, result.Report.Recovery.RemainingMethodStubs);
            Assert.Contains(result.Report.Evidence,
                evidence => evidence.Category == "method-encryption");
        }
        finally
        {
            Directory.Delete(outputDirectory, true);
        }
    }

    [Fact]
    public void CorpusOutcomesAreDeterministic()
    {
        var root = FindRepositoryRoot();
        var first = Path.Combine(Path.GetTempPath(), $"reactor-corpus-{Guid.NewGuid():N}");
        var second = Path.Combine(Path.GetTempPath(), $"reactor-corpus-{Guid.NewGuid():N}");
        try
        {
            var manifest = Path.Combine(root, "corpus", "reactor-6-nonvirt.manifest.json");
            var samples = Path.Combine(root, "samples");
            var firstReport = CorpusRunner.Run(manifest, samples, first);
            var secondReport = CorpusRunner.Run(manifest, samples, second);

            Assert.Equal(9, firstReport.Passed);
            Assert.Equal(0, firstReport.Failed);
            Assert.Equal(0, firstReport.Missing);

            // Recovery must never delete a member whose name the protector left intact; that is
            // program surface, not scaffolding. Surplus over the oracle is allowed to remain and is
            // bounded by the manifest ratchet instead.
            foreach (var outcome in firstReport.Samples.Where(sample => sample.Oracle is not null))
            {
                Assert.True(
                    outcome.Oracle!.PreservedNamesIntact,
                    $"{outcome.Id} lost preserved-name members: " +
                    string.Join(", ", outcome.Oracle.MissingPreservedNameMembers));
            }

            Assert.Equal(
                File.ReadAllBytes(Path.Combine(first, "corpus.outcomes.json")),
                File.ReadAllBytes(Path.Combine(second, "corpus.outcomes.json")));
        }
        finally
        {
            Directory.Delete(first, true);
            Directory.Delete(second, true);
        }
    }

    private static string FindSample(string filename) =>
        Path.Combine(FindRepositoryRoot(), "samples", filename);

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "ReactorUnpack.slnx")))
                return current.FullName;
            current = current.Parent;
        }

        throw new DirectoryNotFoundException("Repository root not found.");
    }
}
