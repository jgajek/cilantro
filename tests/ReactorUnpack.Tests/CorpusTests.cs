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
        var manifest = CorpusRunner.LoadManifest(
            Path.Combine(Checkout.Root, "corpus", "reactor-6-nonvirt.manifest.json"));

        Assert.Equal(1, manifest.ManifestVersion);
        Assert.Equal(11, manifest.Samples.Count);
        Assert.Equal(manifest.Samples.Count,
            manifest.Samples.Select(sample => sample.Sha256).Distinct().Count());
        Assert.Contains(manifest.Samples, sample => sample.Tier == "profiled");
        Assert.Contains(manifest.Samples, sample => sample.Tier == "detected");
        Assert.Contains(manifest.Samples, sample => sample.Tier == "negative");
        Assert.Contains(manifest.Samples, sample => sample.Tier == "exploratory");
        Assert.All(manifest.Samples,
            sample => Assert.Matches("^[a-f0-9]{64}$", sample.Sha256));
    }

    [SampleFact]
    public void StructuralDiscoveryDerivesQbjuefProxyCodec()
    {
        using var context = ArtifactContext.Load(Checkout.Sample("Qbjuef.exe"));
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

    [SampleFact]
    [Trait(Cost.Key, Cost.High)]
    public void MethodProtectedGenerationIsDetectedAndFullyRecovered()
    {
        var sample = Checkout.Sample("Reason.PAC.dll");
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

    [SampleFact]
    [Trait(Cost.Key, Cost.High)]
    public void CorpusOutcomesAreDeterministic()
    {
        var first = Path.Combine(Path.GetTempPath(), $"reactor-corpus-{Guid.NewGuid():N}");
        var second = Path.Combine(Path.GetTempPath(), $"reactor-corpus-{Guid.NewGuid():N}");
        try
        {
            var manifest = Path.Combine(Checkout.Root, "corpus", "reactor-6-nonvirt.manifest.json");
            var samples = Checkout.Samples;
            // The two runs go at once, which is the point rather than a shortcut. A run already
            // analyses several samples in parallel, so overlapping the pair leaves the two copies
            // of each sample interleaved differently against everything else in flight; agreeing
            // afterwards is then evidence that the outcome does not depend on what ran beside it.
            var directories = new[] { first, second };
            var reports = new CorpusRunReport[directories.Length];
            Parallel.For(
                0,
                directories.Length,
                index => reports[index] = CorpusRunner.Run(manifest, samples, directories[index]));

            var firstReport = reports[0];
            Assert.Equal(11, firstReport.Passed);
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

}
