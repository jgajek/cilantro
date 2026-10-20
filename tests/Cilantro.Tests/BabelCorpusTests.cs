using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Corpus;

namespace Cilantro.Tests;

public sealed class BabelCorpusTests
{
    [Fact]
    public void BabelManifestPinsEveryIdentifiedAssemblyAndMeasuredRecovery()
    {
        var manifest = CorpusRunner.LoadManifest(Path.Combine(Checkout.Root, "corpus", "babel-static.manifest.json"));
        Assert.Equal(9, manifest.Samples.Count);
        Assert.All(manifest.Samples, sample =>
        {
            Assert.Equal(1.0, sample.MinimumStringSiteCoverage);
            Assert.True(sample.MinimumRecoveredStringSites > 0);
            Assert.NotEmpty(sample.ExpectedDecodedResourceSha256!);
            Assert.Contains("emitted-string-runtime", sample.ExpectedCapabilities);
            Assert.True(sample.MinimumNumericTableSites > 0 || sample.ExpectedMissingResourceNames is { Count: > 0 });
        });
        var zebekeadu = Assert.Single(manifest.Samples, sample => sample.LocalName == "Zebekeadu.dll");
        Assert.Equal("417032e561fe410a246fea4f580b7ae8de4a8cc5098a508931a78322916199dd", zebekeadu.Sha256);
        Assert.Equal(2, zebekeadu.ExpectedDecodedResourceSha256!.Count);
        var proxySample = Assert.Single(manifest.Samples, sample => sample.LocalName == "pin_mxi_decoded_stage.exe");
        Assert.Equal(1990, proxySample.MinimumProxyCallsRestored);
        Assert.Equal("YQLy", Assert.Single(proxySample.ExpectedMissingResourceNames!));
    }

    [BabelCorpusFact]
    [Trait(Cost.Key, Cost.High)]
    public void CapturedBabelCorpusRecoversAndIntroducesNoIlVerifierRegressions()
    {
        var samples = Environment.GetEnvironmentVariable("CILANTRO_BABEL_SAMPLES")!;
        var savedResults = Environment.GetEnvironmentVariable("CILANTRO_BABEL_RESULTS");
        var directory = savedResults is { Length: > 0 }
            ? Directory.CreateDirectory(savedResults).FullName
            : Directory.CreateTempSubdirectory("Cilantro.BabelCorpus.").FullName;
        try
        {
            var manifestPath = Path.Combine(Checkout.Root, "corpus", "babel-static.manifest.json");
            var manifest = CorpusRunner.LoadManifest(manifestPath);
            var outcome = CorpusRunner.Run(manifestPath, samples, directory);
            Assert.True(outcome.Failed == 0 && outcome.Missing == 0 && outcome.Passed == manifest.Samples.Count,
                JsonSerializer.Serialize(outcome, CilantroPipeline.ReportJsonOptions));
            foreach (var sample in manifest.Samples)
            {
                if (sample.Id == "pin-mxi-decoded-stage")
                {
                    Assert.Contains(outcome.Samples.Single(entry => entry.Id == sample.Id).Passes,
                        pass => pass.Pass == "babel-proxies" && pass.Diagnostics.Any(note => note.Contains("2353/2353 Babel proxy bindings")));
                    Assert.Contains(outcome.Samples.Single(entry => entry.Id == sample.Id).Passes,
                        pass => pass.Pass == "babel-proxies" && pass.Diagnostics.Any(note => note.Contains("Recovered 413 direct calls in accessible caller contexts")));
                }
                var original = Path.Combine(samples, sample.LocalName);
                var cleaned = Path.Combine(directory, sample.Id, "cleaned.bin");
                var difference = IlVerification.Against(IlVerification.Read(original), IlVerification.Read(cleaned));
                Assert.Empty(difference.Broken.Except(difference.Was.Unreadable));
                Assert.True(difference.Worsened.Count == 0, sample.Id + ": " + difference.Describe());
            }
        }
        finally { if (string.IsNullOrEmpty(savedResults)) Directory.Delete(directory, recursive: true); }
    }
}

public sealed class BabelCorpusFactAttribute : FactAttribute
{
    public BabelCorpusFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("CILANTRO_BABEL_SAMPLES") is not { Length: > 0 })
            Skip = "Set CILANTRO_BABEL_SAMPLES to the hash-pinned Babel corpus directory; see docs/corpus.md.";
    }
}
