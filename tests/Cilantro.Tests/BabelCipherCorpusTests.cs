using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Corpus;

namespace Cilantro.Tests;

public sealed class BabelCipherCorpusTests
{
    private static string Manifest => Path.Combine(Checkout.Root, "corpus", "babel-12-ciphers.manifest.json");

    [Fact]
    public void ManifestCoversEveryAdvertisedCipherOnEachFramework()
    {
        var samples = CorpusRunner.LoadManifest(Manifest).Samples;
        Assert.Equal(24, samples.Count);
        Assert.Equal(3, samples.Count(s => s.Tier == "oracle"));
        foreach (var framework in new[] { "net48", "net8.0", "net10.0" })
        foreach (var cipher in new[] { "aes", "aesmanaged", "des", "tripledes", "rijndael", "rc2", "xor" })
        {
            var sample = Assert.Single(samples, s => s.Id == framework + "-" + cipher);
            Assert.Equal(1, sample.ExpectedRestoredBodyCount);
            Assert.Equal(0, sample.MaximumRemainingStubs);
            Assert.Equal(0, sample.MaximumRemainingSwitchDispatchers);
            Assert.Equal(0, sample.MaximumUnreachableInstructions);
            Assert.Equal(0, sample.MaximumSurplusResources);
            Assert.True(sample.RequireOracleResourceParity);
            Assert.NotEmpty(sample.ExpectedRetiredResourceNames!);
        }
    }

    [Babel12CorpusFact]
    [Trait(Cost.Key, Cost.High)]
    public void CipherMethodImagesRecoverWithoutNewVerifierFindings()
    {
        var root = Environment.GetEnvironmentVariable("CILANTRO_BABEL12_SAMPLES")!;
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelCiphers.").FullName;
        try
        {
            var outcome = CorpusRunner.Run(Manifest, root, directory);
            Assert.True(outcome.Passed == 21 && outcome.Failed == 0 && outcome.Missing == 0,
                JsonSerializer.Serialize(outcome.Samples.Where(s => s.Status != "passed"), CilantroPipeline.ReportJsonOptions));
            foreach (var sample in CorpusRunner.LoadManifest(Manifest).Samples.Where(s => s.Tier == "profiled" && s.Id.StartsWith("net48-", StringComparison.Ordinal)))
            {
                var difference = IlVerification.Against(IlVerification.Read(Path.Combine(root, sample.LocalName)),
                    IlVerification.Read(Path.Combine(directory, sample.Id, "cleaned.bin")));
                Assert.Empty(difference.Broken.Except(difference.Was.Unreadable));
                Assert.Empty(difference.Worsened);
                Assert.Empty(difference.Is.Unreadable);
            }
        }
        finally { Directory.Delete(directory, true); }
    }
}
