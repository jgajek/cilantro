using System.Text.Json;
using System.Security.Cryptography;
using Cilantro.Core;
using Cilantro.Core.Corpus;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class DotfuscatorResourceTypesCorpusTests
{
    private static string ManifestPath => Path.Combine(Checkout.Root, "corpus", "dotfuscator-7-resource-types.manifest.json");

    [Fact]
    public void MixedResourceManifestRecordsProducerTypeLoss()
    {
        var samples = CorpusRunner.LoadManifest(ManifestPath).Samples;
        Assert.Equal(6, samples.Count);
        Assert.Equal(3, samples.Count(sample => sample.Tier == "oracle"));
        Assert.All(samples.Where(sample => sample.Tier != "oracle"), sample =>
        {
            Assert.False(sample.RequireOracleResourceParity);
            Assert.Equal(1, sample.MinimumResourcesRestored);
        });
    }

    [DotfuscatorResourceCorpusFact]
    [Trait(Cost.Key, Cost.High)]
    public void CapturedMixedResourcesRecoverInTheFullPipeline()
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.DotfuscatorResourceTypes.").FullName;
        try
        {
            var outcome = CorpusRunner.Run(ManifestPath, Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_RESOURCE_SAMPLES")!, directory);
            Assert.True(outcome.Passed == 3 && outcome.Failed == 0 && outcome.Missing == 0,
                JsonSerializer.Serialize(outcome, CilantroPipeline.ReportJsonOptions));
            foreach (var sample in outcome.Samples.Where(sample => sample.Tier != "oracle"))
            {
                Assert.Contains(sample.Passes, pass => pass.Pass == "dotfuscator-resources" && pass.Status == PassStatus.Success && pass.Changes == 8);
                using var module = ModuleDefMD.Load(Path.Combine(directory, sample.Id, "cleaned.bin"));
                var resource = Assert.Single(module.Resources.OfType<EmbeddedResource>());
                Assert.Equal("a646149cfb5ee8392faab180fa2dc982819cadcf0b8dc44d99e01678c5476d13",
                    Convert.ToHexStringLower(SHA256.HashData(resource.CreateReader().ToArray())));
            }
        }
        finally { Directory.Delete(directory, true); }
    }
}
