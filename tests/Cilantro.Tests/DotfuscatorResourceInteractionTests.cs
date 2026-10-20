using System.Security.Cryptography;
using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Corpus;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class DotfuscatorResourceInteractionTests
{
    private static string ManifestPath => Path.Combine(Checkout.Root, "corpus", "dotfuscator-7-resource-interactions.manifest.json");
    private static string Samples => Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_RESOURCE_SAMPLES")!;
    private static readonly string[] Cultures = ["fr", "fr-CA"];

    [Fact]
    public void ManifestRequiresResourcesStringsAndCompleteControlFlowRecovery()
    {
        var samples = CorpusRunner.LoadManifest(ManifestPath).Samples;
        Assert.Equal(12, samples.Count);
        Assert.Equal(3, samples.Count(sample => sample.Tier == "oracle"));
        foreach (var sample in samples.Where(sample => sample.Tier != "oracle"))
        {
            Assert.Equal(3, sample.MinimumResourcesRestored);
            Assert.Equal(0, sample.MaximumRemainingSwitchDispatchers);
            Assert.Equal(0, sample.MaximumUnreachableInstructions);
            if (sample.Id.EndsWith("-flow", StringComparison.Ordinal)) Assert.True(sample.RequireOracleResourceParity);
            else
            {
                Assert.False(sample.RequireOracleResourceParity);
                Assert.Equal(sample.Id.EndsWith("-renamed-v1", StringComparison.Ordinal) ? 12 : 11, sample.MinimumRecoveredStringSites);
            }
        }
    }

    [DotfuscatorResourceCorpusFact]
    [Trait(Cost.Key, Cost.High)]
    public void CombinedCapturesRestoreEveryCultureAndRetireResourceAndNativeRuntimes()
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.ResourceInteractions.").FullName;
        try
        {
            var manifest = CorpusRunner.LoadManifest(ManifestPath);
            AssertCompanionPins(manifest);
            var outcome = CorpusRunner.Run(ManifestPath, Samples, directory);
            Assert.True(outcome.Passed == 9 && outcome.Failed == 0 && outcome.Missing == 0,
                JsonSerializer.Serialize(outcome, CilantroPipeline.ReportJsonOptions));
            foreach (var sample in manifest.Samples.Where(sample => sample.Tier != "oracle"))
            {
                var result = outcome.Samples.Single(result => result.Id == sample.Id);
                Assert.Contains(result.Passes, pass => pass.Pass == "dotfuscator-resources" && pass.Status == PassStatus.Success && pass.Changes == 15);
                var source = Path.Combine(Samples, sample.LocalName);
                var oracle = Path.Combine(Samples, manifest.Samples.Single(oracle => oracle.Sha256 == sample.OracleSha256).LocalName);
                var output = Path.Combine(directory, sample.Id, "cleaned.bin");
                using var original = ModuleDefMD.Load(oracle);
                using var cleaned = ModuleDefMD.Load(output);
                Assert.Equal(ResourceHashes(original), ResourceHashes(cleaned));
                Assert.DoesNotContain(cleaned.GetTypes(), type => type.Name.String is "CRManager" or "DRReader" or "NativeCPP");
                foreach (var culture in Cultures)
                {
                    using var sourceCulture = ModuleDefMD.Load(Path.Combine(Path.GetDirectoryName(oracle)!, culture, "SatelliteProbe.resources.dll"));
                    using var outputCulture = ModuleDefMD.Load(Path.Combine(directory, sample.Id, culture, "SatelliteProbe.resources.dll"));
                    Assert.Equal(ResourceHashes(sourceCulture), ResourceHashes(outputCulture));
                    Assert.Equal(sourceCulture.Assembly.FullName, outputCulture.Assembly.FullName);
                }
                Assert.Empty(Directory.EnumerateFiles(Path.Combine(directory, sample.Id), "Runtime.Extensions.*", SearchOption.AllDirectories));
                Assert.Empty(Directory.EnumerateFiles(Path.Combine(directory, sample.Id), "environment????????.bin", SearchOption.AllDirectories));
                if (!sample.Id.StartsWith("net48", StringComparison.Ordinal)) continue;
                var verification = IlVerification.Against(IlVerification.Read(source), IlVerification.Read(output));
                Assert.Empty(verification.Broken.Except(verification.Was.Unreadable));
                Assert.Empty(verification.Worsened);
            }
        }
        finally { Directory.Delete(directory, true); }
    }

    private static void AssertCompanionPins(CorpusManifest manifest)
    {
        using var provenance = JsonDocument.Parse(File.ReadAllText(Path.Combine(Checkout.Root, "corpus", "dotfuscator-7-resource-interactions.provenance.json")));
        foreach (var fixture in provenance.RootElement.GetProperty("fixtures").EnumerateArray())
        {
            var framework = fixture.GetProperty("Framework").GetString()!;
            var id = framework + "-" + fixture.GetProperty("Profile").GetString();
            var sample = manifest.Samples.Single(sample => sample.Id == id);
            var oracle = manifest.Samples.Single(sample => sample.Id == framework + "-resource-oracle");
            foreach (var companion in fixture.GetProperty("Companions").EnumerateArray())
            {
                var relative = companion.GetProperty("path").GetString()!;
                var root = Path.GetDirectoryName(Path.Combine(Samples, relative.StartsWith("oracle/", StringComparison.Ordinal) ? oracle.LocalName : sample.LocalName))!;
                var path = Path.Combine(root, relative[(relative.IndexOf('/') + 1)..]);
                Assert.Equal(companion.GetProperty("sha256").GetString(), Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path))));
            }
        }
    }

    private static string[] ResourceHashes(ModuleDef module) => module.Resources.OfType<EmbeddedResource>()
        .Select(resource => Convert.ToHexStringLower(SHA256.HashData(resource.CreateReader().ToArray()))).Order(StringComparer.Ordinal).ToArray();
}
