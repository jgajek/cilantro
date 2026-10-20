using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Corpus;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DotfuscatorCorpusTests
{
    [Fact]
    public void ManifestPinsAllFrameworksConfigurationsAndRecoveryExpectations()
    {
        var manifest = CorpusRunner.LoadManifest(Path.Combine(Checkout.Root, "corpus", "dotfuscator-7-static.manifest.json"));
        Assert.Equal(15, manifest.Samples.Count);
        Assert.Equal(3, manifest.Samples.Count(sample => sample.Tier == "oracle"));
        Assert.Equal(9, manifest.Samples.Count(sample => sample.MinimumRecoveredStringSites == 19));
        Assert.All(manifest.Samples.Where(sample => sample.Tier != "oracle"), sample =>
        {
            Assert.Equal("dotfuscator", sample.ExpectedDetection);
            Assert.Equal(0, sample.MaximumRemainingSwitchDispatchers);
            Assert.True(sample.RequireOracleResourceParity);
            Assert.Contains(manifest.Samples, oracle => oracle.Tier == "oracle" && oracle.Sha256 == sample.OracleSha256);
        });
    }

    [DotfuscatorCorpusFact]
    [Trait(Cost.Key, Cost.High)]
    public void CapturedCorpusRestoresStringsControlFlowAndResources()
    {
        var samples = Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_SAMPLES")!;
        var results = Directory.CreateTempSubdirectory("Cilantro.Dotfuscator.").FullName;
        try
        {
            var path = Path.Combine(Checkout.Root, "corpus", "dotfuscator-7-static.manifest.json");
            var manifest = CorpusRunner.LoadManifest(path);
            var outcome = CorpusRunner.Run(path, samples, results);
            Assert.True(outcome.Failed == 0 && outcome.Missing == 0 && outcome.Passed == 12,
                JsonSerializer.Serialize(new { outcome.Passed, outcome.Failed, outcome.Missing,
                    Problems = outcome.Samples.Where(sample => sample.Status != "passed").Select(sample => new { sample.Id, sample.Diagnostics }) }, CilantroPipeline.ReportJsonOptions));
            foreach (var sample in manifest.Samples.Where(sample => sample.Tier != "oracle"))
            {
                var output = Path.Combine(results, sample.Id, "cleaned.bin");
                var oracle = manifest.Samples.Single(candidate => candidate.Sha256 == sample.OracleSha256);
                using var original = ModuleDefMD.Load(Path.Combine(samples, oracle.LocalName));
                using var cleaned = ModuleDefMD.Load(output);
                var actualStrings = Literals(cleaned);
                Assert.Subset(actualStrings, Literals(original));
                if (!sample.Id.EndsWith("-strings", StringComparison.Ordinal))
                    Assert.Contains(outcome.Samples.Single(entry => entry.Id == sample.Id).Passes,
                        pass => pass.Pass == "dotfuscator-control-flow" && pass.Changes > 0);
                // This verifier helper resolves the .NET Framework reference set.
                // CoreCLR variants are checked structurally and by the benign runtime harness.
                if (sample.Id.StartsWith("net48-", StringComparison.Ordinal))
                {
                    var difference = IlVerification.Against(IlVerification.Read(Path.Combine(samples, sample.LocalName)), IlVerification.Read(output));
                    Assert.Empty(difference.Broken.Except(difference.Was.Unreadable));
                    Assert.True(difference.Worsened.Count == 0, sample.Id + ": " + difference.Describe());
                }
            }
        }
        finally { Directory.Delete(results, recursive: true); }
    }

    private static HashSet<string> Literals(ModuleDef module) => module.GetTypes().SelectMany(t => t.Methods)
        .Where(m => m.HasBody).SelectMany(m => m.Body.Instructions)
        .Where(i => i.OpCode.Code == Code.Ldstr).Select(i => (string)i.Operand).ToHashSet(StringComparer.Ordinal);
}

public sealed class DotfuscatorCorpusFactAttribute : FactAttribute
{
    public DotfuscatorCorpusFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_SAMPLES") is not { Length: > 0 })
            Skip = "Set CILANTRO_DOTFUSCATOR_SAMPLES to the pinned Dotfuscator corpus; see docs/corpus.md.";
    }
}
