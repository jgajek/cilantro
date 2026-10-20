using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Corpus;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class BabelHardeningCorpusTests
{
    private static string Manifest => Path.Combine(Checkout.Root, "corpus", "babel-12-hardening.manifest.json");

    [Fact]
    public void ManifestPinsMetadataAndCompleteControlFlowConfigurations()
    {
        var samples = CorpusRunner.LoadManifest(Manifest).Samples;
        Assert.Equal(12, samples.Count);
        Assert.Equal(3, samples.Count(s => s.Tier == "oracle"));
        foreach (var framework in new[] { "net48", "net8.0", "net10.0" })
        {
            var cases = samples.Where(s => s.Tier == "profiled" && s.Id.StartsWith(framework + "-", StringComparison.Ordinal)).ToArray();
            Assert.Equal(3, cases.Length);
            Assert.All(cases, sample =>
            {
                Assert.True(sample.RequireOracleResourceParity);
                Assert.Equal(0, sample.MaximumSurplusResources);
                Assert.Equal(0, sample.MaximumRemainingSwitchDispatchers);
                Assert.Equal(0, sample.MaximumUnreachableInstructions);
            });
            var combined = Assert.Single(cases, s => s.Id.EndsWith("metadata-combined", StringComparison.Ordinal));
            Assert.Equal(8, combined.MinimumRecoveredStringSites);
            Assert.Equal(1, combined.MinimumResourcesRestored);
        }
    }

    [Babel12CorpusFact]
    [Trait(Cost.Key, Cost.High)]
    public void DuplicateRowsAndHeapsNormalizeAlongsideStringResourceAndFlowRecovery()
    {
        var root = Environment.GetEnvironmentVariable("CILANTRO_BABEL12_SAMPLES")!;
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelHardening.").FullName;
        try
        {
            var outcome = CorpusRunner.Run(Manifest, root, directory);
            Assert.True(outcome.Passed == 9 && outcome.Failed == 0 && outcome.Missing == 0,
                JsonSerializer.Serialize(outcome.Samples.Where(s => s.Status != "passed"), CilantroPipeline.ReportJsonOptions));
            foreach (var sample in CorpusRunner.LoadManifest(Manifest).Samples.Where(s => s.Tier == "profiled"))
            {
                var input = Path.Combine(root, sample.LocalName);
                var cleaned = Path.Combine(directory, sample.Id, "cleaned.bin");
                if (sample.Id.Contains("-metadata", StringComparison.Ordinal))
                {
                    var before = RawMetadataPreflight.Analyze(File.ReadAllBytes(input));
                    var after = RawMetadataPreflight.Analyze(File.ReadAllBytes(cleaned));
                    Assert.Equal(2u, before.ModuleRows); Assert.Equal(2u, before.AssemblyRows);
                    Assert.Contains(before.Streams.GroupBy(s => s.Name), group => group.Count() > 1);
                    Assert.Equal(1u, after.ModuleRows); Assert.Equal(1u, after.AssemblyRows);
                    Assert.All(after.Streams.GroupBy(s => s.Name), group => Assert.Single(group));
                    using var source = ModuleDefMD.Load(input);
                    using var output = ModuleDefMD.Load(cleaned);
                    const string marker = "System.Runtime.CompilerServices.SuppressIldasmAttribute";
                    Assert.Contains(source.CustomAttributes.Concat(source.Assembly.CustomAttributes), a => a.TypeFullName == marker);
                    Assert.DoesNotContain(output.CustomAttributes.Concat(output.Assembly.CustomAttributes), a => a.TypeFullName == marker);
                    var result = Assert.Single(outcome.Samples, s => s.Id == sample.Id);
                    Assert.Equal(1, Assert.Single(result.Passes, p => p.Pass == "anti-disassembly-metadata").Changes);
                }
                if (sample.Id.StartsWith("net48-", StringComparison.Ordinal))
                {
                    var reference = input;
                    if (sample.Id.Contains("-metadata", StringComparison.Ordinal))
                    {
                        // Babel's compressed stream intentionally contains tables rejected by
                        // Microsoft's reader. Compare the repaired image with the source oracle.
                        Assert.Throws<BadImageFormatException>(() => IlVerification.Read(input));
                        reference = Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(input))!, "oracle", Path.GetFileName(input));
                    }
                    var difference = IlVerification.Against(IlVerification.Read(reference), IlVerification.Read(cleaned));
                    Assert.Empty(difference.Broken.Except(difference.Was.Unreadable));
                    Assert.Empty(difference.Worsened);
                    Assert.Empty(difference.Is.Unreadable);
                }
            }
        }
        finally { Directory.Delete(directory, true); }
    }
}
