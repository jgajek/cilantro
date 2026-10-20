using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Corpus;

namespace Cilantro.Tests;

public sealed class Babel12CorpusTests
{
    private static readonly string[] CoreClrRetiredResources = ["Jrog", "zSRe", "pYuyE", "hgqQK"];
    private static readonly string[] FrameworkRetiredResources = ["Olbx", "zdwc", "sEOy"];
    private static string Manifest => Path.Combine(Checkout.Root, "corpus", "babel-12-baseline.manifest.json");

    [Fact]
    public void TrialBaselinePinsAvailableFeaturesAndMeasuredPartialRecovery()
    {
        var manifest = CorpusRunner.LoadManifest(Manifest);
        Assert.Equal(30, manifest.Samples.Count);
        Assert.Equal(3, manifest.Samples.Count(sample => sample.Tier == "oracle"));
        Assert.Contains("Partial-recovery", manifest.Description);
        Assert.DoesNotContain(manifest.Samples, sample => sample.Id.Contains("strings-stream", StringComparison.Ordinal));
        foreach (var framework in new[] { "net48", "net8.0", "net10.0" })
        {
            var cases = manifest.Samples.Where(sample => sample.Tier != "oracle" && sample.Id.StartsWith(framework + "-", StringComparison.Ordinal)).ToArray();
            Assert.Equal(9, cases.Length);
            Assert.Equal(8, Assert.Single(cases, sample => sample.Id.EndsWith("strings-xor", StringComparison.Ordinal)).MinimumRecoveredStringSites);
            Assert.Equal(28, Assert.Single(cases, sample => sample.Id.EndsWith("values", StringComparison.Ordinal)).MinimumNumericTableSites);
            var values = Assert.Single(cases, sample => sample.Id.EndsWith("values", StringComparison.Ordinal));
            Assert.Equal(1, values.MinimumRecoveredNumericArrays); Assert.Equal(0, values.MaximumSurplusResources); Assert.True(values.RequireOracleResourceParity);
            Assert.True(Assert.Single(cases, sample => sample.Id.EndsWith("proxies", StringComparison.Ordinal)).MinimumProxyCallsRestored >= 16);
            foreach (var sample in cases.Where(sample => sample.Id.EndsWith("proxies", StringComparison.Ordinal) || sample.Id.EndsWith("combined", StringComparison.Ordinal)))
            {
                Assert.Equal(19, sample.MinimumRetiredProxyInitializers);
                Assert.Equal(framework == "net48" ? 13 : 11, sample.MinimumLateProxyCallSites);
            }
            Assert.NotEmpty(Assert.Single(cases, sample => sample.Id.EndsWith("code", StringComparison.Ordinal)).ExpectedDecodedResourceSha256!);
            if (framework != "net48")
            {
                Assert.Equal(7, Assert.Single(cases, sample => sample.Id.EndsWith("strings-hash", StringComparison.Ordinal)).MinimumMaterializedHashStrings);
                Assert.Equal(6, Assert.Single(cases, sample => sample.Id.EndsWith("combined", StringComparison.Ordinal)).MinimumMaterializedHashStrings);
                Assert.Equal("zDWJQ", Assert.Single(Assert.Single(cases, sample => sample.Id.EndsWith("strings-hash", StringComparison.Ordinal)).ExpectedRetiredResourceNames!));
                Assert.Equal(CoreClrRetiredResources, Assert.Single(cases, sample => sample.Id.EndsWith("combined", StringComparison.Ordinal)).ExpectedRetiredResourceNames);
            }
            else Assert.Equal(FrameworkRetiredResources, Assert.Single(cases, sample => sample.Id.EndsWith("combined", StringComparison.Ordinal)).ExpectedRetiredResourceNames);
            foreach (var sample in cases.Where(sample => sample.Id.EndsWith("code", StringComparison.Ordinal) || sample.Id.EndsWith("combined", StringComparison.Ordinal)))
            {
                Assert.Equal(1, sample.ExpectedRestoredBodyCount);
                Assert.Equal(0, sample.MaximumRemainingStubs);
                Assert.Equal(0, sample.MaximumSurplusResources);
                Assert.True(sample.RequireOracleResourceParity);
            }
            foreach (var sample in cases.Where(sample => sample.Id.EndsWith("checks", StringComparison.Ordinal) || sample.Id.EndsWith("combined", StringComparison.Ordinal)))
                Assert.Equal(3, sample.MinimumNeutralizedCheckSites);
            foreach (var sample in cases.Where(sample => sample.Id.EndsWith("resources", StringComparison.Ordinal) || sample.Id.EndsWith("combined", StringComparison.Ordinal)))
            {
                Assert.Equal(1, sample.MinimumResourcesRestored);
                Assert.True(sample.RequireOracleResourceParity);
            }
        }
    }

    [Babel12CorpusFact]
    [Trait(Cost.Key, Cost.High)]
    public void TrialBaselineRecoversMeasuredSitesWithoutNewNetFrameworkVerifierFindings()
    {
        var samples = Environment.GetEnvironmentVariable("CILANTRO_BABEL12_SAMPLES")!;
        var directory = Directory.CreateTempSubdirectory("Cilantro.Babel12.").FullName;
        try
        {
            var outcome = CorpusRunner.Run(Manifest, samples, directory);
            Assert.True(outcome.Passed == 27 && outcome.Failed == 0 && outcome.Missing == 0,
                JsonSerializer.Serialize(outcome.Samples.Where(sample => sample.Status != "passed"), CilantroPipeline.ReportJsonOptions));
            foreach (var sample in CorpusRunner.LoadManifest(Manifest).Samples.Where(sample => sample.Tier != "oracle" && sample.Id.StartsWith("net48-", StringComparison.Ordinal)))
            {
                var original = Path.Combine(samples, sample.LocalName);
                var output = Path.Combine(directory, sample.Id, "cleaned.bin");
                var difference = IlVerification.Against(IlVerification.Read(original), IlVerification.Read(output));
                Assert.Empty(difference.Broken.Except(difference.Was.Unreadable));
                Assert.True(difference.Worsened.Count == 0, sample.Id + ": " + difference.Describe());
            }
        }
        finally { Directory.Delete(directory, true); }
    }
}

public sealed class Babel12CorpusFactAttribute : FactAttribute
{
    public Babel12CorpusFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("CILANTRO_BABEL12_SAMPLES") is not { Length: > 0 })
            Skip = "Set CILANTRO_BABEL12_SAMPLES to the pinned Babel 12 benign sample package; see docs/corpus.md.";
    }
}
