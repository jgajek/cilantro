using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Corpus;

namespace Cilantro.Tests;

public sealed class BabelExternalCodeCorpusTests
{
    private static string Manifest => Path.Combine(Checkout.Root, "corpus", "babel-12-external.manifest.json");
    private static string Root => Environment.GetEnvironmentVariable("CILANTRO_BABEL12_SAMPLES")!;

    [Fact]
    public void ManifestPinsSeparateMethodCodeInputsAndCompleteRecoveryGates()
    {
        var samples = CorpusRunner.LoadManifest(Manifest).Samples;
        Assert.Equal(6, samples.Count); Assert.Equal(3, samples.Count(s => s.Tier == "oracle"));
        Assert.All(samples.Where(s => s.Tier == "profiled"), sample =>
        {
            var source = Assert.Single(sample.BabelCodeSources!); Assert.Equal(64, source.Sha256.Length);
            Assert.EndsWith("/protected/probe-code.eil", source.LocalName, StringComparison.Ordinal);
            Assert.Equal(1, sample.ExpectedRestoredBodyCount); Assert.Equal(0, sample.MaximumRemainingStubs);
            Assert.Equal(0, sample.MaximumRemainingSwitchDispatchers); Assert.Equal(0, sample.MaximumUnreachableInstructions);
            Assert.Equal(0, sample.MaximumSurplusResources); Assert.True(sample.RequireOracleResourceParity);
        });
    }

    [Babel12CorpusFact]
    [Trait(Cost.Key, Cost.High)]
    public void ExplicitCompanionsRestoreAllBodiesWithoutRemainingStubsOrNewIlFindings()
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelExternalCode.").FullName;
        try
        {
            var outcome = CorpusRunner.Run(Manifest, Root, directory);
            Assert.True(outcome.Passed == 3 && outcome.Failed == 0 && outcome.Missing == 0,
                JsonSerializer.Serialize(outcome.Samples.Where(s => s.Status != "passed"), CilantroPipeline.ReportJsonOptions));
            Assert.All(outcome.Samples, sample => Assert.False(File.Exists(Path.Combine(directory, sample.Id, "probe-code.eil"))));
            var sample = CorpusRunner.LoadManifest(Manifest).Samples.Single(s => s.Id == "net48-external");
            var difference = IlVerification.Against(IlVerification.Read(Path.Combine(Root, sample.LocalName)),
                IlVerification.Read(Path.Combine(directory, sample.Id, "cleaned.bin")));
            Assert.Empty(difference.Broken.Except(difference.Was.Unreadable));
            Assert.Empty(difference.Worsened); Assert.Empty(difference.Is.Unreadable);
        }
        finally { Directory.Delete(directory, true); }
    }

    [Babel12CorpusFact]
    [Trait(Cost.Key, Cost.High)]
    public void UnregisteredAndDamagedDataCannotRestoreTheEncryptedBody()
    {
        var sample = CorpusRunner.LoadManifest(Manifest).Samples.Single(s => s.Id == "net8.0-external");
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelExternalRefusal.").FullName;
        try
        {
            var input = Path.Combine(Root, sample.LocalName);
            // Its real sibling exists. An interpreter must still refuse it without an explicit input.
            Assert.True(File.Exists(Path.Combine(Path.GetDirectoryName(input)!, "probe-code.eil")));
            var missing = new CilantroPipeline().Run(input, new PipelineOptions(OutputPath: Path.Combine(directory, "missing.dll")));
            Assert.Equal(0, missing.Report.Recovery.RestoredMethodBodies); Assert.Equal(1, missing.Report.Recovery.RemainingMethodStubs);
            var damagedFile = Path.Combine(directory, "probe-code.eil"); File.WriteAllBytes(damagedFile, [0, 1, 2]);
            var damaged = new CilantroPipeline().Run(input, new PipelineOptions(OutputPath: Path.Combine(directory, "damaged.dll"))
                { BabelCodeSourceFiles = [damagedFile] });
            Assert.Equal(0, damaged.Report.Recovery.RestoredMethodBodies); Assert.Equal(1, damaged.Report.Recovery.RemainingMethodStubs);
            Assert.Contains(damaged.Report.Evidence, e => e.Category == "babel-code-source");
        }
        finally { Directory.Delete(directory, true); }
    }

    [Babel12CorpusTheory]
    [InlineData("babel-12-external-combined.manifest.json")]
    [InlineData("babel-12-password-combined.manifest.json")]
    [Trait(Cost.Key, Cost.High)]
    public void StringsResourcesProxiesAndFlowCombinationsLeaveNoEncryptedData(string manifestName)
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelCodeCombinations.").FullName;
        try
        {
            var manifest = Path.Combine(Checkout.Root, "corpus", manifestName);
            var outcome = CorpusRunner.Run(manifest, Root, directory);
            Assert.True(outcome.Passed == 3 && outcome.Failed == 0 && outcome.Missing == 0,
                JsonSerializer.Serialize(outcome.Samples.Where(s => s.Status != "passed"), CilantroPipeline.ReportJsonOptions));
            Assert.All(outcome.Samples, sample =>
            {
                Assert.True(Assert.Single(sample.Passes, p => p.Pass == "babel-literal-strings").Changes >= 4);
                Assert.True(Assert.Single(sample.Passes, p => p.Pass == "babel-proxies").Changes >= 11);
            });
            var sample = CorpusRunner.LoadManifest(manifest).Samples.Single(s => s.Id.StartsWith("net48-", StringComparison.Ordinal) && s.Tier == "profiled");
            var difference = IlVerification.Against(IlVerification.Read(Path.Combine(Root, sample.LocalName)),
                IlVerification.Read(Path.Combine(directory, sample.Id, "cleaned.bin")));
            Assert.Empty(difference.Broken.Except(difference.Was.Unreadable)); Assert.Empty(difference.Worsened); Assert.Empty(difference.Is.Unreadable);
        }
        finally { Directory.Delete(directory, true); }
    }

    [Babel12CorpusFact]
    public void ChangedCompanionHashesFailTheCorpusBeforeInterpretation()
    {
        var sample = CorpusRunner.LoadManifest(Manifest).Samples.Single(s => s.Id == "net8.0-external");
        var source = Assert.Single(sample.BabelCodeSources!);
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelExternalHash.").FullName;
        try
        {
            var manifest = new CorpusManifest(1, "changed-code-source", "negative control",
                [sample with { BabelCodeSources = [source with { Sha256 = new string('0', 64) }] }]);
            var path = Path.Combine(directory, "manifest.json"); File.WriteAllText(path, JsonSerializer.Serialize(manifest));
            var outcome = CorpusRunner.Run(path, Root, Path.Combine(directory, "out"));
            Assert.Equal(1, outcome.Failed); Assert.Equal(0, outcome.Passed);
            var result = Assert.Single(outcome.Samples); Assert.True(result.HashVerified); Assert.Empty(result.Passes);
            Assert.Contains(result.Diagnostics, d => d.Contains("code-source SHA-256", StringComparison.Ordinal));
        }
        finally { Directory.Delete(directory, true); }
    }

    [Theory]
    [InlineData("../outside.eil")]
    [InlineData("nested/../outside.eil")]
    [InlineData("/absolute.eil")]
    public void CompanionPathsCannotEscapeTheCorpusRoot(string localName)
    {
        var sample = CorpusRunner.LoadManifest(Manifest).Samples.Single(s => s.Id == "net8.0-external");
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelExternalPath.").FullName;
        try
        {
            var path = Path.Combine(directory, "manifest.json");
            File.WriteAllText(path, JsonSerializer.Serialize(new CorpusManifest(1, "bad-path", "negative control",
                [sample with { BabelCodeSources = [new(localName, new string('0', 64))] }])));
            Assert.Throws<InvalidDataException>(() => CorpusRunner.LoadManifest(path));
        }
        finally { Directory.Delete(directory, true); }
    }
}
