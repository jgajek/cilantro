using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Corpus;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class BabelEmbeddingIdentityCorpusTests
{
    private static string Manifest => Path.Combine(Checkout.Root, "corpus", "babel-12-embedding-identities.manifest.json");
    private static string Root => Environment.GetEnvironmentVariable("CILANTRO_BABEL12_SAMPLES")!;

    [Fact]
    public void ManifestPinsSignedAndUnsignedRenamedInputsIndependently()
    {
        var samples = CorpusRunner.LoadManifest(Manifest).Samples;
        Assert.Equal(15, samples.Count); Assert.Equal(6, samples.Count(s => s.Tier == "oracle"));
        Assert.All(samples.Where(s => s.Tier == "profiled"), sample =>
        {
            Assert.Equal(2, sample.ExpectedPayloadSha256!.Count); Assert.Single(sample.ExpectedRetiredResourceNames!);
            Assert.Equal(0, sample.MaximumRemainingSwitchDispatchers); Assert.Equal(0, sample.MaximumUnreachableInstructions);
        });
    }

    [Babel12CorpusFact]
    [Trait(Cost.Key, Cost.High)]
    public void AllNineRenamedAndSignedCapturesRecoverTheirCompleteDependencyBundles()
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelEmbeddingIdentities.").FullName;
        try
        {
            var result = CorpusRunner.Run(Manifest, Root, directory);
            Assert.True(result.Passed == 9 && result.Failed == 0 && result.Missing == 0,
                JsonSerializer.Serialize(result.Samples.Where(s => s.Status != "passed"), CilantroPipeline.ReportJsonOptions));
            Assert.All(result.Samples.Where(s => s.Tier == "profiled"), sample =>
                Assert.Equal(1, Assert.Single(sample.Passes, p => p.Pass == "babel-dependency-deployment").Changes));
        }
        finally { Directory.Delete(directory, true); }
    }

    [Babel12CorpusTheory]
    [InlineData("net48-signed-combined")]
    [InlineData("net8.0-signed-combined")]
    [InlineData("net10.0-signed-combined")]
    [Trait(Cost.Key, Cost.High)]
    public void PublicKeysVersionsAndTokensSurviveRecursiveDeployment(string id)
    {
        var sample = CorpusRunner.LoadManifest(Manifest).Samples.Single(s => s.Id == id);
        var input = Path.Combine(Root, sample.LocalName); var original = File.ReadAllBytes(input);
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelSignedIdentity.").FullName;
        try
        {
            var result = new CilantroPipeline().Run(input, new PipelineOptions(OutputPath: Path.Combine(directory, "host.dll"), ReportDirectory: directory,
                RecoverEmbeddedAssemblies: true));
            Assert.True(result.Success, string.Join("; ", result.Report.VerificationDiagnostics)); Assert.Equal(2, result.DependencyPaths.Count);
            using var source = ModuleDefMD.Load(original); using var output = ModuleDefMD.Load(result.OutputPath!);
            Assert.True(source.IsStrongNameSigned); Assert.True(output.IsStrongNameSigned);
            Assert.Equal(source.Assembly.FullName, output.Assembly.FullName); Assert.Equal(source.Assembly.PublicKey.Data, output.Assembly.PublicKey.Data);
            Assert.NotEmpty(source.Assembly.PublicKey.Data);
            var oracle = Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(input))!, "oracle");
            foreach (var path in result.DependencyPaths)
            {
                using var expected = ModuleDefMD.Load(Path.Combine(oracle, Path.GetFileName(path))); using var deployed = ModuleDefMD.Load(path);
                Assert.Equal(expected.Assembly.FullName, deployed.Assembly.FullName); Assert.Equal(expected.Assembly.PublicKey.Data, deployed.Assembly.PublicKey.Data);
            }
            Assert.Equal(original, File.ReadAllBytes(input));
        }
        finally { Directory.Delete(directory, true); }
    }
}
