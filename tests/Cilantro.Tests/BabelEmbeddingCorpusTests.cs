using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Corpus;
using Cilantro.Core.Analysis;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class BabelEmbeddingCorpusTests
{
    private static string Manifest => Path.Combine(Checkout.Root, "corpus", "babel-12-embedding.manifest.json");
    private static string Root => Environment.GetEnvironmentVariable("CILANTRO_BABEL12_SAMPLES")!;

    [Fact]
    public void ManifestPinsExecutableDependenciesAcrossAllEmbeddingProfiles()
    {
        var samples = CorpusRunner.LoadManifest(Manifest).Samples;
        Assert.Equal(15, samples.Count); Assert.Equal(3, samples.Count(sample => sample.Tier == "oracle"));
        Assert.All(samples.Where(sample => sample.Tier == "profiled"), sample =>
        {
            Assert.Equal(sample.Id.EndsWith("-single", StringComparison.Ordinal) || sample.Id.EndsWith("-nested", StringComparison.Ordinal) ? 1 : 2,
                sample.ExpectedPayloadSha256!.Count);
            Assert.Equal(0, sample.MaximumRemainingSwitchDispatchers); Assert.Equal(0, sample.MaximumUnreachableInstructions);
            Assert.Single(sample.ExpectedRetiredResourceNames!);
        });
    }

    [Babel12CorpusFact]
    [Trait(Cost.Key, Cost.High)]
    public void AllTwelveCapturesExtractTheirExactOriginalDependencyImages()
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelEmbedding.").FullName;
        try
        {
            var result = CorpusRunner.Run(Manifest, Root, directory);
            Assert.True(result.Passed == 12 && result.Failed == 0 && result.Missing == 0,
                JsonSerializer.Serialize(result.Samples.Where(sample => sample.Status != "passed"), CilantroPipeline.ReportJsonOptions));
            Assert.All(result.Samples.Where(sample => sample.Tier == "profiled"), sample =>
                Assert.Equal(1, Assert.Single(sample.Passes, pass => pass.Pass == "babel-dependency-deployment").Changes));
        }
        finally { Directory.Delete(directory, true); }
    }

    [Babel12CorpusTheory]
    [InlineData("net48-nested")]
    [InlineData("net8.0-nested")]
    [InlineData("net10.0-nested")]
    [Trait(Cost.Key, Cost.High)]
    public void RecursiveRecoveryFindsTheLeafWithoutExecutingEitherDependency(string id)
    {
        var sample = CorpusRunner.LoadManifest(Manifest).Samples.Single(sample => sample.Id == id);
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelNestedEmbedding.").FullName;
        try
        {
            var input = Path.Combine(Root, sample.LocalName);
            var result = new CilantroPipeline().Run(input, new PipelineOptions(OutputPath: Path.Combine(directory, "cleaned.dll"),
                ReportDirectory: directory, RecoverEmbeddedAssemblies: true));
            Assert.True(result.Success, string.Join(";", result.Report.VerificationDiagnostics));
            var report = Assert.IsType<EmbeddedRecoveryReport>(result.EmbeddedRecovery);
            Assert.True(report.Complete); Assert.Equal(3, report.Nodes.Count);
            Assert.Equal(2, report.Nodes.Max(node => node.Depth));
            var oracle = Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(input))!, "oracle", "BabelEmbedLeaf.dll");
            var hash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(oracle)));
            Assert.Contains(report.Nodes, node => node.Depth == 2 && node.Sha256 == hash && node.Run?.Success == true);
            Assert.Equal(2, result.DependencyPaths.Count);
            Assert.All(result.DependencyPaths.Append(result.OutputPath!), path =>
            {
                using var image = ModuleDefMD.Load(path);
                Assert.Empty(BabelEmbeddingShape.Find(image));
                Assert.DoesNotContain(image.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody).SelectMany(method => method.Body.Instructions),
                    instruction => instruction.Operand is IMethod called && called.FullName == "System.Void System.AppDomain::add_AssemblyResolve(System.ResolveEventHandler)");
            });
            var deployedLeaf = result.DependencyPaths.Single(path => Path.GetFileName(path) == "BabelEmbedLeaf.dll");
            var recoveredLeaf = Assert.Single(report.Nodes, node => node.Depth == 2).Run!.Wrote.Cleaned!;
            Assert.Equal(File.ReadAllBytes(recoveredLeaf), File.ReadAllBytes(deployedLeaf));
            using var oracleImage = ModuleDefMD.Load(oracle); using var deployedImage = ModuleDefMD.Load(deployedLeaf);
            Assert.Equal(oracleImage.Assembly.FullName, deployedImage.Assembly.FullName);
        }
        finally { Directory.Delete(directory, true); }
    }
}
