using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Corpus;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class BabelHierarchyCorpusTests
{
    private static string Manifest => Path.Combine(Checkout.Root, "corpus", "babel-12-hierarchy.manifest.json");
    private static string Root => Environment.GetEnvironmentVariable("CILANTRO_BABEL12_METHOD_SAMPLES")!;

    [Fact]
    public void ManifestPinsNineIndependentHierarchyCaptures()
    {
        var samples = CorpusRunner.LoadManifest(Manifest).Samples;
        Assert.Equal(12, samples.Count);
        Assert.Equal(3, samples.Count(sample => sample.Tier == "oracle"));
        Assert.Equal(9, samples.Count(sample => sample.Tier == "profiled"));
        Assert.All(samples.Where(sample => sample.Tier == "profiled"), sample =>
        {
            Assert.Equal(1, sample.ExpectedRestoredBodyCount);
            Assert.Equal(0, sample.MaximumRemainingStubs);
            Assert.Equal(0, sample.MaximumSurplusResources);
            Assert.True(sample.RequireOracleResourceParity);
        });
    }

    [BabelMethodCorpusTheory]
    [InlineData("net48-deep")]
    [InlineData("net8.0-deep")]
    [InlineData("net10.0-deep")]
    [InlineData("net48-swapped")]
    [InlineData("net8.0-swapped")]
    [InlineData("net10.0-swapped")]
    [InlineData("net48-nested")]
    [InlineData("net8.0-nested")]
    [InlineData("net10.0-nested")]
    public void RecoveryRetainsBaseStateAndBindings(string id)
    {
        var sample = CorpusRunner.LoadManifest(Manifest).Samples.Single(sample => sample.Id == id);
        using var context = ArtifactContext.Load(Path.Combine(Root, sample.LocalName));
        new BabelDetectionPass().Run(context);
        var storage = context.Module.GetTypes().Single(type => type.Name == "Storage`1");
        var initializer = storage.FindStaticConstructor();
        Assert.NotNull(initializer);
        var snapshot = MethodBodySnapshot.Capture(initializer);
        var result = new BabelMethodImagePass().Run(context);
        Assert.True(result.Status == PassStatus.Success && result.Changes == 1, string.Join("; ", result.Diagnostics));
        Assert.Same(initializer, storage.FindStaticConstructor());
        Assert.True(snapshot.StructurallyEquals(initializer));
        var name = id.EndsWith("-deep", StringComparison.Ordinal) ? "DeepBox`2" :
            id.EndsWith("-swapped", StringComparison.Ordinal) ? "SwappedBox`2" : "NestedBox`1";
        var owner = context.Module.GetTypes().Single(type => type.Name == name);
        var method = owner.Methods.Single(method => method.Name == "Exchange");
        Assert.IsType<GenericVar>(method.ReturnType);
        var fields = method.Body.Instructions.Select(instruction => instruction.Operand).OfType<IField>().Where(field => field.FieldSig is not null).ToArray();
        Assert.NotEmpty(fields);
        Assert.All(fields, field => Assert.Same(storage, field.ResolveFieldDef()!.DeclaringType));
        Assert.Contains(method.Body.Instructions, instruction => instruction.OpCode.Code == Code.Stsfld);
        Assert.True(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure).Passed);
    }

    [BabelMethodCorpusFact]
    public void FullPipelineMeetsAllNineRecoveryContracts()
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelHierarchy.").FullName;
        try
        {
            var result = CorpusRunner.Run(Manifest, Root, directory);
            Assert.True(result.Passed == 9 && result.Failed == 0 && result.Missing == 0,
                JsonSerializer.Serialize(result.Samples.Where(sample => sample.Status != "passed"), CilantroPipeline.ReportJsonOptions));
            foreach (var sample in CorpusRunner.LoadManifest(Manifest).Samples.Where(sample => sample.Tier == "profiled" && sample.Id.StartsWith("net48-", StringComparison.Ordinal)))
            {
                var difference = IlVerification.Against(IlVerification.Read(Path.Combine(Root, sample.LocalName)),
                    IlVerification.Read(Path.Combine(directory, sample.Id, "cleaned.bin")));
                Assert.Empty(difference.Broken.Except(difference.Was.Unreadable));
                Assert.Empty(difference.Worsened);
            }
        }
        finally { Directory.Delete(directory, true); }
    }
}
