using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Corpus;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class BabelExternalBaseCorpusTests
{
    private static string Manifest => Path.Combine(Checkout.Root, "corpus", "babel-12-external-bases.manifest.json");
    private static string Root => Environment.GetEnvironmentVariable("CILANTRO_BABEL12_METHOD_SAMPLES")!;

    [Fact]
    public void ManifestPinsFrameworkBasesAndNongenericControls()
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
    [InlineData("net48-error")]
    [InlineData("net8.0-error")]
    [InlineData("net10.0-error")]
    [InlineData("net48-list")]
    [InlineData("net8.0-list")]
    [InlineData("net10.0-list")]
    [InlineData("net48-plain")]
    [InlineData("net8.0-plain")]
    [InlineData("net10.0-plain")]
    public void RecoveryPreservesConstructorsBasesAndOriginalMemberScopes(string id)
    {
        var sample = CorpusRunner.LoadManifest(Manifest).Samples.Single(sample => sample.Id == id);
        using var context = ArtifactContext.Load(Path.Combine(Root, sample.LocalName));
        new BabelDetectionPass().Run(context);
        var name = id.EndsWith("-plain", StringComparison.Ordinal) ? "PlainError" :
            id.EndsWith("-list", StringComparison.Ordinal) ? "ListBox`1" : "ErrorBox`1";
        var owner = context.Module.GetTypes().Single(type => type.Name == name);
        var parent = owner.BaseType;
        var constructors = owner.FindInstanceConstructors().ToDictionary(method => method, MethodBodySnapshot.Capture);
        var result = new BabelMethodImagePass().Run(context);
        Assert.True(result.Status == PassStatus.Success && result.Changes == 1, string.Join("; ", result.Diagnostics));
        Assert.Same(parent, owner.BaseType);
        Assert.All(constructors, pair => Assert.True(pair.Value.StructurallyEquals(pair.Key)));
        var method = owner.Methods.Single(method => method.Name == "Exchange");
        Assert.DoesNotContain(method.Body.Instructions, instruction => instruction.Operand is IMethod called &&
            called.MethodSig is { Params.Count: 4, RetType.ElementType: ElementType.Object });
        if (id.EndsWith("-list", StringComparison.Ordinal))
        {
            var members = method.Body.Instructions.Select(instruction => instruction.Operand).OfType<IMethod>().ToArray();
            Assert.Collection(members, member => Assert.Equal("get_Item", member.Name.String),
                member => Assert.Equal("set_Item", member.Name.String));
            Assert.All(members, member => Assert.Equal(parent.DefinitionAssembly.FullName, member.DeclaringType.DefinitionAssembly.FullName));
            Assert.Equal(2, members[1].MethodSig.Params.Count);
            Assert.IsType<GenericVar>(members[1].MethodSig.Params[1]);
            Assert.Equal(ElementType.Void, members[1].MethodSig.RetType.ElementType);
        }
        Assert.True(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure).Passed);
    }

    [BabelMethodCorpusFact]
    public void FullPipelineRestoresAllNineCapturesWithoutNewFrameworkVerifierFindings()
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelExternalBases.").FullName;
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
