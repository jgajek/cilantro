using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Corpus;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class BabelDependencyDeploymentTests
{
    [Babel12CorpusFact]
    [Trait(Cost.Key, Cost.High)]
    public void AConflictingTransitiveFilePreventsEveryRecursiveReplacement()
    {
        var sample = CorpusRunner.LoadManifest(Path.Combine(Checkout.Root, "corpus", "babel-12-embedding.manifest.json")).Samples.Single(s => s.Id == "net8.0-nested");
        var input = Path.Combine(Environment.GetEnvironmentVariable("CILANTRO_BABEL12_SAMPLES")!, sample.LocalName);
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelDeploymentConflict.").FullName;
        try
        {
            var root = new CilantroPipeline().Run(input, new PipelineOptions(OutputPath: Path.Combine(directory, "host.dll"), ReportDirectory: Path.Combine(directory, "reports")));
            Assert.True(root.Success); var deployed = Assert.Single(root.DependencyPaths); var before = File.ReadAllBytes(deployed);
            var childInput = Assert.Single(root.ExtractedPayloadPaths);
            var child = new CilantroPipeline().Run(childInput, new PipelineOptions(OutputPath: Path.Combine(directory, "child", "child.dll"), ReportDirectory: Path.Combine(directory, "child", "reports")));
            Assert.True(child.Success); Assert.Single(child.DependencyPaths);
            var conflict = Path.Combine(directory, "BabelEmbedLeaf.dll"); File.WriteAllBytes(conflict, [9, 8, 7]);
            var nodes = new List<EmbeddedRecoveryNode> { new(input, root.Report.InputSha256, 0, "recovered", RunManifest.Of(root)),
                new(childInput, child.Report.InputSha256, 1, "recovered", RunManifest.Of(child)) };
            Assert.False(DependencyDeploymentCompletion.TryComplete(root, nodes, [new(0, 1, childInput)], out _, out var why));
            Assert.Contains("conflict", why, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(before, File.ReadAllBytes(deployed)); Assert.Equal(new byte[] { 9, 8, 7 }, File.ReadAllBytes(conflict));
        }
        finally { Directory.Delete(directory, true); }
    }

    [Babel12CorpusTheory]
    [InlineData("wire")]
    [InlineData("registration")]
    [InlineData("metadata")]
    [InlineData("extra-field")]
    [InlineData("handle")]
    [InlineData("reflection")]
    [InlineData("codec-effect")]
    [InlineData("keep-runtime")]
    [InlineData("type-name")]
    [InlineData("field-name")]
    [InlineData("method-name")]
    [Trait(Cost.Key, Cost.High)]
    public void ChangedOrObservedLoadersRetainTheirHooksAndDoNotPublishDeployment(string variant)
    {
        var sample = CorpusRunner.LoadManifest(Path.Combine(Checkout.Root, "corpus", "babel-12-embedding.manifest.json")).Samples.Single(s => s.Id == "net8.0-multiple");
        var input = Path.Combine(Environment.GetEnvironmentVariable("CILANTRO_BABEL12_SAMPLES")!, sample.LocalName);
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelDeploymentRefusal.").FullName;
        try
        {
            var passes = CilantroPipeline.CreateDefaultPasses().ToList();
            if (variant != "keep-runtime") passes.Insert(passes.FindIndex(p => p.Name == "babel-dependency-deployment"), new Mutation(variant));
            var result = new CilantroPipeline(passes).Run(input, new PipelineOptions(OutputPath: Path.Combine(directory, "host.dll"), ReportDirectory: directory,
                RemoveRuntime: variant != "keep-runtime", RenameSymbols: false));
            Assert.Equal(0, Assert.Single(result.Report.Passes, p => p.Pass == "babel-dependency-deployment").Changes);
            Assert.Empty(result.DependencyPaths);
            Assert.False(File.Exists(Path.Combine(directory, "BabelEmbedLibrary.dll")));
        }
        finally { Directory.Delete(directory, true); }
    }

    private sealed class Mutation(string variant) : DeobfuscationPass
    {
        public override string Name => "test-mutate-babel-deployment";
        protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
        {
            var shape = Assert.Single(BabelEmbeddingShape.Find(context.Module));
            var type = shape.Install.DeclaringType;
            if (variant == "wire")
            {
                var xor = shape.Resolve.Body.Instructions.First(i => i.OpCode.Code == Code.Xor);
                var previous = shape.Resolve.Body.Instructions[shape.Resolve.Body.Instructions.IndexOf(xor) - 1];
                Assert.True(previous.IsLdcI4()); var key = previous.GetLdcI4Value(); previous.OpCode = OpCodes.Ldc_I4; previous.Operand = key ^ 1;
            }
            else if (variant == "extra-field") type.Fields.Add(new FieldDefUser("Extra", new FieldSig(context.Module.CorLibTypes.Int32), FieldAttributes.Private | FieldAttributes.Static));
            else if (variant == "metadata") type.Fields[0].Attributes |= FieldAttributes.InitOnly;
            else if (variant == "type-name") type.Name = "ChangedLoaderName";
            else if (variant == "field-name") type.Fields[0].Name = "ChangedFieldName";
            else if (variant == "method-name") shape.Install.Name = "ChangedMethodName";
            else if (variant is "handle" or "reflection")
            {
                var method = context.Module.EntryPoint!;
                method.Body.Instructions.Insert(0, variant == "handle" ? OpCodes.Ldtoken.ToInstruction(type) : OpCodes.Ldstr.ToInstruction(type.ReflectionFullName));
                method.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
            }
            else
            {
                var method = variant == "codec-effect" ? shape.Codec : shape.Install;
                method.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(new MemberRefUser(context.Module, "get_TickCount", MethodSig.CreateStatic(context.Module.CorLibTypes.Int32),
                    context.Module.CorLibTypes.GetTypeRef("System", "Environment"))));
                method.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
            }
            return (PassStatus.Success, 0, []);
        }
    }
}
