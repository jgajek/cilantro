using Cilantro.Core;
using System.Text.Json;
using Cilantro.Core.Analysis;
using Cilantro.Core.Corpus;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class BabelMethodRuntimeCleanupTests
{
    private static string Root => Environment.GetEnvironmentVariable("CILANTRO_BABEL12_METHOD_SAMPLES")!;
    private static string Sample(string id) => Path.Combine(Root, CorpusRunner.LoadManifest(Path.Combine(Checkout.Root, "corpus", "babel-12-baseline.manifest.json")).Samples.Single(sample => sample.Id == id).LocalName);
    private static TypeDef Factory(ModuleDef module) => module.GetTypes().Single(type => type.Fields.Count == 2 &&
        type.Fields.Any(field => field.FieldType.FullName == "System.Reflection.Emit.DynamicMethod") &&
        type.Fields.Any(field => field.FieldType.FullName == "System.Type"));

    [BabelMethodCorpusTheory]
    [InlineData("net48-code")]
    [InlineData("net48-combined")]
    [InlineData("net8.0-code")]
    [InlineData("net8.0-combined")]
    [InlineData("net10.0-code")]
    [InlineData("net10.0-combined")]
    public void FullRecoveryRetiresTheReviewedFactory(string id)
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelFactory.").FullName;
        try
        {
            var input = Sample(id);
            using var original = ModuleDefMD.Load(input); var name = Factory(original).FullName;
            var result = new CilantroPipeline().Run(input, new PipelineOptions(OutputPath: Path.Combine(directory, "cleaned.bin"), ReportDirectory: Path.Combine(directory, "reports")));
            Assert.True(result.Success); Assert.NotNull(result.OutputPath);
            using var cleaned = ModuleDefMD.Load(result.OutputPath);
            Assert.DoesNotContain(cleaned.GetTypes(), type => type.Fields.Any(field => field.FieldType.FullName == "System.Reflection.Emit.DynamicMethod"));
            using var changes = JsonDocument.Parse(File.ReadAllText(result.ChangesReportPath));
            Assert.Contains(changes.RootElement.EnumerateArray(), change => change.GetProperty("Kind").GetString() == "remove-runtime-type" &&
                change.GetProperty("Location").GetString()!.EndsWith(name, StringComparison.Ordinal));
            if (id.StartsWith("net48-", StringComparison.Ordinal))
            {
                var difference = IlVerification.Against(IlVerification.Read(input), IlVerification.Read(result.OutputPath));
                Assert.Empty(difference.Broken.Except(difference.Was.Unreadable)); Assert.Empty(difference.Worsened);
            }
        }
        finally { Directory.Delete(directory, true); }
    }

    [BabelMethodCorpusTheory]
    [InlineData("body")]
    [InlineData("field")]
    [InlineData("extra-field")]
    [InlineData("property")]
    [InlineData("parameter-name")]
    [InlineData("literal-name")]
    [InlineData("handle")]
    [InlineData("live-call")]
    [InlineData("no-recovery")]
    public void ChangesAndSurvivingConsumersRetainFactory(string change)
    {
        using var context = ArtifactContext.Load(Sample("net8.0-code"));
        context.SetFact("options.removeRuntime", true); new BabelDetectionPass().Run(context);
        var factory = Factory(context.Module);
        if (change != "no-recovery") Assert.Equal(PassStatus.Success, new BabelMethodImagePass().Run(context).Status);
        var creator = factory.Methods.Single(method => !method.IsConstructor);
        switch (change)
        {
            case "body": creator.Body = new CilBody(); creator.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); creator.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); break;
            case "field": factory.Fields[0].FieldSig = new FieldSig(context.Module.CorLibTypes.Object); break;
            case "extra-field": factory.Fields.Add(new FieldDefUser("Extra", new FieldSig(context.Module.CorLibTypes.Int32), FieldAttributes.Private)); break;
            case "property": factory.Properties.Add(new PropertyDefUser("Extra", PropertySig.CreateInstance(creator.ReturnType, creator.MethodSig.Params.ToArray())) { GetMethod = creator }); break;
            case "parameter-name": creator.ParamDefs[0].Name = "Changed"; break;
            case "literal-name": AddRoot([OpCodes.Ldstr.ToInstruction(factory.ReflectionFullName), OpCodes.Pop.ToInstruction()]); break;
            case "handle": AddRoot([OpCodes.Ldtoken.ToInstruction(factory), OpCodes.Pop.ToInstruction()]); break;
            case "live-call": AddRoot([OpCodes.Ldnull.ToInstruction(), OpCodes.Ldnull.ToInstruction(), OpCodes.Newobj.ToInstruction(factory.FindInstanceConstructors().Single()), OpCodes.Pop.ToInstruction()]); break;
        }
        BabelMethodConstructionRuntime.Publish(context);
        if (change is not ("handle" or "live-call")) Assert.DoesNotContain(factory.MDToken.Raw, RecoveryOrphans.TypesOf(context));
        Assert.Equal(PassStatus.Success, new RuntimeCleanupPass().Run(context).Status);
        Assert.Contains(factory, context.Module.GetTypes());

        void AddRoot(IEnumerable<Instruction> instructions)
        {
            var root = context.Module.GlobalType.FindOrCreateStaticConstructor();
            foreach (var instruction in instructions) root.Body.Instructions.Insert(root.Body.Instructions.Count - 1, instruction);
        }
    }
}
