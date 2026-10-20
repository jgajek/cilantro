using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Corpus;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class BabelDormantRuntimeCleanupTests
{
    private static string Sample(string id) => Path.Combine(Environment.GetEnvironmentVariable("CILANTRO_BABEL12_METHOD_SAMPLES")!,
        CorpusRunner.LoadManifest(Path.Combine(Checkout.Root, "corpus", "babel-12-methods.manifest.json")).Samples.Single(sample => sample.Id == id).LocalName);
    private static TypeDef[] Family(ModuleDef module) => module.GetTypes().Where(type => type.FullName.Any(character => character is >= '\ue000' and <= '\uf8ff')).ToArray();
    private static MethodDef Dispatcher(ModuleDef module) => module.GetTypes().SelectMany(type => type.Methods).Single(method =>
        method.IsStatic && method.ReturnType.FullName == "System.Object" && method.MethodSig.Params.Count == 4);

    [BabelMethodCorpusTheory]
    [InlineData("net48-struct")]
    [InlineData("net48-generic-method")]
    [InlineData("net8.0-struct")]
    [InlineData("net8.0-generic-method")]
    [InlineData("net10.0-struct")]
    [InlineData("net10.0-generic-method")]
    public void FullPipelineRetiresTheCompleteUnusedRuntime(string id)
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelDormant.").FullName;
        try
        {
            var input = Sample(id);
            using var original = ModuleDefMD.Load(input);
            Assert.Equal(54, Family(original).Length);
            var result = new CilantroPipeline().Run(input, new PipelineOptions(OutputPath: Path.Combine(directory, "cleaned.bin"), ReportDirectory: Path.Combine(directory, "reports")));
            Assert.True(result.Success);
            using var cleaned = ModuleDefMD.Load(result.OutputPath!);
            Assert.Equal(original.GetTypes().Count() - 54, cleaned.GetTypes().Count());
            Assert.DoesNotContain(cleaned.GetTypes(), type => type.Fields.Any(field => field.FieldType.FullName == "System.Reflection.Emit.DynamicMethod"));
            foreach (var type in original.GetTypes().Where(type => type.Namespace == "BabelMethodProbe"))
                Assert.Contains(cleaned.GetTypes(), remaining => remaining.FullName == type.FullName);
            Assert.Empty(cleaned.Resources);
            if (id.StartsWith("net48-", StringComparison.Ordinal))
            {
                var difference = IlVerification.Against(IlVerification.Read(input), IlVerification.Read(result.OutputPath!));
                Assert.Empty(difference.Broken.Except(difference.Was.Unreadable)); Assert.Empty(difference.Worsened);
            }
        }
        finally { Directory.Delete(directory, true); }
    }

    [BabelMethodCorpusTheory]
    [InlineData("body")]
    [InlineData("parameter-name")]
    [InlineData("parameter-flags")]
    [InlineData("enum-constant")]
    [InlineData("property")]
    [InlineData("layout")]
    [InlineData("extra-field")]
    [InlineData("storage")]
    [InlineData("resource")]
    [InlineData("literal-name")]
    [InlineData("handle")]
    [InlineData("live-call")]
    [InlineData("application-field")]
    [InlineData("no-proof")]
    public void ChangedFamiliesAndSurvivingConsumersRetainTheWholeRuntime(string change)
    {
        using var context = ArtifactContext.Load(Sample("net8.0-struct"));
        context.SetFact("options.removeRuntime", true);
        new BabelDetectionPass().Run(context);
        if (change != "no-proof") Assert.Equal(PassStatus.Success, new BabelMethodImagePass().Run(context).Status);
        var family = Family(context.Module); Assert.Equal(54, family.Length);
        var dispatcher = Dispatcher(context.Module);
        var enumeration = family.First(type => type.IsEnum);
        switch (change)
        {
            case "body": dispatcher.Body.Instructions.Insert(0, OpCodes.Nop.ToInstruction()); dispatcher.Body.Instructions.Insert(0, OpCodes.Break.ToInstruction()); break;
            case "parameter-name": dispatcher.ParamDefs[0].Name = "Changed"; break;
            case "parameter-flags": dispatcher.ParamDefs[0].Attributes ^= ParamAttributes.In; break;
            case "enum-constant": enumeration.Fields.First(field => field.HasConstant).Constant.Value = 917; break;
            case "property": dispatcher.DeclaringType.Properties.Add(new PropertyDefUser("Extra", PropertySig.CreateStatic(dispatcher.ReturnType, dispatcher.MethodSig.Params.ToArray())) { GetMethod = dispatcher }); break;
            case "layout": enumeration.ClassLayout = new ClassLayoutUser(1, 128); break;
            case "extra-field": dispatcher.DeclaringType.Fields.Add(new FieldDefUser("Extra", new FieldSig(context.Module.CorLibTypes.Object), FieldAttributes.Private)); break;
            case "storage": family.Single(type => type.IsValueType && !type.IsEnum && type.Methods.Count == 0 && type.Fields.Count == 2 && type.Fields[1].FieldType.ElementType == ElementType.Object).Fields[1].Attributes ^= FieldAttributes.InitOnly; break;
            case "resource": context.Module.Resources.Add(new EmbeddedResource("ApplicationData", [1, 2, 3])); break;
            case "literal-name": AddRoot([OpCodes.Ldstr.ToInstruction(dispatcher.DeclaringType.ReflectionFullName), OpCodes.Pop.ToInstruction()]); break;
            case "handle": AddRoot([OpCodes.Ldtoken.ToInstruction(dispatcher.DeclaringType), OpCodes.Pop.ToInstruction()]); break;
            case "live-call": AddRoot([OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldnull.ToInstruction(), OpCodes.Ldnull.ToInstruction(), OpCodes.Ldnull.ToInstruction(), OpCodes.Call.ToInstruction(dispatcher), OpCodes.Pop.ToInstruction()]); break;
            case "application-field": context.Module.EntryPoint.DeclaringType.Fields.Add(new FieldDefUser("SavedRuntimeValue", new FieldSig(enumeration.ToTypeSig()), FieldAttributes.Private | FieldAttributes.Static)); break;
        }
        Assert.Equal(PassStatus.Success, new RuntimeCleanupPass().Run(context).Status);
        Assert.All(family, type => Assert.Contains(type, context.Module.GetTypes()));

        void AddRoot(IEnumerable<Instruction> instructions)
        {
            var root = context.Module.GlobalType.FindOrCreateStaticConstructor();
            foreach (var instruction in instructions) root.Body.Instructions.Insert(root.Body.Instructions.Count - 1, instruction);
        }
    }

    [BabelMethodCorpusTheory]
    [InlineData(true)]
    [InlineData(false)]
    public void UnrelatedUnusedApplicationDeclarationsArePreserved(bool keepRuntime)
    {
        using var context = ArtifactContext.Load(Sample("net8.0-struct"));
        context.SetFact("options.removeRuntime", !keepRuntime);
        new BabelDetectionPass().Run(context); new BabelMethodImagePass().Run(context);
        var family = Family(context.Module);
        var application = new TypeDefUser("App", "Unused", context.Module.CorLibTypes.Object.TypeDefOrRef) { Attributes = TypeAttributes.NotPublic };
        context.Module.Types.Add(application);
        Assert.Equal(PassStatus.Success, new RuntimeCleanupPass().Run(context).Status);
        Assert.Contains(application, context.Module.Types);
        if (keepRuntime) Assert.All(family, type => Assert.Contains(type, context.Module.GetTypes()));
        else Assert.All(family, type => Assert.DoesNotContain(type, context.Module.GetTypes()));
    }

    [BabelMethodCorpusFact]
    public void ChangedOriginalBodyCannotEstablishOwnership()
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelDormantInput.").FullName;
        try
        {
            var path = Path.Combine(directory, "changed.dll");
            using (var module = ModuleDefMD.Load(Sample("net8.0-struct")))
            {
                Dispatcher(module).Body.Instructions.Insert(0, OpCodes.Break.ToInstruction());
                module.Write(path);
            }
            using var context = ArtifactContext.Load(path);
            context.SetFact("options.removeRuntime", true);
            new BabelDetectionPass().Run(context); new BabelMethodImagePass().Run(context);
            var family = Family(context.Module);
            Assert.Equal(PassStatus.Success, new RuntimeCleanupPass().Run(context).Status);
            Assert.All(family, type => Assert.Contains(type, context.Module.GetTypes()));
        }
        finally { Directory.Delete(directory, true); }
    }

    [BabelMethodCorpusFact]
    public void LocalAssemblyIdentityDoesNotDetermineRuntimeOwnership()
    {
        using var context = ArtifactContext.Load(Sample("net8.0-struct"));
        context.SetFact("options.removeRuntime", true);
        new BabelDetectionPass().Run(context); new BabelMethodImagePass().Run(context);
        var family = Family(context.Module);
        context.Module.Assembly.Name = "RenamedApplication";
        Assert.Equal(PassStatus.Success, new RuntimeCleanupPass().Run(context).Status);
        Assert.All(family, type => Assert.DoesNotContain(type, context.Module.GetTypes()));
    }
}
