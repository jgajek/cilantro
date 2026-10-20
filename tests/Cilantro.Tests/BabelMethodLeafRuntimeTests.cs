using Cilantro.Core;
using System.Text.Json;
using Cilantro.Core.Analysis;
using Cilantro.Core.Corpus;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

namespace Cilantro.Tests;

public sealed class BabelMethodLeafRuntimeTests
{
    private static string Sample(string id) => Path.Combine(Environment.GetEnvironmentVariable("CILANTRO_BABEL12_METHOD_SAMPLES")!,
        CorpusRunner.LoadManifest(Path.Combine(Checkout.Root, "corpus", "babel-12-baseline.manifest.json")).Samples.Single(sample => sample.Id == id).LocalName);
    private static MethodDef Dispatcher(ModuleDef module) => module.GetTypes().SelectMany(type => type.Methods).Single(method =>
        method.IsStatic && method.ReturnType.FullName == "System.Object" && method.MethodSig.Params.Count == 4);
    private static TypeDef[] Leaves(ModuleDef module) => BabelDormantMethodRuntime.Family(Dispatcher(module))
        .Where(type => !type.IsNested && (type.IsEnum || type.IsValueType && type.Methods.Count == 0 ||
            type.Methods.Count == 5 && type.Fields.Count == 2 && type.Fields.Any(field => field.FieldType.FullName == "System.Int32[]") &&
            type.Fields.Any(field => field.FieldType.ElementType == ElementType.I4))).ToArray();

    [BabelMethodCorpusTheory]
    [InlineData("net48-code")]
    [InlineData("net8.0-code")]
    [InlineData("net10.0-code")]
    public void CodeOnlyRecoveryRetiresTheComplete54TypeMethodRuntime(string id)
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelMethodLeaves.").FullName;
        try
        {
            var input = Sample(id); using var original = ModuleDefMD.Load(input);
            var result = new CilantroPipeline().Run(input, new PipelineOptions(OutputPath: Path.Combine(directory, "cleaned.bin"), ReportDirectory: Path.Combine(directory, "reports")));
            Assert.True(result.Success);
            using var cleaned = ModuleDefMD.Load(result.OutputPath!);
            Assert.Equal(original.GetTypes().Count() - 54, cleaned.GetTypes().Count());
            Assert.Single(cleaned.Resources); Assert.Equal("BabelProbe.Secret.txt", cleaned.Resources[0].Name);
            Assert.Contains(cleaned.GetTypes(), type => type.FullName == "BabelProbe.Program");
            if (id.StartsWith("net48-", StringComparison.Ordinal))
            {
                var difference = IlVerification.Against(IlVerification.Read(input), IlVerification.Read(result.OutputPath!));
                Assert.Empty(difference.Broken.Except(difference.Was.Unreadable)); Assert.Empty(difference.Worsened);
            }
        }
        finally { Directory.Delete(directory, true); }
    }

    [BabelMethodCorpusTheory]
    [InlineData("net48-combined", 9)]
    [InlineData("net8.0-combined", 9)]
    [InlineData("net10.0-combined", 9)]
    public void CombinedRecoveryRetiresOnlyUnusedLeaves(string id, int expectedRetired)
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelCombinedLeaves.").FullName;
        try
        {
            var input = Sample(id); using var original = ModuleDefMD.Load(input);
            var leaves = Leaves(original);
            var result = new CilantroPipeline().Run(input, new PipelineOptions(OutputPath: Path.Combine(directory, "cleaned.bin"), ReportDirectory: Path.Combine(directory, "reports")));
            Assert.True(result.Success);
            using var changes = JsonDocument.Parse(File.ReadAllText(result.ChangesReportPath));
            var removed = changes.RootElement.EnumerateArray().Where(change => change.GetProperty("Kind").GetString() == "remove-runtime-type")
                .Select(change => change.GetProperty("Location").GetString()!.Split(' ', 2)[1]).ToHashSet(StringComparer.Ordinal);
            Assert.Equal(expectedRetired, leaves.Count(type => removed.Contains(type.FullName)));
            Assert.All(leaves.Where(type => type.IsEnum), type => Assert.Contains(type.FullName, removed));
            if (id.StartsWith("net48-", StringComparison.Ordinal))
            {
                Assert.Contains(leaves.Single(type => type.Methods.Count != 0).FullName, removed);
                var difference = IlVerification.Against(IlVerification.Read(input), IlVerification.Read(result.OutputPath!));
                Assert.Empty(difference.Broken.Except(difference.Was.Unreadable)); Assert.Empty(difference.Worsened);
            }
        }
        finally { Directory.Delete(directory, true); }
    }

    [BabelMethodCorpusTheory]
    [InlineData("enum-constant")]
    [InlineData("enum-base-scope")]
    [InlineData("extra-field")]
    [InlineData("extra-method")]
    [InlineData("property")]
    [InlineData("parameter-name")]
    [InlineData("parameter-flags")]
    [InlineData("layout")]
    [InlineData("attribute")]
    [InlineData("buffer-body")]
    [InlineData("empty-buffer-body")]
    [InlineData("literal-name")]
    [InlineData("no-recovery")]
    [InlineData("no-read-proof")]
    public void ChangedDeclarationsAndMissingRecoveryProofRetainTheLeaves(string change)
    {
        using var context = ArtifactContext.Load(Sample("net8.0-code"));
        context.SetFact("options.removeRuntime", true); new BabelDetectionPass().Run(context);
        var leaves = Leaves(context.Module); Assert.Equal(9, leaves.Length);
        if (change is not ("no-recovery" or "no-read-proof")) Assert.Equal(PassStatus.Success, new BabelMethodImagePass().Run(context).Status);
        var enumeration = leaves.First(type => type.IsEnum);
        var buffer = leaves.Single(type => type.Methods.Count != 0);
        var parameter = buffer.Methods.First(method => method.ParamDefs.Count != 0).ParamDefs[0];
        switch (change)
        {
            case "enum-constant": enumeration.Fields.First(field => field.HasConstant).Constant.Value = 719; break;
            case "enum-base-scope": enumeration.BaseType = new TypeRefUser(context.Module, "System", "Enum", new AssemblyRefUser("Foreign.Framework", new Version(1, 0))); break;
            case "extra-field": enumeration.Fields.Add(new FieldDefUser("Extra", new FieldSig(context.Module.CorLibTypes.Int32), FieldAttributes.Private | FieldAttributes.Static)); break;
            case "extra-method":
                var extra = new MethodDefUser("Extra", MethodSig.CreateStatic(context.Module.CorLibTypes.Void), MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
                extra.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); enumeration.Methods.Add(extra); break;
            case "property": buffer.Properties.Add(new PropertyDefUser("Extra", PropertySig.CreateInstance(context.Module.CorLibTypes.Int32)) { GetMethod = buffer.Methods[0] }); break;
            case "parameter-name": parameter.Name = "Changed"; break;
            case "parameter-flags": parameter.Attributes ^= ParamAttributes.In; break;
            case "layout": leaves.First(type => type.IsValueType && !type.IsEnum).ClassLayout = new ClassLayoutUser(1, 8); break;
            case "attribute": buffer.CustomAttributes.Clear(); break;
            case "buffer-body": buffer.Methods[0].Body.Instructions.Insert(0, OpCodes.Break.ToInstruction()); break;
            case "empty-buffer-body": buffer.Methods[0].Body = new CilBody(); break;
            case "literal-name": AddRoot(context, [OpCodes.Ldstr.ToInstruction(enumeration.ReflectionFullName), OpCodes.Pop.ToInstruction()]); break;
            case "no-read-proof":
                context.SetFact("babel.methodImages.detected", 1); context.SetFact("babel.methodImages.restored", 1);
                BabelMethodLeafRuntime.Remember(context, context.Module, [Dispatcher(context.Module)], []); break;
        }
        BabelMethodLeafRuntime.Publish(context);
        Assert.All(leaves, type => Assert.DoesNotContain(type.MDToken.Raw, RecoveryOrphans.TypesOf(context)));
        Assert.Equal(PassStatus.Success, new RuntimeCleanupPass().Run(context).Status);
        Assert.All(leaves, type => Assert.Contains(type, context.Module.GetTypes()));
    }

    [BabelMethodCorpusTheory]
    [InlineData("handle")]
    [InlineData("construction")]
    [InlineData("field")]
    public void SurvivingConsumersRetainTheirReferencedLeaf(string consumer)
    {
        using var context = ArtifactContext.Load(Sample("net8.0-code"));
        context.SetFact("options.removeRuntime", true); new BabelDetectionPass().Run(context);
        var leaves = Leaves(context.Module);
        Assert.Equal(PassStatus.Success, new BabelMethodImagePass().Run(context).Status);
        var target = consumer == "construction" ? leaves.Single(type => type.Methods.Count != 0) : leaves.First(type => type.IsEnum);
        if (consumer == "handle") AddRoot(context, [OpCodes.Ldtoken.ToInstruction(target), OpCodes.Pop.ToInstruction()]);
        if (consumer == "construction") AddRoot(context, [OpCodes.Newobj.ToInstruction(target.FindInstanceConstructors().Single()), OpCodes.Pop.ToInstruction()]);
        if (consumer == "field") context.Module.EntryPoint.DeclaringType.Fields.Add(new FieldDefUser("SavedRuntimeValue", new FieldSig(target.ToTypeSig()), FieldAttributes.Private | FieldAttributes.Static));
        Assert.Equal(PassStatus.Success, new RuntimeCleanupPass().Run(context).Status);
        Assert.Contains(target, context.Module.GetTypes());
    }

    [BabelMethodCorpusTheory]
    [InlineData(true)]
    [InlineData(false)]
    public void ApplicationDeclarationsAndKeepRuntimeAreRespected(bool keepRuntime)
    {
        using var context = ArtifactContext.Load(Sample("net8.0-code"));
        context.SetFact("options.removeRuntime", !keepRuntime); new BabelDetectionPass().Run(context);
        var leaves = Leaves(context.Module);
        Assert.Equal(PassStatus.Success, new BabelMethodImagePass().Run(context).Status);
        var application = new TypeDefUser("App", "Unused", context.Module.CorLibTypes.Object.TypeDefOrRef) { Attributes = TypeAttributes.NotPublic };
        context.Module.Types.Add(application);
        Assert.Equal(PassStatus.Success, new RuntimeCleanupPass().Run(context).Status);
        Assert.Contains(application, context.Module.Types);
        if (keepRuntime) Assert.All(leaves, type => Assert.Contains(type, context.Module.GetTypes()));
        else Assert.All(leaves, type => Assert.DoesNotContain(type, context.Module.GetTypes()));
    }

    [BabelMethodCorpusFact]
    public void ChangedOriginalRuntimeMetadataCannotEstablishLeafOwnership()
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelMethodLeafInput.").FullName;
        try
        {
            var path = Path.Combine(directory, "changed.dll");
            using (var original = ModuleDefMD.Load(Sample("net8.0-code")))
            {
                var buffer = Leaves(original).Single(type => type.Methods.Count != 0);
                buffer.CustomAttributes[0].ConstructorArguments[0] = new CAArgument(original.CorLibTypes.String, "Changed");
                var options = new ModuleWriterOptions(original);
                options.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
                original.Write(path, options);
            }
            using var context = ArtifactContext.Load(path);
            context.SetFact("options.removeRuntime", true); new BabelDetectionPass().Run(context);
            var leaves = Leaves(context.Module);
            var recovered = new BabelMethodImagePass().Run(context);
            Assert.True(recovered.Status == PassStatus.Success, string.Join("; ", recovered.Diagnostics));
            BabelMethodLeafRuntime.Publish(context);
            Assert.All(leaves, type => Assert.DoesNotContain(type.MDToken.Raw, RecoveryOrphans.TypesOf(context)));
            Assert.Equal(PassStatus.Success, new RuntimeCleanupPass().Run(context).Status);
            Assert.All(leaves, type => Assert.Contains(type, context.Module.GetTypes()));
        }
        finally { Directory.Delete(directory, true); }
    }

    private static void AddRoot(ArtifactContext context, IEnumerable<Instruction> instructions)
    {
        var root = context.Module.GlobalType.FindOrCreateStaticConstructor();
        foreach (var instruction in instructions) root.Body.Instructions.Insert(root.Body.Instructions.Count - 1, instruction);
    }
}
