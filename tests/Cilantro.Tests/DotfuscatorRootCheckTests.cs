using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Corpus;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DotfuscatorRootCheckTests
{
    private static string Manifest => Path.Combine(Checkout.Root, "corpus", "dotfuscator-7-root-checks.manifest.json");
    private static string Root => Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_CHECK_SAMPLES")!;
    private static string Sample(string id) => Path.Combine(Root, CorpusRunner.LoadManifest(Manifest).Samples.Single(sample => sample.Id == id).LocalName);

    [Fact]
    public void ManifestPinsRealRootChecksAndBothStringCombinations()
    {
        var samples = CorpusRunner.LoadManifest(Manifest).Samples;
        Assert.Equal(7, samples.Count);
        Assert.Single(samples, sample => sample.Tier == "oracle");
        Assert.All(samples.Where(sample => sample.Tier == "profiled"), sample => Assert.Equal(1, sample.MinimumNeutralizedCheckSites));
        Assert.All(samples.Where(sample => sample.Id.EndsWith("-flow", StringComparison.Ordinal) || sample.Id.EndsWith("-native", StringComparison.Ordinal)),
            sample => Assert.Equal(1, sample.MinimumRecoveredStringSites));
    }

    [DotfuscatorCheckCorpusTheory]
    [InlineData("net10.0-root-none")]
    [InlineData("net10.0-root-method")]
    [InlineData("net10.0-root-exit")]
    [InlineData("net10.0-root-hang")]
    [InlineData("net10.0-root-flow")]
    [InlineData("net10.0-root-native")]
    public void CompleteReviewedGenericFamilySelectsCleanVerdict(string id)
    {
        using var context = ArtifactContext.Load(Sample(id));
        new DotfuscatorDetectionPass().Run(context);
        var runtime = Assert.Single(DotfuscatorCheckShape.Find(context.Module));
        Assert.Equal("root", runtime.Kind);
        Assert.Equal(11, runtime.Types.Count);
        Assert.Contains(runtime.Types, type => type.HasGenericParameters);
        Assert.NotEqual(64, GeneratedRuntimeShape.Read(runtime.Method).Fingerprint.Length);
        var attributes = runtime.Types.SelectMany(type => type.CustomAttributes).ToArray();
        var result = new DotfuscatorCheckPass().Run(context);
        Assert.True(result.Status == PassStatus.Success && result.Changes == 1, string.Join("; ", result.Diagnostics));
        Assert.Equal(attributes, runtime.Types.SelectMany(type => type.CustomAttributes));
        Assert.Collection(runtime.Method.Body.Instructions,
            instruction => Assert.Equal(unchecked((int)runtime.CleanVerdict), instruction.GetLdcI4Value()),
            instruction => Assert.Equal(Code.Ret, instruction.OpCode.Code));
        Assert.Equal(2, RetiredDotfuscatorRootRuntime.Unused(context).Count());
        Assert.Equal(id.EndsWith("-flow", StringComparison.Ordinal) || id.EndsWith("-native", StringComparison.Ordinal) ? 1 : 2,
            RetiredDotfuscatorRootRuntime.UnusedHelpers(context).Count());
        Assert.DoesNotContain(context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody)
            .SelectMany(method => method.Body.Instructions), instruction => instruction.OpCode.Code == Code.Call &&
                instruction.Operand is IMethod called && called.ResolveMethodDef() == runtime.Method);
    }

    [DotfuscatorCheckCorpusTheory]
    [InlineData("net10.0-root-none", 0)]
    [InlineData("net10.0-root-method", 2)]
    [InlineData("net10.0-root-exit", 2)]
    [InlineData("net10.0-root-hang", 2)]
    public void CleanSelectionPreservesApplicationNotificationCounts(string id, int notifications)
    {
        using var context = ArtifactContext.Load(Sample(id));
        new DotfuscatorDetectionPass().Run(context);
        Assert.Equal(PassStatus.Success, new DotfuscatorCheckPass().Run(context).Status);
        var host = context.Module.GetTypes().Single(type => type.FullName == "RootCheckProbe.Program");
        var guarded = host.Methods.Single(method => method.Name == "Guarded");
        Assert.True(BootstrapMachine.TrySeed(context, 100_000, out var machine, out var why), why);
        var first = machine!.Execute(guarded, [StaticValue.FromInt32(3)]);
        var second = machine.Execute(guarded, [StaticValue.FromInt32(7)]);
        Assert.True(first.Succeeded, first.Diagnostic); Assert.True(second.Succeeded, second.Diagnostic);
        Assert.Equal(54, first.Value.AsInt32()); Assert.Equal(122, second.Value.AsInt32());
        Assert.Equal(notifications, machine.State.ReadStaticField(host.Fields.Single(field => field.Name == "notifications")).AsInt32());
        Assert.Equal(0, machine.State.ReadStaticField(host.Fields.Single(field => field.Name == "detected")).AsInt32());
    }

    [DotfuscatorCheckCorpusTheory]
    [InlineData("verdict")]
    [InlineData("field")]
    [InlineData("generic-flags")]
    [InlineData("generic-name")]
    [InlineData("constraint")]
    [InlineData("attribute")]
    [InlineData("base-scope")]
    [InlineData("method-flags")]
    [InlineData("initializer")]
    [InlineData("effect")]
    public void ChangedFamiliesRetainAllBodiesAndWithholdEmission(string change)
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.RootCheckRefusal.").FullName;
        try
        {
            var path = Path.Combine(directory, "RootCheckProbe.dll");
            using (var module = ModuleDefMD.Load(Sample("net10.0-root-method")))
            {
                var runtime = Assert.Single(DotfuscatorCheckShape.Find(module));
                var generic = runtime.Types.Single(type => type.HasGenericParameters);
                if (change == "verdict") runtime.Method.Body.Instructions.First(instruction => instruction.IsLdcI4() && instruction.GetLdcI4Value() == -1577367022).Operand = 0;
                if (change == "field") runtime.Method.DeclaringType.Fields.Add(new FieldDefUser("Unreviewed", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Private | FieldAttributes.Static));
                if (change == "generic-flags") generic.GenericParameters[0].Flags = GenericParamAttributes.Covariant;
                if (change == "generic-name") generic.GenericParameters[0].Name = "Changed";
                if (change == "constraint") generic.GenericParameters[0].GenericParamConstraints.Add(new GenericParamConstraintUser(module.CorLibTypes.Object.TypeDefOrRef));
                if (change == "attribute")
                {
                    var type = runtime.Types.First(type => type.CustomAttributes.Any(attribute => attribute.TypeFullName == "System.Runtime.CompilerServices.NullableContextAttribute"));
                    var attribute = type.CustomAttributes.Single(attribute => attribute.TypeFullName == "System.Runtime.CompilerServices.NullableContextAttribute");
                    attribute.ConstructorArguments[0] = new CAArgument(module.CorLibTypes.Byte, (byte)2);
                }
                if (change == "base-scope") runtime.Types.Single(type => type.BaseType?.FullName == "_Microsoft.Android.Resource.Designer.Resource").BaseType =
                    new TypeRefUser(module, "_Microsoft.Android.Resource.Designer", "Resource", new AssemblyRefUser("Foreign"));
                if (change == "method-flags") runtime.Method.ImplAttributes |= MethodImplAttributes.NoInlining;
                if (change == "initializer")
                {
                    var initializer = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                        MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() };
                    runtime.Method.DeclaringType.Methods.Add(initializer); initializer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                }
                if (change == "effect")
                {
                    var notification = module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "OnCheck");
                    runtime.Method.Body.Instructions.Insert(0, OpCodes.Ldc_I4_1.ToInstruction());
                    runtime.Method.Body.Instructions.Insert(1, OpCodes.Call.ToInstruction(notification));
                }
                module.Write(path);
            }
            using var context = ArtifactContext.Load(path);
            new DotfuscatorDetectionPass().Run(context);
            var before = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody).ToDictionary(method => method, MethodBodySnapshot.Capture);
            var result = new DotfuscatorCheckPass().Run(context);
            Assert.Equal(PassStatus.Unsupported, result.Status); Assert.Equal(0, result.Changes);
            Assert.All(before, pair => Assert.True(pair.Value.StructurallyEquals(pair.Key)));
            Assert.Empty(context.Changes);
            var pipeline = new CilantroPipeline().Run(path, new PipelineOptions(OutputPath: Path.Combine(directory, "cleaned.dll"), ReportDirectory: Path.Combine(directory, "reports")));
            Assert.False(pipeline.Success); Assert.Null(pipeline.OutputPath);
        }
        finally { Directory.Delete(directory, true); }
    }

    [DotfuscatorCheckCorpusFact]
    public void PublicLeafRetirementRejectsLaterBodyOrMetadataChanges()
    {
        foreach (var change in new[] { "body", "metadata", "reflection" })
        {
            using var context = ArtifactContext.Load(Sample("net10.0-root-method"));
            new DotfuscatorDetectionPass().Run(context);
            Assert.Equal(PassStatus.Success, new DotfuscatorCheckPass().Run(context).Status);
            var leaves = RetiredDotfuscatorRootRuntime.Unused(context).ToArray();
            Assert.Equal(2, leaves.Length);
            var type = leaves.Single(type => type.Name == "PreserveAttribute");
            if (change == "metadata") type.Attributes ^= TypeAttributes.Sealed;
            else if (change == "body")
            {
                var body = type.Methods.Single(method => method.IsConstructor).Body;
                body.Instructions.Insert(0, OpCodes.Ldstr.ToInstruction("changed"));
                body.Instructions.Insert(1, OpCodes.Call.ToInstruction(new Importer(context.Module).Import(typeof(Console).GetMethod(nameof(Console.WriteLine), [typeof(string)])!)));
            }
            else
            {
                context.Module.EntryPoint.Body.Instructions.Insert(0, OpCodes.Ldstr.ToInstruction(type.ReflectionFullName));
                context.Module.EntryPoint.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
            }
            Assert.Empty(RetiredDotfuscatorRootRuntime.Unused(context));
        }
    }

    [DotfuscatorCheckCorpusTheory]
    [InlineData("handle")]
    [InlineData("field")]
    [InlineData("attribute")]
    public void SurvivingConsumersKeepReviewedPublicLeaves(string use)
    {
        using var context = ArtifactContext.Load(Sample("net10.0-root-method"));
        new DotfuscatorDetectionPass().Run(context);
        Assert.Equal(PassStatus.Success, new DotfuscatorCheckPass().Run(context).Status);
        var leaves = RetiredDotfuscatorRootRuntime.Unused(context).ToHashSet();
        Assert.Equal(2, leaves.Count);
        var type = leaves.Single(type => type.Name == "PreserveAttribute");
        var host = context.Module.EntryPoint.DeclaringType;
        if (use == "handle")
        {
            context.Module.EntryPoint.Body.Instructions.Insert(0, OpCodes.Ldtoken.ToInstruction(type));
            context.Module.EntryPoint.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
        }
        else if (use == "field") host.Fields.Add(new FieldDefUser("ApplicationState", new FieldSig(new ClassSig(type)), FieldAttributes.Public | FieldAttributes.Static));
        else host.CustomAttributes.Add(new CustomAttribute(type.Methods.Single(method => method.IsConstructor)));
        var survivors = context.Module.GetTypes().Where(candidate => !leaves.Contains(candidate)).ToArray();
        Assert.Contains(type, RuntimeCleanupPass.CollectReferencedCandidates(context.Module, survivors, leaves));
    }

    [DotfuscatorCheckCorpusFact]
    public void FullPipelineMeetsAllSixRootCheckContracts()
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.RootCheckCorpus.").FullName;
        try
        {
            var result = CorpusRunner.Run(Manifest, Root, directory);
            Assert.True(result.Passed == 6 && result.Failed == 0 && result.Missing == 0,
                JsonSerializer.Serialize(result.Samples.Where(sample => sample.Status != "passed"), CilantroPipeline.ReportJsonOptions));
            foreach (var sample in result.Samples)
            {
                using var output = ModuleDefMD.Load(Path.Combine(directory, sample.Id, "cleaned.bin"));
                Assert.DoesNotContain(output.GetTypes(), type => type.BaseType?.FullName == "System.Exception");
                Assert.DoesNotContain(output.GetTypes(), type => type.FullName is "XamarinRootChecker.PreserveAttribute" or "XamarinRootChecker.Resource");
                Assert.DoesNotContain(output.GetTypes(), type => type.FullName == "PreEmptive.Protection.Checks.Android.Runtime.Root.PlatformClass1");
                Assert.DoesNotContain(output.GetTypes().SelectMany(type => type.Methods), method =>
                    method.MethodSig.Params.FirstOrDefault()?.FullName == "Microsoft.Maui.Controls.BindingMode");
            }
        }
        finally { Directory.Delete(directory, true); }
    }
}
