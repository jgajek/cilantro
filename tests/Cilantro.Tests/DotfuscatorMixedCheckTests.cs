using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Corpus;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DotfuscatorMixedCheckTests
{
    private static string Manifest => Path.Combine(Checkout.Root, "corpus", "dotfuscator-7-check-interactions.manifest.json");
    private static string Sample(string id) => Path.Combine(Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_CHECK_INTERACTION_SAMPLES")!,
        CorpusRunner.LoadManifest(Manifest).Samples.Single(sample => sample.Id == id).LocalName);

    [Fact]
    public void InteractionManifestRequiresChecksStringsAndDispatcherRecovery()
    {
        var samples = CorpusRunner.LoadManifest(Manifest).Samples;
        Assert.Equal(12, samples.Count);
        Assert.Equal(3, samples.Count(sample => sample.Tier == "oracle"));
        foreach (var sample in samples.Where(sample => sample.Tier != "oracle"))
        {
            Assert.Equal(2, sample.MinimumNeutralizedCheckSites);
            Assert.True(sample.RequireOracleResourceParity);
            Assert.Equal(0, sample.MaximumRemainingSwitchDispatchers);
            if (!sample.Id.EndsWith("flow", StringComparison.Ordinal)) Assert.True(sample.MinimumRecoveredStringSites >= 4);
        }
    }

    [DotfuscatorMixedCheckTheory]
    [InlineData("net48-combined-flow")]
    [InlineData("net48-combined-renamed")]
    [InlineData("net48-combined-native")]
    [InlineData("net8.0-combined-flow")]
    [InlineData("net8.0-combined-renamed")]
    [InlineData("net8.0-combined-native")]
    [InlineData("net10.0-combined-flow")]
    [InlineData("net10.0-combined-renamed")]
    [InlineData("net10.0-combined-native")]
    public void MixedFamiliesReachReviewedCompleteGraphs(string id)
    {
        using var context = ArtifactContext.Load(Sample(id));
        new DotfuscatorDetectionPass().Run(context);
        Assert.All(DotfuscatorCheckShape.Find(context.Module), runtime => Assert.False(DotfuscatorCheckShape.Supported(runtime)));
        var result = new DotfuscatorCheckPass().Run(context);
        Assert.True(result.Status == PassStatus.Success, string.Join("; ", result.Diagnostics));
        Assert.Equal(2, result.Changes);
        Assert.True(context.TryGetFact<Dictionary<uint, string>>("dotfuscator.checks.normalizedGraphs", out var graphs));
        Assert.Equal(3, graphs!.Count);
        Assert.All(graphs.Values, fingerprint => Assert.True(DotfuscatorCheckNormalization.Reviewed(fingerprint)));
    }

    [DotfuscatorMixedCheckFact]
    [Trait(Cost.Key, Cost.High)]
    public void InteractionCorpusRecoversWithoutNewFrameworkVerifierFindings()
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.MixedChecks.").FullName;
        try
        {
            var root = Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_CHECK_INTERACTION_SAMPLES")!;
            var outcome = CorpusRunner.Run(Manifest, root, directory);
            Assert.True(outcome.Passed == 9 && outcome.Failed == 0 && outcome.Missing == 0,
                JsonSerializer.Serialize(outcome.Samples.Where(sample => sample.Status != "passed"), CilantroPipeline.ReportJsonOptions));
            foreach (var sample in outcome.Samples)
            {
                using var output = ModuleDefMD.Load(Path.Combine(directory, sample.Id, "cleaned.bin"));
                Assert.DoesNotContain(output.GetTypes(), type => type.BaseType?.FullName == "System.Exception");
            }
            foreach (var sample in CorpusRunner.LoadManifest(Manifest).Samples.Where(sample => sample.Tier != "oracle" && sample.Id.StartsWith("net48", StringComparison.Ordinal)))
            {
                var difference = IlVerification.Against(IlVerification.Read(Path.Combine(root, sample.LocalName)),
                    IlVerification.Read(Path.Combine(directory, sample.Id, "cleaned.bin")));
                Assert.Empty(difference.Broken.Except(difference.Was.Unreadable));
                Assert.True(difference.Worsened.Count == 0, sample.Id + ": " + difference.Describe());
            }
        }
        finally { Directory.Delete(directory, true); }
    }

    [DotfuscatorMixedCheckTheory]
    [InlineData("call")]
    [InlineData("import")]
    [InlineData("layout")]
    [InlineData("dispatch")]
    [InlineData("exception")]
    [InlineData("marker-use")]
    [InlineData("marker-type")]
    [InlineData("bounds")]
    public void ChangedMixedFamiliesRefuseWithoutMutatingAnyCheck(string change)
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.MixedCheckRefusal.").FullName;
        try
        {
            var path = Path.Combine(directory, "CheckProbe.exe");
            using (var module = ModuleDefMD.Load(Sample("net48-combined-flow")))
            {
                var checks = DotfuscatorCheckShape.Find(module).ToArray();
                var debug = checks.Single(check => check.Kind == "debugging");
                var tamper = checks.Single(check => check.Kind == "tamper-file");
                if (change == "call") debug.Method.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(new MemberRefUser(module, "Collect",
                    MethodSig.CreateStatic(module.CorLibTypes.Void), new TypeRefUser(module, "System", "GC", module.CorLibTypes.AssemblyRef))));
                if (change == "import") debug.Types.SelectMany(type => type.Methods).First(method => method.IsPinvokeImpl).ImplMap.Name = "UnreviewedProbe";
                if (change == "layout") debug.Types.First(type => type.IsValueType).ClassSize++;
                if (change == "dispatch") tamper.Types.SelectMany(type => type.Methods).First(method => method.IsVirtual).Name = "UnknownDispatch";
                if (change == "exception") debug.Types.SelectMany(type => type.Methods).First(method => method.HasBody && method.Body.HasExceptionHandlers)
                    .Body.ExceptionHandlers.First().CatchType = new TypeRefUser(module, "System", "ArgumentException", module.CorLibTypes.AssemblyRef);
                if (change.StartsWith("marker-", StringComparison.Ordinal))
                {
                    var field = debug.Method.DeclaringType.Fields.Single(field => field.Attributes == (FieldAttributes)32897);
                    if (change == "marker-type") field.FieldSig = new FieldSig(module.CorLibTypes.Int32);
                    else { debug.Method.Body.Instructions.Insert(0, OpCodes.Ldtoken.ToInstruction(field)); debug.Method.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction()); }
                }
                if (change == "bounds") for (var index = 0; index < 4097; index++) debug.Method.Body.Instructions.Insert(0, OpCodes.Nop.ToInstruction());
                module.Write(path);
            }
            using var context = ArtifactContext.Load(path);
            new DotfuscatorDetectionPass().Run(context);
            var snapshots = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody).ToDictionary(method => method, MethodBodySnapshot.Capture);
            var result = new DotfuscatorCheckPass().Run(context);
            Assert.Equal(PassStatus.Unsupported, result.Status);
            Assert.Equal(0, result.Changes);
            Assert.All(snapshots, item => Assert.True(item.Value.StructurallyEquals(item.Key)));
            Assert.Empty(context.Changes);
            if (change == "call")
            {
                var pipeline = new CilantroPipeline().Run(path, new PipelineOptions(OutputPath: Path.Combine(directory, "cleaned.exe"), ReportDirectory: Path.Combine(directory, "reports")));
                Assert.False(pipeline.Success);
                Assert.Null(pipeline.OutputPath);
            }
        }
        finally { Directory.Delete(directory, true); }
    }
}

public sealed class DotfuscatorMixedCheckFactAttribute : FactAttribute
{
    public DotfuscatorMixedCheckFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_CHECK_INTERACTION_SAMPLES") is not { Length: > 0 })
            Skip = "Set CILANTRO_DOTFUSCATOR_CHECK_INTERACTION_SAMPLES to the combined-protection check corpus.";
    }
}

public sealed class DotfuscatorMixedCheckTheoryAttribute : TheoryAttribute
{
    public DotfuscatorMixedCheckTheoryAttribute()
    {
        if (Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_CHECK_INTERACTION_SAMPLES") is not { Length: > 0 })
            Skip = "Set CILANTRO_DOTFUSCATOR_CHECK_INTERACTION_SAMPLES to the combined-protection check corpus.";
    }
}
