using System.Security.Cryptography;
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

public sealed class DotfuscatorCheckTests
{
    private static string Samples => Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_CHECK_SAMPLES")!;
    private static string ManifestPath => Path.Combine(Checkout.Root, "corpus", "dotfuscator-7-checks.manifest.json");
    private static string Sample(string id) => Path.Combine(Samples, CorpusRunner.LoadManifest(ManifestPath).Samples.Single(sample => sample.Id == id).LocalName);

    [Fact]
    public void CheckManifestRequiresMeasuredRecoveryAcrossFrameworksAndSinkKinds()
    {
        var samples = CorpusRunner.LoadManifest(ManifestPath).Samples;
        Assert.Equal(33, samples.Count);
        Assert.Equal(3, samples.Count(sample => sample.Tier == "oracle"));
        Assert.All(samples.Where(sample => sample.Tier != "oracle"), sample => Assert.Equal(
            sample.Id.Contains("combined", StringComparison.Ordinal) ? 2 : 1, sample.MinimumNeutralizedCheckSites));
        foreach (var sink in new[] { "method", "field", "property", "delegate", "none", "exit", "hang", "probability" })
            Assert.Equal(3, samples.Count(sample => sample.Id.EndsWith("debug-" + sink, StringComparison.Ordinal)));
    }

    [DotfuscatorCheckCorpusFact]
    [Trait(Cost.Key, Cost.High)]
    public void CheckCorpusNeutralizesAllSitesWithoutNewFrameworkVerifierFindings()
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.DotfuscatorChecks.").FullName;
        try
        {
            var outcome = CorpusRunner.Run(ManifestPath, Samples, directory);
            Assert.True(outcome.Passed == 30 && outcome.Failed == 0 && outcome.Missing == 0,
                JsonSerializer.Serialize(new { outcome.Passed, outcome.Failed, outcome.Missing,
                    Problems = outcome.Samples.Where(sample => sample.Status != "passed").Select(sample => new { sample.Id, sample.Diagnostics }) }, CilantroPipeline.ReportJsonOptions));
            foreach (var sample in CorpusRunner.LoadManifest(ManifestPath).Samples.Where(sample => sample.Tier != "oracle"))
            {
                Assert.Contains(outcome.Samples.Single(entry => entry.Id == sample.Id).Passes, pass => pass.Pass == "dotfuscator-checks" &&
                    pass.Status == PassStatus.Success && pass.Changes == sample.MinimumNeutralizedCheckSites);
                var output = Path.Combine(directory, sample.Id, "cleaned.bin");
                using var module = ModuleDefMD.Load(output);
                Assert.DoesNotContain(module.GetTypes(), type => type.BaseType?.FullName == "System.Exception");
                var guarded = module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Guarded");
                Assert.DoesNotContain(guarded.Body.Instructions, instruction => instruction.Operand is IMethod called &&
                    (called.DeclaringType?.Namespace == "PreEmptive.SoS.Runtime" || called.DeclaringType?.FullName == "System.Action"));
                if (sample.Id.EndsWith("probability", StringComparison.Ordinal))
                    Assert.DoesNotContain(guarded.Body.Instructions, instruction => instruction.Operand is IMethod called &&
                        called.DeclaringType?.FullName == "System.Security.Cryptography.RandomNumberGenerator");
                if (!sample.Id.StartsWith("net48", StringComparison.Ordinal)) continue;
                var difference = IlVerification.Against(IlVerification.Read(Path.Combine(Samples, sample.LocalName)), IlVerification.Read(output));
                Assert.Empty(difference.Broken.Except(difference.Was.Unreadable));
                Assert.True(difference.Worsened.Count == 0, sample.Id + ": " + difference.Describe());
            }
        }
        finally { Directory.Delete(directory, true); }
    }

    [DotfuscatorCheckCorpusTheory]
    [InlineData("net48-debug-method", 2)]
    [InlineData("net48-tamper-method", 2)]
    [InlineData("net48-combined-method", 4)]
    public void CleanVerdictsRetainApplicationCallbackCounts(string id, int notifications)
    {
        using var context = ArtifactContext.Load(Sample(id));
        new DotfuscatorDetectionPass().Run(context);
        Assert.Equal(PassStatus.Success, new DotfuscatorCheckPass().Run(context).Status);
        var host = context.Module.GetTypes().Single(type => type.FullName == "CheckProbe.Program");
        var guarded = host.Methods.Single(method => method.Name == "Guarded");
        Assert.True(BootstrapMachine.TrySeed(context, 100_000, out var machine, out var why), why);
        var first = machine!.Execute(guarded, [StaticValue.FromInt32(3)]);
        Assert.True(first.Succeeded, first.Diagnostic);
        Assert.Equal(54, first.Value.AsInt32());
        var second = machine.Execute(guarded, [StaticValue.FromInt32(7)]);
        Assert.True(second.Succeeded, second.Diagnostic);
        Assert.Equal(122, second.Value.AsInt32());
        Assert.Equal(notifications, machine.State.ReadStaticField(host.Fields.Single(field => field.Name == "notifications")).AsInt32());
        Assert.Equal(0, machine.State.ReadStaticField(host.Fields.Single(field => field.Name == "detected")).AsInt32());
    }

    [DotfuscatorCheckCorpusTheory]
    [InlineData("instructions")]
    [InlineData("import")]
    [InlineData("layout")]
    [InlineData("bounds")]
    [InlineData("dispatch")]
    public void ChangedCheckerFamiliesDeclineAndWithholdEmission(string change)
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.DotfuscatorCheckRefusal.").FullName;
        try
        {
            var path = Path.Combine(directory, "CheckProbe.exe");
            using (var module = ModuleDefMD.Load(Sample(change == "dispatch" ? "net48-tamper-method" : "net48-debug-method")))
            {
                var runtime = DotfuscatorCheckShape.Find(module).First();
                if (change == "instructions") runtime.Method.Body.Instructions.Insert(0, OpCodes.Nop.ToInstruction());
                if (change == "import") runtime.Types.SelectMany(type => type.Methods).First(method => method.IsPinvokeImpl).ImplMap.Attributes = PInvokeAttributes.CallConvCdecl;
                if (change == "layout") runtime.Types.First(type => type.IsValueType).ClassSize++;
                if (change == "dispatch") runtime.Types.SelectMany(type => type.Methods).First(method => method.IsVirtual).Name = "UnknownDispatch";
                if (change == "bounds")
                    for (var index = 0; index < 4097; index++) runtime.Method.Body.Instructions.Insert(0, OpCodes.Nop.ToInstruction());
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
            var pipeline = new CilantroPipeline().Run(path, new PipelineOptions(OutputPath: Path.Combine(directory, "cleaned.exe"), ReportDirectory: Path.Combine(directory, "reports")));
            Assert.False(pipeline.Success);
            Assert.Null(pipeline.OutputPath);
        }
        finally { Directory.Delete(directory, true); }
    }

    [DotfuscatorCheckCorpusFact]
    public void MetadataGetterEffectsAndEscapingResponseArraysArePreserved()
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.DotfuscatorCheckEffects.").FullName;
        try
        {
            var path = Path.Combine(directory, "CheckProbe.exe");
            using (var module = ModuleDefMD.Load(Sample("net48-tamper-method")))
            {
                var host = module.GetTypes().Single(type => type.FullName == "CheckProbe.Program");
                var getter = host.Methods.Single(method => method.ReturnType.FullName == "System.String[]");
                getter.Body.Instructions.Insert(0, OpCodes.Ldc_I4_0.ToInstruction());
                getter.Body.Instructions.Insert(1, OpCodes.Call.ToInstruction(host.Methods.Single(method => method.Name == "OnCheck")));
                var guarded = host.Methods.Single(method => method.Name == "Guarded");
                var response = guarded.Body.Variables.Single(local => local.Type.FullName == "System.Action[]");
                var at = guarded.Body.Instructions.Count - 1;
                guarded.Body.Instructions.Insert(at, OpCodes.Ldloc.ToInstruction(response));
                guarded.Body.Instructions.Insert(at + 1, OpCodes.Pop.ToInstruction());
                module.Write(path);
            }
            using var context = ArtifactContext.Load(path);
            new DotfuscatorDetectionPass().Run(context);
            var application = context.Module.GetTypes().Single(type => type.FullName == "CheckProbe.Program");
            var metadata = application.Methods.Single(method => method.ReturnType.FullName == "System.String[]");
            var snapshot = MethodBodySnapshot.Capture(metadata);
            Assert.Equal(PassStatus.Success, new DotfuscatorCheckPass().Run(context).Status);
            Assert.True(snapshot.StructurallyEquals(metadata));
            var caller = application.Methods.Single(method => method.Name == "Guarded");
            Assert.Contains(caller.Body.Instructions, instruction => instruction.Operand is IMethod called && called.ResolveMethodDef() == metadata);
            Assert.Contains(caller.Body.Instructions, instruction => instruction.OpCode.Code == Code.Newarr && instruction.Operand is ITypeDefOrRef { FullName: "System.Action" });
            Assert.True(EvaluationStackAnalyzer.Analyze(caller).Valid);
        }
        finally { Directory.Delete(directory, true); }
    }

    [DotfuscatorCheckCorpusTheory]
    [InlineData(false)]
    [InlineData(true)]
    public void ApplicationWritesAndResponseEffectsPreventScaffoldingRemoval(bool responseEffect)
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.DotfuscatorCheckFlow.").FullName;
        try
        {
            var path = Path.Combine(directory, "CheckProbe.exe");
            using (var module = ModuleDefMD.Load(Sample(responseEffect ? "net48-debug-probability" : "net48-debug-method")))
            {
                var host = module.GetTypes().Single(type => type.FullName == "CheckProbe.Program");
                if (responseEffect)
                {
                    var response = host.Methods.Single(method => method.Name.String.StartsWith("<>sos__DEB", StringComparison.Ordinal) &&
                        method.HasBody && method.Body.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop).All(instruction => instruction.OpCode.Code == Code.Ret));
                    response.Body.Instructions.Insert(0, OpCodes.Ldc_I4_0.ToInstruction());
                    response.Body.Instructions.Insert(1, OpCodes.Call.ToInstruction(host.Methods.Single(method => method.Name == "OnCheck")));
                }
                else
                {
                    var guarded = host.Methods.Single(method => method.Name == "Guarded");
                    var store = guarded.Body.Instructions.First(instruction => instruction.IsStloc());
                    var verdict = store.GetLocal(guarded.Body.Variables);
                    var dispatch = guarded.Body.Instructions.First(instruction => instruction.OpCode.Code == Code.Newarr && instruction.Operand is ITypeDefOrRef { FullName: "System.Action" });
                    var at = guarded.Body.Instructions.IndexOf(dispatch) - 1;
                    var target = guarded.Body.Instructions[at];
                    foreach (var instruction in new[] { OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Bge.ToInstruction(target),
                                 OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Stloc.ToInstruction(verdict) }) guarded.Body.Instructions.Insert(at++, instruction);
                }
                module.Write(path);
            }
            using var context = ArtifactContext.Load(path);
            new DotfuscatorDetectionPass().Run(context);
            Assert.Equal(PassStatus.Success, new DotfuscatorCheckPass().Run(context).Status);
            var caller = context.Module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Guarded");
            if (responseEffect)
                Assert.Contains(caller.Body.Instructions, instruction => instruction.Operand is IMethod called && called.DeclaringType?.FullName == "System.Security.Cryptography.RandomNumberGenerator");
            else
                Assert.Contains(caller.Body.Instructions, instruction => instruction.OpCode.Code == Code.Newarr && instruction.Operand is ITypeDefOrRef { FullName: "System.Action" });
            Assert.True(EvaluationStackAnalyzer.Analyze(caller).Valid);
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public void CheckRecoveryGateCannotPassAnUnprotectedInput()
    {
        using var context = SyntheticContext.Build(_ => { });
        var directory = Directory.CreateTempSubdirectory("Cilantro.CheckCorpusGate.").FullName;
        try
        {
            var bytes = context.OriginalBytes;
            var hash = Convert.ToHexStringLower(SHA256.HashData(bytes));
            File.WriteAllBytes(Path.Combine(directory, "input.dll"), bytes);
            var manifest = new CorpusManifest(1, "negative-check-gate", "Unprotected input cannot satisfy a check-recovery gate.",
                [new CorpusSample("input", "detected", hash, "input.dll", "none", [], null, MinimumNeutralizedCheckSites: 1)]);
            var path = Path.Combine(directory, "manifest.json");
            File.WriteAllText(path, JsonSerializer.Serialize(manifest, CilantroPipeline.ReportJsonOptions));
            var outcome = CorpusRunner.Run(path, directory, Path.Combine(directory, "results"));
            Assert.Equal(1, outcome.Failed);
            Assert.Contains(Assert.Single(outcome.Samples).Diagnostics, note => note.Contains("Neutralized check sites 0 is below 1", StringComparison.Ordinal));
        }
        finally { Directory.Delete(directory, true); }
    }
}

public sealed class DotfuscatorCheckCorpusFactAttribute : FactAttribute
{
    public DotfuscatorCheckCorpusFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_CHECK_SAMPLES") is not { Length: > 0 })
            Skip = "Set CILANTRO_DOTFUSCATOR_CHECK_SAMPLES to the hash-pinned check corpus directory.";
    }
}

public sealed class DotfuscatorCheckCorpusTheoryAttribute : TheoryAttribute
{
    public DotfuscatorCheckCorpusTheoryAttribute()
    {
        if (Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_CHECK_SAMPLES") is not { Length: > 0 })
            Skip = "Set CILANTRO_DOTFUSCATOR_CHECK_SAMPLES to the hash-pinned check corpus directory.";
    }
}
