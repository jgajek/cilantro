using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Corpus;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.PE;

namespace Cilantro.Tests;

public sealed class DotfuscatorX86CorpusTests
{
    private static string Manifest => Path.Combine(Checkout.Root, "corpus", "dotfuscator-7-native-x86.manifest.json");
    private static string Samples => Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_V2_SAMPLES")!;

    [Fact]
    public void ManifestPinsIndependentX86Captures()
    {
        var samples = CorpusRunner.LoadManifest(Manifest).Samples;
        Assert.Equal(8, samples.Count);
        Assert.Equal(2, samples.Count(sample => sample.Tier == "oracle"));
        Assert.All(samples.Where(sample => sample.Tier != "oracle"), sample =>
        {
            Assert.Equal(17, sample.MinimumRecoveredStringSites);
            Assert.Equal(0, sample.MaximumRemainingSwitchDispatchers);
            Assert.Equal(0, sample.MaximumUnreachableInstructions);
            Assert.True(sample.RequireOracleResourceParity);
        });
    }

    [DotfuscatorV2CorpusFact]
    public void X86CapturesRecoverAndRetireTheirNativeBridge()
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.DotfuscatorX86.").FullName;
        try
        {
            var manifest = CorpusRunner.LoadManifest(Manifest);
            var outcome = CorpusRunner.Run(Manifest, Samples, directory);
            Assert.True(outcome.Passed == 6 && outcome.Failed == 0 && outcome.Missing == 0,
                JsonSerializer.Serialize(outcome.Samples.Where(sample => sample.Status != "passed"), CilantroPipeline.ReportJsonOptions));
            foreach (var sample in manifest.Samples.Where(sample => sample.Tier != "oracle"))
            {
                var input = Path.Combine(Samples, sample.LocalName);
                var output = Path.Combine(directory, sample.Id, "cleaned.bin");
                using var original = ModuleDefMD.Load(input);
                using var cleaned = ModuleDefMD.Load(output);
                Assert.Equal(Machine.I386, original.Machine);
                Assert.True(original.Is32BitRequired);
                Assert.Equal(original.Machine, cleaned.Machine);
                Assert.Equal(original.Cor20HeaderFlags, cleaned.Cor20HeaderFlags);
                Assert.DoesNotContain(cleaned.GetTypes(), type => type.FullName == "PreEmptive.Protection.Runtime.Native.NativeCPP");
                Assert.DoesNotContain(cleaned.GetTypes().SelectMany(type => type.Methods), method => method.ImplMap?.Module.Name.String is "Runtime.Extensions" or "Runtime.Extensions.dll");
                if (sample.Id.StartsWith("net48-", StringComparison.Ordinal))
                {
                    var difference = IlVerification.Against(IlVerification.Read(input), IlVerification.Read(output));
                    Assert.Empty(difference.Broken.Except(difference.Was.Unreadable));
                    Assert.Empty(difference.Worsened);
                }
            }
        }
        finally { Directory.Delete(directory, true); }
    }

    [DotfuscatorV2CorpusTheory]
    [InlineData("missing-x86")]
    [InlineData("x64-in-x86-path")]
    [InlineData("tampered-x86")]
    [InlineData("unknown-machine")]
    [InlineData("x64-with-only-x86")]
    [InlineData("anycpu-tampered-x86")]
    public void ArchitectureAndNativeIdentityFailuresWithholdOutput(string failure)
    {
        var source = Path.GetDirectoryName(Path.Combine(Samples, CorpusRunner.LoadManifest(Manifest).Samples.Single(sample => sample.Id == "net48-native-x86-strings").LocalName))!;
        var directory = Directory.CreateTempSubdirectory("Cilantro.DotfuscatorX86Refusal.").FullName;
        try
        {
            foreach (var file in Directory.GetFiles(source, "*", SearchOption.AllDirectories))
            {
                var target = Path.Combine(directory, Path.GetRelativePath(source, file));
                Directory.CreateDirectory(Path.GetDirectoryName(target)!); File.Copy(file, target);
            }
            var path = Path.Combine(directory, "Probe.exe");
            var x86 = Path.Combine(directory, "runtimes", "win-x86", "native", "Runtime.Extensions.dll");
            var x64Source = Path.Combine(Samples, "dotfuscator-v2", "net48-strings", "runtimes", "win-x64", "native", "Runtime.Extensions.dll");
            var x64 = Path.Combine(directory, "runtimes", "win-x64", "native", "Runtime.Extensions.dll");
            Directory.CreateDirectory(Path.GetDirectoryName(x64)!); File.Copy(x64Source, x64);
            if (failure == "missing-x86") File.Delete(x86);
            if (failure == "x64-in-x86-path") File.Copy(x64Source, x86, true);
            if (failure is "tampered-x86" or "anycpu-tampered-x86") File.WriteAllBytes(x86, [0]);
            if (failure == "x64-with-only-x86") File.Delete(x64);
            if (failure is "unknown-machine" or "anycpu-tampered-x86" or "x64-with-only-x86")
            {
                using var changed = ModuleDefMD.Load(path);
                if (failure == "unknown-machine") changed.Machine = Machine.ARMNT;
                else changed.Is32BitRequired = false;
                if (failure == "x64-with-only-x86") changed.Machine = Machine.AMD64;
                changed.Write(path + ".changed");
            }
            if (File.Exists(path + ".changed")) File.Move(path + ".changed", path, true);
            using var context = ArtifactContext.Load(path); new DotfuscatorDetectionPass().Run(context);
            var before = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody).ToDictionary(method => method, MethodBodySnapshot.Capture);
            var result = new DotfuscatorV2StringPass().Run(context);
            Assert.Equal(PassStatus.Unsupported, result.Status); Assert.Equal(0, result.Changes);
            Assert.All(before, pair => Assert.True(pair.Value.StructurallyEquals(pair.Key)));
            Assert.Empty(context.Changes);
            var pipeline = new CilantroPipeline().Run(path, new PipelineOptions(OutputPath: Path.Combine(directory, "cleaned.exe"), ReportDirectory: Path.Combine(directory, "reports")));
            Assert.False(pipeline.Success); Assert.Null(pipeline.OutputPath);
        }
        finally { Directory.Delete(directory, true); }
    }
}
