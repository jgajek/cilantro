using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Corpus;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.PE;

namespace Cilantro.Tests;

public sealed class DotfuscatorArm64CorpusTests
{
    private static string Manifest => Path.Combine(Checkout.Root, "corpus", "dotfuscator-7-native-linux-arm64.manifest.json");
    private static string Samples => Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_V2_SAMPLES")!;
    private static string Sample(string id) => Path.Combine(Samples, CorpusRunner.LoadManifest(Manifest).Samples.Single(sample => sample.Id == id).LocalName);

    [Fact]
    public void ManifestPinsLinuxOnlyCompanionLayouts()
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
            Assert.StartsWith("dotfuscator-v2-linux-arm64/", sample.LocalName, StringComparison.Ordinal);
        });
    }

    [DotfuscatorV2CorpusFact]
    public void LinuxOnlyCompanionsRecoverAndRetireNativeImports()
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.DotfuscatorLinux.").FullName;
        try
        {
            var manifest = CorpusRunner.LoadManifest(Manifest);
            var outcome = CorpusRunner.Run(Manifest, Samples, directory);
            Assert.True(outcome.Passed == 6 && outcome.Failed == 0 && outcome.Missing == 0,
                JsonSerializer.Serialize(outcome.Samples.Where(sample => sample.Status != "passed"), CilantroPipeline.ReportJsonOptions));
            foreach (var sample in manifest.Samples.Where(sample => sample.Tier != "oracle"))
            {
                var input = Path.Combine(Samples, sample.LocalName);
                var companions = Path.Combine(Path.GetDirectoryName(input)!, "runtimes");
                Assert.Equal("linux-arm64", Path.GetFileName(Assert.Single(Directory.GetDirectories(companions))));
                using var original = ModuleDefMD.Load(input);
                using var cleaned = ModuleDefMD.Load(Path.Combine(directory, sample.Id, "cleaned.bin"));
                Assert.Equal(Machine.ARM64, original.Machine);
                Assert.False(original.Is32BitRequired);
                Assert.Equal(original.Machine, cleaned.Machine);
                Assert.Equal(original.Cor20HeaderFlags, cleaned.Cor20HeaderFlags);
                Assert.DoesNotContain(cleaned.GetTypes(), type => type.FullName == "PreEmptive.Protection.Runtime.Native.NativeCPP");
                Assert.DoesNotContain(cleaned.GetTypes().SelectMany(type => type.Methods), method => method.ImplMap?.Module.Name.String is "Runtime.Extensions" or "Runtime.Extensions.dll");
            }
        }
        finally { Directory.Delete(directory, true); }
    }

    [DotfuscatorV2CorpusTheory]
    [InlineData("missing-linux")]
    [InlineData("windows-in-linux-path")]
    [InlineData("wrong-linux-architecture")]
    [InlineData("tampered-linux")]
    [InlineData("different-environment")]
    [InlineData("valid-windows-tampered-linux")]
    [InlineData("required-x86")]
    [InlineData("unsupported-machine")]
    public void UnknownPlatformInputsRefuseWithoutRewriting(string failure)
    {
        var source = Path.GetDirectoryName(Sample("net8.0-native-linux-arm64-strings"))!;
        var directory = Directory.CreateTempSubdirectory("Cilantro.DotfuscatorLinuxRefusal.").FullName;
        try
        {
            foreach (var file in Directory.GetFiles(source, "*", SearchOption.AllDirectories))
            {
                var target = Path.Combine(directory, Path.GetRelativePath(source, file));
                Directory.CreateDirectory(Path.GetDirectoryName(target)!); File.Copy(file, target);
            }
            var path = Path.Combine(directory, "Probe.dll");
            var native = Path.Combine(directory, "runtimes", "linux-arm64", "native", "Runtime.Extensions.so");
            var windowsSource = Path.Combine(Samples, "dotfuscator-v2", "net48-strings", "runtimes", "win-x64", "native", "Runtime.Extensions.dll");
            if (failure == "missing-linux") File.Delete(native);
            if (failure == "windows-in-linux-path") File.Copy(windowsSource, native, true);
            if (failure == "wrong-linux-architecture") File.Copy(Path.Combine(Samples, "dotfuscator-v2-linux-x64", "net8.0-strings", "runtimes", "linux-x64", "native", "Runtime.Extensions.so"), native, true);
            if (failure is "tampered-linux" or "valid-windows-tampered-linux") File.WriteAllBytes(native, [0]);
            if (failure == "valid-windows-tampered-linux")
            {
                var windows = Path.Combine(directory, "runtimes", "win-x64", "native", "Runtime.Extensions.dll");
                Directory.CreateDirectory(Path.GetDirectoryName(windows)!); File.Copy(windowsSource, windows);
            }
            if (failure == "different-environment")
            {
                var foreign = Directory.GetFiles(Path.GetDirectoryName(Sample("net10.0-native-linux-arm64-strings"))!, "environment????????.bin").Single();
                File.Copy(foreign, Directory.GetFiles(directory, "environment????????.bin").Single(), true);
            }
            if (failure is "required-x86" or "unsupported-machine" or "valid-windows-tampered-linux")
            {
                using var changed = ModuleDefMD.Load(path);
                if (failure == "required-x86") { changed.Machine = Machine.I386; changed.Is32BitRequired = true; }
                else changed.Machine = failure == "unsupported-machine" ? Machine.ARMNT : Machine.I386;
                changed.Write(path + ".changed");
            }
            if (File.Exists(path + ".changed")) File.Move(path + ".changed", path, true);
            using var context = ArtifactContext.Load(path); new DotfuscatorDetectionPass().Run(context);
            var before = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody).ToDictionary(method => method, MethodBodySnapshot.Capture);
            var result = new DotfuscatorV2StringPass().Run(context);
            Assert.Equal(PassStatus.Unsupported, result.Status); Assert.Equal(0, result.Changes);
            Assert.All(before, pair => Assert.True(pair.Value.StructurallyEquals(pair.Key)));
            Assert.Empty(context.Changes);
            var pipeline = new CilantroPipeline().Run(path, new PipelineOptions(OutputPath: Path.Combine(directory, "cleaned.dll"), ReportDirectory: Path.Combine(directory, "reports")));
            Assert.False(pipeline.Success); Assert.Null(pipeline.OutputPath);
        }
        finally { Directory.Delete(directory, true); }
    }

    [DotfuscatorV2CorpusTheory]
    [InlineData("net8.0-native-linux-arm64-strings")]
    [InlineData("net10.0-native-linux-arm64-strings")]
    public void AnyCpuLayoutAlsoRecoversWithOnlyTheArm64Companion(string id)
    {
        var source = Path.GetDirectoryName(Sample(id))!;
        var directory = Directory.CreateTempSubdirectory("Cilantro.DotfuscatorArm64AnyCpu.").FullName;
        try
        {
            foreach (var file in Directory.GetFiles(source, "*", SearchOption.AllDirectories))
            {
                var target = Path.Combine(directory, Path.GetRelativePath(source, file));
                Directory.CreateDirectory(Path.GetDirectoryName(target)!); File.Copy(file, target);
            }
            var path = Path.Combine(directory, "Probe.dll");
            using (var changed = ModuleDefMD.Load(path))
            {
                changed.Machine = Machine.I386;
                changed.Is32BitRequired = false;
                changed.Write(path + ".changed");
            }
            File.Move(path + ".changed", path, true);
            var result = new CilantroPipeline().Run(path, new PipelineOptions(OutputPath: Path.Combine(directory, "cleaned.dll"), ReportDirectory: Path.Combine(directory, "reports")));
            Assert.True(result.Success, JsonSerializer.Serialize(result.Report, CilantroPipeline.ReportJsonOptions));
            Assert.NotNull(result.OutputPath);
            using var cleaned = ModuleDefMD.Load(result.OutputPath);
            Assert.Equal(Machine.I386, cleaned.Machine); Assert.False(cleaned.Is32BitRequired);
            Assert.DoesNotContain(cleaned.GetTypes(), type => type.FullName == "PreEmptive.Protection.Runtime.Native.NativeCPP");
        }
        finally { Directory.Delete(directory, true); }
    }
}
