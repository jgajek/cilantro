using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Corpus;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.PE;

namespace Cilantro.Tests;

public sealed class DotfuscatorMacOsCorpusTests
{
    private static string Manifest(string rid) => Path.Combine(Checkout.Root, "corpus", $"dotfuscator-7-native-{rid}.manifest.json");
    private static string Samples => Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_V2_SAMPLES")!;
    private static string Sample(string id) => Path.Combine(Samples, CorpusRunner.LoadManifest(Manifest(id.Contains("osx-arm64", StringComparison.Ordinal) ? "osx-arm64" : "osx-x64")).Samples.Single(sample => sample.Id == id).LocalName);

    [Theory]
    [InlineData("osx-x64")]
    [InlineData("osx-arm64")]
    public void ManifestPinsMacOsOnlyCompanionPackages(string rid)
    {
        var samples = CorpusRunner.LoadManifest(Manifest(rid)).Samples;
        Assert.Equal(6, samples.Count); Assert.Equal(2, samples.Count(sample => sample.Tier == "oracle"));
        Assert.Equal(2, samples.Count(sample => sample.MinimumRecoveredStringSites == 20));
        Assert.Equal(2, samples.Count(sample => sample.MinimumRecoveredStringSites == 17));
        Assert.All(samples.Where(sample => sample.Tier != "oracle"), sample =>
        {
            Assert.Equal(0, sample.MaximumRemainingSwitchDispatchers); Assert.Equal(0, sample.MaximumUnreachableInstructions);
            Assert.True(sample.RequireOracleResourceParity);
        });
    }

    [DotfuscatorV2CorpusTheory]
    [InlineData("osx-x64")]
    [InlineData("osx-arm64")]
    public void MacOsOnlyPackagesRecoverAndRetireTheNativeBridge(string rid)
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.DotfuscatorMacOs.").FullName;
        try
        {
            var manifest = CorpusRunner.LoadManifest(Manifest(rid));
            var outcome = CorpusRunner.Run(Manifest(rid), Samples, directory);
            Assert.True(outcome.Passed == 4 && outcome.Failed == 0 && outcome.Missing == 0,
                JsonSerializer.Serialize(outcome.Samples.Where(sample => sample.Status != "passed"), CilantroPipeline.ReportJsonOptions));
            foreach (var sample in manifest.Samples.Where(sample => sample.Tier != "oracle"))
            {
                var input = Path.Combine(Samples, sample.LocalName);
                var nativeDirectory = Path.Combine(Path.GetDirectoryName(input)!, "runtimes");
                Assert.Equal(rid, Path.GetFileName(Assert.Single(Directory.GetDirectories(nativeDirectory))));
                using var original = ModuleDefMD.Load(input);
                using var cleaned = ModuleDefMD.Load(Path.Combine(directory, sample.Id, "cleaned.bin"));
                Assert.Equal(original.Machine, cleaned.Machine); Assert.Equal(original.Cor20HeaderFlags, cleaned.Cor20HeaderFlags);
                Assert.DoesNotContain(cleaned.GetTypes(), type => type.FullName == "PreEmptive.Protection.Runtime.Native.NativeCPP");
                Assert.DoesNotContain(cleaned.GetTypes().SelectMany(type => type.Methods), method => method.ImplMap?.Module.Name.String is "Runtime.Extensions" or "Runtime.Extensions.dll");
            }
        }
        finally { Directory.Delete(directory, true); }
    }

    [DotfuscatorV2CorpusTheory]
    [InlineData(Machine.I386, false, "osx-x64", true)]
    [InlineData(Machine.I386, false, "osx-arm64", true)]
    [InlineData(Machine.I386, true, "osx-x64", false)]
    [InlineData(Machine.I386, true, "osx-arm64", false)]
    [InlineData(Machine.AMD64, false, "osx-x64", true)]
    [InlineData(Machine.AMD64, false, "osx-arm64", false)]
    [InlineData(Machine.ARM64, false, "osx-arm64", true)]
    [InlineData(Machine.ARM64, false, "osx-x64", false)]
    [InlineData(Machine.ARMNT, false, "osx-arm64", false)]
    public void NativeAuthenticationRespectsArchitecture(Machine machine, bool requiredX86, string rid, bool expected)
    {
        var directory = Path.GetDirectoryName(Sample($"net8.0-{rid}-all-signatures"))!;
        using var module = new ModuleDefUser("Architecture") { Machine = machine, Is32BitRequired = requiredX86 };
        Assert.Equal(expected, DotfuscatorV2Companions.TryValidateNative(directory, module, out _));
    }

    [DotfuscatorV2CorpusTheory]
    [InlineData("missing")]
    [InlineData("tampered")]
    [InlineData("wrong-architecture")]
    [InlineData("windows-in-macos-path")]
    [InlineData("valid-windows-tampered-macos")]
    [InlineData("valid-macos-tampered-second-macos")]
    [InlineData("wrong-environment")]
    public void ChangedCompanionsWithholdRecoveryAtomically(string failure)
    {
        var source = Path.GetDirectoryName(Sample("net8.0-osx-x64-all-signatures"))!;
        var directory = Directory.CreateTempSubdirectory("Cilantro.DotfuscatorMacOsRefusal.").FullName;
        try
        {
            foreach (var file in Directory.GetFiles(source, "*", SearchOption.AllDirectories))
            {
                var target = Path.Combine(directory, Path.GetRelativePath(source, file));
                Directory.CreateDirectory(Path.GetDirectoryName(target)!); File.Copy(file, target);
            }
            var path = Path.Combine(directory, "DotfuscatorSignatures.dll");
            var native = Path.Combine(directory, "runtimes", "osx-x64", "native", "Runtime.Extensions.dylib");
            var windowsSource = Path.Combine(Samples, "dotfuscator-signatures", "net8.0-all-signatures", "protected", "runtimes", "win-x64", "native", "Runtime.Extensions.dll");
            if (failure == "missing") File.Delete(native);
            if (failure is "tampered" or "valid-windows-tampered-macos") File.WriteAllBytes(native, [0]);
            if (failure == "wrong-architecture") File.Copy(Path.Combine(Path.GetDirectoryName(Sample("net8.0-osx-arm64-all-signatures"))!, "runtimes", "osx-arm64", "native", "Runtime.Extensions.dylib"), native, true);
            if (failure == "windows-in-macos-path") File.Copy(windowsSource, native, true);
            if (failure == "valid-windows-tampered-macos")
            {
                var windows = Path.Combine(directory, "runtimes", "win-x64", "native", "Runtime.Extensions.dll");
                Directory.CreateDirectory(Path.GetDirectoryName(windows)!); File.Copy(windowsSource, windows);
            }
            if (failure == "valid-macos-tampered-second-macos")
            {
                var second = Path.Combine(directory, "runtimes", "osx-arm64", "native", "Runtime.Extensions.dylib");
                Directory.CreateDirectory(Path.GetDirectoryName(second)!); File.WriteAllBytes(second, [0]);
            }
            if (failure == "wrong-environment") File.WriteAllBytes(Directory.GetFiles(directory, "environment????????.bin").Single(), new byte[20480]);
            using var context = ArtifactContext.Load(path); new DotfuscatorDetectionPass().Run(context);
            var before = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody).ToDictionary(method => method, MethodBodySnapshot.Capture);
            var result = new DotfuscatorV2StringPass().Run(context);
            Assert.Equal(PassStatus.Unsupported, result.Status); Assert.Equal(0, result.Changes);
            Assert.All(before, pair => Assert.True(pair.Value.StructurallyEquals(pair.Key))); Assert.Empty(context.Changes);
            var pipeline = new CilantroPipeline().Run(path, new PipelineOptions(OutputPath: Path.Combine(directory, "cleaned.dll"), ReportDirectory: Path.Combine(directory, "reports")));
            Assert.False(pipeline.Success); Assert.Null(pipeline.OutputPath);
        }
        finally { Directory.Delete(directory, true); }
    }
}
