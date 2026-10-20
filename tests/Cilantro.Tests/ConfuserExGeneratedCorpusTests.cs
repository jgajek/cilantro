using System.Diagnostics;
using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Corpus;

namespace Cilantro.Tests;

public sealed class ConfuserExGeneratedCorpusTests
{
    private static string Manifest => Path.Combine(Checkout.Root, "corpus", "confuserex-generated.manifest.json");

    [Fact]
    public void ManifestPinsBothEditionsAndCombinedRecovery()
    {
        var samples = CorpusRunner.LoadManifest(Manifest).Samples;
        Assert.Equal(19, samples.Count);
        Assert.Single(samples, sample => sample.Tier == "oracle");
        foreach (var edition in new[] { "confuserex-1", "confuserex-2" })
        {
            var cases = samples.Where(sample => sample.Id.StartsWith(edition + "-", StringComparison.Ordinal)).ToArray();
            Assert.Equal(9, cases.Length);
            var combined = Assert.Single(cases, sample => sample.Id == edition + "-combined");
            Assert.True(combined.MinimumRecoveredStringSites >= 8);
            Assert.True(combined.MinimumResourcesRestored >= 1);
            Assert.True(combined.MinimumRedirectedDispatcherEdges >= 500);
            Assert.True(combined.MinimumNeutralizedCheckSites >= 2);
            Assert.True(combined.RequireOracleResourceParity);
        }
    }

    [ConfuserExGeneratedCorpusFact]
    [Trait(Cost.Key, Cost.High)]
    public void BothEditionsRecoverAndRunLikeTheOracle()
    {
        var samples = Environment.GetEnvironmentVariable("CILANTRO_CONFUSEREX_SAMPLES")!;
        var output = Directory.CreateTempSubdirectory("Cilantro.ConfuserEx.").FullName;
        try
        {
            var report = CorpusRunner.Run(Manifest, samples, output);
            Assert.True(report.Passed == 18 && report.Failed == 0 && report.Missing == 0,
                JsonSerializer.Serialize(report.Samples.Where(sample => sample.Status != "passed"),
                    CilantroPipeline.ReportJsonOptions));

            var oracle = Path.Combine(samples, "confuserex-generated", "oracle", "ConfuserExProbe.exe");
            foreach (var edition in new[] { "confuserex-1", "confuserex-2" })
            foreach (var profile in new[] { "combined", "combined-no-rename" })
            {
                var id = edition + "-" + profile;
                var protectedFile = Path.Combine(samples, "confuserex-generated", edition,
                    profile, "ConfuserExProbe.exe");
                var cleanedFile = Path.Combine(output, id, "ConfuserExProbe.cleaned.exe");
                File.Copy(Path.Combine(output, id, "cleaned.bin"), cleanedFile);
                foreach (var argument in new[] { "7", "8", "-3" })
                {
                    var expected = Run(oracle, argument);
                    Assert.Equal(expected, Run(protectedFile, argument));
                    Assert.Equal(expected, Run(cleanedFile, argument));
                }
            }
        }
        finally { Directory.Delete(output, true); }
    }

    [ConfuserExGeneratedCorpusFact]
    [Trait(Cost.Key, Cost.High)]
    public void X86ConstantStubsBecomeRunnableCil()
    {
        var samples = Environment.GetEnvironmentVariable("CILANTRO_CONFUSEREX_SAMPLES")!;
        foreach (var edition in new[] { "confuserex-1", "confuserex-2" })
        {
            var input = Path.Combine(samples, "confuserex-advanced", edition,
                "constants-x86", "ConfuserExProbe.exe");
            if (!File.Exists(input)) return;
            var output = Directory.CreateTempSubdirectory("Cilantro.ConfuserExX86.").FullName;
            try
            {
                var result = new CilantroPipeline().Run(input,
                    new PipelineOptions(OutputPath: Path.Combine(output, "cleaned.exe"),
                        ReportDirectory: output));
                var constants = Assert.Single(result.Report.Passes,
                    pass => pass.Pass == "confuserex-constants");
                Assert.Equal(6, constants.Changes);
                Assert.NotNull(result.OutputPath);
                Assert.Contains(result.Report.Passes,
                    pass => pass.Pass == "metadata-preflight" &&
                        pass.Status == PassStatus.Success);
                Assert.Contains(result.Report.Passes,
                    pass => pass.Pass == "confuserex-x86-native" &&
                        pass.Status == PassStatus.Success && pass.Changes == 5);
                foreach (var argument in new[] { "7", "8", "-3" })
                {
                    var oracle = Path.Combine(samples, "confuserex-advanced", "oracle", "ConfuserExProbe.exe");
                    Assert.Equal(Run(oracle, argument), Run(result.OutputPath!, argument));
                }
            }
            finally { Directory.Delete(output, true); }
        }
    }

    [ConfuserExGeneratedCorpusFact]
    [Trait(Cost.Key, Cost.High)]
    public void JitAntiTamperRestoresIndexedMethodBodies()
    {
        var samples = Environment.GetEnvironmentVariable("CILANTRO_CONFUSEREX_SAMPLES")!;
        foreach (var edition in new[] { "confuserex-1", "confuserex-2" })
        {
            var input = Path.Combine(samples, "confuserex-advanced", edition,
                "tamper-jit", "ConfuserExProbe.exe");
            if (!File.Exists(input)) return;
            var output = Directory.CreateTempSubdirectory("Cilantro.ConfuserExJit.").FullName;
            try
            {
                var result = new CilantroPipeline().Run(input,
                    new PipelineOptions(OutputPath: Path.Combine(output, "cleaned.exe"),
                        ReportDirectory: output));
                Assert.NotNull(result.OutputPath);
                Assert.Contains(result.Report.Evidence, evidence =>
                    evidence.Category == "capability" && evidence.Message == "jit-anti-tamper");
                Assert.Contains(result.Report.Passes, pass =>
                    pass.Pass == "confuserex-antitamper" && pass.Status == PassStatus.Success &&
                    pass.Changes == (edition == "confuserex-1" ? 4 : 3));
            }
            finally { Directory.Delete(output, true); }
        }
    }

    [ConfuserExGeneratedCorpusFact]
    [Trait(Cost.Key, Cost.High)]
    public void BothCompressorsYieldPinnedNetmodules()
    {
        var samples = Environment.GetEnvironmentVariable("CILANTRO_CONFUSEREX_SAMPLES")!;
        var packed = Path.Combine(samples, "confuserex-advanced", "confuserex-1",
            "packed", "ConfuserExProbe.exe");
        if (!File.Exists(packed)) return;
        var output = Directory.CreateTempSubdirectory("Cilantro.ConfuserExPacked.").FullName;
        try
        {
            var manifest = Path.Combine(Checkout.Root, "corpus", "confuserex-packed.manifest.json");
            var report = CorpusRunner.Run(manifest, samples, output);
            Assert.True(report.Passed == 2 && report.Failed == 0 && report.Missing == 0,
                JsonSerializer.Serialize(report.Samples.Where(sample => sample.Status != "passed"),
                    CilantroPipeline.ReportJsonOptions));
            var oracle = Path.Combine(samples, "confuserex-advanced", "oracle", "ConfuserExProbe.exe");
            foreach (var edition in new[] { "confuserex-1", "confuserex-2" })
            {
                var payloadDirectory = Path.Combine(output, edition + "-packed", "ConfuserExProbe.payloads");
                var rebuilt = Assert.Single(Directory.GetFiles(payloadDirectory, "*.exe"));
                foreach (var argument in new[] { "7", "8", "-3" })
                    Assert.Equal(Run(oracle, argument), Run(rebuilt, argument));
            }
        }
        finally { Directory.Delete(output, true); }
    }

    [ConfuserExGeneratedCorpusFact]
    [Trait(Cost.Key, Cost.High)]
    public void AdditionalModesRecoverAndRunLikeTheOracle()
    {
        var samples = Environment.GetEnvironmentVariable("CILANTRO_CONFUSEREX_SAMPLES")!;
        var advanced = Path.Combine(samples, "confuserex-advanced");
        if (!Directory.Exists(advanced)) return;
        var output = Directory.CreateTempSubdirectory("Cilantro.ConfuserExAdvanced.").FullName;
        try
        {
            var manifest = Path.Combine(Checkout.Root, "corpus", "confuserex-advanced.manifest.json");
            var report = CorpusRunner.Run(manifest, samples, output);
            Assert.True(report.Passed == 25 && report.Failed == 0 && report.Missing == 0,
                JsonSerializer.Serialize(report.Samples.Where(sample => sample.Status != "passed"),
                    CilantroPipeline.ReportJsonOptions));
            var oracle = Path.Combine(advanced, "oracle", "ConfuserExProbe.exe");
            foreach (var sample in CorpusRunner.LoadManifest(manifest).Samples.Where(item => item.Tier != "oracle"))
            {
                var cleaned = Path.Combine(output, sample.Id, "ConfuserExProbe.cleaned.exe");
                File.Copy(Path.Combine(output, sample.Id, "cleaned.bin"), cleaned);
                foreach (var argument in new[] { "7", "8", "-3" })
                    Assert.Equal(Run(oracle, argument), Run(cleaned, argument));
            }
        }
        finally { Directory.Delete(output, true); }
    }

    [ConfuserExGeneratedCorpusFact]
    [Trait(Cost.Key, Cost.High)]
    public void CombinedStrongProxyRecoversAndRunsLikeTheOracle()
    {
        var samples = Environment.GetEnvironmentVariable("CILANTRO_CONFUSEREX_SAMPLES")!;
        var oracle = Path.Combine(samples, "confuserex-combined-strong", "oracle", "ConfuserExProbe.exe");
        if (!File.Exists(oracle)) return;
        var output = Directory.CreateTempSubdirectory("Cilantro.ConfuserExCombinedStrong.").FullName;
        try
        {
            var manifest = Path.Combine(Checkout.Root, "corpus", "confuserex-combined-strong.manifest.json");
            var report = CorpusRunner.Run(manifest, samples, output);
            Assert.True(report.Passed == 2 && report.Failed == 0 && report.Missing == 0,
                JsonSerializer.Serialize(report.Samples.Where(sample => sample.Status != "passed"),
                    CilantroPipeline.ReportJsonOptions));
            foreach (var edition in new[] { "confuserex-1", "confuserex-2" })
            {
                var id = edition + "-combined-strong";
                var cleaned = Path.Combine(output, id, "ConfuserExProbe.cleaned.exe");
                File.Copy(Path.Combine(output, id, "cleaned.bin"), cleaned);
                foreach (var argument in new[] { "7", "8", "-3" })
                    Assert.Equal(Run(oracle, argument), Run(cleaned, argument));
            }
        }
        finally { Directory.Delete(output, true); }
    }

    [ConfuserExGeneratedCorpusFact]
    [Trait(Cost.Key, Cost.High)]
    public void CombinedDynamicJitAndX86RecoverAndRunLikeTheOracle()
    {
        var samples = Environment.GetEnvironmentVariable("CILANTRO_CONFUSEREX_SAMPLES")!;
        var oracle = Path.Combine(samples, "confuserex-combined-hard", "oracle", "ConfuserExProbe.exe");
        if (!File.Exists(oracle)) return;
        var output = Directory.CreateTempSubdirectory("Cilantro.ConfuserExCombinedHard.").FullName;
        try
        {
            var manifest = Path.Combine(Checkout.Root, "corpus", "confuserex-combined-hard.manifest.json");
            var report = CorpusRunner.Run(manifest, samples, output);
            Assert.True(report.Passed == 4 && report.Failed == 0 && report.Missing == 0,
                JsonSerializer.Serialize(report.Samples.Where(sample => sample.Status != "passed"),
                    CilantroPipeline.ReportJsonOptions));
            foreach (var edition in new[] { "confuserex-1", "confuserex-2" })
                foreach (var mode in new[] { "combined-dynamic-jit", "combined-x86" })
                {
                    var id = edition + "-" + mode;
                    var cleaned = Path.Combine(output, id, "ConfuserExProbe.cleaned.exe");
                    File.Copy(Path.Combine(output, id, "cleaned.bin"), cleaned);
                    foreach (var argument in new[] { "7", "8", "-3" })
                        Assert.Equal(Run(oracle, argument), Run(cleaned, argument));
                }
        }
        finally { Directory.Delete(output, true); }
    }

    private static (int ExitCode, string Output) Run(string path, string argument)
    {
        using var process = Process.Start(new ProcessStartInfo(path, argument)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        })!;
        Assert.True(process.WaitForExit(10_000), $"Timed out: {path}");
        var error = process.StandardError.ReadToEnd();
        Assert.True(error.Length == 0, $"{path}: {error}");
        return (process.ExitCode, process.StandardOutput.ReadToEnd());
    }
}

public sealed class ConfuserExGeneratedCorpusFactAttribute : FactAttribute
{
    public ConfuserExGeneratedCorpusFactAttribute()
    {
        if (!OperatingSystem.IsWindows())
            Skip = "The source-built fixture targets .NET Framework 4.8 on Windows.";
        else if (Environment.GetEnvironmentVariable("CILANTRO_CONFUSEREX_SAMPLES") is not { Length: > 0 })
            Skip = "Set CILANTRO_CONFUSEREX_SAMPLES to the directory containing the pinned benign fixtures.";
    }
}
