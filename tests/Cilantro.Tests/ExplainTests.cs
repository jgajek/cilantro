using System.Text;
using dnlib.DotNet;
using Cilantro.Cli;
using Cilantro.Core;

namespace Cilantro.Tests;

/// <summary>
/// Covers what a person is told when a run finishes.
/// </summary>
/// <remarks>
/// The failure mode is a successful recovery that reads as a failure. A default run that names
/// its assumptions, its skipped calls, or an unchecked rebuild is the thing that produced that
/// reading, so those words are the ones these tests refuse.
/// </remarks>
public sealed class ExplainTests
{
    [Fact]
    public void ADefaultRunOnAnUnprotectedFileSaysSoAndDoesNotMentionTriage()
    {
        using var directory = Temporary();
        var sample = WritePlain(directory.Path);
        var result = new CilantroPipeline().Run(sample, new PipelineOptions(
            AnalyzeOnly: true,
            ReportDirectory: directory.Path));

        var page = Shown(result, sample);

        Assert.Contains("RESULT   Not protected", page, StringComparison.Ordinal);
        Assert.DoesNotContain("triage", page, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("strict", page, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ASSUMED", page, StringComparison.Ordinal);
        Assert.DoesNotContain("Reading  ", page, StringComparison.Ordinal);
    }

    [Fact]
    public void AStrictRunNamesThatItIsStrict()
    {
        using var directory = Temporary();
        var sample = WritePlain(directory.Path);
        var result = new CilantroPipeline().Run(sample, new PipelineOptions(
            AnalyzeOnly: true,
            ReportDirectory: directory.Path,
            Strict: true));

        var page = Shown(result, sample);

        Assert.Contains("RESULT   Not protected", page, StringComparison.Ordinal);
        Assert.Contains("Reading  strict", page, StringComparison.Ordinal);
    }

    /// <summary>
    /// The sample that was reported as a failed deobfuscation after a finished recovery.
    /// </summary>
    [SampleFact]
    [Trait(Cost.Key, Cost.High)]
    public void ADefaultRunOnARecoveredSampleSaysRecoveredAndNothingElse()
    {
        using var directory = Temporary();
        var sample = Checkout.Sample("Qbjuef.exe");
        var result = new CilantroPipeline().Run(sample, new PipelineOptions(
            OutputPath: Path.Combine(directory.Path, "a.cleaned.exe"),
            ReportDirectory: directory.Path));

        Assert.True(result.Success);
        Assert.NotNull(result.OutputPath);
        var page = Shown(result, sample);

        Assert.Contains("RESULT   Recovered", page, StringComparison.Ordinal);
        Assert.Contains("Methods rebuilt from VM opcodes", page, StringComparison.Ordinal);
        Assert.Contains("1 of 1", page, StringComparison.Ordinal);
        Assert.DoesNotContain("Method bodies decrypted", page, StringComparison.Ordinal);
        Assert.Contains("Proxy calls restored", page, StringComparison.Ordinal);
        Assert.Contains("1,230", page, StringComparison.Ordinal);
        Assert.DoesNotContain("Hidden calls resolved", page, StringComparison.Ordinal);
        Assert.Contains("VM listings", page, StringComparison.Ordinal);
        Assert.DoesNotContain("Hidden code", page, StringComparison.Ordinal);
        Assert.Contains("Cleaned copy", page, StringComparison.Ordinal);
        Assert.Contains("Open the cleaned copy", page, StringComparison.Ordinal);
        Assert.DoesNotContain("Failed", page, StringComparison.Ordinal);
        Assert.DoesNotContain("triage", page, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ASSUMED", page, StringComparison.Ordinal);
        Assert.DoesNotContain("BLOCKED", page, StringComparison.Ordinal);
        Assert.DoesNotContain("unchecked", page, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("The check was not made", page, StringComparison.Ordinal);
        Assert.DoesNotContain("Reading  ", page, StringComparison.Ordinal);
        Assert.DoesNotContain("[RebuiltFromReading]", page, StringComparison.Ordinal);
    }

    private static string Shown(PipelineResult result, string sample)
    {
        var page = new StringBuilder();
        using var writer = new StringWriter(page);
        Explain.Summarize(result, sample, writer);
        return page.ToString();
    }

    private static string WritePlain(string directory)
    {
        var module = new ModuleDefUser("plain.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser("plain", new Version(1, 0));
        assembly.Modules.Add(module);
        var path = Path.Combine(directory, "plain.dll");
        module.Write(path);
        return path;
    }

    private static TemporaryDirectory Temporary() => new();

    private sealed class TemporaryDirectory : IDisposable
    {
        public string Path { get; } = Directory.CreateTempSubdirectory("Cilantro.Explain").FullName;

        public void Dispose() => Directory.Delete(Path, recursive: true);
    }
}
