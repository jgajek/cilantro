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
        Assert.Contains("Methods devirtualized", page, StringComparison.Ordinal);
        Assert.Contains("1 of 1", page, StringComparison.Ordinal);
        // The second program this file holds is run by a type initializer that does other work, so
        // it is counted here and not as a method that failed to be devirtualized.
        Assert.Contains(
            "Interpreter programs found elsewhere   1, listed but not rebuilt",
            page,
            StringComparison.Ordinal);
        Assert.Contains("DEVIRTUALIZED METHODS", page, StringComparison.Ordinal);
        Assert.Contains(
            "methods protected by code virtualization into readable",
            page,
            StringComparison.Ordinal);
        Assert.Contains(
            "reconstructions from the virtual machine's instructions",
            page,
            StringComparison.Ordinal);
        Assert.Contains("not the original method bodies", page, StringComparison.Ordinal);
        Assert.Contains("uses      Activator.CreateInstance", page, StringComparison.Ordinal);
        Assert.Contains("changes   ", page, StringComparison.Ordinal);
        Assert.Contains("status    nothing in the cleaned copy calls this", page, StringComparison.Ordinal);
        Assert.DoesNotContain("  REBUILT", page, StringComparison.Ordinal);
        Assert.DoesNotContain("METHODS MADE READABLE", page, StringComparison.Ordinal);
        Assert.DoesNotContain("Method bodies decrypted", page, StringComparison.Ordinal);
        Assert.Contains("Proxy calls restored", page, StringComparison.Ordinal);
        Assert.Contains("1,230", page, StringComparison.Ordinal);
        Assert.DoesNotContain("Hidden calls resolved", page, StringComparison.Ordinal);
        Assert.Contains("Methods with control flow simplified", page, StringComparison.Ordinal);
        // Both of these count two runs of the fold rather than one, the second reaching the methods
        // whose predicates read state the interpreter assigned and nothing named until its program
        // was written out as IL. That is 23 further methods and 77 further branches here.
        Assert.Contains("289", page, StringComparison.Ordinal);
        Assert.Contains("Constant branches resolved", page, StringComparison.Ordinal);
        // 64 of these are owed to a reference deciding a branch as surely as an integer does, being
        // true exactly when it is not null, and this file puts a null constant in front of one
        // often.
        Assert.Contains("357", page, StringComparison.Ordinal);
        // Was 0 of 3 while the rewrite only looked for dispatchers reading a variable. Reactor
        // hands most of its dispatchers their state on the evaluation stack instead, and counting
        // those is what turned a line saying nothing was straightened into one saying almost
        // everything was.
        Assert.Contains("Flattened methods restored", page, StringComparison.Ordinal);
        // One more candidate and one more restored than while a rebuilt body carried its state in
        // a slot declared as an object: the dispatcher rewrite reads a state variable, and it can
        // only read one that holds a number.
        Assert.Contains("351 of 352 candidates", page, StringComparison.Ordinal);
        Assert.Contains("VM listings", page, StringComparison.Ordinal);
        Assert.DoesNotContain("Hidden code", page, StringComparison.Ordinal);
        Assert.Contains("Cleaned copy", page, StringComparison.Ordinal);
        Assert.Contains("Extracted files 2", page, StringComparison.Ordinal);
        Assert.Contains("Zebekeadu.dll (90.5 KB)", page, StringComparison.Ordinal);
        Assert.Contains("Assembly    Zebekeadu", page, StringComparison.Ordinal);
        Assert.Contains(
            "SHA-256     417032e561fe410a246fea4f580b7ae8de4a8cc5098a508931a78322916199dd",
            page,
            StringComparison.Ordinal);
        Assert.Contains("From        KyVgypcyOSoGANSpXe::uMqwgnxr1", page, StringComparison.Ordinal);
        Assert.Contains(
            "nkXbYoyJhFlJ5QXl4A.CZFLvot6mL92Di9HnX.dll (51 KB)",
            page,
            StringComparison.Ordinal);
        Assert.DoesNotContain("PureRAT", page, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("final payload", page, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("support library", page, StringComparison.OrdinalIgnoreCase);
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
