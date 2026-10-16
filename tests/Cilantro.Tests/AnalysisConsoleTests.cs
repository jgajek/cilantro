using System.Diagnostics;
using System.Text.Json;
using Cilantro.Cli;
using Cilantro.Core;

namespace Cilantro.Tests;

public sealed class AnalysisConsoleTests
{
    [Theory]
    [InlineData(false, null, null, false, true)]
    [InlineData(true, null, null, false, false)]
    [InlineData(false, "1", null, false, false)]
    [InlineData(false, null, "dumb", false, false)]
    [InlineData(false, null, "xterm", true, false)]
    public void ColorHonorsTerminalAndUserPreferences(bool redirected, string? noColor, string? term,
        bool disabled, bool expected) =>
        Assert.Equal(expected, ConsoleTheme.Enabled(redirected, noColor, term, disabled));

    [Fact]
    public void InterruptedPassIsNotShownAsSuccessful()
    {
        using var writer = new StringWriter();
        var terminal = new AnalysisConsole(writer, color: true);
        terminal.Report(new("sample.dll", PipelineStage.Recovery, "decoding", 1, 2));
        terminal.Failed();
        var text = writer.ToString();
        Assert.Contains("INTERRUPTED", text, StringComparison.Ordinal);
        Assert.Contains("[FAILED]", text, StringComparison.Ordinal);
        Assert.Contains("\u001b[91m", text, StringComparison.Ordinal);
        Assert.DoesNotContain("DONE", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RedirectedCliIncludesLiveProgressResultAndRealReportPathsWithoutAnsi()
    {
        var directory = Directory.CreateTempSubdirectory("cilantro CLI progress ");
        try
        {
            var input = PipelineProgressTests.WritePlain(directory.FullName);
            var (exit, text, error) = await RunCli(input, "--analyze-only", "--strict", "--report-dir", directory.FullName);
            Assert.Equal(0, exit);
            Assert.Empty(error);
            Assert.Contains($"CILantro {CilantroPipeline.Version}", text, StringComparison.Ordinal);
            Assert.Contains("__________", text, StringComparison.Ordinal);
            Assert.True(text.IndexOf("[RECOVERY]", StringComparison.Ordinal) < text.IndexOf("RESULT", StringComparison.Ordinal));
            Assert.Contains("metadata-preflight ... OK", text, StringComparison.Ordinal);
            Assert.Contains("[VERIFICATION]", text, StringComparison.Ordinal);
            Assert.DoesNotContain("[EMISSION]", text, StringComparison.Ordinal);
            Assert.Contains("Analysis complete; no cleaned assembly requested", text, StringComparison.Ordinal);
            Assert.DoesNotContain("\u001b", text, StringComparison.Ordinal);
            var report = Path.Combine(directory.FullName, "plain.report.html");
            Assert.Contains(report, text, StringComparison.Ordinal);
            Assert.True(File.Exists(report));
        }
        finally { directory.Delete(recursive: true); }
    }

    [Fact]
    public async Task JsonSuccessAndErrorsRemainSingleObjectsAndVersionIsBare()
    {
        var directory = Directory.CreateTempSubdirectory("cilantro CLI json ");
        try
        {
            var input = PipelineProgressTests.WritePlain(directory.FullName);
            var (exit, text, error) = await RunCli(input, "--analyze-only", "--json", "--no-color", "--report-dir", directory.FullName);
            Assert.Equal(0, exit);
            Assert.Empty(error);
            using var json = JsonDocument.Parse(text);
            Assert.Equal(JsonValueKind.Object, json.RootElement.ValueKind);
            Assert.DoesNotContain("[RECOVERY]", text, StringComparison.Ordinal);
            var failure = await RunCli(Path.Combine(directory.FullName, "missing.dll"), "--json");
            Assert.Equal(2, failure.Exit);
            Assert.Empty(failure.Error);
            using var failureJson = JsonDocument.Parse(failure.Text);
            Assert.Equal(JsonValueKind.Object, failureJson.RootElement.ValueKind);
            var version = await RunCli("--version");
            Assert.Equal(CilantroPipeline.Version, version.Text.Trim());
        }
        finally { directory.Delete(recursive: true); }
    }

    private static async Task<(int Exit, string Text, string Error)> RunCli(params string[] arguments)
    {
        var start = new ProcessStartInfo("dotnet")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        start.ArgumentList.Add(typeof(CilantroCommand).Assembly.Location);
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        using var process = Process.Start(start)!;
        var text = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        try { await process.WaitForExitAsync(timeout.Token); }
        finally { if (!process.HasExited) process.Kill(entireProcessTree: true); }
        return (process.ExitCode, await text, await error);
    }
}
