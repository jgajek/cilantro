using System.Text.Json;
using Cilantro.Cli;
using Cilantro.Core;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class AnalysisArgumentsTests
{
    [Fact]
    public void ExplicitBabelCodeSourcesAcceptRepeatedAndInlinePaths()
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.CodeArguments.").FullName;
        try
        {
            var input = PipelineProgressTests.WritePlain(directory);
            var one = Path.Combine(directory, "one.eil"); var two = Path.Combine(directory, "two.eil");
            File.WriteAllBytes(one, [1]); File.WriteAllBytes(two, [2]);
            var options = AnalysisArguments.Parse([input, "--babel-code-source=" + one, "--babel-code-source", two]).PreparePipelineOptions();
            Assert.Equal(new[] { one, two }, options.BabelCodeSourceFiles);
            Assert.Throws<ArgumentException>(() => AnalysisArguments.Parse([input, "--babel-code-source", Path.Combine(directory, "missing.eil")]).PreparePipelineOptions());
        }
        finally { Directory.Delete(directory, true); }
    }
    [Fact]
    public void ExplicitSigningKeysAcceptRepeatedAndInlinePaths()
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.SigningArguments.").FullName;
        try
        {
            var input = PipelineProgressTests.WritePlain(directory);
            var one = Path.Combine(directory, "one.snk"); var two = Path.Combine(directory, "two.snk");
            File.WriteAllBytes(one, [1]); File.WriteAllBytes(two, [2]);
            var options = AnalysisArguments.Parse([input, "--signing-key=" + one, "--signing-key", two]).PreparePipelineOptions();
            Assert.Equal(new[] { one, two }, options.StrongNameKeyFiles);
            Assert.Throws<ArgumentException>(() => AnalysisArguments.Parse([input, "--signing-key", Path.Combine(directory, "missing.snk")]).PreparePipelineOptions());
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public async Task FileAloneRecoversChildrenWritesStatusAndKeepsAllArtifactsInANewCaseFolder()
    {
        var directory = Directory.CreateTempSubdirectory("cilantro simplest ");
        try
        {
            var child = PipelineProgressTests.WritePlain(directory.FullName);
            var parent = Path.Combine(directory.FullName, "parent.dll");
            using (var module = ModuleDefMD.Load(child))
            {
                module.Name = "parent.dll";
                module.Assembly.Name = "parent";
                module.Resources.Add(new EmbeddedResource("costura.plain.dll", File.ReadAllBytes(child), ManifestResourceAttributes.Private));
                module.Write(parent);
            }
            var before = File.ReadAllBytes(parent);
            // Generic recovery is deliberately explicit for an unrecognized root protector.
            var options = AnalysisArguments.Parse([parent]).PreparePipelineOptions();
            Assert.True(options.RecoverEmbeddedAssemblies);
            Assert.NotNull(options.StatusPath);
            Assert.True(options.Renames);
            Assert.True(options.Devirtualizes);
            var run = await AnalysisConsoleTests.RunCli(parent, "--generic-recovery", "--json");
            Assert.Equal(0, run.Exit);
            using var json = JsonDocument.Parse(run.Text);
            var caseFolder = Path.Combine(directory.FullName, "parent.cilantro");
            var cleaned = json.RootElement.GetProperty("Wrote").GetProperty("Cleaned").GetString();
            Assert.Equal(Path.Combine(caseFolder, "parent.cleaned.dll"), cleaned);
            Assert.True(File.Exists(cleaned));
            Assert.True(File.Exists(Path.Combine(caseFolder, "parent.report.html")));
            var status = RunStatus.Read(Path.Combine(caseFolder, "parent.status.json"));
            Assert.Equal(RunPhase.Finished, status!.Phase);
            Assert.True(status.Result!.Success);
            var graphPath = json.RootElement.GetProperty("Wrote").GetProperty("Embedded").GetString();
            using var graph = JsonDocument.Parse(File.ReadAllText(graphPath!));
            Assert.Equal(2, graph.RootElement.GetProperty("Nodes").GetArrayLength());
            Assert.Equal(before, File.ReadAllBytes(parent));
            var next = AnalysisArguments.Parse([parent]).PreparePipelineOptions();
            Assert.Equal(caseFolder + "-2", next.ReportDirectory);
        }
        finally { directory.Delete(recursive: true); }
    }

    [Fact]
    public void OutputIsAFolderAndNonemptyCasesCannotBeOverwritten()
    {
        var directory = Directory.CreateTempSubdirectory("cilantro case policy ");
        try
        {
            var input = PipelineProgressTests.WritePlain(directory.FullName);
            var chosen = Path.Combine(directory.FullName, "analyst case");
            var options = AnalysisArguments.Parse([input, "--output=" + chosen, "--strict", "--no-recursion"]).PreparePipelineOptions();
            Assert.Equal(chosen, options.ReportDirectory);
            Assert.Equal(Path.Combine(chosen, "plain.cleaned.dll"), options.OutputPath);
            Assert.False(options.RecoverEmbeddedAssemblies);
            Assert.False(options.Renames);
            Assert.False(options.Devirtualizes);
            Directory.CreateDirectory(chosen);
            var evidence = Path.Combine(chosen, "evidence.txt");
            File.WriteAllText(evidence, "preserve");
            Assert.Throws<ArgumentException>(() => AnalysisArguments.Parse([input, "-o", chosen]).PreparePipelineOptions());
            Assert.Throws<ArgumentException>(() => AnalysisArguments.Parse([input, "-o", input]).PreparePipelineOptions());
            Assert.Equal("preserve", File.ReadAllText(evidence));
            Assert.Equal("--strict", AnalysisArguments.Parse(["--", "--strict"]).Input);
        }
        finally { directory.Delete(recursive: true); }
    }

    [Theory]
    [InlineData("--bogus")]
    [InlineData("--not-an-option")]
    [InlineData("--typo")]
    [InlineData("--output-folder")]
    [InlineData("--enable-colors")]
    [InlineData("--frobnicate")]
    public async Task UnknownOptionsGiveAnActionableJsonError(string option)
    {
        var run = await AnalysisConsoleTests.RunCli("sample.exe", option, "--json");
        Assert.Equal(2, run.Exit);
        Assert.Empty(run.Error);
        using var json = JsonDocument.Parse(run.Text);
        Assert.Contains("Unknown option", run.Text, StringComparison.Ordinal);
        Assert.Contains("--help-all", run.Text, StringComparison.Ordinal);
        Assert.Contains(option, run.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CommonHelpStaysShortAndSpecialistControlsAreDiscoverable()
    {
        var common = await AnalysisConsoleTests.RunCli("--help");
        var advanced = await AnalysisConsoleTests.RunCli("--help-all");
        Assert.Equal(0, common.Exit);
        Assert.Equal(0, advanced.Exit);
        Assert.Contains("--help-all", common.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("--declarations FILE", common.Text, StringComparison.Ordinal);
        Assert.Contains("--declarations FILE", advanced.Text, StringComparison.Ordinal);
        Assert.Contains("--no-recursion", advanced.Text, StringComparison.Ordinal);
    }
}
