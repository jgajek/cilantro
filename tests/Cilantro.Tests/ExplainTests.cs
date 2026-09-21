using System.Text;
using dnlib.DotNet;
using Cilantro.Cli;
using Cilantro.Core;
using Cilantro.Core.Recovery;

namespace Cilantro.Tests;

/// <summary>Analyst-facing outcomes must agree with written files and expose material limitations.</summary>
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

        Assert.Contains("Analysis complete; no cleaned assembly requested", page, StringComparison.Ordinal);
        Assert.Contains("No supported protection detected", page, StringComparison.Ordinal);
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

        Assert.Contains("Analysis complete; no cleaned assembly requested", page, StringComparison.Ordinal);
        Assert.Contains("No supported protection detected", page, StringComparison.Ordinal);
        Assert.Contains("Reading  strict", page, StringComparison.Ordinal);
    }

    [Fact]
    public void OutputComesFirstAndLimitationsAreVisibleWithoutVerbose()
    {
        using var directory = Temporary();
        var sample = WritePlain(directory.Path);
        var basis = new CilantroPipeline().Run(sample, new PipelineOptions(AnalyzeOnly: true, ReportDirectory: directory.Path));
        var result = basis with
        {
            AnalyzeOnly = false,
            OutputPath = Path.Combine(directory.Path, "sample.cleaned.dll"),
            RebuiltMethods = 1,
            VirtualizedMethods = 2,
            Report = basis.Report with
            {
                Protector = "reactor",
                Recovery = basis.Report.Recovery with
                {
                    RestoredMethodBodies = 312, ReplacedStringSites = 63, StringCallSites = 65,
                    RemainingSwitchDispatchers = 1, ControlFlowMethodsSimplified = 76,
                    DispatcherMethodsRestored = 37, DispatcherMethodCandidates = 38
                }
            }
        };
        var page = Shown(result, sample);
        Assert.Contains("RESULT   Cleaned assembly written", page, StringComparison.Ordinal);
        Assert.True(page.IndexOf(result.OutputPath, StringComparison.Ordinal) < page.IndexOf("WHAT CHANGED", StringComparison.Ordinal));
        Assert.Contains("63 encrypted string uses resolved (not unique strings)", page, StringComparison.Ordinal);
        Assert.Contains("2 detected encrypted string uses remain unresolved", page, StringComparison.Ordinal);
        Assert.DoesNotContain("a method can count more than once", page, StringComparison.Ordinal);
        Assert.Contains("a method can count more than once", Shown(result, sample, verbose: true), StringComparison.Ordinal);
        Assert.Contains("dispatcher-like", page, StringComparison.Ordinal);
        Assert.Contains("have not been cross-checked", page, StringComparison.Ordinal);
        Assert.Contains("1 virtualized method was not reconstructed", page, StringComparison.Ordinal);
        Assert.DoesNotContain("Flattened methods restored", page, StringComparison.Ordinal);
        Assert.Contains("Program behavior was not independently verified", page, StringComparison.Ordinal);
    }

    [Fact]
    public void FailedRecoveryDoesNotImplyAnEmptySample()
    {
        using var directory = Temporary();
        var sample = WritePlain(directory.Path);
        var basis = new CilantroPipeline().Run(sample, new PipelineOptions(AnalyzeOnly: true, ReportDirectory: directory.Path));
        var result = basis with
        {
            Success = false, AnalyzeOnly = false,
            Report = basis.Report with
            {
                VerificationPassed = false,
                Passes = [new("payload-extraction", PassStatus.Partial, 0, ["Budget exhausted"], TimeSpan.Zero)]
            }
        };
        var page = Shown(result, sample);
        Assert.Contains("Run incomplete", page, StringComparison.Ordinal);
        Assert.Contains("Extraction may be incomplete", page, StringComparison.Ordinal);
        Assert.Contains("Structural checks failed", page, StringComparison.Ordinal);
        Assert.DoesNotContain("RESULT   No supported protection", page, StringComparison.Ordinal);
    }

    [Fact]
    public void BootstrapIsExtractedOnlyAndTheNextCommandQuotesItsPath()
    {
        using var directory = Temporary();
        var sample = WritePlain(directory.Path);
        var basis = new CilantroPipeline().Run(sample, new PipelineOptions(AnalyzeOnly: true, ReportDirectory: directory.Path));
        var payload = Path.Combine(directory.Path, "a b'c.dll");
        var result = basis with
        {
            AnalyzeOnly = false, ExtractedPayloadPaths = [payload],
            Report = basis.Report with { Protector = "reactor-bootstrap" }
        };
        var page = Shown(result, sample);
        Assert.Contains("RESULT   Managed assembly extracted", page, StringComparison.Ordinal);
        Assert.Contains("Extracted only; not yet cleaned", page, StringComparison.Ordinal);
        Assert.Contains("cilantro '" + payload.Replace("'", "''", StringComparison.Ordinal) + "'", page, StringComparison.Ordinal);
        Assert.DoesNotContain("Structural checks passed", page, StringComparison.Ordinal);
    }

    [Fact]
    public void HtmlEscapesSampleTextAndLinksToTheActualOutputs()
    {
        using var directory = Temporary();
        var sample = WritePlain(directory.Path);
        var basis = new CilantroPipeline().Run(sample, new PipelineOptions(AnalyzeOnly: true, ReportDirectory: directory.Path));
        var payloadPath = Path.Combine(directory.Path, "a #& b.dll");
        var result = AnalystReport.Write(basis with
        {
            ExtractedPayloadPaths = [payloadPath],
            Report = basis.Report with
            {
                Payloads = [new("<script>alert(1)</script>", "", 0, "", 0, "hash", "<img src=x>", "module", 0, [], payloadPath)],
                Passes = [new("payload-extraction", PassStatus.Partial, 0, ["<script>bad()</script>"], TimeSpan.Zero)]
            }
        }, true);
        var html = File.ReadAllText(result.ReadableReportPath!);
        Assert.DoesNotContain("<script>", html, StringComparison.Ordinal);
        Assert.Contains("&lt;script&gt;", html, StringComparison.Ordinal);
        Assert.Contains("href=\"./a%20%23%26%20b.dll\"", html, StringComparison.Ordinal);
        Assert.Contains("&lt;script&gt;bad()&lt;/script&gt;", html, StringComparison.Ordinal);
        Assert.Equal(result.ReadableReportPath, RunManifest.Of(result).Wrote.Report);
        Assert.Contains("plain.analysis.json", html, StringComparison.Ordinal);
        Assert.Contains("Extraction may be incomplete", html, StringComparison.Ordinal);
    }

    [Fact]
    public void AProgramLiftedToAHelperIsNotReportedAsUnrebuilt()
    {
        using var directory = Temporary();
        var sample = WritePlain(directory.Path);
        var basis = new CilantroPipeline().Run(sample, new PipelineOptions(AnalyzeOnly: true, ReportDirectory: directory.Path));
        var result = basis with { ProgramsRunElsewhere = 1, LiftedPrograms = 1 };
        var page = Shown(result, sample);
        Assert.Contains("additional interpreter program reconstructed as a helper method", page, StringComparison.Ordinal);
        Assert.DoesNotContain("program was not rebuilt", page, StringComparison.Ordinal);
        Assert.Contains("have not been cross-checked", page, StringComparison.Ordinal);
        Assert.Equal(1, RunManifest.Of(result).LiftedPrograms);
    }

    [Fact]
    public void LoadCapturedAssemblyIsPrioritizedAheadOfTheResourceBundle()
    {
        using var directory = Temporary();
        var sample = WritePlain(directory.Path);
        var basis = new CilantroPipeline().Run(sample, new PipelineOptions(AnalyzeOnly: true, ReportDirectory: directory.Path));
        var bundle = new PayloadInfo("resource", "", 0, "", 0, "bundle", "encoded-name", "bundle", 0, [], Path.Combine(directory.Path, "bundle.dll"), PayloadOrigin.ResourceBundle);
        var payload = new PayloadInfo("loader", "", 0, "", 0, "payload", "Zebekeadu", "Zebekeadu.dll", 0, [], Path.Combine(directory.Path, "payload.dll"), PayloadOrigin.AssemblyLoad);
        var child = basis with { OutputPath = Path.Combine(directory.Path, "cleaned-child.dll"), Report = basis.Report with { InputPath = payload.WrittenTo!, Recovery = basis.Report.Recovery with { ReplacedStringSites = 152 } } };
        var root = basis with { AnalyzeOnly = false, OutputPath = Path.Combine(directory.Path, "cleaned-root.dll"), ExtractedPayloadPaths = [bundle.WrittenTo!, payload.WrittenTo!], Report = basis.Report with { Payloads = [bundle, payload] } };
        var extracted = Shown(root, sample);
        Assert.Contains("Start here: Zebekeadu", extracted, StringComparison.Ordinal);
        Assert.Contains("cilantro '" + payload.WrittenTo, extracted, StringComparison.Ordinal);
        Assert.DoesNotContain("cilantro '" + bundle.WrittenTo, extracted, StringComparison.Ordinal);
        root = root with { EmbeddedRecovery = new(true, 4, 32, 1000,
            [new(sample, "root", 0, "recovered", RunManifest.Of(root)), new(payload.WrittenTo!, "payload", 1, "recovered", RunManifest.Of(child)), new(bundle.WrittenTo!, "bundle", 1, "limited", null, "Depth limit reached.")],
            [new(0, 1, payload.WrittenTo!), new(0, 2, bundle.WrittenTo!)]) };
        root = AnalystReport.Write(root, false);
        var html = File.ReadAllText(root.ReadableReportPath!);
        Assert.True(html.IndexOf("Start here: Zebekeadu", StringComparison.Ordinal) < html.IndexOf("Restored resource bundle", StringComparison.Ordinal));
        Assert.Contains("cleaned-child.dll", html, StringComparison.Ordinal);
        Assert.Contains("152", html, StringComparison.Ordinal);
        Assert.Contains("Depth limit reached.", html, StringComparison.Ordinal);
        Assert.DoesNotContain("cilantro &#39;", html, StringComparison.Ordinal);
    }

    [Fact]
    public void ReconstructionDetailsAreCollapsedAndPayloadAgreementIsSeparateFromCoverage()
    {
        using var directory = Temporary();
        var sample = WritePlain(directory.Path);
        var basis = new CilantroPipeline().Run(sample, new PipelineOptions(AnalyzeOnly: true, ReportDirectory: directory.Path));
        var result = AnalystReport.Write(basis with
        {
            RebuiltMethods = 1,
            Report = basis.Report with
            {
                RebuiltMethods = [new("<method>", ["<api>"], ["field"], false, 100)],
                Evidence = [new("reconstruction-payload-comparison", "Both interpreter runs extracted identical assembly bytes."), new("reconstruction-coverage", "Reconstructed bodies exercised by this comparison: 0 of 2.")]
            }
        }, false);
        var html = File.ReadAllText(result.ReadableReportPath!);
        Assert.Contains("<details><summary>Reconstructed bodies (1)", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<details open", html, StringComparison.Ordinal);
        Assert.Contains("&lt;method&gt;", html, StringComparison.Ordinal);
        Assert.Contains("Both interpreter runs extracted identical", html, StringComparison.Ordinal);
        Assert.Contains("0 of 2", html, StringComparison.Ordinal);
        Assert.Contains("No direct callers were found", html, StringComparison.Ordinal);
    }

    [Fact]
    public void MethodDisagreementIsVisibleEvenWhenPayloadEvidenceExistsAndEmissionSucceeded()
    {
        using var directory = Temporary();
        var sample = WritePlain(directory.Path);
        var basis = new CilantroPipeline().Run(sample, new PipelineOptions(AnalyzeOnly: true, ReportDirectory: directory.Path));
        var result = AnalystReport.Write(basis with
        {
            Success = true, AnalyzeOnly = false, OutputPath = Path.Combine(directory.Path, "cleaned.dll"),
            RebuiltMethods = 1, DevirtualizationCheck = DevirtualizationCheck.Disagreed,
            Report = basis.Report with
            {
                VerificationPassed = true,
                Evidence = [new("reconstruction-payload-comparison", "Payload bytes matched."),
                    new("reconstruction-method-trial", "Debugger-present trial: original threw; rebuilt completed.")]
            }
        }, false);
        var page = Shown(result, sample);
        Assert.Contains("NEEDS REVIEW", page, StringComparison.Ordinal);
        Assert.Contains("Reconstruction check disagreed", page, StringComparison.Ordinal);
        Assert.Contains("Structural checks passed", page, StringComparison.Ordinal);
        Assert.DoesNotContain("did not reproduce the original payload", page, StringComparison.Ordinal);
        Assert.DoesNotContain("Debugger-present trial", page, StringComparison.Ordinal);
        Assert.Contains("Debugger-present trial", Shown(result, sample, verbose: true), StringComparison.Ordinal);
        var html = File.ReadAllText(result.ReadableReportPath!);
        Assert.Contains("<section class=\"notice\"><h2>Needs review", html, StringComparison.Ordinal);
        Assert.Contains("Debugger-present trial", html, StringComparison.Ordinal);
    }

    [Fact]
    public void ChildReconstructionDisagreementIsVisibleInTheParentSummary()
    {
        using var directory = Temporary();
        var sample = WritePlain(directory.Path);
        var basis = new CilantroPipeline().Run(sample, new PipelineOptions(AnalyzeOnly: true, ReportDirectory: directory.Path));
        var payload = Path.Combine(directory.Path, "child.dll");
        var child = basis with { DevirtualizationCheck = DevirtualizationCheck.Disagreed,
            Report = basis.Report with { InputPath = payload } };
        var root = basis with
        {
            EmbeddedRecovery = new(true, 4, 32, 1000,
                [new(sample, "root", 0, "recovered", RunManifest.Of(basis)),
                 new(payload, "child", 1, "recovered", RunManifest.Of(child))],
                [new(0, 1, payload)])
        };
        var page = Shown(root, sample);
        Assert.Contains("NEEDS REVIEW", page, StringComparison.Ordinal);
        Assert.Contains("child.dll: reconstruction check disagreed", page, StringComparison.Ordinal);
    }

    private static string Shown(PipelineResult result, string sample, bool verbose = false)
    {
        var page = new StringBuilder();
        using var writer = new StringWriter(page);
        Explain.Summarize(result, sample, writer, verbose);
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
