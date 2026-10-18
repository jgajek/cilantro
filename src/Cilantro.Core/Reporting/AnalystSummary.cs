using System.Globalization;
using Cilantro.Core.Recovery;

namespace Cilantro.Core;

/// <summary>The shared analyst-facing interpretation of a run.</summary>
public sealed record AnalystSummary(string Outcome, string Protection, IReadOnlyList<AnalystSection> Sections)
{
    public static AnalystSummary Of(PipelineResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        var report = result.Report;
        var r = report.Recovery;
        var bootstrap = report.Protector == "reactor-bootstrap" || report.Evidence.Any(e => e.Category == "native-bootstrap");
        var detected = report.Protector != "none" || report.Evidence.Any(e => e.Category == "capability");
        var protection = report.Evidence.FirstOrDefault(e => e.Category == "protector-name")?.Message ?? (report.Protector switch
        {
            "reactor" => ".NET Reactor",
            "reactor-bootstrap" => ".NET Reactor native wrapper",
            "confuserex" => "ConfuserEx",
            _ => detected ? "Unrecognized protector" : "No supported protection detected"
        });
        var outcome = !result.Success ? "Run incomplete" : result.OutputPath is not null ? "Cleaned assembly written"
            : bootstrap && result.ExtractedPayloadPaths.Count > 0 ? "Managed assembly extracted"
            : result.AnalyzeOnly ? "Analysis complete; no cleaned assembly requested"
            : !detected ? "No supported protection detected" : "No cleaned assembly written";
        var sections = new List<AnalystSection>();
        var artifacts = AnalystArtifact.Of(result);
        var lead = AnalystArtifact.Lead(artifacts);
        if (bootstrap && result.EmbeddedRecovery is not null)
            outcome = !result.Success ? "Native wrapper unpacked; managed recovery incomplete"
                : result.AnalyzeOnly ? "Native wrapper unpacked; managed assembly analyzed"
                : "Native wrapper unpacked; managed assembly cleaned";
        if (result.OutputPath is not null && artifacts.Count > 0)
            outcome = result.EmbeddedRecovery is null ? "Input cleaned; embedded assemblies extracted"
                : result.Success ? "Cleaned input and child assemblies written" : "Input cleaned; embedded recovery incomplete";
        var open = new List<AnalystItem>();
        if (lead is not null)
        {
            open.Add(new($"Start here: {lead.Name} ({lead.Status.ToLowerInvariant()})", lead.Cleaned ?? lead.Original));
            open.Add(new(lead.Source));
        }
        if (result.OutputPath is { } cleaned) open.Add(new("Cleaned input assembly", cleaned));
        else open.Add(new(result.AnalyzeOnly ? "No cleaned assembly requested (--analyze-only)."
            : bootstrap ? "Native wrapper unpacked; see the managed assembly and its recovery report below." : "No cleaned input assembly written; see Remaining."));
        if (result.ReadableReportPath is { } readable) open.Add(new("Readable report", readable));
        if (result.ConfigReportPath is { } config) open.Add(new("Recovered constants", config));
        open.Add(new("Case folder", Path.GetDirectoryName(result.AnalysisReportPath)!));
        sections.Add(new("Output", open));
        var attention = new List<AnalystItem>();
        if (result.VirtualizedMethods > result.RebuiltMethods || result.ProgramsRunElsewhere > result.LiftedPrograms)
            attention.Add(new("VM reconstruction is incomplete; the output is not fully unprotected. If another tool rewrote this sample, retry from the intact original."));
        if (result.DevirtualizationCheck == DevirtualizationCheck.Disagreed)
            attention.Add(new("Reconstruction check disagreed with the original. Treat reconstructed methods as unverified; inspect the comparison details before relying on them."));
        foreach (var artifact in artifacts.Where(a => a.Run?.RebuiltCheck == DevirtualizationCheck.Disagreed))
            attention.Add(new($"{artifact.Name}: reconstruction check disagreed with the original. Treat its reconstructed methods as unverified.", artifact.Report));
        if (!result.Success)
            attention.Add(new("Recovery is incomplete. Files already extracted may still be useful; review Remaining and the report."));
        if (!report.VerificationPassed)
            attention.Add(new("Structural verification failed. Do not treat the output as a verified assembly."));
        sections.Add(new("Needs review", attention));
        if (artifacts.Count > 0)
        {
            var inventory = new List<AnalystItem>();
            foreach (var artifact in artifacts)
            {
                inventory.Add(new($"{artifact.Parent} -> {artifact.Name}: {artifact.Status}", artifact.Cleaned ?? artifact.Original));
                inventory.Add(new(artifact.Source));
                if (artifact.Run is { } child && child.Recovery.ReplacedStringSites > 0)
                    inventory.Add(new($"{N(child.Recovery.ReplacedStringSites)} encrypted string uses resolved in {artifact.Name}."));
                if (artifact.Limitation is { } limitation) inventory.Add(new(limitation));
                if (artifact.Report is { } childReport) inventory.Add(new("Child report", childReport));
            }
            sections.Add(new("Artifacts", inventory));
        }
        if (report.DecodedResources is { Count: > 0 } decodedResources)
            sections.Add(new("Decoded resources", decodedResources.Select(resource =>
                new AnalystItem($"{resource.SourceResource}: {N(resource.DecodedLength)} decoded bytes; SHA-256 {resource.DecodedSha256}", resource.WrittenTo)).ToArray()));
        var next = new List<AnalystItem>();
        if (lead?.Cleaned is not null || lead is null && result.OutputPath is not null)
            next.Add(new("Open the recommended cleaned assembly in ILSpy or dnSpyEx to inspect its code."));
        else if (lead?.Original is { } original)
        {
            if (lead.Run is not null)
                next.Add(new("Managed recovery was attempted; review its report for remaining blockers.", lead.Report));
            else
            {
                next.Add(new("The extracted assembly has not been cleaned. Continue recovery with this PowerShell command:"));
                next.Add(new(Command(original)));
            }
        }
        else if (artifacts.FirstOrDefault(a => a.Origin != PayloadOrigin.ResourceBundle)?.Original is { } unknown)
        {
            next.Add(new("Inspect the extracted assembly; its role is not established. To attempt cleanup in PowerShell:"));
            next.Add(new(Command(unknown)));
        }
        if (!result.Success) next.Add(new("Review Remaining and the artifact reports for incomplete recovery or traversal limits."));
        if (!detected) next.Add(new("Detection covers supported protections only; this does not establish that the input is unobfuscated."));
        sections.Add(new("Next", next));

        var overview = new List<AnalystItem>();
        Add(overview, r.RestoredMethodBodies, "encrypted method bodies restored", "encrypted method body restored");
        Add(overview, r.ReplacedStringSites, "encrypted string uses resolved (not unique strings)", "encrypted string use resolved");
        Add(overview, r.ConstantStringSites, "additional string decoder calls replaced", "additional string decoder call replaced");
        Add(overview, result.Report.Passes.Where(p => p.Pass is "numeric-tables" or "integer-helpers" or "numeric-tables-recheck" or "integer-helpers-recheck" or
            "numeric-tables-completion" or "integer-helpers-completion" or "numeric-tables-finalization").Sum(p => p.Changes),
            "numeric constant uses recovered", "numeric constant use recovered");
        Add(overview, result.RebuiltMethods, "virtualized methods reconstructed as .NET code", "virtualized method reconstructed as .NET code");
        Add(overview, result.LiftedPrograms, "additional interpreter programs reconstructed as helper methods", "additional interpreter program reconstructed as a helper method");
        if (r.ProxyCallsRestored + r.TokensRestored > 0) overview.Add(new("Made hidden calls or metadata references explicit."));
        if (r.ControlFlowMethodsSimplified + r.RedirectedDispatcherEdges > 0) overview.Add(new("Simplified control flow and removed unreachable code."));
        if (r.ResourcesRestored > 0) overview.Add(new("Restored encrypted resources to the input assembly."));
        if (r.RuntimeTypesRemoved > 0) overview.Add(new("Removed unused protector support code."));
        if (overview.Count == 0) overview.Add(new(bootstrap ? "Unpacked the managed assembly from the native wrapper." : "No recovery changes recorded."));
        if (result.AnalyzeOnly && !bootstrap) overview.Insert(0, new("Analysis only: these changes were not saved as a cleaned assembly."));
        if (report.RebuiltMethods is { Count: > 0 } bodies && bodies.All(m => !m.Reachable))
            overview.Add(new("No direct callers were found for the reconstructed bodies after cleanup; they are retained for inspection. This does not rule out indirect calls."));
        sections.Add(new("What changed in the input", overview));
        var counters = new List<AnalystItem>();
        Add(counters, r.ProxyCallsRestored, "hidden method calls made explicit", "hidden method call made explicit");
        Add(counters, r.TokensRestored, "hidden metadata references resolved", "hidden metadata reference resolved");
        Add(counters, r.BooleansRecovered, "hidden true/false values resolved", "hidden true/false value resolved");
        Add(counters, r.ControlFlowMethodsSimplified, "method simplifications across passes (a method can count more than once)", "method simplification across passes (a method can count more than once)");
        Add(counters, r.ConstantBranchesFolded, "constant branches resolved", "constant branch resolved");
        Add(counters, r.RedirectedDispatcherEdges, "dispatcher jumps made direct", "dispatcher jump made direct");
        Add(counters, result.Report.Passes.Where(p => p.Pass is "dispatcher-paths" or "dispatcher-paths-completion" or "dispatcher-effects-completion").Sum(p => p.Changes),
            "dispatcher path rewrites", "dispatcher path rewrite");
        Add(counters, r.UnreachableInstructionsRemoved, "unreachable instructions removed", "unreachable instruction removed");
        Add(counters, r.ResourcesRestored, "encrypted resources restored", "encrypted resource restored");
        Add(counters, r.RuntimeTypesRemoved, "protector support types removed", "protector support type removed");
        Add(counters, r.SymbolsRenamed, "obfuscated names replaced with readable placeholders", "obfuscated name replaced with a readable placeholder");
        Add(counters, r.RemainingUnreachableInstructions, "unreachable instructions remain", "unreachable instruction remains");
        sections.Add(new("Recovery counters", counters, DetailsOnly: true));

        var remaining = new List<AnalystItem>();
        Add(remaining, r.RemainingMethodStubs, "method stubs still lack recovered bodies", "method stub still lacks a recovered body");
        Add(remaining, Math.Max(0, r.StringCallSites - r.ReplacedStringSites), "detected encrypted string uses remain unresolved", "detected encrypted string use remains unresolved");
        Add(remaining, Math.Max(0, result.VirtualizedMethods - result.RebuiltMethods), "virtualized methods were not reconstructed", "virtualized method was not reconstructed");
        Add(remaining, Math.Max(0, result.ProgramsRunElsewhere - result.LiftedPrograms), "additional interpreter programs were not rebuilt as methods; consult the listings", "additional interpreter program was not rebuilt as a method; consult the listings");
        Add(remaining, r.RemainingSwitchDispatchers, "dispatcher-like control-flow patterns remain; these can include ordinary program logic", "dispatcher-like control-flow pattern remains; this can be ordinary program logic");
        var incomplete = report.Passes.Where(p => p.Status != PassStatus.Success && p.Pass is not ("reactor-detection" or "confuserex-detection")).ToArray();
        if (incomplete.Length > 0) remaining.Add(new(incomplete.Length == 1
            ? "1 processing step was incomplete or failed; see the technical diagnostics."
            : $"{N(incomplete.Length)} processing steps were incomplete or failed; see the technical diagnostics."));
        if (report.Blockers is { Count: > 0 } blockers) remaining.Add(new($"Recovery encountered {N(blockers.Count)} blockers; see the blockers report for remedies."));
        if (result.ExtractedPayloadPaths.Count == 0)
            remaining.Add(new(incomplete.Length > 0 || report.Blockers is { Count: > 0 }
                ? "Extraction may be incomplete. No embedded assemblies were written."
                : "No embedded assemblies were found by supported extraction methods; other embedded content may remain."));
        else if (incomplete.Length > 0 || report.Blockers is { Count: > 0 }) remaining.Add(new("Extraction may be incomplete; additional embedded content may remain."));
        if (report.ContinuedPast is { Count: > 0 } continued) remaining.Add(new($"Recovery continued past {N(continued.Count)} {(continued.Count == 1 ? "call" : "calls")} it could not fully interpret; see the blockers report."));
        if (report.HostProfile?.Consulted.Any(f => f.Answered && !f.Stated) == true) remaining.Add(new("Recovery used assumed host settings; see the analysis report or --verbose."));
        foreach (var artifact in artifacts)
        {
            if (artifact.Limitation is { } limitation) remaining.Add(new($"{artifact.Name}: {limitation}", artifact.Report));
            else if (artifact.Run is { Success: false }) remaining.Add(new($"{artifact.Name}: cleanup incomplete.", artifact.Report));
        }
        if (remaining.Count == 0) remaining.Add(new("No remaining issues were recorded by the supported checks."));
        sections.Add(new("Remaining", remaining));
        var validation = new List<AnalystItem>
        {
            new(bootstrap ? "The extracted file was validated as a managed assembly."
                : report.VerificationPassed ? "Structural checks passed" + (result.OutputPath is null ? " on the in-memory assembly." : ".")
                    : "Structural checks failed; see the verification diagnostics."),
            new("Program behavior was not independently verified.")
        };
        var comparison = report.Evidence.Where(e => e.Category is "reconstruction-payload-comparison" or "reconstruction-coverage").ToArray();
        if (result.RebuiltMethods + result.LiftedPrograms > 0 || result.DevirtualizationCheck == DevirtualizationCheck.Disagreed)
            validation.Add(new(result.DevirtualizationCheck switch
            {
                DevirtualizationCheck.Agreed => "Bounded reconstruction checks agreed for the exercised paths; this is not full behavioral equivalence.",
                DevirtualizationCheck.Disagreed => "A reconstruction comparison disagreed. This can concern method behavior or payload extraction; see the comparison details.",
                _ => "Reconstructed methods have not been cross-checked conclusively; see comparison details for any partial coverage."
            }));
        if (!report.VerificationPassed)
            foreach (var diagnostic in report.VerificationDiagnostics) validation.Add(new(diagnostic));
        foreach (var evidence in report.Evidence.Where(e => e.Category == "reconstruction-state-boundary"))
            validation.Add(new(evidence.Message));
        sections.Add(new("Validation", validation));
        sections.Add(new("Reconstruction comparison details", comparison.Select(e => new AnalystItem(e.Message))
            .Concat(report.Evidence.Where(e => e.Category == "reconstruction-method-trial")
                .Select(e => new AnalystItem(e.Message))).ToArray(), DetailsOnly: true));
        return new(outcome, protection, sections);
    }
    private static string Command(string path) => "cilantro '" + path.Replace("'", "''", StringComparison.Ordinal) + "' --generic-recovery";
    private static string N(int value) => value.ToString("N0", CultureInfo.InvariantCulture);
    private static void Add(List<AnalystItem> items, int count, string plural, string singular)
    {
        if (count > 0) items.Add(new($"{N(count)} {(count == 1 ? singular : plural)}."));
    }
}

public sealed record AnalystSection(string Title, IReadOnlyList<AnalystItem> Items, bool DetailsOnly = false);
public sealed record AnalystItem(string Text, string? Path = null);
