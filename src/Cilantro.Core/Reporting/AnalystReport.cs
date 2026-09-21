using System.Globalization;
using System.Net;
using System.Text;
using Cilantro.Core.Recovery;

namespace Cilantro.Core;

/// <summary>Offline, script-free HTML. Every sample-controlled value is escaped.</summary>
internal static class AnalystReport
{
    public static PipelineResult Write(PipelineResult result, bool analyzeOnly)
    {
        var directory = Path.GetDirectoryName(result.AnalysisReportPath)!;
        var path = Path.Combine(directory, Path.GetFileNameWithoutExtension(result.Report.InputPath) + ".report.html");
        result = result with { ReadableReportPath = path, AnalyzeOnly = analyzeOnly };
        var summary = AnalystSummary.Of(result);
        var html = new StringBuilder("""
            <!doctype html><html lang="en"><head><meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>CILantro recovery report</title>
            <style>
            :root{color-scheme:light}*{box-sizing:border-box}body{margin:0;background:#f3f6f8;color:#192a38;font:16px/1.6 system-ui,sans-serif}
            main{max-width:1060px;margin:40px auto;padding:0 24px 48px}.eyebrow{color:#376b71;font-size:.8rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase}
            h1{font-size:2rem;line-height:1.25;margin:.5rem 0}h2{font-size:1.2rem;margin:0 0 14px}h3{margin:0;font-size:1.05rem}
            header{margin-bottom:28px}header p{color:#526676}section,.artifact{background:white;border:1px solid #dce4e8;border-radius:10px;padding:22px;margin:18px 0}
            .artifact{margin:12px 0;border-left:4px solid #49848a}.artifact p{margin:8px 0}.status{display:inline-block;background:#edf3f5;padding:2px 9px;border-radius:5px;font-size:.85rem}
            .route{color:#526676;font-size:.9rem}.links{display:flex;flex-wrap:wrap;gap:12px}a{color:#12676d;text-underline-offset:3px}a:focus-visible,summary:focus-visible{outline:3px solid #df9c37;outline-offset:4px}
            li{margin:7px 0}ul{padding-left:22px;margin:8px 0}p,li,h3,code,a{overflow-wrap:anywhere}details{border-top:1px solid #e1e7ec;padding:13px 0;margin-top:12px}summary{cursor:pointer;font-weight:600}
            .notice{color:#814d14;background:#fff6e9;border-radius:5px;padding:10px}code{white-space:pre-wrap;font-size:.87rem}small{color:#526676}footer{margin-top:28px}
            @media(max-width:600px){main{margin:20px auto;padding:0 14px 30px}section,.artifact{padding:16px}h1{font-size:1.6rem}}
            </style></head><body><main>
            """);
        html.Append("<header><div class=\"eyebrow\">CILantro · Recovery report</div><h1>")
            .Append(E(summary.Outcome)).Append("</h1><p>").Append(E(Path.GetFileName(result.Report.InputPath)))
            .Append(" · ").Append(E(summary.Protection)).Append("</p></header>");
        var artifacts = AnalystArtifact.Of(result);
        foreach (var section in summary.Sections.Where(section => !section.DetailsOnly && section.Items.Count > 0))
        {
            if (section.Title == "Artifacts")
            {
                html.Append("<section><h2>Recovered artifacts</h2><p>Follow the extraction path below. Cleaned outputs and original extracted copies are kept separately.</p>");
                foreach (var artifact in artifacts) Artifact(html, artifact, directory);
                html.Append("<small>Extraction provenance establishes how a file was found, not its malware family or final role.</small></section>");
                continue;
            }
            html.Append(section.Title == "Needs review" ? "<section class=\"notice\"><h2>" : "<section><h2>")
                .Append(E(section.Title)).Append("</h2><ul>");
            foreach (var item in section.Items)
            {
                html.Append("<li>").Append(E(item.Text));
                if (item.Path is { } target) html.Append(": ").Append(Link(target, directory, Path.GetFileName(target)));
                html.Append("</li>");
            }
            html.Append("</ul></section>");
        }
        html.Append("<section><h2>Technical details</h2>");
        foreach (var section in summary.Sections.Where(section => section.DetailsOnly && section.Items.Count > 0))
        {
            html.Append("<details><summary>").Append(E(section.Title)).Append("</summary><ul>");
            foreach (var item in section.Items) html.Append("<li>").Append(E(item.Text)).Append("</li>");
            html.Append("</ul></details>");
        }
        if (result.Report.RebuiltMethods is { Count: > 0 } rebuilt)
        {
            html.Append("<details><summary>Reconstructed bodies (").Append(rebuilt.Count)
                .Append(")</summary><p>These are reconstructions from virtual-machine instructions, not original method bodies.</p>");
            var index = 0;
            foreach (var method in rebuilt)
            {
                html.Append("<details><summary>Body ").Append(++index).Append(" — ").Append(method.Instructions.ToString("N0", CultureInfo.InvariantCulture))
                    .Append(" IL instructions; ").Append(method.Reachable ? "callers found" : "no direct callers found")
                    .Append("</summary><p><code>").Append(E(method.Method)).Append("</code></p><p>No direct callers does not exclude reflection or other indirect calls.</p><ul>");
                foreach (var member in method.Reaches) html.Append("<li>Uses: ").Append(E(member)).Append("</li>");
                foreach (var field in method.Writes) html.Append("<li>Writes: ").Append(E(field)).Append("</li>");
                html.Append("</ul></details>");
            }
            html.Append("</details>");
        }
        html.Append("<details><summary>Processing and validation diagnostics</summary><ul>");
        foreach (var pass in result.Report.Passes.Where(p => p.Status != PassStatus.Success && p.Pass is not ("reactor-detection" or "confuserex-detection")))
        {
            html.Append("<li>").Append(E(pass.Pass)).Append(" (").Append(pass.Status).Append(")<ul>");
            foreach (var diagnostic in pass.Diagnostics) html.Append("<li>").Append(E(diagnostic)).Append("</li>");
            html.Append("</ul></li>");
        }
        foreach (var diagnostic in result.Report.VerificationDiagnostics.Concat(result.DevirtualizationNotes)) html.Append("<li>").Append(E(diagnostic)).Append("</li>");
        html.Append("</ul></details><details><summary>JSON reports and virtual-machine listings</summary><ul>");
        foreach (var target in new[] { result.AnalysisReportPath, result.ChangesReportPath, result.BlockerReportPath, result.RenameMapPath, result.ConfigReportPath, result.EmbeddedRecoveryReportPath }
            .Where(p => p is not null).Cast<string>().Concat(result.VirtualProgramPaths))
            html.Append("<li>").Append(Link(target, directory)).Append("</li>");
        html.Append("</ul></details><details><summary>Input identity</summary><p>").Append(E(result.Report.InputPath))
            .Append("</p><p>SHA-256: <code>").Append(E(result.Report.InputSha256)).Append("</code></p></details></section><footer><small>CILantro ")
            .Append(E(result.Report.ToolVersion)).Append(" · Static recovery; the sample was not executed.</small></footer></main></body></html>");
        File.WriteAllText(path, html.ToString(), new UTF8Encoding(false));
        return result;
    }

    private static void Artifact(StringBuilder html, AnalystArtifact artifact, string directory)
    {
        html.Append("<article class=\"artifact\"><div class=\"route\">").Append(E(artifact.Parent)).Append(" → ").Append(E(artifact.Name))
            .Append("</div><h3>").Append(E(artifact.Name)).Append("</h3><p><span class=\"status\">").Append(E(artifact.Status)).Append("</span></p><p>")
            .Append(E(artifact.Source)).Append("</p><p class=\"links\">");
        if (artifact.Cleaned is { } cleaned) html.Append(Link(cleaned, directory, "Open cleaned assembly"));
        if (artifact.Report is { } report) html.Append(Link(report, directory, "Recovery report"));
        if (artifact.Original is { } original) html.Append(Link(original, directory, "Original extracted copy"));
        html.Append("</p>");
        if (artifact.Run is { } run)
        {
            html.Append("<p>Structural checks: ").Append(run.Verified ? "passed" : "failed")
                .Append(". Encrypted string uses resolved: ").Append(run.Recovery.ReplacedStringSites.ToString("N0", CultureInfo.InvariantCulture)).Append(".</p>");
            if (run.Recovery.RemainingMethodStubs > 0) html.Append("<p class=\"notice\">Unrecovered method bodies remain.</p>");
            if (run.RebuiltMethods + run.LiftedPrograms > 0 && run.RebuiltCheck != DevirtualizationCheck.Agreed)
                html.Append("<p class=\"notice\">Reconstructed code has not passed the payload comparison.</p>");
        }
        if (artifact.Limitation is { } limitation) html.Append("<p class=\"notice\">").Append(E(limitation)).Append(" See the child report for details.</p>");
        html.Append("<details><summary>File identity and extraction source</summary>");
        if (artifact.Payload is { } payload)
            html.Append("<p>Assembly: ").Append(E(payload.AssemblyName)).Append("</p><p>Size: ")
                .Append(payload.PayloadLength.ToString("N0", CultureInfo.InvariantCulture)).Append(" bytes</p><p>SHA-256: <code>").Append(E(payload.PayloadSha256))
                .Append("</code></p><p>Source: ").Append(E(payload.SourceResource)).Append("</p><p>Managed entry point: ")
                .Append(payload.EntryPointToken == 0 ? "absent (libraries can still contain executable code)" : "present")
                .Append(". Embedded resources: ").Append(payload.EmbeddedResources.Count).Append(".</p>");
        if (artifact.Original is { } fullPath) html.Append("<p>Extracted path: <code>").Append(E(fullPath)).Append("</code></p>");
        html.Append("</details></article>");
    }
    private static string E(string value) => WebUtility.HtmlEncode(value);
    private static string Link(string path, string directory, string? label = null)
    {
        var relative = Path.GetRelativePath(directory, path);
        var href = Path.IsPathRooted(relative) ? new Uri(Path.GetFullPath(path)).AbsoluteUri
            : "./" + string.Join("/", relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Select(Uri.EscapeDataString));
        return "<a href=\"" + E(href) + "\">" + E(label ?? relative) + "</a>";
    }
}
