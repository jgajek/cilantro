namespace Cilantro.Core;

/// <summary>Analyst labels come from extraction provenance and actual child-run results.</summary>
internal sealed record AnalystArtifact(
    string Name, string Parent, int Depth, PayloadOrigin Origin, string Source,
    string Status, string? Original, string? Cleaned, string? Report, PayloadInfo? Payload,
    RunManifest? Run, string? Diagnostic)
{
    internal static List<AnalystArtifact> Of(PipelineResult result)
    {
        var artifacts = new List<AnalystArtifact>();
        var rootName = Path.GetFileName(result.Report.InputPath);
        if (result.EmbeddedRecovery is { } chain)
        {
            for (var index = 1; index < chain.Nodes.Count; index++)
            {
                var node = chain.Nodes[index];
                var link = chain.Links.FirstOrDefault(link => link.Child == index);
                var parent = link is null ? null : chain.Nodes[link.Parent];
                var payload = parent?.Run?.Payloads.FirstOrDefault(p => p.PayloadSha256 == node.Sha256 || p.WrittenTo == node.InputPath);
                var parents = chain.Links.Where(edge => edge.Child == index)
                    .Select(edge => DisplayParent(chain.Nodes[edge.Parent])).Distinct(StringComparer.Ordinal);
                artifacts.Add(Create(payload, node.InputPath, string.Join(", ", parents), node.Depth, node));
            }
        }
        else
        {
            foreach (var path in result.ExtractedPayloadPaths)
                artifacts.Add(Create(result.Report.Payloads.FirstOrDefault(p => p.WrittenTo == path), path, rootName, 1, null));
        }
        return artifacts.OrderBy(a => Priority(a.Origin)).ThenBy(a => a.Depth).ThenBy(a => a.Name, StringComparer.Ordinal).ToList();
    }

    internal static AnalystArtifact? Lead(List<AnalystArtifact> artifacts) => artifacts.FirstOrDefault(a =>
        a.Origin is PayloadOrigin.AssemblyLoad or PayloadOrigin.NativeWrapper or PayloadOrigin.ResourceCodec);

    private static string DisplayParent(EmbeddedRecoveryNode node)
    {
        var name = Path.GetFileName(node.InputPath);
        return node.Sha256 is { Length: 64 } hash ? name.Replace("." + hash, "", StringComparison.Ordinal) : name;
    }

    private static AnalystArtifact Create(PayloadInfo? payload, string path, string parent, int depth, EmbeddedRecoveryNode? node)
    {
        var origin = payload?.Origin ?? PayloadOrigin.Unknown;
        var name = origin == PayloadOrigin.ResourceBundle ? "Restored resource bundle" : payload?.AssemblyName ?? Path.GetFileName(path);
        var source = origin switch
        {
            PayloadOrigin.AssemblyLoad => "Captured from an assembly load while interpreting the parent.",
            PayloadOrigin.ResourceBundle => "Decrypted resource bundle; resources were restored to the parent assembly.",
            PayloadOrigin.EmbeddedDependency => "Extracted from a bundled dependency resource.",
            PayloadOrigin.NativeWrapper => "Unpacked from the native wrapper.",
            PayloadOrigin.ResourceCodec => "Decoded from an embedded resource.",
            _ => "Extraction mechanism not recorded; role undetermined."
        };
        var run = node?.Run;
        var status = run?.Wrote.Cleaned is not null ? "Cleaned assembly available"
            : node?.Status == "limited" ? "Not processed: traversal limit"
            : node?.Status == "failed" ? "Recovery failed"
            : run is { Success: true } ? "Analyzed; no cleaned copy requested"
            : run is not null ? "Cleanup incomplete; extracted copy available"
            : "Extracted only; not yet cleaned";
        return new(name, parent, depth, origin, source, status, path, run?.Wrote.Cleaned,
            run?.Wrote.Report, payload, run, node?.Diagnostic);
    }

    internal string? Limitation => Run is { } run &&
        run.Passes.Any(p => p.Pass == "payload-extraction" && p.Status != PassStatus.Success)
        ? "Further payload extraction was not completed."
        : Diagnostic;

    private static int Priority(PayloadOrigin origin) => origin switch
    {
        PayloadOrigin.AssemblyLoad => 0,
        PayloadOrigin.NativeWrapper => 1,
        PayloadOrigin.ResourceCodec => 2,
        PayloadOrigin.Unknown => 3,
        PayloadOrigin.EmbeddedDependency => 4,
        _ => 5
    };
}
