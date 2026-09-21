using System.Security.Cryptography;

namespace Cilantro.Core;

/// <summary>Results of following embedded managed assemblies, keyed by content rather than filenames.</summary>
public sealed record EmbeddedRecoveryReport(
    bool Complete,
    int MaximumDepth,
    int MaximumArtifacts,
    long MaximumInputBytes,
    IReadOnlyList<EmbeddedRecoveryNode> Nodes,
    IReadOnlyList<EmbeddedRecoveryLink> Links);

public sealed record EmbeddedRecoveryNode(
    string InputPath, string? Sha256, int Depth, string Status, RunManifest? Run, string? Diagnostic = null);

public sealed record EmbeddedRecoveryLink(int Parent, int Child, string ExtractedPath);

/// <summary>Bounded breadth-first recovery; never executes an extracted assembly.</summary>
internal static class EmbeddedAssemblyRecovery
{
    internal const int MaximumDepth = 4;
    internal const int MaximumArtifacts = 32;
    internal const long MaximumInputBytes = 256L * 1024 * 1024;

    internal static PipelineResult Run(PipelineResult root, PipelineOptions options,
        Func<string, PipelineOptions, PipelineResult> recover, bool nativeOnly = false)
    {
        var nodes = new List<EmbeddedRecoveryNode>
        {
            new(root.Report.InputPath, root.Report.InputSha256, 0, root.Success ? "recovered" : "incomplete", RunManifest.Of(root))
        };
        var links = new List<EmbeddedRecoveryLink>();
        var known = new Dictionary<string, int>(StringComparer.Ordinal) { [root.Report.InputSha256] = 0 };
        var pending = new Queue<(int Parent, int Depth, string Path)>();
        Enqueue(root, 0, 1);
        var directory = Path.Combine(Path.GetDirectoryName(root.AnalysisReportPath)!,
            Path.GetFileNameWithoutExtension(root.Report.InputPath) + ".children");
        var processed = 1;
        var bytes = root.Report.InputLength;
        var complete = root.Success;
        while (pending.TryDequeue(out var next))
        {
            options.Cancellation.ThrowIfCancellationRequested();
            var node = nodes.Count;
            string? hash = null;
            long length;
            try
            {
                using var input = File.OpenRead(next.Path);
                length = input.Length;
                // Do not hash an oversized child: reading it would itself exceed the
                // traversal budget, even if we decided not to run recovery afterward.
                if (length > MaximumInputBytes - bytes)
                {
                    links.Add(new(next.Parent, node, next.Path));
                    nodes.Add(new(next.Path, null, next.Depth, "limited", null, "Total input-byte limit reached."));
                    complete = false;
                    continue;
                }
                hash = Convert.ToHexStringLower(SHA256.HashData(input));
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                links.Add(new(next.Parent, node, next.Path));
                nodes.Add(new(next.Path, null, next.Depth, "failed", null, exception.Message));
                complete = false;
                continue;
            }
            if (known.TryGetValue(hash, out var previous))
            {
                links.Add(new(next.Parent, previous, next.Path));
                continue;
            }
            known.Add(hash, node);
            links.Add(new(next.Parent, node, next.Path));
            var limit = next.Depth > MaximumDepth ? "Depth limit reached."
                : processed >= MaximumArtifacts ? "Artifact limit reached."
                : null;
            if (limit is not null)
            {
                nodes.Add(new(next.Path, hash, next.Depth, "limited", null, limit));
                complete = false;
                continue;
            }
            processed++;
            bytes += length;
            var childDirectory = Path.Combine(directory, hash);
            var childOptions = options with
            {
                RecoverEmbeddedAssemblies = false,
                ReportDirectory = childDirectory,
                OutputPath = Path.Combine(childDirectory, "cleaned" + Path.GetExtension(next.Path)),
                StatusPath = null
            };
            // The wrapper has no managed output of its own. An explicit destination
            // therefore belongs to its directly contained managed assembly.
            if (next.Parent == 0 && root.Report.Protector == Native.NativeBootstrapStage.BootstrapProtector
                && options.OutputPath is not null)
                childOptions = childOptions with { OutputPath = options.OutputPath };
            try
            {
                if (!childOptions.AnalyzeOnly && childOptions.OutputPath is { } output &&
                    (string.Equals(Path.GetFullPath(output), Path.GetFullPath(root.Report.InputPath), StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(Path.GetFullPath(output), Path.GetFullPath(next.Path), StringComparison.OrdinalIgnoreCase)))
                    throw new IOException("The cleaned output must not overwrite the input or extracted assembly.");
                var child = recover(next.Path, childOptions);
                nodes.Add(new(next.Path, hash, next.Depth, child.Success ? "recovered" : "incomplete", RunManifest.Of(child)));
                complete &= child.Success;
                // An incomplete cleanup can still have extracted a recoverable next stage.
                Enqueue(child, node, next.Depth + 1);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or BadImageFormatException or InvalidOperationException)
            {
                nodes.Add(new(next.Path, hash, next.Depth, "failed", null, exception.Message));
                complete = false;
            }
        }
        var report = new EmbeddedRecoveryReport(complete, MaximumDepth, MaximumArtifacts, MaximumInputBytes, nodes, links);
        var path = Path.Combine(Path.GetDirectoryName(root.AnalysisReportPath)!,
            Path.GetFileNameWithoutExtension(root.Report.InputPath) + ".embedded.json");
        CilantroPipeline.WriteJson(path, report);
        return root with { Success = complete, EmbeddedRecoveryReportPath = path, EmbeddedRecovery = report };

        void Enqueue(PipelineResult result, int parent, int depth)
        {
            if (nativeOnly && result.Report.Protector != Native.NativeBootstrapStage.BootstrapProtector)
                return;
            foreach (var path in result.ExtractedPayloadPaths) pending.Enqueue((parent, depth, path));
        }
    }
}
