using System.Security.Cryptography;
using dnlib.DotNet;
using FileAttributes = System.IO.FileAttributes;

namespace Cilantro.Core;

/// <summary>Connects recursively recovered dependency images to their ordinary deployment files.</summary>
internal static class DependencyDeploymentCompletion
{
    private sealed record FilePlan(string Path, byte[] Bytes, byte[]? Before);

    internal static bool TryComplete(PipelineResult root, IList<EmbeddedRecoveryNode> nodes, IReadOnlyList<EmbeddedRecoveryLink> links,
        out PipelineResult completed, out string why)
    {
        completed = root; why = "";
        if (root.DependencyPaths.Count == 0) return true;
        var plans = new List<FilePlan>(); var changed = new List<FilePlan>();
        var paths = new Dictionary<int, string[]>();
        try
        {
            foreach (var parent in Enumerable.Range(0, nodes.Count).Where(n => nodes[n].Run?.Wrote.Dependencies.Count > 0))
            {
                var run = nodes[parent].Run!;
                if (!run.Success || !run.Verified || run.Wrote.Cleaned is not { } output) throw new IOException("A deployed dependency parent did not verify.");
                var directory = Path.GetDirectoryName(Path.GetFullPath(output))!;
                if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0) throw new IOException("Dependency deployment directory cannot be a symbolic link.");
                var files = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
                var visited = new HashSet<int>();
                Collect(parent);
                var direct = run.Wrote.Dependencies.Select(Path.GetFullPath).ToHashSet(StringComparer.OrdinalIgnoreCase);
                var targets = files.Select(pair => Path.Combine(directory, pair.Key)).ToArray();
                foreach (var pair in files)
                {
                    var target = Path.Combine(directory, pair.Key); byte[]? before = null;
                    if (string.Equals(target, Path.GetFullPath(output), StringComparison.OrdinalIgnoreCase)) throw new IOException("A dependency conflicts with its host assembly.");
                    if (File.Exists(target))
                    {
                        if ((File.GetAttributes(target) & FileAttributes.ReparsePoint) != 0) throw new IOException("Dependency deployment target cannot be a symbolic link.");
                        before = File.ReadAllBytes(target);
                        if (!direct.Contains(target) && !before.AsSpan().SequenceEqual(pair.Value)) throw new IOException("A transitive dependency conflicts with an existing file: " + target);
                    }
                    plans.Add(new(target, pair.Value, before));
                }
                paths[parent] = targets;

                void Collect(int index)
                {
                    if (!visited.Add(index)) return;
                    var owner = nodes[index].Run;
                    if (owner is null || !owner.Success || !owner.Verified) throw new IOException("A deployed dependency did not recover completely.");
                    foreach (var file in owner.Wrote.Dependencies)
                    {
                        var name = Path.GetFileName(file);
                        if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0) throw new IOException("Dependency source cannot be a symbolic link.");
                        var bytes = File.ReadAllBytes(file); var hash = Hash(bytes);
                        if (!owner.Payloads.Any(p => p.PayloadSha256 == hash && p.AssemblyName + ".dll" == name))
                            throw new IOException("A deployed dependency no longer matches its captured payload.");
                        var children = links.Where(l => l.Parent == index && nodes[l.Child].Sha256 == hash).Select(l => l.Child).Distinct().ToArray();
                        if (children.Length > 1) throw new IOException("A dependency has ambiguous recursive recovery results.");
                        if (children.Length == 1)
                        {
                            var child = nodes[children[0]];
                            if (child.Run is not { Success: true, Verified: true, Wrote.Cleaned: { } cleaned }) throw new IOException("A deployed dependency has no verified cleaned image.");
                            var replacement = File.ReadAllBytes(cleaned);
                            using var original = ModuleDefMD.Load(bytes); using var rewritten = ModuleDefMD.Load(replacement);
                            if (original.Assembly is null || rewritten.Assembly?.FullName != original.Assembly.FullName ||
                                name != original.Assembly.Name.String + ".dll") throw new IOException("A cleaned dependency changed assembly identity.");
                            bytes = replacement;
                            Collect(children[0]);
                        }
                        if (files.TryGetValue(name, out var existing) && !existing.AsSpan().SequenceEqual(bytes)) throw new IOException("Transitive dependency names conflict: " + name);
                        files[name] = bytes;
                    }
                }
            }
            if (plans.GroupBy(p => p.Path, StringComparer.OrdinalIgnoreCase).Any(g => g.Skip(1).Any(p => !p.Bytes.AsSpan().SequenceEqual(g.First().Bytes))))
                throw new IOException("Recursive deployment plans disagree on an output path.");
            foreach (var plan in plans.DistinctBy(p => p.Path, StringComparer.OrdinalIgnoreCase))
            {
                if (plan.Before is null ? File.Exists(plan.Path) : !File.Exists(plan.Path) || !File.ReadAllBytes(plan.Path).AsSpan().SequenceEqual(plan.Before))
                    throw new IOException("Dependency output changed during recursive deployment: " + plan.Path);
                if (plan.Before is not null && plan.Before.AsSpan().SequenceEqual(plan.Bytes)) continue;
                changed.Add(plan); File.WriteAllBytes(plan.Path, plan.Bytes);
            }
            foreach (var pair in paths)
                if (nodes[pair.Key].Run is { } run) nodes[pair.Key] = nodes[pair.Key] with { Run = run with { Wrote = run.Wrote with { Dependencies = pair.Value } } };
            if (paths.TryGetValue(0, out var rootPaths)) completed = root with { DependencyPaths = rootPaths };
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or BadImageFormatException)
        {
            foreach (var plan in changed.AsEnumerable().Reverse())
                if (plan.Before is null) File.Delete(plan.Path); else File.WriteAllBytes(plan.Path, plan.Before);
            why = exception.Message; return false;
        }
    }

    private static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
}
