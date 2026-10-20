using Cilantro.Core.Recovery;

namespace Cilantro.Core.Pipeline;

/// <summary>Publishes ordinary dependencies required by a retired embedded loader.</summary>
internal static class DependencyDeploymentEmission
{
    internal static bool HasDependencies(ArtifactContext context) => context.TryGetFact<IReadOnlyList<BabelDependencyDeploymentPass.Dependency>>(
        BabelDependencyDeploymentPass.Fact, out var files) && files is { Count: > 0 };

    internal static bool TryWrite(ArtifactContext context, string outputPath, out IReadOnlyList<string> paths, out string why, bool validateOnly = false)
    {
        paths = []; why = "";
        if (!context.TryGetFact<IReadOnlyList<BabelDependencyDeploymentPass.Dependency>>(BabelDependencyDeploymentPass.Fact, out var files) || files is null) return true;
        var created = new List<string>();
        try
        {
            var root = Path.GetDirectoryName(Path.GetFullPath(outputPath))!;
            if (Directory.Exists(root) && (File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0) throw new IOException("Dependency output directory cannot be a symbolic link.");
            var targets = files.Select(file => (File: file, Path: Path.Combine(root, file.Name))).ToArray();
            foreach (var target in targets)
            {
                if (Path.GetFileName(target.File.Name) != target.File.Name || string.Equals(target.Path, Path.GetFullPath(outputPath), StringComparison.OrdinalIgnoreCase))
                    throw new IOException("Dependency deployment conflicts with the cleaned assembly path.");
                if (File.Exists(target.Path) && ((File.GetAttributes(target.Path) & FileAttributes.ReparsePoint) != 0 ||
                    new FileInfo(target.Path).Length != target.File.Bytes.Length || !File.ReadAllBytes(target.Path).AsSpan().SequenceEqual(target.File.Bytes)))
                    throw new IOException($"Dependency output already exists with different bytes: {target.Path}. Choose a separate output directory.");
            }
            if (validateOnly) return true;
            Directory.CreateDirectory(root);
            foreach (var target in targets)
            {
                if (File.Exists(target.Path)) continue;
                using var stream = new FileStream(target.Path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                created.Add(target.Path); stream.Write(target.File.Bytes);
            }
            paths = targets.Select(target => target.Path).ToArray();
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            foreach (var file in created) File.Delete(file);
            why = exception.Message; return false;
        }
    }
}
