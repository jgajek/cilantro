using Cilantro.Core.Recovery;

namespace Cilantro.Core.Pipeline;

/// <summary>Publishes restored culture companions without replacing protected source files.</summary>
internal static class ResourceSatelliteEmission
{
    internal static bool HasSatellites(ArtifactContext context) => context.TryGetFact<IReadOnlyList<DotfuscatorResourceSatellites.Restored>>(
        DotfuscatorResourceSatellites.Fact, out var satellites) && satellites is { Count: > 0 };

    internal static bool TryWrite(ArtifactContext context, string outputPath, out IReadOnlyList<string> paths, out string why, bool validateOnly = false)
    {
        paths = [];
        why = "";
        if (!context.TryGetFact<IReadOnlyList<DotfuscatorResourceSatellites.Restored>>(
                DotfuscatorResourceSatellites.Fact, out var satellites) || satellites is not { Count: > 0 }) return true;
        var created = new List<string>();
        try
        {
            var root = Path.GetDirectoryName(outputPath)!;
            var targets = satellites.Select(satellite => (Satellite: satellite, Path: Path.Combine(root, satellite.Culture, satellite.FileName))).ToArray();
            foreach (var target in targets)
            {
                var directory = Path.GetDirectoryName(target.Path)!;
                if (Directory.Exists(directory) && (File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("Satellite output directory cannot be a symbolic link.");
                if (File.Exists(target.Path))
                {
                    if ((File.GetAttributes(target.Path) & FileAttributes.ReparsePoint) != 0 ||
                        new FileInfo(target.Path).Length != target.Satellite.Bytes.Length ||
                        !File.ReadAllBytes(target.Path).AsSpan().SequenceEqual(target.Satellite.Bytes))
                        throw new IOException($"Satellite output already exists with different bytes: {target.Path}. Choose a separate output directory.");
                }
            }
            if (validateOnly) return true;
            foreach (var target in targets)
            {
                if (File.Exists(target.Path)) continue;
                Directory.CreateDirectory(Path.GetDirectoryName(target.Path)!);
                using var stream = new FileStream(target.Path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                created.Add(target.Path);
                stream.Write(target.Satellite.Bytes);
            }
            paths = targets.Select(target => target.Path).ToArray();
            foreach (var path in paths) context.AddEvidence(new("restored-resource-satellite", path));
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            foreach (var path in created) File.Delete(path);
            why = exception.Message;
            return false;
        }
    }
}
