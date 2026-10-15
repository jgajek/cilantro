using System.Security.Cryptography;
using System.Text.Json;

namespace Cilantro.Core;

/// <summary>A caller-supplied inventory of independently reviewed, unprotected dependencies.
/// Matching proves byte identity only; the classification is an explicit caller declaration.</summary>
internal sealed class ReviewedDependencyCatalog
{
    internal sealed record Reference(string Sha256, string Path, string Source, string Classification);
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };
    private readonly IReadOnlyDictionary<string, Reference> references;
    private ReviewedDependencyCatalog(IReadOnlyDictionary<string, Reference> references) => this.references = references;
    internal Reference? Match(string sha256) => references.GetValueOrDefault(sha256.ToLowerInvariant());
    internal static ReviewedDependencyCatalog Load(string manifest, CancellationToken cancellation = default)
    {
        var fullPath = System.IO.Path.GetFullPath(manifest);
        using var input = File.OpenRead(fullPath);
        if (input.Length > 1024 * 1024) throw new InvalidDataException("Reviewed dependency manifest exceeds 1 MiB.");
        var rows = JsonSerializer.Deserialize<Reference[]>(input, JsonOptions)
            ?? throw new InvalidDataException("Reviewed dependency manifest must be an array.");
        if (rows.Length is 0 or > 128) throw new InvalidDataException("Reviewed dependency manifest must contain 1 to 128 references.");
        var references = new Dictionary<string, Reference>(StringComparer.Ordinal);
        long total = 0;
        foreach (var row in rows)
        {
            cancellation.ThrowIfCancellationRequested();
            if (row is null || row.Sha256 is not { Length: 64 } || !row.Sha256.All(Uri.IsHexDigit) ||
                string.IsNullOrWhiteSpace(row.Path) || string.IsNullOrWhiteSpace(row.Source) ||
                row.Classification != "unprotected-dependency")
                throw new InvalidDataException("Each reviewed reference requires SHA-256, path, source and classification unprotected-dependency.");
            var hash = row.Sha256.ToLowerInvariant();
            if (references.ContainsKey(hash)) throw new InvalidDataException("Duplicate reviewed dependency hash.");
            var path = System.IO.Path.GetFullPath(row.Path, System.IO.Path.GetDirectoryName(fullPath)!);
            using var file = File.OpenRead(path);
            total += file.Length;
            if (total > 256L * 1024 * 1024) throw new InvalidDataException("Reviewed dependency reference bytes exceed 256 MiB.");
            if (Convert.ToHexStringLower(SHA256.HashData(file)) != hash)
                throw new InvalidDataException($"Reviewed dependency reference hash mismatch: {path}");
            references.Add(hash, row with { Sha256 = hash, Path = path });
        }
        return new(references);
    }
}
