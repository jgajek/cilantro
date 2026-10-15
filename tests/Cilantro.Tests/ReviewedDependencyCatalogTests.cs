using System.Security.Cryptography;
using System.Text.Json;
using Cilantro.Core;
namespace Cilantro.Tests;
public sealed class ReviewedDependencyCatalogTests
{
    [Theory]
    [InlineData("valid")]
    [InlineData("changed")]
    [InlineData("duplicate")]
    [InlineData("unclassified")]
    [InlineData("bad-hash")]
    [InlineData("missing-source")]
    public void RequiresExplicitReviewAndExactReferenceBytes(string mode)
    {
        var directory = Path.Combine(Path.GetTempPath(), "Cilantro.ReviewedReference." + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            byte[] bytes = [1, 2, 3, 4];
            var hash = Convert.ToHexStringLower(SHA256.HashData(bytes));
            File.WriteAllBytes(Path.Combine(directory, "reference.bin"), bytes);
            var row = new ReviewedDependencyCatalog.Reference(mode == "bad-hash" ? "bad" : hash, "reference.bin",
                mode == "missing-source" ? "" : "Reviewed upstream fixture", mode == "unclassified" ? "" : "unprotected-dependency");
            var manifest = Path.Combine(directory, "references.json");
            File.WriteAllText(manifest, JsonSerializer.Serialize(mode == "duplicate" ? new[] { row, row } : [row]));
            if (mode == "changed") File.WriteAllBytes(Path.Combine(directory, "reference.bin"), [5, 6]);
            if (mode != "valid") Assert.Throws<InvalidDataException>(() => ReviewedDependencyCatalog.Load(manifest));
            else
            {
                var catalog = ReviewedDependencyCatalog.Load(manifest);
                Assert.Equal(hash, catalog.Match(hash.ToUpperInvariant())?.Sha256);
                Assert.Null(catalog.Match(new string('0', 64)));
                Assert.Equal(Path.Combine(directory, "reference.bin"), catalog.Match(hash)?.Path);
            }
        }
        finally { Directory.Delete(directory, true); }
    }
}
