using System.Security.Cryptography;
using dnlib.DotNet;

namespace Cilantro.Core.Analysis;

/// <summary>The exact input resource used by a successful decoder, not an inferred resource role.</summary>
public sealed record RecoveredResourceOrigin(string Name, string Sha256)
{
    public static RecoveredResourceOrigin Capture(EmbeddedResource resource) =>
        new(resource.Name.String, Convert.ToHexStringLower(SHA256.HashData(resource.CreateReader().ToArray())));

    public bool Matches(EmbeddedResource resource) => Name == resource.Name.String && Capture(resource).Sha256 == Sha256;
}

/// <summary>A decoded resource bundle and the exact application streams restored from it.</summary>
public sealed record RestoredResourceBundle(RecoveredResourceOrigin Source, IReadOnlyList<RecoveredResourceOrigin> Entries)
{
    public bool IsPreserved(ModuleDef module) => Entries.Count != 0 && Entries.All(entry =>
        entry.Name != Source.Name && module.Resources.Count(resource => resource.Name.String == entry.Name) == 1 &&
        module.Resources.OfType<EmbeddedResource>().Count(entry.Matches) == 1);
}
