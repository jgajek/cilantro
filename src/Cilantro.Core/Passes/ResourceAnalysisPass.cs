using System.Security.Cryptography;
using dnlib.DotNet;

namespace Cilantro.Core;

public sealed class ResourceAnalysisPass : DeobfuscationPass
{
    public override string Name => "resource-analysis";
    public override IReadOnlyCollection<string> Dependencies => ["field-rva-recovery"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var resources = ResourceInspector.Inspect(context.Module);
        context.SetFact("resources.catalog", resources);
        foreach (var resource in resources)
        {
            context.AddEvidence(new Evidence(
                "resource",
                $"{resource.Classification} resource, {resource.Length} bytes, entropy {resource.Entropy:F3}.",
                resource.Name,
                resource.Entropy > 7.5 ? 0.9 : 0.65));
        }

        return (PassStatus.Success, 0, [$"Cataloged {resources.Count} embedded resources."]);
    }
}

public static class ResourceInspector
{
    public static IReadOnlyList<ResourceInfo> Inspect(ModuleDef module) =>
        module.Resources
            .OfType<EmbeddedResource>()
            .Select(resource =>
            {
                var data = resource.CreateReader().ToArray();
                var entropy = Entropy.Calculate(data);
                var classification = Classify(data, entropy);
                return new ResourceInfo(
                    resource.Name,
                    (uint)data.Length,
                    entropy,
                    Convert.ToHexStringLower(SHA256.HashData(data)),
                    classification);
            })
            .ToArray();

    /// <summary>
    /// What a blob looks like from its first bytes and its entropy, for reports that list resources.
    /// </summary>
    /// <remarks>
    /// Public because the Win32 resources of a native bootstrap are described the same way as a
    /// managed module's own, and a reader comparing the two should not have to know that one of them
    /// was classified by a different rule.
    /// </remarks>
    public static string Classify(byte[] data, double entropy)
    {
        if (data.Length >= 2 && data[0] == 0x1F && data[1] == 0x8B) return "gzip";
        if (data.Length >= 2 && data[0] == 0x4D && data[1] == 0x5A) return "portable-executable";
        if (entropy > 7.85) return "encrypted-or-compressed";
        if (entropy > 7.0) return "encoded";
        return "structured";
    }
}
