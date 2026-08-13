using System.Security.Cryptography;
using dnlib.DotNet;
using ReactorUnpack.Core.Passes;
using ReactorUnpack.Core.Payload;

namespace ReactorUnpack.Core.Recovery;

/// <summary>
/// Extracts assemblies embedded by Costura.Fody into the shared payload writer.
/// </summary>
/// <remarks>
/// Costura stores each merged assembly as an embedded resource named <c>costura.&lt;name&gt;.dll</c>
/// or, when packed, <c>costura.&lt;name&gt;.dll.compressed</c> holding a raw DEFLATE stream. This is
/// orthogonal to Reactor's own protection but frequently layered underneath it, so recovering these
/// assemblies is part of reaching the real payload. Each candidate is bounded-decompressed when
/// packed and parsed as managed metadata before it is accepted; anything that fails to validate is
/// dropped rather than emitted, and the module itself is not modified.
/// </remarks>
public sealed class CosturaExtractionPass : DeobfuscationPass
{
    public override string Name => "costura-extraction";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => ["payload-extraction"];

    private const int MaximumAssemblyLength = 256 * 1024 * 1024;

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        var candidates = context.Module.Resources
            .OfType<EmbeddedResource>()
            .Where(resource => resource.Name.String.StartsWith("costura.", StringComparison.OrdinalIgnoreCase) &&
                (resource.Name.String.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                 resource.Name.String.EndsWith(".dll.compressed", StringComparison.OrdinalIgnoreCase)))
            .ToArray();
        if (candidates.Length == 0)
            return (PassStatus.Success, 0, ["No Costura.Fody embedded assembly was detected."]);

        var extracted = new List<ExtractedPayload>();
        var diagnostics = new List<string>();
        foreach (var resource in candidates)
        {
            var encoded = resource.CreateReader().ToArray();
            byte[] assemblyBytes;
            try
            {
                assemblyBytes = resource.Name.String.EndsWith(
                        ".compressed", StringComparison.OrdinalIgnoreCase)
                    ? ResourceTransforms.Decompress(encoded, "deflate", MaximumAssemblyLength)
                    : encoded;
            }
            catch (Exception exception) when (
                exception is InvalidDataException or NotSupportedException)
            {
                return (PassStatus.Partial, 0,
                [
                    $"Costura resource {resource.Name} could not be decompressed: {exception.Message}.",
                    "No Costura payload was recorded."
                ]);
            }

            PayloadInfo info;
            try
            {
                using var payloadModule = ModuleDefMD.Load(assemblyBytes);
                info = new PayloadInfo(
                    resource.Name,
                    Convert.ToHexStringLower(SHA256.HashData(encoded)),
                    encoded.Length,
                    Convert.ToHexStringLower(SHA256.HashData(assemblyBytes)),
                    assemblyBytes.Length,
                    Convert.ToHexStringLower(SHA256.HashData(assemblyBytes)),
                    payloadModule.Assembly?.Name.String ?? payloadModule.Name.String,
                    payloadModule.Name,
                    payloadModule.EntryPoint?.MDToken.Raw ?? 0,
                    payloadModule.Resources.Select(item => item.Name.String).ToArray());
            }
            catch (Exception exception) when (ManagedImage.Rejects(exception))
            {
                return (PassStatus.Partial, 0,
                [
                    $"Costura resource {resource.Name} is not a valid managed assembly: {exception.Message}.",
                    "No Costura payload was recorded."
                ]);
            }
            extracted.Add(new ExtractedPayload(info, assemblyBytes));
            diagnostics.Add($"Extracted {info.AssemblyName} ({info.PayloadLength} bytes) from {resource.Name}.");
            context.AddEvidence(new Evidence(
                "costura-payload",
                $"Recovered Costura-embedded assembly {info.AssemblyName}.",
                resource.Name,
                1.0));
            context.AddChange(new ChangeRecord(
                Name,
                "extract-costura-assembly",
                resource.Name,
                $"{info.AssemblyName}, SHA-256 {info.PayloadSha256}"));
        }

        var combined = context.TryGetFact<IReadOnlyList<ExtractedPayload>>(
                "payload.artifacts", out var existing) && existing is not null
            ? existing.Concat(extracted).ToArray()
            : extracted.ToArray();
        context.SetFact<IReadOnlyList<ExtractedPayload>>("payload.artifacts", combined);
        diagnostics.Insert(0, $"Extracted {extracted.Count} Costura-embedded assembly/assemblies.");
        return (PassStatus.Success, extracted.Count, diagnostics);
    }
}
