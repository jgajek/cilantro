using System.Security.Cryptography;
using dnlib.DotNet;
using Cilantro.Core.Passes;
using Cilantro.Core.Payload;

namespace Cilantro.Core.Recovery;

/// <summary>
/// Extracts assemblies embedded by Costura.Fody into the shared payload writer.
/// </summary>
/// <remarks>
/// Costura stores each merged assembly as an embedded resource named <c>costura.&lt;name&gt;.dll</c>
/// or, when packed, <c>costura.&lt;name&gt;.dll.compressed</c> holding a raw DEFLATE stream. This is
/// orthogonal to Reactor's own protection but frequently layered underneath it, so recovering these
/// assemblies is part of reaching the real payload. Each candidate is bounded-decompressed when
/// packed and validated as managed metadata or a native PE before it is accepted; invalid content is
/// dropped rather than emitted, and the module itself is not modified.
/// </remarks>
public sealed class CosturaExtractionPass : DeobfuscationPass
{
    public override string Name => "costura-extraction";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => ["payload-extraction"];

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        var candidates = context.Module.Resources
            .OfType<EmbeddedResource>()
            .Where(resource => CosturaResource.IsCandidate(resource.Name.String))
            .ToArray();
        if (candidates.Length == 0)
            return (PassStatus.Success, 0, ["No Costura.Fody embedded assembly was detected."]);

        var extracted = new List<ExtractedPayload>();
        var diagnostics = new List<string>();
        var incomplete = false;
        foreach (var resource in candidates)
        {
            var encoded = resource.CreateReader().ToArray();
            byte[] assemblyBytes;
            try
            {
                if (encoded.Length > CosturaResource.MaximumLength)
                    throw new InvalidDataException("Resource exceeds the extraction size limit");
                assemblyBytes = resource.Name.String.EndsWith(
                        ".compressed", StringComparison.OrdinalIgnoreCase)
                    ? ResourceTransforms.Decompress(encoded, "deflate", CosturaResource.MaximumLength)
                    : encoded;
            }
            catch (Exception exception) when (
                exception is InvalidDataException or NotSupportedException)
            {
                incomplete = true;
                diagnostics.Add($"Costura resource {resource.Name} could not be decompressed: {exception.Message}.");
                continue;
            }

            PayloadInfo info;
            try
            {
                if (CosturaResource.TryNative(assemblyBytes, out var upx))
                {
                    var hash = Convert.ToHexStringLower(SHA256.HashData(assemblyBytes));
                    info = new PayloadInfo(resource.Name,
                        Convert.ToHexStringLower(SHA256.HashData(encoded)), encoded.Length,
                        hash, assemblyBytes.Length, hash, resource.Name, resource.Name, 0, [],
                        Origin: PayloadOrigin.NativeDependency);
                    diagnostics.Add($"Native PE extracted from {resource.Name}; " +
                        (upx ? "UPX section markers detected; unpacking has not been performed." : "Native code was not deprotected."));
                }
                else
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
                        payloadModule.Resources.Select(item => item.Name.String).ToArray(),
                        Origin: PayloadOrigin.EmbeddedDependency);
                    }
            }
            catch (Exception exception) when (ManagedImage.Rejects(exception))
            {
                incomplete = true;
                diagnostics.Add($"Costura resource {resource.Name} is not a valid managed assembly or native PE: {exception.Message}.");
                continue;
            }
            extracted.Add(new ExtractedPayload(info, assemblyBytes));
            diagnostics.Add($"Extracted {info.AssemblyName} ({info.PayloadLength} bytes) from {resource.Name}.");
            context.AddEvidence(new Evidence(
                "costura-payload",
                $"Extracted Costura dependency {info.AssemblyName}.",
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
        diagnostics.Insert(0, $"Extracted {extracted.Count} Costura dependencies.");
        return (incomplete ? PassStatus.Partial : PassStatus.Success, extracted.Count, diagnostics);
    }
}
