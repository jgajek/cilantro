using System.Buffers.Binary;
using System.Resources;
using System.Security.Cryptography;
using dnlib.DotNet;
using Cilantro.Core.Payload;

namespace Cilantro.Core.Recovery;

/// <summary>Reads raw byte-array/stream resource entries without deserializing objects.</summary>
public sealed class ResourceEntryExtractionPass : DeobfuscationPass
{
    public override string Name => "resource-entry-extraction";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => ["costura-extraction"];
    private const int MaximumContainerBytes = 64 * 1024 * 1024;
    private const int MaximumEntries = 4096;
    private const int MaximumOutputBytes = 128 * 1024 * 1024;

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var extracted = new List<ExtractedPayload>();
        var diagnostics = new List<string>();
        var partial = false;
        var entries = 0;
        var outputBytes = 0;
        foreach (var resource in context.Module.Resources.OfType<EmbeddedResource>()
                     .Where(resource => resource.Name.String.EndsWith(".resources", StringComparison.OrdinalIgnoreCase)))
        {
            try
            {
                if (resource.CreateReader().Length > MaximumContainerBytes)
                    throw new InvalidDataException("Resource container exceeds the 64 MiB limit.");
                var container = resource.CreateReader().ToArray();
                var sourceHash = Convert.ToHexStringLower(SHA256.HashData(container));
                using var reader = new ResourceReader(new MemoryStream(container, writable: false));
                var iterator = reader.GetEnumerator();
                while (iterator.MoveNext())
                {
                    if (++entries > MaximumEntries)
                        throw new InvalidDataException("Resource-entry limit reached.");
                    // Never read iterator.Value: it can deserialize a user-defined object.
                    var key = (string)iterator.Key;
                    reader.GetResourceData(key, out var type, out var raw);
                    if (type is not ("ResourceTypeCode.ByteArray" or "ResourceTypeCode.Stream"))
                        continue;
                    if (raw.Length < 4 || BinaryPrimitives.ReadInt32LittleEndian(raw) != raw.Length - 4)
                    {
                        partial = true;
                        diagnostics.Add($"{resource.Name}/{key}: invalid byte-array/stream length.");
                        continue;
                    }
                    if (raw.Length < 6 || raw[4] != 'M' || raw[5] != 'Z') continue;
                    if (raw.Length - 4 > MaximumOutputBytes - outputBytes)
                        throw new InvalidDataException("Resource payload output limit reached.");
                    var image = raw.AsSpan(4).ToArray();
                    PayloadInfo info;
                    var hash = Convert.ToHexStringLower(SHA256.HashData(image));
                    var source = $"{resource.Name}/{key}";
                    if (CosturaResource.TryNative(image, out var upx))
                    {
                        info = new(source, sourceHash, container.Length, hash, image.Length, hash,
                            key, key, 0, [], Origin: PayloadOrigin.NativeDependency);
                        diagnostics.Add($"Extracted native PE {source}. " +
                            (upx ? "UPX section markers detected; unpacking remains required." : "Native deprotection was not performed."));
                    }
                    else
                    {
                        try
                        {
                            using var module = ModuleDefMD.Load(image);
                            info = new(source, sourceHash, container.Length, hash, image.Length, hash,
                                module.Assembly?.Name.String ?? module.Name.String, module.Name,
                                module.EntryPoint?.MDToken.Raw ?? 0,
                                module.Resources.Select(item => item.Name.String).ToArray(),
                                Origin: PayloadOrigin.ResourceCodec);
                        }
                        catch (Exception exception) when (ManagedImage.Rejects(exception))
                        {
                            partial = true;
                            diagnostics.Add($"{source}: PE-like entry could not be validated: {exception.Message}");
                            continue;
                        }
                    }
                    extracted.Add(new(info, image));
                    outputBytes += image.Length;
                    context.AddChange(new(Name, "extract-resource-entry", source, $"SHA-256 {hash}; {image.Length} bytes."));
                }
            }
            catch (Exception exception) when (ManagedImage.Rejects(exception))
            {
                partial = true;
                diagnostics.Add($"{resource.Name}: {exception.Message}");
            }
            if (entries > MaximumEntries) break;
        }
        context.TryGetFact<IReadOnlyList<ExtractedPayload>>("payload.artifacts", out var existing);
        context.SetFact<IReadOnlyList<ExtractedPayload>>("payload.artifacts", [.. existing ?? [], .. extracted]);
        diagnostics.Insert(0, $"Extracted {extracted.Count} PE payload(s) from application resource entries; serialized objects were not deserialized.");
        return (partial ? PassStatus.Partial : PassStatus.Success, extracted.Count, diagnostics);
    }
}
