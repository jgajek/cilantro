using System.Security.Cryptography;
using System.Text;
using Cilantro.Core.Analysis;
using Cilantro.Core.Codec;
using Cilantro.Core.Payload;
using dnlib.DotNet;

namespace Cilantro.Core.Recovery;

/// <summary>Extracts legacy Babel assemblies without loading code or deserializing object graphs.</summary>
public class BabelUnpackingPass : DeobfuscationPass
{
    public override string Name => "babel-unpacking";
    public override IReadOnlyCollection<string> Dependencies => ["payload-extraction", "babel-detection"];
    public override bool GatesEmission => false;

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<BabelStructureFacts>("babel.structure", out var facts) || facts?.IsBabel != true)
            return (PassStatus.Success, 0, ["No Babel resource unpacking required."]);
        var recovered = new List<ExtractedPayload>();
        context.TryGetFact<IReadOnlyList<ExtractedPayload>>("payload.artifacts", out var previouslyExtracted);
        var diagnostics = new List<string>();
        var incomplete = false;
        var publicKey = context.Module.Assembly?.PublicKey?.Data ?? [];
        context.TryGetFact<IReadOnlyList<BabelDecodedResource>>(BabelResourceRecoveryPass.ResourcesFact, out var decoded);
        var interpreted = (decoded ?? []).ToDictionary(resource => (resource.Info.SourceResource, resource.Info.SourceSha256));
        foreach (var resource in context.Module.Resources.OfType<EmbeddedResource>())
        {
            if (resource.Length > BabelResourceCodec.MaximumLength) continue;
            var encoded = resource.CreateReader().ToArray();
            var wasInterpreted = interpreted.TryGetValue((resource.Name.String, Convert.ToHexStringLower(SHA256.HashData(encoded))), out var captured);
            byte[] plain;
            if (wasInterpreted) plain = captured!.Bytes;
            else if (!BabelResourceCodec.IsCandidate(encoded)) continue;
            else if (!BabelResourceCodec.TryDecode(encoded, publicKey, out plain, out var why))
            {
                incomplete = true;
                diagnostics.Add($"{resource.Name}: {why}");
                continue;
            }
            IReadOnlyList<byte[]> assemblies;
            if (PayloadStageValidator.TryValidateManaged(plain, out _)) assemblies = [plain];
            else if (!TryReadAssemblyBundle(plain, out assemblies))
            {
                if (wasInterpreted)
                {
                    diagnostics.Add($"{resource.Name}: decoded data stream is reported separately; no managed assembly bundle is present.");
                    continue;
                }
                incomplete = true;
                diagnostics.Add($"{resource.Name}: decoded content is not a validated managed assembly or assembly bundle; retained encrypted input.");
                continue;
            }
            foreach (var bytes in assemblies)
            {
                PayloadStageValidator.TryValidateManaged(bytes, out var identity);
                var hash = Convert.ToHexStringLower(SHA256.HashData(bytes));
                if (previouslyExtracted?.Any(payload => payload.Info.SourceResource == resource.Name && payload.Info.PayloadSha256 == hash) == true) continue;
                var info = new PayloadInfo(resource.Name,
                    Convert.ToHexStringLower(SHA256.HashData(encoded)), encoded.Length,
                    Convert.ToHexStringLower(SHA256.HashData(plain)), bytes.Length, hash,
                    identity!.AssemblyName, identity.ModuleName, identity.EntryPointToken, identity.Resources,
                    Origin: PayloadOrigin.EmbeddedDependency);
                recovered.Add(new(info, bytes));
                context.AddChange(new(Name, "extract-babel-assembly", resource.Name, $"{info.AssemblyName}, SHA-256 {hash}"));
                context.AddEvidence(new("babel-payload", $"Decoded Babel resource into {info.AssemblyName} ({bytes.Length} bytes).", resource.Name, 0.95));
            }
        }
        var combined = context.TryGetFact<IReadOnlyList<ExtractedPayload>>("payload.artifacts", out var existing) && existing is not null
            ? existing.Concat(recovered).DistinctBy(payload => (payload.Info.SourceResource, payload.Info.PayloadSha256)).ToArray()
            : recovered.ToArray();
        context.SetFact<IReadOnlyList<ExtractedPayload>>("payload.artifacts", combined);
        diagnostics.Insert(0, $"Extracted {recovered.Count} managed Babel assembly artifact(s); encrypted source resources preserved.");
        return (incomplete ? PassStatus.Partial : PassStatus.Success, recovered.Count, diagnostics);
    }

    /// <summary>All-or-nothing parser for the count/name/length/PE assembly bundle.</summary>
    public static bool TryReadAssemblyBundle(byte[] bytes, out IReadOnlyList<byte[]> assemblies)
    {
        assemblies = [];
        if (bytes.Length < 4 || bytes.Length > BabelResourceCodec.MaximumLength) return false;
        try
        {
            using var stream = new MemoryStream(bytes, writable: false);
            using var reader = new BinaryReader(stream, new UTF8Encoding(false, true));
            var count = reader.ReadInt32();
            if (count is < 1 or > 1024 || count > (bytes.Length - 4) / 5) return false;
            var parsed = new List<byte[]>();
            for (var index = 0; index < count; index++)
            {
                var name = reader.ReadString();
                if (name.Length is < 1 or > 4096) return false;
                var length = reader.ReadInt32();
                if (length < 1 || length > stream.Length - stream.Position) return false;
                var assembly = reader.ReadBytes(length);
                if (!PayloadStageValidator.TryValidateManaged(assembly, out _)) return false;
                parsed.Add(assembly);
            }
            if (stream.Position != stream.Length) return false;
            assemblies = parsed;
            return true;
        }
        catch (Exception exception) when (exception is IOException or ArgumentException or FormatException)
        {
            return false;
        }
    }
}

public sealed class BabelUnpackingCompletionPass : BabelUnpackingPass
{
    public override string Name => "babel-unpacking-completion";
    public override IReadOnlyCollection<string> Dependencies => ["babel-resource-completion", "babel-unpacking"];
}
