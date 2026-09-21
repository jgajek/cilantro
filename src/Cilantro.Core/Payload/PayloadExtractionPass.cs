using System.Security.Cryptography;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Codec;
using Cilantro.Core.Payload;
using Cilantro.Core.Recovery;

namespace Cilantro.Core;

public sealed class PayloadExtractionPass : DeobfuscationPass
{
    public override string Name => "payload-extraction";
    public override IReadOnlyCollection<string> Dependencies =>
        ["resource-role-refinement", "resource-restoration"];
    public override bool GatesEmission => false;

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        // Nothing is recorded for a later pass here. What is proved is that no resource this module
        // embeds carries an assembly, and a load takes the bytes it is given from wherever they were
        // built; so this says nothing about what the module hands the runtime, and a reader treating
        // it as though it did would take a check it could have made for one there was no point making.
        if (TryProveNoManagedPayload(context, out var accounting))
            return (PassStatus.Success, 0, accounting);

        // Asking the module to unpack itself is the general answer and the one that survives a
        // change of crypter, so it is tried before anything that reasons about a particular codec.
        if (TryRecoverByInterpretation(context, out var interpreted, out var declined))
            return interpreted;

        // This one did watch every load the startup path reached, so its silence means something.
        Told(context, [], declined);

        context.TryGetFact<ReactorStructureFacts>("reactor.structure", out var facts);
        if (facts is not null &&
            StructuralStreamDiscovery.TryDiscoverProxyProfile(
                context.Module,
                facts,
                out var proxyProfile) &&
            proxyProfile is not null &&
            StructuralStreamDiscovery.TryDiscoverOuterPayload(
                context.Module,
                proxyProfile,
                out var discovered) &&
            discovered is not null)
        {
            // The discovery already read the image to accept it, so this reads it again only for
            // what it says about itself, and cannot be the first to find it unreadable.
            PayloadStageValidator.TryValidateManaged(discovered.ManagedAssembly, out var read);
            var sourceBytes = discovered.Resource.CreateReader().ToArray();
            var structuralInfo = new PayloadInfo(
                discovered.Resource.Name,
                Convert.ToHexStringLower(SHA256.HashData(sourceBytes)),
                sourceBytes.Length,
                Convert.ToHexStringLower(SHA256.HashData(discovered.DecodedStream)),
                discovered.ManagedAssembly.Length,
                Convert.ToHexStringLower(SHA256.HashData(discovered.ManagedAssembly)),
                discovered.AssemblyName,
                read?.ModuleName ?? discovered.AssemblyName,
                read?.EntryPointToken ?? 0,
                read?.Resources ?? [], Origin: PayloadOrigin.ResourceCodec);
            IReadOnlyList<ExtractedPayload> structuralPayloads =
                [new(structuralInfo, discovered.ManagedAssembly)];
            context.SetFact("payload.artifacts", structuralPayloads);
            context.AddEvidence(new Evidence(
                "extracted-payload",
                $"Structurally recovered managed assembly {structuralInfo.AssemblyName}.",
                discovered.Resource.Name,
                1.0));
            context.AddEvidence(new Evidence(
                "stream-constants",
                $"Derived keyed payload constants A=0x{discovered.A:X8}, D=0x{discovered.D:X8}.",
                discovered.Resource.Name,
                1.0));
            context.AddChange(new ChangeRecord(
                Name,
                "extract-managed-payload",
                discovered.Resource.Name,
                $"{structuralInfo.AssemblyName}, SHA-256 {structuralInfo.PayloadSha256}"));
            return (PassStatus.Success, 1,
            [
                $"Structurally extracted {structuralInfo.AssemblyName}.dll ({structuralInfo.PayloadLength} bytes).",
                $"SHA-256: {structuralInfo.PayloadSha256}"
            ]);
        }

        return (PassStatus.Unsupported, 0,
        [
            "No payload could be recovered by interpreting the module's own unpacker.",
            .. declined,
            "No structurally validated payload codec was found either."
        ]);
    }

    /// <summary>
    /// Recovers payloads by interpreting the unpacker the module carries.
    /// </summary>
    /// <remarks>
    /// See <see cref="PayloadChainRecovery"/> for why the anchor is the load rather than the codec.
    /// A decline says nothing about whether a payload was there, so the caller carries on to the
    /// narrower routes rather than concluding anything from it.
    /// </remarks>
    private bool TryRecoverByInterpretation(
        ArtifactContext context,
        out (PassStatus, int, IReadOnlyList<string>) outcome,
        out IReadOnlyList<string> declined)
    {
        outcome = default;
        var recovered = PayloadChainRecovery.Recover(context, out var why);
        declined = why;
        if (recovered.Count == 0)
            return false;

        var payloads = new List<ExtractedPayload>();
        var diagnostics = new List<string>
        {
            $"Interpreted the module's own unpacker and captured {recovered.Count} assembly load(s)."
        };
        foreach (var item in recovered)
        {
            var origin = $"{item.Root.DeclaringType?.Name}::{item.Root.Name}";

            // What the loader was watched handing to the runtime is only a payload if it is one.
            // A capture that will not read is reported as what it is rather than written out as an
            // assembly, and the others are extracted regardless of it.
            if (!PayloadStageValidator.TryValidateManaged(item.Image, out var read) || read is null)
            {
                diagnostics.Add(
                    $"{origin}: the {item.Image.Length} byte(s) handed to the runtime are not a " +
                    "managed image, so nothing was extracted from that load.");
                continue;
            }
            var info = new PayloadInfo(
                origin,
                context.OriginalSha256,
                context.OriginalBytes.Length,
                item.Sha256,
                item.Image.Length,
                item.Sha256,
                item.AssemblyName,
                read.ModuleName,
                read.EntryPointToken,
                read.Resources, Origin: PayloadOrigin.AssemblyLoad);
            payloads.Add(new ExtractedPayload(info, item.Image));
            context.AddEvidence(new Evidence(
                "extracted-payload",
                $"Recovered managed assembly {item.AssemblyName} ({item.Image.Length} bytes) " +
                "by interpreting the module's own loader.",
                origin,
                1.0));
            context.AddChange(new ChangeRecord(
                Name, "extract-managed-payload", origin,
                $"{item.AssemblyName}, SHA-256 {item.Sha256}"));
            diagnostics.Add(
                $"Extracted {item.AssemblyName} ({item.Image.Length} bytes), SHA-256 {item.Sha256}.");
        }

        var combined = context.TryGetFact<IReadOnlyList<ExtractedPayload>>(
                "payload.artifacts", out var existing) && existing is not null
            ? existing.Concat(payloads).ToArray()
            : payloads.ToArray();
        context.SetFact<IReadOnlyList<ExtractedPayload>>("payload.artifacts", combined);
        diagnostics.AddRange(why);
        Told(context, recovered.Select(item => item.Sha256), why);
        outcome = (PassStatus.Success, payloads.Count, diagnostics);
        return true;
    }

    /// <summary>Records what interpreting the module's own startup path came to.</summary>
    private static void Told(
        ArtifactContext context,
        IEnumerable<string> unpacked,
        IReadOnlyList<string> why) =>
        context.SetFact(
            PayloadChainRecovery.ChainFact,
            new PayloadChainRecovery.InterpretedChain(
                unpacked.ToHashSet(StringComparer.Ordinal), why));

    /// <summary>
    /// Decides whether the absence of a payload is a proven fact or an unsupported codec.
    /// </summary>
    /// <remarks>
    /// Reporting "no payload codec" for an assembly that simply never embedded one is a false
    /// negative, and because incomplete recovery withholds output it blocks otherwise complete
    /// artifacts. Not every Reactor build uses the embedded-assembly feature: protected libraries
    /// commonly ship only a method-patch stream, a string table, an integrity blob, and an
    /// encrypted resource bundle.
    ///
    /// The proof is completeness of attribution rather than absence of a signal. Every embedded
    /// resource must be attributed to a role established from recovered consumer IL, and none of
    /// those roles may be a managed payload. A single unattributed resource keeps the pass
    /// unsupported, because that blob is exactly where an unextracted assembly would hide.
    /// </remarks>
    private static bool TryProveNoManagedPayload(
        ArtifactContext context,
        out IReadOnlyList<string> diagnostics)
    {
        diagnostics = [];
        var resources = context.Module.Resources.OfType<EmbeddedResource>().ToArray();
        if (resources.Length == 0)
        {
            diagnostics = ["The module embeds no resource that could carry a managed payload."];
            return true;
        }
        if (!context.TryGetFact<IReadOnlyList<ResourceRoleFact>>("resource.roles", out var roles) ||
            roles is null)
        {
            return false;
        }

        var byName = roles.ToDictionary(role => role.Resource, StringComparer.Ordinal);
        var attributed = resources.All(resource =>
            byName.TryGetValue(resource.Name, out var role) && role.Role != ResourceRole.Unknown);
        if (!attributed || roles.Any(role => role.Role == ResourceRole.ManagedPayload))
            return false;

        diagnostics =
        [
            $"All {resources.Length} embedded resource(s) are attributed to non-payload roles.",
            "Roles: " + string.Join(
                ", ",
                roles.GroupBy(role => role.Role)
                    .OrderBy(group => group.Key.ToString(), StringComparer.Ordinal)
                    .Select(group => $"{group.Key}={group.Count()}")),
            "The module does not embed a managed assembly, so there is nothing to extract."
        ];
        return true;
    }

    private static byte[] ExtractByteArrayRecord(ReadOnlySpan<byte> resourceData, int expectedLength)
    {
        var matches = new List<byte[]>();
        for (var offset = 0; offset + 5 <= resourceData.Length; offset++)
        {
            if (resourceData[offset] != 0x20 ||
                System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(
                    resourceData[(offset + 1)..]) != expectedLength ||
                offset + 5 + expectedLength != resourceData.Length)
            {
                continue;
            }

            matches.Add(resourceData.Slice(offset + 5, expectedLength).ToArray());
        }

        return matches.Count == 1
            ? matches[0]
            : throw new InvalidDataException(
                $"Expected one terminal ByteArray record, found {matches.Count}.");
    }
}
