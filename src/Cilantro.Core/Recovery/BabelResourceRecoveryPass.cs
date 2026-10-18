using System.Security.Cryptography;
using Cilantro.Core.Analysis;
using Cilantro.Core.Codec;
using Cilantro.Core.Interpretation;
using dnlib.DotNet;

namespace Cilantro.Core.Recovery;

public sealed record BabelDecodedResource(DecodedResourceInfo Info, byte[] Bytes);

/// <summary>Reads Babel resources through the actual stream decoder, including newer cipher/inflater builds.</summary>
public class BabelResourceRecoveryPass : DeobfuscationPass
{
    public const string ResourcesFact = "babel.decodedResources";
    public override string Name => "babel-resource-recovery";
    public override IReadOnlyCollection<string> Dependencies => ["string-lookup-recovery", "babel-detection"];
    public override bool GatesEmission => false;

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        // Restored method bodies and types can expose Babel underneath a Reactor wrapper.
        var facts = BabelStructureDetector.Analyze(context.Module);
        context.TryGetFact<BabelStructureFacts>("babel.structure", out var earlier);
        if (facts.IsBabel)
        {
            context.SetFact("babel.structure", facts);
            if (earlier?.IsBabel != true)
                context.AddEvidence(new("protector", "Babel generated runtime exposed after recovery of the outer layer.", Confidence: facts.Confidence));
            foreach (var capability in facts.CapabilityNames.Except(earlier?.CapabilityNames ?? []))
                context.AddEvidence(new("capability", capability, Confidence: facts.Confidence));
        }
        if (!facts.IsBabel && earlier?.IsBabel != true)
            return (PassStatus.Success, 0, ["No Babel runtime requires resource recovery."]);

        var decoders = BabelStructureDetector.StreamDecoders(context.Module).Take(8).ToArray();
        if (decoders.Length == 0) return (PassStatus.Success, 0, ["No exposed Babel stream decoder remains; legacy envelope unpacking is still available."]);
        context.TryGetFact<IReadOnlyList<BabelDecodedResource>>(ResourcesFact, out var previous);
        var recovered = (previous ?? []).ToList();
        var initialCount = recovered.Count;
        var notes = new List<string>();
        var incomplete = false;
        var work = new StaticWorkBudget(64_000_000);
        foreach (var resource in context.Module.Resources.OfType<EmbeddedResource>().Where(resource =>
                     resource.Length <= BabelResourceCodec.MaximumLength).Take(64))
        {
            var encoded = resource.CreateReader().ToArray();
            var sourceHash = Hash(encoded);
            if (recovered.Any(item => item.Info.SourceResource == resource.Name && item.Info.SourceSha256 == sourceHash)) continue;
            if (!BabelResourceCodec.IsStreamEnvelopeCandidate(encoded) && !BabelResourceCodec.IsCandidate(encoded)) continue;
            var accepted = false;
            foreach (var decoder in decoders)
            {
                if (!Read(context, resource, decoder, work, out var first, out var why) ||
                    !Read(context, resource, decoder, work, out var second, out why) ||
                    first is null || second is null || !first.AsSpan().SequenceEqual(second) || first.AsSpan().SequenceEqual(encoded))
                {
                    notes.Add($"{resource.Name}, {decoder.MDToken}: {why}");
                    continue;
                }
                var info = new DecodedResourceInfo(resource.Name, sourceHash, first.Length, Hash(first),
                    $"{decoder.MDToken} {decoder.FullName}");
                recovered.Add(new(info, first));
                accepted = true;
                context.AddEvidence(new("babel-resource-decoded",
                    $"Two independent bounded interpretations agreed on {first.Length} decoded bytes; SHA-256 {info.DecodedSha256}.", resource.Name));
                context.AddChange(new(Name, "decode-babel-resource", resource.Name, $"{first.Length} bytes, SHA-256 {info.DecodedSha256}"));
                break;
            }
            incomplete |= !accepted;
        }
        context.SetFact<IReadOnlyList<BabelDecodedResource>>(ResourcesFact, recovered);
        return (incomplete ? PassStatus.Partial : PassStatus.Success, recovered.Count - initialCount,
            [$"Recovered {recovered.Count} Babel stream(s) using the module's own decoder; encrypted inputs were preserved.", .. notes.Take(8)]);
    }

    private static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static bool Read(ArtifactContext context, EmbeddedResource resource, MethodDef decoder, StaticWorkBudget work,
        out byte[]? bytes, out string why)
    {
        bytes = null;
        if (!BootstrapMachine.TrySeed(context, 16_000_000, out var machine, out why) || machine is null) return false;
        machine.State.RegisterRunEnvironment(new RunEnvironment(new HostEnvironment(HostProfile.Empty)));
        if (!machine.State.TryOpenResource(resource.Name, out var stream)) { why = "resource stream unavailable"; return false; }
        var answer = machine.Execute(decoder, [stream], work);
        if (!answer.Succeeded) { why = answer.Diagnostic ?? answer.Status.ToString(); return false; }
        var effects = machine.State.LoaderEvidence.EffectsOf(decoder.MDToken.Raw);
        if (effects.WroteMappedImage || effects.WroteScratchRegion || effects.Registrations.Count != 0 ||
            !machine.State.Heap.TryGetModelValue<StaticValue>(answer.Value, "Buffer", out var buffer) ||
            machine.State.Heap.GetBytesSnapshot(buffer) is not { } data)
        { why = "decoder did not return an isolated concrete stream"; return false; }
        var consumed = machine.State.Heap.TryGetModelValue<long>(stream, "Position", out var position) ? position : -1;
        if (consumed != resource.Length) { why = "decoder did not consume the complete encoded resource"; return false; }
        var length = machine.State.Heap.TryGetModelValue<int>(answer.Value, "Length", out var integerLength) ? integerLength :
            machine.State.Heap.TryGetModelValue<long>(answer.Value, "Length", out var longLength) ? longLength : -1;
        var origin = machine.State.Heap.TryGetModelValue<int>(answer.Value, "Origin", out var start) ? start : 0;
        if (origin < 0 || length < 0 || length > BabelResourceCodec.MaximumLength || origin > data.Length - length)
        { why = "invalid returned stream range"; return false; }
        bytes = data.AsSpan(origin, (int)length).ToArray();
        why = "independent decoder trials disagreed or returned unchanged input";
        return true;
    }
}

/// <summary>Revisits Babel codecs whose bodies were hidden inside the outer protector's VM.</summary>
public sealed class BabelResourceCompletionPass : BabelResourceRecoveryPass
{
    public override string Name => "babel-resource-completion";
    public override IReadOnlyCollection<string> Dependencies => ["emitted-method-reconstruction", "babel-resource-recovery"];
}
