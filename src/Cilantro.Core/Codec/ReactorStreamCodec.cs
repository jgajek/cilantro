using System.Buffers.Binary;
using System.Numerics;
using dnlib.DotNet;
using Cilantro.Core.Analysis;
using Cilantro.Core.Payload;

namespace Cilantro.Core.Codec;

public static class ReactorStreamMixer
{
    public static uint Mix(uint state, uint a, uint d)
    {
        var old = state;
        var r = BitOperations.RotateRight(a, 5) ^ old;
        r = ((r & 0xFF00FF00u) >> 8) | ((r & 0x00FF00FFu) << 8);
        var v = unchecked(0u - r);
        var q = old == 0 ? uint.MaxValue : old;
        q = unchecked(r - (r / q + q));
        v = unchecked(10476u * (v & 0xFFFFu) - (v >> 16));
        r = unchecked(22014u * r + q);
        q ^= q << 9;
        q = unchecked(q + v);
        q ^= q << 1;
        q = unchecked(q + q);
        q ^= q >> 5;
        q = unchecked(q + d);
        q = unchecked((((v << 11) + r) ^ v) + q);
        return unchecked(old + q);
    }

    public static byte[] DecodeProxy(ReadOnlySpan<byte> ciphertext, uint a, uint d) =>
        Decode(ciphertext, a, d, []);

    public static byte[] DecodeKeyed(
        ReadOnlySpan<byte> ciphertext,
        uint a,
        uint d,
        ReadOnlySpan<byte> key)
    {
        if (key.Length != 32)
            throw new ArgumentException("A keyed Reactor stream requires 32 key bytes.", nameof(key));
        return Decode(ciphertext, a, d, key);
    }

    private static byte[] Decode(
        ReadOnlySpan<byte> ciphertext,
        uint a,
        uint d,
        ReadOnlySpan<byte> key)
    {
        var output = new byte[ciphertext.Length];
        Span<byte> wordBytes = stackalloc byte[4];
        uint state = 0;
        for (var offset = 0; offset < ciphertext.Length; offset += 4)
        {
            if (!key.IsEmpty)
            {
                state = unchecked(state + BinaryPrimitives.ReadUInt32LittleEndian(
                    key.Slice(offset & 31, 4)));
            }

            state = Mix(state, a, d);
            var count = Math.Min(4, ciphertext.Length - offset);
            wordBytes.Clear();
            ciphertext.Slice(offset, count).CopyTo(wordBytes);
            var cipher = BinaryPrimitives.ReadUInt32LittleEndian(wordBytes);
            BinaryPrimitives.WriteUInt32LittleEndian(wordBytes, cipher ^ state);
            wordBytes[..count].CopyTo(output.AsSpan(offset, count));
        }

        return output;
    }
}

public sealed record DiscoveredProxyProfile(
    uint A,
    uint D,
    EmbeddedResource Resource,
    IReadOnlyList<ProxyBinding> Bindings,
    string EvidenceMethod);

public sealed record DiscoveredPayloadStage(
    EmbeddedResource Resource,
    byte[] DecodedStream,
    byte[] ManagedAssembly,
    uint A,
    uint D,
    byte[] Key,
    string AssemblyName);

public static class StructuralStreamDiscovery
{
    public static bool TryDiscoverProxyProfile(
        ModuleDefMD module,
        ReactorStructureFacts facts,
        out DiscoveredProxyProfile? profile)
    {
        profile = null;
        if (facts.DelegateProxyCount == 0)
            return false;

        var proxyFields = module.GetTypes()
            .Where(ReactorStructureDetector.IsDelegateProxy)
            .SelectMany(type => type.Fields)
            .Where(field => field.IsStatic)
            .ToDictionary(field => field.MDToken.Raw);
        var resources = module.Resources
            .OfType<EmbeddedResource>()
            .Where(resource => resource.CreateReader().Length == (uint)(proxyFields.Count * 8))
            .ToArray();
        if (resources.Length == 0)
            return false;

        var resolverCandidates = module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody)
            .Where(method => method.Body.Instructions.Any(instruction =>
                instruction.Operand is IMethod called &&
                called.DeclaringType?.FullName == "System.Reflection.Module" &&
                called.Name.String.StartsWith("Resolve", StringComparison.Ordinal)))
            .Where(method =>
            {
                var constants = method.Body.Instructions
                    .Where(instruction => instruction.IsLdcI4())
                    .Select(instruction => instruction.GetLdcI4Value())
                    .ToHashSet();
                return constants.Contains(10476) && constants.Contains(22014);
            })
            .ToArray();

        foreach (var method in resolverCandidates)
        {
            var constants = method.Body.Instructions
                .Where(instruction => instruction.IsLdcI4())
                .Select(instruction => unchecked((uint)instruction.GetLdcI4Value()))
                .Where(value => value > 0xFFFFu && value != uint.MaxValue)
                .Distinct()
                .ToArray();
            foreach (var resource in resources)
            {
                var encoded = resource.CreateReader().ToArray();
                foreach (var a in constants)
                {
                    foreach (var d in constants)
                    {
                        if (a == d)
                            continue;
                        var decoded = ReactorStreamMixer.DecodeProxy(encoded, a, d);
                        if (!TryParseAndValidateBindings(module, decoded, proxyFields, out var bindings))
                            continue;
                        profile = new DiscoveredProxyProfile(a, d, resource, bindings, method.FullName);
                        return true;
                    }
                }
            }
        }

        return false;
    }

    public static bool TryDiscoverOuterPayload(
        ModuleDefMD module,
        DiscoveredProxyProfile proxyProfile,
        out DiscoveredPayloadStage? payload)
    {
        payload = null;
        var baseKeys = module.GetTypes()
            .SelectMany(type => type.Fields)
            .Where(field => field.HasFieldRVA && field.InitialValue is { Length: 32 })
            .Select(field => field.InitialValue)
            .Concat(ConstantArrayDiscovery.FindThirtyTwoByteArrays(module))
            .Distinct(ByteArrayComparer.Instance)
            .ToArray();
        var keys = ExpandCandidateKeys(baseKeys);
        var resources = module.Resources
            .OfType<EmbeddedResource>()
            .Where(resource =>
                !ReferenceEquals(resource, proxyProfile.Resource) &&
                resource.CreateReader().Length >= 512)
            .ToArray();

        foreach (var resource in resources)
        {
            var encoded = resource.CreateReader().ToArray();
            foreach (var key in keys)
            {
                var decoded = ReactorStreamMixer.DecodeKeyed(
                    encoded,
                    proxyProfile.A,
                    proxyProfile.D,
                    key);
                byte[] inflated;
                try
                {
                    inflated = ResourceTransforms.Decompress(
                        decoded,
                        "deflate",
                        maximumLength: 256 * 1024 * 1024);
                }
                catch (InvalidDataException)
                {
                    continue;
                }

                // A valid DEFLATE stream is not sufficient; require managed metadata. Nearly every
                // key produces neither, and the reader has as many ways of saying so as there are
                // ways for bytes to be wrong.
                if (!PayloadStageValidator.TryValidateManaged(inflated, out var validated) ||
                    validated is null)
                {
                    continue;
                }
                payload = new DiscoveredPayloadStage(
                    resource,
                    decoded,
                    inflated,
                    proxyProfile.A,
                    proxyProfile.D,
                    key,
                    validated.AssemblyName);
                return true;
            }
        }

        return false;
    }

    private static byte[][] ExpandCandidateKeys(byte[][] baseKeys)
    {
        var candidates = new List<byte[]>(baseKeys);
        for (var left = 0; left < baseKeys.Length; left++)
        {
            for (var right = left + 1; right < baseKeys.Length; right++)
            {
                var xor = new byte[32];
                for (var index = 0; index < xor.Length; index++)
                    xor[index] = (byte)(baseKeys[left][index] ^ baseKeys[right][index]);
                candidates.Add(xor);
                if (candidates.Count >= 4096)
                    return candidates.Distinct(ByteArrayComparer.Instance).ToArray();
            }
        }

        return candidates.Distinct(ByteArrayComparer.Instance).ToArray();
    }

    private static bool TryParseAndValidateBindings(
        ModuleDefMD module,
        ReadOnlySpan<byte> decoded,
        Dictionary<uint, FieldDef> proxyFields,
        out IReadOnlyList<ProxyBinding> bindings)
    {
        bindings = [];
        if (decoded.Length == 0 || decoded.Length % 8 != 0)
            return false;

        var parsed = new List<ProxyBinding>(decoded.Length / 8);
        var seen = new HashSet<uint>();
        for (var offset = 0; offset < decoded.Length; offset += 8)
        {
            var fieldToken = BinaryPrimitives.ReadUInt32LittleEndian(decoded[offset..]);
            var encodedTarget = BinaryPrimitives.ReadUInt32LittleEndian(decoded[(offset + 4)..]);
            var targetToken = encodedTarget & 0x3FFFFFFFu;
            if (!proxyFields.ContainsKey(fieldToken) ||
                !seen.Add(fieldToken) ||
                module.ResolveToken(targetToken) is not IMethod)
            {
                return false;
            }

            parsed.Add(new ProxyBinding(
                fieldToken,
                targetToken,
                (encodedTarget & 0x40000000u) != 0));
        }

        if (seen.Count != proxyFields.Count)
            return false;
        bindings = parsed;
        return true;
    }

    private sealed class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        public static ByteArrayComparer Instance { get; } = new();

        public bool Equals(byte[]? left, byte[]? right) =>
            left is not null && right is not null && left.AsSpan().SequenceEqual(right);

        public int GetHashCode(byte[] value)
        {
            var hash = new HashCode();
            foreach (var item in value)
                hash.Add(item);
            return hash.ToHashCode();
        }
    }
}
