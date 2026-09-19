using Cilantro.Core.Codec;

namespace Cilantro.Core;

public sealed record ProxyCodecProfile(
    string ResourceSha256,
    string DecodedSha256,
    uint A,
    uint D);

public static class ProxyResourceCodec
{
    private static readonly Dictionary<string, ProxyCodecProfile> Profiles =
        new Dictionary<string, ProxyCodecProfile>(StringComparer.OrdinalIgnoreCase)
        {
            ["ad0c3182b18b5d7ba8771d830f4d51b4ada7e26f8d05223f4379e6312aba65fa"] =
                new(
                    "ce449eb84252e5af5cf132907dfd3061d59fa8d259500e6a9025243ce46274d2",
                    "c9082fc2408d149d5e7fa1064c7a7f5d80fc88eb07e3fbc8c5db1edcd9aac343",
                    0x14F5581E,
                    0x2C784A62),
            ["c405398fc582e33bbbd37222b7360a6cfdc526146622141503de1ccf9de6174a"] =
                new(
                    "9ef76059d278b7c90b228d145b722c77913751492ce79da82794427757e75f3b",
                    "13f268283b8084526fa0efc47237c7e66986d825e2a07349ca508ede2e6f7a18",
                    0x3DBE5B8B,
                    0x468A5E02)
        };

    public static bool TryGetProfile(string inputSha256, out ProxyCodecProfile profile) =>
        Profiles.TryGetValue(inputSha256, out profile!);

    public static byte[] Decode(ReadOnlySpan<byte> ciphertext, ProxyCodecProfile profile)
        => ReactorStreamMixer.DecodeProxy(ciphertext, profile.A, profile.D);

    public static IReadOnlyList<ProxyBinding> Parse(ReadOnlySpan<byte> decoded)
    {
        if (decoded.Length % 8 != 0)
        {
            throw new InvalidDataException("Proxy mapping length is not a multiple of eight.");
        }

        var bindings = new List<ProxyBinding>(decoded.Length / 8);
        for (var offset = 0; offset < decoded.Length; offset += 8)
        {
            var fieldToken = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(decoded[offset..]);
            var encoded = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(decoded[(offset + 4)..]);
            bindings.Add(new ProxyBinding(
                fieldToken,
                encoded & 0x3FFFFFFFu,
                (encoded & 0x40000000u) != 0));
        }

        return bindings;
    }
}
