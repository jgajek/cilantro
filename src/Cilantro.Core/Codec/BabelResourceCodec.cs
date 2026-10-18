using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace Cilantro.Core.Codec;

/// <summary>Bounded reader for the DES resource envelopes used by Babel 3.x–4.x.</summary>
public static class BabelResourceCodec
{
    public const int MaximumLength = 64 * 1024 * 1024;

    /// <summary>Length-prefixed masked headers carried by newer stream-decoder builds.</summary>
    public static bool IsStreamEnvelopeCandidate(ReadOnlySpan<byte> data)
    {
        if (data.Length < 6 || data.Length > MaximumLength) return false;
        var header = data[0] | data[1] << 8;
        return header is > 0 and <= 4096 && header + 3 < data.Length &&
            data[header + 2] is > 0 and <= 32 && header + 3 + data[header + 2] < data.Length;
    }

    public static bool IsCandidate(ReadOnlySpan<byte> data) =>
        data.Length >= 19 && data.Length <= MaximumLength &&
        (data[0] == 8 && data[9] <= 1 && data[10] == 8 ||
         data[0] <= 1 && (data[1] | data[2] << 8) is >= 11 and <= 4096);

    public static bool TryDecode(byte[] data, byte[] publicKey, out byte[] decoded, out string diagnostic)
    {
        decoded = [];
        diagnostic = "Not a supported Babel resource envelope.";
        if (!IsCandidate(data)) return false;
        try
        {
            using var input = new MemoryStream(data, writable: false);
            using var reader = new BinaryReader(input, Encoding.UTF8);
            byte[] key;
            byte[] iv;
            var compressed = true;
            if (data[0] == 8 && data[9] <= 1 && data[10] == 8)
            {
                iv = Bytes(reader, 8, skipLength: true);
                key = Key(reader, publicKey, 0);
                _ = Bytes(reader, reader.ReadInt32()); // legacy hash, not an authentication guarantee
            }
            else
            {
                var masked = Boolean(reader);
                var header = Bytes(reader, reader.ReadUInt16());
                if (masked)
                {
                    var mask = Bytes(reader, 8);
                    for (var index = 0; index < header.Length; index++) header[index] ^= mask[index % mask.Length];
                }
                using var headerStream = new MemoryStream(header, writable: false);
                using var fields = new BinaryReader(headerStream, new UTF8Encoding(false, true));
                if (header.Length == 0) throw new InvalidDataException("Empty Babel header.");
                if (header[0] != 8) _ = fields.ReadString(); // license string
                if (headerStream.Position >= headerStream.Length) throw new InvalidDataException("Missing envelope fields.");
                if (header[headerStream.Position] != 8) compressed = Boolean(fields);
                iv = Bytes(fields, 8, skipLength: true);
                key = Key(fields, publicKey, 12);
                if (headerStream.Position != headerStream.Length)
                    throw new InvalidDataException("Unsupported Babel header extension (retail 5.x requires its own inflater).");
            }
            var encrypted = Bytes(reader, checked((int)(input.Length - input.Position)));
            if (encrypted.Length == 0 || encrypted.Length % 8 != 0) throw new InvalidDataException("Invalid DES ciphertext length.");
            // DES is the on-disk protector format, never a choice for newly protected data.
#pragma warning disable CA5351
            using var cipher = DES.Create();
#pragma warning restore CA5351
            cipher.Key = key;
            cipher.IV = iv;
            var plain = cipher.DecryptCbc(encrypted, iv, PaddingMode.PKCS7);
            if (compressed)
            {
                using var packed = new MemoryStream(plain, writable: false);
                using var inflater = new ZLibStream(packed, CompressionMode.Decompress);
                using var output = new MemoryStream();
                var buffer = new byte[8192];
                int read;
                while ((read = inflater.Read(buffer)) != 0)
                {
                    if (output.Length > MaximumLength - read) throw new InvalidDataException("Babel resource exceeds the output limit.");
                    output.Write(buffer, 0, read);
                }
                plain = output.ToArray();
            }
            decoded = plain;
            diagnostic = $"Decoded Babel DES resource ({plain.Length} bytes).";
            return true;
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or CryptographicException or ArgumentException or OverflowException or FormatException)
        {
            diagnostic = exception.Message;
            return false;
        }
    }

    private static bool Boolean(BinaryReader reader) => reader.ReadByte() switch
    {
        0 => false,
        1 => true,
        _ => throw new InvalidDataException("Invalid Babel boolean field.")
    };

    private static byte[] Key(BinaryReader reader, byte[] publicKey, int offset)
    {
        var embedded = Boolean(reader);
        if (embedded) return Bytes(reader, 8, skipLength: true);
        if (reader.ReadByte() != 8 || publicKey.Length < offset + 8)
            throw new InvalidDataException("Babel public-key-derived DES key is unavailable.");
        var key = publicKey.AsSpan(offset, 8).ToArray();
        if (offset != 0) key[5] |= 0x80;
        return key;
    }

    private static byte[] Bytes(BinaryReader reader, int count, bool skipLength = false)
    {
        if (skipLength && reader.ReadByte() != count) throw new InvalidDataException("Unsupported Babel key or IV length.");
        if (count < 0 || count > MaximumLength || count > reader.BaseStream.Length - reader.BaseStream.Position)
            throw new InvalidDataException("Truncated or oversized Babel field.");
        return reader.ReadBytes(count);
    }
}
