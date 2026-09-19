using System.IO.Compression;
using System.Security.Cryptography;

namespace Cilantro.Core;

public static class ResourceTransforms
{
    public static byte[] AesCbcDecrypt(
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> iv,
        PaddingMode padding = PaddingMode.PKCS7)
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = padding;
        aes.Key = key.ToArray();
        aes.IV = iv.ToArray();
        return aes.DecryptCbc(ciphertext, iv, padding);
    }

    public static byte[] Xor(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
    {
        if (key.IsEmpty) throw new ArgumentException("The XOR key cannot be empty.", nameof(key));
        var output = new byte[data.Length];
        for (var index = 0; index < data.Length; index++)
        {
            output[index] = (byte)(data[index] ^ key[index % key.Length]);
        }

        return output;
    }

    public static byte[] Decompress(ReadOnlySpan<byte> data, string codec, int maximumLength = 256 * 1024 * 1024)
    {
        using var input = new MemoryStream(data.ToArray(), false);
        using Stream decoder = codec.ToLowerInvariant() switch
        {
            "gzip" => new GZipStream(input, CompressionMode.Decompress, false),
            "deflate" => new DeflateStream(input, CompressionMode.Decompress, false),
            "brotli" => new BrotliStream(input, CompressionMode.Decompress, false),
            _ => throw new NotSupportedException($"Unsupported compression codec: {codec}")
        };
        using var output = new MemoryStream();
        var buffer = new byte[81920];
        while (true)
        {
            var read = decoder.Read(buffer, 0, buffer.Length);
            if (read == 0) break;
            if (output.Length + read > maximumLength)
            {
                throw new InvalidDataException("Decompressed resource exceeds the configured limit.");
            }

            output.Write(buffer, 0, read);
        }

        return output.ToArray();
    }
}
