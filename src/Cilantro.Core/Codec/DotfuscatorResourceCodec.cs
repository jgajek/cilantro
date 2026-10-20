using System.Buffers.Binary;
using System.Resources;
using System.Text;

namespace Cilantro.Core.Codec;

/// <summary>Restores primitive Dotfuscator resource entries without object deserialization.</summary>
internal static class DotfuscatorResourceCodec
{
    internal const int MaximumLength = 32 * 1024 * 1024;

    internal static bool TryRestore(byte[] container, long seed, IReadOnlySet<string> keys,
        out byte[] restored, out int count, out string why)
    {
        restored = [];
        count = 0;
        why = "";
        if (container.Length > MaximumLength) { why = "Resource container exceeds the 32 MiB bound."; return false; }
        try
        {
            using var input = new MemoryStream(container, false);
            using var reader = new ResourceReader(input);
            using var output = new MemoryStream();
            using var writer = new ResourceWriter(output);
            var entries = reader.GetEnumerator();
            while (entries.MoveNext())
            {
                if (++count > 4096) throw new InvalidDataException("Resource entry limit exceeded.");
                // Reading Value would permit user-defined deserialization.
                var name = (string)entries.Key;
                reader.GetResourceData(name, out var type, out var raw);
                if (type != "ResourceTypeCode.ByteArray" || raw.Length < 5 || raw.Length > MaximumLength ||
                    BinaryPrimitives.ReadInt32LittleEndian(raw) != raw.Length - 4)
                    throw new InvalidDataException($"{name}: expected a wrapped byte-array entry.");
                var encoded = raw.AsSpan(4);
                if (encoded[0] is not (0 or 1)) throw new InvalidDataException($"{name}: unsupported resource value marker {encoded[0]}.");
                byte[] plain;
                if (keys.Contains(name))
                {
                    if (encoded.Length % 2 != 1) throw new InvalidDataException($"{name}: invalid encrypted entry length.");
                    // The decoder XORs the interleaved stream, swaps adjacent
                    // bytes, then takes the first byte of each resulting pair.
                    plain = new byte[encoded.Length / 2];
                    for (var index = 0; index < plain.Length; index++)
                        plain[index] = (byte)(encoded[2 + 2 * index] ^ unchecked((byte)(seed + 1 + 2L * index)));
                }
                else plain = encoded[1..].ToArray();
                if (encoded[0] == 1) writer.AddResource(name, Encoding.UTF8.GetString(plain));
                else writer.AddResource(name, plain);
            }
            writer.Generate();
            if (output.Length > MaximumLength) throw new InvalidDataException("Decoded resource exceeds the 32 MiB bound.");
            restored = output.ToArray();
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or InvalidDataException or BadImageFormatException or NotSupportedException or InvalidOperationException or OverflowException)
        {
            count = 0;
            why = exception.Message;
            return false;
        }
    }
}
