using System.Buffers.Binary;
using System.Text;

namespace ReactorUnpack.Core.Strings;

public static class StrictStringTable
{
    private static readonly UnicodeEncoding Utf16 =
        new(bigEndian: false, byteOrderMark: false, throwOnInvalidBytes: true);

    public static bool TryDecodeComplete(
        ReadOnlySpan<byte> bytes,
        out IReadOnlyList<DecodedStringRecord> records,
        int maximumRecords = 100_000)
    {
        var decoded = new List<DecodedStringRecord>();
        var offset = 0;
        try
        {
            while (offset < bytes.Length && decoded.Count < maximumRecords)
            {
                if (offset > bytes.Length - sizeof(int))
                    return Failure(out records);
                var byteLength = BinaryPrimitives.ReadInt32LittleEndian(bytes[offset..]);
                if (byteLength < 0 || (byteLength & 1) != 0 ||
                    byteLength > bytes.Length - offset - sizeof(int))
                    return Failure(out records);
                var value = Utf16.GetString(bytes.Slice(offset + sizeof(int), byteLength));
                if (value.Any(character => char.IsControl(character) &&
                        character is not '\r' and not '\n' and not '\t'))
                    return Failure(out records);
                decoded.Add(new DecodedStringRecord(offset, byteLength, value));
                offset = checked(offset + sizeof(int) + byteLength);
            }
        }
        catch (DecoderFallbackException)
        {
            return Failure(out records);
        }

        if (offset != bytes.Length || decoded.Count < 2 || decoded.Count >= maximumRecords)
            return Failure(out records);
        records = decoded;
        return true;
    }

    private static bool Failure(out IReadOnlyList<DecodedStringRecord> records)
    {
        records = [];
        return false;
    }
}
