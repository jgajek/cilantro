using System.Buffers.Binary;
using System.Text;

namespace Cilantro.Core.Strings;

public sealed record DecodedStringRecord(int Offset, int ByteLength, string Value);

public static class LengthPrefixedStringTable
{
    public static bool TryDecode(
        ReadOnlySpan<byte> table,
        int offset,
        out DecodedStringRecord? record)
    {
        record = null;
        if (offset < 0 || offset > table.Length - 4)
            return false;
        var byteLength = BinaryPrimitives.ReadInt32LittleEndian(table[offset..]);
        if (byteLength < 0 ||
            (byteLength & 1) != 0 ||
            byteLength > table.Length - offset - 4)
        {
            return false;
        }

        var bytes = table.Slice(offset + 4, byteLength);
        var value = Encoding.Unicode.GetString(bytes);
        if (value.Any(character => char.IsControl(character) &&
                character is not '\r' and not '\n' and not '\t'))
        {
            return false;
        }

        record = new DecodedStringRecord(offset, byteLength, value);
        return true;
    }

    public static IReadOnlyList<DecodedStringRecord> DecodeSequential(
        ReadOnlySpan<byte> table,
        int maximumRecords = 100_000)
    {
        var records = new List<DecodedStringRecord>();
        var offset = 0;
        while (offset < table.Length && records.Count < maximumRecords)
        {
            if (!TryDecode(table, offset, out var record) || record is null)
                break;
            records.Add(record);
            offset = checked(offset + 4 + record.ByteLength);
        }

        return records;
    }
}
