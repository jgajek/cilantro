using System.Buffers.Binary;
using System.Text;

namespace Cilantro.Core.Strings;

public static class StrictStringTable
{
    private static readonly UnicodeEncoding Utf16 =
        new(bigEndian: false, byteOrderMark: false, throwOnInvalidBytes: true);

    /// <summary>
    /// Reads a table of length-prefixed UTF-16 records, where the bytes are one.
    /// </summary>
    /// <remarks>
    /// What makes this strict is that the records have to account for every byte handed in: each
    /// length has to be even, non-negative, and within what is left, each record has to be UTF-16
    /// the encoder will accept, and the last one has to end exactly where the array does. An array
    /// of anything else fails at its first length, since almost no four bytes read as a length that
    /// fits.
    ///
    /// What the records say is not part of the test. A protected string holds whatever the program
    /// wrote in it — a key, a separator, a byte the author never meant a reader to see — so a table
    /// with a control character in it is a table, and a reading that rejected one on those grounds
    /// rejected the whole file over one string. Whether the records are this module's strings is
    /// settled by the call sites afterwards, which is a question about the module rather than about
    /// how the characters look.
    /// </remarks>
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
