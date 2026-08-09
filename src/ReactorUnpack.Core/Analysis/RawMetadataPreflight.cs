using System.Buffers.Binary;
using System.Text;

namespace ReactorUnpack.Core.Analysis;

public sealed record MetadataStreamInfo(string Name, int Offset, int Size, bool InBounds);

public sealed record RawMetadataFacts(
    int MetadataOffset,
    uint ModuleRows,
    uint AssemblyRows,
    ulong ValidMask,
    ulong SortedMask,
    IReadOnlyList<MetadataStreamInfo> Streams,
    IReadOnlyList<string> Anomalies);

public static class RawMetadataPreflight
{
    private const uint MetadataSignature = 0x424A5342;

    public static RawMetadataFacts Analyze(ReadOnlySpan<byte> bytes)
    {
        var metadataOffset = LocateMetadata(bytes);
        if (metadataOffset < 0)
            throw new BadImageFormatException("CLR metadata signature was not found.");
        var cursor = metadataOffset + 12;
        EnsureAvailable(bytes, cursor, 4);
        var versionLength = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(bytes[cursor..]));
        cursor += 4;
        EnsureAvailable(bytes, cursor, versionLength + 4);
        cursor += Align4(versionLength);
        cursor += 2;
        var streamCount = BinaryPrimitives.ReadUInt16LittleEndian(bytes[cursor..]);
        cursor += 2;
        var streams = new List<MetadataStreamInfo>(streamCount);
        for (var index = 0; index < streamCount; index++)
        {
            EnsureAvailable(bytes, cursor, 8);
            var offset = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(bytes[cursor..]));
            var size = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(bytes[(cursor + 4)..]));
            cursor += 8;
            var nameStart = cursor;
            while (cursor < bytes.Length && bytes[cursor] != 0 && cursor - nameStart < 32)
                cursor++;
            if (cursor >= bytes.Length || cursor - nameStart >= 32)
                throw new BadImageFormatException("Invalid metadata stream name.");
            var name = Encoding.ASCII.GetString(bytes[nameStart..cursor]);
            cursor = Align4(cursor + 1 - metadataOffset) + metadataOffset;
            var absolute = metadataOffset + offset;
            var inBounds = absolute >= metadataOffset &&
                size >= 0 &&
                absolute <= bytes.Length - size;
            streams.Add(new MetadataStreamInfo(name, offset, size, inBounds));
        }

        var tables = streams.FirstOrDefault(stream => stream.Name is "#~" or "#-");
        uint moduleRows = 0;
        uint assemblyRows = 0;
        ulong valid = 0;
        ulong sorted = 0;
        var anomalies = streams
            .Where(stream => !stream.InBounds)
            .Select(stream => $"Stream {stream.Name} is outside the file.")
            .ToList();
        if (tables is not null && tables.InBounds)
        {
            var tableCursor = metadataOffset + tables.Offset;
            EnsureAvailable(bytes, tableCursor, 24);
            valid = BinaryPrimitives.ReadUInt64LittleEndian(bytes[(tableCursor + 8)..]);
            sorted = BinaryPrimitives.ReadUInt64LittleEndian(bytes[(tableCursor + 16)..]);
            tableCursor += 24;
            for (var table = 0; table < 64; table++)
            {
                if ((valid & (1UL << table)) == 0)
                    continue;
                EnsureAvailable(bytes, tableCursor, 4);
                var rows = BinaryPrimitives.ReadUInt32LittleEndian(bytes[tableCursor..]);
                tableCursor += 4;
                if (table == 0) moduleRows = rows;
                if (table == 32) assemblyRows = rows;
            }
        }

        if (moduleRows > 1) anomalies.Add($"Module table contains {moduleRows} rows.");
        if (assemblyRows > 1) anomalies.Add($"Assembly table contains {assemblyRows} rows.");
        if (valid != 0 && sorted == 0) anomalies.Add("Metadata sorted mask is zero.");
        return new RawMetadataFacts(
            metadataOffset,
            moduleRows,
            assemblyRows,
            valid,
            sorted,
            streams,
            anomalies);
    }

    private static int LocateMetadata(ReadOnlySpan<byte> bytes)
    {
        Span<byte> signature = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(signature, MetadataSignature);
        return bytes.IndexOf(signature);
    }

    private static int Align4(int value) => checked((value + 3) & ~3);

    private static void EnsureAvailable(ReadOnlySpan<byte> bytes, int offset, int count)
    {
        if (offset < 0 || count < 0 || offset > bytes.Length - count)
            throw new BadImageFormatException("Metadata structure extends beyond the file.");
    }
}

public sealed class MetadataPreflightPass : DeobfuscationPass
{
    public override string Name => "metadata-preflight";

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var facts = RawMetadataPreflight.Analyze(context.OriginalBytes);
        context.SetFact("metadata.raw", facts);
        foreach (var anomaly in facts.Anomalies)
            context.AddEvidence(new Evidence("metadata-anomaly", anomaly, Confidence: 1.0));
        return (PassStatus.Success, 0,
        [
            $"Raw metadata: {facts.ModuleRows} Module row(s), {facts.AssemblyRows} Assembly row(s).",
            $"Streams: {string.Join(", ", facts.Streams.Select(stream => stream.Name))}.",
            $"Anomalies: {facts.Anomalies.Count}."
        ]);
    }
}
