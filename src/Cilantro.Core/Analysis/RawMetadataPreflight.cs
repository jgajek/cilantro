using System.Buffers.Binary;
using System.Text;

namespace Cilantro.Core.Analysis;

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
    private const int MaximumStreams = 32;

    public static RawMetadataFacts Analyze(ReadOnlySpan<byte> bytes) => Analyze(bytes, null);

    /// <summary>
    /// Reads the raw metadata root of a managed image, preferring the location its CLI header
    /// declares over any search of the file.
    /// </summary>
    /// <param name="bytes">The file bytes.</param>
    /// <param name="image">
    /// A parsed view of the same bytes when the caller already has one, which spares this a second
    /// parse and mapping of the image.
    /// </param>
    public static RawMetadataFacts Analyze(ReadOnlySpan<byte> bytes, PeImageView? image)
    {
        var (metadataOffset, diagnostic) = Locate(bytes, image);
        if (metadataOffset < 0)
            throw new BadImageFormatException("CLR metadata signature was not found.");
        var facts = AnalyzeAt(bytes, metadataOffset);
        return diagnostic is null
            ? facts
            : facts with { Anomalies = [.. facts.Anomalies, diagnostic] };
    }

    private static RawMetadataFacts AnalyzeAt(ReadOnlySpan<byte> bytes, int metadataOffset)
    {
        var cursor = metadataOffset + 12;
        EnsureAvailable(bytes, cursor, 4);
        var versionLength = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(bytes[cursor..]));
        cursor += 4;
        EnsureAvailable(bytes, cursor, versionLength + 4);
        cursor += Align4(versionLength);
        cursor += 2;
        // Aligning the version string can carry the cursor up to three bytes past what the check
        // above covered, which matters when a candidate root sits near the end of the file.
        EnsureAvailable(bytes, cursor, 2);
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

    /// <summary>
    /// Finds the metadata root, and says so when the file made that harder than it should be.
    /// </summary>
    /// <remarks>
    /// The CLI header is asked first because it is what the runtime reads, and because the
    /// <c>BSJB</c> signature is not unique to the metadata root: a protector that verifies its own
    /// header carries the same four bytes as an <c>ldc.i4</c> operand in every method that performs
    /// the check, and those bodies routinely sit at lower file offsets than the metadata. Searching
    /// is kept only for images whose header cannot be believed, and a candidate then has to parse
    /// as a metadata root before it is accepted.
    /// </remarks>
    private static (int Offset, string? Diagnostic) Locate(
        ReadOnlySpan<byte> bytes,
        PeImageView? image)
    {
        var view = image;
        if (view is null && PeImageView.TryParse(bytes, out var parsed))
            view = parsed;

        var declared = -1;
        if (view is not null && view.TryGetCliMetadataFileRange(out var headerOffset, out _))
        {
            declared = headerOffset;
            if (HasSignatureAt(bytes, declared))
                return (declared, null);
        }

        // Aligned candidates first: a real metadata root is 4-byte aligned, and preferring those
        // keeps a misaligned operand from being chosen over the root itself.
        var found = Scan(bytes, requireAlignment: true);
        if (found < 0)
            found = Scan(bytes, requireAlignment: false);
        if (found < 0)
            return (-1, null);

        var diagnostic = declared switch
        {
            < 0 => "No CLI header named a metadata root, which was found by searching the file " +
                $"at 0x{found:x}.",
            _ => $"The CLI header points at 0x{declared:x}, where no metadata root begins; " +
                $"one was found by searching the file at 0x{found:x}."
        };
        return (found, diagnostic);
    }

    private static int Scan(ReadOnlySpan<byte> bytes, bool requireAlignment)
    {
        Span<byte> signature = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(signature, MetadataSignature);
        var start = 0;
        while (start < bytes.Length)
        {
            var hit = bytes[start..].IndexOf(signature);
            if (hit < 0)
                return -1;
            var candidate = start + hit;
            if ((!requireAlignment || candidate % 4 == 0) && ParsesAsMetadataRoot(bytes, candidate))
                return candidate;
            start = candidate + 1;
        }

        return -1;
    }

    private static bool HasSignatureAt(ReadOnlySpan<byte> bytes, int offset) =>
        offset >= 0 &&
        offset <= bytes.Length - 4 &&
        BinaryPrimitives.ReadUInt32LittleEndian(bytes[offset..]) == MetadataSignature;

    private static bool ParsesAsMetadataRoot(ReadOnlySpan<byte> bytes, int offset)
    {
        try
        {
            var facts = AnalyzeAt(bytes, offset);
            return facts.Streams.Count is not 0 and <= MaximumStreams &&
                facts.Streams.Any(stream => stream.Name is "#~" or "#-");
        }
        catch (BadImageFormatException)
        {
            return false;
        }
        catch (OverflowException)
        {
            return false;
        }
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
        var facts = RawMetadataPreflight.Analyze(context.OriginalBytes, context.OriginalImage);
        context.SetFact("metadata.raw", facts);
        foreach (var anomaly in facts.Anomalies)
            context.AddEvidence(new Evidence("metadata-anomaly", anomaly, Confidence: 1.0));

        if (NativePackDetector.TryDescribe(context.Module, out var nativeReason))
        {
            context.SetFact("preflight.nativePacked", true);
            context.AddEvidence(new Evidence("native-pack", nativeReason, Confidence: 1.0));
            return (PassStatus.Unsupported, 0,
            [
                nativeReason,
                "Native-stub unpacking (NecroBit native/QuickLZ) is a deferred capability; " +
                "static managed recovery cannot proceed on this input."
            ]);
        }

        return (PassStatus.Success, 0,
        [
            $"Raw metadata: {facts.ModuleRows} Module row(s), {facts.AssemblyRows} Assembly row(s).",
            $"Streams: {string.Join(", ", facts.Streams.Select(stream => stream.Name))}.",
            $"Anomalies: {facts.Anomalies.Count}."
        ]);
    }
}
