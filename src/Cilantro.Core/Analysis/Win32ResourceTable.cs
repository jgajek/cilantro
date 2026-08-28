using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace Cilantro.Core.Analysis;

/// <summary>One leaf of a PE resource directory: what it is called, and where its bytes are.</summary>
/// <remarks>
/// Type and name each arrive as either an integer or a string, never both, which is why both forms
/// are carried. <see cref="Describe"/> is what to put in a report; matching is better done on the
/// fields, because a numbered resource and one named for the same number are different resources.
/// </remarks>
public sealed record Win32Resource(
    uint TypeId,
    string? TypeName,
    uint NameId,
    string? Name,
    uint LanguageId,
    uint DataRva,
    uint Size)
{
    /// <summary>The RT_RCDATA type, which is where a packer puts bytes it does not want named.</summary>
    public const uint RcDataType = 10;

    public bool IsNamed(uint type, string name) =>
        TypeName is null &&
        TypeId == type &&
        Name is not null &&
        string.Equals(Name, name, StringComparison.Ordinal);

    public string Describe() =>
        string.Create(
            CultureInfo.InvariantCulture,
            $"{TypeName ?? TypeId.ToString(CultureInfo.InvariantCulture)}/" +
            $"{Name ?? NameId.ToString(CultureInfo.InvariantCulture)}/{LanguageId}");
}

/// <summary>
/// Reads the resource directory of a PE image, for the cases where the resources matter and the
/// managed metadata either does not exist or is not the thing being asked about.
/// </summary>
/// <remarks>
/// Separate from <see cref="ResourceInspector"/>, which reads a managed module's own resources
/// through dnlib. This one reads the Win32 directory underneath, which is the only place a native
/// bootstrap keeps anything, and is therefore readable on a file with no CLR header at all.
/// </remarks>
public static class Win32ResourceTable
{
    /// <summary>The data-directory slot holding the resource directory.</summary>
    public const int DirectoryIndex = 2;

    private const int DirectoryHeaderSize = 16;
    private const int DirectoryEntrySize = 8;
    private const int DataEntrySize = 16;
    private const uint HighBit = 0x8000_0000;

    // Types, names, languages. A directory found below the third level is malformed, and treating it
    // as a leaf would invent resources; the reader stops instead.
    private const int MaximumDepth = 3;

    // A cap rather than a guess: a real image has tens, and an unbounded walk over a crafted
    // directory is how a reader of untrusted files becomes a way to spend all day.
    private const int MaximumResources = 4096;

    public static IReadOnlyList<Win32Resource> Read(PeImageView image)
    {
        ArgumentNullException.ThrowIfNull(image);
        if (!image.TryGetDataDirectory(DirectoryIndex, out var rootRva, out var size) ||
            rootRva == 0 ||
            size == 0)
        {
            return [];
        }

        var found = new List<Win32Resource>();
        Walk(image, rootRva, rootRva, depth: 0, 0, null, 0, null, found);
        return found;
    }

    /// <summary>Reads one resource's bytes, or false where the image does not carry them.</summary>
    public static bool TryReadBytes(
        PeImageView image,
        Win32Resource resource,
        out ReadOnlyMemory<byte> bytes)
    {
        ArgumentNullException.ThrowIfNull(image);
        ArgumentNullException.ThrowIfNull(resource);
        bytes = default;
        return resource.Size <= int.MaxValue &&
            image.TryRead(resource.DataRva, (int)resource.Size, out bytes);
    }

    private static void Walk(
        PeImageView image,
        uint rootRva,
        uint directoryRva,
        int depth,
        uint typeId,
        string? typeName,
        uint nameId,
        string? name,
        List<Win32Resource> found)
    {
        if (depth >= MaximumDepth ||
            found.Count >= MaximumResources ||
            !image.TryRead(directoryRva, DirectoryHeaderSize, out var header))
        {
            return;
        }

        var named = BinaryPrimitives.ReadUInt16LittleEndian(header.Span[12..]);
        var numbered = BinaryPrimitives.ReadUInt16LittleEndian(header.Span[14..]);
        var total = named + numbered;
        for (var index = 0; index < total; index++)
        {
            if (found.Count >= MaximumResources)
                return;

            var entryRva = directoryRva + (uint)DirectoryHeaderSize + (uint)(index * DirectoryEntrySize);
            if (!image.TryRead(entryRva, DirectoryEntrySize, out var entry))
                return;

            var identifier = BinaryPrimitives.ReadUInt32LittleEndian(entry.Span);
            var offset = BinaryPrimitives.ReadUInt32LittleEndian(entry.Span[4..]);

            uint entryId = 0;
            string? entryName = null;
            if ((identifier & HighBit) != 0)
                entryName = ReadName(image, rootRva + (identifier & ~HighBit));
            else
                entryId = identifier;

            // A named entry whose name could not be read is skipped rather than reported under its
            // raw offset, which would be a name no other tool agrees with.
            if ((identifier & HighBit) != 0 && entryName is null)
                continue;

            var childRva = rootRva + (offset & ~HighBit);
            if ((offset & HighBit) != 0)
            {
                Walk(
                    image,
                    rootRva,
                    childRva,
                    depth + 1,
                    depth == 0 ? entryId : typeId,
                    depth == 0 ? entryName : typeName,
                    depth == 1 ? entryId : nameId,
                    depth == 1 ? entryName : name,
                    found);
                continue;
            }

            // Leaves below the language level are the only ones that name a real blob. A leaf found
            // higher up is a directory that lied about its depth.
            if (depth != MaximumDepth - 1 || !image.TryRead(childRva, DataEntrySize, out var data))
                continue;

            var dataRva = BinaryPrimitives.ReadUInt32LittleEndian(data.Span);
            var dataSize = BinaryPrimitives.ReadUInt32LittleEndian(data.Span[4..]);
            if (dataSize == 0 || dataSize > int.MaxValue || !image.TryRead(dataRva, 1, out _))
                continue;

            found.Add(new Win32Resource(
                typeId,
                typeName,
                nameId,
                name,
                entryId,
                dataRva,
                dataSize));
        }
    }

    private static string? ReadName(PeImageView image, uint rva)
    {
        if (!image.TryRead(rva, sizeof(ushort), out var lengthBytes))
            return null;
        var characters = BinaryPrimitives.ReadUInt16LittleEndian(lengthBytes.Span);
        if (characters == 0)
            return string.Empty;
        return image.TryRead(rva + sizeof(ushort), characters * sizeof(char), out var text)
            ? Encoding.Unicode.GetString(text.Span)
            : null;
    }
}
