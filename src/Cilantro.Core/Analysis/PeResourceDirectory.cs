using System.Buffers.Binary;
using System.Text;

namespace Cilantro.Core.Analysis;

/// <summary>
/// Reads <paramref name="destination"/>.Length bytes at an RVA of a mapped image, or answers false
/// where that range is not mapped.
/// </summary>
/// <remarks>
/// A delegate rather than a span so the caller can serve the bytes from wherever the image it means
/// actually lives — a file view, or an interpreter's heap region that the interpreted program may
/// itself have written to — without any of it being copied to be read.
/// </remarks>
public delegate bool MappedImageReader(int rva, Span<byte> destination);

/// <summary>Either of the two things a Win32 resource type or name can be.</summary>
public readonly record struct ResourceName(ushort Id, string? Name)
{
    public static ResourceName FromId(ushort id) => new(id, null);

    public static ResourceName FromString(string name) => new(0, name);

    public bool IsNamed => Name is not null;

    public override string ToString() => Name is null ? $"#{Id}" : $"\"{Name}\"";
}

/// <summary>
/// Walks the Win32 resource directory of a mapped image the way <c>FindResource</c> walks it:
/// type, then name, then language.
/// </summary>
/// <remarks>
/// A protector that keeps its payload in <c>RT_RCDATA</c> and fetches it through the resource API
/// reaches it this way rather than through a managed manifest resource, so a static reading of that
/// loader has to be able to answer the same question against the same bytes.
/// </remarks>
public static class PeResourceDirectory
{
    /// <summary>The data-directory slot holding the Win32 resource directory.</summary>
    public const int ResourceDirectoryIndex = 2;

    private const int DirectoryHeaderSize = 16;
    private const int DirectoryEntrySize = 8;
    private const uint SubdirectoryFlag = 0x8000_0000;
    private const uint OffsetMask = 0x7FFF_FFFF;
    private const int MaximumEntriesPerNode = 4096;
    private const int MaximumNameLength = 256;

    /// <summary>
    /// Finds one resource and returns the RVA of its <c>IMAGE_RESOURCE_DATA_ENTRY</c>, which is
    /// what <c>FindResource</c> hands back: a pointer into the image rather than a fresh object.
    /// </summary>
    public static bool TryFindDataEntry(
        MappedImageReader read,
        ResourceName type,
        ResourceName name,
        out uint dataEntryRva)
    {
        ArgumentNullException.ThrowIfNull(read);
        dataEntryRva = 0;
        if (!TryGetDirectory(read, out var directoryRva, out _) ||
            !TryFindChild(read, directoryRva, directoryRva, type, out var typeNode, out var isTypeDir) ||
            !isTypeDir ||
            !TryFindChild(read, directoryRva, typeNode, name, out var nameNode, out var isNameDir) ||
            !isNameDir)
        {
            return false;
        }

        // The language level is not searched. Which language a running process would be given is a
        // fact about that machine, and a resource carrying a payload is filed under one language;
        // taking the first entry is the reading that does not invent a host.
        if (!TryFirstChild(read, directoryRva, nameNode, out var leaf, out var isLeafDir) ||
            isLeafDir)
        {
            return false;
        }

        dataEntryRva = leaf;
        return true;
    }

    /// <summary>Reads the data RVA and byte count out of an <c>IMAGE_RESOURCE_DATA_ENTRY</c>.</summary>
    public static bool TryReadDataEntry(
        MappedImageReader read,
        uint dataEntryRva,
        out uint dataRva,
        out int size)
    {
        ArgumentNullException.ThrowIfNull(read);
        dataRva = 0;
        size = 0;
        Span<byte> entry = stackalloc byte[8];
        if (dataEntryRva > int.MaxValue || !read((int)dataEntryRva, entry))
            return false;
        dataRva = BinaryPrimitives.ReadUInt32LittleEndian(entry);
        var declared = BinaryPrimitives.ReadUInt32LittleEndian(entry[4..]);
        if (dataRva == 0 || declared == 0 || declared > int.MaxValue)
            return false;
        size = (int)declared;
        return true;
    }

    /// <summary>Locates the resource directory through the data directory of the mapped headers.</summary>
    public static bool TryGetDirectory(MappedImageReader read, out uint rva, out uint size)
    {
        ArgumentNullException.ThrowIfNull(read);
        rva = 0;
        size = 0;
        Span<byte> word = stackalloc byte[4];
        if (!read(0x3C, word))
            return false;
        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(word);
        if (peOffset < 0 || !read(peOffset, word) ||
            BinaryPrimitives.ReadUInt32LittleEndian(word) != 0x0000_4550)
        {
            return false;
        }

        Span<byte> half = stackalloc byte[2];
        if (!read(peOffset + 20, half))
            return false;
        var optionalHeaderSize = BinaryPrimitives.ReadUInt16LittleEndian(half);
        var optionalOffset = peOffset + 24;
        if (!read(optionalOffset, half))
            return false;
        var directoriesRelative = BinaryPrimitives.ReadUInt16LittleEndian(half) == 0x20B ? 112 : 96;
        var slotRelative = directoriesRelative + ResourceDirectoryIndex * DirectoryEntrySize;
        if (optionalHeaderSize < slotRelative + DirectoryEntrySize)
            return false;

        Span<byte> slot = stackalloc byte[DirectoryEntrySize];
        if (!read(optionalOffset + slotRelative, slot))
            return false;
        rva = BinaryPrimitives.ReadUInt32LittleEndian(slot);
        size = BinaryPrimitives.ReadUInt32LittleEndian(slot[4..]);
        return rva != 0 && size != 0;
    }

    private static bool TryFindChild(
        MappedImageReader read,
        uint directoryRva,
        uint nodeRva,
        ResourceName key,
        out uint childRva,
        out bool isDirectory)
    {
        childRva = 0;
        isDirectory = false;
        if (!TryReadCounts(read, nodeRva, out var named, out var identified))
            return false;
        var total = named + identified;
        for (var index = 0; index < total; index++)
        {
            if (!TryReadEntry(read, nodeRva, index, out var nameField, out var dataField))
                return false;
            var entryIsNamed = (nameField & SubdirectoryFlag) != 0;
            if (entryIsNamed != key.IsNamed)
                continue;
            var matches = entryIsNamed
                ? TryReadName(read, directoryRva + (nameField & OffsetMask), out var text) &&
                    string.Equals(text, key.Name, StringComparison.OrdinalIgnoreCase)
                : (ushort)nameField == key.Id;
            if (!matches)
                continue;
            isDirectory = (dataField & SubdirectoryFlag) != 0;
            childRva = directoryRva + (dataField & OffsetMask);
            return true;
        }

        return false;
    }

    private static bool TryFirstChild(
        MappedImageReader read,
        uint directoryRva,
        uint nodeRva,
        out uint childRva,
        out bool isDirectory)
    {
        childRva = 0;
        isDirectory = false;
        if (!TryReadCounts(read, nodeRva, out var named, out var identified) ||
            named + identified == 0 ||
            !TryReadEntry(read, nodeRva, 0, out _, out var dataField))
        {
            return false;
        }

        isDirectory = (dataField & SubdirectoryFlag) != 0;
        childRva = directoryRva + (dataField & OffsetMask);
        return true;
    }

    private static bool TryReadCounts(
        MappedImageReader read,
        uint nodeRva,
        out int named,
        out int identified)
    {
        named = 0;
        identified = 0;
        Span<byte> header = stackalloc byte[DirectoryHeaderSize];
        if (nodeRva > int.MaxValue || !read((int)nodeRva, header))
            return false;
        named = BinaryPrimitives.ReadUInt16LittleEndian(header[12..]);
        identified = BinaryPrimitives.ReadUInt16LittleEndian(header[14..]);
        return named + identified <= MaximumEntriesPerNode;
    }

    private static bool TryReadEntry(
        MappedImageReader read,
        uint nodeRva,
        int index,
        out uint nameField,
        out uint dataField)
    {
        nameField = 0;
        dataField = 0;
        var offset = nodeRva + (ulong)DirectoryHeaderSize + (ulong)index * DirectoryEntrySize;
        if (offset > int.MaxValue)
            return false;
        Span<byte> entry = stackalloc byte[DirectoryEntrySize];
        if (!read((int)offset, entry))
            return false;
        nameField = BinaryPrimitives.ReadUInt32LittleEndian(entry);
        dataField = BinaryPrimitives.ReadUInt32LittleEndian(entry[4..]);
        return true;
    }

    private static bool TryReadName(MappedImageReader read, uint rva, out string? text)
    {
        text = null;
        Span<byte> half = stackalloc byte[2];
        if (rva > int.MaxValue || !read((int)rva, half))
            return false;
        var length = BinaryPrimitives.ReadUInt16LittleEndian(half);
        if (length == 0 || length > MaximumNameLength)
            return false;
        Span<byte> characters = stackalloc byte[length * 2];
        if (!read((int)rva + 2, characters))
            return false;
        text = Encoding.Unicode.GetString(characters);
        return true;
    }
}
