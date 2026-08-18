using System.Buffers.Binary;
using System.Collections.ObjectModel;
using System.Text;

namespace ReactorUnpack.Core.Analysis;

public sealed record PeSection(
    string Name,
    uint VirtualAddress,
    uint VirtualSize,
    uint PointerToRawData,
    uint SizeOfRawData,
    uint Characteristics)
{
    private const uint MemoryExecute = 0x2000_0000;
    private const uint MemoryRead = 0x4000_0000;
    private const uint MemoryWrite = 0x8000_0000;

    public uint MappedSize => Math.Max(VirtualSize, SizeOfRawData);

    /// <summary>
    /// The page protection the loader gives this section once the image is mapped.
    /// </summary>
    /// <remarks>
    /// A writable section of a mapped image is not plain writable: the loader maps the image
    /// copy-on-write, so a section asking for write comes back as one of the WRITECOPY
    /// protections until something writes to it. The distinction is invisible to code that only
    /// reads and writes, and it is exactly what a protector asks about when it wants to know
    /// whether someone else has already made its section writable.
    /// </remarks>
    public uint PageProtection => (Characteristics & (MemoryExecute | MemoryRead | MemoryWrite))
        switch
        {
            MemoryExecute | MemoryRead | MemoryWrite => 0x80, // PAGE_EXECUTE_WRITECOPY
            MemoryExecute | MemoryRead => 0x20,               // PAGE_EXECUTE_READ
            MemoryExecute | MemoryWrite => 0x80,              // PAGE_EXECUTE_WRITECOPY
            MemoryExecute => 0x10,                            // PAGE_EXECUTE
            MemoryRead | MemoryWrite => 0x08,                 // PAGE_WRITECOPY
            MemoryRead => 0x02,                               // PAGE_READONLY
            MemoryWrite => 0x08,                              // PAGE_WRITECOPY
            _ => 0x01                                         // PAGE_NOACCESS
        };
}

/// <summary>
/// A validated, read-only view of a PE file and its loader-style mapped image.
/// </summary>
public sealed class PeImageView
{
    public const int DefaultMaximumMappedImageSize = 256 * 1024 * 1024;

    private const int DosHeaderSize = 64;
    private const int CoffHeaderSize = 20;
    private const int SectionHeaderSize = 40;
    private const ushort Pe32Magic = 0x10B;
    private const ushort Pe32PlusMagic = 0x20B;

    private readonly byte[] _fileBytes;
    private readonly byte[] _mappedBytes;
    private readonly ReadOnlyCollection<PeSection> _sections;

    public PeImageView(
        ReadOnlySpan<byte> bytes,
        int maximumMappedImageSize = DefaultMaximumMappedImageSize)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumMappedImageSize);

        EnsureAvailable(bytes, 0, DosHeaderSize, "DOS header");
        if (ReadUInt16(bytes, 0) != 0x5A4D)
            throw Invalid("Missing DOS MZ signature.");

        var peOffset = ReadInt32(bytes, 0x3C);
        if (peOffset < DosHeaderSize)
            throw Invalid("The PE header overlaps the DOS header.");
        EnsureAvailable(bytes, peOffset, 4 + CoffHeaderSize, "PE and COFF headers");
        if (ReadUInt32(bytes, peOffset) != 0x00004550)
            throw Invalid("Missing PE signature.");

        PeHeaderOffset = peOffset;
        var coffOffset = peOffset + 4;
        Machine = ReadUInt16(bytes, coffOffset);
        var numberOfSections = ReadUInt16(bytes, coffOffset + 2);
        var optionalHeaderSize = ReadUInt16(bytes, coffOffset + 16);
        Characteristics = ReadUInt16(bytes, coffOffset + 18);
        if (numberOfSections == 0)
            throw Invalid("The PE image has no sections.");

        var optionalOffset = checked(coffOffset + CoffHeaderSize);
        EnsureAvailable(bytes, optionalOffset, optionalHeaderSize, "optional header");
        if (optionalHeaderSize < 64)
            throw Invalid("The optional header is too small.");

        OptionalHeaderMagic = ReadUInt16(bytes, optionalOffset);
        if (OptionalHeaderMagic == Pe32Magic)
        {
            IsPe32Plus = false;
            ImageBase = ReadUInt32(bytes, optionalOffset + 28);
        }
        else if (OptionalHeaderMagic == Pe32PlusMagic)
        {
            IsPe32Plus = true;
            ImageBase = ReadUInt64(bytes, optionalOffset + 24);
        }
        else
        {
            throw Invalid("Unsupported optional-header magic.");
        }

        AddressOfEntryPoint = ReadUInt32(bytes, optionalOffset + 16);
        SectionAlignment = ReadUInt32(bytes, optionalOffset + 32);
        FileAlignment = ReadUInt32(bytes, optionalOffset + 36);
        SizeOfImage = ReadUInt32(bytes, optionalOffset + 56);
        SizeOfHeaders = ReadUInt32(bytes, optionalOffset + 60);

        if (SectionAlignment == 0 || FileAlignment == 0)
            throw Invalid("PE alignment values must be nonzero.");
        if (SizeOfImage == 0 || SizeOfImage > int.MaxValue ||
            SizeOfImage > (uint)maximumMappedImageSize)
        {
            throw Invalid("The mapped image size is invalid or exceeds the configured limit.");
        }
        if (SizeOfHeaders == 0 || SizeOfHeaders > SizeOfImage ||
            SizeOfHeaders > (uint)bytes.Length)
        {
            throw Invalid("SizeOfHeaders is outside the file or mapped image.");
        }
        if (AddressOfEntryPoint >= SizeOfImage && AddressOfEntryPoint != 0)
            throw Invalid("The entry point is outside the mapped image.");

        var sectionTableOffset = checked(optionalOffset + optionalHeaderSize);
        var sectionTableSize = checked((int)numberOfSections * SectionHeaderSize);
        EnsureAvailable(bytes, sectionTableOffset, sectionTableSize, "section table");
        if ((ulong)sectionTableOffset + (uint)sectionTableSize > SizeOfHeaders)
            throw Invalid("The section table extends beyond SizeOfHeaders.");

        var sections = new PeSection[numberOfSections];
        for (var index = 0; index < sections.Length; index++)
        {
            var offset = checked(sectionTableOffset + index * SectionHeaderSize);
            var name = ReadSectionName(bytes.Slice(offset, 8));
            var section = new PeSection(
                name,
                ReadUInt32(bytes, offset + 12),
                ReadUInt32(bytes, offset + 8),
                ReadUInt32(bytes, offset + 20),
                ReadUInt32(bytes, offset + 16),
                ReadUInt32(bytes, offset + 36));
            ValidateSection(section, bytes.Length);
            sections[index] = section;
        }

        RejectOverlaps(sections);

        _fileBytes = bytes.ToArray();
        _mappedBytes = new byte[checked((int)SizeOfImage)];
        bytes[..checked((int)SizeOfHeaders)].CopyTo(_mappedBytes);
        foreach (var section in sections)
        {
            if (section.SizeOfRawData == 0)
                continue;
            bytes.Slice(
                    checked((int)section.PointerToRawData),
                    checked((int)section.SizeOfRawData))
                .CopyTo(_mappedBytes.AsSpan(
                    checked((int)section.VirtualAddress),
                    checked((int)section.SizeOfRawData)));
        }

        _sections = Array.AsReadOnly(sections);
    }

    public int PeHeaderOffset { get; }
    public ushort Machine { get; }
    public ushort Characteristics { get; }
    public ushort OptionalHeaderMagic { get; }
    public bool IsPe32Plus { get; }
    public ulong ImageBase { get; }
    public uint AddressOfEntryPoint { get; }
    public uint SectionAlignment { get; }
    public uint FileAlignment { get; }
    public uint SizeOfHeaders { get; }
    public uint SizeOfImage { get; }
    public int FileLength => _fileBytes.Length;
    public IReadOnlyList<PeSection> Sections => _sections;

    public static bool TryParse(
        ReadOnlySpan<byte> bytes,
        out PeImageView? image,
        int maximumMappedImageSize = DefaultMaximumMappedImageSize)
    {
        try
        {
            image = new PeImageView(bytes, maximumMappedImageSize);
            return true;
        }
        catch (BadImageFormatException)
        {
            image = null;
            return false;
        }
        catch (OverflowException)
        {
            image = null;
            return false;
        }
    }

    public bool TryRvaToFileOffset(uint rva, out int fileOffset)
    {
        if (rva < SizeOfHeaders)
        {
            fileOffset = checked((int)rva);
            return true;
        }

        foreach (var section in _sections)
        {
            if (rva < section.VirtualAddress)
                continue;
            var delta = (ulong)rva - section.VirtualAddress;
            if (delta >= section.SizeOfRawData)
                continue;

            var offset = (ulong)section.PointerToRawData + delta;
            if (offset < (ulong)_fileBytes.Length)
            {
                fileOffset = (int)offset;
                return true;
            }
        }

        fileOffset = 0;
        return false;
    }

    public bool TryFileOffsetToRva(int fileOffset, out uint rva)
    {
        if (fileOffset < 0 || fileOffset >= _fileBytes.Length)
        {
            rva = 0;
            return false;
        }
        if ((uint)fileOffset < SizeOfHeaders)
        {
            rva = (uint)fileOffset;
            return true;
        }

        foreach (var section in _sections)
        {
            if ((uint)fileOffset < section.PointerToRawData)
                continue;
            var delta = (ulong)(uint)fileOffset - section.PointerToRawData;
            if (delta >= section.SizeOfRawData)
                continue;

            rva = checked(section.VirtualAddress + (uint)delta);
            return true;
        }

        rva = 0;
        return false;
    }

    public bool IsZeroFilledRva(uint rva) =>
        rva < SizeOfImage && !TryRvaToFileOffset(rva, out _);

    public bool TryRead(uint rva, int count, out ReadOnlyMemory<byte> bytes)
    {
        if (!IsRangeValid(rva, count, _mappedBytes.Length))
        {
            bytes = default;
            return false;
        }

        bytes = _mappedBytes.AsMemory(checked((int)rva), count);
        return true;
    }

    public ReadOnlyMemory<byte> Read(uint rva, int count)
    {
        if (!TryRead(rva, count, out var bytes))
            throw new ArgumentOutOfRangeException(nameof(rva), "The RVA range is outside the mapped image.");
        return bytes;
    }

    public bool TryCopyTo(uint rva, Span<byte> destination)
    {
        if (!IsRangeValid(rva, destination.Length, _mappedBytes.Length))
            return false;
        _mappedBytes.AsSpan(checked((int)rva), destination.Length).CopyTo(destination);
        return true;
    }

    public bool TryReadFile(int fileOffset, int count, out ReadOnlyMemory<byte> bytes)
    {
        if (fileOffset < 0 || count < 0 || fileOffset > _fileBytes.Length - count)
        {
            bytes = default;
            return false;
        }

        bytes = _fileBytes.AsMemory(fileOffset, count);
        return true;
    }

    public bool TryCopyFileTo(int fileOffset, Span<byte> destination)
    {
        if (fileOffset < 0 || fileOffset > _fileBytes.Length - destination.Length)
            return false;
        _fileBytes.AsSpan(fileOffset, destination.Length).CopyTo(destination);
        return true;
    }

    public byte[] CreateMappedImage() => (byte[])_mappedBytes.Clone();

    public byte[] CreateFileCopy() => (byte[])_fileBytes.Clone();

    private void ValidateSection(PeSection section, int fileLength)
    {
        var mappedEnd = (ulong)section.VirtualAddress + section.MappedSize;
        if (section.MappedSize != 0 &&
            (section.VirtualAddress < SizeOfHeaders || mappedEnd > SizeOfImage))
        {
            throw Invalid($"Section '{section.Name}' is outside the mapped image or overlaps headers.");
        }

        if (section.SizeOfRawData == 0)
            return;

        var rawEnd = (ulong)section.PointerToRawData + section.SizeOfRawData;
        if (section.PointerToRawData < SizeOfHeaders || rawEnd > (ulong)fileLength)
            throw Invalid($"Section '{section.Name}' raw data is outside the file or overlaps headers.");
    }

    private static void RejectOverlaps(IReadOnlyList<PeSection> sections)
    {
        RejectOverlaps(
            sections
                .Where(section => section.MappedSize != 0)
                .Select(section => (
                    Start: section.VirtualAddress,
                    Size: section.MappedSize,
                    section.Name))
                .OrderBy(range => range.Start),
            "memory");
        RejectOverlaps(
            sections
                .Where(section => section.SizeOfRawData != 0)
                .Select(section => (
                    Start: section.PointerToRawData,
                    Size: section.SizeOfRawData,
                    section.Name))
                .OrderBy(range => range.Start),
            "file");
    }

    private static void RejectOverlaps(
        IEnumerable<(uint Start, uint Size, string Name)> ranges,
        string location)
    {
        (uint Start, uint Size, string Name)? previous = null;
        foreach (var current in ranges)
        {
            if (previous is { } left &&
                RangesOverlap(left.Start, left.Size, current.Start, current.Size))
            {
                throw Invalid(
                    $"Sections '{left.Name}' and '{current.Name}' overlap in {location}.");
            }
            previous = current;
        }
    }

    private static bool RangesOverlap(uint leftStart, uint leftSize, uint rightStart, uint rightSize)
    {
        if (leftSize == 0 || rightSize == 0)
            return false;
        var leftEnd = (ulong)leftStart + leftSize;
        var rightEnd = (ulong)rightStart + rightSize;
        return leftStart < rightEnd && rightStart < leftEnd;
    }

    private static bool IsRangeValid(uint offset, int count, int length) =>
        count >= 0 && offset <= (uint)length && (ulong)offset + (uint)count <= (uint)length;

    private static string ReadSectionName(ReadOnlySpan<byte> bytes)
    {
        var length = bytes.IndexOf((byte)0);
        if (length < 0)
            length = bytes.Length;
        return Encoding.ASCII.GetString(bytes[..length]);
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> bytes, int offset)
    {
        EnsureAvailable(bytes, offset, sizeof(ushort), "PE field");
        return BinaryPrimitives.ReadUInt16LittleEndian(bytes[offset..]);
    }

    private static uint ReadUInt32(ReadOnlySpan<byte> bytes, int offset)
    {
        EnsureAvailable(bytes, offset, sizeof(uint), "PE field");
        return BinaryPrimitives.ReadUInt32LittleEndian(bytes[offset..]);
    }

    private static int ReadInt32(ReadOnlySpan<byte> bytes, int offset)
    {
        EnsureAvailable(bytes, offset, sizeof(int), "PE field");
        return BinaryPrimitives.ReadInt32LittleEndian(bytes[offset..]);
    }

    private static ulong ReadUInt64(ReadOnlySpan<byte> bytes, int offset)
    {
        EnsureAvailable(bytes, offset, sizeof(ulong), "PE field");
        return BinaryPrimitives.ReadUInt64LittleEndian(bytes[offset..]);
    }

    private static void EnsureAvailable(
        ReadOnlySpan<byte> bytes,
        int offset,
        int count,
        string structure)
    {
        if (offset < 0 || count < 0 || offset > bytes.Length - count)
            throw Invalid($"The {structure} extends beyond the file.");
    }

    private static BadImageFormatException Invalid(string message) => new(message);
}
