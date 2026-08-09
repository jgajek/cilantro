using System.Buffers.Binary;
using ReactorUnpack.Core.Analysis;

namespace ReactorUnpack.Tests;

public sealed class PeImageViewTests
{
    [Fact]
    public void ParsesPe32HeadersSectionsAndMappedImage()
    {
        var file = CreateImage(pe32Plus: false);

        var image = new PeImageView(file);

        Assert.False(image.IsPe32Plus);
        Assert.Equal((ushort)0x14C, image.Machine);
        Assert.Equal(0x00400000UL, image.ImageBase);
        Assert.Equal(0x1010u, image.AddressOfEntryPoint);
        Assert.Equal(0x200u, image.SizeOfHeaders);
        Assert.Equal(0x3000u, image.SizeOfImage);
        var section = Assert.Single(image.Sections);
        Assert.Equal(".text", section.Name);
        Assert.Equal(0x1000u, section.VirtualAddress);
        Assert.Equal(0x300u, section.VirtualSize);
        Assert.Equal(0x200u, section.PointerToRawData);
        Assert.Equal(0x200u, section.SizeOfRawData);

        Assert.Equal(file[..0x200], image.Read(0, 0x200).ToArray());
        Assert.Equal(file[0x200..0x400], image.Read(0x1000, 0x200).ToArray());
        Assert.All(image.Read(0x1200, 0x100).ToArray(), value => Assert.Equal(0, value));
        Assert.All(image.Read(0x800, 0x100).ToArray(), value => Assert.Equal(0, value));
    }

    [Fact]
    public void ParsesPe32PlusImageBase()
    {
        var image = new PeImageView(CreateImage(pe32Plus: true));

        Assert.True(image.IsPe32Plus);
        Assert.Equal((ushort)0x20B, image.OptionalHeaderMagic);
        Assert.Equal(0x0000000140000000UL, image.ImageBase);
    }

    [Fact]
    public void ConvertsOnlyFileBackedRvasAndReportsZeroFill()
    {
        var image = new PeImageView(CreateImage(pe32Plus: false));

        Assert.True(image.TryRvaToFileOffset(0x100, out var headerOffset));
        Assert.Equal(0x100, headerOffset);
        Assert.True(image.TryRvaToFileOffset(0x11FF, out var sectionOffset));
        Assert.Equal(0x3FF, sectionOffset);
        Assert.False(image.TryRvaToFileOffset(0x1200, out _));
        Assert.True(image.IsZeroFilledRva(0x1200));
        Assert.True(image.IsZeroFilledRva(0x800));
        Assert.False(image.IsZeroFilledRva(0x3000));

        Assert.True(image.TryFileOffsetToRva(0x100, out var headerRva));
        Assert.Equal(0x100u, headerRva);
        Assert.True(image.TryFileOffsetToRva(0x3FF, out var sectionRva));
        Assert.Equal(0x11FFu, sectionRva);
        Assert.False(image.TryFileOffsetToRva(0x400, out _));
    }

    [Fact]
    public void BoundsReadsAndCopiesWithoutExposingMutableStorage()
    {
        var file = CreateImage(pe32Plus: false);
        var expected = file[0x220..0x230].ToArray();
        var image = new PeImageView(file);
        file.AsSpan().Clear();

        Assert.Equal(expected, image.Read(0x1020, 0x10).ToArray());
        Assert.False(image.TryRead(0x2FFF, 2, out _));
        Assert.False(image.TryRead(0, -1, out _));
        Assert.False(image.TryReadFile(-1, 1, out _));
        Assert.Throws<ArgumentOutOfRangeException>(() => image.Read(0x3000, 1));

        Span<byte> destination = stackalloc byte[16];
        Assert.True(image.TryCopyTo(0x1020, destination));
        Assert.Equal(expected, destination.ToArray());
        Assert.False(image.TryCopyTo(0x2FFF, destination));

        var mappedCopy = image.CreateMappedImage();
        mappedCopy[0x1020] ^= 0xFF;
        Assert.Equal(expected, image.Read(0x1020, 0x10).ToArray());
    }

    [Fact]
    public void SectionCollectionAndMetadataAreImmutable()
    {
        var image = new PeImageView(CreateImage(pe32Plus: false));
        var sections = Assert.IsAssignableFrom<IList<PeSection>>(image.Sections);

        Assert.Throws<NotSupportedException>(() =>
            sections[0] = sections[0] with { Name = ".changed" });
        Assert.Equal(".text", image.Sections[0].Name);
    }

    [Fact]
    public void RejectsTruncatedAndInvalidHeaders()
    {
        Assert.False(PeImageView.TryParse([], out _));

        var badDos = CreateImage(pe32Plus: false);
        badDos[0] = 0;
        Assert.False(PeImageView.TryParse(badDos, out _));

        var badPeOffset = CreateImage(pe32Plus: false);
        BinaryPrimitives.WriteInt32LittleEndian(badPeOffset.AsSpan(0x3C), int.MaxValue);
        Assert.False(PeImageView.TryParse(badPeOffset, out _));

        var truncated = CreateImage(pe32Plus: false)[..0x300];
        Assert.False(PeImageView.TryParse(truncated, out _));
    }

    [Fact]
    public void RejectsOverlappingSectionsInMemoryOrFile()
    {
        var virtualOverlap = CreateImage(pe32Plus: false, includeSecondSection: true);
        var secondHeader = GetSectionTableOffset(pe32Plus: false) + 40;
        BinaryPrimitives.WriteUInt32LittleEndian(
            virtualOverlap.AsSpan(secondHeader + 12),
            0x1100);
        Assert.False(PeImageView.TryParse(virtualOverlap, out _));

        var rawOverlap = CreateImage(pe32Plus: false, includeSecondSection: true);
        BinaryPrimitives.WriteUInt32LittleEndian(
            rawOverlap.AsSpan(secondHeader + 20),
            0x300);
        Assert.False(PeImageView.TryParse(rawOverlap, out _));
    }

    [Fact]
    public void RejectsSectionsThatOverlapHeadersOrExceedImage()
    {
        var headerOverlap = CreateImage(pe32Plus: false);
        var sectionHeader = GetSectionTableOffset(pe32Plus: false);
        BinaryPrimitives.WriteUInt32LittleEndian(
            headerOverlap.AsSpan(sectionHeader + 12),
            0x100);
        Assert.False(PeImageView.TryParse(headerOverlap, out _));

        var imageOverflow = CreateImage(pe32Plus: false);
        BinaryPrimitives.WriteUInt32LittleEndian(
            imageOverflow.AsSpan(sectionHeader + 8),
            0x3000);
        Assert.False(PeImageView.TryParse(imageOverflow, out _));
    }

    [Fact]
    public void EnforcesConfiguredMappedImageLimit()
    {
        var file = CreateImage(pe32Plus: false);

        Assert.False(PeImageView.TryParse(file, out _, maximumMappedImageSize: 0x2000));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new PeImageView(file, maximumMappedImageSize: 0));
    }

    private static byte[] CreateImage(bool pe32Plus, bool includeSecondSection = false)
    {
        const int peOffset = 0x80;
        const int sizeOfHeaders = 0x200;
        var optionalHeaderSize = pe32Plus ? 0xF0 : 0xE0;
        var sectionCount = includeSecondSection ? 2 : 1;
        var file = new byte[includeSecondSection ? 0x600 : 0x400];

        BinaryPrimitives.WriteUInt16LittleEndian(file, 0x5A4D);
        BinaryPrimitives.WriteInt32LittleEndian(file.AsSpan(0x3C), peOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(peOffset), 0x00004550);

        var coff = peOffset + 4;
        BinaryPrimitives.WriteUInt16LittleEndian(
            file.AsSpan(coff),
            pe32Plus ? (ushort)0x8664 : (ushort)0x14C);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(coff + 2), (ushort)sectionCount);
        BinaryPrimitives.WriteUInt16LittleEndian(
            file.AsSpan(coff + 16),
            (ushort)optionalHeaderSize);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(coff + 18), 0x2022);

        var optional = coff + 20;
        BinaryPrimitives.WriteUInt16LittleEndian(
            file.AsSpan(optional),
            pe32Plus ? (ushort)0x20B : (ushort)0x10B);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(optional + 16), 0x1010);
        if (pe32Plus)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(
                file.AsSpan(optional + 24),
                0x0000000140000000UL);
        }
        else
        {
            BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(optional + 28), 0x00400000);
        }
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(optional + 32), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(optional + 36), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(optional + 56), 0x3000);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(optional + 60), sizeOfHeaders);

        WriteSection(
            file,
            GetSectionTableOffset(pe32Plus),
            ".text",
            virtualSize: 0x300,
            virtualAddress: 0x1000,
            rawSize: 0x200,
            rawOffset: 0x200,
            characteristics: 0x60000020);
        FillPayload(file.AsSpan(0x200, 0x200), 0x31);

        if (includeSecondSection)
        {
            WriteSection(
                file,
                GetSectionTableOffset(pe32Plus) + 40,
                ".data",
                virtualSize: 0x180,
                virtualAddress: 0x2000,
                rawSize: 0x200,
                rawOffset: 0x400,
                characteristics: 0xC0000040);
            FillPayload(file.AsSpan(0x400, 0x200), 0x79);
        }

        return file;
    }

    private static int GetSectionTableOffset(bool pe32Plus) =>
        0x80 + 4 + 20 + (pe32Plus ? 0xF0 : 0xE0);

    private static void WriteSection(
        Span<byte> file,
        int offset,
        string name,
        uint virtualSize,
        uint virtualAddress,
        uint rawSize,
        uint rawOffset,
        uint characteristics)
    {
        System.Text.Encoding.ASCII.GetBytes(name).CopyTo(file[offset..]);
        BinaryPrimitives.WriteUInt32LittleEndian(file[(offset + 8)..], virtualSize);
        BinaryPrimitives.WriteUInt32LittleEndian(file[(offset + 12)..], virtualAddress);
        BinaryPrimitives.WriteUInt32LittleEndian(file[(offset + 16)..], rawSize);
        BinaryPrimitives.WriteUInt32LittleEndian(file[(offset + 20)..], rawOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(file[(offset + 36)..], characteristics);
    }

    private static void FillPayload(Span<byte> bytes, byte seed)
    {
        for (var index = 0; index < bytes.Length; index++)
            bytes[index] = unchecked((byte)(seed + index));
    }
}
