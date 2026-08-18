using System.Buffers.Binary;
using dnlib.DotNet;
using Cilantro.Core.Analysis;

namespace Cilantro.Core.Recovery;

/// <summary>
/// ConfuserEx's anti-tamper rewrite, which decrypts one section it owns and nothing else.
/// </summary>
/// <remarks>
/// The bound cannot be per method the way Reactor's is: ConfuserEx moved every protected body into
/// a section of its own and decrypts the whole thing in one pass, so a per-slot bound would reject
/// the decryptor for doing exactly what it exists to do. What can be required is that the rewrite
/// stayed inside a single section, that the section is the one the protector added, and that every
/// byte outside it is untouched.
///
/// The section is identified from the write log itself rather than from the detector's guess, so
/// the bound describes what the decryptor did rather than what it was expected to do, and the two
/// have to agree.
/// </remarks>
public sealed class ConfuserExSectionRewritePolicy : IImageRewritePolicy
{
    private readonly PeSection _expected;
    private readonly RewriteTarget[] _targets;

    public ConfuserExSectionRewritePolicy(PeSection encryptedSection, ModuleDefMD module)
    {
        ArgumentNullException.ThrowIfNull(encryptedSection);
        ArgumentNullException.ThrowIfNull(module);
        _expected = encryptedSection;
        _targets = module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => Covers(encryptedSection, (uint)method.RVA))
            .Select(method => new RewriteTarget(method.MDToken.Raw, (uint)method.RVA))
            .OrderBy(target => target.Rva)
            .ToArray();
    }

    public string Protector => "ConfuserEx";

    public IReadOnlyList<RewriteTarget> Targets => _targets;

    public bool TryReplay(
        PeImageView image,
        IReadOnlyList<MappedImageWrite> writes,
        out byte[] restoredFile,
        out IReadOnlySet<uint> restoredTokens,
        out string? diagnostic)
    {
        ArgumentNullException.ThrowIfNull(image);
        ArgumentNullException.ThrowIfNull(writes);
        restoredFile = image.CreateFileCopy();
        var original = image.CreateFileCopy();

        if (!TryMeasureExtent(writes, out var start, out var end, out var extentRefusal))
            return Refuse(out restoredFile, out restoredTokens, out diagnostic, extentRefusal!);

        var section = image.Sections.FirstOrDefault(candidate =>
            start >= candidate.VirtualAddress &&
            end <= (ulong)candidate.VirtualAddress + candidate.MappedSize);
        if (section is null)
            return Refuse(
                out restoredFile,
                out restoredTokens,
                out diagnostic,
                $"The rewrite spans [0x{start:X8},0x{end:X8}), which is not inside one section.");
        if (!string.Equals(section.Name, _expected.Name, StringComparison.Ordinal) ||
            section.VirtualAddress != _expected.VirtualAddress)
            return Refuse(
                out restoredFile,
                out restoredTokens,
                out diagnostic,
                $"The rewrite targeted section at RVA 0x{section.VirtualAddress:X8}, not the " +
                $"encrypted section at RVA 0x{_expected.VirtualAddress:X8}.");

        foreach (var write in writes)
        {
            for (var index = 0; index < write.Bytes.Length; index++)
            {
                var rva = checked((uint)write.Offset + (uint)index);
                if (!image.TryRvaToFileOffset(rva, out var fileOffset))
                    return Refuse(
                        out restoredFile,
                        out restoredTokens,
                        out diagnostic,
                        $"A rewrite at RVA 0x{rva:X8} is not file-backed.");
                restoredFile[fileOffset] = write.Bytes[index];
            }
        }

        if (!OutsideSectionIsPreserved(image, section, original, restoredFile))
            return Refuse(
                out restoredFile,
                out restoredTokens,
                out diagnostic,
                "Replay changed bytes outside the encrypted section.");

        // The metadata says where every body in this section begins. A section that decrypted
        // correctly has a well-formed method header at each of those places, and one that
        // decrypted with the wrong key does not. This is the check that separates the two.
        if (!TryValidateMethodHeaders(image, restoredFile, out var headerRefusal))
            return Refuse(out restoredFile, out restoredTokens, out diagnostic, headerRefusal!);

        restoredTokens = _targets.Select(target => target.Token).ToHashSet();
        diagnostic = null;
        return true;
    }

    /// <summary>
    /// A method is still protected here if its body did not survive the decryption, which is the
    /// only claim this policy can make without reading the code back.
    /// </summary>
    public bool IsStillProtected(MethodDef method)
    {
        ArgumentNullException.ThrowIfNull(method);
        return !method.HasBody;
    }

    /// <summary>
    /// Field data inside the encrypted section was decrypted along with the code around it, and
    /// ConfuserEx's constants table is exactly that.
    /// </summary>
    public bool CoversFieldData(uint rva, int length) =>
        length > 0 &&
        rva >= _expected.VirtualAddress &&
        (ulong)rva + (uint)length <= (ulong)_expected.VirtualAddress + _expected.MappedSize;

    private bool TryValidateMethodHeaders(
        PeImageView image,
        byte[] restoredFile,
        out string? diagnostic)
    {
        var malformed = 0;
        var firstBad = 0u;
        foreach (var target in _targets)
        {
            if (!image.TryRvaToFileOffset(target.Rva, out var offset) ||
                offset + 12 > restoredFile.Length ||
                !IsWellFormedHeader(restoredFile.AsSpan(offset)))
            {
                malformed++;
                if (firstBad == 0)
                    firstBad = target.Rva;
            }
        }
        if (malformed == 0)
        {
            diagnostic = null;
            return true;
        }
        diagnostic = $"{malformed} of {_targets.Length} decrypted method bodies do not begin with " +
            $"a well-formed CIL header (first at RVA 0x{firstBad:X8}); the decryption did not " +
            "produce method bodies.";
        return false;
    }

    private static bool IsWellFormedHeader(ReadOnlySpan<byte> body)
    {
        if ((body[0] & 3) == 2)
            return body[0] >> 2 > 0;
        if ((body[0] & 3) != 3)
            return false;
        var flags = BinaryPrimitives.ReadUInt16LittleEndian(body);
        if ((flags >> 12) < 3)
            return false;
        var codeSize = BinaryPrimitives.ReadUInt32LittleEndian(body[4..]);
        return codeSize > 0 && codeSize <= int.MaxValue / 2;
    }

    private static bool TryMeasureExtent(
        IReadOnlyList<MappedImageWrite> writes,
        out uint start,
        out ulong end,
        out string? diagnostic)
    {
        start = uint.MaxValue;
        end = 0;
        foreach (var write in writes)
        {
            if (!string.Equals(write.RegionKind, "MappedImage", StringComparison.Ordinal))
            {
                diagnostic = $"A write targeted non-image region '{write.RegionKind}'.";
                return false;
            }
            if (write.Bytes.Length == 0 || write.Offset < 0)
            {
                diagnostic = "A mapped-image write has an empty or negative range.";
                return false;
            }
            start = Math.Min(start, (uint)write.Offset);
            end = Math.Max(end, (ulong)(uint)write.Offset + (uint)write.Bytes.Length);
        }
        if (end == 0)
        {
            diagnostic = "The rewrite wrote nothing to the mapped image.";
            return false;
        }
        diagnostic = null;
        return true;
    }

    private static bool OutsideSectionIsPreserved(
        PeImageView image,
        PeSection section,
        ReadOnlySpan<byte> original,
        ReadOnlySpan<byte> restored)
    {
        if (original.Length != restored.Length)
            return false;
        var allowed = new bool[original.Length];
        for (var offset = 0u; offset < section.MappedSize; offset++)
        {
            if (image.TryRvaToFileOffset(section.VirtualAddress + offset, out var fileOffset) &&
                (uint)fileOffset < (uint)allowed.Length)
            {
                allowed[fileOffset] = true;
            }
        }
        for (var index = 0; index < original.Length; index++)
        {
            if (!allowed[index] && original[index] != restored[index])
                return false;
        }
        return true;
    }

    private static bool Covers(PeSection section, uint rva) =>
        rva != 0 && rva >= section.VirtualAddress &&
        rva - section.VirtualAddress < section.MappedSize;

    private static bool Refuse(
        out byte[] restoredFile,
        out IReadOnlySet<uint> restoredTokens,
        out string? diagnostic,
        string message)
    {
        restoredFile = [];
        restoredTokens = new HashSet<uint>();
        diagnostic = message;
        return false;
    }
}
