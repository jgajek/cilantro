using System.Buffers.Binary;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;

namespace Cilantro.Core.Recovery;

internal sealed record ConfuserExJitEntry(MethodDef Method, int FileOffset, int WordCount);

/// <summary>Reads the sorted method-token index in a decrypted ConfuserEx JIT section.</summary>
internal static class ConfuserExJitBodyIndex
{
    internal static bool TryRead(ModuleDefMD module, PeImageView image, PeSection section,
        byte[] restoredFile, out IReadOnlyList<ConfuserExJitEntry> entries,
        out string diagnostic)
    {
        entries = [];
        diagnostic = string.Empty;
        if (!image.TryRvaToFileOffset(section.VirtualAddress, out var sectionStart) ||
            sectionStart < 0 || section.SizeOfRawData > int.MaxValue ||
            (long)sectionStart + section.SizeOfRawData > restoredFile.Length ||
            section.SizeOfRawData < 24)
        {
            diagnostic = "JIT section is not wholly file-backed.";
            return false;
        }
        var sectionEnd = sectionStart + (int)section.SizeOfRawData;
        var count = BinaryPrimitives.ReadUInt32LittleEndian(restoredFile.AsSpan(sectionStart + 16));
        var methodCount = module.GetTypes().SelectMany(type => type.Methods).Count();
        if (count == 0 || count > methodCount || count > 100_000 ||
            (ulong)20 + 8ul * count > section.SizeOfRawData)
        {
            diagnostic = $"JIT body index count {count} is outside the section or method table.";
            return false;
        }
        var indexBase = sectionStart + 20;
        var bodyStart = indexBase + checked((int)count * 8);
        var result = new List<ConfuserExJitEntry>((int)count);
        uint priorToken = 0;
        int priorOffset = -1;
        for (var i = 0; i < count; i++)
        {
            var pair = indexBase + checked((int)i * 8);
            var token = BinaryPrimitives.ReadUInt32LittleEndian(restoredFile.AsSpan(pair));
            var offsetWords = BinaryPrimitives.ReadUInt32LittleEndian(restoredFile.AsSpan(pair + 4));
            var absolute = (ulong)indexBase + 4ul * offsetWords;
            if (token <= priorToken || module.ResolveToken(new MDToken(token)) is not MethodDef method ||
                method.Body.Instructions is not [
                    { OpCode.Code: Code.Ldnull }, { OpCode.Code: Code.Throw }] ||
                absolute < (ulong)bodyStart || absolute + 4 > (ulong)sectionEnd)
            {
                diagnostic = $"JIT index entry {i} has a bad token, stub or body offset.";
                return false;
            }
            var fileOffset = checked((int)absolute);
            if (fileOffset <= priorOffset)
            {
                diagnostic = $"JIT index entry {i} is not sorted by body offset.";
                return false;
            }
            var words = BinaryPrimitives.ReadUInt32LittleEndian(restoredFile.AsSpan(fileOffset));
            if (words == 0 || words > int.MaxValue / 4 ||
                absolute + 4ul + 4ul * words > (ulong)sectionEnd)
            {
                diagnostic = $"JIT index entry {i} has an invalid body length.";
                return false;
            }
            result.Add(new ConfuserExJitEntry(method, fileOffset + 4, (int)words));
            priorToken = token;
            priorOffset = fileOffset;
        }
        for (var i = 1; i < result.Count; i++)
            if ((long)result[i - 1].FileOffset + 4L * result[i - 1].WordCount >
                result[i].FileOffset - 4L)
            {
                diagnostic = "JIT body records overlap.";
                return false;
            }
        entries = result;
        return true;
    }
}
