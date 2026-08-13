using dnlib.DotNet;
using ReactorUnpack.Core.Analysis;

namespace ReactorUnpack.Tests;

public sealed class NativePackDetectionTests
{
    [SampleFact]
    public void ManagedReactorSampleIsNotFlaggedAsNativePacked()
    {
        using var module = ModuleDefMD.Load(Checkout.Sample("Qbjuef.exe"));

        Assert.False(NativePackDetector.TryDescribe(module, out _));
    }

    [SampleFact]
    public void ClearingTheIlOnlyFlagIsReportedAsNativePacked()
    {
        var patched = ClearIlOnly(File.ReadAllBytes(Checkout.Sample("Qbjuef.exe")));
        using var module = ModuleDefMD.Load(patched);

        Assert.True(NativePackDetector.TryDescribe(module, out var reason));
        Assert.Contains("IL-only", reason, StringComparison.OrdinalIgnoreCase);
    }

    private static byte[] ClearIlOnly(byte[] original)
    {
        var bytes = (byte[])original.Clone();
        var pe = BitConverter.ToInt32(bytes, 0x3C);
        var optional = pe + 24;
        var magic = BitConverter.ToUInt16(bytes, optional);
        var dataDirectory = optional + (magic == 0x20B ? 112 : 96);
        var cliRva = BitConverter.ToInt32(bytes, dataDirectory + 14 * 8);
        var cliOffset = RvaToFileOffset(bytes, pe, (uint)cliRva);
        var flagsOffset = cliOffset + 16;
        var flags = BitConverter.ToUInt32(bytes, flagsOffset);
        flags &= ~1u; // COMIMAGE_FLAGS_ILONLY
        BitConverter.GetBytes(flags).CopyTo(bytes, flagsOffset);
        return bytes;
    }

    private static int RvaToFileOffset(byte[] bytes, int peOffset, uint rva)
    {
        var sectionCount = BitConverter.ToUInt16(bytes, peOffset + 6);
        var optionalSize = BitConverter.ToUInt16(bytes, peOffset + 20);
        var sectionTable = peOffset + 24 + optionalSize;
        for (var index = 0; index < sectionCount; index++)
        {
            var header = sectionTable + index * 40;
            var virtualAddress = BitConverter.ToUInt32(bytes, header + 12);
            var rawSize = BitConverter.ToUInt32(bytes, header + 16);
            var rawPointer = BitConverter.ToUInt32(bytes, header + 20);
            if (rva >= virtualAddress && rva < virtualAddress + rawSize)
                return (int)(rawPointer + (rva - virtualAddress));
        }

        throw new InvalidOperationException("RVA is outside every section.");
    }
}
