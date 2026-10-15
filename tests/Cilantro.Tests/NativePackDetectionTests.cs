using dnlib.DotNet;
using Cilantro.Core.Analysis;

namespace Cilantro.Tests;

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

    [Theory]
    [InlineData(0u, "IL-only")]
    [InlineData(0x10u, "native entry point")]
    public void NativeHeadersRefuseManagedRewriteWithoutClaimingProtection(uint flags, string detail)
    {
        using var synthetic = new ModuleDefUser("ordinary.dll") { Kind = ModuleKind.Dll };
        new AssemblyDefUser("Ordinary", new Version(1, 0)).Modules.Add(synthetic);
        using var stream = new MemoryStream();
        synthetic.Write(stream);
        var bytes = stream.ToArray();
        var pe = BitConverter.ToInt32(bytes, 0x3c);
        var optional = pe + 24;
        var directories = optional + (BitConverter.ToUInt16(bytes, optional) == 0x20b ? 112 : 96);
        var cor = RvaToFileOffset(bytes, pe, BitConverter.ToUInt32(bytes, directories + 14 * 8));
        BitConverter.GetBytes(flags).CopyTo(bytes, cor + 16);
        using var module = ModuleDefMD.Load(bytes);
        Assert.True(NativePackDetector.TryDescribe(module, out var reason));
        Assert.Contains(detail, reason, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("packed", reason, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Reactor", reason, StringComparison.OrdinalIgnoreCase);
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
