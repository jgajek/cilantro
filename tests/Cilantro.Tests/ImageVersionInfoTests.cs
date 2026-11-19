using System.Buffers.Binary;
using System.Reflection;
using System.Text;
using Cilantro.Core.Interpretation;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class ImageVersionInfoTests
{
    [Fact]
    public void ReadsFixedPartsAndTextFromOneLanguageTable()
    {
        var data = VersionData();
        Assert.True(ImageVersionInfo.TryParse(data, out var version));
        Assert.Equal(0x00070002u, version.FileHigh);
        Assert.Equal(0x00030004u, version.FileLow);
        Assert.Equal("7.2.3.4", version.Strings["FileVersion"]);
        Assert.Equal("Product", version.Strings["ProductName"]);
    }

    [Fact]
    public void RejectsTruncatedAndOutOfBoundsVersionBlocks()
    {
        var bytes = VersionData();
        for (var size = 0; size < bytes.Length; size++)
            Assert.False(ImageVersionInfo.TryParse(bytes.AsSpan(0, size), out _));
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(2), ushort.MaxValue);
        Assert.False(ImageVersionInfo.TryParse(bytes, out _));
    }

    [Fact]
    public void DoesNotGuessWhichLanguageTableTheHostWouldSelect()
    {
        Assert.False(ImageVersionInfo.TryParse(Block("VS_VERSION_INFO", 0, [],
            Block("StringFileInfo", 1, [],
                Block("040904b0", 1, [], Text("FileVersion", "First")),
                Block("040704b0", 1, [], Text("FileVersion", "Second")))), out _));
    }

    [Fact]
    public void RegisteredImageVersionIsDistinctFromRuntimeVersion()
    {
        using var module = new ModuleDefUser("VersionTrial");
        var state = new StaticMachineState(new StaticMachineLimits());
        state.RegisterModuleFile("/case/sample.exe", File.ReadAllBytes(typeof(ImageVersionInfoTests).Assembly.Location));
        var intrinsic = new LoaderFrameworkIntrinsic();
        var application = new TypeRefUser(module, "System.Windows.Forms", "Application", new AssemblyRefUser("System.Windows.Forms"));
        var pathResult = intrinsic.Invoke(new IntrinsicContext(state), new MemberRefUser(module,
            "get_ExecutablePath", MethodSig.CreateStatic(module.CorLibTypes.String), application), []);
        Assert.Equal(StaticExecutionStatus.Completed, pathResult.Status);
        Assert.True(state.Heap.TryGetString(pathResult.Value, out var path));
        Assert.Equal("/case/sample.exe", path);
        var versionType = new TypeRefUser(module, "System.Diagnostics", "FileVersionInfo", module.CorLibTypes.AssemblyRef);
        var getInfo = new MemberRefUser(module, "GetVersionInfo", MethodSig.CreateStatic(versionType.ToTypeSig(), module.CorLibTypes.String), versionType);
        var info = intrinsic.Invoke(new IntrinsicContext(state), getInfo, [pathResult.Value]);
        Assert.Equal(StaticExecutionStatus.Completed, info.Status);
        var getter = new MemberRefUser(module, "get_FileVersion", MethodSig.CreateInstance(module.CorLibTypes.String), versionType);
        var result = intrinsic.Invoke(new IntrinsicContext(state), getter, [info.Value]);
        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.True(state.Heap.TryGetString(result.Value, out var version));
        Assert.Equal(typeof(ImageVersionInfoTests).Assembly.GetCustomAttribute<AssemblyFileVersionAttribute>()!.Version, version);
        Assert.Equal(result.Value, intrinsic.Invoke(new IntrinsicContext(state), getter, [info.Value]).Value);
        Assert.True(state.Heap.TryAllocateString(typeof(ImageVersionInfoTests).Assembly.Location, out var foreign));
        Assert.NotEqual(StaticExecutionStatus.Completed, intrinsic.Invoke(new IntrinsicContext(state), getInfo, [foreign]).Status);
        Assert.Empty(state.Host.Questions);
    }

    private static byte[] VersionData()
    {
        var fixedInfo = new byte[52];
        BinaryPrimitives.WriteUInt32LittleEndian(fixedInfo, 0xFEEF04BD);
        BinaryPrimitives.WriteUInt32LittleEndian(fixedInfo.AsSpan(8), 0x00070002);
        BinaryPrimitives.WriteUInt32LittleEndian(fixedInfo.AsSpan(12), 0x00030004);
        return Block("VS_VERSION_INFO", 0, fixedInfo,
            Block("StringFileInfo", 1, [],
                Block("040904b0", 1, [], Text("FileVersion", "7.2.3.4"), Text("ProductName", "Product"))));
    }

    private static byte[] Text(string key, string value) => Block(key, 1, Encoding.Unicode.GetBytes(value + '\0'));

    private static byte[] Block(string key, ushort type, byte[] value, params byte[][] children)
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, Encoding.Unicode, leaveOpen: true);
        writer.Write((ushort)0);
        writer.Write((ushort)(type == 1 ? value.Length / 2 : value.Length));
        writer.Write(type);
        writer.Write(Encoding.Unicode.GetBytes(key + '\0'));
        Align();
        writer.Write(value);
        foreach (var child in children) { Align(); writer.Write(child); }
        var bytes = stream.ToArray();
        BinaryPrimitives.WriteUInt16LittleEndian(bytes, (ushort)bytes.Length);
        return bytes;
        void Align() { while (stream.Position % 4 != 0) writer.Write((byte)0); }
    }
}
