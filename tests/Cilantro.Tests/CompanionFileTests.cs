using System.Security.Cryptography;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class CompanionFileTests
{
    [Fact]
    public void OnlyExplicitCopiedFilesCanBeReadAndStreamsStayReadOnly()
    {
        using var module = new ModuleDefUser("Files"); var importer = new Importer(module);
        var state = new StaticMachineState(new StaticMachineLimits()); var intrinsic = new LoaderFrameworkIntrinsic();
        var context = new IntrinsicContext(state);
        var home = Path.Combine(Path.GetTempPath(), "Cilantro.Virtual", "host.dll"); state.RegisterModuleFile(home, [9]);
        byte[] supplied = [4, 5, 6]; Assert.True(state.RegisterCompanionFile("code.eil", supplied)); supplied[0] = 99;
        StaticValue Text(string text) { Assert.True(state.Heap.TryAllocateString(text, out var value)); return value; }
        var domain = intrinsic.Invoke(context, importer.Import(typeof(AppDomain).GetProperty("CurrentDomain")!.GetMethod!), []).Value;
        var directory = intrinsic.Invoke(context, importer.Import(typeof(AppDomain).GetProperty("BaseDirectory")!.GetMethod!), [domain]);
        Assert.Equal(StaticExecutionStatus.Completed, directory.Status);
        var appDirectory = intrinsic.Invoke(context, importer.Import(typeof(AppContext).GetProperty("BaseDirectory")!.GetMethod!), []);
        Assert.True(state.Heap.TryGetString(directory.Value, out var directoryText));
        Assert.True(state.Heap.TryGetString(appDirectory.Value, out var appDirectoryText));
        Assert.Equal(directoryText, appDirectoryText);
        var path = intrinsic.Invoke(context, importer.Import(typeof(Path).GetMethod("Combine", [typeof(string), typeof(string)])!), [directory.Value, Text("code.eil")]);
        Assert.Equal(StaticExecutionStatus.Completed, path.Status);
        var read = importer.Import(typeof(File).GetMethod("ReadAllBytes", [typeof(string)])!);
        var one = intrinsic.Invoke(context, read, [path.Value]); Assert.Equal(StaticExecutionStatus.Completed, one.Status);
        Assert.Equal(new byte[] { 4, 5, 6 }, state.Heap.GetBytesSnapshot(one.Value));
        Assert.True(state.Heap.TryWriteArray(one.Value, 0, StaticValue.FromInt32(77)));
        var two = intrinsic.Invoke(context, read, [path.Value]);
        Assert.Equal(new byte[] { 4, 5, 6 }, state.Heap.GetBytesSnapshot(two.Value));
        var stream = intrinsic.Invoke(context, importer.Import(typeof(File).GetMethod("OpenRead", [typeof(string)])!), [path.Value]);
        Assert.Equal(StaticExecutionStatus.Completed, stream.Status);
        Assert.True(state.Heap.TryGetRuntimeTypeName(stream.Value, out var type)); Assert.Equal("System.IO.FileStream", type);
        Assert.Equal(0, intrinsic.Invoke(context, importer.Import(typeof(Stream).GetProperty("CanWrite")!.GetMethod!), [stream.Value]).Value.AsInt32());
        Assert.Equal(4, intrinsic.Invoke(context, importer.Import(typeof(Stream).GetMethod("ReadByte")!), [stream.Value]).Value.AsInt32());
        Assert.DoesNotContain(state.LoaderEvidence.Observations, o => o.Kind == LoaderObservationKind.ModuleFileRead);
        Assert.Contains(state.LoaderEvidence.Observations, o => o.Kind == LoaderObservationKind.CompanionFileRead &&
            o.Detail.Contains(Convert.ToHexStringLower(SHA256.HashData(new byte[] { 4, 5, 6 })), StringComparison.Ordinal));
        var ctor = importer.Import(typeof(FileStream).GetConstructor([typeof(string), typeof(FileMode), typeof(FileAccess)])!);
        Assert.True(state.Heap.TryAllocateObject("System.IO.FileStream", out var receiver));
        Assert.Equal(StaticExecutionStatus.Completed, intrinsic.Invoke(context, ctor,
            [receiver, path.Value, StaticValue.FromInt32((int)FileMode.Open), StaticValue.FromInt32((int)FileAccess.Read)]).Status);
        Assert.NotEqual(StaticExecutionStatus.Completed, intrinsic.Invoke(context, ctor,
            [receiver, path.Value, StaticValue.FromInt32((int)FileMode.Open), StaticValue.FromInt32((int)FileAccess.ReadWrite)]).Status);
        var outside = Text(Path.Combine(Path.GetTempPath(), "not-registered.eil"));
        Assert.NotEqual(StaticExecutionStatus.Completed, intrinsic.Invoke(context, read, [outside]).Status);
        Assert.NotEqual(StaticExecutionStatus.Completed, intrinsic.Invoke(context,
            importer.Import(typeof(Path).GetMethod("Combine", [typeof(string), typeof(string)])!), [directory.Value, Text("../code.eil")]).Status);
        state.RegisterModuleBytes([9]);
        Assert.NotEqual(StaticExecutionStatus.Completed, intrinsic.Invoke(context, read, [path.Value]).Status);
        Assert.NotEqual(StaticExecutionStatus.Completed, intrinsic.Invoke(context,
            importer.Import(typeof(AppDomain).GetProperty("BaseDirectory")!.GetMethod!), [domain]).Status);
    }

    [Theory]
    [InlineData("..")]
    [InlineData("../code.eil")]
    [InlineData("nested/code.eil")]
    [InlineData("C:\\code.eil")]
    [InlineData("host.dll")]
    public void MountsRequireSafeUniqueLeafNames(string name)
    {
        var state = new StaticMachineState(new StaticMachineLimits());
        state.RegisterModuleFile(Path.Combine(Path.GetTempPath(), "host.dll"), [1]);
        Assert.False(state.RegisterCompanionFile(name, [2]));
        Assert.True(state.RegisterCompanionFile("code.eil", [2]));
        Assert.False(state.RegisterCompanionFile("CODE.EIL", [3]));
        Assert.False(state.RegisterCompanionFile("empty.eil", []));
        for (var i = 1; i < 16; i++) Assert.True(state.RegisterCompanionFile($"code{i}.eil", [2]));
        Assert.False(state.RegisterCompanionFile("overflow.eil", [2]));
    }

    [Fact]
    public void RegistrationSnapshotsFilesAtomicallyAndRecordsTheirHashes()
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.CodeInputs.").FullName;
        try
        {
            using var context = SyntheticContext.Build(_ => { });
            var file = Path.Combine(directory, "code.eil"); File.WriteAllBytes(file, [1, 2, 3]);
            Assert.Throws<FileNotFoundException>(() => BabelCodeSourceInputs.Register(context, [file, Path.Combine(directory, "missing.eil")]));
            Assert.DoesNotContain(context.Evidence, e => e.Category == "babel-code-source");
            BabelCodeSourceInputs.Register(context, [file]);
            File.WriteAllBytes(file, [9]);
            var state = new StaticMachineState(new StaticMachineLimits()); state.RegisterModuleFile(context.InputPath, context.OriginalBytes);
            Assert.True(BabelCodeSourceInputs.Attach(context, state));
            Assert.True(state.TryReadCompanionFile(Path.Combine(Path.GetDirectoryName(context.InputPath)!, "code.eil"), "test", out var bytes));
            Assert.Equal(new byte[] { 1, 2, 3 }, bytes);
            Assert.Contains(context.Evidence, e => e.Category == "babel-code-source" &&
                e.Message.Contains(Convert.ToHexStringLower(SHA256.HashData(bytes)), StringComparison.Ordinal));
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public void ExistingUnregisteredHostFilesAreUnavailableAndHeapBoundsStillApply()
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.ClosedFiles.").FullName;
        try
        {
            var hostFile = Path.Combine(directory, "private.eil"); File.WriteAllBytes(hostFile, [9, 8, 7]);
            using var module = new ModuleDefUser("Files"); var importer = new Importer(module);
            var state = new StaticMachineState(new StaticMachineLimits(MaximumArrayLength: 512));
            state.RegisterModuleFile(Path.Combine(directory, "host.dll"), [1]);
            Assert.True(state.RegisterCompanionFile("allowed.eil", new byte[513]));
            Assert.True(state.Heap.TryAllocateString(hostFile, out var path));
            var intrinsic = new LoaderFrameworkIntrinsic(); var context = new IntrinsicContext(state);
            var read = importer.Import(typeof(File).GetMethod("ReadAllBytes", [typeof(string)])!);
            Assert.NotEqual(StaticExecutionStatus.Completed, intrinsic.Invoke(context, read, [path]).Status);
            Assert.Equal(0, intrinsic.Invoke(context, importer.Import(typeof(File).GetMethod("Exists", [typeof(string)])!), [path]).Value.AsInt32());
            Assert.True(state.Heap.TryAllocateString(Path.Combine(directory, "allowed.eil"), out var allowed));
            Assert.NotEqual(StaticExecutionStatus.Completed, intrinsic.Invoke(context, read, [allowed]).Status);
            Assert.Equal(new byte[] { 9, 8, 7 }, File.ReadAllBytes(hostFile));
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public void CatalogByteBoundsAndVolumeRootMountsAreEnforced()
    {
        var state = new StaticMachineState(new StaticMachineLimits());
        var root = Path.GetPathRoot(Path.GetFullPath(Path.GetTempPath()))!;
        state.RegisterModuleFile(Path.Combine(root, "host.dll"), [1]);
        Assert.False(state.RegisterCompanionFile("too-large.eil", new byte[16 * 1024 * 1024 + 1]));
        var maximum = new byte[16 * 1024 * 1024];
        Assert.True(state.RegisterCompanionFile("one.eil", maximum));
        Assert.True(state.RegisterCompanionFile("two.eil", maximum));
        Assert.False(state.RegisterCompanionFile("aggregate-overflow.eil", [2]));
        Assert.Equal(root, state.CompanionBaseDirectory);
        Assert.True(state.TryReadCompanionFile(Path.Combine(state.CompanionBaseDirectory!, "one.eil"), "test", out var bytes));
        Assert.Equal(maximum.Length, bytes.Length);
    }
}
