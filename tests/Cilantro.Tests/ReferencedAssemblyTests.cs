using Cilantro.Core.Interpretation;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class ReferencedAssemblyTests
{
    [Theory]
    [InlineData(65535, 65535, 65535, 65535)]
    [InlineData(1, 0, 65535, 65535)]
    [InlineData(1, 2, 3, 65535)]
    [InlineData(1, 65535, 0, 0)]
    public void MetadataVersionsMatchABenignRuntimeOracle(int major, int minor, int build, int revision)
    {
        var image = Image("ReferenceVersionOracle", "Required", new Version(major, minor, build, revision));
        // This fixture contains only metadata and fields: no sample or executable code.
        var expected = System.Reflection.Assembly.Load(image).GetReferencedAssemblies();
        using var module = ModuleDefMD.Load(image);
        var state = new StaticMachineState(new StaticMachineLimits()); state.RegisterModuleMetadata(module);
        var intrinsic = new LoaderFrameworkIntrinsic(); var context = new IntrinsicContext(state); var importer = new Importer(module);
        var receiver = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.Assembly).GetMethod("GetExecutingAssembly")!), []);
        var result = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.Assembly).GetMethod("GetReferencedAssemblies")!), [receiver.Value]);
        Assert.True(result.Status == StaticExecutionStatus.Completed, result.Diagnostic);
        Assert.True(state.Heap.TryGetLength(result.Value, out var count)); Assert.Equal(expected.Length, count);
        for (var index = 0; index < count; index++)
        {
            Assert.True(state.Heap.TryReadArray(result.Value, index, out var identity));
            Assert.True(state.Heap.TryGetModelValue(identity, "FullName", out string? name)); Assert.Equal(expected[index].FullName, name);
            Assert.True(state.Heap.TryGetModelValue(identity, "VersionComponents", out int[]? version));
            var v = expected[index].Version;
            Assert.Equal(v is null ? [] : new[] { v.Major, v.Minor, v.Build, v.Revision }, version);
            Assert.True(state.Heap.TryGetModelValue(identity, "NullVersion", out bool absent)); Assert.Equal(v is null, absent);
        }
    }

    [Fact]
    public void ReferenceArraysRespectTheInterpreterAllocationLimit()
    {
        using var module = ModuleDefMD.Load(Image("Home", "Required"));
        var state = new StaticMachineState(new StaticMachineLimits(MaximumArrayLength: 0));
        state.RegisterModuleMetadata(module);
        var intrinsic = new LoaderFrameworkIntrinsic(); var context = new IntrinsicContext(state); var importer = new Importer(module);
        var receiver = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.Assembly).GetMethod("GetExecutingAssembly")!), []);
        Assert.Equal(StaticExecutionStatus.Completed, receiver.Status);
        var result = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.Assembly).GetMethod("GetReferencedAssemblies")!), [receiver.Value]);
        Assert.NotEqual(StaticExecutionStatus.Completed, result.Status);
        Assert.Empty(state.CapturedAssemblyLoads);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ReadsTheSelectedImagesMetadataWithoutLoadingItsDependencies(bool loaded)
    {
        var image = Image("Payload", "Required");
        using var payload = ModuleDefMD.Load(image);
        using var home = ModuleDefMD.Load(Image("Home", "Unrelated"));
        var state = new StaticMachineState(new StaticMachineLimits()); state.RegisterModuleMetadata(home);
        var heap = state.Heap; var intrinsic = new LoaderFrameworkIntrinsic(); var context = new IntrinsicContext(state);
        var importer = new Importer(home);
        var executing = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.Assembly).GetMethod("GetExecutingAssembly")!), []);
        var receiver = executing.Value;
        if (loaded)
        {
            Assert.True(heap.TryAllocateByteArray(image, out var bytes));
            receiver = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.Assembly).GetMethod("Load", [typeof(byte[])])!), [bytes]).Value;
        }
        var loads = state.CapturedAssemblyLoads.Count;
        var query = importer.Import(typeof(System.Reflection.Assembly).GetMethod("GetReferencedAssemblies")!);
        var fullName = importer.Import(typeof(System.Reflection.AssemblyName).GetProperty("FullName")!.GetMethod!);
        var expected = (loaded ? payload : home).GetAssemblyRefs().Select(r => r.FullName).ToArray();
        var first = intrinsic.Invoke(context, query, [receiver]); var second = intrinsic.Invoke(context, query, [receiver]);
        Assert.True(first.Status == StaticExecutionStatus.Completed, first.Diagnostic); Assert.Equal(StaticExecutionStatus.Completed, second.Status);
        Assert.NotEqual(first.Value, second.Value);
        Assert.True(heap.TryGetRuntimeTypeName(first.Value, out var type)); Assert.Equal("System.Reflection.AssemblyName[]", type);
        Assert.True(heap.TryGetLength(first.Value, out var length)); Assert.Equal(expected.Length, length);
        for (var index = 0; index < length; index++)
        {
            Assert.True(heap.TryReadArray(first.Value, index, out var one)); Assert.True(heap.TryReadArray(second.Value, index, out var two));
            Assert.NotEqual(one, two);
            Assert.True(heap.TryGetString(intrinsic.Invoke(context, fullName, [one]).Value, out var identity));
            Assert.Equal(expected[index], identity);
            Assert.True(heap.TryWriteArray(first.Value, index, StaticValue.Null));
            Assert.True(heap.TryReadArray(second.Value, index, out var unchanged)); Assert.Equal(two, unchanged);
        }
        Assert.Equal(loads, state.CapturedAssemblyLoads.Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void UnknownOrMalformedAssembliesDoNotBorrowHomeReferences(bool malformed)
    {
        using var module = ModuleDefMD.Load(Image("Home", "Required"));
        var state = new StaticMachineState(new StaticMachineLimits()); state.RegisterModuleMetadata(module);
        Assert.True(state.Heap.TryAllocateObject("System.Reflection.Assembly", out var receiver));
        if (malformed) Assert.True(state.Heap.TrySetModelValue(receiver, "LoadedImage", new byte[] { 1, 2, 3 }));
        var method = new Importer(module).Import(typeof(System.Reflection.Assembly).GetMethod("GetReferencedAssemblies")!);
        var result = new LoaderFrameworkIntrinsic().Invoke(new IntrinsicContext(state), method, [receiver]);
        Assert.NotEqual(StaticExecutionStatus.Completed, result.Status);
        Assert.Empty(state.CapturedAssemblyLoads);
    }

    private static byte[] Image(string name, string dependency, Version? version = null)
    {
        using var module = new ModuleDefUser(name + ".dll");
        new AssemblyDefUser(name, new Version(1, 0)).Modules.Add(module);
        var reference = new AssemblyRefUser(dependency, version ?? new Version(2, 3, 4, 5))
            { Culture = "fr-FR", PublicKeyOrToken = new PublicKeyToken(new byte[] { 0, 17, 34, 51, 68, 85, 102, 119 }), Attributes = AssemblyAttributes.None };
        var owner = SyntheticContext.AddType(module, "Consumer");
        owner.Fields.Add(new FieldDefUser("Dependency", new FieldSig(new TypeRefUser(module, "External", "Service", reference).ToTypeSig()), FieldAttributes.Static));
        using var bytes = new MemoryStream(); module.Write(bytes); return bytes.ToArray();
    }
}
