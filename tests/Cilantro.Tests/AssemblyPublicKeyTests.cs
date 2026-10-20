using Cilantro.Core.Interpretation;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class AssemblyPublicKeyTests
{
    private static readonly byte[] Neutral = Convert.FromHexString("00000000000000000400000000000000");

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void MetadataKeysRetainIdentityWithinANameAndIsolationAcrossNames(bool captured, bool hasKey)
    {
        var expected = hasKey ? typeof(string).Assembly.GetName().GetPublicKey()! : [];
        using var module = Module("Home", captured ? Neutral : expected);
        using var child = Module("Child", expected);
        var state = new StaticMachineState(new StaticMachineLimits()); state.RegisterModuleMetadata(module);
        var intrinsic = new LoaderFrameworkIntrinsic(); var context = new IntrinsicContext(state); var importer = new Importer(module);
        var assembly = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.Assembly).GetMethod("GetExecutingAssembly")!), []).Value;
        if (captured)
        {
            using var bytes = new MemoryStream(); child.Write(bytes);
            Assert.True(state.Heap.TryAllocateByteArray(bytes.ToArray(), out var image));
            var read = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.Assembly).GetMethod("Load", [typeof(byte[])])!), [image]);
            Assert.Equal(StaticExecutionStatus.Completed, read.Status); assembly = read.Value;
        }
        var getName = importer.Import(typeof(System.Reflection.Assembly).GetMethod("GetName", Type.EmptyTypes)!);
        var keyMethod = importer.Import(typeof(System.Reflection.AssemblyName).GetMethod("GetPublicKey")!);
        var one = intrinsic.Invoke(context, getName, [assembly]); var two = intrinsic.Invoke(context, getName, [assembly]);
        Assert.Equal(StaticExecutionStatus.Completed, one.Status); Assert.Equal(StaticExecutionStatus.Completed, two.Status);
        var first = intrinsic.Invoke(context, keyMethod, [one.Value]); var again = intrinsic.Invoke(context, keyMethod, [one.Value]);
        var other = intrinsic.Invoke(context, keyMethod, [two.Value]);
        Assert.Equal(StaticExecutionStatus.Completed, first.Status); Assert.Equal(first.Value, again.Value); Assert.NotEqual(first.Value, other.Value);
        Assert.Equal(expected, state.Heap.GetBytesSnapshot(first.Value)); Assert.Equal(expected, state.Heap.GetBytesSnapshot(other.Value));
        if (expected.Length != 0)
        {
            Assert.True(state.Heap.TryWriteArray(first.Value, 0, StaticValue.FromInt32(expected[0] ^ 1)));
            Assert.NotEqual(state.Heap.GetBytesSnapshot(first.Value), state.Heap.GetBytesSnapshot(other.Value));
            Assert.Equal(expected, (captured ? child : module).Assembly.PublicKey.Data);
        }
        Assert.True(state.Heap.TryAllocateObject("System.Version", out var version));
        int[] components = [8, 7, 6, 5];
        Assert.True(state.Heap.TrySetModelValue(version, "Components", components));
        var changed = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.AssemblyName).GetProperty("Version")!.SetMethod!), [one.Value, version]);
        Assert.Equal(StaticExecutionStatus.Completed, changed.Status);
        Assert.Equal(first.Value, intrinsic.Invoke(context, keyMethod, [one.Value]).Value);
        var flags = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.AssemblyName).GetProperty("Flags")!.GetMethod!), [one.Value]);
        Assert.Equal(hasKey ? 1 : 0, flags.Value.AsInt32() & 1);
    }

    [Theory]
    [InlineData("Dependency, PublicKeyToken=0011223344556677")]
    [InlineData("Dependency, PublicKeyToken=null")]
    [InlineData("Dependency")]
    public void TokenOnlyParsedNamesHaveNoFullKey(string identity)
    {
        using var module = Module("Home", Neutral);
        var state = new StaticMachineState(new StaticMachineLimits()); state.RegisterModuleMetadata(module);
        var importer = new Importer(module); var intrinsic = new LoaderFrameworkIntrinsic(); var context = new IntrinsicContext(state);
        Assert.True(state.Heap.TryAllocateObject("System.Reflection.AssemblyName", out var name)); Assert.True(state.Heap.TryAllocateString(identity, out var text));
        Assert.Equal(StaticExecutionStatus.Completed, intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.AssemblyName).GetConstructor([typeof(string)])!), [name, text]).Status);
        var result = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.AssemblyName).GetMethod("GetPublicKey")!), [name]);
        Assert.Equal(StaticExecutionStatus.Completed, result.Status); Assert.Equal(StaticValue.Null, result.Value);
        Assert.Empty(state.CapturedAssemblyLoads);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void UnknownObjectsDoNotBorrowTheHomePublicKey(bool throughAssembly)
    {
        using var module = Module("Home", Neutral);
        var state = new StaticMachineState(new StaticMachineLimits()); state.RegisterModuleMetadata(module);
        var importer = new Importer(module); var intrinsic = new LoaderFrameworkIntrinsic(); var context = new IntrinsicContext(state);
        Assert.True(state.Heap.TryAllocateObject(throughAssembly ? "System.Reflection.Assembly" : "System.Reflection.AssemblyName", out var name));
        if (throughAssembly) name = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.Assembly).GetMethod("GetName", Type.EmptyTypes)!), [name]).Value;
        var result = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.AssemblyName).GetMethod("GetPublicKey")!), [name]);
        Assert.Equal(StaticExecutionStatus.Unknown, result.Status);
    }

    private static ModuleDefUser Module(string name, byte[] key)
    {
        var module = new ModuleDefUser(name + ".dll");
        new AssemblyDefUser(name, new Version(1, 2, 3, 4)) { PublicKey = new PublicKey(key.ToArray()), Attributes = key.Length == 0 ? 0 : AssemblyAttributes.PublicKey }.Modules.Add(module);
        return module;
    }

    [Fact]
    public void PublicKeyAllocationHonorsTheInterpreterArrayBound()
    {
        using var module = Module("Home", Neutral);
        var state = new StaticMachineState(new StaticMachineLimits(MaximumArrayLength: 0)); state.RegisterModuleMetadata(module);
        var importer = new Importer(module); var intrinsic = new LoaderFrameworkIntrinsic(); var context = new IntrinsicContext(state);
        var assembly = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.Assembly).GetMethod("GetExecutingAssembly")!), []).Value;
        var name = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.Assembly).GetMethod("GetName", Type.EmptyTypes)!), [assembly]).Value;
        var result = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.AssemblyName).GetMethod("GetPublicKey")!), [name]);
        Assert.NotEqual(StaticExecutionStatus.Completed, result.Status);
    }

    [Fact]
    public void AParsedFullKeyRemainsDistinctFromAParsedToken()
    {
        using var module = Module("Home", []);
        var state = new StaticMachineState(new StaticMachineLimits()); state.RegisterModuleMetadata(module);
        var importer = new Importer(module); var intrinsic = new LoaderFrameworkIntrinsic(); var context = new IntrinsicContext(state);
        Assert.True(state.Heap.TryAllocateObject("System.Reflection.AssemblyName", out var name));
        Assert.True(state.Heap.TryAllocateString("Dependency, PublicKey=" + Convert.ToHexString(Neutral), out var text));
        var constructed = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.AssemblyName).GetConstructor([typeof(string)])!), [name, text]);
        Assert.Equal(StaticExecutionStatus.Completed, constructed.Status);
        var result = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.AssemblyName).GetMethod("GetPublicKey")!), [name]);
        Assert.Equal(StaticExecutionStatus.Completed, result.Status); Assert.Equal(Neutral, state.Heap.GetBytesSnapshot(result.Value));
    }
}
