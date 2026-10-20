using System.Security.Cryptography;
using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class CustomSymmetricAlgorithmTests
{
    [Fact]
    public void BasePropertiesUseInputFieldsValidateRangesAndCopyKeyMaterial()
    {
        using var artifact = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Cipher");
            type.BaseType = module.CorLibTypes.GetTypeRef("System.Security.Cryptography", "SymmetricAlgorithm");
        });
        var module = artifact.Module; var type = module.Types.Single(t => t.Name == "Cipher");
        var state = new StaticMachineState(new StaticMachineLimits()); state.RegisterModuleMetadata(module);
        var context = new IntrinsicContext(state); var intrinsic = new LoaderFrameworkIntrinsic(); var importer = new Importer(module);
        Assert.True(state.Heap.TryAllocateObject(type.FullName, out var receiver));
        IField Field(string name, TypeSig value) => new MemberRefUser(module, name, new FieldSig(value), type.BaseType!);
        var ctor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), type.BaseType!);
        Assert.Equal(StaticExecutionStatus.Completed, intrinsic.Invoke(context, ctor, [receiver]).Status);
        var sizes = module.CorLibTypes.GetTypeRef("System.Security.Cryptography", "KeySizes");
        foreach (var (name, min, max, step) in new[] { ("LegalKeySizesValue", 128, 256, 64), ("LegalBlockSizesValue", 128, 128, 0) })
        {
            Assert.True(state.Heap.TryAllocateObject("System.Security.Cryptography.KeySizes", out var range));
            var result = intrinsic.Invoke(context, importer.Import(typeof(KeySizes).GetConstructor([typeof(int), typeof(int), typeof(int)])!),
                [range, StaticValue.FromInt32(min), StaticValue.FromInt32(max), StaticValue.FromInt32(step)]);
            Assert.Equal(StaticExecutionStatus.Completed, result.Status);
            Assert.True(state.Heap.TryAllocateArray(new ClassSig(sizes), 1, out var ranges));
            Assert.True(state.Heap.TryWriteArray(ranges, 0, range));
            Assert.True(state.Heap.TryWriteField(receiver, Field(name, new SZArraySig(new ClassSig(sizes))), ranges));
        }
        IntrinsicResult Set(string name, StaticValue value) => intrinsic.Invoke(context, importer.Import(typeof(SymmetricAlgorithm).GetProperty(name)!.SetMethod!), [receiver, value]);
        IntrinsicResult Get(string name) => intrinsic.Invoke(context, importer.Import(typeof(SymmetricAlgorithm).GetProperty(name)!.GetMethod!), [receiver]);
        Assert.Equal(StaticExecutionStatus.Completed, Set("BlockSize", StaticValue.FromInt32(128)).Status);
        Assert.Equal(StaticExecutionStatus.Completed, Set("KeySize", StaticValue.FromInt32(192)).Status);
        Assert.Equal(192, Get("KeySize").Value.AsInt32()); Assert.Equal(128, Get("BlockSize").Value.AsInt32());
        Assert.NotEqual(StaticExecutionStatus.Completed, Set("KeySize", StaticValue.FromInt32(129)).Status);
        Assert.NotEqual(StaticExecutionStatus.Completed, Set("Mode", StaticValue.FromInt32(99)).Status);
        Assert.True(state.Heap.TryAllocateByteArray(Enumerable.Range(0, 16).Select(i => (byte)i).ToArray(), out var key));
        Assert.Equal(StaticExecutionStatus.Completed, Set("Key", key).Status); Assert.Equal(128, Get("KeySize").Value.AsInt32());
        Assert.True(state.Heap.TryWriteArray(key, 0, StaticValue.FromInt32(99)));
        var first = Get("Key"); Assert.Equal(StaticExecutionStatus.Completed, first.Status);
        Assert.Equal(0, state.Heap.GetBytesSnapshot(first.Value)![0]);
        Assert.True(state.Heap.TryWriteArray(first.Value, 0, StaticValue.FromInt32(77)));
        Assert.Equal(0, state.Heap.GetBytesSnapshot(Get("Key").Value)![0]);
        Assert.Equal(StaticExecutionStatus.Completed, Set("IV", key).Status);
        Assert.Equal(16, state.Heap.GetBytesSnapshot(Get("IV").Value)!.Length);
        Assert.True(state.Heap.TryAllocateByteArray(new byte[15], out var invalid));
        Assert.NotEqual(StaticExecutionStatus.Completed, Set("IV", invalid).Status);
        Assert.NotEqual(StaticExecutionStatus.Completed, Set("Key", invalid).Status);
    }

    [Fact]
    public void SeededByteGenerationHasVisibleBoundedStateAndMatchesSequentialReads()
    {
        using var module = new ModuleDefUser("Random"); var importer = new Importer(module);
        var state = new StaticMachineState(new StaticMachineLimits()); var intrinsic = new LoaderFrameworkIntrinsic();
        var budget = new StaticWorkBudget(1000); var context = new IntrinsicContext(state, ConsumeWork: budget.TryConsumeSteps);
        Assert.True(state.Heap.TryAllocateObject("System.Random", out var random));
        Assert.Equal(StaticExecutionStatus.Completed, intrinsic.Invoke(context, importer.Import(typeof(Random).GetConstructor([typeof(int)])!), [random, StaticValue.FromInt32(17)]).Status);
        var next = importer.Import(typeof(Random).GetMethod("NextBytes", [typeof(byte[])])!);
        var output = new List<byte>();
        foreach (var count in new[] { 8, 7 })
        {
            Assert.True(state.Heap.TryAllocateByteArray(new byte[count], out var bytes));
            Assert.Equal(StaticExecutionStatus.Completed, intrinsic.Invoke(context, next, [random, bytes]).Status);
            output.AddRange(state.Heap.GetBytesSnapshot(bytes)!);
        }
        var expected = new byte[15]; new Random(17).NextBytes(expected); Assert.Equal(expected, output);
        Assert.Equal(23, budget.ConsumedSteps);
        Assert.True(state.Heap.TryGetModelValue(random, "RandomBytes", out int used)); Assert.Equal(15, used);
        Assert.True(state.Heap.TryAllocateByteArray(new byte[65536], out var excessive));
        Assert.NotEqual(StaticExecutionStatus.Completed, intrinsic.Invoke(context, next, [random, excessive]).Status);
        Assert.NotEqual(StaticExecutionStatus.Completed, intrinsic.Invoke(context, importer.Import(typeof(Random).GetConstructor(Type.EmptyTypes)!), [random]).Status);
    }

    [Fact]
    public void MillisecondsAreReadFromKnownTicksThroughManagedReferences()
    {
        using var module = new ModuleDefUser("Clock"); var importer = new Importer(module);
        var state = new StaticMachineState(new StaticMachineLimits());
        Assert.True(state.Heap.TryAllocateObject("System.DateTime", out var date));
        var ticks = new DateTime(2026, 10, 20, 1, 2, 3, 456, DateTimeKind.Utc).Ticks;
        Assert.True(state.Heap.TrySetModelValue(date, "Ticks", ticks));
        var reference = state.Heap.AllocateManagedCell(date);
        var result = new AmbientIntrinsic().Invoke(new(state), importer.Import(typeof(DateTime).GetProperty("Millisecond")!.GetMethod!), [reference]);
        Assert.Equal(StaticExecutionStatus.Completed, result.Status); Assert.Equal(456, result.Value.AsInt32());
    }
}
