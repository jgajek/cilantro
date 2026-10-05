using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;

namespace Cilantro.Tests;

public sealed class ModelArraySnapshotTests
{
    [Fact]
    public void AllModelBytesAreComparedAndMutationsRemainVisible()
    {
        var state = new StaticMachineState(new StaticMachineLimits());
        Assert.True(state.Heap.TryAllocateObject("Assembly", out var model));
        var bytes = new byte[100_000];
        Assert.True(state.Heap.TrySetModelValue(model, "LoadedImage", bytes));
        var before = new RebuiltMethodTrial.Snapshot(state.Heap).Read(model);
        Assert.NotNull(before);
        bytes[^1] = 1;
        var after = new RebuiltMethodTrial.Snapshot(state.Heap).Read(model);
        Assert.NotNull(after);
        Assert.NotEqual(before, after);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ModelArrayAliasesAreKeptAcrossApplicationAndVmRoots(bool integerArray)
    {
        var state = new StaticMachineState(new StaticMachineLimits());
        var heap = state.Heap;
        Assert.True(heap.TryAllocateObject("VM", out var vm));
        Assert.True(heap.TryAllocateObject("Application", out var app));
        object array = integerArray ? new int[] { 1, 2, 3 } : new byte[] { 1, 2, 3 };
        Assert.True(heap.TrySetModelValue(vm, "Data", array));
        Assert.True(heap.TrySetModelValue(app, "Data", array));
        var left = new RebuiltMethodTrial.Snapshot(heap);
        var right = new RebuiltMethodTrial.Snapshot(heap);
        Assert.NotNull(left.Read(vm));
        Assert.NotNull(right.Read(app));
        Assert.True(left.SharesCapturedObjectsWith(right));
        var aliased = new RebuiltMethodTrial.Snapshot(heap);
        Assert.NotNull(aliased.Read(vm));
        var shared = aliased.Read(app);
        Assert.True(heap.TrySetModelValue(app, "Data", ((Array)array).Clone()));
        var independent = new RebuiltMethodTrial.Snapshot(heap);
        Assert.NotNull(independent.Read(vm));
        Assert.NotEqual(shared, independent.Read(app));
        var isolated = new RebuiltMethodTrial.Snapshot(heap);
        Assert.NotNull(isolated.Read(app));
        Assert.False(left.SharesCapturedObjectsWith(isolated));
    }

    [Fact]
    public void ModelArrayElementTypesAndIntegerValuesAreCompared()
    {
        var state = new StaticMachineState(new StaticMachineLimits());
        Assert.True(state.Heap.TryAllocateObject("Model", out var model));
        var values = new[] { 1 };
        Assert.True(state.Heap.TrySetModelValue(model, "Data", values));
        var before = new RebuiltMethodTrial.Snapshot(state.Heap).Read(model);
        values[0] = 2;
        var after = new RebuiltMethodTrial.Snapshot(state.Heap).Read(model);
        Assert.NotEqual(before, after);
        Assert.True(state.Heap.TrySetModelValue(model, "Data", BitConverter.GetBytes(2)));
        Assert.NotEqual(after, new RebuiltMethodTrial.Snapshot(state.Heap).Read(model));
    }

    [Fact]
    public void ModelByteArraysRespectTheBinaryBudget()
    {
        var state = new StaticMachineState(new StaticMachineLimits());
        Assert.True(state.Heap.TryAllocateObject("Assembly", out var model));
        Assert.True(state.Heap.TrySetModelValue(model, "LoadedImage", new byte[RebuiltMethodTrial.Snapshot.MaximumBinaryBytes + 1]));
        var snapshot = new RebuiltMethodTrial.Snapshot(state.Heap);
        Assert.Null(snapshot.Read(model));
        Assert.Equal("binary byte budget exhausted", snapshot.Failure);
    }
}
