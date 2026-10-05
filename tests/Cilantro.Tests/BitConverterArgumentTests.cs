using Cilantro.Core.Interpretation;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class BitConverterArgumentTests
{
    [Theory]
    [InlineData(-1, 0)]
    [InlineData(0, 0)]
    [InlineData(4, -1)]
    [InlineData(4, 4)]
    [InlineData(4, 1)]
    [InlineData(1, 0)]
    public void InvalidByteRangesProduceTheFrameworkArgumentException(int length, int offset)
    {
        byte[]? bytes = length < 0 ? null : new byte[length];
        var actual = Assert.ThrowsAny<ArgumentException>(() => BitConverter.ToInt32(bytes!, offset));
        using var module = new ModuleDefUser("converter");
        var call = new MemberRefUser(module, "ToInt32",
            MethodSig.CreateStatic(module.CorLibTypes.Int32, new SZArraySig(module.CorLibTypes.Byte), module.CorLibTypes.Int32),
            module.CorLibTypes.GetTypeRef("System", "BitConverter"));
        var machine = new StaticMachine();
        var input = StaticValue.Null;
        if (bytes is not null) Assert.True(machine.State.Heap.TryAllocateByteArray(bytes, out input));
        var result = new BitConverterIntrinsic().Invoke(new IntrinsicContext(machine.State), call, [input, StaticValue.FromInt32(offset)]);
        Assert.Equal(StaticExecutionStatus.Threw, result.Status);
        Assert.True(machine.State.Heap.TryGetRuntimeTypeName(result.Value, out var type));
        Assert.Equal(actual.GetType().FullName, type);
        Assert.True(machine.State.Heap.TryGetModelValue<string>(result.Value, "ParamName", out var parameter));
        Assert.Equal(actual.ParamName, parameter);
    }
}
