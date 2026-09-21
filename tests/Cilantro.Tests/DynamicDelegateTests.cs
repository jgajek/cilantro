using Cilantro.Core.Interpretation;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class DynamicDelegateTests
{
    [Theory]
    [InlineData("System.Reflection", "MethodInfo")]
    [InlineData("System.Reflection.Emit", "DynamicMethod")]
    public void DynamicDelegateBindingDispatchesThroughBaseMethod(string ns, string owner)
    {
        using var module = new ModuleDefUser("Fixture");
        var machine = new StaticMachine();
        machine.State.RegisterModuleMetadata(module);
        var heap = machine.State.Heap;
        var context = new IntrinsicContext(machine.State);
        var emit = new ReflectionEmitIntrinsic();
        Assert.True(heap.TryAllocateObject("System.Reflection.Emit.DynamicMethod", out var dynamicMethod));
        Assert.True(heap.TryAllocateString("Answer", out var name));
        Assert.True(heap.TryAllocateType("System.Int32", out var returns));
        Assert.True(heap.TrySetModelValue(returns, "Metadata", module.CorLibTypes.Int32));
        Assert.True(heap.TryAllocateArray(module.CorLibTypes.GetTypeRef("System", "Type").ToTypeSig(), 0, out var parameters));
        Assert.True(emit.Invoke(context, Member("System.Reflection.Emit", "DynamicMethod", ".ctor"),
            [dynamicMethod, name, returns, parameters]).Status == StaticExecutionStatus.Completed);
        var generator = emit.Invoke(context, Member("System.Reflection.Emit", "DynamicMethod", "GetILGenerator"),
            [dynamicMethod]).Value;
        foreach (var opcode in new[] { "Ldc_I4_1", "Ret" })
        {
            Assert.True(heap.TryAllocateObject("System.Reflection.Emit.OpCode", out var op));
            Assert.True(heap.TrySetModelValue(op, "OpCode", opcode));
            Assert.Equal(StaticExecutionStatus.Completed, emit.Invoke(context,
                Member("System.Reflection.Emit", "ILGenerator", "Emit"), [generator, op]).Status);
        }
        Assert.True(heap.TryAllocateType("System.Func`1<System.Int32>", out var delegateType));
        var binding = machine.Invoke(Member(ns, owner, "CreateDelegate"), [dynamicMethod, delegateType]);

        Assert.Equal(StaticExecutionStatus.Completed, binding.Status);
        Assert.True(heap.TryGetModelValue<IMethod>(binding.Value, StaticMachine.DelegateMethodKey, out var method));
        var result = machine.Execute(Assert.IsAssignableFrom<MethodDef>(method));
        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        var oracle = new System.Reflection.Emit.DynamicMethod("Answer", typeof(int), Type.EmptyTypes);
        var il = oracle.GetILGenerator();
        il.Emit(System.Reflection.Emit.OpCodes.Ldc_I4_1);
        il.Emit(System.Reflection.Emit.OpCodes.Ret);
        System.Reflection.MethodInfo asBase = oracle;
#pragma warning disable CA2263 // Exercise the exact non-generic API used by the protected fixture.
        Assert.Equal(((Func<int>)asBase.CreateDelegate(typeof(Func<int>)))(), result.Value.AsInt32());
#pragma warning restore CA2263

        MemberRef Member(string typeNamespace, string typeName, string methodName) => new MemberRefUser(module,
            methodName, MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.Object),
            module.CorLibTypes.GetTypeRef(typeNamespace, typeName));
    }

    [Fact]
    public void UndeclaredDynamicBodyIsNotInvented()
    {
        using var module = new ModuleDefUser("Fixture");
        var machine = new StaticMachine();
        Assert.True(machine.State.Heap.TryAllocateObject("System.Reflection.Emit.DynamicMethod", out var receiver));
        Assert.True(machine.State.Heap.TryAllocateType("System.Action", out var delegateType));
        var method = new MemberRefUser(module, "CreateDelegate",
            MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.Object),
            module.CorLibTypes.GetTypeRef("System.Reflection", "MethodInfo"));

        var result = machine.Invoke(method, [receiver, delegateType]);

        Assert.NotEqual(StaticExecutionStatus.Completed, result.Status);
    }
}
