using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ReferenceBoxingTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void BoxingReferencePreservesIdentityAndNull(bool array, bool isNull)
    {
        using var module = new ModuleDefUser("boxing");
        TypeSig type = array ? new SZArraySig(module.CorLibTypes.Int32) : module.CorLibTypes.Object;
        var machine = new StaticMachine();
        var value = StaticValue.Null;
        if (!isNull)
        {
            if (array) Assert.True(machine.State.Heap.TryAllocateArray(module.CorLibTypes.Int32, 3, out value));
            else Assert.True(machine.State.Heap.TryAllocateObject("System.Object", out value));
        }
        var method = BoxMethod(module, type);
        var allocated = machine.State.Heap.AllocatedBytes;
        var result = machine.Execute(method, [value]);
        Assert.True(result.Status == StaticExecutionStatus.Completed, result.Diagnostic);
        Assert.Equal(value, result.Value);
        Assert.Equal(allocated, machine.State.Heap.AllocatedBytes);

        // Execute only this benign synthetic IL in the CLR as an independent oracle.
        var runtimeType = array ? typeof(int[]) : typeof(object);
        var oracle = new System.Reflection.Emit.DynamicMethod("BoxReference", typeof(object), [runtimeType]);
        var il = oracle.GetILGenerator();
        il.Emit(System.Reflection.Emit.OpCodes.Ldarg_0);
        il.Emit(System.Reflection.Emit.OpCodes.Box, runtimeType);
        il.Emit(System.Reflection.Emit.OpCodes.Ret);
        object? argument = isNull ? null : array ? new int[3] : new object();
        Assert.Same(argument, oracle.Invoke(null, [argument]));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void GenericBoxUsesInstantiatedType(bool array)
    {
        using var module = new ModuleDefUser("generic-box");
        var method = BoxMethod(module, new GenericMVar(0));
        method.MethodSig = MethodSig.CreateStaticGeneric(1, module.CorLibTypes.Object, new GenericMVar(0));
        method.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
        var machine = new StaticMachine();
        TypeSig type = array ? new SZArraySig(module.CorLibTypes.Int32) : module.CorLibTypes.Int32;
        var value = StaticValue.FromInt32(42);
        if (array) Assert.True(machine.State.Heap.TryAllocateArray(module.CorLibTypes.Int32, 3, out value));
        var caller = BoxMethod(module, type);
        caller.Body.Instructions[1] = OpCodes.Call.ToInstruction(new MethodSpecUser(method, new GenericInstMethodSig(type)));
        var result = machine.Execute(caller, [value]);
        Assert.True(result.Status == StaticExecutionStatus.Completed, result.Diagnostic);
        if (array) Assert.Equal(value, result.Value);
        else
        {
            Assert.True(machine.State.Heap.TryUnbox(result.Value, out var content));
            Assert.Equal(value, content);
            Assert.True(machine.State.Heap.TryGetRuntimeTypeName(result.Value, out var name));
            Assert.Equal("System.Int32", name);
        }
    }

    [Fact]
    public void ObjectLengthIsNotMistakenForEmptyArray()
    {
        using var module = new ModuleDefUser("length");
        var machine = new StaticMachine();
        Assert.True(machine.State.Heap.TryAllocateObject("System.Object", out var value));
        Assert.False(machine.State.Heap.TryGetLength(value, out _));
        var method = BoxMethod(module, module.CorLibTypes.Object);
        method.MethodSig.RetType = module.CorLibTypes.Int32;
        method.Body.Instructions.Clear();
        foreach (var instruction in new[] { OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldlen.ToInstruction(),
                     OpCodes.Conv_I4.ToInstruction(), OpCodes.Ret.ToInstruction() })
            method.Body.Instructions.Add(instruction);
        Assert.Equal(StaticExecutionStatus.InvalidProgram, machine.Execute(method, [value]).Status);
        Assert.True(machine.State.Heap.TryAllocateArray(module.CorLibTypes.Int32, 0, out var empty));
        Assert.True(machine.State.Heap.TryGetLength(empty, out var length));
        Assert.Equal(0, length);
    }

    [Theory]
    [InlineData("ModuleHandle")]
    [InlineData("DateTime")]
    [InlineData("Guid")]
    public void FrameworkValueTypeReferencesStillAllocateBoxes(string name)
    {
        using var module = new ModuleDefUser("framework-box");
        // A raw unresolved TypeRef, just as it appears as the operand of box.
        var reference = module.CorLibTypes.GetTypeRef("System", name);
        var machine = new StaticMachine();
        Assert.True(machine.State.Heap.TryAllocateObject(reference.FullName, out var value));
        var method = BoxMethod(module, reference.ToTypeSig());
        method.Body.Instructions[1] = OpCodes.Box.ToInstruction(reference);
        var result = machine.Execute(method, [value]);
        Assert.True(result.Status == StaticExecutionStatus.Completed, result.Diagnostic);
        Assert.NotEqual(value, result.Value);
        Assert.True(machine.State.Heap.TryUnbox(result.Value, out var contents));
        Assert.Equal(value, contents);
        Assert.True(machine.State.Heap.TryGetRuntimeTypeName(result.Value, out var type));
        Assert.Equal(reference.FullName, type);
    }

    [Fact]
    public void UnresolvedExternalTypeDoesNotInventReferenceSemantics()
    {
        using var module = new ModuleDefUser("unknown-box");
        var reference = new TypeRefUser(module, "Unavailable", "MaybeStruct");
        var machine = new StaticMachine();
        Assert.True(machine.State.Heap.TryAllocateObject(reference.FullName, out var value));
        var result = machine.Execute(BoxMethod(module, reference.ToTypeSig()), [value]);
        Assert.Equal(StaticExecutionStatus.Unknown, result.Status);
    }

    private static MethodDefUser BoxMethod(ModuleDef module, TypeSig type)
    {
        var method = new MethodDefUser("Box", MethodSig.CreateStatic(module.CorLibTypes.Object, type))
        { Attributes = MethodAttributes.Static, Body = new CilBody() };
        module.GlobalType.Methods.Add(method);
        foreach (var instruction in new[] { OpCodes.Ldarg_0.ToInstruction(),
                     OpCodes.Box.ToInstruction(type.ToTypeDefOrRef()), OpCodes.Ret.ToInstruction() })
            method.Body.Instructions.Add(instruction);
        return method;
    }
}
