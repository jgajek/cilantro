using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ReferenceUnboxingTests
{
    [Fact]
    public void ReferenceCastDoesNotInventAReconstructionDisagreement()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Host");
            var field = new FieldDefUser("Saved", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Static);
            owner.Fields.Add(field);
            var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Object))
            { Attributes = MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(method);
            foreach (var instruction in new[] { OpCodes.Ldc_I4.ToInstruction(42),
                         OpCodes.Box.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef),
                         OpCodes.Dup.ToInstruction(), OpCodes.Stsfld.ToInstruction(field),
                         OpCodes.Unbox_Any.ToInstruction(module.CorLibTypes.Object.TypeDefOrRef),
                         OpCodes.Ret.ToInstruction() }) method.Body.Instructions.Add(instruction);
        });
        var method = context.Module.GetTypes().SelectMany(type => type.Methods).Single(method => method.Name == "Run");
        var rebuilt = new CilBody();
        foreach (var instruction in method.Body.Instructions)
            rebuilt.Instructions.Add(instruction.OpCode.Code == Code.Unbox_Any
                ? OpCodes.Nop.ToInstruction() : new Instruction(instruction.OpCode, instruction.Operand));
        var result = RebuiltMethodTrial.Compare(context, method, rebuilt, 0);
        Assert.Equal(DevirtualizationCheck.Agreed, result.Verdict);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void ObjectTargetPreservesBoxIdentityAndNull(bool generic, bool isNull)
    {
        using var module = new ModuleDefUser("unbox-reference");
        var machine = new StaticMachine();
        var value = StaticValue.Null;
        if (!isNull) Assert.True(machine.State.Heap.TryAllocateBox("System.Int32", StaticValue.FromInt32(42), out value));
        var result = machine.Execute(Method(module, module.CorLibTypes.Object, generic), [value]);
        Assert.True(result.Status == StaticExecutionStatus.Completed, result.Diagnostic);
        Assert.Equal(value, result.Value);
        object? oracleValue = isNull ? null : 42;
        Assert.Same(oracleValue, Oracle(typeof(object)).Invoke(null, [oracleValue]));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ArrayTargetPreservesArrayOfValues(bool generic)
    {
        using var module = new ModuleDefUser("unbox-array");
        var machine = new StaticMachine();
        Assert.True(machine.State.Heap.TryAllocateArray(module.CorLibTypes.Int32, 3, out var array));
        Assert.True(machine.State.Heap.TryWriteArray(array, 1, StaticValue.FromInt32(42)));
        var result = machine.Execute(Method(module, new SZArraySig(module.CorLibTypes.Int32), generic), [array]);
        Assert.True(result.Status == StaticExecutionStatus.Completed, result.Diagnostic);
        Assert.Equal(array, result.Value);
        int[] oracle = [1, 42, 3];
        Assert.Same(oracle, Oracle(typeof(int[])).Invoke(null, [oracle]));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void IncompatibleReferenceTargetDoesNotUnwrapAValue(bool generic)
    {
        using var module = new ModuleDefUser("unbox-invalid-cast");
        var machine = new StaticMachine();
        Assert.True(machine.State.Heap.TryAllocateBox("System.Int32", StaticValue.FromInt32(42), out var value));
        var result = machine.Execute(Method(module, module.CorLibTypes.String, generic), [value]);
        Assert.Equal(StaticExecutionStatus.InvalidProgram, result.Status);
        Assert.Contains("cannot be cast", result.Diagnostic);
        var failure = Assert.Throws<System.Reflection.TargetInvocationException>(() => Oracle(typeof(string)).Invoke(null, [42]));
        Assert.IsType<InvalidCastException>(failure.InnerException);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ValueTargetStillUnboxes(bool generic)
    {
        using var module = new ModuleDefUser("unbox-value");
        var machine = new StaticMachine();
        Assert.True(machine.State.Heap.TryAllocateBox("System.Int32", StaticValue.FromInt32(42), out var value));
        var result = machine.Execute(Method(module, module.CorLibTypes.Int32, generic), [value]);
        Assert.True(result.Status == StaticExecutionStatus.Completed, result.Diagnostic);
        Assert.Equal(StaticValue.FromInt32(42), result.Value);
        Assert.Equal(42, Oracle(typeof(int)).Invoke(null, [42]));
    }

    private static MethodDefUser Method(ModuleDef module, TypeSig target, bool generic)
    {
        var method = new MethodDefUser("Read", generic
            ? MethodSig.CreateStaticGeneric(1, new GenericMVar(0), module.CorLibTypes.Object)
            : MethodSig.CreateStatic(target, module.CorLibTypes.Object))
        { Attributes = MethodAttributes.Static, Body = new CilBody() };
        module.GlobalType.Methods.Add(method);
        if (generic) method.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
        method.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
        method.Body.Instructions.Add(OpCodes.Unbox_Any.ToInstruction((generic ? new GenericMVar(0) : target).ToTypeDefOrRef()));
        method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        if (!generic) return method;
        var caller = new MethodDefUser("Call", MethodSig.CreateStatic(target, module.CorLibTypes.Object))
        { Attributes = MethodAttributes.Static, Body = new CilBody() };
        module.GlobalType.Methods.Add(caller);
        caller.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
        caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MethodSpecUser(method, new GenericInstMethodSig(target))));
        caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        return caller;
    }

    // Only these small synthetic instructions are executed by the host CLR.
    private static System.Reflection.Emit.DynamicMethod Oracle(Type target)
    {
        var method = new System.Reflection.Emit.DynamicMethod("UnboxReference", target, [typeof(object)]);
        var il = method.GetILGenerator();
        il.Emit(System.Reflection.Emit.OpCodes.Ldarg_0);
        il.Emit(System.Reflection.Emit.OpCodes.Unbox_Any, target);
        il.Emit(System.Reflection.Emit.OpCodes.Ret);
        return method;
    }
}
