using System.Reflection;
using System.Reflection.Emit;
using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using MethodAttributes = dnlib.DotNet.MethodAttributes;
using OpCodes = dnlib.DotNet.Emit.OpCodes;

namespace Cilantro.Tests;

public sealed class RawLocalSignatureTests
{
    [Theory]
    [InlineData("null")]
    [InlineData("empty")]
    [InlineData("invalid")]
    public void NoArgumentDynamicInvocationIsCapturedWithoutExecutingTheBody(string arguments)
    {
        using var fixture = new Fixture(); var info = fixture.Info();
        Assert.Equal(StaticExecutionStatus.Completed, fixture.Set(info, fixture.Signature(fixture.Helper())).Status);
        Assert.True(fixture.Heap.TryAllocateByteArray([0x2a], out var code));
        Assert.Equal(StaticExecutionStatus.Completed, fixture.Call(typeof(DynamicILInfo).GetMethod("SetCode", [typeof(byte[]), typeof(int)])!, info, code, StaticValue.FromInt32(0)).Status);
        var capture = RawDynamicMethodIntrinsic.Read(fixture.Heap, info)!;
        Assert.True(fixture.Heap.TryAllocateType(typeof(Action).FullName!, out var delegateType));
        var created = fixture.Call(typeof(DynamicMethod).GetMethod("CreateDelegate", [typeof(Type)])!, capture.Reference, delegateType);
        Assert.Equal(StaticExecutionStatus.Completed, created.Status);
        var count = -1;
        fixture.Registry.Invoking = (_, supplied) => count = supplied.Count;
        var packed = StaticValue.Null;
        if (arguments == "empty") Assert.True(fixture.Heap.TryAllocateArray(null, 0, out packed));
        else if (arguments == "invalid") packed = StaticValue.FromInt32(1);
        var result = fixture.Call(typeof(Delegate).GetMethod("DynamicInvoke")!, created.Value, packed);
        Assert.Equal(arguments == "invalid" ? -1 : 0, count);
        Assert.NotEqual(StaticExecutionStatus.Completed, result.Status);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CertifiedGenericLocalsPreserveTypesAndPinningWithoutInventingBytes(bool pinned)
    {
        using var fixture = new Fixture();
        var helper = fixture.Helper();
        fixture.Add(helper, fixture.Model(fixture.Module.CorLibTypes.Int32));
        fixture.Add(helper, fixture.Scope.RuntimeType(fixture.Scope.Variables[0]), pinned);
        var array = new SZArraySig(fixture.Scope.Variables[0]);
        fixture.Add(helper, fixture.Scope.RuntimeType(array));
        var transport = fixture.Signature(helper);
        Assert.NotEqual(StaticExecutionStatus.Completed, fixture.Call(typeof(object).GetMethod("GetHashCode")!, transport).Status);
        Assert.NotEqual(StaticExecutionStatus.Completed, fixture.Call(typeof(object).GetMethod("GetType")!, transport).Status);
        Assert.NotEqual(StaticExecutionStatus.Completed, fixture.Call(typeof(object).GetMethod("ReferenceEquals")!, transport, transport).Status);
        Assert.Null(fixture.Heap.GetBytesSnapshot(transport));
        Assert.False(fixture.Heap.TryGetLength(transport, out _));
        Assert.False(fixture.Heap.TryReadArray(transport, 0, out _));
        Assert.False(fixture.Heap.TryWriteArray(transport, 0, StaticValue.FromInt32(0)));
        var info = fixture.Info();
        Assert.Equal(StaticExecutionStatus.Completed, fixture.Set(info, transport).Status);
        var locals = RawDynamicMethodIntrinsic.Read(fixture.Heap, info)!.Locals!;
        Assert.Equal(3, locals.Count);
        Assert.Equal(ElementType.I4, locals[0].ElementType);
        Assert.Equal(pinned, locals[1] is PinnedSig);
        Assert.Same(fixture.Scope.Variables[0], pinned ? locals[1].Next : locals[1]);
        Assert.Same(array, locals[2]);
        Assert.True(fixture.Heap.TryAllocateByteArray([0x2a], out var code));
        var assembled = fixture.Call(typeof(DynamicILInfo).GetMethod("SetCode", [typeof(byte[]), typeof(int)])!, info, code, StaticValue.FromInt32(0));
        Assert.Equal(StaticExecutionStatus.Completed, assembled.Status);
        Assert.Equal(3, RawDynamicMethodIntrinsic.Read(fixture.Heap, info)!.Assembled!.Body.Variables.Count);
    }

    [Fact]
    public void OpaqueSignatureCannotDecideLengthElementOrIdentityBranches()
    {
        using var fixture = new Fixture(); var helper = fixture.Helper();
        fixture.Add(helper, fixture.Scope.RuntimeType(fixture.Scope.Variables[0]));
        var transport = fixture.Signature(helper);
        foreach (var observation in new[] { "length", "element", "identity" })
        {
            var method = new MethodDefUser("Observe", MethodSig.CreateStatic(fixture.Module.CorLibTypes.Int32,
                new SZArraySig(fixture.Module.CorLibTypes.Byte)), MethodAttributes.Static) { Body = new CilBody() };
            fixture.Owner.Methods.Add(method);
            method.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            if (observation == "identity")
            {
                var target = OpCodes.Ldc_I4_1.ToInstruction();
                method.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction()); method.Body.Instructions.Add(OpCodes.Beq.ToInstruction(target));
                method.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction()); method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                method.Body.Instructions.Add(target);
            }
            else if (observation == "element") { method.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction()); method.Body.Instructions.Add(OpCodes.Ldelem_U1.ToInstruction()); }
            else { method.Body.Instructions.Add(OpCodes.Ldlen.ToInstruction()); method.Body.Instructions.Add(OpCodes.Conv_I4.ToInstruction()); }
            method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            Assert.False(fixture.Machine.Execute(method, [transport]).Succeeded);
        }
    }

    [Fact]
    public void EachOpaqueTransportIsFreshAndFreezesItsLocalList()
    {
        using var fixture = new Fixture(); var helper = fixture.Helper();
        var type = fixture.Scope.RuntimeType(fixture.Scope.Variables[0]); fixture.Add(helper, type);
        var first = fixture.Signature(helper); var second = fixture.Signature(helper);
        Assert.NotEqual(first, second);
        Assert.NotEqual(StaticExecutionStatus.Completed, fixture.Call(typeof(SignatureHelper).GetMethod("AddArgument", [typeof(Type)])!, helper, type).Status);
        Assert.Equal(StaticExecutionStatus.Completed, fixture.Set(fixture.Info(), first).Status);
        Assert.Equal(StaticExecutionStatus.Completed, fixture.Set(fixture.Info(), second).Status);
    }

    [Fact]
    public void OpenParametersAndUncertifiedCopiesCannotBecomeRuntimeLocalTypes()
    {
        using var fixture = new Fixture();
        foreach (var type in new[] { fixture.Model(new GenericVar(0, fixture.Owner)), fixture.Model(fixture.Scope.Variables[0]) })
            Assert.NotEqual(StaticExecutionStatus.Completed, fixture.Call(typeof(SignatureHelper).GetMethod("AddArgument", [typeof(Type)])!, fixture.Helper(), type).Status);
        fixture.Registry.OpaqueLocalInput = null;
        Assert.NotEqual(StaticExecutionStatus.Completed, fixture.Call(typeof(SignatureHelper).GetMethod("AddArgument", [typeof(Type)])!, fixture.Helper(), fixture.Scope.RuntimeType(fixture.Scope.Variables[0])).Status);
    }

    [Fact]
    public void ForgedAndCrossRegistryTransportsCannotSupplyLocals()
    {
        using var fixture = new Fixture(); var helper = fixture.Helper();
        fixture.Add(helper, fixture.Scope.RuntimeType(fixture.Scope.Variables[0]));
        var real = fixture.Signature(helper); var info = fixture.Info();
        Assert.True(fixture.Heap.TryAllocateObject("System.Byte[]", out var forged));
        Assert.NotEqual(StaticExecutionStatus.Completed, fixture.Set(info, forged).Status);
        var foreign = new RawDynamicMethodIntrinsic();
        Assert.NotEqual(StaticExecutionStatus.Completed, foreign.Invoke(new(fixture.Machine.State),
            new Importer(fixture.Module).Import(typeof(DynamicILInfo).GetMethod("SetLocalSignature", [typeof(byte[])])!), [info, real]).Status);
        Assert.Null(RawDynamicMethodIntrinsic.Read(fixture.Heap, info)!.Locals);
        Assert.Equal(StaticExecutionStatus.Completed, fixture.Set(info, real).Status);
        Assert.NotEqual(StaticExecutionStatus.Completed, fixture.Set(info, real).Status);
    }

    [Fact]
    public void PrimitiveSignaturesRemainInspectableAndRejectModifiedBytes()
    {
        using var fixture = new Fixture(); var helper = fixture.Helper();
        fixture.Add(helper, fixture.Model(fixture.Module.CorLibTypes.Int32));
        var transport = fixture.Signature(helper); var bytes = fixture.Heap.GetBytesSnapshot(transport);
        Assert.NotNull(bytes); Assert.NotEmpty(bytes);
        Assert.True(fixture.Heap.TryWriteArray(transport, 0, StaticValue.FromInt32(bytes[0] ^ 1)));
        var info = fixture.Info();
        Assert.NotEqual(StaticExecutionStatus.Completed, fixture.Set(info, transport).Status);
        Assert.Null(RawDynamicMethodIntrinsic.Read(fixture.Heap, info)!.Locals);
    }

    private sealed class Fixture : IDisposable
    {
        internal ModuleDefUser Module { get; } = new("LocalSignatures");
        internal TypeDefUser Owner { get; }
        internal RawDynamicMethodIntrinsic Registry { get; } = new();
        internal ParametricTypeIntrinsic Scope { get; }
        internal StaticMachine Machine { get; }
        internal StaticHeap Heap => Machine.State.Heap;
        internal Fixture()
        {
            Owner = new TypeDefUser("Probe", "Box`1", Module.CorLibTypes.Object.TypeDefOrRef); Module.Types.Add(Owner);
            Owner.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NotNullableValueTypeConstraint | GenericParamAttributes.DefaultConstructorConstraint, "T"));
            Scope = new(Owner, Registry); Machine = new(intrinsics: Scope); Scope.Attach(Machine); Machine.State.RegisterModuleMetadata(Module);
            Registry.OpaqueLocalInput = Scope.CertifiesRuntimeType;
        }
        internal StaticValue Model(TypeSig type)
        { Assert.True(Heap.TryAllocateObject("System.Type", out var value)); Heap.TrySetModelValue(value, "Metadata", type); return value; }
        internal IntrinsicResult Call(MethodBase method, params StaticValue[] arguments) => Scope.Invoke(new(Machine.State), new Importer(Module).Import(method), arguments);
        internal StaticValue Helper()
        { var result = Call(typeof(SignatureHelper).GetMethod("GetLocalVarSigHelper", Type.EmptyTypes)!); Assert.Equal(StaticExecutionStatus.Completed, result.Status); return result.Value; }
        internal void Add(StaticValue helper, StaticValue type, bool pinned = false)
        { Assert.Equal(StaticExecutionStatus.Completed, Call(typeof(SignatureHelper).GetMethod("AddArgument", [typeof(Type), typeof(bool)])!, helper, type, StaticValue.FromInt32(pinned ? 1 : 0)).Status); }
        internal StaticValue Signature(StaticValue helper)
        { var result = Call(typeof(SignatureHelper).GetMethod("GetSignature", Type.EmptyTypes)!, helper); Assert.Equal(StaticExecutionStatus.Completed, result.Status); return result.Value; }
        internal StaticValue Info()
        {
            Assert.True(Heap.TryAllocateObject("System.Reflection.Emit.DynamicMethod", out var method));
            Assert.True(Heap.TryAllocateString("Captured", out var name)); Assert.True(Heap.TryAllocateArray(null, 0, out var parameters));
            var constructor = typeof(DynamicMethod).GetConstructor([typeof(string), typeof(Type), typeof(Type[])])!;
            Assert.Equal(StaticExecutionStatus.Completed, Call(constructor, method, name, Model(Module.CorLibTypes.Void), parameters).Status);
            var result = Call(typeof(DynamicMethod).GetMethod("GetDynamicILInfo")!, method);
            Assert.Equal(StaticExecutionStatus.Completed, result.Status); return result.Value;
        }
        internal IntrinsicResult Set(StaticValue info, StaticValue transport) => Call(typeof(DynamicILInfo).GetMethod("SetLocalSignature", [typeof(byte[])])!, info, transport);
        public void Dispose() => Module.Dispose();
    }
}
