using System.Reflection;
using System.Runtime.CompilerServices;
using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using FieldAttributes = dnlib.DotNet.FieldAttributes;
using MethodAttributes = dnlib.DotNet.MethodAttributes;
using Fixture = Cilantro.Tests.BabelInheritedReceiverTests.Fixture;
using OpCodes = dnlib.DotNet.Emit.OpCodes;

namespace Cilantro.Tests;

public sealed class BabelApplicationStaticStateTests
{
    [Fact]
    public void EveryGenericConstructionKeepsStaticValuesAndAddressesOpaque()
    {
        using var f = new Fixture();
        var field = new FieldDefUser("State", new FieldSig(f.Module.CorLibTypes.Int32), FieldAttributes.Static | FieldAttributes.Public); f.Owner.Fields.Add(field);
        var aliases = new List<IField> { field };
        foreach (var argument in new TypeSig[] { f.Types.Variables[0], f.Module.CorLibTypes.Int32, f.Module.CorLibTypes.String })
            aliases.Add(new MemberRefUser(f.Module, field.Name, field.FieldSig, new TypeSpecUser(new GenericInstSig(new ClassSig(f.Owner), argument))));
        foreach (var alias in aliases)
        {
            Assert.True(f.Machine.State.IsPreservedStaticField(alias));
            Assert.Throws<InvalidOperationException>(() => f.Machine.State.ReadStaticField(alias));
            Assert.Throws<InvalidOperationException>(() => f.Machine.State.WriteStaticField(alias, StaticValue.FromInt32(7)));
            Assert.Throws<InvalidOperationException>(() => f.Machine.State.GetStaticFieldReference(alias));
        }
        Assert.Empty(f.Machine.State.StaticFields); Assert.True(f.Proof.Unchanged(f.Heap));
    }

    [Theory]
    [InlineData("read")]
    [InlineData("write")]
    [InlineData("address")]
    public void CilCannotObserveOrChangePreservedStaticState(string operation)
    {
        using var f = new Fixture();
        var field = new FieldDefUser("State", new FieldSig(f.Module.CorLibTypes.Int32), FieldAttributes.Static | FieldAttributes.Public); f.Owner.Fields.Add(field);
        var alias = new MemberRefUser(f.Module, field.Name, field.FieldSig, f.Types.Owner.ToTypeDefOrRef());
        var instructions = operation == "write"
            ? new[] { OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(alias), OpCodes.Ret.ToInstruction() }
            : new[] { (operation == "read" ? OpCodes.Ldsfld : OpCodes.Ldsflda).ToInstruction(alias), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction() };
        var result = f.Machine.Execute(f.Probe(f.Module.CorLibTypes.Void, instructions), [f.Receiver]);
        Assert.False(result.Succeeded); Assert.Contains("opaque", result.Diagnostic);
        Assert.Empty(f.Machine.State.StaticFields); Assert.True(f.Proof.Unchanged(f.Heap));
    }

    [Fact]
    public void ApplicationInitializerIsNeverRunDuringConstruction()
    {
        using var f = new Fixture();
        var observation = new FieldDefUser("Observed", new FieldSig(f.Module.CorLibTypes.Int32), FieldAttributes.Static | FieldAttributes.Public); f.Derived.Fields.Add(observation);
        var initializer = new MethodDefUser(".cctor", MethodSig.CreateStatic(f.Module.CorLibTypes.Void),
            MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() }; f.Owner.Methods.Add(initializer);
        initializer.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction()); initializer.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(observation)); initializer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        Assert.Equal(StaticExecutionStatus.Unknown, f.Machine.Execute(initializer).Status);
        Assert.Equal(StaticExecutionStatus.Unknown, f.Machine.Invoke(initializer).Status);
        var caller = f.Probe(f.Module.CorLibTypes.Void, OpCodes.Call.ToInstruction(initializer), OpCodes.Ret.ToInstruction());
        Assert.Equal(StaticExecutionStatus.Unknown, f.Machine.Execute(caller, [f.Receiver]).Status);
        Assert.Empty(f.Machine.State.StaticFields);
    }

    [Fact]
    public void StaticFieldMetadataCanBeEmittedButCannotBeReadOrUsedAsRuntimeStorage()
    {
        using var f = new Fixture();
        var field = new FieldDefUser("State", new FieldSig(f.Module.CorLibTypes.Int32), FieldAttributes.Static | FieldAttributes.Public); f.Owner.Fields.Add(field);
        Assert.True(f.Heap.TryAllocateMetadataHandle(field, out var handle)); Assert.True(f.Heap.TryAllocateMetadataHandle(f.Types.Owner, out var owner));
        var api = typeof(FieldInfo).GetMethod("GetFieldFromHandle", [typeof(RuntimeFieldHandle), typeof(RuntimeTypeHandle)])!;
        var reflected = f.Call(api, [handle, owner]); Assert.Equal(StaticExecutionStatus.Completed, reflected.Status);
        var type = f.Call(typeof(FieldInfo).GetProperty("FieldType")!.GetMethod!, [reflected.Value]); Assert.Equal(StaticExecutionStatus.Completed, type.Status);
        Assert.Equal(ElementType.I4, ReflectionEmitIntrinsic.Signatures(f.Heap, type.Value)!.ElementType);
        Assert.Equal(StaticExecutionStatus.Unknown, f.Call(typeof(FieldInfo).GetMethod("GetValue")!, [reflected.Value, StaticValue.Null]).Status);
        Assert.Equal(StaticExecutionStatus.Unknown, f.Call(typeof(FieldInfo).GetMethod("SetValue", [typeof(object), typeof(object)])!, [reflected.Value, StaticValue.Null, StaticValue.Null]).Status);
        Assert.Equal(StaticExecutionStatus.Unknown, f.Call(typeof(RuntimeFieldHandle).GetProperty("Value")!.GetMethod!, [handle]).Status);
        Assert.True(f.Heap.TryAllocateByteArray([1, 2, 3], out var destination));
        Assert.Equal(StaticExecutionStatus.Unknown, f.Call(typeof(RuntimeHelpers).GetMethod("InitializeArray")!, [destination, handle]).Status);
        Assert.Equal(new byte[] { 1, 2, 3 }, f.Heap.GetBytesSnapshot(destination)); Assert.Empty(f.Machine.State.StaticFields);
    }
}
