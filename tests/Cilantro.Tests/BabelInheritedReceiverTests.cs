using System.Reflection;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using FieldAttributes = dnlib.DotNet.FieldAttributes;
using MethodAttributes = dnlib.DotNet.MethodAttributes;
using OpCode = dnlib.DotNet.Emit.OpCode;
using OpCodes = dnlib.DotNet.Emit.OpCodes;

namespace Cilantro.Tests;

public sealed class BabelInheritedReceiverTests
{
    [Fact]
    public void SubtypeHandlesOnlyNormalizeTheCertifiedDeclaringMethod()
    {
        using var f = new Fixture();
        var type = f.Call(typeof(object).GetMethod("GetType")!, [f.Receiver], true);
        Assert.Equal(StaticExecutionStatus.Completed, type.Status);
        Assert.NotEqual(StaticExecutionStatus.Completed, f.Call(typeof(object).GetMethod("GetType")!, [f.Receiver]).Status);
        foreach (var query in new[] { "Name", "BaseType", "IsSealed", "FullName" })
            Assert.NotEqual(StaticExecutionStatus.Completed, f.Call(typeof(Type).GetProperty(query)!.GetMethod!, [type.Value], true).Status);
        var api = typeof(Type).GetProperty("TypeHandle")!.GetMethod!;
        Assert.NotEqual(StaticExecutionStatus.Completed, f.Call(api, [type.Value]).Status);
        var handle = f.Call(api, [type.Value], true); Assert.Equal(StaticExecutionStatus.Completed, handle.Status);
        Assert.True(f.Heap.TryAllocateMetadataHandle(f.Stub, out var method));
        var bind = typeof(MethodBase).GetMethod("GetMethodFromHandle", [typeof(RuntimeMethodHandle), typeof(RuntimeTypeHandle)])!;
        Assert.NotEqual(StaticExecutionStatus.Completed, f.Call(bind, [method, handle.Value]).Status);
        Assert.True(f.Heap.TryAllocateMetadataHandle(f.Owner.FindInstanceConstructors().FirstOrDefault() ?? f.Other, out var wrong));
        Assert.NotEqual(StaticExecutionStatus.Completed, f.Call(bind, [wrong, handle.Value], true).Status);
        var result = f.Call(bind, [method, handle.Value], true); Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.True(f.Heap.TryGetModelValue<IMethod>(result.Value, "Metadata", out var bound));
        var owner = Assert.IsType<GenericInstSig>(Assert.IsType<TypeSpecUser>(bound!.DeclaringType).TypeSig);
        Assert.Same(f.Types.Variables[0], Assert.Single(owner.GenericArguments));
        Assert.True(f.Proof.Unchanged(f.Heap));
    }

    [Fact]
    public void MissingSubclassStorageAndExactRuntimeTypesAreNeverInvented()
    {
        using var f = new Fixture();
        Assert.False(f.Heap.TryGetRuntimeTypeName(f.Receiver, out _)); Assert.False(f.Heap.TryGetObjectType(f.Receiver, out _));
        Assert.True(f.Heap.TryReadField(f.Receiver, f.Field, out var original)); Assert.False(original.IsKnown);
        Assert.True(f.Heap.TryGetFieldReference(f.Receiver, f.Field, out _));
        var extra = new FieldDefUser("extra", new FieldSig(f.Module.CorLibTypes.Int32), FieldAttributes.Public); f.Derived.Fields.Add(extra);
        Assert.False(f.Heap.TryReadField(f.Receiver, extra, out _));
        Assert.False(f.Heap.TryGetFieldReference(f.Receiver, extra, out _));
        Assert.True(f.Proof.Unchanged(f.Heap));
        Assert.True(f.Heap.TryWriteField(f.Receiver, extra, StaticValue.FromInt32(7)));
        Assert.False(f.Proof.Unchanged(f.Heap));
    }

    [Theory]
    [InlineData("cast")]
    [InlineData("isinst")]
    [InlineData("unbox")]
    public void OnlyTheKnownBaseOrObjectCanBeProvedInTypeTests(string operation)
    {
        using var f = new Fixture();
        var opcode = operation == "cast" ? OpCodes.Castclass : operation == "isinst" ? OpCodes.Isinst : OpCodes.Unbox_Any;
        foreach (var type in new ITypeDefOrRef[] { f.Types.Owner.ToTypeDefOrRef(), f.Module.CorLibTypes.Object.TypeDefOrRef, f.Derived })
        {
            var probe = f.Probe(f.Module.CorLibTypes.Object, OpCodes.Ldarg_0.ToInstruction(), opcode.ToInstruction(type), OpCodes.Ret.ToInstruction());
            var result = f.Machine.Execute(probe, [f.Receiver]);
            Assert.Equal(type != f.Derived, result.Succeeded);
            if (result.Succeeded) Assert.Equal(f.Receiver, result.Value);
        }
    }

    [Theory]
    [InlineData("callvirt")]
    [InlineData("reflection")]
    [InlineData("pointer")]
    [InlineData("callback")]
    public void DispatchNeverSelectsAnOverrideForAnUnknownSubtype(string entry)
    {
        using var f = new Fixture();
        var target = new MethodDefUser("Virtual", MethodSig.CreateInstance(f.Module.CorLibTypes.Int32), MethodAttributes.Public | MethodAttributes.Virtual)
        { Body = new CilBody() }; f.Owner.Methods.Add(target);
        target.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction()); target.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        var bound = new MemberRefUser(f.Module, target.Name, target.MethodSig, f.Types.Owner.ToTypeDefOrRef());
        if (entry == "reflection") Assert.Equal(StaticExecutionStatus.Unknown, f.Machine.Invoke(bound, [f.Receiver]).Status);
        else if (entry == "callback")
        {
            Assert.True(f.Heap.TryAllocateObject("System.Func`1<System.Int32>", out var callback));
            f.Heap.TrySetModelValue(callback, StaticMachine.DelegateMethodKey, (IMethod)bound);
            f.Heap.TrySetModelValue(callback, StaticMachine.DelegateTargetKey, f.Receiver);
            Assert.Equal(StaticExecutionStatus.Unknown, f.Machine.InvokeCallback(callback, [], new StaticWorkBudget(1000)).Status);
        }
        else
        {
            var opcode = entry == "pointer" ? OpCodes.Ldvirtftn : OpCodes.Callvirt;
            var probe = f.Probe(entry == "pointer" ? f.Module.CorLibTypes.IntPtr : f.Module.CorLibTypes.Int32,
                OpCodes.Ldarg_0.ToInstruction(), opcode.ToInstruction(bound), OpCodes.Ret.ToInstruction());
            Assert.Equal(StaticExecutionStatus.Unknown, f.Machine.Execute(probe, [f.Receiver]).Status);
        }
    }

    internal sealed class Fixture : IDisposable
    {
        internal ModuleDefUser Module { get; } = new("Subtype");
        internal TypeDefUser Owner { get; }
        internal TypeDefUser Derived { get; }
        internal FieldDefUser Field { get; }
        internal MethodDefUser Stub { get; }
        internal MethodDefUser Other { get; }
        internal ParametricTypeIntrinsic Types { get; }
        internal StaticMachine Machine { get; }
        internal StaticHeap Heap => Machine.State.Heap;
        internal StaticValue Receiver { get; }
        internal BabelGenericStub Proof { get; }
        internal Fixture()
        {
            Owner = new TypeDefUser("Probe", "Base`1", Module.CorLibTypes.Object.TypeDefOrRef); Module.Types.Add(Owner);
            Owner.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            Derived = new TypeDefUser("Probe", "Child", new TypeSpecUser(new GenericInstSig(new ClassSig(Owner), Module.CorLibTypes.Int32))); Module.Types.Add(Derived);
            var formal = new GenericVar(0, Owner);
            Field = new FieldDefUser("value", new FieldSig(formal), FieldAttributes.Public); Owner.Fields.Add(Field);
            Stub = new MethodDefUser("Exchange", MethodSig.CreateInstance(formal, formal), MethodAttributes.Public) { Body = new CilBody { InitLocals = true } }; Owner.Methods.Add(Stub);
            Other = new MethodDefUser("Other", MethodSig.CreateStatic(Module.CorLibTypes.Void), MethodAttributes.Static | MethodAttributes.Public) { Body = new CilBody() };
            Owner.Methods.Add(Other); Other.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var objects = new SZArraySig(Module.CorLibTypes.Object); Stub.Body.Variables.Add(new Local(objects));
            var dispatch = new MethodDefUser("Dispatch", MethodSig.CreateStatic(Module.CorLibTypes.Object, Module.CorLibTypes.Int32,
                new Importer(Module).ImportAsTypeSig(typeof(MethodBase)), Module.CorLibTypes.Object, objects), MethodAttributes.Static);
            Owner.Methods.Add(dispatch);
            void Add(OpCode op, object? operand = null) => Stub.Body.Instructions.Add(new Instruction(op, operand));
            IMethod Api(MethodBase method) => new Importer(Module).Import(method);
            Add(OpCodes.Ldc_I4_1); Add(OpCodes.Newarr, Module.CorLibTypes.Object.TypeDefOrRef); Add(OpCodes.Dup); Add(OpCodes.Ldc_I4_0);
            Add(OpCodes.Ldarg_1); Add(OpCodes.Box, formal.ToTypeDefOrRef()); Add(OpCodes.Stelem_Ref); Add(OpCodes.Stloc_0); Add(OpCodes.Ldc_I4_1);
            Add(OpCodes.Call, Api(typeof(MethodBase).GetMethod("GetCurrentMethod")!)); Add(OpCodes.Callvirt, Api(typeof(MethodBase).GetProperty("MethodHandle")!.GetMethod!));
            Add(OpCodes.Ldarg_0); Add(OpCodes.Call, Api(typeof(object).GetMethod("GetType")!)); Add(OpCodes.Callvirt, Api(typeof(Type).GetProperty("TypeHandle")!.GetMethod!));
            Add(OpCodes.Call, Api(typeof(MethodBase).GetMethod("GetMethodFromHandle", [typeof(RuntimeMethodHandle), typeof(RuntimeTypeHandle)])!));
            Add(OpCodes.Ldarg_0); Add(OpCodes.Ldloc_0); Add(OpCodes.Call, dispatch); Add(OpCodes.Unbox_Any, formal.ToTypeDefOrRef()); Add(OpCodes.Ret);
            Proof = Assert.IsType<BabelGenericStub>(BabelGenericStub.Match(Stub, method => method == dispatch));
            Types = new(Owner, new RawDynamicMethodIntrinsic()); Machine = new(intrinsics: Types); Types.Attach(Machine); Machine.State.RegisterModuleMetadata(Module);
            Receiver = Proof.Prepare(Machine, Types);
        }
        internal IntrinsicResult Call(MethodBase method, StaticValue[] arguments, bool certified = false) =>
            Types.Invoke(new(Machine.State, Frames: certified ? [Stub] : [Other]), new Importer(Module).Import(method), arguments);
        internal MethodDefUser Probe(TypeSig returns, params Instruction[] instructions)
        {
            var method = new MethodDefUser("Probe" + Module.GlobalType.Methods.Count, MethodSig.CreateStatic(returns, Module.CorLibTypes.Object), MethodAttributes.Static | MethodAttributes.Public)
            { Body = new CilBody() }; Module.GlobalType.Methods.Add(method); foreach (var instruction in instructions) method.Body.Instructions.Add(instruction); return method;
        }
        public void Dispose() => Module.Dispose();
    }
}
