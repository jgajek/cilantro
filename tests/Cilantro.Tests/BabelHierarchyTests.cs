using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Fixture = Cilantro.Tests.BabelInheritedReceiverTests.Fixture;

namespace Cilantro.Tests;

public sealed class BabelHierarchyTests
{
    [Fact]
    public void ReorderedBaseArgumentsAndEveryInheritedFieldRemainOpaque()
    {
        using var f = new Fixture();
        var storage = Parent(f.Module, "Storage`1", 1, f.Module.CorLibTypes.Object.TypeDefOrRef);
        var inherited = new FieldDefUser("value", new FieldSig(new GenericVar(0, storage)), FieldAttributes.Public); storage.Fields.Add(inherited);
        var count = new FieldDefUser("Count", new FieldSig(f.Module.CorLibTypes.Int32), FieldAttributes.Public | FieldAttributes.Static); storage.Fields.Add(count);
        var middle = Parent(f.Module, "Middle`2", 2, new TypeSpecUser(new GenericInstSig(new ClassSig(storage), new GenericVar(1))));
        middle.Fields.Add(new FieldDefUser("value", new FieldSig(f.Module.CorLibTypes.Int64), FieldAttributes.Public));
        f.Owner.GenericParameters.Add(new GenericParamUser(1, GenericParamAttributes.NonVariant, "Other"));
        f.Owner.BaseType = new TypeSpecUser(new GenericInstSig(new ClassSig(middle), new GenericVar(1, f.Owner), new GenericVar(0, f.Owner)));
        var proof = Assert.IsType<BabelGenericStub>(BabelGenericStub.Match(f.Stub, method => method.Name == "Dispatch"));
        var types = new ParametricTypeIntrinsic(f.Owner, new RawDynamicMethodIntrinsic());
        var machine = new StaticMachine(intrinsics: types); types.Attach(machine); machine.State.RegisterModuleMetadata(f.Module);
        var receiver = proof.Prepare(machine, types);
        Assert.True(GenericOwnerHierarchy.TryRead(types.Owner, out var chain));
        Assert.Equal(3, chain.Count);
        Assert.Same(types.Variables[0], Assert.Single(Assert.IsType<GenericInstSig>(chain[2].Type).GenericArguments));
        Assert.Same(types.Variables[1], Assert.IsType<GenericInstSig>(chain[1].Type).GenericArguments[0]);
        foreach (var field in chain.SelectMany(layer => layer.Definition.Fields).Where(field => !field.IsStatic))
        {
            Assert.True(machine.State.Heap.TryReadField(receiver, field, out var value)); Assert.False(value.IsKnown);
        }
        Assert.Throws<InvalidOperationException>(() => machine.State.ReadStaticField(count));
        var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(f.Module.CorLibTypes.Void), MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() };
        storage.Methods.Add(cctor); cctor.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        Assert.Equal(StaticExecutionStatus.Unknown, machine.Execute(cctor).Status);
        Assert.True(proof.Unchanged(machine.State.Heap));
        var alias = new MemberRefUser(f.Module, inherited.Name, inherited.FieldSig, chain[2].Type.ToTypeDefOrRef());
        Assert.True(machine.State.Heap.TryWriteField(receiver, alias, StaticValue.FromInt32(17)));
        Assert.False(proof.Unchanged(machine.State.Heap));
    }

    [Theory]
    [InlineData("cycle")]
    [InlineData("same-assembly-alias")]
    [InlineData("variable")]
    [InlineData("pointer")]
    [InlineData("depth")]
    public void UnreviewedHierarchyShapesDecline(string shape)
    {
        using var f = new Fixture();
        if (shape == "same-assembly-alias") new AssemblyDefUser("LocalOwner").Modules.Add(f.Module);
        var parent = Parent(f.Module, "Parent`1", 1, f.Module.CorLibTypes.Object.TypeDefOrRef);
        TypeSig argument = new GenericVar(shape == "variable" ? 99U : 0U, f.Owner);
        if (shape == "pointer") argument = new PtrSig(argument);
        if (shape == "depth") for (var index = 0; index < 40; index++) argument = new SZArraySig(argument);
        var target = shape == "same-assembly-alias" ? (ITypeDefOrRef)new TypeRefUser(f.Module, "Foreign", "Parent`1", new AssemblyRefUser(f.Module.Assembly)) : shape == "cycle" ? f.Owner : parent;
        f.Owner.BaseType = new TypeSpecUser(new GenericInstSig(new ClassSig(target), argument));
        Assert.False(GenericOwnerHierarchy.TryRead(f.Types.Owner, out _));
        Assert.Null(BabelGenericStub.Match(f.Stub, method => method.Name == "Dispatch"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ExternalBaseStateRemainsOpaqueEvenForExactSealedReceivers(bool sealedOwner)
    {
        using var f = new Fixture();
        f.Owner.IsSealed = sealedOwner;
        var external = new TypeRefUser(f.Module, "Foreign", "Parent`1", new AssemblyRefUser("Foreign"));
        f.Owner.BaseType = new TypeSpecUser(new GenericInstSig(new ClassSig(external), new GenericVar(0, f.Owner)));
        var types = new ParametricTypeIntrinsic(f.Owner, new RawDynamicMethodIntrinsic());
        Assert.True(GenericOwnerHierarchy.TryRead(types.Owner, out var chain, out var boundary));
        Assert.Single(chain);
        Assert.Same(types.Variables[0], Assert.Single(Assert.IsType<GenericInstSig>(boundary).GenericArguments));
        var machine = new StaticMachine(intrinsics: types); types.Attach(machine); machine.State.RegisterModuleMetadata(f.Module);
        var proof = Assert.IsType<BabelGenericStub>(BabelGenericStub.Match(f.Stub, method => method.Name == "Dispatch"));
        var receiver = proof.Prepare(machine, types);
        Assert.Equal(!sealedOwner, machine.State.Heap.HasUnknownRuntimeType(receiver));
        var field = new MemberRefUser(f.Module, "unknown", new FieldSig(f.Module.CorLibTypes.Int32), external);
        Assert.False(machine.State.Heap.TryReadField(receiver, field, out _));
        Assert.False(machine.State.Heap.TryGetFieldReference(receiver, field, out _));
        Assert.Throws<InvalidOperationException>(() => machine.State.ReadStaticField(field));
        Assert.Throws<InvalidOperationException>(() => machine.State.WriteStaticField(field, StaticValue.FromInt32(17)));
        Assert.Throws<InvalidOperationException>(() => machine.State.GetStaticFieldReference(field));
        var inherited = new MemberRefUser(f.Module, "inherited", new FieldSig(f.Module.CorLibTypes.Int32),
            new TypeRefUser(f.Module, "Foreign", "Ancestor", new AssemblyRefUser("Foreign")));
        Assert.Throws<InvalidOperationException>(() => machine.State.ReadStaticField(inherited));
        using var foreign = new ModuleDefUser("Foreign");
        new AssemblyDefUser("Foreign").Modules.Add(foreign);
        var ancestor = Parent(foreign, "Ancestor", 0, foreign.CorLibTypes.Object.TypeDefOrRef);
        var initializer = new MethodDefUser(".cctor", MethodSig.CreateStatic(foreign.CorLibTypes.Void),
            MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() };
        ancestor.Methods.Add(initializer); initializer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        Assert.Equal(StaticExecutionStatus.Unknown, machine.Execute(initializer).Status);
        Assert.True(proof.Unchanged(machine.State.Heap));
        Assert.True(machine.State.Heap.TryWriteField(receiver, field, StaticValue.FromInt32(17)));
        Assert.False(proof.Unchanged(machine.State.Heap));
    }

    [Theory]
    [InlineData("value-base")]
    [InlineData("pointer")]
    [InlineData("variable")]
    [InlineData("generic-overflow")]
    [InlineData("module-scope")]
    public void ExternalBoundaryStillRequiresABoundedNominalClassExpression(string shape)
    {
        using var f = new Fixture();
        var reference = new TypeRefUser(f.Module, "Foreign", "Base`1", shape == "module-scope" ?
            new ModuleRefUser(f.Module, "Missing") : new AssemblyRefUser("Foreign"));
        ClassOrValueTypeSig nominal = shape == "value-base" ? new ValueTypeSig(reference) : new ClassSig(reference);
        TypeSig argument = shape == "variable" ? new GenericVar(99, f.Owner) : new GenericVar(0, f.Owner);
        if (shape == "pointer") argument = new PtrSig(argument);
        var arguments = shape == "generic-overflow" ? Enumerable.Repeat(argument, 9).ToArray() : [argument];
        f.Owner.BaseType = new TypeSpecUser(new GenericInstSig(nominal, arguments));
        Assert.False(GenericOwnerHierarchy.TryRead(f.Types.Owner, out _));
        Assert.Null(BabelGenericStub.Match(f.Stub, method => method.Name == "Dispatch"));
    }

    [Fact]
    public void ExactExternalBaseExpressionCanBeReconstructedWithoutInferringItsConstraints()
    {
        using var f = new Fixture();
        var reference = new TypeRefUser(f.Module, "Foreign", "Constrained`1", new AssemblyRefUser("Foreign"));
        f.Owner.BaseType = new TypeSpecUser(new GenericInstSig(new ClassSig(reference), new GenericVar(0, f.Owner)));
        var type = f.Types.RuntimeType(new ClassSig(reference));
        var argument = f.Types.RuntimeType(f.Types.Variables[0]);
        Assert.True(f.Heap.TryAllocateArray(null, 1, out var arguments)); f.Heap.TryWriteArray(arguments, 0, argument);
        var api = new MemberRefUser(f.Module, "MakeGenericType", MethodSig.CreateInstance(f.Module.CorLibTypes.GetTypeRef("System", "Type").ToTypeSig(),
            new SZArraySig(f.Module.CorLibTypes.GetTypeRef("System", "Type").ToTypeSig())), f.Module.CorLibTypes.GetTypeRef("System", "Type"));
        var result = f.Types.Invoke(new(f.Machine.State), api, [type, arguments]);
        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        var closed = Assert.IsType<GenericInstSig>(ReflectionEmitIntrinsic.Signatures(f.Heap, result.Value));
        Assert.Same(reference, closed.GenericType.TypeDefOrRef);
        Assert.Same(f.Types.Variables[0], Assert.Single(closed.GenericArguments));
        var other = f.Types.RuntimeType(new ClassSig(new TypeRefUser(f.Module, "Foreign", "Other`1", new AssemblyRefUser("Foreign"))));
        Assert.NotEqual(StaticExecutionStatus.Completed, f.Types.Invoke(new(f.Machine.State), api, [other, arguments]).Status);
    }

    [Fact]
    public void ExistingNestedBaseExpressionCanBeReconstructedWithoutRelaxingItsConstraints()
    {
        using var f = new Fixture();
        var parent = Parent(f.Module, "Parent`1", 1, f.Module.CorLibTypes.Object.TypeDefOrRef);
        var list = new ClassSig(f.Module.CorLibTypes.GetTypeRef("System.Collections.Generic", "List`1"));
        f.Owner.BaseType = new TypeSpecUser(new GenericInstSig(new ClassSig(parent), new GenericInstSig(list, new GenericVar(0, f.Owner))));
        var type = f.Types.RuntimeType(list); var argument = f.Types.RuntimeType(f.Types.Variables[0]);
        Assert.True(f.Heap.TryAllocateArray(null, 1, out var arguments)); f.Heap.TryWriteArray(arguments, 0, argument);
        var api = new MemberRefUser(f.Module, "MakeGenericType", MethodSig.CreateInstance(f.Module.CorLibTypes.GetTypeRef("System", "Type").ToTypeSig(),
            new SZArraySig(f.Module.CorLibTypes.GetTypeRef("System", "Type").ToTypeSig())), f.Module.CorLibTypes.GetTypeRef("System", "Type"));
        var result = f.Types.Invoke(new(f.Machine.State), api, [type, arguments]);
        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        var closed = Assert.IsType<GenericInstSig>(ReflectionEmitIntrinsic.Signatures(f.Heap, result.Value));
        Assert.Same(f.Types.Variables[0], Assert.Single(closed.GenericArguments));
    }

    [Fact]
    public void ListMetadataPreservesTheInputScopeAndRejectsForeignOrUnknownArgumentMatching()
    {
        using var f = new Fixture();
        var variable = f.Types.Variables[0];
        var list = new GenericInstSig(new ClassSig(f.Module.CorLibTypes.GetTypeRef("System.Collections.Generic", "List`1")), variable);
        var add = Assert.IsAssignableFrom<IMethod>(ParametricListMembers.Bind(f.Module, list, "Add", 52, [variable]));
        Assert.Same(list, Assert.IsType<TypeSpecUser>(add.DeclaringType).TypeSig);
        Assert.Equal(ElementType.Void, add.MethodSig.RetType.ElementType);
        var setter = Assert.IsAssignableFrom<IMethod>(ParametricListMembers.Bind(f.Module, list, "set_Item", 52, [f.Module.CorLibTypes.Int32, variable]));
        Assert.Same(list, Assert.IsType<TypeSpecUser>(setter.DeclaringType).TypeSig);
        Assert.Equal(ElementType.Void, setter.MethodSig.RetType.ElementType);
        Assert.Null(ParametricListMembers.Bind(f.Module, list, "set_Item", 52, [variable, f.Module.CorLibTypes.Int32]));
        Assert.Null(ParametricListMembers.Bind(f.Module, list, "Add", 52, [new GenericVar(0, f.Owner)]));
        Assert.Null(ParametricListMembers.Bind(f.Module, list, "Add", 52, [f.Module.CorLibTypes.Int32]));
        Assert.Null(ParametricListMembers.Bind(f.Module, list, "get_Item", 52, [variable]));
        Assert.Null(ParametricListMembers.Bind(f.Module, list, "EnsureCapacity", 52, [f.Module.CorLibTypes.Int32]));
        var foreign = new GenericInstSig(new ClassSig(new TypeRefUser(f.Module, "System.Collections.Generic", "List`1", new AssemblyRefUser("Foreign"))), variable);
        Assert.Null(ParametricListMembers.Bind(f.Module, foreign, "Add", 52, [variable]));
    }

    [Fact]
    public void CustomBinderSelectionRunsItsCilAndRetainsItsEffects()
    {
        using var f = new Fixture();
        var binder = new TypeDefUser("Probe", "Binder", f.Module.CorLibTypes.GetTypeRef("System.Reflection", "Binder")); f.Module.Types.Add(binder);
        var seen = new FieldDefUser("Seen", new FieldSig(f.Module.CorLibTypes.Int32), FieldAttributes.Public | FieldAttributes.Static); binder.Fields.Add(seen);
        var methodBase = f.Module.CorLibTypes.GetTypeRef("System.Reflection", "MethodBase").ToTypeSig();
        var runtimeType = f.Module.CorLibTypes.GetTypeRef("System", "Type").ToTypeSig();
        var modifiers = new SZArraySig(new ValueTypeSig(f.Module.CorLibTypes.GetTypeRef("System.Reflection", "ParameterModifier")));
        var select = new MethodDefUser("SelectMethod", MethodSig.CreateInstance(methodBase, f.Module.CorLibTypes.Int32, new SZArraySig(methodBase), new SZArraySig(runtimeType), modifiers),
            MethodAttributes.Public | MethodAttributes.Virtual) { Body = new CilBody() }; binder.Methods.Add(select);
        foreach (var instruction in new[] { OpCodes.Ldc_I4.ToInstruction(42), OpCodes.Stsfld.ToInstruction(seen), OpCodes.Ldarg_2.ToInstruction(), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldelem_Ref.ToInstruction(), OpCodes.Ret.ToInstruction() }) select.Body.Instructions.Add(instruction);
        var list = new GenericInstSig(new ClassSig(f.Module.CorLibTypes.GetTypeRef("System.Collections.Generic", "List`1")), f.Types.Variables[0]);
        var target = f.Types.RuntimeType(list); Assert.True(f.Heap.TryAllocateString("Add", out var name));
        Assert.True(f.Heap.TryAllocateObject(binder.FullName, out var selector)); Assert.True(f.Heap.TryAllocateArray(null, 1, out var parameters));
        f.Heap.TryWriteArray(parameters, 0, f.Types.RuntimeType(f.Types.Variables[0]));
        var api = new MemberRefUser(f.Module, "GetMethod", MethodSig.CreateInstance(f.Module.CorLibTypes.GetTypeRef("System.Reflection", "MethodInfo").ToTypeSig(),
            f.Module.CorLibTypes.String, f.Module.CorLibTypes.Int32, f.Module.CorLibTypes.Object, new SZArraySig(runtimeType), modifiers), f.Module.CorLibTypes.GetTypeRef("System", "Type"));
        IntrinsicResult Call(IMethod method, IReadOnlyList<StaticValue> arguments)
        {
            var called = f.Machine.Invoke(method, arguments);
            return new(called.Status, called.Value, called.Diagnostic);
        }
        var result = f.Types.Invoke(new(f.Machine.State, Call: Call), api, [target, name, StaticValue.FromInt32(52), selector, parameters, StaticValue.Null]);
        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(42, f.Machine.State.ReadStaticField(seen).AsInt32());
        Assert.True(f.Heap.TryGetModelValue<IMethod>(result.Value, "Metadata", out var selected)); Assert.Equal("Add", selected!.Name.String);
    }

    [Fact]
    public void TypeEqualityProvesReflexivityButDoesNotCompareDifferentUnknownArguments()
    {
        using var f = new Fixture();
        var value = f.Types.RuntimeType(f.Types.Variables[0]);
        var api = new MemberRefUser(f.Module, "Equals", MethodSig.CreateInstance(f.Module.CorLibTypes.Boolean, f.Module.CorLibTypes.GetTypeRef("System", "Type").ToTypeSig()), f.Module.CorLibTypes.GetTypeRef("System", "Type"));
        Assert.Equal(1, f.Types.Invoke(new(f.Machine.State), api, [value, value]).Value.AsInt32());
        var other = f.Types.RuntimeType(new GenericVar(0, f.Derived));
        Assert.Equal(StaticExecutionStatus.Unknown, f.Types.Invoke(new(f.Machine.State), api, [value, other]).Status);
    }

    private static TypeDefUser Parent(ModuleDef module, string name, int count, ITypeDefOrRef parent)
    {
        var type = new TypeDefUser("Probe", name, parent); module.Types.Add(type);
        for (var index = 0; index < count; index++) type.GenericParameters.Add(new GenericParamUser((ushort)index, GenericParamAttributes.NonVariant, "T" + index));
        return type;
    }
}
