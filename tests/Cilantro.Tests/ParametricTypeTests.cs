using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Reflection;
using FieldAttributes = dnlib.DotNet.FieldAttributes;
using MethodAttributes = dnlib.DotNet.MethodAttributes;

namespace Cilantro.Tests;

public sealed class ParametricTypeTests
{
    [Theory]
    [InlineData(GenericParamAttributes.NonVariant, GenericParamAttributes.NonVariant, true)]
    [InlineData(GenericParamAttributes.ReferenceTypeConstraint, GenericParamAttributes.ReferenceTypeConstraint, true)]
    [InlineData(GenericParamAttributes.ReferenceTypeConstraint, GenericParamAttributes.DefaultConstructorConstraint, false)]
    [InlineData(GenericParamAttributes.NotNullableValueTypeConstraint, GenericParamAttributes.NotNullableValueTypeConstraint, true)]
    [InlineData(GenericParamAttributes.NotNullableValueTypeConstraint, GenericParamAttributes.ReferenceTypeConstraint, false)]
    [InlineData(GenericParamAttributes.DefaultConstructorConstraint, GenericParamAttributes.DefaultConstructorConstraint, true)]
    [InlineData(GenericParamAttributes.DefaultConstructorConstraint, GenericParamAttributes.NotNullableValueTypeConstraint, true)]
    [InlineData(GenericParamAttributes.DefaultConstructorConstraint, GenericParamAttributes.ReferenceTypeConstraint, false)]
    public void MethodConstructionRequiresReceiverConstraintsToImplyMethodConstraints(GenericParamAttributes required, GenericParamAttributes actual, bool accepted)
    {
        using var fixture = new Fixture(actual);
        var method = new MethodDefUser("Make", MethodSig.CreateStatic(fixture.Module.CorLibTypes.Void), MethodAttributes.Static);
        fixture.Owner.Methods.Add(method); method.MethodSig.Generic = true; method.MethodSig.GenParamCount = 1;
        method.GenericParameters.Add(new GenericParamUser(0, required, "U"));
        Assert.True(fixture.Heap.TryAllocateObject("System.Reflection.MethodInfo", out var reflected));
        fixture.Heap.TrySetModelValue(reflected, "Metadata", (IMethod)method);
        var result = fixture.Call(typeof(MethodInfo).GetMethod("MakeGenericMethod")!, reflected,
            fixture.Array(fixture.Scope.RuntimeType(fixture.Scope.Variables[0])));
        Assert.Equal(accepted, result.Status == StaticExecutionStatus.Completed);
        if (accepted)
        {
            Assert.True(fixture.Heap.TryGetModelValue<IMethod>(result.Value, "Metadata", out var bound));
            var spec = Assert.IsType<MethodSpecUser>(bound);
            Assert.Same(fixture.Scope.Variables[0], Assert.Single(spec.GenericInstMethodSig.GenericArguments));
            Assert.Equal(1, fixture.Call(typeof(MethodBase).GetProperty("IsGenericMethod")!.GetMethod!, result.Value).Value.AsInt32());
            Assert.Equal(0, fixture.Call(typeof(MethodBase).GetProperty("IsGenericMethodDefinition")!.GetMethod!, result.Value).Value.AsInt32());
        }
    }

    [Theory]
    [InlineData("interface")]
    [InlineData("value-type-without-special-flag")]
    [InlineData("open-argument")]
    [InlineData("arity")]
    [InlineData("already-constructed")]
    public void UnprovedMethodConstructionsRefuse(string change)
    {
        using var fixture = new Fixture(GenericParamAttributes.DefaultConstructorConstraint);
        var method = new MethodDefUser("Make", MethodSig.CreateStatic(fixture.Module.CorLibTypes.Void), MethodAttributes.Static);
        fixture.Owner.Methods.Add(method); method.MethodSig.Generic = true; method.MethodSig.GenParamCount = 1;
        method.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "U"));
        if (change is "interface" or "value-type-without-special-flag") method.GenericParameters[0].GenericParamConstraints.Add(
            new GenericParamConstraintUser(fixture.Module.CorLibTypes.GetTypeRef("System", change == "interface" ? "IDisposable" : "ValueType")));
        Assert.True(fixture.Heap.TryAllocateObject("System.Reflection.MethodInfo", out var reflected));
        IMethod metadata = change == "already-constructed" ? new MethodSpecUser(method, new GenericInstMethodSig(fixture.Scope.Variables[0])) : method;
        fixture.Heap.TrySetModelValue(reflected, "Metadata", metadata);
        var argument = change == "open-argument" ? fixture.Model(new GenericVar(0, fixture.Owner)) : fixture.Scope.RuntimeType(fixture.Scope.Variables[0]);
        var array = change == "arity" ? fixture.Array(argument, argument) : fixture.Array(argument);
        Assert.NotEqual(StaticExecutionStatus.Completed, fixture.Call(typeof(MethodInfo).GetMethod("MakeGenericMethod")!, reflected, array).Status);
    }

    [Fact]
    public void CoreLibraryMethodBindingUsesTheInputsAssemblyScopeAndNeverInvokesItsBody()
    {
        using var fixture = new Fixture(GenericParamAttributes.DefaultConstructorConstraint);
        var host = typeof(Activator).GetMethods().Single(method => method.Name == "CreateInstance" && method.IsGenericMethodDefinition);
        Assert.True(fixture.Heap.TryAllocateObject("System.Reflection.MethodInfo", out var reflected));
        fixture.Heap.TrySetModelValue(reflected, "Metadata", host);
        var argument = fixture.Scope.RuntimeType(fixture.Scope.Variables[0]);
        var result = fixture.Call(typeof(MethodInfo).GetMethod("MakeGenericMethod")!, reflected, fixture.Array(argument));
        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.True(fixture.Heap.TryGetModelValue<IMethod>(result.Value, "Metadata", out var metadata));
        var spec = Assert.IsType<MethodSpecUser>(metadata);
        Assert.Equal(fixture.Module.CorLibTypes.AssemblyRef.FullName, spec.DeclaringType.DefinitionAssembly.FullName);
        Assert.Same(fixture.Scope.Variables[0], Assert.Single(spec.GenericInstMethodSig.GenericArguments));
        Assert.Equal(argument, fixture.Call(typeof(MethodInfo).GetProperty("ReturnType")!.GetMethod!, result.Value).Value);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void GenericMethodFlagsMatchClrForFrameworkAndFileMetadata(bool framework)
    {
        using var fixture = new Fixture(); var intrinsic = new LoaderFrameworkIntrinsic();
        var factory = typeof(Activator).GetMethods().Single(method => method.Name == "CreateInstance" && method.IsGenericMethodDefinition);
        var genericOwner = typeof(FlagOwner<>);
        foreach (var method in new[] { factory, factory.MakeGenericMethod(typeof(int)), genericOwner.GetMethod("Plain")!,
            genericOwner.GetMethod("Identity")!, genericOwner.GetMethod("Identity")!.MakeGenericMethod(typeof(string)) })
        {
            Assert.True(fixture.Heap.TryAllocateObject("System.Reflection.MethodInfo", out var reflected));
            var importer = new Importer(fixture.Module);
            // Constructed calls need an explicit MethodSpec, distinct from their
            // generic definition's MemberRef and its generic signature.
            object metadata = framework ? method : method.IsGenericMethod && !method.IsGenericMethodDefinition
                ? new MethodSpecUser((IMethodDefOrRef)importer.Import(method.GetGenericMethodDefinition()),
                    new GenericInstMethodSig(method.GetGenericArguments().Select(importer.ImportAsTypeSig).ToArray()))
                : importer.Import(method);
            fixture.Heap.TrySetModelValue(reflected, "Metadata", metadata);
            foreach (var property in new[] { "IsGenericMethod", "IsGenericMethodDefinition" })
            {
                var result = intrinsic.Invoke(new(fixture.Machine.State), new Importer(fixture.Module).Import(typeof(MethodBase).GetProperty(property)!.GetMethod!), [reflected]);
                Assert.Equal(StaticExecutionStatus.Completed, result.Status);
                Assert.Equal((bool)typeof(MethodBase).GetProperty(property)!.GetValue(method)! ? 1 : 0, result.Value.AsInt32());
            }
        }
    }

    public sealed class FlagOwner<T>
    {
        public void Plain() { }
        public TValue Identity<TValue>(TValue value) => value;
    }

    [Fact]
    public void EmptyParameterListsOnUnknownClosedOwnersRemainKnown()
    {
        using var fixture = new Fixture(GenericParamAttributes.DefaultConstructorConstraint);
        var method = new MethodDefUser("Read", MethodSig.CreateInstance(new GenericVar(0, fixture.Owner)));
        fixture.Owner.Methods.Add(method);
        Assert.True(fixture.Heap.TryAllocateObject("System.Reflection.MethodInfo", out var metadata));
        fixture.Heap.TrySetModelValue(metadata, "Metadata", (IMethod)new MemberRefUser(fixture.Module, method.Name, method.MethodSig, fixture.Scope.Owner.ToTypeDefOrRef()));
        var result = fixture.Call(typeof(MethodBase).GetMethod("GetParameters")!, metadata);
        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.True(fixture.Heap.TryGetLength(result.Value, out var count));
        Assert.Equal(0, count);
    }

    [Theory]
    [InlineData(GenericParamAttributes.ReferenceTypeConstraint)]
    [InlineData(GenericParamAttributes.NotNullableValueTypeConstraint | GenericParamAttributes.DefaultConstructorConstraint)]
    [InlineData(GenericParamAttributes.DefaultConstructorConstraint)]
    public void ConstrainedOwnerCanReconstructOnlyItsExistingRuntimeArguments(GenericParamAttributes constraints)
    {
        using var fixture = new Fixture(constraints);
        var opaque = fixture.Scope.RuntimeType(fixture.Scope.Variables[0]);
        var result = fixture.Call(typeof(Type).GetMethod("MakeGenericType")!, fixture.Model(fixture.Owner), fixture.Array(opaque));
        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(fixture.Scope.RuntimeType(fixture.Scope.Owner), result.Value);
        Assert.Equal(StaticExecutionStatus.Unknown, fixture.Call(typeof(Type).GetProperty("IsValueType")!.GetMethod!, opaque).Status);
        var foreign = new TypeDefUser("Probe", "Foreign`1", fixture.Module.CorLibTypes.Object.TypeDefOrRef);
        fixture.Module.Types.Add(foreign);
        foreign.GenericParameters.Add(new GenericParamUser(0, constraints, "U"));
        Assert.Equal(StaticExecutionStatus.Unknown,
            fixture.Call(typeof(Type).GetMethod("MakeGenericType")!, fixture.Model(foreign), fixture.Array(opaque)).Status);
    }

    [Fact]
    public void RuntimeUnknownAndOpenMetadataParametersHaveSeparateIdentities()
    {
        using var fixture = new Fixture(); var opaque = fixture.Scope.RuntimeType(fixture.Scope.Variables[0]);
        var definition = fixture.Model(fixture.Owner);
        var openArray = fixture.Call(typeof(Type).GetMethod("GetGenericArguments")!, definition); Assert.True(openArray.Status == StaticExecutionStatus.Completed);
        Assert.True(fixture.Heap.TryReadArray(openArray.Value, 0, out var open)); Assert.NotEqual(opaque, open);
        var openKind = fixture.Call(typeof(Type).GetProperty("IsGenericParameter")!.GetMethod!, open); Assert.Equal(1, openKind.Value.AsInt32());
        Assert.Equal(StaticExecutionStatus.Unknown, fixture.Call(typeof(Type).GetProperty("IsGenericParameter")!.GetMethod!, opaque).Status);
        Assert.True(fixture.Heap.TryGetModelValue<TypeSig>(open, "Metadata", out var openSignature));
        Assert.False(fixture.Scope.Contains(openSignature)); Assert.True(fixture.Scope.Contains(ReflectionEmitIntrinsic.Signatures(fixture.Heap, opaque)));
    }

    [Fact]
    public void UnknownClosedArgumentsDoNotCollapseToTheirOpenDefinition()
    {
        using var fixture = new Fixture(); var opaque = fixture.Scope.RuntimeType(fixture.Scope.Variables[0]); var template = fixture.Model(fixture.Owner);
        var array = fixture.Array(opaque); var result = fixture.Call(typeof(Type).GetMethod("MakeGenericType")!, template, array);
        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        var constructed = Assert.IsType<GenericInstSig>(ReflectionEmitIntrinsic.Signatures(fixture.Heap, result.Value));
        Assert.Same(fixture.Scope.Variables[0], Assert.Single(constructed.GenericArguments));
        var formal = fixture.Model(new GenericVar(0, fixture.Owner));
        var open = fixture.Call(typeof(Type).GetMethod("MakeGenericType")!, template, fixture.Array(formal));
        Assert.Equal(StaticExecutionStatus.Completed, open.Status); Assert.IsType<ClassSig>(ReflectionEmitIntrinsic.Signatures(fixture.Heap, open.Value));
        var arguments = fixture.Call(typeof(Type).GetMethod("GetGenericArguments")!, result.Value);
        Assert.True(fixture.Heap.TryReadArray(arguments.Value, 0, out var first)); Assert.Equal(opaque, first);
    }

    [Fact]
    public void DeclaredFieldAndHandleRetainTheUnknownOwnerArgument()
    {
        using var fixture = new Fixture(); var runtime = fixture.Scope.RuntimeType(fixture.Scope.Owner);
        Assert.True(fixture.Heap.TryAllocateString("value", out var name));
        var result = fixture.Call(typeof(Type).GetMethod("GetField", [typeof(string), typeof(BindingFlags)])!, runtime, name,
            StaticValue.FromInt32((int)(BindingFlags.Instance | BindingFlags.Public)));
        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.True(fixture.Heap.TryGetModelValue<IField>(result.Value, "Metadata", out var field));
        Assert.IsType<GenericInstSig>(Assert.IsType<TypeSpecUser>(field!.DeclaringType).TypeSig);
        var held = fixture.Call(typeof(FieldInfo).GetProperty("FieldType")!.GetMethod!, result.Value);
        Assert.Equal(fixture.Scope.RuntimeType(fixture.Scope.Variables[0]), held.Value);
        var handle = fixture.Call(typeof(FieldInfo).GetProperty("FieldHandle")!.GetMethod!, result.Value);
        Assert.Equal(StaticExecutionStatus.Completed, handle.Status); Assert.True(fixture.Heap.TryGetMetadataHandle(handle.Value, out var metadata));
        Assert.Same(field, metadata);
    }

    [Theory]
    [InlineData("FullName")]
    [InlineData("Name")]
    [InlineData("IsValueType")]
    [InlineData("IsClass")]
    [InlineData("IsEnum")]
    [InlineData("IsArray")]
    [InlineData("IsGenericType")]
    [InlineData("IsGenericParameter")]
    [InlineData("IsGenericTypeDefinition")]
    [InlineData("ContainsGenericParameters")]
    [InlineData("AssemblyQualifiedName")]
    public void UnknownTypeTraitsAreNotAnsweredFromAnOpenParameter(string property)
    {
        using var fixture = new Fixture(); var value = fixture.Scope.RuntimeType(fixture.Scope.Variables[0]);
        Assert.Equal(StaticExecutionStatus.Unknown, fixture.Call(typeof(Type).GetProperty(property)!.GetMethod!, value).Status);
    }

    [Theory]
    [InlineData("GetGenericArguments")]
    [InlineData("GetGenericTypeDefinition")]
    [InlineData("GetHashCode")]
    [InlineData("ToString")]
    public void OperationsThatInspectTheUnknownArgumentRefuse(string operation)
    {
        using var fixture = new Fixture(); var value = fixture.Scope.RuntimeType(fixture.Scope.Variables[0]);
        Assert.Equal(StaticExecutionStatus.Unknown, fixture.Call(typeof(Type).GetMethod(operation, Type.EmptyTypes)!, value).Status);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TypeAndHandleIdentityCannotDecideCilComparisons(bool handles)
    {
        using var fixture = new Fixture(); var opaque = fixture.Scope.RuntimeType(fixture.Scope.Variables[0]); var known = fixture.Model(fixture.Module.CorLibTypes.Int32);
        if (handles)
        {
            opaque = fixture.Call(typeof(Type).GetProperty("TypeHandle")!.GetMethod!, opaque).Value;
            known = fixture.Call(typeof(Type).GetProperty("TypeHandle")!.GetMethod!, known).Value;
        }
        var method = fixture.Compare(false); Assert.Equal(StaticExecutionStatus.Unknown, fixture.Machine.Execute(method, [opaque, known]).Status);
        Assert.Equal(StaticExecutionStatus.Unknown, fixture.Machine.Execute(fixture.Compare(true), [opaque, known]).Status);
        Assert.True(fixture.Machine.Execute(method, [opaque, StaticValue.Null]).Succeeded);
    }

    [Fact]
    public void OrdinaryReflectionEqualityAndUnknownIdentityHaveDifferentResults()
    {
        using var fixture = new Fixture(); var opaque = fixture.Scope.RuntimeType(fixture.Scope.Variables[0]); var known = fixture.Model(fixture.Module.CorLibTypes.Int32);
        var equal = typeof(Type).GetMethod("op_Equality")!;
        Assert.Equal(StaticExecutionStatus.Unknown, fixture.Call(equal, opaque, known).Status);
        Assert.Equal(0, fixture.Call(equal, opaque, StaticValue.Null).Value.AsInt32());
        var handle = fixture.Call(typeof(Type).GetProperty("TypeHandle")!.GetMethod!, opaque);
        Assert.Equal(opaque, fixture.Call(typeof(Type).GetMethod("GetTypeFromHandle")!, handle.Value).Value);
    }

    [Fact]
    public void HashTablesCannotCompareUnknownTypeKeys()
    {
        using var fixture = new Fixture(); var opaque = fixture.Scope.RuntimeType(fixture.Scope.Variables[0]);
        Assert.True(fixture.Heap.TryAllocateObject("System.Collections.Hashtable", out var table));
        fixture.Heap.TrySetModelValue(table, "Entries", new Dictionary<StaticValue, StaticValue> { [opaque] = StaticValue.FromInt32(7) });
        var known = fixture.Model(fixture.Module.CorLibTypes.Int32);
        Assert.Equal(StaticExecutionStatus.Unknown, fixture.Call(typeof(System.Collections.Hashtable).GetMethod("ContainsKey")!, table, known).Status);
    }

    [Fact]
    public void OnlyTheFirstTypeKeyInADefaultEmptyDictionaryNeedsNoIdentityDecision()
    {
        using var fixture = new Fixture(); var definition = typeof(Dictionary<Type, object>);
        Assert.True(fixture.Heap.TryAllocateObject(definition.FullName!, out var receiver));
        var created = fixture.Call(definition.GetConstructor(Type.EmptyTypes)!, receiver); Assert.Equal(StaticExecutionStatus.Completed, created.Status);
        var key = fixture.Scope.RuntimeType(fixture.Scope.Owner); var add = definition.GetMethod("Add")!;
        Assert.Equal(StaticExecutionStatus.Completed, fixture.Call(add, created.Value, key, StaticValue.Null).Status);
        Assert.Equal(StaticExecutionStatus.Unknown, fixture.Call(add, created.Value, key, StaticValue.Null).Status);
        Assert.Equal(StaticExecutionStatus.Unknown, fixture.Call(definition.GetMethod("ContainsKey")!, created.Value, fixture.Model(fixture.Module.CorLibTypes.Int32)).Status);
        Assert.Equal(1, fixture.Call(definition.GetProperty("Count")!.GetMethod!, created.Value).Value.AsInt32());
        var custom = fixture.Call(definition.GetConstructor([typeof(IEqualityComparer<Type>)])!, receiver, StaticValue.Null);
        Assert.Equal(StaticExecutionStatus.Unknown, custom.Status);
    }

    [Fact]
    public void DictionaryValuesCannotBeComparedAsIfUnknownRuntimeTypesWereDifferent()
    {
        using var fixture = new Fixture(); var definition = typeof(Dictionary<int, Type>);
        Assert.True(fixture.Heap.TryAllocateObject(definition.FullName!, out var receiver));
        var created = fixture.Call(definition.GetConstructor(Type.EmptyTypes)!, receiver);
        Assert.Equal(StaticExecutionStatus.Completed, fixture.Call(definition.GetMethod("Add")!, created.Value, StaticValue.FromInt32(0), fixture.Scope.RuntimeType(fixture.Scope.Variables[0])).Status);
        Assert.Equal(StaticExecutionStatus.Unknown, fixture.Call(definition.GetMethod("ContainsValue")!, created.Value, fixture.Model(fixture.Module.CorLibTypes.Int32)).Status);
    }

    [Fact]
    public void GenericMethodHandlesRetainTheirUnknownMethodArguments()
    {
        using var fixture = new Fixture(); var owner = new TypeDefUser("Probe", "Methods", fixture.Module.CorLibTypes.Object.TypeDefOrRef); fixture.Module.Types.Add(owner);
        var method = new MethodDefUser("Identity", MethodSig.CreateStatic(fixture.Module.CorLibTypes.Object), MethodAttributes.Static); owner.Methods.Add(method);
        method.MethodSig.Generic = true; method.MethodSig.GenParamCount = 1;
        method.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "U"));
        method.MethodSig.RetType = new GenericMVar(0, method);
        Assert.True(fixture.Heap.TryAllocateObject("System.Reflection.MethodInfo", out var opaque));
        fixture.Heap.TrySetModelValue(opaque, "Metadata", new MethodSpecUser(method, new GenericInstMethodSig(fixture.Scope.Variables[0])));
        Assert.True(fixture.Heap.TryAllocateObject("System.Reflection.MethodInfo", out var known));
        fixture.Heap.TrySetModelValue(known, "Metadata", new MethodSpecUser(method, new GenericInstMethodSig(fixture.Module.CorLibTypes.Int32)));
        Assert.Equal(fixture.Scope.RuntimeType(fixture.Scope.Variables[0]), fixture.Call(typeof(MethodInfo).GetProperty("ReturnType")!.GetMethod!, opaque).Value);
        var a = fixture.Call(typeof(MethodInfo).GetProperty("MethodHandle")!.GetMethod!, opaque);
        var b = fixture.Call(typeof(MethodInfo).GetProperty("MethodHandle")!.GetMethod!, known);
        Assert.Equal(StaticExecutionStatus.Unknown, fixture.Machine.Execute(fixture.Compare(false), [a.Value, b.Value]).Status);
    }

    [Fact]
    public void AnOpenForeignParameterCannotBeTreatedAsAClosedRuntimeArgument()
    {
        using var fixture = new Fixture(); var owner = new TypeDefUser("Probe", "Pair`2", fixture.Module.CorLibTypes.Object.TypeDefOrRef); fixture.Module.Types.Add(owner);
        owner.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "U")); owner.GenericParameters.Add(new GenericParamUser(1, GenericParamAttributes.NonVariant, "V"));
        var arguments = fixture.Array(fixture.Scope.RuntimeType(fixture.Scope.Variables[0]), fixture.Model(new GenericVar(0, owner)));
        Assert.Equal(StaticExecutionStatus.Unknown, fixture.Call(typeof(Type).GetMethod("MakeGenericType")!, fixture.Model(owner), arguments).Status);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void UnknownValuesCannotDecideTypeTests(bool cast)
    {
        using var fixture = new Fixture();
        var method = new MethodDefUser("TypeTest", MethodSig.CreateStatic(fixture.Module.CorLibTypes.Object, fixture.Module.CorLibTypes.Object), MethodAttributes.Static) { Body = new CilBody() };
        fixture.Owner.Methods.Add(method);
        method.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
        method.Body.Instructions.Add((cast ? OpCodes.Castclass : OpCodes.Isinst).ToInstruction(fixture.Module.CorLibTypes.String.TypeDefOrRef));
        method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        Assert.Equal(StaticExecutionStatus.Unknown, fixture.Machine.Execute(method, [StaticValue.Unknown]).Status);
    }

    [Fact]
    public void UnknownGenericBoxRequiresAnExactTransportCertificate()
    {
        using var fixture = new Fixture();
        var method = new MethodDefUser("Box", MethodSig.CreateInstance(fixture.Module.CorLibTypes.Object, new GenericVar(0, fixture.Owner))) { Body = new CilBody() };
        fixture.Owner.Methods.Add(method);
        method.Body.Instructions.Add(OpCodes.Ldarg_1.ToInstruction());
        method.Body.Instructions.Add(OpCodes.Box.ToInstruction(new TypeSpecUser(new GenericVar(0, fixture.Owner))));
        method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        Assert.True(fixture.Heap.TryAllocateObject(fixture.Scope.Owner.FullName, out var receiver));
        Assert.Equal(StaticExecutionStatus.Unknown, fixture.Machine.Execute(method, [receiver, StaticValue.Unknown]).Status);
    }

    [Theory]
    [InlineData("Name")]
    [InlineData("FullName")]
    [InlineData("AssemblyQualifiedName")]
    public void SymbolicEmittedNamesCannotEscapeThroughReflection(string property)
    {
        using var fixture = new Fixture();
        var emitted = new TypeDefUser("Generated", "Symbolic", fixture.Module.CorLibTypes.Object.TypeDefOrRef); fixture.Module.Types.Add(emitted);
        fixture.Scope.MarkSymbolicName(emitted);
        Assert.Equal(StaticExecutionStatus.Unknown, fixture.Call(typeof(Type).GetProperty(property)!.GetMethod!, fixture.Model(emitted)).Status);
    }

    private sealed class Fixture : IDisposable
    {
        internal ModuleDefUser Module { get; } = new("Parametric");
        internal TypeDefUser Owner { get; }
        internal ParametricTypeIntrinsic Scope { get; }
        internal StaticMachine Machine { get; }
        internal StaticHeap Heap => Machine.State.Heap;
        internal Fixture(GenericParamAttributes constraints = GenericParamAttributes.NonVariant)
        {
            Owner = new TypeDefUser("Probe", "Box`1", Module.CorLibTypes.Object.TypeDefOrRef); Module.Types.Add(Owner);
            Owner.GenericParameters.Add(new GenericParamUser(0, constraints, "T"));
            Owner.Fields.Add(new FieldDefUser("value", new FieldSig(new GenericVar(0, Owner)), FieldAttributes.Public));
            Scope = new ParametricTypeIntrinsic(Owner, new RawDynamicMethodIntrinsic()); Machine = new StaticMachine(intrinsics: Scope); Scope.Attach(Machine); Machine.State.RegisterModuleMetadata(Module);
        }
        internal StaticValue Model(object metadata)
        { Assert.True(Heap.TryAllocateObject("System.Type", out var value)); Heap.TrySetModelValue(value, "Metadata", metadata); if(metadata is IFullName named) Heap.TrySetModelValue(value, "TypeName", named.FullName); return value; }
        internal StaticValue Array(params StaticValue[] values)
        { Assert.True(Heap.TryAllocateArray(null, values.Length, out var array)); for(var index=0;index<values.Length;index++) Heap.TryWriteArray(array,index,values[index]); return array; }
        internal IntrinsicResult Call(MethodBase method, params StaticValue[] values) => Scope.Invoke(new(Machine.State), new Importer(Module).Import(method), values);
        internal MethodDefUser Compare(bool branch)
        {
            var method = new MethodDefUser("Compare" + branch, MethodSig.CreateStatic(Module.CorLibTypes.Int32, Module.CorLibTypes.Object, Module.CorLibTypes.Object), MethodAttributes.Static) { Body = new CilBody() }; Owner.Methods.Add(method);
            method.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction()); method.Body.Instructions.Add(OpCodes.Ldarg_1.ToInstruction());
            if (!branch) { method.Body.Instructions.Add(OpCodes.Ceq.ToInstruction()); method.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); return method; }
            var target = OpCodes.Ldc_I4_1.ToInstruction(); method.Body.Instructions.Add(OpCodes.Beq.ToInstruction(target)); method.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction()); method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            method.Body.Instructions.Add(target); method.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); return method;
        }
        public void Dispose() => Module.Dispose();
    }
}
