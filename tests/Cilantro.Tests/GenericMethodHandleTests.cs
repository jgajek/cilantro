using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class GenericMethodHandleTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void GenericReflectionEntryBindsTheOwnerAndRespectsTheModuleBoundary(bool allowed)
    {
        using var module = new ModuleDefUser("EntryScope");
        using var other = new ModuleDefUser("Other");
        var owner = new TypeDefUser("Probe", "Scope`1", module.CorLibTypes.Object.TypeDefOrRef); module.Types.Add(owner);
        owner.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
        var target = new MethodDefUser("Describe", MethodSig.CreateStatic(new Importer(module).ImportAsTypeSig(typeof(Type))), MethodAttributes.Static | MethodAttributes.Public)
        { Body = new CilBody() }; owner.Methods.Add(target);
        target.Body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(new TypeSpecUser(new GenericVar(0, owner))));
        target.Body.Instructions.Add(OpCodes.Call.ToInstruction(new Importer(module).Import(typeof(Type).GetMethod("GetTypeFromHandle")!)));
        target.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        var machine = new StaticMachine(); machine.State.RegisterModuleMetadata(allowed ? module : other);
        var entered = 0; machine.FrameEntered += (_, _) => entered++;
        foreach (var argument in new TypeSig[] { module.CorLibTypes.Int32, module.CorLibTypes.String })
        {
            var context = new TypeSpecUser(new GenericInstSig(new ClassSig(owner), argument));
            Assert.Same(owner, context.ScopeType.ResolveTypeDef());
            Assert.Same(target, owner.FindMethod(target.Name, target.MethodSig));
            var result = machine.Invoke(new MemberRefUser(module, target.Name, target.MethodSig, context));
            Assert.True(allowed == result.Succeeded, result.Diagnostic);
            if (allowed) Assert.Equal(argument.FullName, ReflectionEmitIntrinsic.Signatures(machine.State.Heap, result.Value)!.FullName);
        }
        Assert.Equal(allowed ? 2 : 0, entered);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CurrentMethodDescribesTheInnermostInterpretedFrame(bool constructor)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Owner");
            var reflected = new ClassSig(module.CorLibTypes.GetTypeRef("System.Reflection", "MethodBase"));
            var field = new FieldDefUser("Seen", new FieldSig(reflected), FieldAttributes.Static); owner.Fields.Add(field);
            var target = new MethodDefUser(constructor ? ".ctor" : "Current", constructor ? MethodSig.CreateInstance(module.CorLibTypes.Void) : MethodSig.CreateStatic(module.CorLibTypes.Void),
                constructor ? MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName : MethodAttributes.Static)
                { Body = new CilBody() };
            owner.Methods.Add(target);
            if (constructor)
            {
                target.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                target.Body.Instructions.Add(OpCodes.Call.ToInstruction(new Importer(module).Import(typeof(object).GetConstructor(Type.EmptyTypes)!)));
            }
            target.Body.Instructions.Add(OpCodes.Call.ToInstruction(new Importer(module).Import(typeof(System.Reflection.MethodBase).GetMethod("GetCurrentMethod")!)));
            target.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(field));
            target.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var caller = new MethodDefUser("Caller", MethodSig.CreateStatic(reflected), MethodAttributes.Static) { Body = new CilBody() };
            module.GlobalType.Methods.Add(caller);
            caller.Body.Instructions.Add((constructor ? OpCodes.Newobj : OpCodes.Call).ToInstruction(target));
            if (constructor) caller.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            caller.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(field)); caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var machine = new StaticMachine(); machine.State.RegisterModuleMetadata(context.Module);
        var result = machine.Execute(context.Module.GlobalType.Methods.Single(method => method.Name == "Caller"));
        Assert.True(result.Succeeded, result.Diagnostic);
        Assert.True(machine.State.Heap.TryGetModelValue<IMethod>(result.Value, "Metadata", out var described));
        Assert.Equal(constructor ? ".ctor" : "Current", described!.Name.String);
        Assert.True(machine.State.Heap.TryGetRuntimeTypeName(result.Value, out var kind));
        Assert.Equal(constructor ? "System.Reflection.ConstructorInfo" : "System.Reflection.MethodInfo", kind);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void TypeContextBindsOwnerArgumentsWithoutLosingMethodArguments(bool constructor, bool genericMethod)
    {
        using var module = new ModuleDefUser("Handles");
        var owner = new TypeDefUser("Probe", "Box`1", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(owner); owner.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
        var signature = MethodSig.CreateInstance(constructor ? module.CorLibTypes.Void : new GenericVar(0, owner), new GenericVar(0, owner));
        var target = new MethodDefUser(constructor ? ".ctor" : "Exchange", signature, MethodAttributes.Public);
        owner.Methods.Add(target);
        IMethod handled = target;
        if (genericMethod)
        {
            signature.Generic = true; signature.GenParamCount = 1;
            target.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "U"));
            signature.Params.Add(new GenericMVar(0, target));
            handled = new MethodSpecUser(target, new GenericInstMethodSig(module.CorLibTypes.String));
        }
        var closed = new TypeSpecUser(new GenericInstSig(new ClassSig(owner), module.CorLibTypes.Int32));
        var machine = new StaticMachine(); var heap = machine.State.Heap;
        Assert.True(heap.TryAllocateMetadataHandle(handled, out var methodHandle));
        Assert.True(heap.TryAllocateMetadataHandle(closed, out var ownerHandle));
        var intrinsic = new LoaderFrameworkIntrinsic(); var invocation = new IntrinsicContext(machine.State);
        var importer = new Importer(module);
        var api = importer.Import(typeof(System.Reflection.MethodBase).GetMethod("GetMethodFromHandle", [typeof(RuntimeMethodHandle), typeof(RuntimeTypeHandle)])!);
        var result = intrinsic.Invoke(invocation, api, [methodHandle, ownerHandle]);
        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        var declaring = intrinsic.Invoke(invocation, importer.Import(typeof(System.Reflection.MemberInfo).GetProperty("DeclaringType")!.GetMethod!), [result.Value]);
        Assert.True(heap.TryGetModelValue<ITypeDefOrRef>(declaring.Value, "Metadata", out var actualOwner)); Assert.Same(closed, actualOwner);
        var parameters = intrinsic.Invoke(invocation, importer.Import(typeof(System.Reflection.MethodBase).GetMethod("GetParameters")!), [result.Value]);
        Assert.Equal(StaticExecutionStatus.Completed, parameters.Status);
        Assert.True(heap.TryGetLength(parameters.Value, out var count)); Assert.Equal(genericMethod ? 2 : 1, count);
        for (var index = 0; index < count; index++)
        {
            Assert.True(heap.TryReadArray(parameters.Value, index, out var parameter));
            var parameterType = intrinsic.Invoke(invocation, importer.Import(typeof(System.Reflection.ParameterInfo).GetProperty("ParameterType")!.GetMethod!), [parameter]);
            Assert.Equal(StaticExecutionStatus.Completed, parameterType.Status);
            Assert.Equal(index == 0 ? "System.Int32" : "System.String", ReflectionEmitIntrinsic.Signatures(heap, parameterType.Value)!.FullName);
        }
        var arguments = intrinsic.Invoke(invocation, importer.Import(typeof(Type).GetMethod("GetGenericArguments")!), [declaring.Value]);
        Assert.Equal(StaticExecutionStatus.Completed, arguments.Status); Assert.True(heap.TryGetLength(arguments.Value, out count)); Assert.Equal(1, count);
        Assert.True(heap.TryReadArray(arguments.Value, 0, out var argument));
        Assert.Equal("System.Int32", ReflectionEmitIntrinsic.Signatures(heap, argument)!.FullName);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MissingOrUnrelatedTypeContextsAreRefused(bool unrelated)
    {
        using var module = new ModuleDefUser("Handles");
        var owner = new TypeDefUser("Probe", "Owner", module.CorLibTypes.Object.TypeDefOrRef); module.Types.Add(owner);
        var other = new TypeDefUser("Probe", "Other", module.CorLibTypes.Object.TypeDefOrRef); module.Types.Add(other);
        var target = new MethodDefUser("Target", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodAttributes.Static); owner.Methods.Add(target);
        var heap = new StaticMachine().State;
        Assert.True(heap.Heap.TryAllocateMetadataHandle(target, out var methodHandle));
        var context = StaticValue.Null;
        if (unrelated) Assert.True(heap.Heap.TryAllocateMetadataHandle(other, out context));
        var api = new Importer(module).Import(typeof(System.Reflection.MethodBase).GetMethod("GetMethodFromHandle", [typeof(RuntimeMethodHandle), typeof(RuntimeTypeHandle)])!);
        var result = new LoaderFrameworkIntrinsic().Invoke(new(heap), api, [methodHandle, context]);
        Assert.NotEqual(StaticExecutionStatus.Completed, result.Status);
    }

    [Fact]
    public void GenericOwnerRequiresTheTwoHandleOverload()
    {
        using var module = new ModuleDefUser("Handles");
        var owner = new TypeDefUser("Probe", "Box`1", module.CorLibTypes.Object.TypeDefOrRef); module.Types.Add(owner);
        owner.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
        var target = new MethodDefUser("Target", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodAttributes.Static); owner.Methods.Add(target);
        var state = new StaticMachine().State; Assert.True(state.Heap.TryAllocateMetadataHandle(target, out var handle));
        var api = new Importer(module).Import(typeof(System.Reflection.MethodBase).GetMethod("GetMethodFromHandle", [typeof(RuntimeMethodHandle)])!);
        Assert.NotEqual(StaticExecutionStatus.Completed, new LoaderFrameworkIntrinsic().Invoke(new(state), api, [handle]).Status);
    }

    [Fact]
    public void CurrentMethodNeedsAnInterpretedFrame()
    {
        using var module = new ModuleDefUser("Handles");
        var api = new Importer(module).Import(typeof(System.Reflection.MethodBase).GetMethod("GetCurrentMethod")!);
        Assert.Equal(StaticExecutionStatus.Unknown, new LoaderFrameworkIntrinsic().Invoke(new(new StaticMachine().State), api, []).Status);
    }

    [Fact]
    public void GenericFieldHandleUsesTheSuppliedOwnerContext()
    {
        using var module = new ModuleDefUser("Handles");
        var owner = new TypeDefUser("Probe", "Box`1", module.CorLibTypes.Object.TypeDefOrRef); module.Types.Add(owner);
        owner.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
        var field = new FieldDefUser("Value", new FieldSig(new GenericVar(0, owner))); owner.Fields.Add(field);
        var closed = new GenericInstSig(new ClassSig(owner), module.CorLibTypes.String);
        var state = new StaticMachine().State; var heap = state.Heap;
        Assert.True(heap.TryAllocateMetadataHandle(field, out var fieldHandle)); Assert.True(heap.TryAllocateMetadataHandle(closed, out var ownerHandle));
        var importer = new Importer(module); var intrinsic = new LoaderFrameworkIntrinsic(); var invocation = new IntrinsicContext(state);
        var api = importer.Import(typeof(System.Reflection.FieldInfo).GetMethod("GetFieldFromHandle", [typeof(RuntimeFieldHandle), typeof(RuntimeTypeHandle)])!);
        var result = intrinsic.Invoke(invocation, api, [fieldHandle, ownerHandle]); Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        var fieldType = intrinsic.Invoke(invocation, importer.Import(typeof(System.Reflection.FieldInfo).GetProperty("FieldType")!.GetMethod!), [result.Value]);
        Assert.Equal(StaticExecutionStatus.Completed, fieldType.Status);
        Assert.Equal("System.String", ReflectionEmitIntrinsic.Signatures(heap, fieldType.Value)!.FullName);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AContextCannotTurnAFieldHandleIntoAMethodHandleOrTheReverse(bool requestMethod)
    {
        using var module = new ModuleDefUser("Handles");
        var owner = new TypeDefUser("Probe", "Owner", module.CorLibTypes.Object.TypeDefOrRef); module.Types.Add(owner);
        var target = new MethodDefUser("Target", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodAttributes.Static); owner.Methods.Add(target);
        var field = new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Int32)); owner.Fields.Add(field);
        var state = new StaticMachine().State;
        Assert.True(state.Heap.TryAllocateMetadataHandle(requestMethod ? (object)field : target, out var memberHandle));
        Assert.True(state.Heap.TryAllocateMetadataHandle(owner, out var ownerHandle));
        var api = new Importer(module).Import(requestMethod
            ? typeof(System.Reflection.MethodBase).GetMethod("GetMethodFromHandle", [typeof(RuntimeMethodHandle), typeof(RuntimeTypeHandle)])!
            : typeof(System.Reflection.FieldInfo).GetMethod("GetFieldFromHandle", [typeof(RuntimeFieldHandle), typeof(RuntimeTypeHandle)])!);
        Assert.NotEqual(StaticExecutionStatus.Completed, new LoaderFrameworkIntrinsic().Invoke(new(state), api, [memberHandle, ownerHandle]).Status);
    }

    [Fact]
    public void GenericDefinitionArgumentsRemainParameters()
    {
        using var module = new ModuleDefUser("Handles");
        var owner = new TypeDefUser("Probe", "Box`1", module.CorLibTypes.Object.TypeDefOrRef); module.Types.Add(owner);
        owner.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
        var state = new StaticMachine().State; var heap = state.Heap;
        Assert.True(heap.TryAllocateMetadataHandle(owner, out var handle));
        var importer = new Importer(module); var intrinsic = new LoaderFrameworkIntrinsic(); var invocation = new IntrinsicContext(state);
        var reflected = intrinsic.Invoke(invocation, importer.Import(typeof(Type).GetMethod("GetTypeFromHandle")!), [handle]);
        var arguments = intrinsic.Invoke(invocation, importer.Import(typeof(Type).GetMethod("GetGenericArguments")!), [reflected.Value]);
        Assert.Equal(StaticExecutionStatus.Completed, arguments.Status); Assert.True(heap.TryGetLength(arguments.Value, out var count)); Assert.Equal(1, count);
        Assert.True(heap.TryReadArray(arguments.Value, 0, out var argument));
        var isParameter = intrinsic.Invoke(invocation, importer.Import(typeof(Type).GetProperty("IsGenericParameter")!.GetMethod!), [argument]);
        Assert.Equal(StaticExecutionStatus.Completed, isParameter.Status); Assert.Equal(1, isParameter.Value.AsInt32());
        var signature = Assert.IsType<GenericVar>(ReflectionEmitIntrinsic.Signatures(heap, argument));
        Assert.Equal(0U, signature.Number); Assert.Same(owner, signature.OwnerType);
    }
}
