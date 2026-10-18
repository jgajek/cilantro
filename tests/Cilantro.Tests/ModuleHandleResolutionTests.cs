using Cilantro.Core.Interpretation;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class ModuleHandleResolutionTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MethodHandlesDescribeMethodsAndConstructorsWithTheirRuntimeKinds(bool constructor)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Owner");
            var method = new MethodDefUser(constructor ? ".ctor" : "Target", constructor ? MethodSig.CreateInstance(module.CorLibTypes.Void) : MethodSig.CreateStatic(module.CorLibTypes.Void),
                constructor ? MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName : MethodAttributes.Static)
                { Body = new dnlib.DotNet.Emit.CilBody() };
            owner.Methods.Add(method); method.Body.Instructions.Add(dnlib.DotNet.Emit.OpCodes.Ret.ToInstruction());
        });
        var state = new StaticMachineState(new StaticMachineLimits());
        state.RegisterModuleMetadata(context.Module);
        var target = context.Module.GetTypes().Single(type => type.Name == "Owner").Methods[0];
        Assert.True(state.Heap.TryAllocateMetadataHandle(target, out var handle));
        var reference = new MemberRefUser(context.Module, "GetMethodFromHandle", MethodSig.CreateStatic(
            new ClassSig(context.Module.CorLibTypes.GetTypeRef("System.Reflection", "MethodBase")),
            new ValueTypeSig(context.Module.CorLibTypes.GetTypeRef("System", "RuntimeMethodHandle"))),
            context.Module.CorLibTypes.GetTypeRef("System.Reflection", "MethodBase"));
        var answer = new LoaderFrameworkIntrinsic().Invoke(new IntrinsicContext(state), reference, [handle]);
        Assert.Equal(StaticExecutionStatus.Completed, answer.Status);
        Assert.True(state.Heap.TryGetRuntimeTypeName(answer.Value, out var type));
        Assert.Equal(constructor ? "System.Reflection.ConstructorInfo" : "System.Reflection.MethodInfo", type);
    }

    [Fact]
    public void ClosedGenericDeclaringTypesAndByReferenceShapesRetainTheirMetadata()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Generic`1");
            type.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            var constructor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void),
                MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new dnlib.DotNet.Emit.CilBody() };
            type.Methods.Add(constructor); constructor.Body.Instructions.Add(dnlib.DotNet.Emit.OpCodes.Ret.ToInstruction());
        });
        var module = context.Module;
        var generic = module.GetTypes().Single(type => type.Name == "Generic`1");
        var closed = new TypeSpecUser(new GenericInstSig(new ClassSig(generic), module.CorLibTypes.Int32));
        var constructorRef = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), closed);
        var state = new StaticMachineState(new StaticMachineLimits()); state.RegisterModuleMetadata(module);
        Assert.True(state.Heap.TryAllocateObject("System.Reflection.ConstructorInfo", out var member));
        state.Heap.TrySetModelValue(member, "Metadata", constructorRef);
        var typeRef = module.CorLibTypes.GetTypeRef("System", "Type");
        var declaring = new MemberRefUser(module, "get_DeclaringType", MethodSig.CreateInstance(new ClassSig(typeRef)),
            module.CorLibTypes.GetTypeRef("System.Reflection", "MemberInfo"));
        var intrinsic = new LoaderFrameworkIntrinsic(); var invocation = new IntrinsicContext(state);
        var owner = intrinsic.Invoke(invocation, declaring, [member]);
        Assert.Equal(StaticExecutionStatus.Completed, owner.Status);
        Assert.True(state.Heap.TryGetModelValue<object>(owner.Value, "Metadata", out var ownerMetadata)); Assert.Same(closed, ownerMetadata);
        var byRef = new MemberRefUser(module, "MakeByRefType", MethodSig.CreateInstance(new ClassSig(typeRef)), typeRef);
        var answer = intrinsic.Invoke(invocation, byRef, [owner.Value]);
        Assert.Equal(StaticExecutionStatus.Completed, answer.Status);
        Assert.Equal(closed.FullName + "&", ReflectionEmitIntrinsic.Signatures(state.Heap, answer.Value)!.FullName);
    }

    [Theory]
    [InlineData("ResolveTypeHandle", false)]
    [InlineData("ResolveTypeHandle", true)]
    [InlineData("ResolveMethodHandle", false)]
    [InlineData("ResolveFieldHandle", true)]
    public void ResolvesOnlyCorrectTokensInTheKnownOwningModule(string operation, bool byReference)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Owner");
            owner.Fields.Add(new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Int32)));
            owner.Methods.Add(new MethodDefUser("Target", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodAttributes.Static)
                { Body = new dnlib.DotNet.Emit.CilBody() });
            owner.Methods[0].Body.Instructions.Add(dnlib.DotNet.Emit.OpCodes.Ret.ToInstruction());
        });
        var type = context.Module.GetTypes().Single(type => type.Name == "Owner");
        IMDTokenProvider target = operation switch
        {
            "ResolveTypeHandle" => type,
            "ResolveMethodHandle" => type.Methods[0],
            _ => type.Fields[0]
        };
        var state = new StaticMachineState(new StaticMachineLimits());
        state.RegisterModuleMetadata(context.Module);
        Assert.True(state.Heap.TryAllocateObject("System.Reflection.Module", out var moduleModel));
        state.Heap.TrySetModelValue(moduleModel, LoaderFrameworkIntrinsic.HomeModuleMark, true);
        var receiver = byReference ? state.Heap.AllocateManagedCell(moduleModel) : moduleModel;
        var handleName = operation == "ResolveTypeHandle" ? "RuntimeTypeHandle" : operation == "ResolveMethodHandle" ? "RuntimeMethodHandle" : "RuntimeFieldHandle";
        var signature = new MemberRefUser(context.Module, operation, MethodSig.CreateInstance(
            new ValueTypeSig(new TypeRefUser(context.Module, "System", handleName, context.Module.CorLibTypes.AssemblyRef)), context.Module.CorLibTypes.Int32),
            new TypeRefUser(context.Module, "System", "ModuleHandle", context.Module.CorLibTypes.AssemblyRef));
        var intrinsic = new LoaderFrameworkIntrinsic();
        var result = intrinsic.Invoke(new IntrinsicContext(state), signature, [receiver, StaticValue.FromInt32(unchecked((int)target.MDToken.Raw))]);
        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.True(state.Heap.TryGetMetadataHandle(result.Value, out var actual));
        Assert.Same(target, actual);
        var invalid = intrinsic.Invoke(new IntrinsicContext(state), signature, [receiver, StaticValue.FromInt32(0x0200FFFF)]);
        Assert.NotEqual(StaticExecutionStatus.Completed, invalid.Status);
        state.Heap.TrySetModelValue(moduleModel, LoaderFrameworkIntrinsic.HomeModuleMark, false);
        var foreign = intrinsic.Invoke(new IntrinsicContext(state), signature, [receiver, StaticValue.FromInt32(unchecked((int)target.MDToken.Raw))]);
        Assert.NotEqual(StaticExecutionStatus.Completed, foreign.Status);
    }
}
