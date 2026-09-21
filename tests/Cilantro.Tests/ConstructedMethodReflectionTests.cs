using Cilantro.Core.Interpretation;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class ConstructedMethodReflectionTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MethodArgumentsBindParameterAndReturnTypesWithoutChangingTheDefinition(bool definition)
    {
        using var module = new ModuleDefUser("Reflection");
        var signature = MethodSig.CreateStaticGeneric(1, new GenericMVar(0), new SZArraySig(new GenericMVar(0)));
        IMethodDefOrRef method;
        if (definition)
        {
            var owner = new TypeDefUser("Tests", "Host", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(owner);
            var declared = new MethodDefUser("Run", signature);
            declared.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            owner.Methods.Add(declared);
            method = declared;
        }
        else
            method = new MemberRefUser(module, "Reverse", signature, module.CorLibTypes.GetTypeRef("System", "Array"));

        foreach (var supplied in new[] { module.CorLibTypes.Byte, module.CorLibTypes.Int32 })
        {
            var instantiated = new MethodSpecUser(method, new GenericInstMethodSig(supplied));
            Check(module, instantiated, supplied.FullName, supplied.FullName + "[]");
        }
        Assert.IsType<GenericMVar>(signature.RetType);
        Assert.IsType<GenericMVar>(signature.Params[0].Next);
    }

    [Fact]
    public void DeclaringTypeAndMethodArgumentsBindIndependentlyInsideWrappedSignatures()
    {
        using var module = new ModuleDefUser("Reflection");
        var owner = new TypeSpecUser(new GenericInstSig(
            new ClassSig(new TypeRefUser(module, "Tests", "Container`1", module.CorLibTypes.AssemblyRef)),
            module.CorLibTypes.String));
        var signature = MethodSig.CreateInstanceGeneric(1, new GenericVar(0),
            new ByRefSig(new GenericVar(0)), new SZArraySig(new GenericMVar(0)));
        var reference = new MemberRefUser(module, "Run", signature, owner);
        Check(module, new MethodSpecUser(reference, new GenericInstMethodSig(module.CorLibTypes.Byte)),
            "System.String", "System.String&", "System.Byte[]");
    }

    private static void Check(ModuleDef module, IMethod described, string returned, params string[] parameters)
    {
        var state = new StaticMachineState(new StaticMachineLimits());
        var heap = state.Heap;
        Assert.True(heap.TryAllocateObject("System.Reflection.MethodInfo", out var model));
        Assert.True(heap.TrySetModelValue(model, "Metadata", described));
        var intrinsic = new LoaderFrameworkIntrinsic();
        StaticValue Query(string name, StaticValue target, string owner)
        {
            var call = new MemberRefUser(module, name, MethodSig.CreateInstance(module.CorLibTypes.Object),
                module.CorLibTypes.GetTypeRef("System.Reflection", owner));
            var result = intrinsic.Invoke(new IntrinsicContext(state), call, [target]);
            Assert.Equal(StaticExecutionStatus.Completed, result.Status);
            return result.Value;
        }
        string TypeName(StaticValue type)
        {
            Assert.True(heap.TryGetModelValue<object>(type, "Metadata", out var metadata));
            return Assert.IsAssignableFrom<TypeSig>(metadata).FullName;
        }
        Assert.Equal(returned, TypeName(Query("get_ReturnType", model, "MethodInfo")));
        var array = Query("GetParameters", model, "MethodBase");
        Assert.True(heap.TryGetLength(array, out var length));
        Assert.Equal(parameters.Length, length);
        for (var index = 0; index < parameters.Length; index++)
        {
            Assert.True(heap.TryReadArray(array, index, out var parameter));
            Assert.Equal(parameters[index], TypeName(Query("get_ParameterType", parameter, "ParameterInfo")));
        }
    }

    [Fact]
    public void ConstructedFrameworkMethodFlagsUseTheGenericDeclaration()
    {
        using var module = new ModuleDefUser("Reflection");
        var signature = MethodSig.CreateStaticGeneric(1, module.CorLibTypes.Void, new SZArraySig(new GenericMVar(0)));
        var reference = new MemberRefUser(module, "Reverse", signature, module.CorLibTypes.GetTypeRef("System", "Array"));
        var state = new StaticMachineState(new StaticMachineLimits());
        Assert.True(state.Heap.TryAllocateObject("System.Reflection.MethodInfo", out var model));
        Assert.True(state.Heap.TrySetModelValue(model, "Metadata",
            new MethodSpecUser(reference, new GenericInstMethodSig(module.CorLibTypes.Byte))));
        foreach (var (name, expected) in new[] { ("get_IsVirtual", 0), ("get_IsStatic", 1), ("get_IsPublic", 1), ("get_IsAbstract", 0) })
        {
            var call = new MemberRefUser(module, name, MethodSig.CreateInstance(module.CorLibTypes.Boolean),
                module.CorLibTypes.GetTypeRef("System.Reflection", "MethodBase"));
            var answer = new LoaderFrameworkIntrinsic().Invoke(new IntrinsicContext(state), call, [model]);
            Assert.Equal(StaticExecutionStatus.Completed, answer.Status);
            Assert.Equal(expected, answer.Value.AsInt32());
        }
        // The non-generic overload has the same name and parameter count. Generic arity
        // distinguishes the declarations even when T[] has no framework FullName.
        Assert.Single(LoaderFrameworkIntrinsic.Framework(reference)!.GetGenericArguments());
        var ordinary = new MemberRefUser(module, "Reverse", MethodSig.CreateStatic(module.CorLibTypes.Void,
            module.CorLibTypes.GetTypeRef("System", "Array").ToTypeSig()), reference.DeclaringType);
        Assert.Empty(LoaderFrameworkIntrinsic.Framework(ordinary)!.GetGenericArguments());
    }
}
