using Cilantro.Core.Interpretation;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class GenericTypeConstructionTests
{
    public sealed class OracleBox<T>;
    public sealed class OracleForeign<T>;

    [Theory]
    [InlineData("int", false)]
    [InlineData("string", false)]
    [InlineData("array", false)]
    [InlineData("parameter", false)]
    [InlineData("foreign-parameter", false)]
    [InlineData("int", true)]
    [InlineData("parameter", true)]
    public void ConstructedTypesAndDefinitionsAnswerLikeTheClr(string argumentKind, bool wrap)
    {
        using var module = new ModuleDefUser("Generic");
        var owner = Owner(module); var variable = new GenericVar(0, owner);
        var foreign = new TypeDefUser("Probe", "Foreign`1", module.CorLibTypes.Object.TypeDefOrRef); module.Types.Add(foreign);
        foreign.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "U"));
        TypeSig argument = argumentKind switch
        {
            "int" => module.CorLibTypes.Int32,
            "string" => module.CorLibTypes.String,
            "array" => new SZArraySig(module.CorLibTypes.Int32),
            "foreign-parameter" => new GenericVar(0, foreign),
            _ => variable
        };
        var runtimeArgument = argumentKind switch
        {
            "int" => typeof(int), "string" => typeof(string), "array" => typeof(int[]),
            "foreign-parameter" => typeof(OracleForeign<>).GetGenericArguments()[0],
            _ => typeof(OracleBox<>).GetGenericArguments()[0]
        };
        var oracle = typeof(OracleBox<>).MakeGenericType(runtimeArgument);
        var state = new StaticMachine().State; var heap = state.Heap;
        var definition = Model(heap, owner);
        Assert.True(heap.TryAllocateArray(null, 1, out var packed)); heap.TryWriteArray(packed, 0, Model(heap, argument));
        var result = Call(module, state, "MakeGenericType", [definition, packed]);
        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        var signature = new GenericInstSig(new ClassSig(owner), argument);
        var actual = ReflectionEmitIntrinsic.Signatures(heap, result.Value);
        Assert.True(new SigComparer().Equals(oracle.IsGenericTypeDefinition ? (TypeSig)new ClassSig(owner) : signature, actual));
        var reflected = wrap ? Model(heap, new TypeSpecUser(signature)) : result.Value;
        foreach (var property in new[] { "IsGenericType", "IsGenericTypeDefinition", "ContainsGenericParameters" })
        {
            var answer = Call(module, state, "get_" + property, [reflected]);
            Assert.Equal(StaticExecutionStatus.Completed, answer.Status);
            Assert.Equal((bool)typeof(Type).GetProperty(property)!.GetValue(oracle)!, answer.Value.AsInt32() != 0);
        }
        var template = Call(module, state, "GetGenericTypeDefinition", [reflected]);
        Assert.Equal(StaticExecutionStatus.Completed, template.Status);
        foreach (var property in new[] { "IsGenericType", "IsGenericTypeDefinition", "ContainsGenericParameters" })
        {
            var answer = Call(module, state, "get_" + property, [template.Value]);
            Assert.Equal(StaticExecutionStatus.Completed, answer.Status); Assert.Equal(1, answer.Value.AsInt32());
        }
        var parameters = Call(module, state, "GetGenericArguments", [template.Value]);
        Assert.Equal(StaticExecutionStatus.Completed, parameters.Status);
        Assert.True(heap.TryGetLength(parameters.Value, out var count)); Assert.Equal(1, count);
        Assert.True(heap.TryReadArray(parameters.Value, 0, out var item)); Assert.IsType<GenericVar>(ReflectionEmitIntrinsic.Signatures(heap, item));
        var again = Call(module, state, "GetGenericTypeDefinition", [template.Value]);
        Assert.Equal(StaticExecutionStatus.Completed, again.Status);
        Assert.True(new SigComparer().Equals(ReflectionEmitIntrinsic.Signatures(heap, template.Value), ReflectionEmitIntrinsic.Signatures(heap, again.Value)));
    }

    [Theory]
    [InlineData("count")]
    [InlineData("constructed")]
    [InlineData("nongeneric")]
    [InlineData("unknown-definition")]
    [InlineData("unknown-argument")]
    [InlineData("reference-constraint")]
    [InlineData("value-constraint")]
    [InlineData("constructor-constraint")]
    [InlineData("base-constraint")]
    [InlineData("void")]
    [InlineData("byref")]
    [InlineData("pointer")]
    [InlineData("typedref")]
    [InlineData("pinned")]
    [InlineData("invalid-array-element")]
    [InlineData("byreflike")]
    public void InvalidOrUnprovedConstructionsAreRefused(string scenario)
    {
        using var module = new ModuleDefUser("Generic"); var owner = Owner(module);
        var attributes = scenario switch
        {
            "reference-constraint" => GenericParamAttributes.ReferenceTypeConstraint,
            "value-constraint" => GenericParamAttributes.NotNullableValueTypeConstraint,
            "constructor-constraint" => GenericParamAttributes.DefaultConstructorConstraint,
            _ => GenericParamAttributes.NonVariant
        };
        owner.GenericParameters[0].Flags = attributes;
        if (scenario == "base-constraint") owner.GenericParameters[0].GenericParamConstraints.Add(new GenericParamConstraintUser(module.CorLibTypes.Object.TypeDefOrRef));
        if (scenario == "nongeneric") owner.GenericParameters.Clear();
        var state = new StaticMachine().State; var heap = state.Heap;
        var definition = scenario == "unknown-definition" ? StaticValue.Null : Model(heap, scenario == "constructed"
            ? (object)new GenericInstSig(new ClassSig(owner), module.CorLibTypes.Int32) : owner);
        TypeSig argument = scenario switch
        {
            "void" => module.CorLibTypes.Void,
            "byref" => new ByRefSig(module.CorLibTypes.Int32),
            "pointer" => new PtrSig(module.CorLibTypes.Int32),
            "typedref" => module.CorLibTypes.TypedReference,
            "pinned" => new PinnedSig(module.CorLibTypes.Int32),
            "invalid-array-element" => new SZArraySig(new ByRefSig(module.CorLibTypes.Int32)),
            _ => module.CorLibTypes.Int32
        };
        if (scenario == "byreflike")
        {
            var refLike = new TypeDefUser("Probe", "RefLike", module.CorLibTypes.GetTypeRef("System", "ValueType")); module.Types.Add(refLike);
            refLike.CustomAttributes.Add(new CustomAttribute(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void),
                module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "IsByRefLikeAttribute"))));
            argument = new ValueTypeSig(refLike);
        }
        Assert.True(heap.TryAllocateArray(null, scenario == "count" ? 0 : 1, out var packed));
        if (scenario != "count") heap.TryWriteArray(packed, 0, scenario == "unknown-argument" ? StaticValue.Null : Model(heap, argument));
        Assert.NotEqual(StaticExecutionStatus.Completed, Call(module, state, "MakeGenericType", [definition, packed]).Status);
    }

    private static TypeDefUser Owner(ModuleDef module)
    {
        var owner = new TypeDefUser("Probe", "Box`1", module.CorLibTypes.Object.TypeDefOrRef); module.Types.Add(owner);
        owner.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T")); return owner;
    }

    private static StaticValue Model(StaticHeap heap, object metadata)
    {
        Assert.True(heap.TryAllocateObject("System.Type", out var model)); heap.TrySetModelValue(model, "Metadata", metadata); return model;
    }

    private static IntrinsicResult Call(ModuleDef module, StaticMachineState state, string operation, IReadOnlyList<StaticValue> arguments)
    {
        var method = typeof(Type).GetMethods().Single(method => method.Name == operation && method.GetParameters().Length == (operation == "MakeGenericType" ? 1 : 0));
        return new LoaderFrameworkIntrinsic().Invoke(new(state), new Importer(module).Import(method), arguments);
    }
}
