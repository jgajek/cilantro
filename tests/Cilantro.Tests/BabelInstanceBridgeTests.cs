using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class BabelInstanceBridgeTests
{
    [Theory]
    [InlineData("closed", true)]
    [InlineData("external", false)]
    [InlineData("ambiguous", false)]
    [InlineData("wrong-argument", false)]
    [InlineData("abstract", false)]
    public void ActivatorIsLimitedToUnambiguousEmittedReferenceConstructors(string scenario, bool accepted)
    {
        using var module = new ModuleDefUser("Bridge");
        var type = new TypeDefUser("Emitted", "Bridge", module.CorLibTypes.Object.TypeDefOrRef) { Attributes = TypeAttributes.Public };
        module.Types.Add(type);
        var field = new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Object)); type.Fields.Add(field);
        var constructor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, scenario == "wrong-argument" ?
            new ClassSig(module.CorLibTypes.GetTypeRef("System", "Type")) : module.CorLibTypes.Object),
            MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() };
        constructor.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); type.Methods.Add(constructor);
        if (scenario == "abstract") type.Attributes |= TypeAttributes.Abstract;
        if (scenario == "ambiguous")
        {
            var other = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String), MethodImplAttributes.IL, constructor.Attributes) { Body = new CilBody() };
            other.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); type.Methods.Add(other);
        }
        var state = new StaticMachine().State;
        if (scenario != "external") state.RegisterAssembledModule(module);
        var heap = state.Heap;
        Assert.True(heap.TryAllocateObject("System.Type", out var metadata)); heap.TrySetModelValue(metadata, "Metadata", (TypeDef)type);
        Assert.True(heap.TryAllocateString("value", out var value)); Assert.True(heap.TryAllocateArray(module.CorLibTypes.Object, 1, out var packed));
        heap.TryWriteArray(packed, 0, value);
        var calls = 0;
        var context = new IntrinsicContext(state, Call: (called, arguments) =>
        {
            calls++; Assert.Same(constructor, called); Assert.Equal(value, arguments[1]);
            heap.TryWriteField(arguments[0], field, arguments[1]); return IntrinsicResult.Completed();
        });
        var api = new MemberRefUser(module, "CreateInstance", MethodSig.CreateStatic(module.CorLibTypes.Object,
            new ClassSig(module.CorLibTypes.GetTypeRef("System", "Type")), new SZArraySig(module.CorLibTypes.Object)), module.CorLibTypes.GetTypeRef("System", "Activator"));
        var registry = new RawDynamicMethodIntrinsic();
        var result = registry.Invoke(context, api, [metadata, packed]);
        Assert.Equal(accepted, result.Status == StaticExecutionStatus.Completed);
        Assert.Equal(accepted ? 1 : 0, calls);
        if (!accepted) return;
        Assert.True(heap.TryReadField(result.Value, field, out var stored)); Assert.Equal(value, stored);
        var getType = new MemberRefUser(module, "GetType", MethodSig.CreateInstance(new ClassSig(module.CorLibTypes.GetTypeRef("System", "Type"))), module.CorLibTypes.Object.TypeDefOrRef);
        Assert.Equal(metadata, registry.Invoke(context, getType, [result.Value]).Value);
        Assert.Equal(metadata, registry.Invoke(context, getType, [result.Value]).Value);
        var next = registry.Invoke(context, api, [metadata, packed]); Assert.NotEqual(result.Value, next.Value); Assert.Equal(2, calls);
    }

    [Theory]
    [InlineData("closed", true)]
    [InlineData("external", false)]
    [InlineData("binder", false)]
    [InlineData("wrong-receiver", false)]
    [InlineData("wrong-argument", false)]
    [InlineData("flags", false)]
    [InlineData("private", false)]
    public void InvokeMemberUsesOnlyAnExactEmittedInstanceBinding(string scenario, bool accepted)
    {
        using var module = new ModuleDefUser("Bridge");
        var type = new TypeDefUser("Emitted", "Bridge", module.CorLibTypes.Object.TypeDefOrRef); module.Types.Add(type);
        var echo = new MethodDefUser("Echo", MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.String),
            MethodImplAttributes.IL, scenario == "private" ? MethodAttributes.Private : MethodAttributes.Public) { Body = new CilBody() };
        echo.Body.Instructions.Add(OpCodes.Ldarg_1.ToInstruction()); echo.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); type.Methods.Add(echo);
        var state = new StaticMachine().State; if (scenario != "external") state.RegisterAssembledModule(module);
        var heap = state.Heap;
        Assert.True(heap.TryAllocateObject("System.Type", out var metadata)); heap.TrySetModelValue(metadata, "Metadata", (TypeDef)type);
        Assert.True(heap.TryAllocateString("Echo", out var name)); Assert.True(heap.TryAllocateString("value", out var value));
        Assert.True(heap.TryAllocateObject(scenario == "wrong-receiver" ? "Other" : type.FullName, out var receiver));
        Assert.True(heap.TryAllocateObject("Other", out var other)); Assert.True(heap.TryAllocateArray(module.CorLibTypes.Object, 1, out var packed));
        heap.TryWriteArray(packed, 0, scenario == "wrong-argument" ? other : value);
        var calls = 0;
        var context = new IntrinsicContext(state, Call: (called, arguments) =>
        {
            calls++; Assert.Same(echo, called); Assert.Equal(receiver, arguments[0]); Assert.Equal(value, arguments[1]);
            return IntrinsicResult.Completed(value);
        });
        var api = new Importer(module).Import(typeof(Type).GetMethod("InvokeMember", [typeof(string), typeof(System.Reflection.BindingFlags), typeof(System.Reflection.Binder), typeof(object), typeof(object[])])!);
        var result = new RawDynamicMethodIntrinsic().Invoke(context, api,
            [metadata, name, StaticValue.FromInt32(scenario == "flags" ? 1024 : 256), scenario == "binder" ? other : StaticValue.Null, receiver, packed]);
        Assert.Equal(accepted, result.Status == StaticExecutionStatus.Completed); Assert.Equal(accepted ? 1 : 0, calls);
        if (accepted) Assert.Equal(value, result.Value);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AModeledDelegateCanBeCastToItsFrameworkBase(bool bound)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var method = new MethodDefUser("Cast", MethodSig.CreateStatic(module.CorLibTypes.Object, module.CorLibTypes.Object),
                MethodImplAttributes.IL, MethodAttributes.Static | MethodAttributes.Public) { Body = new CilBody() };
            method.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            method.Body.Instructions.Add(OpCodes.Castclass.ToInstruction(module.CorLibTypes.GetTypeRef("System", "Delegate")));
            method.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); module.GlobalType.Methods.Add(method);
        });
        var machine = new StaticMachine(); machine.State.RegisterModuleMetadata(context.Module);
        var method = context.Module.GlobalType.Methods.Single(method => method.Name == "Cast");
        Assert.True(machine.State.Heap.TryAllocateObject("<emitted>.Delegate", out var value));
        if (bound) machine.State.Heap.TrySetModelValue(value, StaticMachine.DelegateMethodKey, (IMethod)method);
        var result = machine.Execute(method, [value]); Assert.Equal(bound, result.Succeeded);
        if (bound) Assert.Equal(value, result.Value);
    }

    [Theory]
    [InlineData("System.Collections.Generic.List`1<System.Int32>", true)]
    [InlineData("System.Collections.Generic.List`1<System.String>", false)]
    [InlineData("CustomCollection", false)]
    public void CollectionInterfaceAddsRequireTheMatchingConcreteList(string runtimeType, bool accepted)
    {
        using var module = new ModuleDefUser("Collection");
        var type = new TypeSpecUser(new GenericInstSig(new ClassSig(module.CorLibTypes.GetTypeRef("System.Collections.Generic", "ICollection`1")), module.CorLibTypes.Int32));
        var add = new MemberRefUser(module, "Add", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Int32), type);
        var state = new StaticMachine().State; var heap = state.Heap;
        Assert.True(heap.TryAllocateObject(runtimeType, out var receiver)); var items = new List<StaticValue>(); heap.TrySetModelValue(receiver, "Items", items);
        var model = new GenericListIntrinsic(); Assert.True(model.Matches(add));
        var result = model.Invoke(new(state), add, [receiver, StaticValue.FromInt32(7)]);
        Assert.Equal(accepted, result.Status == StaticExecutionStatus.Completed); Assert.Equal(accepted ? 1 : 0, items.Count);
    }
}
