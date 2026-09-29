using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class FrameworkCallbackBindingTests
{
    [Fact]
    public void OpenFrameworkCallbacksUseTheSequenceElementAsReceiver()
    {
        using var module = new ModuleDefUser("callbacks");
        var machine = new StaticMachine();
        machine.State.RegisterModuleMetadata(module);
        var heap = machine.State.Heap;
        Assert.True(heap.TryAllocateString("sample", out var element));
        var method = new MemberRefUser(module, "ToUpperInvariant", MethodSig.CreateInstance(module.CorLibTypes.String),
            module.CorLibTypes.String.TypeDefOrRef);
        var result = Select(machine, module, method, element, StaticValue.Null, true);
        Assert.True(result.Status == StaticExecutionStatus.Completed, result.Diagnostic);
        Assert.True(heap.TryReadArray(result.Value, 0, out var answer));
        var oracle = typeof(string).GetMethod(nameof(string.ToUpperInvariant), Type.EmptyTypes)!.CreateDelegate<Func<string, string>>();
        Assert.True(heap.TryGetString(answer, out var text));
        Assert.Equal(oracle("sample"), text);
    }

    [Theory]
    [InlineData("open", false)]
    [InlineData("closed", false)]
    [InlineData("static", false)]
    [InlineData("open", true)]
    public void ManagedCallbacksPreserveBindingAndExceptions(string binding, bool throws)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Target");
            var field = new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Public);
            owner.Fields.Add(field);
            var signature = binding == "open" ? MethodSig.CreateInstance(module.CorLibTypes.Object) :
                binding == "closed" ? MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.Object) :
                MethodSig.CreateStatic(module.CorLibTypes.Object, owner.ToTypeSig());
            var method = new MethodDefUser("Read", signature)
                { Attributes = binding == "static" ? MethodAttributes.Static : MethodAttributes.Public, Body = new CilBody() };
            owner.Methods.Add(method);
            if (throws)
            {
                method.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
                method.Body.Instructions.Add(OpCodes.Throw.ToInstruction());
            }
            else
            {
                method.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                method.Body.Instructions.Add(OpCodes.Ldfld.ToInstruction(field));
                method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            }
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single();
        var field = method.DeclaringType.Fields.Single();
        var machine = new StaticMachine();
        machine.State.RegisterModuleMetadata(context.Module);
        var heap = machine.State.Heap;
        Assert.True(heap.TryAllocateObject(method.DeclaringType.FullName, out var element));
        Assert.True(heap.TryAllocateString("element", out var elementValue));
        Assert.True(heap.TryWriteField(element, field, elementValue));
        Assert.True(heap.TryAllocateObject(method.DeclaringType.FullName, out var receiver));
        Assert.True(heap.TryAllocateString("stored", out var receiverValue));
        Assert.True(heap.TryWriteField(receiver, field, receiverValue));
        var result = Select(machine, context.Module, method, element, receiver, binding == "open");
        Assert.True(result.Status == (throws ? StaticExecutionStatus.Threw : StaticExecutionStatus.Completed), result.Diagnostic);
        if (!throws)
        {
            Assert.True(heap.TryReadArray(result.Value, 0, out var answer));
            Assert.True(heap.TryGetString(answer, out var text));
            Assert.Equal(binding == "closed" ? "stored" : "element", text);
        }
    }

    private static StaticExecutionResult Select(StaticMachine machine, ModuleDef module, IMethod method,
        StaticValue element, StaticValue receiver, bool open)
    {
        var heap = machine.State.Heap;
        Assert.True(heap.TryAllocateArray(module.CorLibTypes.Object, 1, out var sequence));
        Assert.True(heap.TryWriteArray(sequence, 0, element));
        Assert.True(heap.TryAllocateObject("Callback", out var callback));
        Assert.True(heap.TrySetModelValue(callback, StaticMachine.DelegateMethodKey, method));
        Assert.True(heap.TrySetModelValue(callback, StaticMachine.DelegateTargetKey, receiver));
        Assert.True(heap.TrySetModelValue(callback, StaticMachine.DelegateOpenKey, open));
        var select = new MemberRefUser(module, "Select", MethodSig.CreateStatic(module.CorLibTypes.Object,
            module.CorLibTypes.Object, module.CorLibTypes.Object), module.CorLibTypes.GetTypeRef("System.Linq", "Enumerable"));
        return machine.Invoke(select, [sequence, callback]);
    }
}
