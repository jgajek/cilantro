using Cilantro.Core;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class GenericDefaultStateTests
{
    [Fact]
    public void GenericReferenceDefaultsAreNullForStaticsInstancesArraysAndLocals()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Owner");
            var type = new GenericInstSig(new ClassSig(module.CorLibTypes.GetTypeRef("System.Collections.Generic", "List`1")), module.CorLibTypes.String);
            owner.Fields.Add(new FieldDefUser("Static", new FieldSig(type), FieldAttributes.Static));
            owner.Fields.Add(new FieldDefUser("Instance", new FieldSig(type)));
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(type), MethodImplAttributes.IL, MethodAttributes.Static)
                { Body = new CilBody { InitLocals = true } };
            run.Body.Variables.Add(new Local(type));
            run.Body.Instructions.Add(OpCodes.Ldloc_0.ToInstruction());
            run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            owner.Methods.Add(run);
        });
        var owner = context.Module.GetTypes().Single(t => t.Name == "Owner");
        var state = new StaticMachineState(new StaticMachineLimits());
        Assert.Equal(StaticValue.Null, state.ReadStaticField(owner.Fields[0]));
        Assert.True(state.Heap.TryAllocateObject(owner.FullName, out var instance));
        Assert.True(state.Heap.TryReadField(instance, owner.Fields[1], out var field));
        Assert.Equal(StaticValue.Null, field);
        Assert.True(state.Heap.TryAllocateArray(owner.Fields[0].FieldSig.Type, 1, out var array));
        Assert.Equal(StaticValue.Null, Assert.Single(state.Heap.GetArraySnapshot(array)!));
        Assert.True(BootstrapMachine.TrySeed(context, 1000, out var machine, out _));
        var result = machine!.Execute(owner.Methods.Single());
        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(StaticValue.Null, result.Value);
    }
}
