using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Passes;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class StackConstantPropagationTests
{
    private static readonly int[] Flags = [0, 1];
    [Theory]
    [InlineData(7, true)]
    [InlineData(8, false)]
    public void CarriedConstantsRequireEveryIncomingPathToAgree(int alternateValue, bool folds)
    {
        using var module = new ModuleDefUser("stack-join");
        var method = Method(module);
        var local = method.Body.Variables[0];
        var alternate = Instruction.CreateLdcI4(alternateValue);
        var store = OpCodes.Stloc.ToInstruction(local);
        var read = OpCodes.Ldloc.ToInstruction(local);
        Add(method, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Brtrue.ToInstruction(alternate),
            Instruction.CreateLdcI4(7), OpCodes.Br.ToInstruction(store), alternate,
            store, read, OpCodes.Ret.ToInstruction());
        Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);
        LocalConstantPropagation.Fold(method);
        Assert.Equal(folds, read.IsLdcI4());
        foreach (var flag in Flags)
            Assert.Equal(StaticValue.FromInt32(flag == 0 ? 7 : alternateValue),
                new StaticMachine().Execute(method, [StaticValue.FromInt32(flag)]).Value);
    }

    [Fact]
    public void LoopBackEdgeInvalidatesCarriedConstant()
    {
        using var module = new ModuleDefUser("stack-loop");
        var method = Method(module);
        var store = OpCodes.Stloc.ToInstruction(method.Body.Variables[0]);
        var read = OpCodes.Ldloc.ToInstruction(method.Body.Variables[0]);
        var exit = OpCodes.Ret.ToInstruction();
        Add(method, Instruction.CreateLdcI4(7), OpCodes.Br.ToInstruction(store), store, read,
            OpCodes.Ldarg_0.ToInstruction(), OpCodes.Brfalse.ToInstruction(exit),
            Instruction.CreateLdcI4(1), OpCodes.Add.ToInstruction(), OpCodes.Br.ToInstruction(store), exit);
        Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);
        LocalConstantPropagation.Fold(method);
        Assert.True(read.IsLdloc());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RemovingDispatcherPreservesCallsAndBothGuardOutcomes(bool throwing)
    {
        using var module = new ModuleDefUser("stack-effects");
        var method = Method(module);
        var helper = new MethodDefUser("Effect", MethodSig.CreateStatic(module.CorLibTypes.Void))
        { Attributes = MethodAttributes.Static, Body = new CilBody() };
        module.GlobalType.Methods.Add(helper);
        var effect = new FieldDefUser("EffectCount", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
        module.GlobalType.Fields.Add(effect);
        Add(helper, Instruction.CreateLdcI4(19), OpCodes.Stsfld.ToInstruction(effect));
        if (throwing) Add(helper, OpCodes.Ldnull.ToInstruction(), OpCodes.Throw.ToInstruction());
        else Add(helper, OpCodes.Ret.ToInstruction());
        var local = method.Body.Variables[0];
        var alternate = OpCodes.Nop.ToInstruction();
        var store = OpCodes.Stloc.ToInstruction(local);
        var target = Instruction.CreateLdcI4(42);
        Add(method, Instruction.CreateLdcI4(0), OpCodes.Call.ToInstruction(helper),
            OpCodes.Ldarg_0.ToInstruction(), OpCodes.Brtrue.ToInstruction(alternate),
            OpCodes.Br.ToInstruction(store), alternate, OpCodes.Br.ToInstruction(store), store,
            OpCodes.Ldloc.ToInstruction(local), OpCodes.Switch.ToInstruction(new[] { target }),
            Instruction.CreateLdcI4(99), OpCodes.Ret.ToInstruction(), target, OpCodes.Ret.ToInstruction());
        var before = Flags.Select(Run).ToArray();
        Assert.NotNull(ControlFlowCompletionPass.TryComplete(method));
        Assert.DoesNotContain(method.Body.Instructions, i => i.OpCode.Code == Code.Switch);
        Assert.Contains(method.Body.Instructions, i => i.Operand == helper);
        foreach (var flag in Flags) Assert.Equal(before[flag], Run(flag));

        (StaticExecutionStatus, StaticValue, StaticValue) Run(int flag)
        {
            var machine = new StaticMachine();
            var result = machine.Execute(method, [StaticValue.FromInt32(flag)]);
            return (result.Status, result.Value, machine.State.ReadStaticField(effect));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ConstantBelowFieldReadDoesNotRemoveTheReadOrItsNullFailure(bool nullReceiver)
    {
        using var module = new ModuleDefUser("stack-field");
        var owner = new TypeDefUser("Owner", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(owner);
        var field = new FieldDefUser("Guard", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Public);
        owner.Fields.Add(field);
        var method = Method(module);
        method.MethodSig = MethodSig.CreateStatic(module.CorLibTypes.Int32, owner.ToTypeSig());
        var local = method.Body.Variables[0];
        var store = OpCodes.Stloc.ToInstruction(local);
        var read = OpCodes.Ldloc.ToInstruction(local);
        Add(method, Instruction.CreateLdcI4(7), OpCodes.Ldarg_0.ToInstruction(),
            OpCodes.Ldfld.ToInstruction(field), OpCodes.Pop.ToInstruction(),
            OpCodes.Br.ToInstruction(store), store, read, OpCodes.Ret.ToInstruction());
        var before = Run();
        Assert.Equal(1, LocalConstantPropagation.Fold(method));
        Assert.Equal(7, read.GetLdcI4Value());
        Assert.Contains(method.Body.Instructions, i => i.OpCode.Code == Code.Ldfld);
        Assert.Equal(before, Run());

        (StaticExecutionStatus, StaticValue) Run()
        {
            var machine = new StaticMachine();
            var receiver = StaticValue.Null;
            if (!nullReceiver) Assert.True(machine.State.Heap.TryAllocateObject(owner.FullName, out receiver));
            var result = machine.Execute(method, [receiver]);
            return (result.Status, result.Value);
        }
    }

    private static MethodDefUser Method(ModuleDef module)
    {
        var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Boolean))
        { Attributes = MethodAttributes.Static, Body = new CilBody() };
        method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
        module.GlobalType.Methods.Add(method);
        return method;
    }

    private static void Add(MethodDef method, params Instruction[] instructions)
    { foreach (var instruction in instructions) method.Body.Instructions.Add(instruction); }
}
