using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Passes;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DispatcherTemporaryStateTests
{
    [Theory]
    [InlineData("temporary", true)]
    [InlineData("overwrite-state", true)]
    [InlineData("two-temporaries", true)]
    [InlineData("shared-store", true)]
    [InlineData("computed-store", true)]
    [InlineData("address", false)]
    [InlineData("unknown", false)]
    [InlineData("call", true)]
    [InlineData("division-by-zero", false)]
    public void ThreadedPathsPreserveAllWrittenLocalsAndSelectedBehavior(string scenario, bool rewrites)
    {
        using var module = new ModuleDefUser("temporary-dispatch");
        var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32), MethodAttributes.Static)
        { Body = new CilBody { InitLocals = true } }; module.GlobalType.Methods.Add(method);
        var state = new Local(module.CorLibTypes.Int32);
        var temporary = new Local(module.CorLibTypes.Int32);
        var extra = new Local(module.CorLibTypes.Int32);
        method.Body.Variables.Add(state); method.Body.Variables.Add(temporary); method.Body.Variables.Add(extra);
        var other = OpCodes.Ldc_I4_1.ToInstruction();
        var dispatch = OpCodes.Ldloc.ToInstruction(state);
        var zero = OpCodes.Ldloc.ToInstruction(state);
        var one = OpCodes.Ldloc.ToInstruction(state);
        var sharedStore = OpCodes.Stloc.ToInstruction(state);
        var entry = scenario == "shared-store" ? sharedStore : dispatch;
        Add(OpCodes.Ldarg_0.ToInstruction(), OpCodes.Brtrue.ToInstruction(other), OpCodes.Ldc_I4_0.ToInstruction());
        SourceTail();
        Add(other);
        SourceTail();
        if (scenario == "shared-store") Add(sharedStore);
        Add(dispatch, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Xor.ToInstruction(), OpCodes.Stloc.ToInstruction(temporary));
        if (scenario == "address")
        { method.Body.Instructions.Insert(0, OpCodes.Ldloca.ToInstruction(temporary)); method.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction()); }
        if (scenario == "unknown")
        { dispatch.OpCode = OpCodes.Ldloc; dispatch.Operand = extra; }
        if (scenario == "overwrite-state") Add(OpCodes.Ldc_I4.ToInstruction(27), OpCodes.Stloc.ToInstruction(state));
        if (scenario == "two-temporaries") Add(OpCodes.Ldloc.ToInstruction(temporary), OpCodes.Ldc_I4.ToInstruction(19), OpCodes.Add.ToInstruction(), OpCodes.Stloc.ToInstruction(extra));
        if (scenario == "call")
        {
            var effect = new FieldDefUser("Effect", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static); module.GlobalType.Fields.Add(effect);
            var call = new MethodDefUser("Effect", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodAttributes.Static) { Body = new CilBody() }; module.GlobalType.Methods.Add(call);
            foreach (var i in new[] { OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(effect), OpCodes.Ret.ToInstruction() }) call.Body.Instructions.Add(i);
            Add(OpCodes.Call.ToInstruction(call));
        }
        if (scenario == "division-by-zero") Add(OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Div.ToInstruction(), OpCodes.Pop.ToInstruction());
        Add(OpCodes.Ldloc.ToInstruction(temporary), OpCodes.Switch.ToInstruction([zero, one]), OpCodes.Ldc_I4_M1.ToInstruction(), OpCodes.Ret.ToInstruction(),
            zero, OpCodes.Ldc_I4.ToInstruction(100), OpCodes.Mul.ToInstruction(), OpCodes.Ldloc.ToInstruction(temporary), OpCodes.Add.ToInstruction(),
            OpCodes.Ldloc.ToInstruction(extra), OpCodes.Add.ToInstruction(), OpCodes.Ret.ToInstruction(),
            one, OpCodes.Ldc_I4.ToInstruction(200), OpCodes.Mul.ToInstruction(), OpCodes.Ldloc.ToInstruction(temporary), OpCodes.Add.ToInstruction(),
            OpCodes.Ldloc.ToInstruction(extra), OpCodes.Add.ToInstruction(), OpCodes.Ret.ToInstruction());
        var before = new[] { Execute(0), Execute(1) };
        if (rewrites)
        {
            Assert.All(before, result => Assert.Equal(StaticExecutionStatus.Completed, result.Status));
            var expected = scenario switch
            {
                "overwrite-state" => new[] { 5401, 2700 },
                "two-temporaries" => new[] { 21, 119 },
                _ => new[] { 1, 100 }
            };
            Assert.Equal(expected.Select(StaticValue.FromInt32), before.Select(result => result.Value));
        }
        var changes = DispatcherPathPass.Rewrite(method, preserveEffects: true);
        Assert.Equal(rewrites ? 1 : 0, changes);
        Assert.Equal(before, new[] { Execute(0), Execute(1) });
        Assert.True(EvaluationStackAnalyzer.Analyze(method).Valid);
        if (rewrites)
        {
            for (var round = 0; round < 8; round++)
            {
                var count = DispatcherPathPass.Rewrite(method, preserveEffects: true);
                ControlFlowCompletionPass.TryComplete(method);
                if (count == 0) break;
            }
            Assert.DoesNotContain(method.Body.Instructions, i => i.OpCode.Code == Code.Switch);
            Assert.Equal(before, new[] { Execute(0), Execute(1) });
        }

        void Add(params Instruction[] instructions) { foreach (var i in instructions) method.Body.Instructions.Add(i); }
        void SourceTail()
        {
            if (scenario == "computed-store") Add(OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Add.ToInstruction());
            if (scenario != "shared-store") Add(OpCodes.Stloc.ToInstruction(state));
            Add(OpCodes.Br.ToInstruction(entry));
        }
        (StaticExecutionStatus Status, StaticValue Value, StaticValue Effect) Execute(int argument)
        {
            var machine = new StaticMachine();
            var result = machine.Execute(method, [StaticValue.FromInt32(argument)]);
            var effect = module.GlobalType.Fields.SingleOrDefault();
            return (result.Status, result.Value, effect is null ? StaticValue.Null : machine.State.ReadStaticField(effect));
        }
    }
}
