using Cilantro.Core;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Passes;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ParallelDispatcherPathTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ParallelCompletionRetainsSerialBodiesBehaviorAndReportsAcrossRepeatedRuns(bool effects)
    {
        using var serial = Build(effects);
        using var parallel = Build(effects);
        var originals = serial.Module.GlobalType.Methods.Where(m => m.HasBody).ToArray();
        var concurrent = parallel.Module.GlobalType.Methods.Where(m => m.HasBody).ToArray();
        var expected = originals.Select(m => new[] { Run(m, 0), Run(m, 1) }).ToArray();
        var one = new ControlFlowCompletionPass(1);
        var four = new ControlFlowCompletionPass(4);
        for (var round = 0; round < 2; round++)
        {
            var before = one.Run(serial);
            var after = four.Run(parallel);
            Assert.Equal(PassStatus.Success, before.Status);
            Assert.Equal(before.Status, after.Status);
            if (round == 0) Assert.True(before.Changes > 0);
            Assert.Equal(before.Changes, after.Changes);
            Assert.Equal(before.Diagnostics, after.Diagnostics);
            Assert.Equal(serial.Changes, parallel.Changes);
            foreach (var fact in new[] { "cfg.constantBranchesFolded", "cfg.unreachableInstructionsRemoved", "cfg.methodsSimplified" })
            {
                Assert.True(serial.TryGetFact<int>(fact, out var first));
                Assert.True(parallel.TryGetFact<int>(fact, out var second));
                Assert.Equal(first, second);
            }
            for (var index = 0; index < originals.Length; index++)
            {
                Assert.Equal(MethodBodySnapshot.Capture(originals[index]).Fingerprint,
                    MethodBodySnapshot.Capture(concurrent[index]).Fingerprint);
                Assert.Equal(expected[index], new[] { Run(concurrent[index], 0), Run(concurrent[index], 1) });
            }
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void IndependentMethodsRetainSerialBodiesBehaviorAndReportOrder(bool effects)
    {
        using var serial = Build(effects);
        using var parallel = Build(effects);
        var originals = serial.Module.GlobalType.Methods.Where(m => m.HasBody).ToArray();
        var expected = originals.Select(m => new[] { Run(m, 0), Run(m, 1) }).ToArray();
        DispatcherPathPass one = effects ? new EffectfulPass(1) : new DispatcherPathPass(1);
        DispatcherPathPass four = effects ? new EffectfulPass(4) : new DispatcherPathPass(4);
        var before = one.Run(serial);
        var after = four.Run(parallel);
        Assert.Equal(PassStatus.Success, before.Status);
        Assert.Equal(PassStatus.Success, after.Status);
        Assert.True(before.Changes > 0);
        Assert.Equal(before.Changes, after.Changes);
        Assert.Equal(serial.Changes, parallel.Changes);
        Assert.Equal(serial.Evidence, parallel.Evidence);
        var concurrent = parallel.Module.GlobalType.Methods.Where(m => m.HasBody).ToArray();
        for (var index = 0; index < originals.Length; index++)
        {
            Assert.Equal(MethodBodySnapshot.Capture(originals[index]).Fingerprint,
                MethodBodySnapshot.Capture(concurrent[index]).Fingerprint);
            Assert.Equal(expected[index], new[] { Run(concurrent[index], 0), Run(concurrent[index], 1) });
        }
    }

    private static int Run(MethodDef method, int argument)
    {
        var machine = new StaticMachine(new StaticMachineLimits(MaximumSteps: 10000));
        var result = machine.Execute(method, [StaticValue.FromInt32(argument)]);
        Assert.True(result.Succeeded, result.Diagnostic);
        return result.Value.AsInt32();
    }

    private static ArtifactContext Build(bool effects) => SyntheticContext.Build(module =>
    {
        var field = new FieldDefUser("Effect", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
        module.GlobalType.Fields.Add(field);
        for (var number = 0; number < 128; number++)
        {
            var method = new MethodDefUser("Run" + number,
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32), MethodAttributes.Static)
                { Body = new CilBody { InitLocals = true } };
            module.GlobalType.Methods.Add(method);
            var state = new Local(module.CorLibTypes.Int32);
            var temporary = new Local(module.CorLibTypes.Int32);
            var result = new Local(module.CorLibTypes.Int32);
            method.Body.Variables.Add(state); method.Body.Variables.Add(temporary); method.Body.Variables.Add(result);
            var il = method.Body.Instructions;
            var start = OpCodes.Ldarg_0.ToInstruction();
            var alternate = OpCodes.Ldc_I4_1.ToInstruction();
            var dispatch = effects ? OpCodes.Ldsfld.ToInstruction(field) : OpCodes.Nop.ToInstruction();
            var zero = OpCodes.Ldloc.ToInstruction(state);
            var one = OpCodes.Ldloc.ToInstruction(state);
            var exit = OpCodes.Nop.ToInstruction();
            var handler = OpCodes.Ldloc.ToInstruction(result);
            var end = OpCodes.Ldloc.ToInstruction(result);
            Add(start, OpCodes.Brtrue.ToInstruction(alternate), OpCodes.Ldc_I4_0.ToInstruction(),
                OpCodes.Stloc.ToInstruction(state), OpCodes.Br.ToInstruction(dispatch), alternate,
                OpCodes.Stloc.ToInstruction(state), OpCodes.Br.ToInstruction(dispatch), dispatch);
            if (effects) Add(OpCodes.Pop.ToInstruction());
            Add(OpCodes.Ldloc.ToInstruction(state), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Xor.ToInstruction(),
                OpCodes.Stloc.ToInstruction(temporary), OpCodes.Ldloc.ToInstruction(temporary),
                OpCodes.Switch.ToInstruction([zero, one]), OpCodes.Ldc_I4_M1.ToInstruction(),
                OpCodes.Stloc.ToInstruction(result), OpCodes.Br.ToInstruction(exit),
                zero, Instruction.CreateLdcI4(number), OpCodes.Add.ToInstruction(),
                OpCodes.Stloc.ToInstruction(result), OpCodes.Br.ToInstruction(exit),
                one, Instruction.CreateLdcI4(number + 1000), OpCodes.Add.ToInstruction(),
                OpCodes.Stloc.ToInstruction(result), exit);
            if (number % 2 == 0)
            {
                Add(OpCodes.Leave.ToInstruction(end), handler, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Add.ToInstruction(),
                    OpCodes.Stloc.ToInstruction(result), OpCodes.Endfinally.ToInstruction());
                method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Finally)
                    { TryStart = start, TryEnd = handler, HandlerStart = handler, HandlerEnd = end });
            }
            Add(end, OpCodes.Ret.ToInstruction());
            void Add(params Instruction[] instructions) { foreach (var instruction in instructions) il.Add(instruction); }
        }
    });

    private sealed class EffectfulPass(int workers) : DispatcherPathPass(workers)
    {
        protected override bool PreserveEffects => true;
    }
}
