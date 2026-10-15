using Cilantro.Core.Analysis;
using Cilantro.Core;
using Cilantro.Core.Passes;
using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class BranchThreadingTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void BypassesLongChainsAndPreservesSwitchTargets(bool padding)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Owner");
            var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(method);
            var result = OpCodes.Ldc_I4_1.ToInstruction();
            var chain = Enumerable.Range(0, 100).Select(_ => OpCodes.Br.ToInstruction(result)).ToArray();
            var nops = chain.Select(_ => OpCodes.Nop.ToInstruction()).ToArray();
            for (var at = 0; at < chain.Length - 1; at++) chain[at].Operand = padding ? nops[at + 1] : chain[at + 1];
            method.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            method.Body.Instructions.Add(OpCodes.Switch.ToInstruction(new[] { chain[0], chain[20] }));
            method.Body.Instructions.Add(OpCodes.Br.ToInstruction(chain[0]));
            for (var at = 0; at < chain.Length; at++)
            {
                if (padding) method.Body.Instructions.Add(nops[at]);
                method.Body.Instructions.Add(chain[at]);
            }
            method.Body.Instructions.Add(result);
            method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single();
        var il = method.Body.Instructions;
        var targets = ((IList<Instruction>)il[1].Operand).ToArray();
        var destination = il[^2];
        Assert.Equal(100, RedundantControlFlow.ThreadBranches(method));
        Assert.Equal(targets, (IList<Instruction>)il[1].Operand);
        Assert.All(il.Where(i => i.OpCode.Code is Code.Br or Code.Br_S), i => Assert.Same(destination, i.Operand));
        Assert.Equal(0, RedundantControlFlow.ThreadBranches(method));
        Assert.Equal(PassStatus.Success, new BranchCompletionPass().Run(context).Status);
        Assert.Equal(0, new BranchCompletionPass().Run(context).Changes);
        foreach (var argument in new[] { -1, 0, 1, 9 })
            Assert.Equal(1, new StaticMachine().Execute(method, [StaticValue.FromInt32(argument)]).Value.AsInt32());
        using var bytes = new MemoryStream(); context.Module.Write(bytes);
    }

    [Fact]
    public void FinalBranchCleanupFollowsLateTypingAndPrecedesRenaming()
    {
        var passes = CilantroPipeline.CreateDefaultPasses().Select(p => p.Name).ToList();
        Assert.True(passes.IndexOf("branch-completion") > passes.IndexOf("type-recovery-completion"));
        Assert.True(passes.IndexOf("branch-completion") < passes.IndexOf("symbol-renaming"));
    }

    [Fact]
    public void LeavesBranchOnlyCyclesIntact()
    {
        var method = new MethodDefUser { Body = new CilBody() };
        var first = OpCodes.Nop.ToInstruction();
        var second = OpCodes.Br.ToInstruction(first);
        first.OpCode = OpCodes.Br; first.Operand = second;
        method.Body.Instructions.Add(first); method.Body.Instructions.Add(second);
        Assert.Equal(0, RedundantControlFlow.ThreadBranches(method));
        Assert.Same(second, first.Operand); Assert.Same(first, second.Operand);
    }

    [Fact]
    public void DoesNotBypassAnExceptionBoundaryOrLeave()
    {
        var method = new MethodDefUser { Body = new CilBody() };
        var end = OpCodes.Ret.ToInstruction();
        var middle = OpCodes.Br.ToInstruction(end);
        var start = OpCodes.Br.ToInstruction(middle);
        var handler = OpCodes.Endfinally.ToInstruction();
        var leave = OpCodes.Leave.ToInstruction(middle);
        foreach (var instruction in new[] { start, middle, leave, handler, end }) method.Body.Instructions.Add(instruction);
        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Finally)
            { TryStart = start, TryEnd = middle, HandlerStart = handler, HandlerEnd = end });
        Assert.Equal(0, RedundantControlFlow.ThreadBranches(method));
        Assert.Same(middle, start.Operand); Assert.Same(middle, leave.Operand);
    }
}
