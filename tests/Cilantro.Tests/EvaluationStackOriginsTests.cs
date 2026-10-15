using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class EvaluationStackOriginsTests
{
    [Fact]
    public void JoinsAlternativeProducersAcrossBranches()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var method = Add(module); var il = method.Body.Instructions;
            var other = OpCodes.Ldstr.ToInstruction("right"); var join = OpCodes.Pop.ToInstruction();
            il.Add(OpCodes.Ldc_I4_0.ToInstruction()); il.Add(OpCodes.Brtrue.ToInstruction(other));
            il.Add(OpCodes.Ldstr.ToInstruction("left")); il.Add(OpCodes.Br.ToInstruction(join));
            il.Add(other); il.Add(join); il.Add(OpCodes.Ret.ToInstruction());
        });
        var method = Read(context); var result = EvaluationStackOrigins.Analyze(method);
        Assert.True(result.Valid);
        Assert.Equal(2, result.Inputs[method.Body.Instructions.Single(i => i.OpCode.Code == Code.Pop)][0].Count);
    }

    [Fact]
    public void DupRetainsOriginalProducerThroughBackwardEdge()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var method = Add(module); var il = method.Body.Instructions;
            var duplicate = OpCodes.Dup.ToInstruction(); var drop = OpCodes.Pop.ToInstruction();
            il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Br.ToInstruction(duplicate));
            il.Add(drop); il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction());
            il.Add(duplicate); il.Add(OpCodes.Br.ToInstruction(drop));
        });
        var method = Read(context); var result = EvaluationStackOrigins.Analyze(method);
        Assert.True(result.Valid);
        foreach (var pop in method.Body.Instructions.Where(i => i.OpCode.Code == Code.Pop))
            Assert.Same(method.Body.Instructions[0], Assert.Single(result.Inputs[pop][0]));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RejectsUnderflowAndMismatchedJoin(bool join)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var method = Add(module); var il = method.Body.Instructions; var pop = OpCodes.Pop.ToInstruction();
            if (join) { il.Add(OpCodes.Ldc_I4_0.ToInstruction()); il.Add(OpCodes.Brtrue.ToInstruction(pop)); il.Add(OpCodes.Ldnull.ToInstruction()); }
            il.Add(pop); il.Add(OpCodes.Ret.ToInstruction());
        });
        var result = EvaluationStackOrigins.Analyze(Read(context));
        Assert.False(result.Valid); Assert.Empty(result.Inputs);
    }

    [Fact]
    public void CatchStartsWithUnknownExceptionAndLeaveClearsStack()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var method = Add(module); var il = method.Body.Instructions;
            var first = OpCodes.Ldnull.ToInstruction(); var handler = OpCodes.Pop.ToInstruction(); var end = OpCodes.Ret.ToInstruction();
            il.Add(first); il.Add(OpCodes.Leave.ToInstruction(end)); il.Add(handler); il.Add(OpCodes.Leave.ToInstruction(end)); il.Add(end);
            method.Body.ExceptionHandlers.Add(new(ExceptionHandlerType.Catch) { TryStart = first, TryEnd = handler,
                HandlerStart = handler, HandlerEnd = end, CatchType = module.CorLibTypes.GetTypeRef("System", "Exception") });
        });
        var method = Read(context); var result = EvaluationStackOrigins.Analyze(method);
        Assert.True(result.Valid);
        Assert.Null(Assert.Single(result.Inputs[method.Body.ExceptionHandlers[0].HandlerStart][0]));
        Assert.Empty(result.Inputs[method.Body.Instructions[^1]]);
    }

    [Fact]
    public void BudgetExhaustionReturnsNoPartialProof()
    {
        using var context = SyntheticContext.Build(module => { var method = Add(module); method.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); });
        var result = EvaluationStackOrigins.Analyze(Read(context), 0);
        Assert.False(result.Valid); Assert.Empty(result.Inputs);
    }
    [Fact]
    public void LoopRevisitsConsumersWhenAnotherProducerArrives()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var method = Add(module); var il = method.Body.Instructions;
            var head = OpCodes.Dup.ToInstruction(); var replace = OpCodes.Pop.ToInstruction(); var exit = OpCodes.Pop.ToInstruction();
            il.Add(OpCodes.Ldstr.ToInstruction("first")); il.Add(OpCodes.Br.ToInstruction(head));
            il.Add(head); il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Ldc_I4_0.ToInstruction());
            il.Add(OpCodes.Brtrue.ToInstruction(replace)); il.Add(OpCodes.Br.ToInstruction(exit));
            il.Add(replace); il.Add(OpCodes.Ldstr.ToInstruction("later")); il.Add(OpCodes.Br.ToInstruction(head));
            il.Add(exit); il.Add(OpCodes.Ret.ToInstruction());
        });
        var method = Read(context); var result = EvaluationStackOrigins.Analyze(method);
        Assert.True(result.Valid);
        Assert.Equal(2, result.Inputs[method.Body.Instructions[^2]][0].Count);
    }
    private static MethodDefUser Add(ModuleDefUser module)
    {
        var owner = SyntheticContext.AddType(module, "Example");
        var method = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL,
            MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody { KeepOldMaxStack = true, MaxStack = 8 } }; owner.Methods.Add(method); return method;
    }
    private static MethodDef Read(Cilantro.Core.ArtifactContext context) => context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Read");
}
