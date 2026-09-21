using Cilantro.Core;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ColdInitializerTests
{
    [Fact]
    public void ColdProofHonorsTheDeclaredStepBudget()
    {
        using var context = Fixture(false);
        context.SetFact(BootstrapMachine.RunEnvironmentFact,
            new RunEnvironment(new HostEnvironment(HostProfile.Empty),
                RunDeclarations.Parse("{\"budgets\":{\"steps\":32000000}}", "test")));
        Assert.Equal(32_000_000, LoaderCallElisionPass.ColdInitializerStepBudget(context));
    }

    [Fact]
    public void ModuleBootstrapTargetRunsOnlyOncePerIndependentMachine()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var flag = new FieldDefUser("Initialized", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            module.GlobalType.Fields.Add(flag);
            var initializer = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL, MethodAttributes.Static | MethodAttributes.SpecialName |
                MethodAttributes.RTSpecialName) { Body = new CilBody() };
            var failure = OpCodes.Ldnull.ToInstruction();
            foreach (var instruction in new[] { OpCodes.Ldsfld.ToInstruction(flag), OpCodes.Brtrue.ToInstruction(failure),
                OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(flag), OpCodes.Ret.ToInstruction(),
                failure, OpCodes.Throw.ToInstruction() }) initializer.Body.Instructions.Add(instruction);
            module.GlobalType.Methods.Add(initializer);
        });

        Assert.True(LoaderCallElisionPass.TryInterpretColdInitializer(context,
            context.Module.GlobalType.FindStaticConstructor(), new StaticWorkBudget(1000), new StaticWorkBudget(1000),
            out var evidence, out var reason), reason);
        Assert.True(evidence!.EffectsOf(context.Module.GlobalType.FindStaticConstructor().MDToken.Raw).AllInvocationsCompleted);
    }

    [Fact]
    public void RecoveryBootstrapGetsMeasuredOverheadWithoutIncreasingQueryBudget()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var field = new FieldDefUser("Ready", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            module.GlobalType.Fields.Add(field);
            var initializer = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL, MethodAttributes.Static | MethodAttributes.SpecialName |
                MethodAttributes.RTSpecialName) { Body = new CilBody() };
            module.GlobalType.Methods.Add(initializer);
            for (var i = 0; i < 50; i++) initializer.Body.Instructions.Add(OpCodes.Nop.ToInstruction());
            initializer.Body.Instructions.Add(OpCodes.Ldc_I4.ToInstruction(42));
            initializer.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(field));
            initializer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var query = new MethodDefUser("Query", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL, MethodAttributes.Static) { Body = new CilBody() };
            module.GlobalType.Methods.Add(query);
            for (var i = 0; i < 50; i++) query.Body.Instructions.Add(OpCodes.Nop.ToInstruction());
            query.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var field = context.Module.GlobalType.Fields.Single();
        Assert.True(BootstrapMachine.TryRunInitializers(context, 20, out var shortRun, out _));
        Assert.Equal(0, shortRun!.State.ReadStaticField(field).AsInt32());
        context.SetFact("method-protection.attempt",
            new MethodRecoveryAttempt(0, StaticExecutionStatus.Completed, 53, 1, 0, 0, null));

        Assert.True(BootstrapMachine.TryRunInitializers(context, 20, out var recovered, out _));

        Assert.Equal(42, recovered!.State.ReadStaticField(field).AsInt32());
        Assert.Equal(StaticExecutionStatus.StepLimitExceeded,
            recovered.Execute(context.Module.GlobalType.Methods.Single(m => m.Name == "Query")).Status);
    }

    [Theory]
    [InlineData(20_000_000, StaticExecutionStatus.Completed, 24_000_000)]
    [InlineData(20_000_000, StaticExecutionStatus.StepLimitExceeded, 24_000_000)]
    [InlineData(18_000_000, StaticExecutionStatus.Threw, 22_000_000)]
    [InlineData(int.MaxValue, StaticExecutionStatus.Completed, 64_000_000)]
    [InlineData(-1, StaticExecutionStatus.Completed, 4_000_000)]
    public void ColdProofBudgetIncludesMeasuredBootstrapWorkWithinACeiling(int steps, StaticExecutionStatus status, int expected)
    {
        using var context = Fixture(false);
        context.SetFact("method-protection.attempt", new MethodRecoveryAttempt(0, status, steps, 1, 0, 0, null));
        Assert.Equal(expected, LoaderCallElisionPass.ColdInitializerStepBudget(context));
    }

    [Fact]
    public void RecoveredProxyBindingsDoNotPrepopulateTheProofState()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var proxy = new TypeDefUser("Synthetic", "Proxy",
                module.CorLibTypes.GetTypeRef("System", "MulticastDelegate"));
            module.Types.Add(proxy);
            var cached = new FieldDefUser("Cached", new FieldSig(proxy.ToTypeSig()), FieldAttributes.Static);
            var observed = new FieldDefUser("Observed", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            proxy.Fields.Add(cached); proxy.Fields.Add(observed);
            var initializer = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL, MethodAttributes.Static | MethodAttributes.SpecialName |
                MethodAttributes.RTSpecialName) { Body = new CilBody() };
            var end = OpCodes.Ret.ToInstruction();
            initializer.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(cached));
            initializer.Body.Instructions.Add(OpCodes.Brtrue.ToInstruction(end));
            initializer.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction());
            initializer.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(observed));
            initializer.Body.Instructions.Add(end);
            proxy.Methods.Add(initializer);
            var host = SyntheticContext.AddType(module, "Host");
            var target = new MethodDefUser("Target", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL, MethodAttributes.Static) { Body = new CilBody() };
            target.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); host.Methods.Add(target);
        });
        var proxy = context.Module.GetTypes().Single(t => t.Name == "Proxy");
        var initializer = proxy.FindStaticConstructor();
        var target = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Target");
        context.SetFact<IReadOnlyList<ProxyBinding>>("proxy.bindings",
            [new(proxy.FindField("Cached").MDToken.Raw, target.MDToken.Raw, false)]);
        Assert.True(BootstrapMachine.TryRunInitializers(context, 1000, out var warm, out _));
        Assert.True(warm!.Execute(initializer).Succeeded);
        Assert.DoesNotContain("System.Int32 Synthetic.Proxy::Observed",
            warm.State.LoaderEvidence.EffectsOf(initializer.MDToken.Raw).StaticFieldsWritten);

        Assert.True(LoaderCallElisionPass.TryInterpretColdInitializer(context, initializer,
            new StaticWorkBudget(1000), new StaticWorkBudget(1000), out var proof, out var reason), reason);
        Assert.Contains("System.Int32 Synthetic.Proxy::Observed",
            proof!.EffectsOf(initializer.MDToken.Raw).StaticFieldsWritten);
    }

    [Fact]
    public void IndependentInitializersCannotWarmEachOthersCache()
    {
        using var context = Fixture(false);
        var budgets = (new StaticWorkBudget(1000), new StaticWorkBudget(1000));
        var initializers = context.Module.GetTypes().Where(t => t.Name != "<Module>")
            .Select(t => t.FindStaticConstructor()).OfType<MethodDef>().ToArray();

        foreach (var method in initializers)
        {
            Assert.True(LoaderCallElisionPass.TryInterpretColdInitializer(context, method,
                budgets.Item1, budgets.Item2, out var evidence, out var reason), reason);
            Assert.Contains("System.Int32 Synthetic.Cache::Ready", evidence!.EffectsOf(method.MDToken.Raw).StaticFieldsWritten);
        }
        Assert.Equal(2, initializers.Length);
        Assert.Equal(budgets.Item1.ConsumedSteps, budgets.Item2.ConsumedSteps);
    }

    [Fact]
    public void FailedModuleInitializationCannotSupplyAProof()
    {
        using var context = Fixture(true);
        var method = context.Module.GetTypes().Single(t => t.Name == "First").FindStaticConstructor();

        Assert.False(LoaderCallElisionPass.TryInterpretColdInitializer(context, method,
            new StaticWorkBudget(1000), new StaticWorkBudget(1000), out var evidence, out var reason));
        Assert.Null(evidence);
        Assert.Contains("module initialization did not complete", reason);
    }

    [Fact]
    public void ExhaustedBudgetCannotSupplyAProof()
    {
        using var context = Fixture(false);
        var method = context.Module.GetTypes().Single(t => t.Name == "First").FindStaticConstructor();
        var left = new StaticWorkBudget(1);

        Assert.False(LoaderCallElisionPass.TryInterpretColdInitializer(context, method,
            left, new StaticWorkBudget(1), out var evidence, out _));
        Assert.Null(evidence);
        Assert.Equal(0, left.RemainingSteps);
    }

    private static ArtifactContext Fixture(bool failingBootstrap) => SyntheticContext.Build(module =>
    {
        var cache = SyntheticContext.AddType(module, "Cache");
        var field = new FieldDefUser("Ready", new FieldSig(module.CorLibTypes.Int32),
            FieldAttributes.Assembly | FieldAttributes.Static);
        cache.Fields.Add(field);
        for (var index = 0; index < 2; index++)
        {
            var host = SyntheticContext.AddType(module, index == 0 ? "First" : "Second");
            var method = Initializer();
            host.Methods.Add(method);
            var end = OpCodes.Ret.ToInstruction();
            method.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(field));
            method.Body.Instructions.Add(OpCodes.Brtrue.ToInstruction(end));
            method.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction());
            method.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(field));
            method.Body.Instructions.Add(end);
        }
        if (failingBootstrap)
        {
            var initializer = Initializer();
            module.GlobalType.Methods.Add(initializer);
            initializer.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            initializer.Body.Instructions.Add(OpCodes.Throw.ToInstruction());
        }
        MethodDef Initializer() => new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
            MethodImplAttributes.IL, MethodAttributes.Static | MethodAttributes.Private |
            MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() };
    });
}
