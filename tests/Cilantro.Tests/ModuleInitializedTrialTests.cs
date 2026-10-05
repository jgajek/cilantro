using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ModuleInitializedTrialTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CoupledStartupInstallsRebuiltCompanionsBeforeInitialization(bool changesHelper)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            var value = new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            host.Fields.Add(value);
            var helper = AddMethod(host, "Configure", module.CorLibTypes.Void);
            foreach (var i in new[] { OpCodes.Ldc_I4_7.ToInstruction(), OpCodes.Stsfld.ToInstruction(value), OpCodes.Ret.ToInstruction() }) helper.Body.Instructions.Add(i);
            var run = AddMethod(host, "Run", module.CorLibTypes.Int32);
            run.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(value));
            run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var initializer = module.GlobalType.FindOrCreateStaticConstructor();
            initializer.Body.Instructions.Clear();
            initializer.Body.Instructions.Add(OpCodes.Call.ToInstruction(helper));
            initializer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var host = context.Module.GetTypes().Single(type => type.Name == "Host");
        var run = host.Methods.Single(method => method.Name == "Run");
        var helper = host.Methods.Single(method => method.Name == "Configure");
        var original = helper.Body;
        var replacement = new CilBody();
        foreach (var i in new[] { OpCodes.Ldc_I4.ToInstruction(changesHelper ? 9 : 7), OpCodes.Stsfld.ToInstruction(host.Fields.Single()), OpCodes.Ret.ToInstruction() }) replacement.Instructions.Add(i);
        Assert.Equal(DevirtualizationCheck.Agreed,
            RebuiltMethodTrial.Compare(context, run, run.Body, 0, initializeModule: true).Verdict);
        var trial = RebuiltMethodTrial.Compare(context, run, run.Body, 0, initializeModule: true,
            rebuiltCompanions: new Dictionary<MethodDef, CilBody> { [helper] = replacement });
        Assert.Equal(changesHelper ? DevirtualizationCheck.Disagreed : DevirtualizationCheck.Agreed, trial.Verdict);
        Assert.Same(original, helper.Body);
    }

    [Fact]
    public void ModuleInitializationIsASeparateTrialAndDoesNotEraseTheColdDifference()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Host");
            var field = new FieldDefUser("Ready", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            owner.Fields.Add(field);
            var run = AddMethod(owner, "Run", module.CorLibTypes.Int32);
            run.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(field));
            run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var initializer = module.GlobalType.FindOrCreateStaticConstructor();
            initializer.Body.Instructions.Clear();
            foreach (var i in new[] { OpCodes.Ldc_I4_7.ToInstruction(), OpCodes.Stsfld.ToInstruction(field), OpCodes.Ret.ToInstruction() })
                initializer.Body.Instructions.Add(i);
        });
        var run = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Run");
        var rebuilt = new CilBody();
        rebuilt.Instructions.Add(OpCodes.Ldc_I4_7.ToInstruction());
        rebuilt.Instructions.Add(OpCodes.Ret.ToInstruction());
        Assert.Equal(DevirtualizationCheck.Disagreed, RebuiltMethodTrial.Compare(context, run, rebuilt, 0).Verdict);
        Assert.Equal(DevirtualizationCheck.Agreed, RebuiltMethodTrial.Compare(context, run, rebuilt, 0, initializeModule: true).Verdict);
        Assert.Equal(DevirtualizationCheck.Disagreed, RebuiltMethodTrial.Compare(context, run, rebuilt, 0).Verdict);
    }

    [Fact]
    public void EachModuleInitializerUsesItsOwnSelectedBody()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Host");
            var mode = new FieldDefUser("Mode", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            var observed = new FieldDefUser("Observed", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            owner.Fields.Add(mode); owner.Fields.Add(observed);
            var run = AddMethod(owner, "Run", module.CorLibTypes.Int32);
            run.Body.Instructions.Add(OpCodes.Ldc_I4_7.ToInstruction()); run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var initializer = module.GlobalType.FindOrCreateStaticConstructor();
            initializer.Body.Instructions.Clear();
            foreach (var i in new[] { OpCodes.Call.ToInstruction(run), OpCodes.Stsfld.ToInstruction(observed), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(mode), OpCodes.Ret.ToInstruction() })
                initializer.Body.Instructions.Add(i);
        });
        var run = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Run");
        var mode = run.DeclaringType.Fields.Single(f => f.Name == "Mode");
        var normal = OpCodes.Ldc_I4_7.ToInstruction();
        var rebuilt = new CilBody();
        foreach (var i in new[] { OpCodes.Ldsfld.ToInstruction(mode), OpCodes.Brtrue.ToInstruction(normal), OpCodes.Ldc_I4.ToInstruction(9), OpCodes.Ret.ToInstruction(), normal, OpCodes.Ret.ToInstruction() })
            rebuilt.Instructions.Add(i);
        var result = RebuiltMethodTrial.Compare(context, run, rebuilt, 0, initializeModule: true);
        Assert.Equal(DevirtualizationCheck.Disagreed, result.Verdict);
        Assert.Contains("argument snapshots matched", result.Detail);
        Assert.Contains("Observed", result.Detail);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FailedInitializersRemainInconclusiveButNullSubscriptionsAreInert(bool registers)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Host");
            var run = AddMethod(owner, "Run", module.CorLibTypes.Void);
            run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var initializer = module.GlobalType.FindOrCreateStaticConstructor();
            initializer.Body.Instructions.Clear();
            if (registers)
            {
                var domain = module.CorLibTypes.GetTypeRef("System", "AppDomain");
                var current = new MemberRefUser(module, "get_CurrentDomain", MethodSig.CreateStatic(domain.ToTypeSig()), domain);
                var subscribe = new MemberRefUser(module, "add_AssemblyResolve", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object), domain);
                foreach (var i in new[] { OpCodes.Call.ToInstruction(current), OpCodes.Ldnull.ToInstruction(), OpCodes.Callvirt.ToInstruction(subscribe), OpCodes.Ret.ToInstruction() })
                    initializer.Body.Instructions.Add(i);
            }
            else
            {
                initializer.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
                initializer.Body.Instructions.Add(OpCodes.Throw.ToInstruction());
            }
        });
        var run = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Run");
        var result = RebuiltMethodTrial.Compare(context, run, run.Body, 0, initializeModule: true);
        Assert.Equal(registers ? DevirtualizationCheck.Agreed : DevirtualizationCheck.NotMade, result.Verdict);
        Assert.Contains(registers ? "0 callbacks" : "module initialization did not complete", result.Detail);
    }

    [Fact]
    public void ExercisingTheEngineOnlyDuringInitializationDoesNotValidateTheMeasuredCall()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Host");
            var ready = new FieldDefUser("Ready", new FieldSig(module.CorLibTypes.Boolean), FieldAttributes.Static);
            owner.Fields.Add(ready);
            var engine = AddMethod(owner, "Engine", module.CorLibTypes.Void);
            engine.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var run = AddMethod(owner, "Run", module.CorLibTypes.Void);
            var done = OpCodes.Ret.ToInstruction();
            foreach (var i in new[] { OpCodes.Ldsfld.ToInstruction(ready), OpCodes.Brtrue.ToInstruction(done), OpCodes.Call.ToInstruction(engine), done })
                run.Body.Instructions.Add(i);
            var initializer = module.GlobalType.FindOrCreateStaticConstructor();
            initializer.Body.Instructions.Clear();
            foreach (var i in new[] { OpCodes.Call.ToInstruction(run), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(ready), OpCodes.Ret.ToInstruction() })
                initializer.Body.Instructions.Add(i);
        });
        var methods = context.Module.GetTypes().SelectMany(t => t.Methods).ToArray();
        var run = methods.Single(m => m.Name == "Run");
        var engine = methods.Single(m => m.Name == "Engine");
        var result = RebuiltMethodTrial.Compare(context, run, run.Body, 0, engine.MDToken.Raw, initializeModule: true);
        Assert.Equal(DevirtualizationCheck.NotMade, result.Verdict);
        Assert.Contains("body/engine was not exercised", result.Detail);
    }

    private static MethodDefUser AddMethod(TypeDef owner, string name, TypeSig result)
    {
        var method = new MethodDefUser(name, MethodSig.CreateStatic(result), MethodImplAttributes.IL, MethodAttributes.Static) { Body = new CilBody() };
        owner.Methods.Add(method);
        return method;
    }
}
