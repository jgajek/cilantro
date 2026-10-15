using Cilantro.Core;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class NumericBridgeCompletionTests
{
    [Fact]
    public void RemovesFreshlyGeneratedBridgeAndBalancesAddedMethodAccounting()
    {
        using var context = SyntheticContext.Build(module =>
        {
            SyntheticContext.AddType(module, "NumericHolder");
            var app = SyntheticContext.AddType(module, "App");
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void))
            { Attributes = MethodAttributes.Static | MethodAttributes.Public, Body = new CilBody() };
            app.Methods.Add(run); module.EntryPoint = run;
            run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var owner = context.Module.GetTypes().Single(t => t.Name == "NumericHolder");
        var bridge = new MethodDefUser("InitializeNumericTable", MethodSig.CreateStatic(context.Module.CorLibTypes.Void))
        { Attributes = MethodAttributes.Static | MethodAttributes.Assembly, Body = new CilBody() };
        owner.Methods.Add(bridge);
        bridge.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        context.Module.EntryPoint.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(bridge));
        context.SetFact("options.removeRuntime", true);
        context.SetFact(NumericTableRecoveryPass.AddedInitializationMethodsFact, 1);
        context.SetFact(NumericTableRecoveryPass.InitializationBridgesFact,
            new List<NumericTableRecoveryPass.InitializationBridge> { new(bridge,
                new FieldDefUser("RemovedHolder", new FieldSig(context.Module.CorLibTypes.Object))) });
        Assert.Equal(0u, bridge.Rid);
        Assert.Equal(1, new NumericBridgeCompletionPass().Run(context).Changes);
        Assert.Equal(PassStatus.Success, new NumericBridgeRuntimeCleanupPass().Run(context).Status);
        Assert.DoesNotContain(owner, context.Module.GetTypes());
        Assert.True(context.TryGetFact<int>("cleanup.removedAddedMethodCount", out var removed));
        Assert.Equal(1, removed);
        Assert.True(Cilantro.Core.AssemblyVerifier.Verify(context.Module, context.OriginalIdentity,
            context.OriginalStructure, CilantroPipeline.BuildRewriteAllowance(context)).Passed);
    }

    [Theory]
    [InlineData("empty", true)]
    [InlineData("empty-cctor", true)]
    [InlineData("effect", false)]
    [InlineData("cctor-effect", false)]
    [InlineData("no-provenance", false)]
    [InlineData("disabled", false)]
    [InlineData("prefix", false)]
    public void RemovesOnlyRecordedEmptyCallsWithoutInitializationEffects(string scenario, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "NumericBridge");
            var holder = new FieldDefUser("Holder", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Static);
            owner.Fields.Add(holder);
            var bridge = new MethodDefUser("InitializeNumericTable", MethodSig.CreateStatic(module.CorLibTypes.Void))
            { Attributes = MethodAttributes.Static | MethodAttributes.Assembly, Body = new CilBody() };
            owner.Methods.Add(bridge);
            if (scenario == "effect") { bridge.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); bridge.Body.Instructions.Add(OpCodes.Throw.ToInstruction()); }
            else bridge.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            if (scenario is "empty-cctor" or "cctor-effect")
            {
                var init = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static | MethodAttributes.Private | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, Body = new CilBody() };
                owner.Methods.Add(init);
                if (scenario == "cctor-effect") { init.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); init.Body.Instructions.Add(OpCodes.Throw.ToInstruction()); }
                else init.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            }
            var app = SyntheticContext.AddType(module, "App");
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void))
            { Attributes = MethodAttributes.Static | MethodAttributes.Public, Body = new CilBody() };
            app.Methods.Add(run); module.EntryPoint = run;
            if (scenario == "prefix") run.Body.Instructions.Add(OpCodes.Tailcall.ToInstruction());
            run.Body.Instructions.Add(OpCodes.Call.ToInstruction(bridge));
            run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var owner = context.Module.GetTypes().Single(t => t.Name == "NumericBridge");
        context.SetFact("options.removeRuntime", scenario != "disabled");
        if (scenario != "no-provenance") context.SetFact(NumericTableRecoveryPass.InitializationBridgesFact,
            new List<NumericTableRecoveryPass.InitializationBridge> { new(owner.Methods.Single(m => m.Name == "InitializeNumericTable"), owner.Fields[0]) });
        var result = new NumericBridgeCompletionPass().Run(context);
        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(expected ? 1 : 0, result.Changes);
        if (!expected) return;
        Assert.DoesNotContain(context.Module.EntryPoint.Body.Instructions, i => i.OpCode.Code == Code.Call);
        Assert.Equal(0, new NumericBridgeCompletionPass().Run(context).Changes);
        Assert.Equal(PassStatus.Success, new NumericBridgeRuntimeCleanupPass().Run(context).Status);
        Assert.DoesNotContain(owner, context.Module.GetTypes());
    }
}
