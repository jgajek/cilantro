using Cilantro.Core;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class NetworkTrialSnapshotTests
{
    [Theory]
    [InlineData(3072, DevirtualizationCheck.Agreed)]
    [InlineData(192, DevirtualizationCheck.Disagreed)]
    public void TrialObservesNetworkSettingsOutsideManagedStatics(int replacement, DevirtualizationCheck expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Host");
            var manager = module.CorLibTypes.GetTypeRef("System.Net", "ServicePointManager");
            var setter = new MemberRefUser(module, "set_SecurityProtocol",
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32), manager);
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            run.Body.Instructions.Add(Instruction.CreateLdcI4(3072));
            run.Body.Instructions.Add(OpCodes.Call.ToInstruction(setter));
            run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            owner.Methods.Add(run);
        });
        var method = context.Module.GetTypes().SelectMany(type => type.Methods).Single();
        var original = method.Body;
        var rebuilt = new CilBody();
        rebuilt.Instructions.Add(Instruction.CreateLdcI4(replacement));
        rebuilt.Instructions.Add(OpCodes.Call.ToInstruction((IMethod)original.Instructions[1].Operand));
        rebuilt.Instructions.Add(OpCodes.Ret.ToInstruction());
        var result = RebuiltMethodTrial.Compare(context, method, rebuilt, 0);
        Assert.Equal(expected, result.Verdict);
        Assert.Contains("modeled network settings", result.Detail);
        Assert.Same(original, method.Body);
    }

    [Fact]
    public void ReusingAnIntrinsicDoesNotLeakCallbacksBetweenMachines()
    {
        using var module = new ModuleDefUser("test");
        var manager = module.CorLibTypes.GetTypeRef("System.Net", "ServicePointManager");
        var setter = new MemberRefUser(module, "set_ServerCertificateValidationCallback",
            MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object), manager);
        var getter = new MemberRefUser(module, "get_ServerCertificateValidationCallback",
            MethodSig.CreateStatic(module.CorLibTypes.Object), manager);
        var first = new StaticMachineState(new StaticMachineLimits());
        var second = new StaticMachineState(new StaticMachineLimits());
        Assert.True(first.Heap.TryAllocateObject("System.Delegate", out var callback));
        var intrinsic = new NetworkSettingsIntrinsic();
        intrinsic.Invoke(new IntrinsicContext(first), setter, [callback]);
        Assert.Equal(callback, intrinsic.Invoke(new IntrinsicContext(first), getter, []).Value);
        Assert.Equal(StaticValue.Null, intrinsic.Invoke(new IntrinsicContext(second), getter, []).Value);
        // A fresh intrinsic must still see the first machine's state.
        Assert.Equal(callback, new NetworkSettingsIntrinsic().Invoke(new IntrinsicContext(first), getter, []).Value);
    }

    [Fact]
    public void UnknownNetworkSettingStateCannotAgree()
    {
        var state = new StaticMachineState(new StaticMachineLimits());
        state.NetworkSettings["SecurityProtocol"] = StaticValue.Unknown;
        Assert.Null(new RebuiltMethodTrial.Snapshot(state.Heap).ReadNetworkSettings(state));
    }
}
