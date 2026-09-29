using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DomainTrialSnapshotTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void RemovingADomainWriteIsDetectedIncludingAfterModuleInitialization(bool initialize, bool remove)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Host");
            var domain = module.CorLibTypes.GetTypeRef("System", "AppDomain");
            var current = new MemberRefUser(module, "get_CurrentDomain", MethodSig.CreateStatic(domain.ToTypeSig()), domain);
            var store = new MemberRefUser(module, "SetData", MethodSig.CreateInstance(module.CorLibTypes.Void,
                module.CorLibTypes.String, module.CorLibTypes.Object), domain);
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(run);
            foreach (var i in new[] { OpCodes.Call.ToInstruction(current), OpCodes.Ldstr.ToInstruction("slot"),
                OpCodes.Ldstr.ToInstruction("retained"), OpCodes.Callvirt.ToInstruction(store), OpCodes.Ret.ToInstruction() })
                run.Body.Instructions.Add(i);
            var initializer = module.GlobalType.FindOrCreateStaticConstructor();
            initializer.Body.Instructions.Clear();
            initializer.Body.Instructions.Add(OpCodes.Call.ToInstruction(run));
            initializer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Run");
        var rebuilt = new CilBody();
        if (remove) rebuilt.Instructions.Add(OpCodes.Ret.ToInstruction());
        else foreach (var i in method.Body.Instructions) rebuilt.Instructions.Add(new Instruction(i.OpCode, i.Operand));
        var trial = RebuiltMethodTrial.Compare(context, method, rebuilt, 0, initializeModule: initialize);
        Assert.Equal(remove ? DevirtualizationCheck.Disagreed : DevirtualizationCheck.Agreed, trial.Verdict);
        Assert.Contains("application-domain", trial.Detail);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DomainDataPreservesAliasesWithOtherRoots(bool shared)
    {
        static string Capture(bool shared, bool padding)
        {
            var state = new StaticMachineState(new StaticMachineLimits());
            if (padding) Assert.True(state.Heap.TryAllocateObject("Padding", out _));
            Assert.True(state.TryGetOrAllocateRuntimeSingleton("System.AppDomain", out var domain));
            Assert.True(state.Heap.TryAllocateByteArray([1, 2], out var first));
            Assert.True(state.Heap.TryAllocateByteArray([1, 2], out var second));
            Assert.True(state.Heap.TrySetModelValue(domain, "Data:slot", shared ? first : second));
            var snapshot = new RebuiltMethodTrial.Snapshot(state.Heap);
            Assert.NotNull(snapshot.Read(first));
            return Assert.IsType<string>(snapshot.ReadDomainState(state));
        }
        Assert.Equal(Capture(shared, false), Capture(shared, true));
        Assert.NotEqual(Capture(shared, false), Capture(!shared, false));
    }

    [Fact]
    public void AnUnrequestedDomainMatchesAnEmptyRequestedDomain()
    {
        var left = new StaticMachineState(new StaticMachineLimits());
        var right = new StaticMachineState(new StaticMachineLimits());
        Assert.True(right.TryGetOrAllocateRuntimeSingleton("System.AppDomain", out _));
        Assert.Equal(new RebuiltMethodTrial.Snapshot(left.Heap).ReadDomainState(left),
            new RebuiltMethodTrial.Snapshot(right.Heap).ReadDomainState(right));
    }

    [Fact]
    public void OpaqueDomainValuesPreventAgreement()
    {
        var state = new StaticMachineState(new StaticMachineLimits());
        Assert.True(state.TryGetOrAllocateRuntimeSingleton("System.AppDomain", out var domain));
        Assert.True(state.Heap.TrySetModelValue(domain, "Data:slot", StaticValue.Unknown));
        Assert.Null(new RebuiltMethodTrial.Snapshot(state.Heap).ReadDomainState(state));
    }

    [Fact]
    public void DomainSlotNamesConsumeTheTextBudget()
    {
        var state = new StaticMachineState(new StaticMachineLimits());
        Assert.True(state.TryGetOrAllocateRuntimeSingleton("System.AppDomain", out var domain));
        Assert.True(state.Heap.TrySetModelValue(domain, "Data:" + new string('x', 4 * 1024 * 1024), StaticValue.Null));
        var snapshot = new RebuiltMethodTrial.Snapshot(state.Heap);
        Assert.Null(snapshot.ReadDomainState(state));
        Assert.Contains("text budget", snapshot.Failure);
    }

    [Fact]
    public void DomainDataParticipatesInVmSharingDetection()
    {
        var state = new StaticMachineState(new StaticMachineLimits());
        Assert.True(state.TryGetOrAllocateRuntimeSingleton("System.AppDomain", out var domain));
        Assert.True(state.Heap.TryAllocateByteArray([42], out var vmValue));
        Assert.True(state.Heap.TrySetModelValue(domain, "Data:cache", vmValue));
        var vm = new RebuiltMethodTrial.Snapshot(state.Heap);
        var application = new RebuiltMethodTrial.Snapshot(state.Heap);
        Assert.NotNull(vm.Read(vmValue));
        Assert.NotNull(application.ReadDomainState(state));
        Assert.True(vm.SharesCapturedObjectsWith(application));
    }
}
