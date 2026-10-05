using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ResolverTrialSnapshotTests
{
    private static readonly string[] HandlerNames = ["First", "Second"];
    [Theory]
    [InlineData("same", false)]
    [InlineData("same", true)]
    [InlineData("method", false)]
    [InlineData("method", true)]
    [InlineData("order", false)]
    [InlineData("remove", false)]
    public void TrialsCompareSubscriptionsAndExerciseMatchingCallbacks(string change, bool initialize)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Host");
            var domain = module.CorLibTypes.GetTypeRef("System", "AppDomain");
            var handlerType = module.CorLibTypes.GetTypeRef("System", "ResolveEventHandler");
            var current = new MemberRefUser(module, "get_CurrentDomain", MethodSig.CreateStatic(domain.ToTypeSig()), domain);
            var ctor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void,
                module.CorLibTypes.Object, module.CorLibTypes.IntPtr), handlerType);
            var add = new MemberRefUser(module, "add_AssemblyResolve", MethodSig.CreateInstance(module.CorLibTypes.Void,
                handlerType.ToTypeSig()), domain);
            var handlers = HandlerNames.Select(name =>
            {
                var method = new MethodDefUser(name, MethodSig.CreateStatic(module.CorLibTypes.Object,
                    module.CorLibTypes.Object, module.CorLibTypes.Object))
                    { Attributes = MethodAttributes.Static, Body = new CilBody() };
                method.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
                method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                owner.Methods.Add(method);
                return method;
            }).ToArray();
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(run);
            foreach (var handler in handlers)
                foreach (var i in new[] { OpCodes.Call.ToInstruction(current), OpCodes.Ldnull.ToInstruction(),
                    OpCodes.Ldftn.ToInstruction(handler), OpCodes.Newobj.ToInstruction(ctor), OpCodes.Callvirt.ToInstruction(add) })
                    run.Body.Instructions.Add(i);
            run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var initializer = module.GlobalType.FindOrCreateStaticConstructor();
            initializer.Body.Instructions.Clear();
            initializer.Body.Instructions.Add(OpCodes.Call.ToInstruction(run));
            initializer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Run");
        var rebuilt = new CilBody();
        foreach (var i in method.Body.Instructions) rebuilt.Instructions.Add(new Instruction(i.OpCode, i.Operand));
        if (change == "method") rebuilt.Instructions[2].Operand = rebuilt.Instructions[7].Operand;
        if (change == "order") (rebuilt.Instructions[2].Operand, rebuilt.Instructions[7].Operand) =
            (rebuilt.Instructions[7].Operand, rebuilt.Instructions[2].Operand);
        if (change == "remove") { rebuilt.Instructions.Clear(); rebuilt.Instructions.Add(OpCodes.Ret.ToInstruction()); }
        var result = RebuiltMethodTrial.Compare(context, method, rebuilt, 0, initializeModule: initialize);
        Assert.Equal(change == "same" ? DevirtualizationCheck.Agreed : DevirtualizationCheck.Disagreed, result.Verdict);
        Assert.Contains("resolver", result.Detail, StringComparison.OrdinalIgnoreCase);
        if (change != "same") Assert.Contains("modeled application-domain data", result.DifferingRoots!);
    }

    [Theory]
    [InlineData("target")]
    [InlineData("alias")]
    [InlineData("binding")]
    public void CallbackSnapshotsRetainTargetStateAliasesAndBinding(string change)
    {
        using var module = new ModuleDefUser("callbacks");
        var method = new MethodDefUser("Resolve", MethodSig.CreateStatic(module.CorLibTypes.Object));
        var identities = new Dictionary<object, int>(ReferenceEqualityComparer.Instance);
        string Capture(bool changed)
        {
            var state = new StaticMachineState(new StaticMachineLimits());
            Assert.True(state.TryGetOrAllocateRuntimeSingleton("System.AppDomain", out var domain));
            Assert.True(state.Heap.TryAllocateObject("Target", out var target));
            Assert.True(state.Heap.TrySetModelValue(target, "Value", StaticValue.FromInt32(changed && change == "target" ? 2 : 1)));
            Assert.True(state.Heap.TryAllocateObject("Target", out var other));
            Assert.True(state.Heap.TrySetModelValue(other, "Value", StaticValue.FromInt32(1)));
            Assert.True(state.Heap.TryAllocateObject("System.ResolveEventHandler", out var handler));
            Assert.True(state.Heap.TrySetModelValue(handler, StaticMachine.DelegateMethodKey, method));
            Assert.True(state.Heap.TrySetModelValue(handler, StaticMachine.DelegateTargetKey, target));
            Assert.True(state.Heap.TrySetModelValue(handler, StaticMachine.DelegateOpenKey, changed && change == "binding"));
            Assert.Equal(StaticExecutionStatus.Completed, AppDomainEvents.Update(state.Heap, domain, "ResourceResolve", handler, true).Status);
            var snapshot = new RebuiltMethodTrial.Snapshot(state.Heap, identities);
            var root = Assert.IsType<string>(snapshot.Read(changed && change == "alias" ? other : target));
            return root + "|" + Assert.IsType<string>(snapshot.ReadDomainState(state));
        }
        Assert.Equal(Capture(false), Capture(false));
        Assert.NotEqual(Capture(false), Capture(true));
    }
}
