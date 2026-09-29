using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class AppDomainEventTests
{
    private static readonly string[] AnsweringOrder = ["Resolve0", "Resolve1"];
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ResourceResolutionExecutesManagedHandlersAndStopsAfterTheAnswer(bool instance)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Resolver");
            var assembly = new FieldDefUser("Answer", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Static);
            owner.Fields.Add(assembly);
            for (var index = 0; index < 3; index++)
            {
                var signature = instance
                    ? MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.Object, module.CorLibTypes.Object)
                    : MethodSig.CreateStatic(module.CorLibTypes.Object, module.CorLibTypes.Object, module.CorLibTypes.Object);
                var method = new MethodDefUser("Resolve" + index, signature)
                    { Attributes = instance ? MethodAttributes.Public : MethodAttributes.Static, Body = new CilBody() };
                owner.Methods.Add(method);
                method.Body.Instructions.Add(index == 1 ? OpCodes.Ldsfld.ToInstruction(assembly) : OpCodes.Ldnull.ToInstruction());
                method.Body.Instructions.Add(index == 2 ? OpCodes.Throw.ToInstruction() : OpCodes.Ret.ToInstruction());
            }
        });
        using var payload = new ModuleDefUser("resolver-payload.dll");
        new AssemblyDefUser("resolver-payload", new Version(1, 0)).Modules.Add(payload);
        payload.Resources.Add(new EmbeddedResource("payload", new byte[] { 8, 13, 21 }, ManifestResourceAttributes.Public));
        using var image = new MemoryStream();
        payload.Write(image);
        var machine = new StaticMachine();
        var state = machine.State;
        state.RegisterModuleMetadata(context.Module);
        var heap = state.Heap;
        Assert.True(state.TryGetOrAllocateRuntimeSingleton("System.AppDomain", out var domain));
        Assert.True(heap.TryAllocateObject("System.Reflection.Assembly", out var answerAssembly));
        Assert.True(heap.TrySetModelValue(answerAssembly, "LoadedImage", image.ToArray()));
        var methods = context.Module.GetTypes().SelectMany(t => t.Methods).ToArray();
        state.WriteStaticField(methods[0].DeclaringType.Fields.Single(), answerAssembly);
        Assert.True(heap.TryAllocateObject(methods[0].DeclaringType.FullName, out var receiver));
        foreach (var method in methods)
            Assert.Equal(StaticExecutionStatus.Completed,
                AppDomainEvents.Update(heap, domain, "ResourceResolve", Handler(state, method, receiver), true).Status);
        var entered = new List<string>();
        machine.FrameEntered = (method, arguments) =>
        {
            entered.Add(method.Name);
            Assert.Equal(domain, arguments[instance ? 1 : 0]);
            if (instance) Assert.Equal(receiver, arguments[0]);
        };
        Assert.True(heap.TryAllocateObject("System.Reflection.Assembly", out var requester));
        Assert.True(heap.TryAllocateString("payload", out var name));
        var call = new MemberRefUser(context.Module, "GetManifestResourceStream",
            MethodSig.CreateInstance(context.Module.CorLibTypes.Object, context.Module.CorLibTypes.String),
            context.Module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly"));
        var result = machine.Invoke(call, [requester, name]);
        Assert.True(result.Status == StaticExecutionStatus.Completed, result.Diagnostic);
        Assert.Equal(AnsweringOrder, entered);
        Assert.True(heap.TryGetModelValue(result.Value, "Buffer", out StaticValue buffer));
        // This image was built above from resources alone; no corpus assembly is loaded here.
        using var oracle = System.Reflection.Assembly.Load(image.ToArray()).GetManifestResourceStream("payload")!;
        using var oracleBytes = new MemoryStream();
        oracle.CopyTo(oracleBytes);
        Assert.Equal(oracleBytes.ToArray(), heap.GetBytesSnapshot(buffer));
    }

    [Fact]
    public void RemovingAnEqualDelegateRemovesOnlyTheLastSubscription()
    {
        using var module = new ModuleDefUser("events");
        var state = new StaticMachineState(new StaticMachineLimits());
        Assert.True(state.TryGetOrAllocateRuntimeSingleton("System.AppDomain", out var domain));
        var method = new MethodDefUser("Resolve", MethodSig.CreateStatic(module.CorLibTypes.Object));
        var first = Handler(state, method);
        var equivalent = Handler(state, method);
        Assert.True(state.Heap.TryAllocateObject("Target", out var target));
        var different = Handler(state, method, target);
        Update(true, first); Update(true, different); Update(true, equivalent);
        Update(false, Handler(state, method));
        Assert.True(state.Heap.TryGetModelValue(domain, "Event:ResourceResolve", out List<StaticValue>? remaining));
        Assert.Equal(new[] { first, different }, remaining);
        Update(false, equivalent);
        Update(false, equivalent); // absent removal is a no-op
        Update(true, StaticValue.Null);
        Update(false, StaticValue.Null);
        Assert.True(state.Heap.TryGetModelValue(domain, "Event:ResourceResolve", out remaining));
        Assert.Equal(new[] { different }, remaining);

        void Update(bool add, StaticValue value) => Assert.Equal(StaticExecutionStatus.Completed,
            AppDomainEvents.Update(state.Heap, domain, "ResourceResolve", value, add).Status);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ResourceResolutionPreservesOrderAndStopsAtFirstAssembly(bool firstAnswers)
    {
        using var module = new ModuleDefUser("satellite.dll");
        new AssemblyDefUser("satellite", new Version(1, 0)).Modules.Add(module);
        module.Resources.Add(new EmbeddedResource("payload", new byte[] { 1, 2, 3 }, ManifestResourceAttributes.Public));
        using var bytes = new MemoryStream();
        module.Write(bytes);
        var state = new StaticMachineState(new StaticMachineLimits());
        Assert.True(state.TryGetOrAllocateRuntimeSingleton("System.AppDomain", out var domain));
        Assert.True(state.Heap.TryAllocateObject("System.Reflection.Assembly", out var assembly));
        Assert.True(state.Heap.TrySetModelValue(assembly, "LoadedImage", bytes.ToArray()));
        Assert.True(state.Heap.TryAllocateObject("System.Reflection.Assembly", out var requester));
        Assert.True(state.Heap.TryAllocateString("payload", out var name));
        var method = new MethodDefUser("Resolve", MethodSig.CreateStatic(module.CorLibTypes.Object));
        var first = Handler(state, method);
        var second = Handler(state, new MethodDefUser("Second", MethodSig.CreateStatic(module.CorLibTypes.Object)));
        var third = Handler(state, new MethodDefUser("Third", MethodSig.CreateStatic(module.CorLibTypes.Object)));
        foreach (var handler in new[] { first, second, third })
            Assert.Equal(StaticExecutionStatus.Completed,
                AppDomainEvents.Update(state.Heap, domain, "ResourceResolve", handler, true).Status);
        var seen = new List<StaticValue>();
        var context = new IntrinsicContext(state, (handler, args) =>
        {
            Assert.Equal(domain, args[0]);
            var getter = new MemberRefUser(module, "get_RequestingAssembly",
                MethodSig.CreateInstance(module.CorLibTypes.Object),
                module.CorLibTypes.GetTypeRef("System", "ResolveEventArgs"));
            var requesting = new LoaderFrameworkIntrinsic().Invoke(new IntrinsicContext(state), getter, [args[1]]);
            Assert.Equal(StaticExecutionStatus.Completed, requesting.Status);
            Assert.Equal(requester, requesting.Value);
            seen.Add(handler);
            // Removal during dispatch must not change this dispatch's captured subscriptions.
            if (handler == first)
                AppDomainEvents.Update(state.Heap, domain, "ResourceResolve", second, false);
            return IntrinsicResult.Completed(handler == first && !firstAnswers ? StaticValue.Null : assembly);
        });
        var call = new MemberRefUser(module, "GetManifestResourceStream",
            MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.String),
            module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly"));
        var answer = new LoaderFrameworkIntrinsic().Invoke(context, call, [requester, name]);
        Assert.Equal(StaticExecutionStatus.Completed, answer.Status);
        Assert.True(state.Heap.TryGetModelValue(answer.Value, "Buffer", out StaticValue buffer));
        Assert.Equal(new byte[] { 1, 2, 3 }, state.Heap.GetBytesSnapshot(buffer));
        Assert.Equal(firstAnswers ? new[] { first } : new[] { first, second }, seen);
    }

    private static StaticValue Handler(StaticMachineState state, IMethod method, StaticValue? target = null)
    {
        Assert.True(state.Heap.TryAllocateObject("System.ResolveEventHandler", out var value));
        Assert.True(state.Heap.TrySetModelValue(value, StaticMachine.DelegateMethodKey, method));
        Assert.True(state.Heap.TrySetModelValue(value, StaticMachine.DelegateTargetKey, target ?? StaticValue.Null));
        return value;
    }
}
