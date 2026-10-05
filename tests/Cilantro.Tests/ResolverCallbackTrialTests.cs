using Cilantro.Core;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ResolverCallbackTrialTests
{
    [Theory]
    [InlineData(false, false, false, false)]
    [InlineData(true, false, false, false)]
    [InlineData(false, true, false, false)]
    [InlineData(true, false, true, false)]
    [InlineData(false, false, false, true)]
    public void CallbackTrialsCheckVmEscapesAndCannotOverwriteEarlierDifferences(bool readsVm, bool earlierDifference, bool erasesLater, bool unsupported)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var engine = SyntheticContext.AddType(module, "Engine");
            var cache = new FieldDefUser("Cache", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            engine.Fields.Add(cache);
            var entry = new MethodDefUser("Entry", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL,
                MethodAttributes.Static) { Body = new CilBody() };
            foreach (var i in new[] { OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(cache), OpCodes.Ret.ToInstruction() }) entry.Body.Instructions.Add(i);
            engine.Methods.Add(entry);
            var host = SyntheticContext.AddType(module, "Host");
            var state = new FieldDefUser("State", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            host.Fields.Add(state);
            var calls = new FieldDefUser("Calls", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            host.Fields.Add(calls);
            var assembly = module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly");
            var args = module.CorLibTypes.GetTypeRef("System", "ResolveEventArgs");
            var callback = new MethodDefUser("Resolve", MethodSig.CreateStatic(assembly.ToTypeSig(), module.CorLibTypes.Object, args.ToTypeSig()),
                MethodImplAttributes.IL, MethodAttributes.Static) { Body = new CilBody() };
            if (unsupported)
            {
                callback.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("UndeclaredResolverFixtureVariable"));
                callback.Body.Instructions.Add(OpCodes.Call.ToInstruction(new Importer(module).Import(typeof(Environment).GetMethod(nameof(Environment.GetEnvironmentVariable), [typeof(string)])!)));
                callback.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            }
            var store = OpCodes.Stsfld.ToInstruction(state);
            var zero = OpCodes.Ldc_I4_0.ToInstruction();
            if (erasesLater)
            {
                callback.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(calls));
                callback.Body.Instructions.Add(OpCodes.Brtrue.ToInstruction(zero));
            }
            callback.Body.Instructions.Add(readsVm ? OpCodes.Ldsfld.ToInstruction(cache) : OpCodes.Ldc_I4_7.ToInstruction());
            if (erasesLater)
            {
                callback.Body.Instructions.Add(OpCodes.Br.ToInstruction(store));
                callback.Body.Instructions.Add(zero);
            }
            callback.Body.Instructions.Add(store);
            callback.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction());
            callback.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(calls));
            callback.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            callback.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            host.Methods.Add(callback);
            var domain = module.CorLibTypes.GetTypeRef("System", "AppDomain");
            var handler = module.CorLibTypes.GetTypeRef("System", "ResolveEventHandler");
            var ctor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr), handler);
            var current = new MemberRefUser(module, "get_CurrentDomain", MethodSig.CreateStatic(domain.ToTypeSig()), domain);
            var subscribe = new MemberRefUser(module, "add_AssemblyResolve", MethodSig.CreateInstance(module.CorLibTypes.Void, handler.ToTypeSig()), domain);
            var initializer = module.GlobalType.FindOrCreateStaticConstructor();
            initializer.Body.Instructions.Clear();
            foreach (var i in new[] { OpCodes.Call.ToInstruction(current), OpCodes.Ldnull.ToInstruction(), OpCodes.Ldftn.ToInstruction(callback),
                OpCodes.Newobj.ToInstruction(ctor), OpCodes.Callvirt.ToInstruction(subscribe), OpCodes.Ret.ToInstruction() }) initializer.Body.Instructions.Add(i);
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL,
                MethodAttributes.Static) { Body = new CilBody() };
            run.Body.Instructions.Add(OpCodes.Call.ToInstruction(entry));
            if (earlierDifference)
            {
                run.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction());
                run.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(state));
            }
            run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            host.Methods.Add(run);
        });
        var methods = context.Module.GetTypes().SelectMany(type => type.Methods).ToArray();
        var rebuilt = new CilBody();
        rebuilt.Instructions.Add(OpCodes.Ret.ToInstruction());
        var result = RebuiltMethodTrial.Compare(context, methods.Single(method => method.Name == "Run"), rebuilt, 0,
            methods.Single(method => method.Name == "Entry").MDToken.Raw, initializeModule: true);
        Assert.Equal(unsupported ? DevirtualizationCheck.NotMade : DevirtualizationCheck.Disagreed, result.Verdict);
        Assert.Equal(!readsVm && !earlierDifference && !unsupported, result.NonVmStateMatched);
        Assert.Equal(earlierDifference || unsupported, result.ResolverBehaviorUnproven);
        if (!earlierDifference && !unsupported) Assert.Contains("Resolver fixtures exercised", result.Detail);
    }
}
