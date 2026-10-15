using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class SharedInitializationCompletionTests
{
    [Theory]
    [InlineData("closed", true)]
    [InlineData("reader", false)]
    [InlineData("address", false)]
    [InlineData("token", false)]
    [InlineData("named", false)]
    [InlineData("external", false)]
    [InlineData("prefix-effect", false)]
    [InlineData("throw", false)]
    [InlineData("unknown", false)]
    [InlineData("foreign-trigger", false)]
    [InlineData("alternate-entry", false)]
    [InlineData("no-provenance", false)]
    [InlineData("disabled", false)]
    public void RetiresOnlyAttributedIsolatedAndClosedInitialization(string scenario, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Shared");
            if (scenario == "external") owner.Attributes = TypeAttributes.Public;
            var app = SyntheticContext.AddType(module, "App");
            var value = new FieldDefUser("Value", new FieldSig(new SZArraySig(module.CorLibTypes.Int32)), FieldAttributes.Static | FieldAttributes.Assembly);
            owner.Fields.Add(value);
            var observed = new FieldDefUser("Observed", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static | FieldAttributes.Public); app.Fields.Add(observed);
            var init = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void))
            { Attributes = MethodAttributes.Static | MethodAttributes.Private | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, Body = new CilBody() };
            owner.Methods.Add(init);
            if (scenario == "prefix-effect")
            {
                var effect = new MethodDefUser("Effect", MethodSig.CreateStatic(module.CorLibTypes.Void)) { Attributes = MethodAttributes.Static, Body = new CilBody() };
                app.Methods.Add(effect);
                Add(effect, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(observed), OpCodes.Ret.ToInstruction());
                Add(init, OpCodes.Call.ToInstruction(effect));
            }
            if (scenario == "unknown") Add(init, OpCodes.Call.ToInstruction(new MemberRefUser(module, "Effect", MethodSig.CreateStatic(module.CorLibTypes.Void), new TypeRefUser(module, "External", "Api", new AssemblyRefUser("External")))));
            if (scenario == "throw") Add(init, OpCodes.Ldnull.ToInstruction(), OpCodes.Throw.ToInstruction());
            else Add(init, OpCodes.Ldc_I4_2.ToInstruction(), OpCodes.Newarr.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef), OpCodes.Stsfld.ToInstruction(value), OpCodes.Ret.ToInstruction());
            var dead = new MethodDefUser("Unused", MethodSig.CreateStatic(module.CorLibTypes.Void)) { Attributes = MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(dead); Add(dead, OpCodes.Ret.ToInstruction());
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void)) { Attributes = MethodAttributes.Static | MethodAttributes.Public, Body = new CilBody() };
            app.Methods.Add(run); module.EntryPoint = run;
            var trigger = OpCodes.Call.ToInstruction(new MemberRefUser(module, "RunClassConstructor", MethodSig.CreateStatic(module.CorLibTypes.Void,
                new ValueTypeSig(module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle"))), new TypeRefUser(module, "System.Runtime.CompilerServices", "RuntimeHelpers",
                    scenario == "foreign-trigger" ? new AssemblyRefUser("Foreign") : module.CorLibTypes.AssemblyRef)));
            if (scenario == "alternate-entry") Add(run, OpCodes.Ldtoken.ToInstruction(app), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Brtrue.ToInstruction(trigger), OpCodes.Pop.ToInstruction());
            Add(run, OpCodes.Ldtoken.ToInstruction(owner), trigger);
            if (scenario == "reader") Add(run, OpCodes.Ldsfld.ToInstruction(value), OpCodes.Pop.ToInstruction());
            if (scenario == "address") Add(run, OpCodes.Ldsflda.ToInstruction(value), OpCodes.Pop.ToInstruction());
            if (scenario == "token") Add(run, OpCodes.Ldtoken.ToInstruction(owner), OpCodes.Pop.ToInstruction());
            if (scenario == "named") Add(run, OpCodes.Ldstr.ToInstruction(owner.FullName), OpCodes.Pop.ToInstruction());
            Add(run, OpCodes.Ret.ToInstruction());
        });
        var owner = context.Module.GetTypes().Single(t => t.Name == "Shared");
        var run = context.Module.EntryPoint;
        var before = MethodBodySnapshot.Capture(run);
        context.SetFact("options.removeRuntime", scenario != "disabled");
        if (scenario != "no-provenance") context.SetFact<IReadOnlySet<TypeDef>>(NumericInitializationCompletionPass.SharedTypesFact, new HashSet<TypeDef> { owner });
        var result = new SharedInitializationCompletionPass().Run(context);
        Assert.True(result.Changes == (expected ? 1 : 0), string.Join("\n", result.Diagnostics));
        if (!expected) { Assert.True(before.StructurallyEquals(run)); return; }
        Assert.DoesNotContain(run.Body.Instructions, i => i.OpCode.Code is Code.Call or Code.Ldtoken);
        Assert.Equal(0, new SharedInitializationCompletionPass().Run(context).Changes);
        Assert.Equal(Cilantro.Core.PassStatus.Success, new SharedInitializerRuntimeCleanupPass().Run(context).Status);
        Assert.DoesNotContain(owner, context.Module.GetTypes());
        Assert.Same(run, context.Module.EntryPoint);
    }

    private static void Add(MethodDef method, params Instruction[] instructions)
    { foreach (var instruction in instructions) method.Body.Instructions.Add(instruction); }
}
