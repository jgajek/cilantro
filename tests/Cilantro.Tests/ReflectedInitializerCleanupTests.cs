using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ReflectedInitializerCleanupTests
{
    [Theory]
    [InlineData("attributed", true)]
    [InlineData("application", false)]
    [InlineData("effect", false)]
    [InlineData("handle", false)]
    public void OnlyAttributedEmptyInitializerMayLoseItsProtectorMetadata(string mode, bool removed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Application");
            var initializer = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() }; owner.Methods.Add(initializer);
            if (mode == "effect")
            {
                var field = new FieldDefUser("State", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static | FieldAttributes.Private); owner.Fields.Add(field);
                initializer.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction()); initializer.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(field));
            }
            initializer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var helper = new MethodDefUser("UnusedApplicationMethod", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL,
                MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() }; owner.Methods.Add(helper); helper.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var root = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() }; module.GlobalType.Methods.Add(root);
            root.Body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(owner)); root.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            if (mode == "handle") { root.Body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(initializer)); root.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); }
            root.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var owner = context.Module.GetTypes().Single(t => t.Name == "Application");
        var initializer = owner.FindStaticConstructor();
        if (mode != "application") RecoveryOrphans.Declare(context, initializer);
        RecoveryOrphans.Declare(context, owner.Methods.Single(m => m.Name == "UnusedApplicationMethod"));
        context.SetFact("options.removeRuntime", true);
        Assert.True(ModuleReachability.Compute(context.Module).IsReflectivelyExposed(owner));
        var originalLocation = $"{initializer.MDToken} {initializer.FullName}";
        new RuntimeCleanupPass().Run(context);
        Assert.Equal(removed, !owner.Methods.Contains(initializer));
        if (removed) Assert.Contains(context.Changes, change => change.Kind == "remove-dead-method" && change.Location == originalLocation);
        Assert.Contains(owner.Methods, m => m.Name == "UnusedApplicationMethod");
    }
}
