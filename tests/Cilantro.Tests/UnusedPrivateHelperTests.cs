using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class UnusedPrivateHelperTests
{
    [Theory]
    [InlineData("unused", true)]
    [InlineData("call", false)]
    [InlineData("handle", false)]
    [InlineData("name", false)]
    [InlineData("reflection", false)]
    [InlineData("attribute", false)]
    [InlineData("property", false)]
    [InlineData("instance", false)]
    [InlineData("public", false)]
    [InlineData("internal", false)]
    [InlineData("disabled", false)]
    [InlineData("incomplete", false)]
    public void PrunesOnlyUnusedPrivateStaticApplicationHelpers(string mode, bool removed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Application"); owner.Attributes = TypeAttributes.Public;
            var attributes = mode == "public" ? MethodAttributes.Public : mode == "internal" ? MethodAttributes.Assembly : MethodAttributes.Private;
            if (mode != "instance") attributes |= MethodAttributes.Static;
            var helper = new MethodDefUser("Helper", mode == "instance" ? MethodSig.CreateInstance(module.CorLibTypes.Int32) : MethodSig.CreateStatic(module.CorLibTypes.Int32),
                MethodImplAttributes.IL, attributes) { Body = new CilBody() }; owner.Methods.Add(helper);
            Emit(helper, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Ret.ToInstruction());
            if (mode == "attribute") helper.CustomAttributes.Add(new CustomAttribute(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), module.CorLibTypes.GetTypeRef("System", "ObsoleteAttribute"))));
            if (mode == "property")
            {
                var property = new PropertyDefUser("Value", PropertySig.CreateStatic(module.CorLibTypes.Int32)); property.GetMethods.Add(helper); owner.Properties.Add(property);
            }
            var entry = new MethodDefUser("Entry", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL,
                MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() }; owner.Methods.Add(entry);
            if (mode == "call") Emit(entry, OpCodes.Call.ToInstruction(helper), OpCodes.Pop.ToInstruction());
            if (mode == "handle") Emit(entry, OpCodes.Ldtoken.ToInstruction(helper), OpCodes.Pop.ToInstruction());
            if (mode == "name") Emit(entry, OpCodes.Ldstr.ToInstruction("Helper"), OpCodes.Pop.ToInstruction());
            if (mode == "reflection") Emit(entry, OpCodes.Ldtoken.ToInstruction(owner), OpCodes.Pop.ToInstruction());
            Emit(entry, OpCodes.Ret.ToInstruction());
        });
        context.SetFact("options.removeRuntime", mode != "disabled");
        context.SetFact("method-protection.complete", mode != "incomplete");
        var helper = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Helper");
        var token = helper.MDToken.Raw;
        var result = new UnusedPrivateHelperCleanupPass().Run(context);
        Assert.Equal(removed, !context.Module.GetTypes().SelectMany(t => t.Methods).Contains(helper));
        Assert.Equal(removed ? 1 : 0, result.Changes);
        if (removed)
        {
            Assert.Contains(context.Changes, c => c.Kind == "remove-unused-private-helper");
            Assert.DoesNotContain(token, RecoveryOrphans.Of(context));
        }
        Assert.Equal(0, new UnusedPrivateHelperCleanupPass().Run(context).Changes);
    }
    private static void Emit(MethodDef method, params Instruction[] instructions)
    {
        foreach (var instruction in instructions) method.Body.Instructions.Add(instruction);
    }
}
