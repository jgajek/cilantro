using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ReactorRuntimeOwnerCleanupTests
{
    private static readonly string[] HelperNames = ["ReadStrings", "BindProxies", "Keep"];
    [Theory]
    [InlineData("dead", false, false)]
    [InlineData("live", true, false)]
    [InlineData("public", true, false)]
    [InlineData("same-resource", true, true)]
    [InlineData("handle", true, true)]
    public void AttributedDecoyCanAnchorOnlyACompletelyDeadRuntimeNest(string scenario, bool ownerRemains, bool decoyRemains)
    {
        using var context = SyntheticContext.Build(module =>
        {
            module.Resources.Add(new EmbeddedResource("strings", [1], ManifestResourceAttributes.Private));
            module.Resources.Add(new EmbeddedResource("proxies", [2], ManifestResourceAttributes.Private));
            var owner = SyntheticContext.AddType(module, "a1B2c3D4e5F6");
            if (scenario == "public") owner.Attributes = TypeAttributes.Public;
            var spare = SyntheticContext.AddType(module, "UnusedApplicationType");
            Add(spare, "Unused", module.CorLibTypes.Void).Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            foreach (var name in HelperNames)
                Add(owner, name, module.CorLibTypes.Void).Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            owner.Fields.Add(new FieldDefUser("Cache", new FieldSig(new SZArraySig(module.CorLibTypes.Byte)), FieldAttributes.Private | FieldAttributes.Static));
            var decoy = Add(owner, "Decoy", new SZArraySig(module.CorLibTypes.Byte));
            decoy.Attributes = MethodAttributes.Assembly | MethodAttributes.HideBySig;
            decoy.MethodSig = MethodSig.CreateInstance(new SZArraySig(module.CorLibTypes.Byte));
            var length = new MemberRefUser(module, "get_Length", MethodSig.CreateInstance(module.CorLibTypes.Int32), module.CorLibTypes.String.TypeDefOrRef);
            foreach (var i in new[] { OpCodes.Ldstr.ToInstruction("arbitrary literal"), OpCodes.Callvirt.ToInstruction(length), OpCodes.Pop.ToInstruction(),
                OpCodes.Ldc_I4_2.ToInstruction(), OpCodes.Newarr.ToInstruction(module.CorLibTypes.Byte.TypeDefOrRef), OpCodes.Dup.ToInstruction(),
                OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stelem_I1.ToInstruction(), OpCodes.Dup.ToInstruction(),
                OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Ldc_I4_2.ToInstruction(), OpCodes.Stelem_I1.ToInstruction(), OpCodes.Ret.ToInstruction() }) decoy.Body.Instructions.Add(i);
            var api = SyntheticContext.AddType(module, "Api"); api.Attributes = TypeAttributes.Public;
            var run = Add(api, "Run", module.CorLibTypes.Void); run.Attributes = MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig;
            if (scenario == "live") run.Body.Instructions.Add(OpCodes.Call.ToInstruction(owner.Methods.Single(m => m.Name == "Keep")));
            if (scenario == "handle") { run.Body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(owner)); run.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); }
            run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var owner = context.Module.GetTypes().Single(t => t.Name == "a1B2c3D4e5F6");
        var resources = context.Module.Resources.OfType<EmbeddedResource>().ToArray();
        DecodedResourceOwnership.Remember(context, RecoveredResourceOrigin.Capture(resources[0]), [owner.Methods.Single(m => m.Name == "ReadStrings")]);
        DecodedResourceOwnership.Remember(context, RecoveredResourceOrigin.Capture(resources[scenario == "same-resource" ? 0 : 1]),
            [owner.Methods.Single(m => m.Name == "BindProxies")], [owner]);
        context.SetFact("options.removeRuntime", true);
        context.SetFact("method-protection.complete", true);
        context.SetFact("reactor.structure", new ReactorStructureFacts(0, 0, 0, 0, 0, 0, 0, false, false, ReactorCapability.ProtectedStrings, 1, "test"));
        new RuntimeCleanupPass().Run(context);
        Assert.Equal(ownerRemains, context.Module.GetTypes().Contains(owner));
        Assert.Equal(decoyRemains, context.Module.GetTypes().SelectMany(t => t.Methods).Any(m => m.Name == "Decoy"));
        Assert.Contains(context.Module.GetTypes(), t => t.Name == "UnusedApplicationType");
        if (ownerRemains) Assert.Contains(owner.Methods, m => m.Name == "Keep");
    }

    private static MethodDefUser Add(TypeDef owner, string name, TypeSig result)
    {
        var method = new MethodDefUser(name, MethodSig.CreateStatic(result), MethodImplAttributes.IL,
            MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig) { Body = new CilBody() };
        owner.Methods.Add(method); return method;
    }
}
