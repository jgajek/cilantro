using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ReactorRuntimeForwardersTests
{
    private static readonly string[] HelperNames = ["ReadString", "BindProxy", "Keep", "ApplicationHelper"];
    [Theory]
    [InlineData("dead", true)]
    [InlineData("live", false)]
    [InlineData("handle", false)]
    [InlineData("typed", false)]
    [InlineData("extra-effect", false)]
    [InlineData("foreign", false)]
    [InlineData("namespace", false)]
    [InlineData("one-resource", false)]
    [InlineData("same-resource", false)]
    [InlineData("incomplete", false)]
    public void OnlyClosedAttributedErasedForwardersAreRemoved(string scenario, bool removed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            module.Resources.Add(new EmbeddedResource("strings", [1], ManifestResourceAttributes.Private));
            module.Resources.Add(new EmbeddedResource("proxies", [2], ManifestResourceAttributes.Private));
            var owner = SyntheticContext.AddType(module, "a1B2c3D4e5F6");
            owner.Namespace = "ordinary";
            var stream = scenario == "foreign" ? new TypeRefUser(module,"System.IO","Stream",new AssemblyRefUser("Foreign")) : module.CorLibTypes.GetTypeRef(scenario == "namespace" ? "Systematic" : "System.IO","Stream");
            var thunk = new MethodDefUser("Forward", MethodSig.CreateStatic(module.CorLibTypes.Int64,
                scenario == "typed" ? stream.ToTypeSig() : module.CorLibTypes.Object), MethodAttributes.Static | MethodAttributes.Private) { Body = new CilBody() };
            owner.Methods.Add(thunk);
            thunk.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            thunk.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module,"get_Length",MethodSig.CreateInstance(module.CorLibTypes.Int64),stream)));
            if(scenario=="extra-effect")
            {
                thunk.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("effect"));
                thunk.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            }
            thunk.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            foreach(var name in HelperNames) Add(owner,name);
            var root=Add(module.GlobalType,".cctor");
            root.Attributes|=MethodAttributes.SpecialName|MethodAttributes.RTSpecialName;
            root.Body.Instructions.Insert(0,OpCodes.Call.ToInstruction(owner.Methods.Single(m=>m.Name=="Keep")));
            if(scenario=="live")
            {
                root.Body.Instructions.Insert(0,OpCodes.Ldnull.ToInstruction());
                root.Body.Instructions.Insert(1,OpCodes.Call.ToInstruction(thunk));
                root.Body.Instructions.Insert(2,OpCodes.Pop.ToInstruction());
            }
            if(scenario=="handle")
            {
                root.Body.Instructions.Insert(0,OpCodes.Ldtoken.ToInstruction(thunk));
                root.Body.Instructions.Insert(1,OpCodes.Pop.ToInstruction());
            }
        });
        var owner=context.Module.GetTypes().Single(t=>t.Name=="a1B2c3D4e5F6");
        var resources=context.Module.Resources.OfType<EmbeddedResource>().ToArray();
        DecodedResourceOwnership.Remember(context,RecoveredResourceOrigin.Capture(resources[0]),[owner.Methods.Single(m=>m.Name=="ReadString")]);
        if(scenario!="one-resource") DecodedResourceOwnership.Remember(context,RecoveredResourceOrigin.Capture(resources[scenario=="same-resource" ? 0 : 1]),[owner.Methods.Single(m=>m.Name=="BindProxy")],[owner]);
        context.SetFact("options.removeRuntime",true);
        context.SetFact("method-protection.complete",scenario!="incomplete");
        context.SetFact("reactor.structure",new ReactorStructureFacts(0,0,0,0,0,0,0,false,false,ReactorCapability.ProtectedStrings,1,"test"));
        new RuntimeCleanupPass().Run(context);
        Assert.Equal(removed,!owner.Methods.Any(m=>m.Name=="Forward"));
        Assert.Contains(owner.Methods,m=>m.Name=="ApplicationHelper");
    }

    private static MethodDefUser Add(TypeDef owner,string name)
    {
        var method=new MethodDefUser(name,MethodSig.CreateStatic(owner.Module.CorLibTypes.Void),MethodAttributes.Static|MethodAttributes.Private){Body=new CilBody()};
        method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());owner.Methods.Add(method);return method;
    }
}
