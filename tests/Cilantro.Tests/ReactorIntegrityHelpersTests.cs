using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ReactorIntegrityHelpersTests
{
    [Theory]
    [InlineData("dead", true)]
    [InlineData("removed-readers", true)]
    [InlineData("dead-dependency", true)]
    [InlineData("live-dependency", true)]
    [InlineData("foreign-dependency", true)]
    [InlineData("live", false)]
    [InlineData("handle", false)]
    [InlineData("string-only", false)]
    [InlineData("proxy-only", false)]
    [InlineData("same-input", false)]
    [InlineData("other-owner", false)]
    [InlineData("bundle", false)]
    [InlineData("human-name", false)]
    [InlineData("incomplete", false)]
    [InlineData("not-reactor", false)]
    public void OnlyAttributedDeadSelfCheckersAreRemoved(string scenario, bool removed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            module.Resources.Add(new EmbeddedResource("strings", new byte[] { 1 }, ManifestResourceAttributes.Private));
            module.Resources.Add(new EmbeddedResource("proxies", new byte[] { 2 }, ManifestResourceAttributes.Private));
            var owner = SyntheticContext.AddType(module, scenario == "human-name" ? "Application" : "a1B2c3D4e5F6");
            owner.Namespace = "ordinary";
            var gate = Add(owner, "Check"); gate.Body.Instructions.Clear();
            Add(owner, "ReadString"); Add(owner, "BindProxy"); Add(owner, "UnusedApplicationHelper");
            var other = SyntheticContext.AddType(module, "Other"); Add(other, "BindProxy");
            var type = module.CorLibTypes.GetTypeRef("System", "Type");
            var assembly = module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly");
            var rsa = module.CorLibTypes.GetTypeRef("System.Security.Cryptography", "RSACryptoServiceProvider");
            foreach (var instruction in new[] {
                OpCodes.Ldtoken.ToInstruction(owner),
                OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetTypeFromHandle", MethodSig.CreateStatic(type.ToTypeSig(),
                    new ValueTypeSig(module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle"))), type)),
                OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_Assembly", MethodSig.CreateInstance(assembly.ToTypeSig()), type)),
                OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_Location", MethodSig.CreateInstance(module.CorLibTypes.String), assembly)),
                OpCodes.Pop.ToInstruction(), OpCodes.Ldnull.ToInstruction(), OpCodes.Ldnull.ToInstruction(), OpCodes.Ldnull.ToInstruction(), OpCodes.Ldnull.ToInstruction(),
                OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "VerifyHash", MethodSig.CreateInstance(module.CorLibTypes.Boolean,
                    new SZArraySig(module.CorLibTypes.Byte), module.CorLibTypes.String, new SZArraySig(module.CorLibTypes.Byte)), rsa)),
                OpCodes.Pop.ToInstruction(), OpCodes.Ldstr.ToInstruction(" is tampered."), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction()
            }) gate.Body.Instructions.Add(instruction);
            if (scenario.EndsWith("-dependency", StringComparison.Ordinal))
            {
                var helper = Add(scenario == "foreign-dependency" ? other : owner, "CheckerDependency");
                gate.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(helper));
            }
            var root = Add(module.GlobalType, ".cctor"); root.Attributes |= MethodAttributes.SpecialName | MethodAttributes.RTSpecialName;
            if (scenario == "live-dependency")
                root.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(owner.Methods.Single(m => m.Name == "CheckerDependency")));
            if (scenario is "live" or "handle")
            {
                root.Body.Instructions.Insert(0, (scenario == "live" ? OpCodes.Call : OpCodes.Ldftn).ToInstruction(gate));
                if (scenario == "handle") root.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
            }
        });
        var owner = context.Module.GetTypes().Single(t => t.Methods.Any(m => m.Name == "Check"));
        var gate = owner.Methods.Single(m => m.Name == "Check");
        var strings = RecoveredResourceOrigin.Capture((EmbeddedResource)context.Module.Resources[0]);
        var proxies = RecoveredResourceOrigin.Capture((EmbeddedResource)context.Module.Resources[1]);
        if (scenario != "proxy-only") DecodedResourceOwnership.Remember(context, strings,
            [owner.Methods.Single(m => m.Name == "ReadString")], bundle: scenario == "bundle" ? new(strings, [proxies]) : null);
        if (scenario != "string-only") DecodedResourceOwnership.Remember(context, scenario == "same-input" ? strings : proxies,
            [(scenario == "other-owner" ? context.Module.Types.Single(t => t.Name == "Other") : owner).Methods.Single(m => m.Name == "BindProxy")], [owner]);
        if (scenario == "removed-readers")
        {
            owner.Methods.Remove(owner.Methods.Single(m => m.Name == "ReadString"));
            owner.Methods.Remove(owner.Methods.Single(m => m.Name == "BindProxy"));
        }
        context.SetFact("method-protection.complete", scenario != "incomplete");
        context.SetFact("options.removeRuntime", true);
        context.SetFact("reactor.structure", new ReactorStructureFacts(0, 0, 0, 0, 0, 0, 0, false, false,
            ReactorCapability.ProtectedStrings, scenario == "not-reactor" ? 0 : 1, "test"));
        if (scenario == "dead") Assert.Contains(gate, ReactorIntegrityHelpers.Find(context));
        var result = new RuntimeCleanupPass().Run(context);
        if (removed) Assert.True(!owner.Methods.Contains(gate), string.Join("; ", result.Diagnostics));
        Assert.Equal(removed, !owner.Methods.Contains(gate));
        Assert.Contains(owner.Methods, m => m.Name == "UnusedApplicationHelper");
        if (scenario.EndsWith("-dependency", StringComparison.Ordinal))
        {
            new RuntimeCleanupPass().Run(context);
            Assert.Equal(scenario != "dead-dependency", context.Module.GetTypes().SelectMany(t => t.Methods).Any(m => m.Name == "CheckerDependency"));
            Assert.Contains(owner.Methods, m => m.Name == "UnusedApplicationHelper");
        }
    }

    private static MethodDefUser Add(TypeDef owner, string name)
    {
        var method = new MethodDefUser(name, MethodSig.CreateStatic(owner.Module.CorLibTypes.Void),
            MethodAttributes.Static | MethodAttributes.Private) { Body = new CilBody() };
        owner.Methods.Add(method); method.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); return method;
    }
}
