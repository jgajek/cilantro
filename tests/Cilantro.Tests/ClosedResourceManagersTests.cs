using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ClosedResourceManagersTests
{
    [Theory]
    [InlineData("direct", 1)]
    [InlineData("spilled", 1)]
    [InlineData("no-cast", 1)]
    [InlineData("field-reader", 1)]
    [InlineData("unused-local", 1)]
    [InlineData("used-local", 0)]
    [InlineData("public-cache", 0)]
    [InlineData("other-writer", 0)]
    [InlineData("address", 0)]
    [InlineData("foreign", 0)]
    [InlineData("unknown-manager", 0)]
    [InlineData("dynamic-base", 0)]
    [InlineData("alternate-entry", 0)]
    [InlineData("unsupported-reader", 0)]
    public void OnlyClosedFrameworkManagersPermitUnrelatedProtectorDataRemoval(string scenario, int expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            module.Resources.Add(new EmbeddedResource("protector", new byte[] { 1, 2 }, ManifestResourceAttributes.Private));
            module.Resources.Add(new EmbeddedResource("App.resources", new byte[] { 3, 4 }, ManifestResourceAttributes.Private));
            module.Resources.Add(new EmbeddedResource("Other.fr.RESOURCES", new byte[] { 5, 6 }, ManifestResourceAttributes.Private));
            var owner = SyntheticContext.AddType(module, "Resources");
            var manager = new TypeRefUser(module, "System.Resources", "ResourceManager",
                scenario == "foreign" ? new AssemblyRefUser("Foreign") : module.CorLibTypes.AssemblyRef);
            var systemType = module.CorLibTypes.GetTypeRef("System", "Type");
            var assembly = module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly");
            var culture = module.CorLibTypes.GetTypeRef("System.Globalization", "CultureInfo");
            var cache = new FieldDefUser("Cache", new FieldSig(manager.ToTypeSig()), FieldAttributes.Static |
                (scenario == "public-cache" ? FieldAttributes.Public : FieldAttributes.Private)); owner.Fields.Add(cache);
            var get = new MethodDefUser("get_ResourceManager", MethodSig.CreateStatic(manager.ToTypeSig()))
                { Attributes = MethodAttributes.Static, Body = new CilBody() }; owner.Methods.Add(get);
            var cached = OpCodes.Ldsfld.ToInstruction(cache);
            var create = OpCodes.Ldstr.ToInstruction("App");
            var il = get.Body.Instructions;
            il.Add(OpCodes.Ldsfld.ToInstruction(cache)); il.Add(OpCodes.Brtrue.ToInstruction(cached)); il.Add(OpCodes.Br.ToInstruction(create));
            il.Add(cached); il.Add(OpCodes.Ret.ToInstruction()); il.Add(create);
            var token = OpCodes.Ldtoken.ToInstruction(owner); il.Add(token);
            il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetTypeFromHandle",
                MethodSig.CreateStatic(systemType.ToTypeSig(), new ValueTypeSig(module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle"))), systemType)));
            if (scenario != "no-cast") il.Add(OpCodes.Castclass.ToInstruction(systemType));
            il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_Assembly", MethodSig.CreateInstance(assembly.ToTypeSig()), systemType)));
            il.Add(OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String, assembly.ToTypeSig()), manager)));
            il.Add(OpCodes.Stsfld.ToInstruction(cache)); il.Add(OpCodes.Br.ToInstruction(cached));
            if (scenario is "unused-local" or "used-local")
            {
                var spare = new Local(module.CorLibTypes.Object); get.Body.Variables.Add(spare);
                if (scenario == "used-local")
                { il.Insert(0, OpCodes.Stloc.ToInstruction(spare)); il.Insert(0, OpCodes.Ldnull.ToInstruction()); }
            }
            if (scenario == "dynamic-base") { create.OpCode = OpCodes.Ldnull; create.Operand = null; }
            if (scenario == "alternate-entry")
            { il.Insert(0, OpCodes.Br.ToInstruction(token)); il.Insert(0, OpCodes.Ldstr.ToInstruction("Other")); }
            var run = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.Object))
                { Attributes = MethodAttributes.Static, Body = new CilBody() }; owner.Methods.Add(run);
            var body = run.Body.Instructions;
            if (scenario == "other-writer") { body.Add(OpCodes.Ldnull.ToInstruction()); body.Add(OpCodes.Stsfld.ToInstruction(cache)); }
            if (scenario == "address") { body.Add(OpCodes.Ldsflda.ToInstruction(cache)); body.Add(OpCodes.Pop.ToInstruction()); }
            body.Add(scenario == "unknown-manager" ? OpCodes.Ldnull.ToInstruction() : scenario == "field-reader" ?
                OpCodes.Ldsfld.ToInstruction(cache) : OpCodes.Call.ToInstruction(get));
            body.Add(OpCodes.Ldstr.ToInstruction("Payload")); body.Add(OpCodes.Ldnull.ToInstruction());
            if (scenario == "spilled")
            {
                var name = new Local(module.CorLibTypes.String); var lang = new Local(culture.ToTypeSig());
                run.Body.Variables.Add(name); run.Body.Variables.Add(lang); run.Body.InitLocals = true;
                body.Add(OpCodes.Stloc.ToInstruction(lang)); body.Add(OpCodes.Stloc.ToInstruction(name));
                body.Add(OpCodes.Castclass.ToInstruction(manager)); body.Add(OpCodes.Ldloc.ToInstruction(name)); body.Add(OpCodes.Ldloc.ToInstruction(lang));
            }
            body.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, scenario == "unsupported-reader" ? "UnknownRead" : "GetObject",
                MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.String, culture.ToTypeSig()), manager)));
            body.Add(OpCodes.Ret.ToInstruction());
        });
        context.SetFact("options.removeRuntime", true);
        // Attribute all three streams to verify that ResourceManager's entire resource
        // name family stays protected, even if a generic decoder also recorded it.
        context.SetFact<IReadOnlyList<RecoveredResourceOrigin>>("strings.validatedResources",
            context.Module.Resources.OfType<EmbeddedResource>().Select(RecoveredResourceOrigin.Capture).ToArray());
        var bodies = context.Module.GetTypes().SelectMany(t => t.Methods).ToDictionary(m => m, MethodBodySnapshot.Capture);
        var result = new ProtectorResourceCleanupPass().Run(context);
        Assert.Equal(expected, result.Changes);
        Assert.Contains(context.Module.Resources, r => r.Name == "App.resources");
        Assert.Contains(context.Module.Resources, r => r.Name == "Other.fr.RESOURCES");
        Assert.True(bodies.All(p => p.Value.StructurallyEquals(p.Key)));
    }
}
