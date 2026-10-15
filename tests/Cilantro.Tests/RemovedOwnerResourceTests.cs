using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class RemovedOwnerResourceTests
{
    private static readonly string[] Owners = ["numeric", "integrity", "necrobit", "strings", "proxies", "bundle"];
    private static readonly string[] States = ["removed", "retained", "changed", "reader", "application", "duplicate", "incomplete"];
    public static IEnumerable<object[]> Cases =>
        from owner in Owners
        from state in States
        select new object[] { owner, state, state is "removed" or "reader" || owner is "numeric" or "strings" or "proxies" or "bundle" && state == "incomplete" ? 1 : 0 };

    [Theory]
    [MemberData(nameof(Cases))]
    public void PhysicalOwnerRetirementIsRequiredDespiteApplicationLoading(string kind, string state, int expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            module.Resources.Add(new EmbeddedResource("retired", new byte[] { 1, 2 }, ManifestResourceAttributes.Private));
            module.Resources.Add(new EmbeddedResource("decoded", new byte[] { 3, 4 }, ManifestResourceAttributes.Private));
            var owner = SyntheticContext.AddType(module, "Protector");
            owner.Fields.Add(new FieldDefUser("Table", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Static));
            var writer = new MethodDefUser("Write", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static | MethodAttributes.Private, Body = new CilBody() };
            writer.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); owner.Methods.Add(writer);
            var app = SyntheticContext.AddType(module, "App");
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            app.Methods.Add(run);
            var assembly = module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly");
            run.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            run.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "Load",
                MethodSig.CreateStatic(assembly.ToTypeSig(), new SZArraySig(module.CorLibTypes.Byte)), assembly)));
            if (state == "reader")
            {
                run.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
                run.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetManifestResourceStream",
                    MethodSig.CreateInstance(module.CorLibTypes.GetTypeRef("System.IO", "Stream").ToTypeSig(), module.CorLibTypes.String), assembly)));
            }
            run.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var owner = context.Module.Types.Single(t => t.Name == "Protector");
        var origin = RecoveredResourceOrigin.Capture((EmbeddedResource)context.Module.Resources[0]);
        if (kind == "numeric") context.SetFact<IReadOnlyList<NumericResourceOwnership>>(NumericResourceOwnership.Fact, [new(owner, origin)]);
        if (kind == "integrity") context.SetFact<IReadOnlyList<IntegrityResourceOwnership>>("integrity.resourceOwners", [new(owner.Methods[0], origin)]);
        if (kind == "necrobit") context.SetFact<IReadOnlyList<NecroBitResourceOwnership>>("method-protection.necroBitResources", [new(owner.Methods[0], owner.Fields[0], origin)]);
        if (kind is "strings" or "proxies") DecodedResourceOwnership.Remember(context, origin, owner.Methods,
            kind == "proxies" ? new[] { owner } : null);
        if (kind == "bundle") DecodedResourceOwnership.Remember(context, origin, owner.Methods,
            bundle: new(origin, [RecoveredResourceOrigin.Capture((EmbeddedResource)context.Module.Resources[1])]));
        if (state != "retained")
        {
            context.SetFact("cleanup.removedTypeCount", 1);
            context.SetFact("cleanup.removedFieldCount", 1);
            context.SetFact<IReadOnlySet<uint>>("cleanup.removedMethodTokens", owner.Methods.Select(m => m.MDToken.Raw).ToHashSet());
            context.Module.Types.Remove(owner);
        }
        if (state == "changed") context.Module.Resources[0] = new EmbeddedResource("retired", new byte[] { 7 }, ManifestResourceAttributes.Private);
        if (state == "duplicate") context.Module.Resources.Add(new EmbeddedResource("retired", new byte[] { 1, 2 }, ManifestResourceAttributes.Private));
        if (state == "application") context.SetFact<IReadOnlyList<ResourceRoleFact>>("resource.roles", [new("retired", ResourceRole.ManagedPayload, 1, [], [])]);
        context.SetFact("method-protection.complete", state != "incomplete");
        context.SetFact("options.removeRuntime", true);
        context.SetFact("proxy.validatedResource", RecoveredResourceOrigin.Capture((EmbeddedResource)context.Module.Resources[1]));
        Assert.Equal(expected, new ProtectorResourceCleanupPass().Run(context).Changes);
        Assert.Contains(context.Module.Resources, r => r.Name == "decoded");
    }
}
