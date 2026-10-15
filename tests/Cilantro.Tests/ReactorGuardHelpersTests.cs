using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ReactorGuardHelpersTests
{
    [Theory]
    [InlineData("dead", true)]
    [InlineData("reflected", true)]
    [InlineData("reflected-handle", false)]
    [InlineData("reflected-named", false)]
    [InlineData("live", false)]
    [InlineData("handle", false)]
    [InlineData("dead-caller", false)]
    [InlineData("writer", false)]
    [InlineData("address", false)]
    [InlineData("extra-reader", false)]
    [InlineData("typed-field", true)] // Type restoration may specialize Reactor's Object storage to its owner.
    [InlineData("human-name", false)]
    [InlineData("missing-pair", false)]
    [InlineData("public-getter", false)]
    [InlineData("incomplete", false)]
    [InlineData("not-reactor", false)]
    [InlineData("disabled", false)]
    [InlineData("named-field", false)]
    [InlineData("named-getter", false)]
    [InlineData("static-owner", true)]
    [InlineData("static-owner-writer", false)]
    [InlineData("static-owner-named", false)]
    [InlineData("static-owner-instance", false)]
    [InlineData("family", true)]
    [InlineData("family-mismatch", false)]
    [InlineData("family-human-owner", true)] // Injected helpers also live on application types with preserved names.
    [InlineData("family-named", false)]
    public void RemovesOnlyClosedUnusedGuardPairsAndTheirStorage(string scenario, bool removed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Application");
            var staticOwner = scenario.StartsWith("static-owner", StringComparison.Ordinal);
            var family = scenario.StartsWith("family", StringComparison.Ordinal);
            if (family && scenario != "family-human-owner") owner.Name = "a1B2c3D4e5F6";
            if (staticOwner) { owner.Name = "a1B2c3D4e5F6"; owner.Attributes |= TypeAttributes.Abstract | TypeAttributes.Sealed; }
            var field = new FieldDefUser(scenario == "human-name" || staticOwner ? "Instance" : "a1B2c3D4e5F6",
                new FieldSig(scenario == "typed-field" ? owner.ToTypeSig() : module.CorLibTypes.Object), FieldAttributes.Private | FieldAttributes.Static);
            owner.Fields.Add(field);
            if (family) field.Name = "aaaaBBBBccccDD1234";
            var get = Add(owner, "b2C3d4E5f6G7", owner.ToTypeSig());
            get.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(field)); get.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            if (scenario == "public-getter") { owner.Attributes |= TypeAttributes.Public; get.Attributes = MethodAttributes.Public | MethodAttributes.Static; }
            var test = Add(owner, "c3D4e5F6g7H8", module.CorLibTypes.Boolean);
            test.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(field)); test.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            test.Body.Instructions.Add(OpCodes.Ceq.ToInstruction()); test.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            if (family)
            {
                get.Name = scenario == "family-mismatch" ? "b2C3d4E5f6G7" : "aB1cD2eF3gH4iJ5kL6";
                test.Name = "bC1dE2fG3hI4jK5lM6";
                Assert.False(ReactorNameHeuristics.IsGeneratedName(field.Name.String));
            }
            if (scenario == "missing-pair") owner.Methods.Remove(test);
            var unused = Add(owner, "ApplicationHelper", module.CorLibTypes.Void); unused.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            if (scenario == "static-owner-instance") unused.Attributes &= ~MethodAttributes.Static;
            var root = Add(module.GlobalType, ".cctor", module.CorLibTypes.Void);
            root.Attributes |= MethodAttributes.SpecialName | MethodAttributes.RTSpecialName;
            var il = scenario == "dead-caller" ? unused.Body.Instructions : root.Body.Instructions;
            if (scenario.StartsWith("reflected", StringComparison.Ordinal)) { il.Add(OpCodes.Ldtoken.ToInstruction(owner)); il.Add(OpCodes.Pop.ToInstruction()); }
            if (scenario == "reflected-handle") { il.Add(OpCodes.Ldftn.ToInstruction(get)); il.Add(OpCodes.Pop.ToInstruction()); }
            if (scenario == "reflected-named") { il.Add(OpCodes.Ldstr.ToInstruction(get.Name.String)); il.Add(OpCodes.Pop.ToInstruction()); }
            if (scenario is "live" or "handle" or "dead-caller")
            { il.Insert(0, (scenario == "handle" ? OpCodes.Ldftn : OpCodes.Call).ToInstruction(get)); il.Insert(1, OpCodes.Pop.ToInstruction()); }
            if (scenario is "writer" or "static-owner-writer") { il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Stsfld.ToInstruction(field)); }
            if (scenario is "address" or "extra-reader")
            { il.Add((scenario == "address" ? OpCodes.Ldsflda : OpCodes.Ldsfld).ToInstruction(field)); il.Add(OpCodes.Pop.ToInstruction()); }
            if (scenario is "named-field" or "named-getter")
            { il.Add(OpCodes.Ldstr.ToInstruction(scenario == "named-field" ? field.Name.String : get.Name.String)); il.Add(OpCodes.Pop.ToInstruction()); }
            if (scenario is "static-owner-named" or "family-named") { il.Add(OpCodes.Ldstr.ToInstruction(field.Name.String)); il.Add(OpCodes.Pop.ToInstruction()); }
            root.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        context.SetFact("options.removeRuntime", scenario != "disabled");
        context.SetFact("method-protection.complete", scenario != "incomplete");
        context.SetFact("reactor.structure", new ReactorStructureFacts(0, 0, 0, 0, 0, 0, 0, false, false,
            ReactorCapability.DispatcherControlFlow, scenario == "not-reactor" ? 0 : 1, "test"));
        var owner = context.Module.Types.Single(t => t.Methods.Any(m => m.Name == "ApplicationHelper"));
        var application = owner.Methods.Single(m => m.Name == "ApplicationHelper");
        var original = MethodBodySnapshot.Capture(application);
        new RuntimeCleanupPass().Run(context);
        Assert.Equal(removed, owner.Fields.Count == 0);
        Assert.Contains(application, owner.Methods);
        Assert.True(original.StructurallyEquals(application));
        if (removed) Assert.Single(owner.Methods);
        Assert.True(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
            CilantroPipeline.BuildRewriteAllowance(context)).Passed);
    }

    private static MethodDefUser Add(TypeDef owner, string name, TypeSig result)
    {
        var method = new MethodDefUser(name, MethodSig.CreateStatic(result), MethodAttributes.Static | MethodAttributes.Private) { Body = new CilBody() };
        owner.Methods.Add(method); return method;
    }
}
