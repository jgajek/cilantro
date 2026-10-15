using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using Cilantro.Core.Strings;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class RebuiltProtectorCleanupTests
{
    [Theory]
    [InlineData("dependency", true)]
    [InlineData("sibling", false)]
    [InlineData("metadata-only", false)]
    [InlineData("foreign", false)]
    [InlineData("called", false)]
    [InlineData("handle", false)]
    [InlineData("public", false)]
    [InlineData("unresolved", false)]
    public void ReplacedResolverAttributesOnlyItsActualPrivateDependencies(string scenario, bool removed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            module.Resources.Add(new EmbeddedResource("table", new byte[] { 1, 2, 3 }, ManifestResourceAttributes.Private));
            var runtime = SyntheticContext.AddType(module, "ResolverRuntime");
            if (scenario == "public") runtime.Attributes = TypeAttributes.Public;
            var application = SyntheticContext.AddType(module, "Application");
            application.Attributes = TypeAttributes.Public;
            var body = Empty(module, "Reconstructed", scenario == "public" ? MethodAttributes.Public : MethodAttributes.Private);
            (scenario == "foreign" ? application : runtime).Methods.Add(body);
            ReadingMarker.Add(module).Mark(body);
            var resolver = new MethodDefUser("Resolver", MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.Int32))
                { Attributes = MethodAttributes.Assembly | MethodAttributes.Static, Body = new CilBody() };
            runtime.Methods.Add(resolver);
            if (scenario == "metadata-only")
            {
                resolver.Body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(body));
                resolver.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            }
            else if (scenario != "sibling") resolver.Body.Instructions.Add(OpCodes.Call.ToInstruction(body));
            resolver.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("x"));
            resolver.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var entry = Empty(module, "Entry", MethodAttributes.Public); application.Methods.Add(entry);
            entry.Body.Instructions.Insert(0, OpCodes.Ldc_I4_0.ToInstruction());
            entry.Body.Instructions.Insert(1, OpCodes.Call.ToInstruction(resolver));
            entry.Body.Instructions.Insert(2, OpCodes.Pop.ToInstruction());
            if (scenario == "called") entry.Body.Instructions.Insert(3, OpCodes.Call.ToInstruction(body));
            if (scenario == "handle")
            {
                entry.Body.Instructions.Insert(3, OpCodes.Ldtoken.ToInstruction(body));
                entry.Body.Instructions.Insert(4, OpCodes.Pop.ToInstruction());
            }
        });
        var methods = context.Module.GetTypes().SelectMany(t => t.Methods).ToArray();
        var body = methods.Single(m => m.Name == "Reconstructed");
        var resolver = methods.Single(m => m.Name == "Resolver");
        // Broad historical attribution must not admit siblings or foreign application bodies.
        RecoveryOrphans.Declare(context, body);
        var table = new CapturedStringTable("test", [], [new DecodedStringRecord(scenario == "unresolved" ? 1 : 0, 1, "x")],
            new Dictionary<uint, int>(), RecoveredResourceOrigin.Capture(context.Module.Resources.OfType<EmbeddedResource>().Single()));
        var restored = StringRecoveryPass.Restore(context, "test", resolver, table);
        Assert.Equal(scenario == "unresolved" ? 0 : 1, restored.Item2);
        Assert.Equal(scenario != "unresolved", context.TryGetFact<IReadOnlyList<RecoveredResourceOrigin>>("strings.validatedResources", out var origins));
        if (scenario != "unresolved") Assert.Equal(table.Resource, Assert.Single(origins!));
        Assert.Contains(body, RebuiltMethods.CleanupRoots(context));
        context.SetFact("options.removeRuntime", true);
        new RuntimeCleanupPass().Run(context);
        Assert.Equal(!removed, context.Module.GetTypes().SelectMany(t => t.Methods).Contains(body));
        Assert.Equal(removed ? 1 : 0, context.Changes.Count(c => c.Kind == "remove-orphaned-rebuilt-method"));
        var check = AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
            CilantroPipeline.BuildRewriteAllowance(context));
        Assert.True(check.Passed, string.Join("; ", check.Diagnostics));
    }

    [Theory]
    [InlineData("elided", true)]
    [InlineData("orphan-only", false)]
    [InlineData("called", false)]
    [InlineData("handle", false)]
    [InlineData("public", false)]
    public void DirectReconstructionRequiresExplicitElidedLoaderAttribution(string scenario, bool removed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host"); host.Attributes = TypeAttributes.Public;
            var entry = Empty(module, "Entry", MethodAttributes.Public); host.Methods.Add(entry);
            var body = Empty(module, "ReconstructedLoader", scenario == "public" ? MethodAttributes.Public : MethodAttributes.Private);
            host.Methods.Add(body); ReadingMarker.Add(module).Mark(body);
            if (scenario == "called") entry.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(body));
            if (scenario == "handle")
            {
                entry.Body.Instructions.Insert(0, OpCodes.Ldtoken.ToInstruction(body));
                entry.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
            }
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "ReconstructedLoader");
        RecoveryOrphans.Declare(context, method);
        if (scenario != "orphan-only") RebuiltMethods.RememberElidedLoaderSubtree(context, [method]);
        context.SetFact("options.removeRuntime", true);
        new RuntimeCleanupPass().Run(context);
        Assert.Equal(!removed, context.Module.GetTypes().SelectMany(t => t.Methods).Contains(method));
        Assert.Equal(removed ? 1 : 0, context.Changes.Count(change =>
            change.Kind == "remove-orphaned-rebuilt-method" && change.Description.Contains("proven elided loader subtree")));
        var check = AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
            CilantroPipeline.BuildRewriteAllowance(context));
        Assert.True(check.Passed, string.Join("; ", check.Diagnostics));
    }

    [Fact]
    public void RemovingAnEntireProtectorTypeAccountsForItsNewLiftedBody()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var runtime = SyntheticContext.AddType(module, "Runtime");
            runtime.Methods.Add(Empty(module, "OriginalCaller", MethodAttributes.Private));
            var application = SyntheticContext.AddType(module, "Application");
            application.Attributes = TypeAttributes.Public;
            var entry = Empty(module, "Entry", MethodAttributes.Public);
            application.Methods.Add(entry);
            ReadingMarker.Add(module).Mark(entry);
        });
        var owner = context.Module.GetTypes().Single(t => t.Name == "Runtime");
        var caller = owner.Methods.Single();
        var entry = context.Module.GetTypes().Single(t => t.Name == "Application").Methods.Single();
        var holder = Empty(context.Module, "LiftedProgram1", MethodAttributes.Private);
        owner.Methods.Add(holder);
        holder.CustomAttributes.Add(new CustomAttribute(entry.CustomAttributes[0].Constructor,
            [new CAArgument(context.Module.CorLibTypes.String, new UTF8String(ReadingMarker.Warning))]));
        caller.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(holder));
        RecoveryOrphans.Declare(context, caller);
        var program = new VirtualProgram(new VirtualizedMethod(caller, caller, 1, 0), "Synthetic.Instruction", []);
        context.SetFact<IReadOnlyList<VirtualizationRebuildPass.LiftedRecipe>>(VirtualizationRebuildPass.LiftedRecipesFact,
            [new(program, caller.MDToken.Raw, caller.MDToken.Raw, holder)]);
        context.SetFact(VirtualizationRebuildPass.AddedMethodsFact, 1);
        context.SetFact("options.removeRuntime", true);
        new RuntimeCleanupPass().Run(context);
        Assert.DoesNotContain(owner, context.Module.GetTypes());
        Assert.Single(RebuiltMethods.Of(context));
        var check = AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
            CilantroPipeline.BuildRewriteAllowance(context));
        Assert.True(check.Passed, string.Join("; ", check.Diagnostics));
    }

    [Theory]
    [InlineData("orphan", true)]
    [InlineData("application", false)]
    [InlineData("called", false)]
    [InlineData("handle", false)]
    [InlineData("public", false)]
    public void OnlyAnOrphanedLiftedProtectorConsumerAllowsBodyRemoval(string scenario, bool removed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            host.Attributes = TypeAttributes.Public;
            host.Methods.Add(Empty(module, "Entry", MethodAttributes.Public));
            host.Methods.Add(Empty(module, "OriginalCaller", MethodAttributes.Private));
            var application = Empty(module, "ApplicationBody", MethodAttributes.Private);
            host.Methods.Add(application);
            ReadingMarker.Add(module).Mark(application);
        });
        var owner = context.Module.GetTypes().Single(t => t.Name == "Host");
        var caller = owner.Methods.Single(m => m.Name == "OriginalCaller");
        var applicationBody = owner.Methods.Single(m => m.Name == "ApplicationBody");
        var holder = Empty(context.Module, "LiftedProgram1", scenario == "public" ? MethodAttributes.Public : MethodAttributes.Private);
        var unrelated = Empty(context.Module, "UnrelatedNewBody", MethodAttributes.Private);
        owner.Methods.Add(holder);
        owner.Methods.Add(unrelated);
        foreach (var method in new[] { holder, unrelated })
            method.CustomAttributes.Add(new CustomAttribute(applicationBody.CustomAttributes[0].Constructor,
                [new CAArgument(context.Module.CorLibTypes.String, new UTF8String(ReadingMarker.Warning))]));
        caller.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(holder));
        if (scenario != "application") RecoveryOrphans.Declare(context, caller);
        // Existing broad subtree attribution is not enough to delete a reconstructed
        // application method; only the explicit lifted-consumer relation opts it out.
        RecoveryOrphans.Declare(context, applicationBody);
        var entry = owner.Methods.Single(m => m.Name == "Entry");
        if (scenario == "called") entry.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(caller));
        if (scenario == "handle")
        {
            entry.Body.Instructions.Insert(0, OpCodes.Ldtoken.ToInstruction(holder));
            entry.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
        }
        var program = new VirtualProgram(new VirtualizedMethod(caller, caller, 1, 0), "Synthetic.Instruction", []);
        context.SetFact<IReadOnlyList<VirtualizationRebuildPass.LiftedRecipe>>(VirtualizationRebuildPass.LiftedRecipesFact,
            [new(program, caller.MDToken.Raw, caller.MDToken.Raw, holder)]);
        context.SetFact(VirtualizationRebuildPass.AddedMethodsFact, 2);
        context.SetFact("options.removeRuntime", true);
        // This fixture introduces a public method only for the exposure refusal case.
        if (scenario == "public") context.SetFact<IReadOnlySet<string>>("rename.addedPublicApi",
            new HashSet<string> { ArtifactIdentitySnapshot.PublicApiEntry(holder) });

        new RuntimeCleanupPass().Run(context);

        Assert.Equal(!removed, owner.Methods.Contains(holder));
        Assert.Contains(applicationBody, owner.Methods);
        Assert.Contains(unrelated, owner.Methods);
        Assert.Equal(0u, holder.Rid);
        Assert.Equal(0u, unrelated.Rid);
        Assert.DoesNotContain(0x06000000u, RecoveryOrphans.Of(context));
        Assert.Equal(removed ? 1 : 0, context.Changes.Count(change => change.Kind == "remove-orphaned-rebuilt-method"));
        var check = AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
            CilantroPipeline.BuildRewriteAllowance(context));
        Assert.True(check.Passed, string.Join("; ", check.Diagnostics));
    }

    private static MethodDefUser Empty(ModuleDef module, string name, MethodAttributes access)
    {
        var method = new MethodDefUser(name, MethodSig.CreateStatic(module.CorLibTypes.Void))
            { Attributes = access | MethodAttributes.Static, Body = new CilBody() };
        method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        return method;
    }
}
