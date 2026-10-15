using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class NecroBitResourceOwnershipTests
{
    [Theory]
    [InlineData("owned", 1)]
    [InlineData("shared-parent", 1)]
    [InlineData("application", 0)]
    [InlineData("two-direct-inputs", 0)]
    [InlineData("no-direct-input", 0)]
    [InlineData("unobserved", 0)]
    [InlineData("changed", 0)]
    [InlineData("truncated", 0)]
    [InlineData("incomplete-table", 0)]
    [InlineData("no-write", 0)]
    public void OwnershipRequiresActualTableAssignmentAndOneDirectObservedResource(string scenario, int expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            module.Resources.Add(new EmbeddedResource("bodies", [1, 2], ManifestResourceAttributes.Private));
            module.Resources.Add(new EmbeddedResource("proxy", [3, 4], ManifestResourceAttributes.Private));
            var type = SyntheticContext.AddType(module, scenario == "application" ? "Application" : "aB1cD2eF3gH4"); type.Namespace = "";
            var field = new FieldDefUser("Table", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Static);
            type.Fields.Add(field);
            var method = new MethodDefUser("Writer", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            type.Methods.Add(method);
            method.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            method.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(field));
            if (scenario != "no-direct-input") { method.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("bodies")); method.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); }
            if (scenario == "two-direct-inputs") { method.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("proxy")); method.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); }
            method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var writer = context.Module.GetTypes().SelectMany(type => type.Methods).Single();
        var field = writer.DeclaringType.Fields.Single();
        var origin = RecoveredResourceOrigin.Capture(context.Module.Resources.OfType<EmbeddedResource>().First());
        var observations = new List<LoaderObservation>();
        if (scenario != "unobserved") observations.Add(new(LoaderObservationKind.ManagedResourceRead,
            System.Text.Json.JsonSerializer.Serialize(new ManagedResourceRead(origin.Name, scenario == "changed" ? "wrong" : origin.Sha256, 2)), null, [writer.MDToken.Raw]));
        if (scenario == "shared-parent") observations.Add(new(LoaderObservationKind.ManagedResourceRead,
            System.Text.Json.JsonSerializer.Serialize(new ManagedResourceRead("proxy", "other", 2)), null, [writer.MDToken.Raw, 0x06000002]));
        var rewrite = new InterpretedRewrite(new(StaticExecutionStatus.Completed, default), [], [], new Dictionary<uint, int>(),
            new Dictionary<uint, IReadOnlyDictionary<int, int>>(), [new(7, [0x2a], false)],
            new(observations, new Dictionary<uint, LoaderMethodEffects> { [writer.MDToken.Raw] = new(scenario == "no-write" ? [] : [field.FullName], false, false, []) })
            { ObservationsTruncated = scenario == "truncated" }) { NecroBitTables = [new(field.FullName, scenario == "incomplete-table" ? [8] : [7])] };
        var ownership = NecroBitResourceOwnership.Capture(context, rewrite);
        Assert.Equal(expected, ownership.Count);
        context.SetFact("method-protection.necroBitResources", ownership);
        context.SetFact("method-protection.complete", true);
        Assert.Empty(NecroBitResourceOwnership.RemovedOrigins(context));
        writer.DeclaringType.Methods.Remove(writer);
        Assert.Empty(NecroBitResourceOwnership.RemovedOrigins(context));
        field.DeclaringType.Fields.Remove(field);
        Assert.Equal(expected, NecroBitResourceOwnership.RemovedOrigins(context).Count());
        context.SetFact("method-protection.complete", false);
        Assert.Empty(NecroBitResourceOwnership.RemovedOrigins(context));
    }
}
