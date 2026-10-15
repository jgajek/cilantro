using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ProxyResourceProvenanceTests
{
    [Theory]
    [InlineData("valid", 1)]
    [InlineData("incomplete", 0)]
    [InlineData("truncated", 0)]
    [InlineData("debugger-truncated", 1)]
    [InlineData("resource-truncated", 0)]
    [InlineData("other-table", 0)]
    [InlineData("mixed", 0)]
    [InlineData("changed", 0)]
    [InlineData("no-write", 0)]
    [InlineData("other-frame", 0)]
    public void OnlyTheCompletedValidatedTableWriterAttributesItsSingleInput(string scenario, int expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            module.Resources.Add(new EmbeddedResource("proxy", [1, 2], ManifestResourceAttributes.Private));
            var type = SyntheticContext.AddType(module, "Resolver");
            var field = new FieldDefUser("Table", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Static); type.Fields.Add(field);
            var method = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.Void)) { Attributes = MethodAttributes.Static, Body = new CilBody() }; type.Methods.Add(method);
            foreach (var instruction in new[] { OpCodes.Ldnull.ToInstruction(), OpCodes.Stsfld.ToInstruction(field), OpCodes.Ldstr.ToInstruction("proxy"), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction() }) method.Body.Instructions.Add(instruction);
        });
        var method = context.Module.GetTypes().SelectMany(type => type.Methods).Single();
        var field = method.DeclaringType.Fields.Single();
        var origin = RecoveredResourceOrigin.Capture(context.Module.Resources.OfType<EmbeddedResource>().Single());
        var observations = new List<LoaderObservation> { new(LoaderObservationKind.ManagedResourceRead,
            System.Text.Json.JsonSerializer.Serialize(new ManagedResourceRead("proxy", scenario == "changed" ? "wrong" : origin.Sha256, 2)), null,
            [scenario == "other-frame" ? 0u : method.MDToken.Raw]) };
        if (scenario == "mixed") observations.Add(new(LoaderObservationKind.ManagedResourceRead,
            System.Text.Json.JsonSerializer.Serialize(new ManagedResourceRead("payload", "other", 3)), null, [method.MDToken.Raw]));
        var evidence = new LoaderInterpretationEvidence(observations, new Dictionary<uint, LoaderMethodEffects>
            { [method.MDToken.Raw] = new(scenario == "no-write" ? [] : [field.FullName], false, false, []) { AllInvocationsCompleted = scenario != "incomplete" } })
            { ObservationsTruncated = scenario is "truncated" or "debugger-truncated" or "resource-truncated",
                TruncatedObservationKinds = scenario == "debugger-truncated" ? [LoaderObservationKind.DebuggerProbe] :
                    scenario == "resource-truncated" ? [LoaderObservationKind.ManagedResourceRead] : null };
        ProxyLoaderTable.RememberResource(context, method, scenario == "other-table" ? "wrong" : $"{field.MDToken} {field.FullName}", evidence);
        context.TryGetFact<IReadOnlyList<RecoveredResourceOrigin>>("proxy.loaderResources", out var origins);
        Assert.Equal(expected, origins?.Count ?? 0);
    }
}
