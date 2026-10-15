using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class LoaderResourceProvenanceTests
{
    [Theory]
    [InlineData("complete", 1)]
    [InlineData("live", 0)]
    [InlineData("unattributed", 0)]
    [InlineData("incomplete", 0)]
    [InlineData("no-write", 0)]
    [InlineData("mixed-inputs", 0)]
    [InlineData("truncated", 0)]
    [InlineData("debugger-truncated", 1)]
    [InlineData("resources-truncated", 0)]
    [InlineData("debugger-truncated-incomplete", 0)]
    [InlineData("integrity", 1)]
    [InlineData("unneutralized", 0)]
    public void OnlyRemovedCompletedSingleInputWriterSubtreesOwnPatchData(string scenario, int count)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Loader");
            var method = new MethodDefUser("WriteBodies", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static | MethodAttributes.Private, Body = new CilBody() };
            method.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); owner.Methods.Add(method);
        });
        var writer = context.Module.GetTypes().SelectMany(type => type.Methods).Single();
        var token = writer.MDToken.Raw;
        if (scenario != "unattributed") RebuiltMethods.RememberElidedLoaderSubtree(context, [writer]);
        if (scenario != "live") writer.DeclaringType.Methods.Remove(writer);
        var observations = new List<LoaderObservation> { Read("patch", token) };
        if (scenario == "mixed-inputs") observations.Add(Read("payload", token));
        if (scenario is "integrity" or "unneutralized")
        {
            observations.Add(new(LoaderObservationKind.SignatureVerification, "verified", true, [token]));
            context.SetFact("antitamper.neutralized", scenario == "integrity");
            context.SetFact("antitamper.entryPoint", token);
        }
        context.SetFact("method-protection.complete", true);
        context.SetFact("method-protection.restored", 1);
        context.SetFact("bootstrap.evidence", new LoaderInterpretationEvidence(observations,
            new Dictionary<uint, LoaderMethodEffects> { [token] = new([], scenario is not ("no-write" or "integrity" or "unneutralized"), false, [])
                { AllInvocationsCompleted = scenario is not ("incomplete" or "debugger-truncated-incomplete") } })
            {
                ObservationsTruncated = scenario.Contains("truncated", StringComparison.Ordinal),
                TruncatedObservationKinds = scenario switch
                {
                    "debugger-truncated" or "debugger-truncated-incomplete" => [LoaderObservationKind.DebuggerProbe],
                    "resources-truncated" => [LoaderObservationKind.ManagedResourceRead],
                    _ => null
                }
            });
        Assert.Equal(count, ProtectorResourceCleanupPass.LoaderDataOrigins(context).Count);
    }

    [Fact]
    public void EvidenceReportsObservationTruncation()
    {
        var machine = new StaticMachine();
        for (var index = 0; index < 5000; index++) machine.State.Observe(LoaderObservationKind.ManagedResourceRead, "read");
        Assert.True(machine.State.Evidence.Snapshot().ObservationsTruncated);
        Assert.True(machine.State.Evidence.Snapshot().Observations.Count < 5000);
    }

    private static LoaderObservation Read(string name, uint token) => new(LoaderObservationKind.ManagedResourceRead,
        System.Text.Json.JsonSerializer.Serialize(new ManagedResourceRead(name, "hash", 12)), null, [token]);
}
