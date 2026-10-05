using Cilantro.Core;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ReconstructionStateAuditTests
{
    [Theory]
    [InlineData("none", "Bounded application comparison matched")]
    [InlineData("application", "Application comparison differed")]
    [InlineData("payload", "Application comparison differed")]
    [InlineData("shared", "Application comparison incomplete")]
    [InlineData("handle", "Application comparison incomplete")]
    [InlineData("callback", "Application comparison incomplete")]
    [InlineData("retained", "Application comparison incomplete")]
    [InlineData("unresolved", "Application comparison incomplete")]
    public void ApplicationContractCannotHideBehaviorDifferencesOrEscapes(string variant, string expected)
    {
        var trial = new RebuiltMethodTrial.Result(DevirtualizationCheck.Disagreed, "VM cache",
            NonVmStateMatched: variant != "application", VmStateShared: variant == "shared",
            ResolverBehaviorUnproven: variant == "callback", VmMetadataEscaped: variant == "handle");
        var audit = new ReconstructionStateAuditPass.TrialAudit([trial, new(DevirtualizationCheck.NotMade, "null stream fixture")],
            variant == "payload" ? DevirtualizationCheck.Disagreed : DevirtualizationCheck.Agreed);
        var field = new ReconstructionStateAuditPass.FieldAudit(0x04000001, "Cache", variant == "retained", false, [], variant != "unresolved");
        var result = ReconstructionStateAuditPass.AssessApplication(audit, [field]);
        Assert.StartsWith(expected, result);
        Assert.Contains("1 inconclusive fixtures", result);
    }

    [Fact]
    public void UnresolvedTokenIsNotEvidenceOfRemoval()
    {
        using var context = SyntheticContext.Build(module => SyntheticContext.AddType(module, "Host"));
        var audit = Assert.Single(ReconstructionStateAuditPass.Inspect(context.Module, [0x0400FFFF]));
        Assert.False(audit.Resolved);
        context.SetFact<IReadOnlyList<uint>>(ReconstructionStateAuditPass.FieldsFact, [0x0400FFFF]);
        var result = new ReconstructionStateAuditPass().Run(context);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Contains("0 removed, 0 retained, 1 unresolved", StringComparison.Ordinal));
    }

    [Fact]
    public void FinalAuditDistinguishesRemovedRootsFromSurvivingAddressEscapes()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var engine = SyntheticContext.AddType(module, "Engine");
            var field = new FieldDefUser("Cache", new FieldSig(module.CorLibTypes.Int32),
                FieldAttributes.Public | FieldAttributes.Static);
            engine.Fields.Add(field);
            var host = SyntheticContext.AddType(module, "Host");
            var observer = new MethodDefUser("Observe", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL, MethodAttributes.Static) { Body = new CilBody() };
            observer.Body.Instructions.Add(OpCodes.Ldsflda.ToInstruction(field));
            observer.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            observer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            host.Methods.Add(observer);
        });
        var engine = context.Module.GetTypes().Single(type => type.Name == "Engine");
        var field = engine.Fields.Single();
        var token = field.MDToken.Raw;
        field.Name = "RenamedCache";
        var retained = Assert.Single(ReconstructionStateAuditPass.Inspect(context.Module, [token]));
        Assert.True(retained.Retained);
        Assert.True(retained.ExternallyVisible);
        Assert.Single(retained.References);
        Assert.Contains("RenamedCache", retained.Name);

        // Even deleting the owner cannot hide a dangling reference in surviving code.
        context.Module.Types.Remove(engine);
        var dangling = Assert.Single(ReconstructionStateAuditPass.Inspect(context.Module, [token]));
        Assert.False(dangling.Retained);
        Assert.Single(dangling.References);
        context.Module.GetTypes().Single(type => type.Name == "Host").Methods.Clear();
        var removed = Assert.Single(ReconstructionStateAuditPass.Inspect(context.Module, [token]));
        Assert.False(removed.Retained);
        Assert.Empty(removed.References);

        context.SetFact<IReadOnlyList<uint>>(ReconstructionStateAuditPass.FieldsFact, [token]);
        var result = new ReconstructionStateAuditPass().Run(context);
        Assert.Equal(PassStatus.Partial, result.Status);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Contains("disagreement is unchanged", StringComparison.Ordinal));
        Assert.False(new ReconstructionStateAuditPass().GatesEmission);
    }
}
