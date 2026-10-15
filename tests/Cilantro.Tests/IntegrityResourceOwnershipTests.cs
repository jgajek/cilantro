using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class IntegrityResourceOwnershipTests
{
    [Theory]
    [InlineData("valid", true)]
    [InlineData("changed-hash", false)]
    [InlineData("keep-runtime", false)]
    [InlineData("application-owner", false)]
    [InlineData("multiple-resources", false)]
    [InlineData("unassigned-token", false)]
    public void SpecializedVerdictKeepsExactResourceProofUntilCheckerRemoval(string scenario, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, scenario == "application-owner" ? "Application" : "H1lrRRwH0tOVtn61XvY");
            type.Namespace = "";
            var method = new MethodDefUser("Check", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            type.Methods.Add(method);
            method.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("signature"));
            method.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            module.Resources.Add(new EmbeddedResource("signature", new byte[] { 1, 2, 3 }, ManifestResourceAttributes.Private));
        });
        var checker = context.Module.GetTypes().SelectMany(t => t.Methods).Single();
        var origin = RecoveredResourceOrigin.Capture((EmbeddedResource)context.Module.Resources.Single());
        if (scenario == "unassigned-token") checker.Rid = 0;
        if (scenario == "multiple-resources")
        {
            context.Module.Resources.Add(new EmbeddedResource("second", new byte[] { 4 }, ManifestResourceAttributes.Private));
            checker.Body.Instructions.Insert(0, OpCodes.Ldstr.ToInstruction("second"));
            checker.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
        }
        var token = checker.MDToken.Raw;
        var evidence = new LoaderInterpretationEvidence([
            new(LoaderObservationKind.ModuleFileRead, "FileStream over 100 module byte(s)", null, [token]),
            new(LoaderObservationKind.ManagedResourceRead, System.Text.Json.JsonSerializer.Serialize(new ManagedResourceRead("signature", scenario == "changed-hash" ? "other" : origin.Sha256, 3)), null, [token]),
            new(LoaderObservationKind.SignatureVerification, "verified", true, [token])
        ], new Dictionary<uint, LoaderMethodEffects> { [token] = new([], false, false, []) { AllInvocationsCompleted = true } });
        context.SetFact("options.removeRuntime", scenario != "keep-runtime");
        context.SetFact("method-protection.complete", true);
        IntegrityResourceOwnership.CaptureVerifiedVerdict(context, checker, evidence);
        IntegrityResourceOwnership.CaptureVerifiedVerdict(context, checker, evidence);
        Assert.Empty(IntegrityResourceOwnership.RemovedOrigins(context));
        checker.DeclaringType.Methods.Remove(checker);
        Assert.Equal(expected ? new[] { origin } : [], IntegrityResourceOwnership.RemovedOrigins(context));
    }

    [Fact]
    public void LaterCapturePreservesEarlierProofAfterTheCheckerWasRemoved()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Checker");
            var method = new MethodDefUser("Check", MethodSig.CreateStatic(module.CorLibTypes.Void)) { Attributes = MethodAttributes.Static, Body = new CilBody() };
            type.Methods.Add(method); method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var checker = context.Module.GetTypes().SelectMany(type => type.Methods).Single();
        var origin = new RecoveredResourceOrigin("signature", "hash");
        context.SetFact("options.removeRuntime", true);
        context.SetFact("method-protection.complete", true);
        context.SetFact<IReadOnlyList<IntegrityResourceOwnership>>("integrity.resourceOwners", [new(checker, origin)]);
        checker.DeclaringType.Methods.Remove(checker);
        IntegrityResourceOwnership.Capture(context);
        Assert.Equal(origin, Assert.Single(IntegrityResourceOwnership.RemovedOrigins(context)));
    }

    [Fact]
    public void OptionalProbeDoesNotPolluteTheRunsBlockerLedger()
    {
        using var context = SyntheticContext.Build(module =>
        {
            module.Resources.Add(new EmbeddedResource("signature", [1, 2], ManifestResourceAttributes.Private));
            var type = SyntheticContext.AddType(module, "aB1cD2eF3gH4"); type.Namespace = "";
            var method = new MethodDefUser("Check", MethodSig.CreateStatic(module.CorLibTypes.Void)) { Attributes = MethodAttributes.Static | MethodAttributes.Private, Body = new CilBody() };
            type.Methods.Add(method);
            method.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("signature")); method.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            var foreign = new TypeRefUser(module, "External", "Unknown", new AssemblyRefUser("External", new Version(1, 0)));
            method.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "Call", MethodSig.CreateStatic(module.CorLibTypes.Void), foreign)));
            var rsa = new TypeRefUser(module, "System.Security.Cryptography", "RSACryptoServiceProvider", module.CorLibTypes.AssemblyRef);
            for (var index = 0; index < 4; index++) method.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            method.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "VerifyHash", MethodSig.CreateInstance(module.CorLibTypes.Boolean,
                new SZArraySig(module.CorLibTypes.Byte), module.CorLibTypes.String, new SZArraySig(module.CorLibTypes.Byte)), rsa)));
            method.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        context.SetFact("options.removeRuntime", true);
        var checker = context.Module.GetTypes().SelectMany(type => type.Methods).Single();
        Assert.True(BootstrapMachine.TrySeed(context, 1000, out var control, out _));
        control!.State.RegisterRunEnvironment(new RunEnvironment());
        control.Execute(checker);
        Assert.NotEmpty(control.State.Blockers.Blockers);
        IntegrityResourceOwnership.Capture(context);
        Assert.Empty(BootstrapMachine.Environment(context).Blockers.Blockers);
        Assert.Empty(IntegrityResourceOwnership.RemovedOrigins(context));
    }

    [Theory]
    [InlineData("valid", true)]
    [InlineData("failed-signature", false)]
    [InlineData("no-signature", false)]
    [InlineData("exists-only", false)]
    [InlineData("mixed-resource", false)]
    [InlineData("changed-resource", false)]
    [InlineData("truncated", false)]
    [InlineData("incomplete", false)]
    [InlineData("image-write", false)]
    [InlineData("scratch-write", false)]
    [InlineData("registration", false)]
    [InlineData("declared", false)]
    [InlineData("stepped", false)]
    [InlineData("termination", false)]
    public void OnlyCompleteSelfSignatureEvidenceCanOwnData(string scenario, bool valid)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Checker");
            var method = new MethodDefUser("Check", MethodSig.CreateStatic(module.CorLibTypes.Void)) { Attributes = MethodAttributes.Static, Body = new CilBody() };
            type.Methods.Add(method); method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var checker = context.Module.GetTypes().SelectMany(type => type.Methods).Single(); var token = checker.MDToken.Raw;
        var origin = new RecoveredResourceOrigin("signature", "hash");
        var observations = new List<LoaderObservation> {
            new(LoaderObservationKind.ModuleFileRead, scenario == "exists-only" ? "File.Exists on the module path" : "FileStream over 100 module byte(s)", null, [token]),
            new(LoaderObservationKind.ManagedResourceRead, System.Text.Json.JsonSerializer.Serialize(new ManagedResourceRead("signature", scenario == "changed-resource" ? "wrong" : "hash", 256)), null, [token]) };
        if (scenario != "no-signature") observations.Add(new(LoaderObservationKind.SignatureVerification, "verified", scenario != "failed-signature", [token]));
        if (scenario == "mixed-resource") observations.Add(new(LoaderObservationKind.ManagedResourceRead, System.Text.Json.JsonSerializer.Serialize(new ManagedResourceRead("payload", "other", 100)), null, [token]));
        if (scenario is "declared" or "stepped" or "termination") observations.Add(new(scenario switch { "declared" => LoaderObservationKind.DeclaredCall, "stepped" => LoaderObservationKind.SteppedCall, _ => LoaderObservationKind.Termination }, "effect", null, [token]));
        var evidence = new LoaderInterpretationEvidence(observations, new Dictionary<uint, LoaderMethodEffects> {
            [token] = new([], scenario == "image-write", scenario == "scratch-write", scenario == "registration" ? ["handler"] : []) { AllInvocationsCompleted = scenario != "incomplete" } })
            { ObservationsTruncated = scenario == "truncated" };
        Assert.Equal(valid, IntegrityResourceOwnership.Valid(checker, origin, evidence));
        context.SetFact<IReadOnlyList<IntegrityResourceOwnership>>("integrity.resourceOwners", valid ? [new(checker, origin)] : []);
        context.SetFact("method-protection.complete", true);
        Assert.Empty(IntegrityResourceOwnership.RemovedOrigins(context));
        checker.DeclaringType.Methods.Remove(checker);
        Assert.Equal(valid ? 1 : 0, IntegrityResourceOwnership.RemovedOrigins(context).Count());
        context.SetFact("method-protection.complete", false);
        Assert.Empty(IntegrityResourceOwnership.RemovedOrigins(context));
    }
}
