using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class IntegrityVerdictTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void UnprovenVerdictDoesNotGateEmissionUnlessFailOnPartialWasRequested(bool failOnPartial)
    {
        var directory = Directory.CreateTempSubdirectory("cilantro-integrity");
        try
        {
            using var module = new ModuleDefUser("input.dll") { Kind = ModuleKind.Dll };
            new AssemblyDefUser("input", new Version(1, 0)).Modules.Add(module);
            var initializer = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodAttributes.Static | MethodAttributes.Private | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() };
            module.GlobalType.Methods.Add(initializer);
            initializer.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            initializer.Body.Instructions.Add(OpCodes.Throw.ToInstruction());
            var input = Path.Combine(directory.FullName, "input.dll");
            module.Write(input);
            var result = new CilantroPipeline([new RetainedGateFacts(), new IntegrityVerdictPass()]).Run(input,
                new PipelineOptions(FailOnPartial: failOnPartial, ReportDirectory: directory.FullName));
            Assert.Equal(PassStatus.Partial, result.Report.Passes.Single(p => p.Pass == "integrity-verdict").Status);
            Assert.True(result.Report.VerificationPassed);
            Assert.Equal(!failOnPartial, result.Success);
            Assert.Equal(!failOnPartial, result.OutputPath is not null);
        }
        finally { directory.Delete(true); }
    }

    private sealed class RetainedGateFacts : DeobfuscationPass
    {
        public override string Name => "loader-call-recheck";
        protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
        {
            context.SetFact("method-protection.complete", true);
            context.SetFact("bootstrap.evidence", LoaderInterpretationEvidence.Empty);
            context.SetFact("reactor.structure", new ReactorStructureFacts(0, 0, 0, 0, 0, 0, 0, false, false, ReactorCapability.AntiTamper, 1, "test"));
            return (PassStatus.Success, 0, []);
        }
    }

    [Theory]
    [InlineData("passing", true)]
    [InlineData("failed", false)]
    [InlineData("unknown", false)]
    [InlineData("shared-wrapper", false)]
    [InlineData("incomplete", false)]
    [InlineData("registration", false)]
    [InlineData("image-write", false)]
    [InlineData("scratch-write", false)]
    [InlineData("no-file-read", false)]
    [InlineData("exists-only", false)]
    [InlineData("two-sites", false)]
    [InlineData("prefix", false)]
    [InlineData("public", false)]
    [InlineData("other-verdict", false)]
    public void OnlyAUniqueCompletedOriginalFileCheckIsSelected(string scenario, bool accepted)
    {
        using var module = new ModuleDefUser("test");
        var gate = Gate(module);
        if (scenario == "public") gate.Attributes = MethodAttributes.Public | MethodAttributes.Static;
        var site = gate.Body.Instructions.Single(i => i.OpCode == OpCodes.Callvirt);
        if (scenario == "two-sites") gate.Body.Instructions.Insert(0, OpCodes.Callvirt.ToInstruction((IMethod)site.Operand));
        if (scenario == "prefix") gate.Body.Instructions.Insert(gate.Body.Instructions.IndexOf(site), OpCodes.Tailcall.ToInstruction());
        var effects = new LoaderMethodEffects(["shared cache"], scenario == "image-write", scenario == "scratch-write",
            scenario == "registration" ? ["unmodeled call"] : []) { AllInvocationsCompleted = scenario != "incomplete" };
        var observations = new List<LoaderObservation>
        {
            new(LoaderObservationKind.SignatureVerification,
                scenario == "other-verdict" ? "System.Security.Cryptography.RSACryptoServiceProvider::VerifyData over bytes" : "System.Security.Cryptography.RSACryptoServiceProvider::VerifyHash over a digest",
                scenario == "unknown" ? null : scenario != "failed",
                scenario == "shared-wrapper" ? [gate.MDToken.Raw, 0x06000002] : [gate.MDToken.Raw])
        };
        if (scenario != "no-file-read") observations.Add(new(LoaderObservationKind.ModuleFileRead,
            scenario == "exists-only" ? "File.Exists on the module path" : "FileStream over 1024 module byte(s)", null, [gate.MDToken.Raw]));
        var evidence = new LoaderInterpretationEvidence(observations, new Dictionary<uint, LoaderMethodEffects> { [gate.MDToken.Raw] = effects });
        Assert.Equal(accepted, IntegrityVerdictPass.TrySelectSite(gate, evidence, out var selected));
        if (accepted) Assert.Same(site, selected);
    }

    [Fact]
    public void UnassignedReconstructionTokensDoNotCollideDuringFrameSelection()
    {
        using var module = new ModuleDefUser("test");
        var gate = Gate(module);
        var initializer = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodAttributes.Static) { Rid = 2 };
        module.GlobalType.Methods.Add(initializer);
        module.GlobalType.Methods.Add(new MethodDefUser("Generated1"));
        module.GlobalType.Methods.Add(new MethodDefUser("Generated2"));
        var observation = new LoaderObservation(LoaderObservationKind.SignatureVerification, "RSA", true, [initializer.MDToken.Raw, gate.MDToken.Raw]);
        Assert.True(AntiTamperNeutralizationPass.TryChooseEntryPoint(module, initializer, LoaderInterpretationEvidence.Empty,
            [observation], out var selected, out _, out _));
        Assert.Same(gate, selected);
    }

    [Fact]
    public void ReplacingTheVerdictRetainsArgumentEvaluationAndSharedState()
    {
        using var module = new ModuleDefUser("test");
        var gate = Gate(module);
        var state = new FieldDefUser("Cache", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static) { Rid = 1 };
        gate.DeclaringType.Fields.Add(state);
        // Evaluate a stateful argument while the receiver is already on the stack.
        gate.Body.Instructions.Insert(1, OpCodes.Ldc_I4_7.ToInstruction());
        gate.Body.Instructions.Insert(2, OpCodes.Stsfld.ToInstruction(state));
        var reader = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.Int32), MethodAttributes.Static) { Body = new CilBody(), Rid = 2 };
        gate.DeclaringType.Methods.Add(reader);
        reader.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(state));
        reader.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        var site = gate.Body.Instructions.Single(i => i.OpCode == OpCodes.Callvirt);
        IntegrityVerdictPass.ReplaceVerdict(gate, site);
        var machine = new StaticMachine();
        Assert.True(machine.Execute(gate).Succeeded);
        Assert.Equal(7, machine.Execute(reader).Value.AsInt32());
    }

    private static MethodDefUser Gate(ModuleDef module)
    {
        var type = new TypeDefUser("Gate", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(type);
        var gate = new MethodDefUser("Check", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodAttributes.Static) { Rid = 1, Body = new CilBody() };
        type.Methods.Add(gate);
        var rsa = new TypeRefUser(module, "System.Security.Cryptography", "RSACryptoServiceProvider", module.CorLibTypes.AssemblyRef);
        var verify = new MemberRefUser(module, "VerifyHash", MethodSig.CreateInstance(module.CorLibTypes.Boolean,
            new SZArraySig(module.CorLibTypes.Byte), module.CorLibTypes.String, new SZArraySig(module.CorLibTypes.Byte)), rsa);
        foreach (var instruction in new[] { OpCodes.Ldnull.ToInstruction(), OpCodes.Ldnull.ToInstruction(),
                     OpCodes.Ldstr.ToInstruction("SHA1"), OpCodes.Ldnull.ToInstruction(), OpCodes.Callvirt.ToInstruction(verify),
                     OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction() })
            gate.Body.Instructions.Add(instruction);
        return gate;
    }
}
