using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Recovery;

/// <summary>Retains an integrity routine's state changes when its whole body cannot be removed.</summary>
public sealed class IntegrityVerdictPass : DeobfuscationPass
{
    public override string Name => "integrity-verdict";
    // This is an optional improvement to an already recovered assembly. An
    // unproven site stays intact; it must not withhold otherwise valid output.
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => ["loader-call-recheck"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("method-protection.complete", out var complete) || !complete ||
            context.TryGetFact<bool>("antitamper.neutralized", out var removed) && removed ||
            !context.TryGetFact<ReactorStructureFacts>("reactor.structure", out var structure) ||
            structure is null || !structure.Capabilities.HasFlag(ReactorCapability.AntiTamper) ||
            !context.TryGetFact<LoaderInterpretationEvidence>("bootstrap.evidence", out var original) ||
            original is null ||
            original.Observations.Any(o => o.Kind == LoaderObservationKind.SignatureVerification && o.Verdict != true))
            return (PassStatus.Success, 0, ["No retained proven integrity check requires specialization."]);

        var initializer = context.Module.GlobalType.FindStaticConstructor();
        if (initializer?.HasBody != true)
            return (PassStatus.Success, 0, ["No module initializer remains."]);
        var budget = LoaderCallElisionPass.ColdInitializerStepBudget(context);
        if (!LoaderCallElisionPass.TryInterpretColdInitializer(context, initializer,
                new StaticWorkBudget(budget), new StaticWorkBudget(budget), out var evidence, out var reason))
            return (PassStatus.Partial, 0, ["Integrity verdict retained: " + reason]);
        var verifications = evidence!.Observations.Where(o => o.Kind == LoaderObservationKind.SignatureVerification).ToArray();
        if (verifications.Length == 0 || verifications.Any(o => o.Verdict != true) ||
            !AntiTamperNeutralizationPass.TryChooseEntryPoint(context.Module, initializer, evidence,
                verifications, out var gate, out _, out _))
            return (PassStatus.Partial, 0, ["No passing integrity frame was independently established."]);
        if (!TrySelectSite(gate!, evidence, out var site) ||
            !AntiTamperNeutralizationPass.TryFindCalls(context.Module, gate!, out _, out _))
            return (PassStatus.Partial, 0, ["The integrity check cannot be attributed to a unique direct verification site."]);

        using var transaction = new BodyMutationBatch([gate!]);
        ReplaceVerdict(gate!, site!);
        var verification = AssemblyVerifier.Verify(context.Module, context.OriginalIdentity,
            context.OriginalStructure, CilantroPipeline.BuildRewriteAllowance(context));
        if (!verification.Passed)
            return (PassStatus.Failed, 0, ["Integrity verdict rewrite rolled back: " + string.Join("; ", verification.Diagnostics)]);
        transaction.Commit();
        context.AddChange(new(Name, "preserve-integrity-effects", $"{gate!.MDToken} IL_{site!.Offset:X4}",
            "Replaced the independently verified original-file signature verdict with true; retained argument evaluation and the routine's state changes."));
        context.AddEvidence(new("integrity-verdict", "Two complete independent cold startups agreed on a passing, unique direct signature verification. Its stateful routine remains in place.", gate.FullName));
        return (PassStatus.Success, 1, ["Specialized one proven original-file integrity verdict while preserving initialization and shared state."]);
    }

    internal static bool TrySelectSite(MethodDef gate, LoaderInterpretationEvidence evidence, out Instruction? site)
    {
        site = null;
        if (!gate.HasBody || gate.Rid == 0 || ReadingMarker.Marks(gate) || !gate.IsStatic ||
            gate.IsPublic || gate.IsFamily || gate.IsFamilyOrAssembly || gate.HasGenericParameters || gate.DeclaringType.HasGenericParameters ||
            gate.MethodSig?.Params.Count != 0 || gate.ReturnType.ElementType != ElementType.Void)
            return false;
        var effects = evidence.EffectsOf(gate.MDToken.Raw);
        if (!effects.AllInvocationsCompleted || effects.WroteMappedImage || effects.WroteScratchRegion || effects.Registrations.Count != 0)
            return false;
        var observations = evidence.Observations.Where(o => o.Kind == LoaderObservationKind.SignatureVerification).ToArray();
        // A shared wrapper or two sites in one method cannot identify the instruction uniquely.
        if (observations.Length == 0 || observations.Any(o => o.Verdict != true || o.CallStack.Count == 0 || o.CallStack[^1] != gate.MDToken.Raw ||
                !o.Detail.StartsWith("System.Security.Cryptography.RSACryptoServiceProvider::VerifyHash over ", StringComparison.Ordinal)) ||
            !evidence.Observations.Any(o => o.Kind == LoaderObservationKind.ModuleFileRead &&
                (o.Detail.StartsWith("FileStream over ", StringComparison.Ordinal) || o.Detail.StartsWith("File.ReadAllBytes of ", StringComparison.Ordinal)) &&
                o.CallStack.Contains(gate.MDToken.Raw)))
            return false;
        var calls = gate.Body.Instructions.Where(i => i.OpCode.Code is Code.Call or Code.Callvirt &&
            i.Operand is IMethod called && called.Name.String is "VerifyHash" or "VerifyData").ToArray();
        if (calls.Length != 1 || !IsVerification(calls[0]))
            return false;
        var index = gate.Body.Instructions.IndexOf(calls[0]);
        if (index > 0 && gate.Body.Instructions[index - 1].OpCode.OpCodeType == OpCodeType.Prefix)
            return false;
        site = calls[0];
        return true;
    }

    private static bool IsVerification(Instruction instruction) =>
        instruction.OpCode.Code is Code.Call or Code.Callvirt && instruction.Operand is IMethod method &&
        method.DeclaringType.FullName == "System.Security.Cryptography.RSACryptoServiceProvider" &&
        method.DeclaringType is TypeRef && method.Name == "VerifyHash" &&
        method.DeclaringType.DefinitionAssembly?.Name.String is "mscorlib" or "System.Security.Cryptography.Csp" or "System.Security.Cryptography" &&
        method.MethodSig is { HasThis: true, Params.Count: 3 } signature &&
        signature.RetType.ElementType == ElementType.Boolean &&
        signature.Params[0].FullName == "System.Byte[]" && signature.Params[1].ElementType == ElementType.String &&
        signature.Params[2].FullName == "System.Byte[]";

    internal static void ReplaceVerdict(MethodDef method, Instruction site)
    {
        var index = method.Body.Instructions.IndexOf(site);
        // Keep every argument-producing instruction: those computations include the
        // shared crypto cache initialization that prevents deleting the enclosing frame.
        site.OpCode = OpCodes.Pop;
        site.Operand = null;
        for (var offset = 1; offset <= 3; offset++)
            method.Body.Instructions.Insert(index + offset, OpCodes.Pop.ToInstruction());
        method.Body.Instructions.Insert(index + 4, OpCodes.Ldc_I4_1.ToInstruction());
    }
}
