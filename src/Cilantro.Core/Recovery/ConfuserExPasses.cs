using dnlib.DotNet;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;

namespace Cilantro.Core.Recovery;

/// <summary>
/// Records what ConfuserEx left in the module, so that later passes act on a stated protector
/// rather than on a guess made where they run.
/// </summary>
public sealed class ConfuserExDetectionPass : DeobfuscationPass
{
    public override string Name => "confuserex-detection";
    public override IReadOnlyCollection<string> Dependencies => ["metadata-preflight"];

    // See ReactorDetectionPass: absence is an answer, and protector-identity draws the conclusion.
    public override bool GatesEmission => false;

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var facts = ConfuserExStructureDetector.Analyze(context.Module, context.OriginalImage);
        context.SetFact("confuserex.structure", facts);
        if (!facts.IsConfuserExProtected)
        {
            // Looking and finding nothing is a complete answer, so it is reported as one. Whether
            // the run recognized any protector at all is protector-identity's question, and only
            // there is an absence allowed to stand for a failure.
            return (PassStatus.Success, 0,
                [$"Detection confidence: {facts.Confidence:P0}; not ConfuserEx-protected."]);
        }

        context.AddEvidence(new Evidence(
            "protector",
            $"ConfuserEx: {string.Join(", ", facts.CapabilityNames)}.",
            Confidence: facts.Confidence));
        foreach (var capability in facts.CapabilityNames)
            context.AddEvidence(new Evidence("capability", capability, Confidence: facts.Confidence));
        if (facts.HasEncryptedSection)
        {
            context.AddEvidence(new Evidence(
                "encrypted-section",
                $"{facts.MethodsInEncryptedSection} method body/bodies live in an added " +
                $"read-write-execute section at RVA 0x{facts.EncryptedSectionRva:X8} " +
                $"({facts.EncryptedSectionSize} bytes), which the module initializer must decrypt " +
                "before any of them can run.",
                Confidence: 0.95));
        }

        return (PassStatus.Success, 0,
        [
            $"Detection confidence: {facts.Confidence:P0}",
            $"Capabilities: {string.Join(", ", facts.CapabilityNames)}",
            facts.HasEncryptedSection
                ? $"{facts.MethodsInEncryptedSection} method(s) have bodies inside the encrypted section."
                : "No added read-write-execute section was found."
        ]);
    }
}

/// <summary>
/// Undoes ConfuserEx's anti-tamper by interpreting the decryptor and reinstating the bodies it
/// decrypts, rather than by reimplementing the decryption.
/// </summary>
/// <remarks>
/// ConfuserEx randomizes its keys and mutates its own arithmetic per build, so a reimplementation
/// is correct for the sample it was written against and silently wrong for the next one. The
/// decryptor in the module is the specification, and it is already in a form this tool can
/// execute. What the interpretation has to be held to is not the algorithm but the result: the
/// decryption is accepted only if it stayed inside the section it owns and produced a well-formed
/// method body at every address the metadata points into that section.
///
/// If it cannot be interpreted, the pass refuses and says so. A partially decrypted module would
/// verify, load, and lie.
/// </remarks>
public sealed class ConfuserExAntiTamperPass : DeobfuscationPass
{
    public override string Name => "confuserex-antitamper";
    public override IReadOnlyCollection<string> Dependencies => ["confuserex-detection"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        context.SetFact("confuserex.antitamper.complete", false);
        if (!context.TryGetFact<ConfuserExStructureFacts>("confuserex.structure", out var facts) ||
            facts is null ||
            !facts.IsConfuserExProtected)
        {
            return (PassStatus.Success, 0, ["Not ConfuserEx-protected; nothing to decrypt."]);
        }
        if (!facts.Capabilities.HasFlag(ConfuserExCapability.AntiTamper))
        {
            context.SetFact("confuserex.antitamper.complete", true);
            return (PassStatus.Success, 0, ["No ConfuserEx anti-tamper section requires decryption."]);
        }

        var section = ConfuserExStructureDetector.FindEncryptedSection(context.OriginalImage);
        if (section is null)
            return (PassStatus.Failed, 0,
                ["The encrypted section named by detection is no longer present."]);

        var initializer = context.Module.GlobalType.FindStaticConstructor();
        if (initializer is not { HasBody: true })
            return (PassStatus.Unsupported, 0,
                ["ConfuserEx anti-tamper runs from a module initializer, and this module has none."]);

        var policy = new ConfuserExSectionRewritePolicy(section, context.Module);
        if (policy.Targets.Count == 0)
            return (PassStatus.Unsupported, 0,
                ["No method body lies inside the encrypted section; nothing would be restored."]);

        // The decryptor hashes every other section a dword at a time and then decrypts its own a
        // dword at a time, so the step count scales with the size of the image rather than with
        // the complexity of the code. It needs a budget to match.
        var limits = BootstrapMachine.Environment(context).Declarations.Budgets.Over(
            new StaticMachineLimits(
                MaximumSteps: 64_000_000,
                MaximumRecursionDepth: 64,
                MaximumAllocatedBytes: 256 * 1024 * 1024,
                MaximumArrayLength: 256 * 1024 * 1024,
                MaximumProvenanceNodes: 1_000_000,
                MaximumProvenanceDepth: 8_192,
                MaximumRenderedProvenanceNodes: 96));

        if (!ImageRewriteRecovery.TryInterpret(
                context,
                initializer,
                limits,
                out var rewrite,
                out var interpretDiagnostic) ||
            rewrite is null)
        {
            return (PassStatus.Failed, 0,
                [interpretDiagnostic!, "No method body was modified."]);
        }

        context.AddEvidence(new Evidence(
            "confuserex-antitamper",
            $"Two deterministic interpretations of the module initializer agreed: " +
            $"{rewrite.Result.Status}, {rewrite.Result.Steps} steps, " +
            $"{rewrite.ImageWrites.Count} mapped-image writes.",
            $"{initializer.MDToken} {initializer.FullName}",
            0.95));

        var application = ImageRewriteRecovery.TryApply(
            context,
            policy,
            rewrite.ImageWrites,
            out var restored,
            out var applyDiagnostics);
        if (application != RewriteApplication.Applied)
        {
            // The interpretation stopping is the usual reason nothing was written, and it is worth
            // reporting as the cause rather than leaving the empty write log to speak for it.
            var cause = rewrite.Result.Succeeded
                ? []
                : new[]
                {
                    $"The interpretation stopped after {rewrite.Result.Steps} steps: " +
                    $"{rewrite.Result.Status}.",
                    rewrite.Result.Diagnostic ?? "No diagnostic was provided."
                };
            return (PassStatus.Unsupported, 0, [.. cause, .. applyDiagnostics]);
        }

        foreach (var target in policy.Targets)
        {
            context.AddChange(new ChangeRecord(
                Name,
                "decrypt-method-body",
                $"0x{target.Token:X8} RVA 0x{target.Rva:X8}",
                "Reinstated the body the interpreted anti-tamper decryptor wrote into the image."));
        }
        context.SetFact("confuserex.antitamper.complete", true);
        context.SetFact("confuserex.antitamper.restored", restored);
        return (PassStatus.Success, restored,
        [
            $"Decrypted and reinstated {restored} method body/bodies from the encrypted section " +
            $"at RVA 0x{section.VirtualAddress:X8}.",
            $"Replayed {rewrite.ImageWrites.Count} deterministic writes, all inside that section.",
            "Every reinstated body begins with a well-formed CIL header at the address the " +
            "metadata declares.",
            .. applyDiagnostics,
            // The initializer runs the decryptor first and its other stages after, and those stages
            // are themselves inside the section being decrypted, so interpretation of them stops
            // against bodies this pass has only just recovered. Left unsaid, the stop appears in the
            // run's ledger as an unexplained refusal by a pass that reported success.
            .. rewrite.Result.Succeeded
                ? []
                : new[]
                {
                    $"Interpretation stopped after {rewrite.Result.Steps} steps " +
                    $"({rewrite.Result.Status}) in a later stage of the initializer, past the " +
                    "point where the decryptor had written the section. The bodies above come " +
                    "from those writes, so the stop does not qualify them; the stages after it " +
                    "were not interpreted and nothing is claimed about them."
                }
        ]);
    }
}
