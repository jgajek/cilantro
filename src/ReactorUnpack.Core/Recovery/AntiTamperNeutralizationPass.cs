using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Interpretation;
using ReactorUnpack.Core.Passes;
using ReactorUnpack.Core.Verification;

namespace ReactorUnpack.Core.Recovery;

/// <summary>
/// Removes the loader entry point whose only proven purpose is integrity enforcement.
/// </summary>
/// <remarks>
/// Once protected bodies are grafted, an on-disk integrity check is not merely redundant, it is a
/// landmine: the check hashes the file it was shipped in, that file no longer exists in its
/// original form, and the recovered assembly would reject itself at startup. Removing the check is
/// what makes a recovered artifact runnable, so it belongs to recovery rather than to opt-in
/// cleanup.
///
/// Nothing is inferred from names or shapes. The decision rests on facts the bootstrap
/// interpretation already established: which frame's subtree performed the signature verification,
/// and what that subtree wrote. The target must be a <c>static void</c> module-initializer callee
/// whose subtree verified a signature but wrote neither the mapped image nor scratch memory, which
/// distinguishes the pure integrity gate from the method-patcher that shares the initializer. Its
/// only remaining channel is static fields, so removal is sound exactly when no surviving method
/// reads any field the subtree wrote. The strong-name probe, when it is entangled with method
/// patching, is deliberately left to the opt-in runtime-cleanup pass.
///
/// When the evidence does not single out one such frame the pass declines instead of choosing, and
/// it never edits a body outside the module initializer.
/// </remarks>
public sealed class AntiTamperNeutralizationPass : DeobfuscationPass
{
    public override string Name => "antitamper-neutralization";
    public override IReadOnlyCollection<string> Dependencies => ["method-body-recovery"];

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        context.SetFact("antitamper.neutralized", false);
        if (!context.TryGetFact<ReactorStructureFacts>("reactor.structure", out var structure) ||
            structure is null ||
            !structure.Capabilities.HasFlag(ReactorCapability.AntiTamper))
        {
            return (PassStatus.Success, 0,
                ["No anti-tamper capability was detected; nothing required neutralization."]);
        }
        if (!context.TryGetFact<bool>("method-protection.complete", out var complete) || !complete)
        {
            return (PassStatus.Partial, 0,
            [
                "Neutralization was deferred because method-body recovery is not complete.",
                "Removing the loader before its patches are applied statically would lose code.",
                "No instruction was modified."
            ]);
        }
        if (!context.TryGetFact<LoaderInterpretationEvidence>(
                "bootstrap.evidence", out var evidence) ||
            evidence is null)
        {
            return (PassStatus.Partial, 0,
            [
                "No bounded loader interpretation evidence is available.",
                "No instruction was modified."
            ]);
        }

        var initializer = context.Module.GlobalType.FindStaticConstructor();
        if (initializer?.HasBody != true)
            return (PassStatus.Success, 0, ["The module has no global initializer to neutralize."]);

        var integrityFrames = evidence.Observations
            .Where(observation => observation.Kind is
                LoaderObservationKind.SignatureVerification or
                LoaderObservationKind.ModuleFileRead or
                LoaderObservationKind.StrongNameProbe)
            .ToArray();
        var verificationFrames = evidence.Observations
            .Where(observation => observation.Kind == LoaderObservationKind.SignatureVerification)
            .ToArray();
        if (verificationFrames.Length == 0)
        {
            return (PassStatus.Success, 0,
            [
                "The loader interpretation completed no signature verification, so nothing was removed.",
                "The detected anti-tamper capability is reported without a proven enforcement site."
            ]);
        }
        if (verificationFrames.Any(observation => observation.Verdict != true))
        {
            return (PassStatus.Partial, 0,
            [
                "A modeled signature verification did not pass on this input.",
                "Neutralizing a check that fails or is indeterminate would change behavior rather than preserve it.",
                "No instruction was modified."
            ]);
        }

        if (!TryChooseEntryPoint(
                context.Module, initializer, evidence, verificationFrames, out var entryPoint,
                out var subtree, out var selectionDiagnostic))
        {
            return (PassStatus.Partial, 0,
            [
                $"No single removable integrity frame was proven: {selectionDiagnostic}",
                "No instruction was modified."
            ]);
        }

        var effects = evidence.EffectsOf(entryPoint!.MDToken.Raw);
        var escaping = FindEscapingFieldReaders(context.Module, subtree!, effects.StaticFieldsWritten);
        if (escaping.Length != 0)
        {
            return (PassStatus.Partial, 0,
            [
                $"Integrity frame {entryPoint.MDToken} writes {escaping.Length} static field(s) that " +
                "surviving code reads, so its removal is not provably behavior-preserving.",
                $"First escaping field: {escaping[0]}.",
                "No instruction was modified."
            ]);
        }

        var calls = FindInitializerCalls(context.Module, initializer, entryPoint);
        if (calls.Length == 0)
        {
            return (PassStatus.Partial, 0,
            [
                $"Integrity frame {entryPoint.MDToken} has no reachable call in the initializer.",
                "No instruction was modified."
            ]);
        }

        using var transaction = new BodyMutationTransaction(initializer);
        try
        {
            foreach (var call in calls)
            {
                call.OpCode = OpCodes.Nop;
                call.Operand = null;
            }
            var remaining = CfgDeadCodePass.ComputeReachable(initializer)
                .Count(instruction => instruction.Operand is IMethod called &&
                    called.ResolveMethodDef() == entryPoint);
            if (remaining != 0)
                throw new InvalidOperationException(
                    $"{remaining} reachable integrity call(s) survived neutralization.");
            var verification = AssemblyVerifier.Verify(
                context.Module,
                context.OriginalIdentity,
                context.OriginalStructure);
            if (!verification.Passed)
                throw new InvalidOperationException(string.Join("; ", verification.Diagnostics));
            transaction.Commit();
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or ArgumentException)
        {
            transaction.Rollback();
            return (PassStatus.Failed, 0,
            [
                $"Integrity neutralization was rolled back: {exception.Message}"
            ]);
        }

        foreach (var call in calls)
        {
            context.AddChange(new ChangeRecord(
                Name,
                "neutralize-integrity-check",
                $"{initializer.MDToken} IL_{call.Offset:X4}",
                $"Removed the proven integrity-verification frame {entryPoint.MDToken}."));
        }
        context.SetFact("antitamper.neutralized", true);
        context.SetFact("antitamper.entryPoint", entryPoint.MDToken.Raw);
        // The subtree ran only to serve the initializer call that is now gone.
        var byToken = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .ToDictionary(method => method.MDToken.Raw);
        RecoveryOrphans.Declare(
            context,
            subtree!.Where(byToken.ContainsKey).Select(token => byToken[token]));
        context.AddEvidence(new Evidence(
            "antitamper-neutralized",
            $"Removed {calls.Length} initializer call(s) to {entryPoint.MDToken}, whose subtree " +
            $"verified a signature (verdict true), read no other memory channel, and wrote only " +
            $"{effects.StaticFieldsWritten.Count} static field(s) no surviving method reads.",
            $"{entryPoint.MDToken} {entryPoint.FullName}",
            0.95));
        return (PassStatus.Success, calls.Length,
        [
            $"Removed {calls.Length} initializer call(s) to integrity frame {entryPoint.MDToken}.",
            $"Its subtree performed {integrityFrames.Length} integrity observation(s) including " +
            $"{verificationFrames.Length} passing signature verification(s).",
            effects.StaticFieldsWritten.Count == 0
                ? "It wrote no static field."
                : $"The {effects.StaticFieldsWritten.Count} static field(s) it wrote are read only within the removed subtree."
        ]);
    }

    /// <summary>
    /// Picks the outermost module-initializer callee whose subtree performed the integrity
    /// verification and could not have communicated its result to surviving code.
    /// </summary>
    /// <remarks>
    /// Candidates are the frames that enclose every signature verification, considered from the
    /// initializer downwards so the most obfuscation is removed. A candidate must take no
    /// arguments, return void, and have written neither the mapped image nor scratch memory
    /// anywhere in its subtree; the two region constraints are what separate the pure integrity
    /// gate from the method-patcher that shares the initializer and legitimately rewrites the
    /// image. The remaining static-field channel is checked separately by the caller.
    /// </remarks>
    internal static bool TryChooseEntryPoint(
        ModuleDef module,
        MethodDef initializer,
        LoaderInterpretationEvidence evidence,
        LoaderObservation[] verificationFrames,
        out MethodDef? entryPoint,
        out IReadOnlySet<uint>? subtree,
        out string diagnostic)
    {
        entryPoint = null;
        subtree = null;
        diagnostic = string.Empty;
        var byToken = module.GetTypes()
            .SelectMany(type => type.Methods)
            .ToDictionary(method => method.MDToken.Raw);

        var common = verificationFrames
            .Select(observation => observation.CallStack)
            .Aggregate(
                (IReadOnlyList<uint>)verificationFrames[0].CallStack,
                CommonPrefix);
        var candidate = common
            .Select((token, depth) => (Token: token, Depth: depth))
            .Where(item => byToken.TryGetValue(item.Token, out var method) &&
                method != initializer &&
                IsRemovableShape(method) &&
                !evidence.EffectsOf(item.Token).WroteMappedImage &&
                !evidence.EffectsOf(item.Token).WroteScratchRegion)
            .OrderBy(item => item.Depth)
            .Select(item => (uint?)item.Token)
            .FirstOrDefault();
        if (candidate is null)
        {
            diagnostic = common.Count == 0
                ? "the signature verifications share no common enclosing frame"
                : "no enclosing frame is an argument-free void method that touched neither the image nor scratch memory";
            return false;
        }

        entryPoint = byToken[candidate.Value];
        subtree = ComputeCallSubtree(entryPoint);
        return true;
    }

    private static bool IsRemovableShape(MethodDef method) =>
        method.IsStatic &&
        method.MethodSig?.Params.Count == 0 &&
        method.ReturnType.ElementType == ElementType.Void;

    /// <summary>
    /// Collects every method statically reachable through call edges from the entry point.
    /// </summary>
    /// <remarks>
    /// The subtree is what "surviving code" is defined against: a field the subtree writes is safe
    /// to abandon only if nothing outside the subtree reads it. Resolving each call target to a
    /// definition in this module and following it transitively gives a conservative over-approximation
    /// of what disappears when the initializer stops calling the entry point.
    /// </remarks>
    internal static HashSet<uint> ComputeCallSubtree(MethodDef entryPoint)
    {
        var visited = new HashSet<uint>();
        var queue = new Queue<MethodDef>();
        queue.Enqueue(entryPoint);
        visited.Add(entryPoint.MDToken.Raw);
        while (queue.Count != 0)
        {
            var current = queue.Dequeue();
            if (!current.HasBody)
                continue;
            foreach (var instruction in current.Body.Instructions)
            {
                if (instruction.Operand is not IMethod called ||
                    called.ResolveMethodDef() is not { } target ||
                    !visited.Add(target.MDToken.Raw))
                {
                    continue;
                }
                queue.Enqueue(target);
            }
        }
        return visited;
    }

    /// <summary>
    /// Returns any written static fields that a method outside the removed subtree reads.
    /// </summary>
    /// <remarks>
    /// A reader the program can never execute observes nothing, so when reachability is known the
    /// search is restricted to code that can actually run. Passing no reachability keeps the
    /// stricter reading, in which any surviving read counts.
    /// </remarks>
    internal static string[] FindEscapingFieldReaders(
        ModuleDef module,
        IReadOnlySet<uint> subtree,
        IReadOnlyList<string> writtenFields,
        ModuleReachability? reachability = null)
    {
        if (writtenFields.Count == 0)
            return [];
        var written = new HashSet<string>(writtenFields, StringComparer.Ordinal);
        var escaping = new HashSet<string>(StringComparer.Ordinal);
        foreach (var method in module.GetTypes().SelectMany(type => type.Methods))
        {
            if (!method.HasBody ||
                subtree.Contains(method.MDToken.Raw) ||
                reachability?.IsReachable(method) == false)
            {
                continue;
            }
            foreach (var instruction in method.Body.Instructions)
            {
                if (instruction.OpCode.Code is not (Code.Ldsfld or Code.Ldsflda) ||
                    instruction.Operand is not IField field)
                {
                    continue;
                }
                if (written.Contains(field.FullName))
                    escaping.Add(field.FullName);
            }
        }
        return escaping.Order(StringComparer.Ordinal).ToArray();
    }

    private static IReadOnlyList<uint> CommonPrefix(
        IReadOnlyList<uint> left,
        IReadOnlyList<uint> right)
    {
        var length = 0;
        while (length < left.Count && length < right.Count && left[length] == right[length])
            length++;
        return left.Take(length).ToArray();
    }

    private static Instruction[] FindInitializerCalls(
        ModuleDef module,
        MethodDef initializer,
        MethodDef entryPoint)
    {
        // A call anywhere but the initializer means the entry point is shared, so removing it
        // there would be a change this pass has not proven.
        var reachable = module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody)
            .SelectMany(method => CfgDeadCodePass.ComputeReachable(method)
                .Where(instruction => instruction.Operand is IMethod called &&
                    called.ResolveMethodDef() == entryPoint)
                .Select(instruction => (Method: method, Instruction: instruction)))
            .ToArray();
        if (reachable.Length == 0 ||
            reachable.Any(item => item.Method != initializer ||
                item.Instruction.OpCode.FlowControl != FlowControl.Call))
            return [];
        return reachable.Select(item => item.Instruction).ToArray();
    }
}
