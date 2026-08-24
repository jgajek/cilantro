using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Passes;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Recovery;

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
/// When the evidence does not single out one such frame the pass declines instead of choosing.
///
/// Where the calls to that frame live is a separate question from whether removing it is sound.
/// Reactor injects the gate at the head of every type initializer, so an edit confined to the global
/// initializer would leave the other callers still running the check that the removal was for. What
/// the proof above establishes — an argument-free void frame whose one remaining channel is static
/// fields nothing outside it reads — is that executing the frame is unobservable to surviving code,
/// and that holds wherever it is called from. So every reachable call goes at once, or none does,
/// and a reference that names the frame without calling it outright is one this pass declines.
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

        if (!TryFindCalls(context.Module, entryPoint, out var calls, out var callDiagnostic))
        {
            return (PassStatus.Partial, 0,
            [
                $"Integrity frame {entryPoint.MDToken} was left in place: {callDiagnostic}.",
                "No instruction was modified."
            ]);
        }

        var callers = calls.Select(item => item.Method).Distinct().ToArray();
        var transactions = callers.ToDictionary(
            method => method, method => new BodyMutationTransaction(method));
        try
        {
            foreach (var (_, call) in calls)
            {
                call.OpCode = OpCodes.Nop;
                call.Operand = null;
            }
            var remaining = References(context.Module, entryPoint).Length;
            if (remaining != 0)
                throw new InvalidOperationException(
                    $"{remaining} reachable integrity call(s) survived neutralization.");
            var verification = AssemblyVerifier.Verify(
                context.Module,
                context.OriginalIdentity,
                context.OriginalStructure);
            if (!verification.Passed)
                throw new InvalidOperationException(string.Join("; ", verification.Diagnostics));
            foreach (var transaction in transactions.Values)
                transaction.Commit();
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or ArgumentException)
        {
            foreach (var transaction in transactions.Values)
                transaction.Rollback();
            return (PassStatus.Failed, 0,
            [
                $"Integrity neutralization was rolled back: {exception.Message}"
            ]);
        }
        finally
        {
            foreach (var transaction in transactions.Values)
                transaction.Dispose();
        }

        foreach (var (caller, call) in calls)
        {
            context.AddChange(new ChangeRecord(
                Name,
                "neutralize-integrity-check",
                $"{caller.MDToken} IL_{call.Offset:X4}",
                $"Removed the proven integrity-verification frame {entryPoint.MDToken}."));
        }
        context.SetFact("antitamper.neutralized", true);
        context.SetFact("antitamper.entryPoint", entryPoint.MDToken.Raw);
        // The subtree ran only to serve the calls that are now gone.
        var byToken = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .ToDictionary(method => method.MDToken.Raw);
        RecoveryOrphans.Declare(
            context,
            subtree!.Where(byToken.ContainsKey).Select(token => byToken[token]));
        context.AddEvidence(new Evidence(
            "antitamper-neutralized",
            $"Removed {calls.Length} call(s) to {entryPoint.MDToken} across {callers.Length} " +
            $"method(s), whose subtree verified a signature (verdict true), read no other memory " +
            $"channel, and wrote only {effects.StaticFieldsWritten.Count} static field(s) no " +
            $"surviving method reads.",
            $"{entryPoint.MDToken} {entryPoint.FullName}",
            0.95));
        return (PassStatus.Success, calls.Length,
        [
            $"Removed {calls.Length} call(s) to integrity frame {entryPoint.MDToken} across " +
            $"{callers.Length} method(s).",
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

    /// <summary>
    /// Collects every reachable direct call to the integrity frame, wherever in the module it sits.
    /// </summary>
    /// <remarks>
    /// The two ways this comes back empty are worth telling apart, because they send whoever reads
    /// the diagnostic looking in opposite directions: a frame nothing reaches any more needs no
    /// removing at all, while a frame reached by something other than a plain call is one whose
    /// route this pass cannot follow to its end and so will not cut.
    /// </remarks>
    internal static bool TryFindCalls(
        ModuleDef module,
        MethodDef entryPoint,
        out (MethodDef Method, Instruction Instruction)[] calls,
        out string diagnostic)
    {
        calls = [];
        var references = References(module, entryPoint);
        if (references.Length == 0)
        {
            diagnostic = "no reachable call to it survives anywhere in the module";
            return false;
        }

        // A function pointer taken for a delegate names the frame without calling it, and nopping
        // the calls around it would leave that route open while reporting the gate as removed.
        var indirect = references
            .Where(item => item.Instruction.OpCode.Code != Code.Call)
            .ToArray();
        if (indirect.Length != 0)
        {
            diagnostic =
                $"{indirect.Length} of {references.Length} reference(s) reach it other than by a " +
                $"direct call, the first a {indirect[0].Instruction.OpCode.Name} in " +
                $"{indirect[0].Method.MDToken}";
            return false;
        }

        calls = references;
        diagnostic = string.Empty;
        return true;
    }

    private static (MethodDef Method, Instruction Instruction)[] References(
        ModuleDef module,
        MethodDef entryPoint) =>
        module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody)
            .SelectMany(method => CfgDeadCodePass.ComputeReachable(method)
                .Where(instruction => instruction.Operand is IMethod called &&
                    called.ResolveMethodDef() == entryPoint)
                .Select(instruction => (Method: method, Instruction: instruction)))
            .ToArray();
}
