using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Interpretation;
using ReactorUnpack.Core.Passes;
using ReactorUnpack.Core.Verification;

namespace ReactorUnpack.Core.Recovery;

/// <summary>
/// Removes calls to loader entry points that recovery has made inert.
/// </summary>
/// <remarks>
/// Reactor prefixes type initializers throughout the assembly with calls into its runtime, so the
/// protector's machinery stays referenced from ordinary application code even after every guard it
/// installed has been folded away. Those call sites are the last thing holding the runtime alive:
/// while they remain, nothing can prove the runtime unreachable and none of it can be removed.
///
/// An entry point qualifies only on evidence the bootstrap interpretation already produced. It must
/// be a <c>static void</c> method with no parameters that the interpretation actually executed,
/// which confines candidates to the loader itself rather than to any inert-looking application
/// method. Its subtree must have done something only a protector does: verify a signature, read its
/// own file, probe for a strong name or a debugger, ask to terminate, or patch the mapped image.
/// And the one channel through which it could still influence the program, the static fields it
/// wrote, must be read nowhere outside the subtree that disappears with it.
///
/// Patching the mapped image is disqualifying until method bodies have been recovered statically,
/// because before that the runtime patcher is the only thing supplying them. Afterwards it is
/// redundant with work already done, and removing it is what lets the recovered assembly run
/// without the protector.
/// </remarks>
public sealed class LoaderCallElisionPass : DeobfuscationPass
{
    private const int MaximumSteps = 4_000_000;

    public override string Name => "loader-call-elision";
    public override IReadOnlyCollection<string> Dependencies => ["antitamper-neutralization"];

    /// <remarks>
    /// Declining leaves the module untouched, and the rewrite either verifies or is rolled back and
    /// reported as a failure, which the pipeline already treats as fatal.
    /// </remarks>
    public override bool GatesEmission => false;

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("method-protection.complete", out var complete) || !complete)
        {
            return (PassStatus.Success, 0,
                ["No loader call was elided because method-body recovery is not complete."]);
        }
        if (!context.TryGetFact<LoaderInterpretationEvidence>("bootstrap.evidence", out var evidence) ||
            evidence is null ||
            evidence.Effects.Count == 0)
        {
            return (PassStatus.Success, 0, ["No bounded loader interpretation evidence is available."]);
        }

        var byToken = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .ToDictionary(method => method.MDToken.Raw);
        var initializer = context.Module.GlobalType.FindStaticConstructor();
        var entryPoints = new List<(MethodDef Method, IReadOnlySet<uint> Subtree)>();
        var wrongShape = 0;
        var noProtectorWork = 0;
        var escapingState = 0;
        foreach (var token in evidence.Effects.Keys.Order())
        {
            if (!byToken.TryGetValue(token, out var candidate) || candidate == initializer)
                continue;
            if (!IsElidableShape(candidate))
            {
                wrongShape++;
                continue;
            }
            if (!PerformedProtectorWork(evidence, token))
            {
                noProtectorWork++;
                continue;
            }

            var subtree = AntiTamperNeutralizationPass.ComputeCallSubtree(candidate);
            var escaping = AntiTamperNeutralizationPass.FindEscapingFieldReaders(
                context.Module, subtree, evidence.EffectsOf(token).StaticFieldsWritten);
            if (escaping.Length != 0)
            {
                escapingState++;
                continue;
            }
            entryPoints.Add((candidate, subtree));
        }

        // Reactor also injects guard calls at the head of ordinary type initializers, which the
        // module-initializer interpretation never reaches. Those are the call sites that keep the
        // runtime referenced from application code, so each is interpreted on its own terms.
        var reachability = ModuleReachability.Compute(context.Module);
        var interpretedGuards = 0;
        foreach (var guard in GuardCandidates(context.Module, initializer)
                     .Where(guard => entryPoints.All(item => item.Method != guard))
                     .OrderBy(guard => guard.MDToken.Raw))
        {
            if (!TryInterpretGuard(context, guard, out var guardEvidence) || guardEvidence is null)
                continue;
            interpretedGuards++;
            var token = guard.MDToken.Raw;
            if (!PerformedProtectorWork(guardEvidence, token))
            {
                noProtectorWork++;
                continue;
            }

            var subtree = AntiTamperNeutralizationPass.ComputeCallSubtree(guard);
            var escaping = AntiTamperNeutralizationPass.FindEscapingFieldReaders(
                context.Module, subtree, guardEvidence.EffectsOf(token).StaticFieldsWritten,
                reachability);
            if (escaping.Length != 0)
            {
                escapingState++;
                continue;
            }
            entryPoints.Add((guard, subtree));
        }

        var accounting =
            $"{evidence.Effects.Count} interpreted frame(s) and {interpretedGuards} interpreted " +
            $"initializer guard(s): {wrongShape} not argument-free void, {noProtectorWork} " +
            $"performed no protector work, {escapingState} still write state surviving code reads.";

        // A candidate nested inside another candidate's subtree needs no call site of its own
        // removed: it disappears with its enclosing frame.
        var enclosed = entryPoints
            .SelectMany(item => item.Subtree.Where(token => token != item.Method.MDToken.Raw))
            .ToHashSet();
        var outermost = entryPoints
            .Where(item => !enclosed.Contains(item.Method.MDToken.Raw))
            .Select(item => item.Method)
            .ToArray();
        if (outermost.Length == 0)
            return (PassStatus.Success, 0, [$"No loader entry point was proven inert. {accounting}"]);

        var callSites = FindCallSites(context.Module, outermost);
        if (callSites.Length == 0)
        {
            return (PassStatus.Success, 0,
            [
                $"The {outermost.Length} proven-inert loader entry point(s) have no remaining call site.",
                accounting
            ]);
        }

        using var transaction = new InstructionMutationTransaction();
        foreach (var (method, instruction, target) in callSites)
        {
            transaction.Capture(instruction);
            instruction.OpCode = OpCodes.Nop;
            instruction.Operand = null;
            context.AddChange(new ChangeRecord(
                Name,
                "elide-loader-call",
                $"{method.MDToken} IL_{instruction.Offset:X4}",
                $"Removed a call to proven-inert loader entry point {target.MDToken}."));
        }

        var verification = AssemblyVerifier.Verify(
            context.Module, context.OriginalIdentity, context.OriginalStructure);
        if (!verification.Passed)
        {
            transaction.Rollback();
            return (PassStatus.Failed, 0,
            [
                "Eliding loader calls failed verification and was rolled back: " +
                string.Join("; ", verification.Diagnostics)
            ]);
        }

        transaction.Commit();
        // The whole subtree existed to serve these calls, and every one of them is now gone.
        RecoveryOrphans.Declare(
            context,
            entryPoints
                .SelectMany(item => item.Subtree)
                .Distinct()
                .Where(byToken.ContainsKey)
                .Select(token => byToken[token]));
        context.AddEvidence(new Evidence(
            "loader-call-elision",
            $"Removed {callSites.Length} call(s) to {outermost.Length} loader entry point(s) whose " +
            "subtrees performed only protector work and wrote no static field surviving code reads.",
            null,
            0.95));
        return (PassStatus.Success, callSites.Length,
        [
            $"Elided {callSites.Length} call(s) to {outermost.Length} proven-inert loader entry point(s).",
            accounting
        ]);
    }

    /// <summary>
    /// Whether the method can only communicate through the channels the effects record covers.
    /// </summary>
    /// <remarks>
    /// Taking no arguments and returning nothing leaves static fields and the mapped image as the
    /// only ways out, which is what makes the effects record a complete account of the method.
    /// Requiring it to be invisible outside the assembly keeps the conclusion to code whose every
    /// caller is in evidence.
    /// </remarks>
    private static bool IsElidableShape(MethodDef method) =>
        method.IsStatic &&
        method.HasBody &&
        method.MethodSig?.Params.Count == 0 &&
        method.ReturnType.ElementType == ElementType.Void &&
        !MemberVisibility.IsExternallyVisible(method);

    /// <summary>
    /// The argument-free void methods Reactor calls from type initializers other than the module's.
    /// </summary>
    /// <remarks>
    /// Whether a method qualifies is decided by interpreting it, not by how it is called; this only
    /// bounds how many are worth that cost. Injected guards are recognizable by shape of use rather
    /// than by name: the protector adds the same call to initializers of types it did not write, so
    /// a candidate must be called from the initializer of a type other than the one declaring it. A
    /// type's own initialization helper does not look like that.
    /// </remarks>
    private static HashSet<MethodDef> GuardCandidates(ModuleDef module, MethodDef? initializer)
    {
        var candidates = new HashSet<MethodDef>();
        foreach (var type in module.GetTypes())
        {
            var typeInitializer = type.FindStaticConstructor();
            if (typeInitializer?.HasBody != true || typeInitializer == initializer)
                continue;
            foreach (var instruction in typeInitializer.Body.Instructions)
            {
                if (instruction.OpCode.Code == Code.Call &&
                    instruction.Operand is IMethod called &&
                    called.ResolveMethodDef() is { } target &&
                    target.DeclaringType != type &&
                    IsElidableShape(target))
                {
                    candidates.Add(target);
                }
            }
        }
        return candidates;
    }

    /// <summary>
    /// Runs one guard twice from an identical starting state and keeps the evidence only if both
    /// runs agree and both ran to completion.
    /// </summary>
    /// <remarks>
    /// An interpretation that stops early has not shown everything the method does, so its silence
    /// about a side effect is not evidence of absence. Requiring two agreeing runs additionally
    /// rules out a conclusion that depended on interpretation order.
    /// </remarks>
    private static bool TryInterpretGuard(
        ArtifactContext context,
        MethodDef guard,
        out LoaderInterpretationEvidence? evidence)
    {
        evidence = null;
        if (!BootstrapMachine.TryRunInitializers(context, MaximumSteps, out var first, out _) ||
            first is null ||
            !first.Execute(guard).Succeeded ||
            !BootstrapMachine.TryRunInitializers(context, MaximumSteps, out var second, out _) ||
            second is null ||
            !second.Execute(guard).Succeeded)
        {
            return false;
        }

        var candidate = first.State.Evidence.Snapshot();
        if (!candidate.Agrees(second.State.Evidence.Snapshot()))
            return false;
        evidence = candidate;
        return true;
    }

    /// <summary>
    /// Whether the subtree did something that only a protector's runtime does.
    /// </summary>
    private static bool PerformedProtectorWork(LoaderInterpretationEvidence evidence, uint token) =>
        evidence.EffectsOf(token).WroteMappedImage ||
        evidence.Observations.Any(observation => observation.CallStack.Contains(token));

    private static (MethodDef Method, Instruction Instruction, MethodDef Target)[] FindCallSites(
        ModuleDef module,
        IReadOnlyCollection<MethodDef> entryPoints)
    {
        var targets = entryPoints.ToHashSet();
        return module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody)
            .SelectMany(method => CfgDeadCodePass.ComputeReachable(method)
                .Where(instruction => instruction.OpCode.Code == Code.Call &&
                    instruction.Operand is IMethod called &&
                    called.ResolveMethodDef() is { } resolved &&
                    targets.Contains(resolved))
                .Select(instruction => (
                    Method: method,
                    Instruction: instruction,
                    Target: ((IMethod)instruction.Operand).ResolveMethodDef()!)))
            .ToArray();
    }
}
