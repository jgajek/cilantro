using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Passes;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Recovery;

/// <summary>
/// Removes calls and implicit type initialization that recovery has made inert.
/// </summary>
/// <remarks>
/// Reactor prefixes type initializers throughout the assembly with calls into its runtime, so the
/// protector's machinery stays referenced from ordinary application code even after every guard it
/// installed has been folded away. Those call sites are the last thing holding the runtime alive:
/// while they remain, nothing can prove the runtime unreachable and none of it can be removed.
///
/// What justifies removing a call is a complete account of what the call does, and no way for any of
/// it to be noticed afterwards. Both halves rest on the machine refusing every call it does not
/// model: a frame that interprets to completion twice, in agreement, did nothing outside the modeled
/// surface, and that surface is read-only apart from handing the runtime an event handler, which the
/// effects record now names. So a candidate is an argument-free <c>static void</c> method, invisible
/// outside the assembly, that interpreted cleanly and registered nothing — leaving the static fields
/// it wrote as the only channel out, and those must be read by nothing that can still run once the
/// calls are gone.
///
/// Requiring the method to look like a protector was the earlier stand-in for that account, from
/// when the account was known to be incomplete. It cost more than it bought: three of the four entry
/// points Reactor injects into type initializers merely decrypt, and none of them verifies a
/// signature or patches an image, so the one that does could never be freed on its own.
///
/// The last test is answered by making the edit and looking, not by reasoning about it beforehand.
/// Reactor reaches its own runtime mostly through function pointers — the JIT callback and the
/// resource handler are installed, never called — so a reader is not found by following calls from
/// the entry point, and asking instead whether any method at all reads the field condemns every
/// candidate, since the readers are the very code the elision strands. Eliding speculatively and
/// recomputing reachability asks the question that actually matters: can anything that still runs
/// observe the write. Candidates that fail are dropped and the rest retried, because dropping one
/// keeps its readers alive and may implicate another.
/// Type initializers require replacing their bodies during both the speculative and committed
/// edits: the CLR enters them implicitly, even when the module has no explicit call instruction.
///
/// Patching the mapped image is disqualifying until method bodies have been recovered statically,
/// because before that the runtime patcher is the only thing supplying them. Afterwards it is
/// redundant with work already done, and removing it is what lets the recovered assembly run
/// without the protector.
/// </remarks>
public class LoaderCallElisionPass : DeobfuscationPass
{
    private const int MaximumSteps = 4_000_000;

    public override string Name => "loader-call-elision";

    /// <remarks>
    /// Resource-hook elision is a dependency rather than a coincidence of ordering. Reactor's
    /// resolve handler reads four of the loader's fields, and while the subscription stands the
    /// handler is reachable through the function pointer that installs it, so the loader's writes
    /// are observable and no candidate can be cleared.
    /// </remarks>
    public override IReadOnlyCollection<string> Dependencies =>
        ["antitamper-neutralization", "resource-hook-elision"];

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

        // Recovery can add methods before a later invocation. Their row IDs are assigned only
        // when writing the module, and cannot occur in the original bootstrap evidence.
        var byToken = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.MDToken.Rid != 0)
            .ToDictionary(method => method.MDToken.Raw);
        var initializer = context.Module.GlobalType.FindStaticConstructor();
        var candidates = new List<Candidate>();
        var wrongShape = 0;
        var registered = 0;
        foreach (var token in evidence.Effects.Keys.Order())
        {
            if (!byToken.TryGetValue(token, out var candidate) || candidate == initializer)
                continue;
            if (!IsElidableShape(candidate))
            {
                wrongShape++;
                continue;
            }
            if (evidence.EffectsOf(token).Registrations.Count != 0)
            {
                registered++;
                continue;
            }
            candidates.Add(new Candidate(
                candidate,
                AntiTamperNeutralizationPass.ComputeCallSubtree(candidate),
                evidence.EffectsOf(token).StaticFieldsWritten));
        }

        // Reactor also injects guard calls at the head of ordinary type initializers, which the
        // module-initializer interpretation never reaches. Those are the call sites that keep the
        // runtime referenced from application code, so each is interpreted on its own terms.
        var interpretedGuards = 0;
        var guardNotes = new List<string>();
        foreach (var guard in GuardCandidates(context.Module, initializer)
                     .Where(guard => candidates.All(item => item.Method != guard))
                     .OrderBy(guard => guard.MDToken.Raw))
        {
            if (!TryInterpretGuard(context, guard, out var guardEvidence) || guardEvidence is null)
            {
                guardNotes.Add($"{guard.Name} did not interpret to completion");
                continue;
            }
            interpretedGuards++;
            var guardEffects = guardEvidence.EffectsOf(guard.MDToken.Raw);
            if (guardEffects.Registrations.Count != 0)
            {
                registered++;
                guardNotes.Add(
                    $"{guard.Name} registers {string.Join(", ", guardEffects.Registrations)}");
                continue;
            }
            candidates.Add(new Candidate(
                guard,
                AntiTamperNeutralizationPass.ComputeCallSubtree(guard),
                guardEvidence.EffectsOf(guard.MDToken.Raw).StaticFieldsWritten));
        }

        // These initializers pass a type handle to the proxy resolver, so the argument-free
        // callee search cannot find them. Each proof starts from a new heap, without the
        // synthetic delegate seeding used by ordinary recovery interpretation.
        if (ProxyLoaderTable.Read(context).Count != 0)
        {
            var proxySteps = Math.Max(16_000_000, ColdInitializerStepBudget(context));
            var leftBudget = new StaticWorkBudget(proxySteps);
            var rightBudget = new StaticWorkBudget(proxySteps);
            var proxyInitializers = context.Module.GetTypes().Where(ReactorDetectionPass.IsDelegateProxy)
                .Select(type => type.FindStaticConstructor()).OfType<MethodDef>()
                .Where(method => IsElidableShape(method) && !EmptyMethodBodies.DoesNothing(method) &&
                    candidates.All(candidate => candidate.Method != method))
                .OrderBy(method => method.MDToken.Raw).ToArray();
            foreach (var method in proxyInitializers)
            {
                if (!TryInterpretColdInitializer(context, method, leftBudget, rightBudget,
                        out var coldEvidence, out var reason))
                {
                    guardNotes.Add($"proxy initializer {method.MDToken} retained: {reason}");
                    // A common resolver failure or budget exhaustion is shared by the remaining
                    // proxies; do not repeatedly pay for the same unsupported path.
                    break;
                }
                var effects = coldEvidence!.EffectsOf(method.MDToken.Raw);
                if (effects.Registrations.Count != 0) { registered++; continue; }
                candidates.Add(new Candidate(method, AntiTamperNeutralizationPass.ComputeCallSubtree(method),
                    effects.StaticFieldsWritten));
                interpretedGuards++;
            }
        }

        // A candidate that another candidate also calls is kept rather than folded into it. Reactor
        // calls the same entry point both from its own bootstrap and from the head of application
        // type initializers, so an inner frame typically has call sites the outer one does not
        // reach, and treating it as disappearing with its caller leaves those behind.
        var (elidable, callSites, blocked) =
            SelectObservablyInert(context.Module, [.. candidates], RebuiltMethods.Of(context));
        var implicitInitializers = InitializersToEmpty(elidable);
        var accounting =
            $"{evidence.Effects.Count} interpreted frame(s) and {interpretedGuards} interpreted " +
            $"initializer guard(s): {wrongShape} not argument-free void, {registered} " +
            $"hand the runtime a handler that outlives them" +
            (guardNotes.Count == 0 ? "" : $" [{string.Join(", ", guardNotes)}]") +
            (blocked.Count == 0
                ? "."
                : $", {blocked.Count} still write state that code surviving the elision reads " +
                  $"({string.Join("; ", blocked)}).");
        if (callSites.Length == 0 && implicitInitializers.Length == 0)
        {
            return (PassStatus.Success, 0,
            [
                elidable.Length == 0
                    ? "No loader entry point was proven inert."
                    : $"The {elidable.Length} proven-inert loader entry point(s) have no remaining " +
                      "call site.",
                accounting
            ]);
        }

        using var transaction = new BodyMutationBatch();
        foreach (var (method, instruction, target) in callSites)
        {
            transaction.Capture(method);
            instruction.OpCode = OpCodes.Nop;
            instruction.Operand = null;
            transaction.RecordChange(context, new ChangeRecord(
                Name,
                "elide-loader-call",
                $"{method.MDToken} IL_{instruction.Offset:X4}",
                $"Removed a call to proven-inert loader entry point {target.MDToken}."));
        }
        foreach (var method in implicitInitializers)
        {
            transaction.Capture(method);
            EmptyInitializer(method);
            transaction.RecordChange(context, new ChangeRecord(Name, "empty-inert-initializer",
                method.MDToken.ToString(), "Removed proven-inert initialization invoked implicitly by the CLR."));
        }

        var verification = AssemblyVerifier.Verify(
            context.Module,
            context.OriginalIdentity,
            context.OriginalStructure,
            CilantroPipeline.BuildRewriteAllowance(context));
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
            elidable
                .SelectMany(item => item.Subtree)
                .Distinct()
                .Where(byToken.ContainsKey)
                .Select(token => byToken[token]));
        // An initializer or helper the elision hollowed out is the same claim one step on: the call
        // was the whole body, so what is left runs and returns. Rechecking removes calls to empty
        // helpers while preserving initialization; cleanup can then remove their declarations.
        // These passes are told here because
        // this is the pass that emptied it.
        var emptied = callSites
            .Select(site => site.Method)
            .Concat(implicitInitializers)
            .Distinct()
            .Where(EmptyMethodBodies.DoesNothing)
            .ToArray();
        RecoveryOrphans.Declare(context, emptied);
        context.AddEvidence(new Evidence(
            "loader-call-elision",
            $"Removed {callSites.Length} call(s) and emptied {implicitInitializers.Length} implicit " +
            $"initializer(s) among {elidable.Length} loader entry point(s) whose " +
            "subtrees performed only protector work and whose static writes nothing still reachable " +
            "reads.",
            null,
            0.95));
        return (PassStatus.Success, callSites.Length + implicitInitializers.Length,
        [
            $"Elided {callSites.Length} call(s) to {elidable.Length} proven-inert loader entry point(s).",
            $"Emptied {implicitInitializers.Length} proven-inert initializer(s) invoked implicitly by the CLR.",
            $"{emptied.Count(method => method.IsStaticConstructor)} type initializer(s) and " +
                $"{emptied.Count(method => !method.IsStaticConstructor)} helper(s) were left doing nothing and are cleanup's to remove.",
            accounting
        ]);
    }

    private sealed record Candidate(
        MethodDef Method,
        IReadOnlySet<uint> Subtree,
        IReadOnlyList<string> FieldsWritten);

    protected (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) ElideBodiesPreservingInitialization(
        ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("method-protection.complete", out var complete) || !complete ||
            context.Module.GlobalType.FindStaticConstructor() is not { HasBody: true } bootstrap)
            return (PassStatus.Success, 0, []);

        // The original recovery interpretation may have stopped as soon as the encrypted bodies
        // were available. Only two complete, independent cold starts of the current module can
        // justify this distinction after reconstruction. No resolved proxies are pre-seeded.
        if (!TryInterpretColdInitializer(context, bootstrap,
                new StaticWorkBudget(ColdInitializerStepBudget(context)),
                new StaticWorkBudget(ColdInitializerStepBudget(context)), out var evidence, out var reason))
            return (PassStatus.Success, 0, ["Loader bodies retained: " + reason]);

        var methods = context.Module.GetTypes().SelectMany(type => type.Methods).ToArray();
        var accepted = methods.Where(method => IsElidableShape(method) && !method.IsStaticConstructor &&
                method.MDToken.Rid != 0 && !ReadingMarker.Marks(method) &&
                !method.HasGenericParameters && !method.DeclaringType.HasGenericParameters &&
                !method.DeclaringType.IsBeforeFieldInit &&
                method.DeclaringType.FindStaticConstructor() is { HasBody: true } &&
                !EmptyMethodBodies.DoesNothing(method))
            .Select(method => (Method: method, Effects: evidence!.EffectsOf(method.MDToken.Raw)))
            .Where(item => item.Effects.AllInvocationsCompleted && item.Effects.Registrations.Count == 0 &&
                item.Effects.BodyStaticFieldsWritten is not null &&
                item.Effects.StaticFieldsWritten.Except(item.Effects.BodyStaticFieldsWritten).Any())
            .Select(item => new Candidate(item.Method,
                AntiTamperNeutralizationPass.ComputeCallSubtree(item.Method), item.Effects.BodyStaticFieldsWritten!))
            .ToArray();

        // Keep every call instruction. For a non-beforefieldinit type the CLR must still
        // run its initializer when this static method is entered, even with an empty body.
        // Initialization of other types from inside the body is not excluded from its effects.
        while (accepted.Length != 0)
        {
            using var probe = new BodyMutationBatch(accepted.Select(item => item.Method));
            foreach (var item in accepted) EmptyInitializer(item.Method);
            var observed = StaticFieldsReadByReachableCode(context.Module, RebuiltMethods.Of(context));
            probe.Rollback();
            var remaining = accepted.Where(item => !item.FieldsWritten.Any(observed.ContainsKey)).ToArray();
            if (remaining.Length == accepted.Length) break;
            accepted = remaining;
        }
        if (accepted.Length == 0) return (PassStatus.Success, 0, []);

        using var transaction = new BodyMutationBatch(accepted.Select(item => item.Method));
        foreach (var item in accepted)
        {
            EmptyInitializer(item.Method);
            transaction.RecordChange(context, new ChangeRecord(Name, "empty-loader-body-keep-initialization",
                item.Method.MDToken.ToString(),
                "Removed an inert loader body while retaining its calls and required declaring-type initialization."));
        }
        var verification = AssemblyVerifier.Verify(context.Module, context.OriginalIdentity,
            context.OriginalStructure, CilantroPipeline.BuildRewriteAllowance(context));
        if (!verification.Passed)
            return (PassStatus.Failed, 0,
                ["Loader body removal failed verification and was rolled back: " + string.Join("; ", verification.Diagnostics)]);

        transaction.Commit();
        var orphanTokens = accepted.SelectMany(item => item.Subtree).ToHashSet();
        RecoveryOrphans.Declare(context, methods.Where(method => orphanTokens.Contains(method.MDToken.Raw)));
        return (PassStatus.Success, accepted.Length,
            [$"Emptied {accepted.Length} proven-inert loader body(s), preserving their calls and required type initialization."]);
    }

    private static MethodDef[] InitializersToEmpty(IEnumerable<Candidate> candidates) =>
        candidates.Select(item => item.Method)
            .Where(method => method.IsStaticConstructor && !EmptyMethodBodies.DoesNothing(method)).ToArray();

    private static void EmptyInitializer(MethodDef method)
    {
        method.Body = new CilBody();
        method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
    }

    /// <summary>
    /// Narrows candidates to those whose static writes no surviving code can observe, by making the
    /// elision, measuring what remains reachable, and undoing it.
    /// </summary>
    /// <remarks>
    /// A candidate is judged against the module as it would be, not as it is. That is the only way to
    /// see that Reactor's readers are themselves stranded: the JIT callback and the resource handler
    /// are reached solely through function pointers taken inside the loader, so they stop being
    /// reachable exactly when the loader does, and a test run before the edit cannot know that.
    ///
    /// Membership in the elided subtree is not an excuse. Removing a call removes the writes, so a
    /// reader that survives sees a field that never got its value, and it makes no difference whether
    /// that reader was part of the protector. Only unreachability clears a field.
    ///
    /// Retrying after a drop is what makes the answer independent of the order candidates were
    /// considered in. Keeping one candidate keeps everything it reaches alive, which can implicate
    /// another that looked clear alongside it, so the set is shrunk until it stops changing.
    /// </remarks>
    private static (Candidate[] Elidable,
        (MethodDef Method, Instruction Instruction, MethodDef Target)[] CallSites,
        IReadOnlyList<string> Blocked) SelectObservablyInert(
            ModuleDef module,
            Candidate[] candidates,
            IEnumerable<MethodDef> additionalRoots)
    {
        var blocked = new List<string>();
        var accepted = candidates;
        while (accepted.Length != 0)
        {
            var initializers = InitializersToEmpty(accepted);
            var callSites = FindCallSites(module, accepted.Select(item => item.Method).ToArray())
                .Where(site => !initializers.Contains(site.Method)).ToArray();
            if (callSites.Length == 0 && initializers.Length == 0)
                return (accepted, [], blocked);

            Dictionary<string, string> observed;
            using (var probe = new BodyMutationBatch())
            {
                foreach (var (method, instruction, _) in callSites)
                {
                    probe.Capture(method);
                    instruction.OpCode = OpCodes.Nop;
                    instruction.Operand = null;
                }
                foreach (var method in initializers)
                {
                    probe.Capture(method);
                    EmptyInitializer(method);
                }
                observed = StaticFieldsReadByReachableCode(module, additionalRoots);
                probe.Rollback();
            }

            var failing = accepted
                .Where(item => item.FieldsWritten.Any(observed.ContainsKey))
                .ToArray();
            if (failing.Length == 0)
                return (accepted, callSites, blocked);
            foreach (var item in failing)
            {
                blocked.Add(
                    $"{item.Method.Name} writes " +
                    string.Join(", ", item.FieldsWritten
                        .Where(observed.ContainsKey)
                        .Order(StringComparer.Ordinal)
                        .Select(field => $"{ShortName(field)} (read by {observed[field]})")));
            }
            accepted = accepted.Except(failing).ToArray();
        }
        return ([], [], blocked);
    }

    /// <summary>
    /// Every static field reachable code reads, each with one method that reads it.
    /// </summary>
    /// <remarks>
    /// A type initializer counts as running only when its type is used, the same reading cleanup
    /// takes. Here it is not a relaxation but the point of the test: Reactor's own runtime type
    /// reads loader state from its initializer, and asking whether that read can happen is asking
    /// whether anything still touches the type, which after the elision is exactly what is in
    /// question. Treating every initializer as running would answer yes by assumption.
    /// Virtual readers likewise require an instance, using cleanup's conservative fallback when
    /// reflection makes construction uncertain. Reconstructed methods remain explicit roots:
    /// their state dependencies matter even without a normal caller in the input assembly.
    ///
    /// Carrying a reader alongside the field is what makes a decline diagnosable. The field name
    /// alone says the elision is unsafe but not what still depends on the loader, and that is the
    /// thing a reader of the report needs in order to know which recovery is missing.
    /// </remarks>
    private static Dictionary<string, string> StaticFieldsReadByReachableCode(
        ModuleDef module, IEnumerable<MethodDef> additionalRoots)
    {
        var reachability = ModuleReachability.ComputeWithInstances(
            module, typeInitializersAlwaysRun: false, additionalRoots);
        var read = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var method in reachability.ReachableMethods.OrderBy(item => item.MDToken.Raw))
        {
            if (!method.HasBody)
                continue;
            foreach (var instruction in method.Body.Instructions)
            {
                if (instruction.OpCode.Code is Code.Ldsfld or Code.Ldsflda &&
                    instruction.Operand is IField field)
                {
                    read.TryAdd(field.FullName, $"{method.DeclaringType.Name}::{method.Name}");
                }
            }
        }
        return read;
    }

    private static string ShortName(string fieldFullName)
    {
        var separator = fieldFullName.LastIndexOf("::", StringComparison.Ordinal);
        return separator < 0 ? fieldFullName : fieldFullName[(separator + 2)..];
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
        return TryInterpretColdInitializer(context, guard,
            new StaticWorkBudget(ColdInitializerStepBudget(context)),
            new StaticWorkBudget(ColdInitializerStepBudget(context)),
            out evidence, out _);
    }

    internal static int ColdInitializerStepBudget(ArtifactContext context)
    {
        // The proof repeats the entire loader before entering its candidate. Large encrypted
        // method tables can already have required more work than the ordinary guard budget.
        return BootstrapMachine.InitializationStepBudget(context, MaximumSteps);
    }

    internal static bool TryInterpretColdInitializer(ArtifactContext context, MethodDef initializer,
        StaticWorkBudget leftBudget, StaticWorkBudget rightBudget,
        out LoaderInterpretationEvidence? evidence, out string reason)
    {
        evidence = null;
        reason = "independent interpretations did not agree";
        if (!Read(leftBudget, out var left, out reason) || !Read(rightBudget, out var right, out reason))
            return false;
        if (!left!.Agrees(right!))
        {
            reason = "independent interpretations did not agree";
            return false;
        }
        evidence = left;
        return true;

        bool Read(StaticWorkBudget budget, out LoaderInterpretationEvidence? result, out string diagnostic)
        {
            result = null;
            diagnostic = "interpretation budget exhausted";
            if (budget.RemainingSteps == 0 ||
                !BootstrapMachine.TrySeed(context, MaximumSteps, out var machine, out diagnostic) || machine is null)
                return false;
            if (context.Module.GlobalType.FindStaticConstructor() is { HasBody: true } bootstrap)
            {
                var initialized = machine.Execute(bootstrap, [], budget);
                if (!initialized.Succeeded)
                {
                    diagnostic = "module initialization did not complete without seeded proxies: " +
                        (initialized.Diagnostic ?? initialized.Status.ToString())
                            .Split(" | provenance:", StringSplitOptions.None)[0];
                    return false;
                }
            }
            // A module initializer requested as the proof target has already run above.
            // Executing it explicitly again would not model a cold CLR startup.
            if (initializer != context.Module.GlobalType.FindStaticConstructor())
            {
                var execution = machine.Execute(initializer, [], budget);
                if (!execution.Succeeded)
                {
                    diagnostic = $"{execution.Status}: " +
                        (execution.Diagnostic ?? "no diagnostic").Split(" | provenance:", StringSplitOptions.None)[0];
                    return false;
                }
            }
            result = machine.State.Evidence.Snapshot();
            diagnostic = "";
            return true;
        }
    }

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

/// <summary>
/// Rechecks loader dependencies after reconstructed bodies and their predicates have been simplified.
/// </summary>
public sealed class LoaderCallRecheckPass : LoaderCallElisionPass
{
    public override string Name => "loader-call-recheck";

    public override IReadOnlyCollection<string> Dependencies => ["loader-call-elision", "stack-handoff"];

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        if (!RebuiltMethods.Of(context).Any())
            return (PassStatus.Success, 0, ["No reconstructed body requires a later loader dependency check."]);

        // Repeat the effects and reachability checks against the final bodies. A reconstruction
        // alone is not permission to remove its loader: live reads and failed cold proofs still
        // keep initialization in place.
        var calls = base.Execute(context);
        if (calls.Status != PassStatus.Success) return calls;
        var bodies = ElideBodiesPreservingInitialization(context);
        return (bodies.Status, calls.Changes + bodies.Changes, [.. calls.Diagnostics, .. bodies.Diagnostics]);
    }
}
