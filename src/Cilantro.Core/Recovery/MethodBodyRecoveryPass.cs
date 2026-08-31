using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Passes;

namespace Cilantro.Core.Recovery;

public sealed record MethodRecoveryAttempt(
    uint BootstrapToken,
    StaticExecutionStatus ExecutionStatus,
    int Steps,
    int StubCount,
    int ImageWriteCount,
    int ImageWriteBytes,
    string? Diagnostic);

public sealed class MethodBodyRecoveryPass : DeobfuscationPass
{
    public override string Name => "method-body-recovery";
    public override IReadOnlyCollection<string> Dependencies =>
        ["method-protection", "resource-roles", "control-flow-analysis"];

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        context.SetFact("method-protection.complete", false);
        if (!context.TryGetFact<IReadOnlyList<ProtectedMethodStub>>(
                "method-protection.stubs",
                out var stubs) ||
            stubs is null ||
            stubs.Count == 0)
        {
            context.SetFact("method-protection.complete", true);
            return (PassStatus.Success, 0, ["No protected method bodies require restoration."]);
        }

        var bootstrap = FindBootstrap(context.Module);
        if (bootstrap is null)
            return (PassStatus.Unsupported, 0,
                ["No structurally qualified module-initializer patch bootstrap was found."]);

        if (!ReactorStubRewritePolicy.TryCreate(
                context.OriginalImage,
                stubs,
                out var policy,
                out var catalogDiagnostic) ||
            policy is null)
        {
            return (PassStatus.Failed, 0,
                [$"Protected-stub prefix catalog rejected the input: {catalogDiagnostic}"]);
        }

        var budgets = BootstrapMachine.Environment(context).Declarations.Budgets;
        var executionRoot = context.Module.GlobalType.FindStaticConstructor() ?? bootstrap;
        var raisings = new List<string>();
        var rounds = new List<string>();
        var grafted = new HashSet<uint>();
        InterpretedRewrite? rewrite = null;
        InterpretedRewrite? appliedFrom = null;
        AppliedRewrite? applied = null;
        IReadOnlyList<string> applyDiagnostics = [];
        var application = RewriteApplication.NothingToApply;

        // A ceiling once raised stays raised across rounds. Raisings are capped for the pass rather
        // than for a round, so starting each round back at the base would let a later round be
        // stopped by a budget an earlier one had already been given.
        var ceiling = StepBudgetFor(stubs.Count);

        // One interpretation, raising the step ceiling for as long as that is all that stopped it.
        bool Interpret(out InterpretedRewrite? interpreted, out string? failure)
        {
            while (true)
            {
                var limits = budgets.Over(new StaticMachineLimits(
                    MaximumSteps: ceiling,
                    MaximumRecursionDepth: 64,
                    MaximumAllocatedBytes: 256 * 1024 * 1024,
                    MaximumArrayLength: 256 * 1024 * 1024,
                    MaximumProvenanceNodes: 1_000_000,
                    MaximumProvenanceDepth: 8_192,
                    MaximumRenderedProvenanceNodes: 96));
                if (!ImageRewriteRecovery.TryInterpret(
                        context,
                        executionRoot,
                        limits,
                        out interpreted,
                        out failure) ||
                    interpreted is null)
                {
                    return false;
                }
                if (interpreted.Result.Status != StaticExecutionStatus.StepLimitExceeded ||
                    raisings.Count == MostRaisings)
                {
                    return true;
                }
                // The ceiling actually in force, which a declared budget can have raised above ours.
                ceiling = checked(limits.MaximumSteps * 2);
                raisings.Add(
                    $"The bootstrap reached its {limits.MaximumSteps}-step ceiling with nothing to show, " +
                    $"so it was run again with {ceiling}.");
            }
        }

        for (var round = 1; round <= MostRounds; round++)
        {
            if (!Interpret(out rewrite, out var interpretDiagnostic) || rewrite is null)
            {
                return (PassStatus.Failed, 0,
                    [interpretDiagnostic!, "No method body or initializer was modified."]);
            }

            // NecroBit never writes bodies into the image to replay; it decrypts them up front into
            // its JIT-hook table, which one interpretation fills whole. When that table is present it
            // is the recovery, and the image-write rounds below have nothing to do.
            if (round == 1 && rewrite.NecroBitBodies.Count > 0)
                return RecoverViaNecroBit(context, stubs, bootstrap, rewrite, raisings);

            application = ImageRewriteRecovery.TryApply(
                context,
                policy,
                rewrite.ImageWrites,
                out var roundApplied,
                out var roundDiagnostics);
            if (application != RewriteApplication.Applied || roundApplied is null)
            {
                // A later round being refused rolls back only its own graft, so whatever an earlier
                // round proved is still in place. Its account of the module has to survive too, or
                // the pass would report bodies it grafted as bodies it never touched.
                if (applied is null)
                {
                    applyDiagnostics = roundDiagnostics;
                }
                else
                {
                    rounds.Add(
                        $"Round {round} was refused and left the earlier rounds as they were" +
                        (roundDiagnostics.Count == 0 ? "." : $": {roundDiagnostics[0]}"));
                }
                break;
            }

            applied = roundApplied;
            appliedFrom = rewrite;
            applyDiagnostics = roundDiagnostics;
            var fresh = roundApplied.Recovered.Count(target => grafted.Add(target.Token));
            if (rewrite.Result.Succeeded || fresh == 0 || round == MostRounds)
                break;
            rounds.Add(
                $"Round {round} grafted {fresh} body(ies) the loader had already written when it " +
                $"stopped at {rewrite.Result.Status}, then interpreted it again against them.");
        }

        if (rewrite is null)
            return (PassStatus.Failed, 0, ["The bootstrap was never interpreted."]);
        // Everything reported below describes the module as it now stands, so it has to come from the
        // round whose graft is in place rather than from a later round that was rolled back.
        rewrite = appliedFrom ?? rewrite;

        var attempt = new MethodRecoveryAttempt(
            bootstrap.MDToken.Raw,
            rewrite.Result.Status,
            rewrite.Result.Steps,
            stubs.Count,
            rewrite.ImageWrites.Count,
            rewrite.ImageWrites.Sum(write => write.Bytes.Length),
            rewrite.Result.Diagnostic);
        context.SetFact("method-protection.attempt", attempt);
        context.AddEvidence(new Evidence(
            "method-recovery",
            $"Two deterministic static bootstrap executions: {rewrite.Result.Status}, " +
            $"{rewrite.Result.Steps} steps, {rewrite.ImageWrites.Count} mapped-image writes.",
            $"{bootstrap.MDToken} {bootstrap.FullName}",
            rewrite.Result.Succeeded ? 0.95 : 0.75));

        // The loader seeds per-site resolver keys into instance fields of a singleton it roots
        // in a static field. Downstream string and boolean recovery cannot prove any call-site
        // argument without them, and this is the only interpretation that runs the bootstrap.
        if (rewrite.IntegerFields.Count != 0)
        {
            context.SetFact("bootstrap.integerFields", rewrite.IntegerFields);
            context.AddEvidence(new Evidence(
                "loader-key-fields",
                $"Captured {rewrite.IntegerFields.Count} loader-initialized integer field(s) that agreed " +
                "across two independent bootstrap interpretations.",
                $"{bootstrap.MDToken} {bootstrap.FullName}",
                0.95));
        }
        // The loader also builds the tables that say which method a hidden call reaches. They are
        // its own work, decoded with constants that change from build to build, so the run that
        // built them is the only place they exist without reimplementing that build's cipher.
        if (rewrite.TokenMaps.Count != 0)
        {
            context.SetFact("bootstrap.tokenMaps", rewrite.TokenMaps);
            context.AddEvidence(new Evidence(
                "loader-token-tables",
                $"Captured {rewrite.TokenMaps.Count} loader-initialized token table(s) holding " +
                $"{rewrite.TokenMaps.Values.Sum(table => table.Count)} entry(ies) in total, agreeing " +
                "across two independent bootstrap interpretations.",
                $"{bootstrap.MDToken} {bootstrap.FullName}",
                0.95));
        }
        context.SetFact("bootstrap.evidence", rewrite.Evidence);
        context.SetFact("bootstrap.token", bootstrap.MDToken.Raw);
        foreach (var group in rewrite.Evidence.Observations.GroupBy(item => item.Kind))
        {
            context.AddEvidence(new Evidence(
                "loader-observation",
                $"{group.Key}: {group.Count()} occurrence(s); " +
                string.Join("; ", group.Select(item => item.Verdict is null
                    ? item.Detail
                    : $"{item.Detail} => {item.Verdict}").Distinct().Take(4)),
                $"{bootstrap.MDToken} {bootstrap.FullName}",
                0.95));
        }

        if (applied is null)
        {
            // A run that finished and still wrote nothing usable is the old "nothing to apply". A run
            // that stopped is reported as the stop it was, which is the more useful of the two.
            if (rewrite.Result.Succeeded)
            {
                return (application == RewriteApplication.NothingToApply
                    ? PassStatus.Unsupported
                    : PassStatus.Failed, 0, applyDiagnostics);
            }
            return (PassStatus.Unsupported, 0,
            [
                .. raisings,
                $"Both bounded bootstrap interpretations stopped after {rewrite.Result.Steps} steps: " +
                $"{rewrite.Result.Status}.",
                rewrite.Result.Diagnostic ?? "No diagnostic was provided.",
                .. applyDiagnostics,
                "No method body or initializer was modified."
            ]);
        }

        // Only the bodies that came back are recorded as changed. A catalogued stub the loader never
        // wrote was not modified, and a change record claiming otherwise would be the one place the
        // report says a method was restored when it was only ever itself.
        var names = stubs.ToDictionary(stub => stub.Token, stub => stub.Method);
        foreach (var target in applied.Recovered)
        {
            context.AddChange(new ChangeRecord(
                Name,
                "restore-method-body",
                $"0x{target.Token:X8} {names[target.Token]}",
                "Grafted deterministic statically restored CIL by unchanged MethodDef token."));
        }
        var restored = applied.Recovered.Count;
        // Completeness is a claim about the loader having run to the end, not about how many bodies
        // came back. A loader that stopped may have had more to write, so the passes that gate on
        // this stay gated even though every body being reported here is individually proven.
        var complete = rewrite.Result.Succeeded;
        context.SetFact("method-protection.complete", complete);
        context.SetFact("method-protection.restored", restored);

        var notes = new List<string>();
        notes.AddRange(raisings);
        notes.AddRange(rounds);
        if (complete)
        {
            notes.Add(restored == stubs.Count
                ? $"Restored and verified all {restored} protected method bodies."
                : $"Restored and verified {restored} of {stubs.Count} catalogued method bodies.");
        }
        else
        {
            notes.Add(
                $"The bootstrap stopped at {rewrite.Result.Status} after {rewrite.Result.Steps} steps, " +
                $"having already written {restored} of {stubs.Count} catalogued method bodies. Each was " +
                "replayed, reparsed and verified before being grafted.");
            notes.Add(rewrite.Result.Diagnostic ?? "No diagnostic was provided.");
        }
        notes.Add(
            $"Replayed {rewrite.ImageWrites.Count} deterministic writes while preserving all bytes " +
            "outside stub prefixes.");
        notes.AddRange(applyDiagnostics);
        notes.Add(complete
            ? "Removing the loader bootstrap itself is left to anti-tamper neutralization."
            : "Restoration is reported partial because the loader did not finish, so the passes that " +
                "mutate a JIT-hook artifact stay gated.");
        return (complete ? PassStatus.Success : PassStatus.Partial, restored, notes);
    }

    /// <summary>
    /// The step ceiling for the bootstrap, which grows with the number of methods it has to decrypt.
    /// </summary>
    /// <remarks>
    /// The loader walks its table of encrypted bodies once per protected method, so what the
    /// bootstrap costs is set by how many there are rather than by how complicated any of them is.
    /// Measured across the Reactor samples on hand it takes between 2,050 and 2,550 steps per stub,
    /// a 197-stub module and a 5,367-stub one included, so the figure below leaves roughly four
    /// times the observed cost. A ceiling is a guard against code that does not terminate, not an
    /// estimate of the work, and it costs nothing when it is not reached: steps are only spent as
    /// they are taken. A flat ceiling, by contrast, is either too low for a large module or too
    /// patient with a small one that has genuinely hung.
    ///
    /// The floor keeps the smallest samples on the ceiling they already had, so that scaling this
    /// cannot make a module that used to be recovered stop being recovered.
    /// </remarks>
    internal static int StepBudgetFor(int stubs) =>
        Math.Max(2_000_000, checked(stubs * 10_000));

    /// <summary>How many times the pass will raise its own ceiling before reporting the stop.</summary>
    /// <remarks>
    /// Running out of steps here is not a stop worth handing back to whoever ran the tool. Every other
    /// budget stop in a run happens in a pass that goes on to succeed anyway, so raising those buys
    /// nothing; this one decides whether any method body comes back at all, and a run that recovers
    /// nothing and then asks to be run again with a larger number is asking a person to do arithmetic
    /// the tool could have done. So it does it, and says that it did.
    ///
    /// It does not do it indefinitely. The ceiling already starts at about four times what the
    /// bootstrap is measured to cost, and three doublings put it past thirty times. Code that has not
    /// finished by then is not a large module, it is a loop that does not terminate, and reporting
    /// that is the useful answer rather than spending longer to say the same thing.
    /// </remarks>
    internal const int MostRaisings = 3;

    /// <summary>
    /// How many times the bootstrap is interpreted again after grafting the bodies it had written.
    /// </summary>
    /// <remarks>
    /// Reactor's own runtime is among the bodies its loader decrypts: on the samples measured here the
    /// virtualization engine's methods are protected stubs like any other. Interpreting a stub reads
    /// the placeholder rather than the engine, so a bootstrap that calls into its own virtualized code
    /// stops on state that the engine would have built. Grafting what the loader has already written
    /// and interpreting it again gives the second run the real engine to call, which is the state a
    /// process is in once the JIT hook has fired.
    ///
    /// The loop stops as soon as a round recovers no body the previous rounds had not, so a module
    /// whose loader runs to completion the first time pays nothing for this. Rounds are capped because
    /// each one costs a full interpretation, and a bootstrap still finding new bodies on the fourth
    /// pass is not converging on anything.
    /// </remarks>
    internal const int MostRounds = 3;

    /// <summary>
    /// Restores NecroBit-protected bodies from the decrypt table the loader filled before it stopped,
    /// then publishes the same loader facts the image-replay path does so that downstream string and
    /// call recovery can proceed on a fully deprotected module.
    /// </summary>
    private (PassStatus, int, IReadOnlyList<string>) RecoverViaNecroBit(
        ArtifactContext context,
        IReadOnlyList<ProtectedMethodStub> stubs,
        MethodDef bootstrap,
        InterpretedRewrite rewrite,
        IReadOnlyList<string> raisings)
    {
        PublishLoaderFacts(context, bootstrap, rewrite);
        var attempt = new MethodRecoveryAttempt(
            bootstrap.MDToken.Raw,
            rewrite.Result.Status,
            rewrite.Result.Steps,
            stubs.Count,
            0,
            0,
            rewrite.Result.Diagnostic);
        context.SetFact("method-protection.attempt", attempt);

        if (!NecroBitBodyRecovery.TryApply(
                context,
                stubs,
                rewrite.NecroBitBodies,
                rewrite.ImageWrites,
                out var recovered,
                out var applyDiagnostics))
        {
            context.SetFact("method-protection.complete", false);
            return (PassStatus.Unsupported, 0,
            [
                .. raisings,
                $"The NecroBit decrypt table held {rewrite.NecroBitBodies.Count} body(ies), but they " +
                "could not be mapped and grafted.",
                .. applyDiagnostics,
            ]);
        }

        var names = stubs.ToDictionary(stub => stub.Token, stub => stub.Method);
        foreach (var token in recovered)
        {
            context.AddChange(new ChangeRecord(
                Name,
                "restore-method-body",
                $"0x{token:X8} {names.GetValueOrDefault(token, "method")}",
                "Grafted plaintext CIL captured from the NecroBit decrypt table by unchanged " +
                "MethodDef token."));
        }

        // Every catalogued stub whose body came back means NecroBit was holding nothing more, so the
        // protection is fully undone and the passes gated on that can run. A stub left behind is one
        // whose ciphertext the loader had not decrypted when it stopped, which keeps this partial.
        var complete = recovered.Count == stubs.Count;
        context.SetFact("method-protection.complete", complete);
        context.SetFact("method-protection.restored", recovered.Count);
        context.AddEvidence(new Evidence(
            "method-recovery",
            $"Captured NecroBit's decrypt table from two agreeing bootstrap interpretations and " +
            $"grafted {recovered.Count} of {stubs.Count} protected method bodies.",
            $"{bootstrap.MDToken} {bootstrap.FullName}",
            0.95));

        var notes = new List<string>();
        notes.AddRange(raisings);
        notes.Add(complete
            ? $"Restored and verified all {recovered.Count} protected method bodies from the NecroBit " +
                "decrypt table."
            : $"Restored and verified {recovered.Count} of {stubs.Count} protected method bodies from " +
                "the NecroBit decrypt table; the loader had not decrypted the rest when it stopped.");
        notes.AddRange(applyDiagnostics);
        notes.Add(complete
            ? "Removing the loader bootstrap and JIT hook is left to anti-tamper neutralization."
            : "Restoration is reported partial because the loader stopped before decrypting every " +
                "body, so the passes that mutate a JIT-hook artifact stay gated.");
        return (complete ? PassStatus.Success : PassStatus.Partial, recovered.Count, notes);
    }

    /// <summary>
    /// Records the loader-built keys, token tables, and observations from the one interpretation that
    /// runs the bootstrap, which downstream string and call recovery depend on.
    /// </summary>
    private static void PublishLoaderFacts(
        ArtifactContext context,
        MethodDef bootstrap,
        InterpretedRewrite rewrite)
    {
        if (rewrite.IntegerFields.Count != 0)
            context.SetFact("bootstrap.integerFields", rewrite.IntegerFields);
        if (rewrite.TokenMaps.Count != 0)
            context.SetFact("bootstrap.tokenMaps", rewrite.TokenMaps);
        context.SetFact("bootstrap.evidence", rewrite.Evidence);
        context.SetFact("bootstrap.token", bootstrap.MDToken.Raw);
    }

    private static MethodDef? FindBootstrap(ModuleDef module)
    {
        var initializer = module.GlobalType.FindStaticConstructor();
        if (initializer?.HasBody != true)
            return null;
        return initializer.Body.Instructions
            .Where(instruction => instruction.OpCode.FlowControl == FlowControl.Call)
            .Select(instruction => (instruction.Operand as IMethod)?.ResolveMethodDef())
            .FirstOrDefault(method => method?.HasBody == true &&
                method.IsStatic &&
                method.MethodSig?.Params.Count == 0 &&
                method.Body.Instructions.Count >= 100);
    }
}
