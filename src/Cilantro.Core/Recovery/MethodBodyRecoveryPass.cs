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
        var ceiling = StepBudgetFor(stubs.Count);
        var raisings = new List<string>();
        InterpretedRewrite? rewrite;
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
                    out rewrite,
                    out var interpretDiagnostic) ||
                rewrite is null)
            {
                return (PassStatus.Failed, 0,
                    [interpretDiagnostic!, "No method body or initializer was modified."]);
            }
            if (rewrite.Result.Status != StaticExecutionStatus.StepLimitExceeded ||
                raisings.Count == MostRaisings)
            {
                break;
            }
            // The ceiling actually in force, which a declared budget can have raised above ours.
            ceiling = checked(limits.MaximumSteps * 2);
            raisings.Add(
                $"The bootstrap reached its {limits.MaximumSteps}-step ceiling with nothing to show, " +
                $"so it was run again with {ceiling}.");
        }

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

        if (!rewrite.Result.Succeeded)
        {
            return (PassStatus.Unsupported, 0,
            [
                .. raisings,
                $"Both bounded bootstrap interpretations stopped after {rewrite.Result.Steps} steps: " +
                $"{rewrite.Result.Status}.",
                rewrite.Result.Diagnostic ?? "No diagnostic was provided.",
                "No method body or initializer was modified."
            ]);
        }

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

        var application = ImageRewriteRecovery.TryApply(
            context,
            policy,
            rewrite.ImageWrites,
            out var applied,
            out var applyDiagnostics);
        if (application != RewriteApplication.Applied || applied is null)
        {
            return (application == RewriteApplication.NothingToApply
                ? PassStatus.Unsupported
                : PassStatus.Failed, 0, applyDiagnostics);
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
        context.SetFact("method-protection.complete", true);
        context.SetFact("method-protection.restored", restored);
        return (PassStatus.Success, restored,
        [
            .. raisings,
            restored == stubs.Count
                ? $"Restored and verified all {restored} protected method bodies."
                : $"Restored and verified {restored} of {stubs.Count} catalogued method bodies.",
            $"Replayed {rewrite.ImageWrites.Count} deterministic writes while preserving all bytes outside stub prefixes.",
            .. applyDiagnostics,
            "Removing the loader bootstrap itself is left to anti-tamper neutralization."
        ]);
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
