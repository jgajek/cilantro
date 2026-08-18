using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core.Interpretation;
using ReactorUnpack.Core.Passes;

namespace ReactorUnpack.Core.Recovery;

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

        var limits = BootstrapMachine.Environment(context).Declarations.Budgets.Over(
            new StaticMachineLimits(
                MaximumSteps: 2_000_000,
                MaximumRecursionDepth: 64,
                MaximumAllocatedBytes: 256 * 1024 * 1024,
                MaximumArrayLength: 256 * 1024 * 1024,
                MaximumProvenanceNodes: 1_000_000,
                MaximumProvenanceDepth: 8_192,
                MaximumRenderedProvenanceNodes: 96));
        var executionRoot = context.Module.GlobalType.FindStaticConstructor() ?? bootstrap;
        if (!ImageRewriteRecovery.TryInterpret(
                context,
                executionRoot,
                limits,
                out var rewrite,
                out var interpretDiagnostic) ||
            rewrite is null)
        {
            return (PassStatus.Failed, 0,
                [interpretDiagnostic!, "No method body or initializer was modified."]);
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
            out var restored,
            out var applyDiagnostics);
        if (application != RewriteApplication.Applied)
        {
            return (application == RewriteApplication.NothingToApply
                ? PassStatus.Unsupported
                : PassStatus.Failed, 0, applyDiagnostics);
        }

        foreach (var stub in stubs)
        {
            context.AddChange(new ChangeRecord(
                Name,
                "restore-method-body",
                $"0x{stub.Token:X8} {stub.Method}",
                "Grafted deterministic statically restored CIL by unchanged MethodDef token."));
        }
        context.SetFact("method-protection.complete", true);
        context.SetFact("method-protection.restored", restored);
        return (PassStatus.Success, restored,
        [
            $"Restored and verified all {restored} protected method bodies.",
            $"Replayed {rewrite.ImageWrites.Count} deterministic writes while preserving all bytes outside stub prefixes.",
            "Removing the loader bootstrap itself is left to anti-tamper neutralization."
        ]);
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
