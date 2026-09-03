using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Passes;

public sealed class MethodProtectionAnalysisPass : DeobfuscationPass
{
    public override string Name => "method-protection";
    public override IReadOnlyCollection<string> Dependencies => ["reactor-detection"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<ReactorStructureFacts>("reactor.structure", out var facts) ||
            facts is null ||
            facts.MethodStubCount == 0)
        {
            return (PassStatus.Success, 0, ["No Reactor method-body stubs were detected."]);
        }

        var stubs = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(ReactorStructureDetector.IsProtectedMethodStub)
            .Select(method => new ProtectedMethodStub(
                method.MDToken.Raw,
                (uint)method.RVA,
                method.FullName,
                method.Body.Instructions.Count))
            .ToArray();
        context.SetFact("method-protection.stubs", stubs);

        var initializer = context.Module.GlobalType.FindStaticConstructor();
        var bootstrap = initializer?.Body?.Instructions
            .Where(instruction => instruction.OpCode.FlowControl == FlowControl.Call)
            .Select(instruction => instruction.Operand as MethodDef)
            .FirstOrDefault(method => method?.HasBody == true &&
                method.Body.Instructions.Count >= 100);
        if (bootstrap is not null)
        {
            context.AddEvidence(new Evidence(
                "method-protection-bootstrap",
                $"Large module-initializer bootstrap with {bootstrap.Body.Instructions.Count} instructions.",
                $"{bootstrap.MDToken} {bootstrap.FullName}",
                0.95));
        }

        context.AddEvidence(new Evidence(
            "method-encryption",
            $"{stubs.Length} NoInlining default-return method stubs require prefix restoration.",
            Confidence: 1.0));
        return (PassStatus.Success, 0,
        [
            $"Detected {stubs.Length} protected method stubs.",
            "Recovery is delegated to the original-byte method-body recovery phase."
        ]);
    }
}

public sealed record ProtectedMethodStub(uint Token, uint Rva, string Method, int StubInstructionCount);

public sealed class ControlFlowAnalysisPass : DeobfuscationPass
{
    public override string Name => "control-flow-analysis";
    public override IReadOnlyCollection<string> Dependencies => ["method-protection"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var methods = context.Module.GetTypes().SelectMany(type => type.Methods)
            .Where(method => method.HasBody)
            .ToArray();
        var unreachable = 0;
        var dispatchers = 0;
        var stackDiagnostics = 0;
        foreach (var method in methods)
        {
            unreachable += method.Body.Instructions.Count -
                CfgDeadCodePass.ComputeReachable(method).Count;
            if (!ReactorStructureDetector.IsDispatcher(method))
                continue;
            dispatchers++;
            if (method.Body.Instructions.Count <= 10_000)
                stackDiagnostics += EvaluationStackAnalyzer.Analyze(method).Diagnostics.Count;
        }

        context.SetFact("cfg.unreachableInstructions", unreachable);
        context.SetFact("cfg.dispatcherMethods", dispatchers);
        context.SetFact("cfg.stackDiagnostics", stackDiagnostics);
        return (PassStatus.Success, 0,
        [
            $"Found {dispatchers} dispatcher methods and {unreachable} unreachable instructions.",
            $"Conservative stack analysis produced {stackDiagnostics} diagnostics."
        ]);
    }
}

public sealed class ConstantPredicatePass : DeobfuscationPass
{
    public override string Name => "constant-predicates";
    public override IReadOnlyCollection<string> Dependencies => ["method-protection"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        using var transaction = new InstructionMutationTransaction();
        var changes = ConstantHelperFolding.Fold(
            context.Module.GetTypes().SelectMany(type => type.Methods),
            ConstantHelperFolding.Catalog(context.Module),
            transaction,
            (method, instruction, value) => context.AddChange(new ChangeRecord(
                Name,
                "fold-constant-helper",
                $"{method.MDToken} IL_{instruction.Offset:X4}",
                value.ToString())));

        var verification = AssemblyVerifier.Verify(context.Module);
        if (!verification.Passed)
        {
            transaction.Rollback();
            return (PassStatus.Failed, 0,
                ["Constant predicate rewrite failed verification and was rolled back."]);
        }
        transaction.Commit();
        return (PassStatus.Success, changes, [$"Folded {changes} calls to proven constant helpers."]);
    }
}
