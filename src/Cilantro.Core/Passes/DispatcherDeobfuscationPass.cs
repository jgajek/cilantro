using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Passes;

public interface IDispatcherBodyTransaction : IDisposable
{
    void Capture(Instruction instruction);
    void Commit();
    void Rollback();
}

public interface IDispatcherBodyTransactionFactory
{
    IDispatcherBodyTransaction Begin(MethodDef method);
}

public sealed class DispatcherBodyTransactionFactory : IDispatcherBodyTransactionFactory
{
    public IDispatcherBodyTransaction Begin(MethodDef method)
    {
        ArgumentNullException.ThrowIfNull(method);
        return new DispatcherBodyTransaction(method);
    }

    private sealed class DispatcherBodyTransaction : IDispatcherBodyTransaction
    {
        private readonly BodyMutationTransaction transaction;

        public DispatcherBodyTransaction(MethodDef method) =>
            transaction = new BodyMutationTransaction(method);

        public void Capture(Instruction instruction) =>
            ArgumentNullException.ThrowIfNull(instruction);

        public void Commit() => transaction.Commit();

        public void Rollback() => transaction.Rollback();

        public void Dispose() => transaction.Dispose();
    }
}

public sealed record DispatcherMethodRewriteResult(
    DispatcherQualification Qualification,
    int ChangedEdges,
    IReadOnlyList<string> Diagnostics);

/// <summary>
/// Applies only plans produced by <see cref="DispatcherAnalyzer"/>. The pass leaves switch
/// scaffolding in place and redirects proven state-setting edges, minimizing mutation surface.
/// </summary>
public sealed class DispatcherDeobfuscationPass : DeobfuscationPass
{
    private readonly DispatcherAnalyzer analyzer;
    private readonly IDispatcherBodyTransactionFactory transactions;

    public DispatcherDeobfuscationPass(
        DispatcherAnalyzer? analyzer = null,
        IDispatcherBodyTransactionFactory? transactions = null)
    {
        this.analyzer = analyzer ?? new DispatcherAnalyzer();
        this.transactions = transactions ?? new DispatcherBodyTransactionFactory();
    }

    public override string Name => "dispatcher-deobfuscation";
    public override IReadOnlyCollection<string> Dependencies => ["control-flow-analysis"];

    public DispatcherMethodRewriteResult Rewrite(MethodDef method)
    {
        var analysis = analyzer.Analyze(method);
        if (!analysis.IsQualified)
            return new DispatcherMethodRewriteResult(
                analysis.Qualification,
                0,
                analysis.Diagnostics);

        var before = EvaluationStackAnalyzer.Analyze(method);
        if (!before.Valid)
            return new DispatcherMethodRewriteResult(
                DispatcherQualification.Ambiguous,
                0,
                ["Pre-rewrite stack analysis is not valid; method was preserved."]);

        using var transaction = transactions.Begin(method);
        try
        {
            Apply(analysis.Plan!, transaction);
            ControlFlowGraph.Build(method);
            var after = EvaluationStackAnalyzer.Analyze(method);
            if (!after.Valid)
            {
                transaction.Rollback();
                return new DispatcherMethodRewriteResult(
                    DispatcherQualification.Ambiguous,
                    0,
                    ["Rewritten stack analysis failed; method was rolled back."]);
            }
            transaction.Commit();
            return new DispatcherMethodRewriteResult(
                DispatcherQualification.Qualified,
                analysis.Plan!.Rewrites.Count,
                [$"Replaced {analysis.Plan.Rewrites.Count} dispatcher edges."]);
        }
        catch (Exception ex)
        {
            transaction.Rollback();
            return new DispatcherMethodRewriteResult(
                DispatcherQualification.Ambiguous,
                0,
                [$"Rewrite failed closed: {ex.Message}"]);
        }
    }

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        var candidates = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody)
            .Select(method => (Method: method, Analysis: analyzer.Analyze(method)))
            .Where(item => item.Analysis.Qualification != DispatcherQualification.NotCandidate)
            .ToArray();
        var qualified = candidates.Where(item => item.Analysis.IsQualified).ToArray();
        var active = new List<(MethodDef Method, DispatcherRewritePlan Plan,
            IDispatcherBodyTransaction Transaction)>();
        var diagnostics = new List<string>();

        try
        {
            foreach (var item in qualified)
            {
                var stack = EvaluationStackAnalyzer.Analyze(item.Method);
                if (!stack.Valid)
                {
                    diagnostics.Add($"{item.Method.FullName}: invalid pre-rewrite stack; preserved.");
                    continue;
                }

                var transaction = transactions.Begin(item.Method);
                active.Add((item.Method, item.Analysis.Plan!, transaction));
                Apply(item.Analysis.Plan!, transaction);
                ControlFlowGraph.Build(item.Method);
                if (!EvaluationStackAnalyzer.Analyze(item.Method).Valid)
                    throw new InvalidOperationException(
                        $"{item.Method.FullName}: post-rewrite stack analysis failed.");
            }

            var verification = AssemblyVerifier.Verify(context.Module);
            if (!verification.Passed)
                throw new InvalidOperationException(
                    $"assembly verification failed: {string.Join("; ", verification.Diagnostics)}");

            foreach (var item in active)
            {
                item.Transaction.Commit();
                foreach (var rewrite in item.Plan.Rewrites)
                {
                    context.AddChange(new ChangeRecord(
                        Name,
                        "redirect-dispatcher-edge",
                        $"{item.Method.MDToken} IL_{rewrite.Branch.Offset:X4}",
                        $"constant state {rewrite.State} -> IL_{rewrite.Target.Offset:X4}"));
                }
            }
        }
        catch (Exception ex)
        {
            foreach (var item in active)
                item.Transaction.Rollback();
            diagnostics.Add($"All dispatcher changes were rolled back: {ex.Message}");
            return (PassStatus.Failed, 0, diagnostics);
        }
        finally
        {
            foreach (var item in active)
                item.Transaction.Dispose();
        }

        var ambiguous = candidates.Length - qualified.Length;
        if (ambiguous != 0)
            diagnostics.Add($"Preserved {ambiguous} ambiguous dispatcher-like methods.");
        diagnostics.Add($"Rewrote {active.Count} methods using {active.Sum(item => item.Plan.Rewrites.Count)} edges.");
        context.SetFact("cfg.dispatcherQualified", qualified.Length);
        context.SetFact("cfg.dispatcherAmbiguous", ambiguous);
        return (PassStatus.Success, active.Sum(item => item.Plan.Rewrites.Count), diagnostics);
    }

    private static void Apply(
        DispatcherRewritePlan plan,
        IDispatcherBodyTransaction transaction)
    {
        foreach (var rewrite in plan.Rewrites)
        {
            foreach (var removed in rewrite.RemovedInstructions)
            {
                transaction.Capture(removed);
                removed.OpCode = OpCodes.Nop;
                removed.Operand = null;
            }
            transaction.Capture(rewrite.Branch);
            rewrite.Branch.OpCode = OpCodes.Br;
            rewrite.Branch.Operand = rewrite.Target;
        }
    }
}
