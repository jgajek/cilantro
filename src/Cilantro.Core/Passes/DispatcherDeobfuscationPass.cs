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
/// Applies only plans produced by <see cref="DispatcherAnalyzer"/> or
/// <see cref="ConfuserExDispatcherAnalyzer"/>: it redirects the edges they proved and touches
/// nothing else, leaving a dispatcher standing for as long as anything still goes through it.
/// </summary>
/// <remarks>
/// Two things beyond the edges themselves have to happen for the result to be a method a runtime
/// will accept, both of them consequences of the state travelling on the evaluation stack. A
/// dispatcher that loses an edge is handed its state in a variable instead
/// (<see cref="DispatcherEntryRelocation"/>), and scaffolding that nothing reaches any more is
/// neutered, because unreachable code is still checked and the dispatcher's arithmetic expects a
/// state that is no longer pushed.
/// </remarks>
public sealed class DispatcherDeobfuscationPass : DeobfuscationPass
{
    private readonly DispatcherAnalyzer analyzer;
    private readonly ConfuserExDispatcherAnalyzer confuserExAnalyzer;
    private readonly IDispatcherBodyTransactionFactory transactions;

    public DispatcherDeobfuscationPass(
        DispatcherAnalyzer? analyzer = null,
        IDispatcherBodyTransactionFactory? transactions = null,
        ConfuserExDispatcherAnalyzer? confuserExAnalyzer = null)
    {
        this.analyzer = analyzer ?? new DispatcherAnalyzer();
        this.transactions = transactions ?? new DispatcherBodyTransactionFactory();
        this.confuserExAnalyzer = confuserExAnalyzer ?? new ConfuserExDispatcherAnalyzer();
    }

    public override string Name => "dispatcher-deobfuscation";
    public override IReadOnlyCollection<string> Dependencies => ["control-flow-analysis"];

    public DispatcherMethodRewriteResult Rewrite(MethodDef method)
    {
        var analysis = analyzer.Analyze(method);
        IReadOnlyList<DispatcherEdgeRedirect> edges;
        IReadOnlyList<DispatcherEntryRelocation> relocations = [];
        if (analysis.IsQualified)
        {
            edges = analysis.Plan!.Rewrites.Select(DispatcherEdgeRedirect.From).ToArray();
        }
        else if (analysis.Qualification == DispatcherQualification.NotCandidate &&
                 confuserExAnalyzer.Analyze(method) is { } confuserEx)
        {
            if (!confuserEx.IsQualified)
                return new DispatcherMethodRewriteResult(
                    confuserEx.Qualification,
                    0,
                    confuserEx.Diagnostics);
            edges = confuserEx.Plan!.Rewrites;
            relocations = confuserEx.Plan.Relocations;
        }
        else
        {
            return new DispatcherMethodRewriteResult(
                analysis.Qualification,
                0,
                analysis.Diagnostics);
        }

        var before = EvaluationStackAnalyzer.Analyze(method);
        if (!before.Valid)
            return new DispatcherMethodRewriteResult(
                DispatcherQualification.Ambiguous,
                0,
                ["Pre-rewrite stack analysis is not valid; method was preserved."]);

        using var transaction = transactions.Begin(method);
        try
        {
            Apply(method, edges, relocations, transaction);
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
                edges.Count,
                [$"Replaced {edges.Count} dispatcher edges."]);
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
        var methods = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody)
            .ToArray();
        var candidates = methods
            .Select(method => (Method: method, Analysis: analyzer.Analyze(method)))
            .Where(item => item.Analysis.Qualification != DispatcherQualification.NotCandidate)
            .ToArray();
        var qualified = candidates.Where(item => item.Analysis.IsQualified).ToArray();
        var planned = qualified
            .Select(item => (
                item.Method,
                Edges: item.Analysis.Plan!.Rewrites
                    .Select(DispatcherEdgeRedirect.From)
                    .ToArray() as IReadOnlyList<DispatcherEdgeRedirect>,
                Relocations: (IReadOnlyList<DispatcherEntryRelocation>)[]))
            .ToList();
        var diagnostics = new List<string>();

        var confuserEx = PlanConfuserEx(context, methods, qualified, diagnostics);
        planned.AddRange(confuserEx.Planned);

        var active = new List<(MethodDef Method, IReadOnlyList<DispatcherEdgeRedirect> Edges,
            IDispatcherBodyTransaction Transaction)>();

        try
        {
            foreach (var item in planned)
            {
                var stack = EvaluationStackAnalyzer.Analyze(item.Method);
                if (!stack.Valid)
                {
                    diagnostics.Add($"{item.Method.FullName}: invalid pre-rewrite stack; preserved.");
                    continue;
                }

                var transaction = transactions.Begin(item.Method);
                active.Add((item.Method, item.Edges, transaction));
                Apply(item.Method, item.Edges, item.Relocations, transaction);
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
                foreach (var rewrite in item.Edges)
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
        var edges = active.Sum(item => item.Edges.Count);
        context.SetFact("cfg.dispatcherEdgesRedirected", edges);
        diagnostics.Add($"Rewrote {active.Count} methods using {edges} edges.");
        context.SetFact("cfg.dispatcherQualified", qualified.Length);
        context.SetFact("cfg.dispatcherAmbiguous", ambiguous);
        return (PassStatus.Success, edges, diagnostics);
    }

    /// <summary>
    /// ConfuserEx's flattener threads its state through the evaluation stack and derives the case
    /// from a remainder, which is a different shape from the local-state dispatchers
    /// <see cref="DispatcherAnalyzer"/> proves, so it gets its own analyzer and the same rewrite.
    /// </summary>
    private (List<(MethodDef Method, IReadOnlyList<DispatcherEdgeRedirect> Edges,
        IReadOnlyList<DispatcherEntryRelocation> Relocations)> Planned, int Residual)
        PlanConfuserEx(
            ArtifactContext context,
            IReadOnlyList<MethodDef> methods,
            IReadOnlyList<(MethodDef Method, DispatcherAnalysisResult Analysis)> alreadyPlanned,
            List<string> diagnostics)
    {
        var planned = new List<(MethodDef, IReadOnlyList<DispatcherEdgeRedirect>,
            IReadOnlyList<DispatcherEntryRelocation>)>();
        if (!context.TryGetFact<ConfuserExStructureFacts>("confuserex.structure", out var facts) ||
            facts is null || !facts.IsConfuserExProtected)
        {
            return (planned, 0);
        }

        var skip = alreadyPlanned.Select(item => item.Method).ToHashSet();
        var flattened = 0;
        var whole = 0;
        var declined = 0;
        var residual = 0;
        var dispatchers = 0;
        var stored = 0;
        var declines = new Dictionary<ConfuserExEdgeDecline, int>();
        foreach (var method in methods.Where(method => !skip.Contains(method)))
        {
            var result = confuserExAnalyzer.Analyze(method);
            if (result.Qualification == DispatcherQualification.NotCandidate)
                continue;
            if (result.Plan is { } counted)
            {
                foreach (var (decline, count) in counted.Declines)
                    declines[decline] = declines.GetValueOrDefault(decline) + count;
            }

            if (!result.IsQualified)
            {
                declined++;
                continue;
            }

            flattened++;
            dispatchers += result.Plan!.Dispatchers;
            residual += result.Plan.ResidualEdges;
            stored += result.Plan.Rewrites.Count(edge => edge.RestoredStateLocal is not null);
            if (result.Plan.ResidualEdges == 0)
                whole++;
            planned.Add((method, result.Plan.Rewrites, result.Plan.Relocations));
        }

        if (flattened == 0 && declined == 0)
            return (planned, 0);

        var resolved = planned.Sum(item => item.Item2.Count);
        var relocated = planned.Sum(item => item.Item3.Count);
        diagnostics.Add(
            $"ConfuserEx flattening: resolved {resolved} of {resolved + residual} edges across " +
            $"{dispatchers} dispatcher(s) in {flattened} method(s), {whole} of them completely.");
        if (stored != 0)
            diagnostics.Add(
                $"{stored} redirected edge(s) assign the dispatcher state themselves, because " +
                "something outside the erased arithmetic still reads it.");
        if (relocated != 0)
            diagnostics.Add(
                $"{relocated} dispatcher(s) now take their state from a variable, so the edges left " +
                "going through them no longer need the fragment that fell into them.");
        if (declined != 0)
            diagnostics.Add($"Preserved {declined} flattened methods no edge could be proven in.");
        // Naming what stopped the rest is the difference between a limit and an unexplained
        // shortfall, and the categories are what would have to change to go further.
        foreach (var (decline, count) in declines.OrderByDescending(entry => entry.Value))
            diagnostics.Add($"{count} edge(s) left alone: {Explain(decline)}");
        context.SetFact("cfg.confuserExDispatcherMethods", flattened);
        context.SetFact("cfg.confuserExDispatcherResidualEdges", residual);
        return (planned, residual);
    }

    private static string Explain(ConfuserExEdgeDecline decline) => decline switch
    {
        ConfuserExEdgeDecline.SharedFragment =>
            "two states meet on them before either has finished being computed, so neither the " +
            "meeting point nor the last instruction to push the state belongs to one path",
        ConfuserExEdgeDecline.UnremovableExpression =>
            "the state was not a contiguous run of instructions that can be erased without erasing " +
            "anything else",
        ConfuserExEdgeDecline.ExceptionRegion =>
            "a direct jump would enter or leave a try, filter or handler",
        ConfuserExEdgeDecline.VaryingState =>
            "two states chose the same case, so no single state can be assigned where one is read",
        ConfuserExEdgeDecline.DispatcherEntry =>
            "the dispatcher they enter is also reached by a conditional branch or a switch case, " +
            "which leaves nowhere to hand over the state once it moves off the stack",
        _ => decline.ToString()
    };

    /// <summary>
    /// Hands a dispatcher its state in a fresh variable rather than on the evaluation stack, which is
    /// what lets the edges into it be redirected one at a time. See
    /// <see cref="DispatcherEntryRelocation"/> for why the stack makes them interdependent.
    /// </summary>
    private static void Relocate(
        MethodDef method,
        IReadOnlyList<DispatcherEntryRelocation> relocations,
        IDispatcherBodyTransaction transaction)
    {
        foreach (var relocation in relocations)
        {
            var entry = new Local(method.Module.CorLibTypes.Int32);
            method.Body.Variables.Add(entry);

            // The head keeps its place and becomes the load, with the key moved behind it, so the
            // jumps into the dispatcher still land on its first instruction.
            transaction.Capture(relocation.Head);
            var key = new Instruction(relocation.Head.OpCode, relocation.Head.Operand);
            relocation.Head.OpCode = OpCodes.Ldloc;
            relocation.Head.Operand = entry;
            var head = method.Body.Instructions.IndexOf(relocation.Head);
            method.Body.Instructions.Insert(head + 1, key);
            if (relocation.FallsThrough)
                method.Body.Instructions.Insert(head, OpCodes.Stloc.ToInstruction(entry));

            foreach (var branch in relocation.Branches)
            {
                // Same reasoning as the head: something may jump to the branch itself, and would
                // step over a store placed in front of it.
                transaction.Capture(branch);
                var jump = new Instruction(OpCodes.Br, relocation.Head);
                branch.OpCode = OpCodes.Stloc;
                branch.Operand = entry;
                method.Body.Instructions.Insert(method.Body.Instructions.IndexOf(branch) + 1, jump);
            }
        }
    }

    private static void Apply(
        MethodDef method,
        IReadOnlyList<DispatcherEdgeRedirect> rewrites,
        IReadOnlyList<DispatcherEntryRelocation> relocations,
        IDispatcherBodyTransaction transaction)
    {
        Relocate(method, relocations, transaction);
        foreach (var rewrite in rewrites)
        {
            foreach (var removed in rewrite.RemovedInstructions)
            {
                transaction.Capture(removed);
                removed.OpCode = OpCodes.Nop;
                removed.Operand = null;
            }
            transaction.Capture(rewrite.Branch);
            if (rewrite.RestoredStateLocal is not { } state)
            {
                rewrite.Branch.OpCode = OpCodes.Br;
                rewrite.Branch.Operand = rewrite.Target;
                continue;
            }

            // The edge takes over the assignment the bypassed dispatcher would have made. The
            // ingress instruction itself becomes that assignment and the jump is appended behind
            // it, rather than the assignment being put in front: anything that jumped to this edge
            // targets the ingress instruction, and would step over an assignment placed before it.
            // The erased arithmetic left the state on the stack for the dispatcher to pop, where
            // this leaves nothing, which is what lets the dispatcher be skipped.
            rewrite.Branch.OpCode = OpCodes.Ldc_I4;
            rewrite.Branch.Operand = rewrite.State;
            var at = method.Body.Instructions.IndexOf(rewrite.Branch) + 1;
            method.Body.Instructions.Insert(at, OpCodes.Stloc.ToInstruction(state));
            method.Body.Instructions.Insert(at + 1, OpCodes.Br.ToInstruction(rewrite.Target));
        }

        Prune(method, transaction);
        method.Body.UpdateInstructionOffsets();
    }

    /// <summary>
    /// Neuters the scaffolding the redirects stranded, which is the dispatcher's own housekeeping
    /// once nothing reaches it any more.
    /// </summary>
    /// <remarks>
    /// This is not tidying. A fragment that only consumed what an edge pushed still consumes it
    /// where it stands, and unreachable code is checked against an empty stack, so leaving it is
    /// what makes the method unverifiable even though no path can run it.
    /// </remarks>
    private static void Prune(MethodDef method, IDispatcherBodyTransaction transaction)
    {
        var instructions = method.Body.Instructions;
        var reachable = new HashSet<Instruction>();
        var work = new Stack<Instruction>();
        void Reach(Instruction? instruction)
        {
            if (instruction is not null && reachable.Add(instruction))
                work.Push(instruction);
        }

        Reach(instructions.FirstOrDefault());
        foreach (var handler in method.Body.ExceptionHandlers)
        {
            Reach(handler.HandlerStart);
            Reach(handler.FilterStart);
        }

        var indexOf = new Dictionary<Instruction, int>();
        for (var index = 0; index < instructions.Count; index++)
            indexOf[instructions[index]] = index;
        while (work.Count != 0)
        {
            var instruction = work.Pop();
            if (instruction.Operand is Instruction single)
                Reach(single);
            else if (instruction.Operand is IList<Instruction> many)
                foreach (var target in many)
                    Reach(target);
            if (instruction.OpCode.FlowControl is FlowControl.Branch or FlowControl.Return
                or FlowControl.Throw)
            {
                continue;
            }

            if (indexOf[instruction] + 1 < instructions.Count)
                Reach(instructions[indexOf[instruction] + 1]);
        }

        foreach (var instruction in instructions)
        {
            if (reachable.Contains(instruction) || instruction.OpCode.Code == Code.Nop)
                continue;
            transaction.Capture(instruction);
            instruction.OpCode = OpCodes.Nop;
            instruction.Operand = null;
        }
    }
}
