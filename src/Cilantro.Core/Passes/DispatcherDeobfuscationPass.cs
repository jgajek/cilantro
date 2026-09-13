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
public class DispatcherDeobfuscationPass : DeobfuscationPass
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

    /// <summary>
    /// Whether to finish each method the rewrite changed by folding the branches the redirects have
    /// just made constant and deleting what nothing reaches any more.
    /// </summary>
    /// <remarks>
    /// Off for the early run, which is followed by the passes that do this to the whole module
    /// anyway. On for a run placed after them, where a redirected method would otherwise keep the
    /// dispatcher scaffolding the redirect stranded and read no better for having been rewritten.
    /// </remarks>
    protected virtual bool CompletesControlFlow => false;

    /// <summary>
    /// How many times to look for dispatchers before stopping, each round starting from whatever
    /// the one before it left.
    /// </summary>
    /// <remarks>
    /// A single round does not find everything there is to find, because redirecting an edge is
    /// itself one of the things that makes a dispatcher recognizable. The shape looked for is a
    /// block holding nothing but the state read and the switch, entered from blocks that do nothing
    /// after assigning the state but jump to it. Every redirect erases the arithmetic behind an
    /// assignment, and the fold that follows deletes what nothing reaches any more; both leave
    /// blocks shorter than they were, so a block that stood one instruction too long to match now
    /// matches.
    ///
    /// This is not a small remainder. On three real modules the run that reported itself finished
    /// left thirty-two, twenty-one and twenty-six edges standing that the same analyzer proves on
    /// the very next pass over the same IL, with nothing having changed in between but what the run
    /// itself did. Those are the entry edges of methods whose dispatchers would otherwise survive
    /// whole, which is the difference between a method that reads as code and one that reads as a
    /// switch over a state variable.
    /// </remarks>
    protected virtual int Rounds => 1;

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

        var wasUnnameable = ForwardScan.Unnameable(method);
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
            if (ForwardScan.Unnameable(method) > wasUnnameable)
            {
                transaction.Rollback();
                return new DispatcherMethodRewriteResult(
                    DispatcherQualification.Ambiguous,
                    0,
                    [Stranded]);
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
        ArgumentNullException.ThrowIfNull(context);
        var said = new List<string>();
        var total = 0;
        var later = 0;
        var rounds = 0;
        for (var round = 0; round < Math.Max(1, Rounds); round++)
        {
            var (status, changes, diagnostics) = ExecuteRound(context);
            if (status == PassStatus.Failed)
            {
                said.AddRange(diagnostics);
                return (status, total, said);
            }

            // The first round's account is the one worth keeping whole. The rounds after it repeat
            // its shape over a remainder, and reporting each of them in full would bury it.
            if (round == 0)
                said.AddRange(diagnostics);
            else
                later += changes;

            total += changes;
            rounds = round + 1;
            if (changes == 0)
                break;
        }

        if (later > 0)
        {
            said.Add(
                $"Asked again until a round found nothing: {later} further edge(s) over " +
                $"{rounds - 1} more round(s), each one made provable by the redirects and folds of " +
                "the round before it.");
        }

        return (PassStatus.Success, total, said);
    }

    private (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) ExecuteRound(
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

        var partial = PlanPartial(context, methods, qualified, diagnostics);
        planned.AddRange(partial.Planned);

        var confuserEx = PlanConfuserEx(context, methods, qualified, diagnostics);
        planned.AddRange(confuserEx.Planned);

        var active = new List<(MethodDef Method, IReadOnlyList<DispatcherEdgeRedirect> Edges,
            IDispatcherBodyTransaction Transaction)>();
        var stranded = new List<IDispatcherBodyTransaction>();

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

                var wasUnnameable = ForwardScan.Unnameable(item.Method);
                var transaction = transactions.Begin(item.Method);
                active.Add((item.Method, item.Edges, transaction));
                Apply(item.Method, item.Edges, item.Relocations, transaction);
                ControlFlowGraph.Build(item.Method);
                if (!EvaluationStackAnalyzer.Analyze(item.Method).Valid)
                    throw new InvalidOperationException(
                        $"{item.Method.FullName}: post-rewrite stack analysis failed.");

                // Declining one method, rather than failing the round: the other methods planned
                // beside it are unaffected by what this one's dispatcher is entered holding.
                if (ForwardScan.Unnameable(item.Method) > wasUnnameable)
                {
                    transaction.Rollback();
                    active.RemoveAt(active.Count - 1);
                    stranded.Add(transaction);
                    diagnostics.Add($"{item.Method.FullName}: {Stranded}");
                }
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
            foreach (var transaction in stranded)
                transaction.Dispose();
        }

        var rewritten = active.Select(item => item.Method).ToHashSet();
        var preserved = candidates.Where(item => !rewritten.Contains(item.Method)).ToArray();
        if (preserved.Length != 0)
        {
            diagnostics.Add($"Preserved {preserved.Length} ambiguous dispatcher-like methods.");
            // Same reasoning as the ConfuserEx declines below: a count with no reason reads as an
            // unexplained shortfall, where the reasons are what would have to change to go further.
            foreach (var (reason, count) in Tally(preserved))
                diagnostics.Add($"{count} of them: {reason}");
        }

        var edges = active.Sum(item => item.Edges.Count);
        diagnostics.Add($"Rewrote {active.Count} methods using {edges} edges.");
        Complete(context, active.Select(item => item.Method), diagnostics);

        // The rewrite runs more than once in a pipeline, before and after the passes that strip the
        // junk hiding a dispatcher, so what it reports is the union over the runs rather than the
        // last run's view. Methods are counted by token for that reason: a method both runs saw is
        // one candidate, not two. Edges are summed instead, each being redirected at most once.
        // Both flatteners count towards what was found, so a ConfuserEx run reports the same way a
        // Reactor one does rather than reporting nothing.
        var seenCandidates = Union(
            context,
            "cfg.dispatcherCandidateTokens",
            candidates.Select(item => item.Method.MDToken.Raw)
                .Concat(partial.Candidates)
                .Concat(confuserEx.Candidates));
        var seenRewritten = Union(
            context,
            "cfg.dispatcherRewrittenTokens",
            active.Select(item => item.Method.MDToken.Raw));
        var seenQualified = Union(
            context,
            "cfg.dispatcherQualifiedTokens",
            qualified.Select(item => item.Method.MDToken.Raw));

        context.SetFact("cfg.dispatcherEdgesRedirected", Add(context, "cfg.dispatcherEdgesRedirected", edges));
        context.SetFact("cfg.dispatcherMethodsRewritten", seenRewritten.Count);
        context.SetFact("cfg.dispatcherCandidates", seenCandidates.Count);
        context.SetFact("cfg.dispatcherQualified", seenQualified.Count);
        context.SetFact("cfg.dispatcherAmbiguous", seenCandidates.Except(seenRewritten).Count());
        return (PassStatus.Success, edges, diagnostics);
    }

    /// <summary>
    /// Folds what the redirects made constant in the methods they changed. A redirect leaves the
    /// dispatcher it bypassed standing, and the arithmetic feeding it unreachable, so a method is
    /// only as readable as this makes it.
    /// </summary>
    private void Complete(
        ArtifactContext context,
        IEnumerable<MethodDef> rewritten,
        List<string> diagnostics)
    {
        if (!CompletesControlFlow)
            return;
        var folded = 0;
        var removed = 0;
        var methods = 0;
        foreach (var method in rewritten)
        {
            if (ControlFlowCompletionPass.TryComplete(method) is not { } outcome ||
                (outcome.Folded == 0 && outcome.Removed == 0))
            {
                continue;
            }

            folded += outcome.Folded;
            removed += outcome.Removed;
            methods++;
            context.AddChange(new ChangeRecord(
                Name,
                "complete-control-flow",
                $"{method.MDToken} {method.FullName}",
                $"Folded {outcome.Folded} constant branch(es) and removed {outcome.Removed} " +
                "unreachable instruction(s) left by the redirects."));
        }

        if (methods == 0)
            return;
        // Added to, not assigned: this runs once per round, and each round folds what the round
        // before it made foldable.
        context.SetFact(
            "cfg.recheckConstantBranchesFolded", Add(context, "cfg.recheckConstantBranchesFolded", folded));
        context.SetFact(
            "cfg.recheckInstructionsRemoved", Add(context, "cfg.recheckInstructionsRemoved", removed));
        diagnostics.Add(
            $"Folded {folded} branch(es) the redirects made constant and removed {removed} " +
            $"instruction(s) nothing reaches, across {methods} of those methods.");
    }

    /// <summary>Adds this run's methods to the ones earlier runs of the rewrite saw.</summary>
    private static HashSet<uint> Union(
        ArtifactContext context,
        string key,
        IEnumerable<uint> tokens)
    {
        var seen = context.TryGetFact<IReadOnlySet<uint>>(key, out var earlier) && earlier is not null
            ? new HashSet<uint>(earlier)
            : [];
        seen.UnionWith(tokens);
        context.SetFact<IReadOnlySet<uint>>(key, seen);
        return seen;
    }

    private static int Add(ArtifactContext context, string key, int value) =>
        (context.TryGetFact<int>(key, out var earlier) ? earlier : 0) + value;

    /// <summary>
    /// Takes what can be taken from the methods the whole-method proof could not close, proving the
    /// edges into their dispatchers one at a time. See
    /// <see cref="DispatcherAnalyzer.AnalyzePartial"/> for why an edge needs so much less proof than
    /// a method.
    /// </summary>
    private (List<(MethodDef Method, IReadOnlyList<DispatcherEdgeRedirect> Edges,
        IReadOnlyList<DispatcherEntryRelocation> Relocations)> Planned,
        IReadOnlyList<uint> Candidates) PlanPartial(
            ArtifactContext context,
            IReadOnlyList<MethodDef> methods,
            IReadOnlyList<(MethodDef Method, DispatcherAnalysisResult Analysis)> qualified,
            List<string> diagnostics)
    {
        var planned = new List<(MethodDef, IReadOnlyList<DispatcherEdgeRedirect>,
            IReadOnlyList<DispatcherEntryRelocation>)>();
        var skip = qualified.Select(item => item.Method).ToHashSet();
        var declines = new Dictionary<DispatcherEdgeDecline, int>();
        var seen = new List<uint>();
        var changed = new List<uint>();
        var rewritten = 0;
        var residual = 0;
        var whole = 0;
        foreach (var method in methods.Where(method => !skip.Contains(method)))
        {
            var result = analyzer.AnalyzePartial(method);
            if (result.Qualification == DispatcherQualification.NotCandidate)
                continue;
            seen.Add(method.MDToken.Raw);
            if (result.Plan is { } counted)
            {
                foreach (var (decline, count) in counted.Declines)
                    declines[decline] = declines.GetValueOrDefault(decline) + count;
            }

            if (!result.IsQualified)
                continue;
            rewritten++;
            changed.Add(method.MDToken.Raw);
            residual += result.Plan!.ResidualEdges;
            if (result.Plan.ResidualEdges == 0)
                whole++;
            planned.Add((method, result.Plan.Rewrites, []));
        }

        if (rewritten == 0)
            return (planned, seen);

        var resolved = planned.Sum(item => item.Item2.Count);
        diagnostics.Add(
            $"Edge by edge: made {resolved} of {resolved + residual} dispatcher jump(s) direct " +
            $"across {rewritten} method(s) no whole-method proof closed, {whole} of them completely.");
        // Counted by token, because the rewrite is asked in rounds and a method a later round
        // reaches again is one method, not two. The residual is the last round's on purpose: it is
        // what is still standing, not a total of what was standing at each attempt.
        context.SetFact(
            "cfg.partialDispatcherMethods",
            Union(context, "cfg.partialDispatcherMethodTokens", changed).Count);
        context.SetFact("cfg.partialDispatcherResidualEdges", residual);
        foreach (var (decline, count) in declines.OrderByDescending(entry => entry.Value))
            diagnostics.Add($"{count} jump(s) left going through a dispatcher: {Explain(decline)}");
        return (planned, seen);
    }

    private static string Explain(DispatcherEdgeDecline decline) => decline switch
    {
        DispatcherEdgeDecline.UntailedAssignment =>
            "the state is assigned somewhere other than immediately before the jump, so the value " +
            "arriving at the dispatcher is not the one the block computed",
        DispatcherEdgeDecline.UnprovenExpression =>
            "what the state was assigned did not reduce to a single constant",
        DispatcherEdgeDecline.StateOutsideRange =>
            "the constant selects no case the switch declares",
        DispatcherEdgeDecline.ExceptionRegion =>
            "a direct jump would enter or leave a try, filter or handler",
        DispatcherEdgeDecline.RepeatedAssignment =>
            "the block assigns the state more than once, so no one value leaves it",
        _ => decline.ToString()
    };

    /// <summary>
    /// Groups the preserved methods by what stopped each of them, with the offset each reason was
    /// reported at dropped so that the same obstacle in different methods counts as one reason.
    /// </summary>
    private static IEnumerable<(string Reason, int Count)> Tally(
        IEnumerable<(MethodDef Method, DispatcherAnalysisResult Analysis)> preserved)
    {
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var item in preserved)
        {
            foreach (var reason in item.Analysis.Diagnostics.Select(Strip).Distinct(
                         StringComparer.Ordinal))
            {
                counts[reason] = counts.GetValueOrDefault(reason) + 1;
            }
        }

        return counts
            .OrderByDescending(entry => entry.Value)
            .ThenBy(entry => entry.Key, StringComparer.Ordinal)
            .Select(entry => (entry.Key, entry.Value));
    }

    private static string Strip(string diagnostic)
    {
        var separator = diagnostic.IndexOf(": ", StringComparison.Ordinal);
        return separator > 0 && diagnostic.StartsWith("IL_", StringComparison.Ordinal)
            ? diagnostic[(separator + 2)..]
            : diagnostic;
    }

    /// <summary>
    /// ConfuserEx's flattener threads its state through the evaluation stack and derives the case
    /// from a remainder, which is a different shape from the local-state dispatchers
    /// <see cref="DispatcherAnalyzer"/> proves, so it gets its own analyzer and the same rewrite.
    /// </summary>
    private (List<(MethodDef Method, IReadOnlyList<DispatcherEdgeRedirect> Edges,
        IReadOnlyList<DispatcherEntryRelocation> Relocations)> Planned, int Residual,
        IReadOnlyList<uint> Candidates)
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
            return (planned, 0, []);
        }

        var skip = alreadyPlanned.Select(item => item.Method).ToHashSet();
        var flattened = 0;
        var whole = 0;
        var declined = 0;
        var residual = 0;
        var dispatchers = 0;
        var stored = 0;
        var declines = new Dictionary<ConfuserExEdgeDecline, int>();
        var seen = new List<uint>();
        foreach (var method in methods.Where(method => !skip.Contains(method)))
        {
            var result = confuserExAnalyzer.Analyze(method);
            if (result.Qualification == DispatcherQualification.NotCandidate)
                continue;
            seen.Add(method.MDToken.Raw);
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
            return (planned, 0, seen);

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
        return (planned, residual, seen);
    }

    /// <summary>
    /// Why a method whose edges all check out is still left as it was.
    /// </summary>
    /// <remarks>
    /// Redirecting an edge takes away a way into the dispatcher, and the one it takes away is the
    /// one above it. Where the edges left behind are the ones that hand the state over on the
    /// evaluation stack, the dispatcher is afterwards reached only from below with a value pushed,
    /// which no single forward pass through the instructions can account for (ECMA-335 III.1.7.5).
    /// The rewrite is correct instruction by instruction and the paths still agree on every depth;
    /// what it loses is the fall-in that told a verifier what the depth was.
    /// </remarks>
    private const string Stranded =
        "redirecting its edges would leave the dispatcher reached only from below it with the " +
        "state still on the stack, which a single forward scan cannot account for; preserved.";

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

/// <summary>
/// The same rewrite again, at the end of the run, once every pass that takes something out of a
/// method body has taken it.
/// </summary>
/// <remarks>
/// A dispatcher is recognized by its shape: a block that does nothing but read a state variable and
/// switch on it, entered from blocks that do nothing after assigning that state but jump to it.
/// Reactor does not emit that shape, and neither does the module in the middle of a run. The block
/// holding the switch also holds a call to a proxy that has not been redirected yet, or a resolver
/// call where a string will be; the blocks assigning the state carry the same between the
/// assignment and the jump. Every one of those makes the block hold more than the shape allows.
///
/// So the early run sees almost nothing. On one real payload it found 44 candidates where the
/// cleaned copy of that module has over 900 dispatchers standing in plain sight, and on another it
/// found 27 against 663. What closes the gap is not a weaker proof but a later one: proxy
/// redirection, string recovery, token recovery and loader elision each remove an instruction from
/// the middle of these blocks, and none of them can run first, because what they need is recovered
/// by the passes ahead of them.
///
/// The rewrite is therefore asked twice rather than moved. The early run stays where it is, being
/// early enough to simplify what the passes after it have to read; this one runs last, where the
/// shape it looks for is finally the shape the module has, and finishes each method it changes
/// rather than leaving the bypassed dispatcher standing in it.
/// </remarks>
public sealed class DispatcherRecheckPass : DispatcherDeobfuscationPass
{
    public override string Name => "dispatcher-recheck";

    public override IReadOnlyCollection<string> Dependencies => ["rebuilt-body-cleanup"];

    protected override bool CompletesControlFlow => true;

    /// <summary>
    /// Asked until a round finds nothing, which on real modules is three or four rounds. The bound
    /// is a stop, not an expectation: rounds are cheap once there is nothing left to prove, the
    /// analysis being the same walk either way, and the loop leaves as soon as one comes back
    /// empty.
    /// </summary>
    /// <remarks>
    /// Only the late run iterates. The early one is followed by the whole-module control-flow
    /// passes and then by this, so anything its own redirects make newly provable is picked up
    /// here anyway, and rounds there would cost a walk of every method to reach the same place.
    /// </remarks>
    protected override int Rounds => 8;
}
