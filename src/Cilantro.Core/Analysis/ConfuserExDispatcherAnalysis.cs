using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Text;

namespace Cilantro.Core.Analysis;

public sealed record ConfuserExDispatcherOptions(
    int MaximumInstructions = 40_000,
    int MaximumSteps = 1_000_000,
    int MaximumStackDepth = 128,
    int MaximumExpressionLength = 32);

/// <summary>Why one dispatcher edge was left going through its switch.</summary>
public enum ConfuserExEdgeDecline
{
    /// <summary>
    /// Reached with two states, and so was the last instruction on the way to push one, which is
    /// what two states meeting before either is finished looks like.
    /// </summary>
    SharedFragment,

    /// <summary>The state was not a contiguous run of erasable integer instructions.</summary>
    UnremovableExpression,

    /// <summary>A direct jump would enter or leave a try, filter or handler.</summary>
    ExceptionRegion,

    /// <summary>Two states chose the same case, so no single state can be assigned.</summary>
    VaryingState,

    /// <summary>The dispatcher they enter cannot be made reachable with an empty stack.</summary>
    DispatcherEntry
}

/// <param name="Edges">
/// How many edges were up for redirection. This is not the number of jumps into a dispatcher: where
/// paths merge before one, the merge is one jump but each path into it is its own edge, and it is
/// the paths that get redirected.
/// </param>
public sealed record ConfuserExDispatcherPlan(
    MethodDef Method,
    int Dispatchers,
    int Edges,
    IReadOnlyList<DispatcherEdgeRedirect> Rewrites,
    IReadOnlyDictionary<ConfuserExEdgeDecline, int> Declines,
    IReadOnlyList<DispatcherEntryRelocation> Relocations)
{
    /// <summary>Edges the solver saw but could not reduce to one target.</summary>
    public int ResidualEdges => Edges - Rewrites.Count;
}

public sealed record ConfuserExDispatcherResult(
    DispatcherQualification Qualification,
    ConfuserExDispatcherPlan? Plan,
    IReadOnlyList<string> Diagnostics)
{
    public bool IsQualified =>
        Qualification == DispatcherQualification.Qualified && Plan is { Rewrites.Count: > 0 };
}

/// <summary>
/// Recognizes ConfuserEx's switch flattener, whose dispatcher takes the next state from the
/// evaluation stack, mixes it with a per-dispatcher key and indexes its cases by the remainder:
/// <c>ldc.i4 key; xor; dup; stloc state; ldc.i4 n; rem.un; switch</c>.
/// </summary>
/// <remarks>
/// The state is always integer arithmetic over constants and the state itself, so it can be
/// resolved by abstract interpretation rather than execution. An edge is only rewritten when every
/// reachable path through the instruction that reaches a dispatcher agrees on one case, which
/// requires the whole reachable state space to have been enumerated; running out of budget
/// therefore abandons the method rather than rewriting part of it.
///
/// Edges are otherwise independent, because a redirect carries everything the dispatcher would have
/// done. Besides jumping, the dispatcher stores the state in its variable, so where an instruction
/// still reads that variable the redirect assigns it — making the rewrite an exact substitution for
/// the path it replaces rather than something whose safety depends on the other edges. A method
/// with one unprovable edge therefore still gets the rest of its edges straightened, and the
/// dispatcher stays for what is left. See <see cref="Settle"/> for the two cases.
/// </remarks>
public sealed class ConfuserExDispatcherAnalyzer
{
    private readonly ConfuserExDispatcherOptions options;

    public ConfuserExDispatcherAnalyzer(ConfuserExDispatcherOptions? options = null)
    {
        this.options = options ?? new ConfuserExDispatcherOptions();
    }

    public ConfuserExDispatcherResult Analyze(MethodDef method)
    {
        ArgumentNullException.ThrowIfNull(method);
        if (!method.HasBody || method.Body.Instructions.Count == 0)
            return NotCandidate("Method has no CIL body.");
        if (method.Body.Instructions.Count > options.MaximumInstructions)
            return Ambiguous($"Method exceeds the {options.MaximumInstructions} instruction limit.");

        var sites = FindDispatchers(method);
        if (sites.Count == 0)
            return NotCandidate("Method contains no ConfuserEx switch dispatcher.");

        var stateLocals = sites.Select(site => site.State).Distinct().ToArray();
        if (method.Body.Instructions.Any(instruction =>
                instruction.OpCode.Code is Code.Ldloca or Code.Ldloca_S &&
                instruction.GetLocal(method.Body.Variables) is { } local &&
                stateLocals.Contains(local)))
            return Ambiguous("A dispatcher state local has its address taken.");

        ControlFlowGraph graph;
        try
        {
            graph = ControlFlowGraph.Build(method);
        }
        catch (Exception ex)
        {
            return Ambiguous($"CFG construction failed: {ex.Message}");
        }

        var solver = new Solver(method, sites, stateLocals, options);
        if (!solver.TrySolve(out var failure))
            return Ambiguous(failure!);

        var candidates = new List<DispatcherEdgeRedirect>();
        var varying = new HashSet<Instruction>();
        var ledger = new DeclineLedger();
        var targets = BranchTargets(method);
        var indexOf = new Dictionary<Instruction, int>();
        for (var index = 0; index < method.Body.Instructions.Count; index++)
            indexOf[method.Body.Instructions[index]] = index;

        // Returns the reason the edge cannot be redirected, or null once it has been offered.
        (ConfuserExEdgeDecline Decline, string Reason)? Offer(Instruction ingress, Observation observation)
        {
            if (observation.Ambiguous || observation.Targets.Count != 1 || observation.Surplus is null)
            {
                return (ConfuserExEdgeDecline.SharedFragment,
                    $"IL_{ingress.Offset:X4}: reached with more than one state.");
            }

            var target = observation.Targets.Single();
            if (!TryExtractStateExpression(
                    method, graph, targets, indexOf, ingress, observation.Surplus.Value, out var removed))
            {
                return (ConfuserExEdgeDecline.UnremovableExpression,
                    $"IL_{ingress.Offset:X4}: the state is not a removable integer expression.");
            }

            if (!graph.HaveIdenticalExceptionRegions(ingress, target))
            {
                return (ConfuserExEdgeDecline.ExceptionRegion,
                    $"IL_{ingress.Offset:X4}: the direct target crosses an exception region.");
            }

            // The arithmetic sits before the ingress, so only what falls into it computes the state;
            // anything that jumps to the ingress arrives with a state pushed somewhere else. Erasing
            // the run would leave those pushes with nothing to pop them, so the edge has to keep its
            // dispatcher even though the case it selects is settled.
            if (removed.Count != 0 && targets.Contains(ingress))
            {
                return (ConfuserExEdgeDecline.UnremovableExpression,
                    $"IL_{ingress.Offset:X4}: it is jumped to, so not everything reaching it runs " +
                    "the arithmetic that would be erased.");
            }

            if (observation.StateVaries)
                varying.Add(ingress);
            candidates.Add(new DispatcherEdgeRedirect(
                ingress,
                target,
                observation.State!.Value,
                removed,
                observation.StateLocal));
            return null;
        }

        var merges = new List<Instruction>();
        foreach (var (ingress, observation) in solver.Observations.OrderBy(pair => pair.Key.Offset))
        {
            if (Offer(ingress, observation) is not { } declined)
                continue;
            // Only a fragment with two states is worth taking apart; anything else is already as
            // fine-grained as the body gets.
            if (declined.Decline == ConfuserExEdgeDecline.SharedFragment)
                merges.Add(ingress);
            else
                ledger.Add(declined.Decline, declined.Reason);
        }

        // A fragment entered with two states is what a branch in the original program becomes once
        // flattened: each arm computes its own state and the arms merge before the dispatcher. The
        // merge is where the states disagree, while each arm on its own is definite, so attributing
        // the state to the arm sends both straight to their case and leaves the merge in place for
        // anything else still reaching it. An arm has to erase what the merge would have consumed on
        // its behalf too, which is what the surplus the solver recorded measures.
        var offered = new HashSet<Instruction>();
        foreach (var merge in merges)
        {
            if (!solver.Feeds.TryGetValue(merge, out var feeding))
            {
                ledger.Add(
                    ConfuserExEdgeDecline.SharedFragment,
                    $"IL_{merge.Offset:X4}: reached with more than one state, by paths that a direct " +
                    "jump from where the state was pushed would not reproduce.");
                continue;
            }

            foreach (var arm in feeding.OrderBy(instruction => instruction.Offset))
            {
                if (solver.Observations.ContainsKey(arm) || !offered.Add(arm))
                    continue;
                if (Offer(arm, solver.Arms[arm]) is { } armDeclined)
                    ledger.Add(armDeclined.Decline, armDeclined.Reason);
            }
        }

        // Each redirect writes through its own ingress instruction, so an ingress that another
        // edge's arithmetic covers would be overwritten by that edge's erasure and the two rewrites
        // would depend on which ran last. The regions do not overlap in practice, since they hold
        // no branches; this keeps the outcome defined if one ever does.
        var covered = candidates.SelectMany(rewrite => rewrite.RemovedInstructions).ToHashSet();
        for (var index = candidates.Count - 1; index >= 0; index--)
        {
            if (!covered.Contains(candidates[index].Branch))
                continue;
            ledger.Add(
                ConfuserExEdgeDecline.UnremovableExpression,
                $"IL_{candidates[index].Branch.Offset:X4}: another edge's arithmetic covers it.");
            candidates.RemoveAt(index);
        }

        // Redirecting the fragment that falls into a dispatcher is what leaves the jumps back to it
        // illegal, so an edge is only offered where the dispatcher it enters can be reached with an
        // empty stack instead. Deciding this before settling keeps the two independent: dropping an
        // edge here can only remove predecessors, which never makes another dispatcher harder.
        Block(method, sites, candidates, ledger);

        var rewrites = Settle(method, stateLocals, candidates, varying, ledger);
        var plan = new ConfuserExDispatcherPlan(
            method,
            sites.Count,
            rewrites.Count + ledger.Counts.Values.Sum(),
            rewrites,
            ledger.Counts,
            Relocate(method, sites, rewrites));
        if (rewrites.Count == 0)
            return new ConfuserExDispatcherResult(
                DispatcherQualification.Ambiguous,
                plan,
                ledger.Reasons.Count == 0 ? ["No dispatcher edge could be resolved."] : ledger.Reasons);

        var stored = rewrites.Count(rewrite => rewrite.RestoredStateLocal is not null);
        var summary = ledger.Reasons.Count == 0
            ? $"Resolved all {rewrites.Count} edge(s) across {sites.Count} dispatcher(s)."
            : $"Resolved {rewrites.Count} of {plan.Edges} edge(s) across {sites.Count} dispatcher(s).";
        if (stored != 0)
            summary += $" {stored} of them assign the state a surviving instruction still reads.";
        return new ConfuserExDispatcherResult(
            DispatcherQualification.Qualified,
            plan,
            [summary, .. ledger.Reasons.Take(3)]);
    }

    /// <summary>
    /// Drops the candidates that enter a dispatcher which cannot be given a variable to take its
    /// state from, since redirecting them would leave the jumps back to that dispatcher unverifiable.
    /// </summary>
    private static void Block(
        MethodDef method,
        IReadOnlyList<Site> sites,
        List<DispatcherEdgeRedirect> candidates,
        DeclineLedger ledger)
    {
        var redirected = candidates.Select(candidate => candidate.Branch).ToHashSet();
        var blocked = new HashSet<Instruction>();
        foreach (var site in sites)
        {
            var entry = Entry(method, site);
            if (!redirected.Overlaps(entry.Predecessors) || entry.Relocatable)
                continue;
            foreach (var predecessor in entry.Predecessors)
                blocked.Add(predecessor);
        }

        if (blocked.Count == 0)
            return;

        for (var index = candidates.Count - 1; index >= 0; index--)
        {
            if (!blocked.Contains(candidates[index].Branch))
                continue;
            ledger.Add(
                ConfuserExEdgeDecline.DispatcherEntry,
                $"IL_{candidates[index].Branch.Offset:X4}: the dispatcher it enters is also reached " +
                "in a way that cannot hand over the state in a variable.");
            candidates.RemoveAt(index);
        }
    }

    /// <summary>
    /// Describes how each dispatcher that a surviving redirect takes a predecessor away from has to
    /// be re-entered, which is the part of the rewrite the individual edges depend on.
    /// </summary>
    private static List<DispatcherEntryRelocation> Relocate(
        MethodDef method,
        IReadOnlyList<Site> sites,
        IReadOnlyList<DispatcherEdgeRedirect> rewrites)
    {
        var redirected = rewrites.Select(rewrite => rewrite.Branch).ToHashSet();
        var relocations = new List<DispatcherEntryRelocation>();
        foreach (var site in sites)
        {
            var entry = Entry(method, site);
            if (!redirected.Overlaps(entry.Predecessors))
                continue;
            relocations.Add(new DispatcherEntryRelocation(
                method.Body.Instructions[site.KeyIndex],
                site.Key,
                entry.Branches.Where(branch => !redirected.Contains(branch)).ToArray(),
                entry.FallsThrough is { } falls && !redirected.Contains(falls)));
        }

        return relocations;
    }

    /// <summary>
    /// Everything that hands control to a dispatcher, and whether a variable could carry the state
    /// on all of those paths. Only an unconditional branch and a fall-through leave somewhere to put
    /// the store; a conditional branch or a switch case would need a landing pad, which is more
    /// rewriting than the shape has ever called for, so it is treated as out of reach instead.
    /// </summary>
    private static (
        List<Instruction> Predecessors,
        List<Instruction> Branches,
        Instruction? FallsThrough,
        bool Relocatable) Entry(MethodDef method, Site site)
    {
        var instructions = method.Body.Instructions;
        var head = instructions[site.KeyIndex];
        var predecessors = new List<Instruction>();
        var branches = new List<Instruction>();
        var relocatable = true;
        foreach (var instruction in instructions)
        {
            if (instruction.Operand is Instruction single && ReferenceEquals(single, head))
            {
                predecessors.Add(instruction);
                if (instruction.OpCode.Code is Code.Br or Code.Br_S)
                    branches.Add(instruction);
                else
                    relocatable = false;
            }
            else if (instruction.Operand is Instruction[] many && many.Any(one =>
                         ReferenceEquals(one, head)))
            {
                predecessors.Add(instruction);
                relocatable = false;
            }
        }

        // Moving the key behind a load of the variable would move a region boundary with it.
        if (method.Body.ExceptionHandlers.Any(handler =>
                ReferenceEquals(handler.TryStart, head) || ReferenceEquals(handler.TryEnd, head) ||
                ReferenceEquals(handler.HandlerStart, head) ||
                ReferenceEquals(handler.HandlerEnd, head) ||
                ReferenceEquals(handler.FilterStart, head)))
        {
            relocatable = false;
        }

        var previous = site.KeyIndex > 0 ? instructions[site.KeyIndex - 1] : null;
        var falls = previous is not null && previous.OpCode.FlowControl is not
            (FlowControl.Branch or FlowControl.Return or FlowControl.Throw) ? previous : null;
        if (falls is not null)
            predecessors.Add(falls);
        return (predecessors, branches, falls, relocatable);
    }

    /// <summary>
    /// Collects the edges left alone, both as counted categories for the report and as sentences
    /// naming the instruction, since one example is worth more than a total when reading a run.
    /// </summary>
    private sealed class DeclineLedger
    {
        public Dictionary<ConfuserExEdgeDecline, int> Counts { get; } = [];

        public List<string> Reasons { get; } = [];

        public void Add(ConfuserExEdgeDecline decline, string reason)
        {
            Counts[decline] = Counts.GetValueOrDefault(decline) + 1;
            Reasons.Add(reason);
        }
    }

    /// <summary>
    /// Decides which of the resolvable edges to redirect, and which of them have to assign the
    /// dispatcher state on their way out.
    /// </summary>
    /// <remarks>
    /// Bypassing the dispatcher skips the one thing it does besides jumping, which is to store the
    /// state in its variable. Where nothing reads that variable afterwards the store is dead and the
    /// edges can simply be erased. Where something does read it, each redirected edge assigns the
    /// state itself, which makes it an exact substitution for the path it replaces and so keeps the
    /// edges independent of one another — a method with one unprovable edge still gets the rest.
    ///
    /// An edge whose visits agreed on the case but not on the state cannot assign one value, so it
    /// is given up rather than guessed at. Dropping it leaves its own arithmetic in place and its
    /// reads intact, which the remaining edges' assignments already account for.
    /// </remarks>
    private static List<DispatcherEdgeRedirect> Settle(
        MethodDef method,
        IReadOnlyList<Local> stateLocals,
        List<DispatcherEdgeRedirect> candidates,
        HashSet<Instruction> varying,
        DeclineLedger ledger)
    {
        if (candidates.Count == 0)
            return candidates;

        var erased = candidates.SelectMany(rewrite => rewrite.RemovedInstructions).ToHashSet();
        var read = method.Body.Instructions.FirstOrDefault(instruction =>
            GetLoadedLocal(method, instruction) is { } loaded &&
            stateLocals.Contains(loaded) &&
            !erased.Contains(instruction));
        if (read is null)
            return candidates.Select(rewrite => rewrite with { RestoredStateLocal = null }).ToList();

        var settled = new List<DispatcherEdgeRedirect>(candidates.Count);
        foreach (var rewrite in candidates)
        {
            if (varying.Contains(rewrite.Branch))
            {
                ledger.Add(
                    ConfuserExEdgeDecline.VaryingState,
                    $"IL_{rewrite.Branch.Offset:X4}: two states chose the same case, so there is no " +
                    $"one value to assign, and IL_{read.Offset:X4} still reads the state.");
                continue;
            }

            if (rewrite.RestoredStateLocal is null)
            {
                ledger.Add(
                    ConfuserExEdgeDecline.VaryingState,
                    $"IL_{rewrite.Branch.Offset:X4}: the dispatcher it enters was not identified, " +
                    "so the state it would assign is unknown.");
                continue;
            }

            settled.Add(rewrite);
        }

        return settled;
    }

    /// <summary>
    /// Whether the method still contains a recognizable dispatcher, without solving for its edges.
    /// Reporting how much flattening is left does not need the states, only the shape.
    /// </summary>
    public static bool HasDispatcherShape(MethodDef method)
    {
        ArgumentNullException.ThrowIfNull(method);
        return method.HasBody &&
            method.Body.Instructions.Count != 0 &&
            FindDispatchers(method).Count != 0;
    }

    private static ConfuserExDispatcherResult NotCandidate(string reason) =>
        new(DispatcherQualification.NotCandidate, null, [reason]);

    private static ConfuserExDispatcherResult Ambiguous(string reason) =>
        new(DispatcherQualification.Ambiguous, null, [reason]);

    private static List<Site> FindDispatchers(MethodDef method)
    {
        var instructions = method.Body.Instructions;
        var sites = new List<Site>();
        for (var index = 6; index < instructions.Count; index++)
        {
            if (instructions[index].OpCode.Code != Code.Switch ||
                instructions[index].Operand is not Instruction[] cases ||
                cases.Length == 0 ||
                instructions[index - 1].OpCode.Code != Code.Rem_Un ||
                !TryGetInt32(instructions[index - 2], out var modulus) ||
                modulus != cases.Length ||
                GetStoredLocal(method, instructions[index - 3]) is not { } state ||
                state.Type?.ElementType is not (ElementType.I4 or ElementType.U4) ||
                instructions[index - 4].OpCode.Code != Code.Dup ||
                instructions[index - 5].OpCode.Code != Code.Xor ||
                !TryGetInt32(instructions[index - 6], out var key))
            {
                continue;
            }

            sites.Add(new Site(index - 6, key, modulus, state, cases));
        }

        return sites;
    }

    /// <summary>
    /// Finds the contiguous, side-effect-free integer expression that leaves the dispatcher state
    /// on the stack, so that erasing it cannot change anything but the state.
    /// </summary>
    /// <param name="surplus">
    /// How many values the run has to account for. It is one where the edge hands the dispatcher its
    /// state, and more where the path merges into a fragment that consumes something on the way, all
    /// of which the direct jump skips.
    /// </param>
    private bool TryExtractStateExpression(
        MethodDef method,
        ControlFlowGraph graph,
        HashSet<Instruction> targets,
        Dictionary<Instruction, int> indexOf,
        Instruction ingress,
        int surplus,
        out IReadOnlyList<Instruction> removed)
    {
        removed = [];
        var instructions = method.Body.Instructions;
        if (!indexOf.TryGetValue(ingress, out var ingressIndex))
            return false;

        // A branch keeps its place and becomes the direct jump; a fall-through has no branch of its
        // own, so its last expression instruction is the one that becomes the jump.
        var isBranch = ingress.OpCode.FlowControl == FlowControl.Branch;
        var end = isBranch ? ingressIndex - 1 : ingressIndex;
        if (end < 0)
            return false;

        var delta = 0;
        var start = -1;
        for (var index = end; index >= 0 && end - index < options.MaximumExpressionLength; index--)
        {
            var instruction = instructions[index];
            if (!IsRemovableExpression(instruction))
                break;
            delta += StackDelta(instruction);
            if (delta > surplus)
                break;
            if (delta == surplus)
            {
                start = index;
                break;
            }

            // The run may begin on a jump destination, since that is what a fragment start looks
            // like, but extending back past one would leave something landing on the nops inside it.
            if (targets.Contains(instruction))
                break;
        }

        if (start < 0 || !graph.HaveIdenticalExceptionRegions(instructions[start], ingress))
            return false;

        var run = new List<Instruction>();
        for (var index = start; index <= end; index++)
        {
            if (!ReferenceEquals(instructions[index], ingress))
                run.Add(instructions[index]);
        }

        removed = run;
        return true;
    }

    private static HashSet<Instruction> BranchTargets(MethodDef method)
    {
        var targets = new HashSet<Instruction>();
        foreach (var instruction in method.Body.Instructions)
        {
            if (instruction.Operand is Instruction single)
                targets.Add(single);
            else if (instruction.Operand is Instruction[] many)
                foreach (var target in many)
                    targets.Add(target);
        }

        foreach (var handler in method.Body.ExceptionHandlers)
        {
            foreach (var boundary in new[]
                     {
                         handler.TryStart, handler.TryEnd, handler.HandlerStart,
                         handler.HandlerEnd, handler.FilterStart
                     })
            {
                if (boundary is not null)
                    targets.Add(boundary);
            }
        }

        return targets;
    }

    private static bool IsRemovableExpression(Instruction instruction) =>
        instruction.OpCode.Code switch
        {
            Code.Nop or Code.Dup or Code.Pop => true,
            Code.Neg or Code.Not or Code.Conv_I4 or Code.Conv_U4 => true,
            Code.Add or Code.Sub or Code.Mul or Code.Xor or Code.And or Code.Or => true,
            Code.Shl or Code.Shr or Code.Shr_Un => true,
            var code when code is >= Code.Ldc_I4_M1 and <= Code.Ldc_I4_8 => true,
            Code.Ldc_I4 or Code.Ldc_I4_S => true,
            Code.Ldloc or Code.Ldloc_S or Code.Ldloc_0 or Code.Ldloc_1 or Code.Ldloc_2
                or Code.Ldloc_3 => true,
            // Division can throw, so removing it is not the no-op the rest of this list is.
            _ => false
        };

    private static int StackDelta(Instruction instruction) =>
        instruction.OpCode.Code switch
        {
            Code.Nop => 0,
            Code.Dup => 1,
            Code.Pop => -1,
            Code.Neg or Code.Not or Code.Conv_I4 or Code.Conv_U4 => 0,
            Code.Add or Code.Sub or Code.Mul or Code.Xor or Code.And or Code.Or => -1,
            Code.Shl or Code.Shr or Code.Shr_Un => -1,
            _ => 1
        };

    internal static bool TryGetInt32(Instruction instruction, out int value)
    {
        var code = instruction.OpCode.Code;
        if (code is >= Code.Ldc_I4_M1 and <= Code.Ldc_I4_8)
        {
            value = code - Code.Ldc_I4_0;
            return true;
        }

        if (code is Code.Ldc_I4 or Code.Ldc_I4_S)
        {
            value = instruction.Operand switch
            {
                int direct => direct,
                sbyte tiny => tiny,
                _ => 0
            };
            return instruction.Operand is int or sbyte;
        }

        value = 0;
        return false;
    }

    // The short forms carry their local in the opcode rather than the operand, so the local always
    // has to come from dnlib's resolution against the body's variable list.
    internal static Local? GetStoredLocal(MethodDef method, Instruction instruction) =>
        instruction.OpCode.Code is Code.Stloc or Code.Stloc_S or Code.Stloc_0 or Code.Stloc_1
            or Code.Stloc_2 or Code.Stloc_3
            ? instruction.GetLocal(method.Body.Variables)
            : null;

    internal static Local? GetLoadedLocal(MethodDef method, Instruction instruction) =>
        instruction.OpCode.Code is Code.Ldloc or Code.Ldloc_S or Code.Ldloc_0 or Code.Ldloc_1
            or Code.Ldloc_2 or Code.Ldloc_3
            ? instruction.GetLocal(method.Body.Variables)
            : null;

    internal sealed record Site(
        int KeyIndex,
        int Key,
        int Modulus,
        Local State,
        Instruction[] Cases);

    internal sealed class Observation
    {
        public HashSet<Instruction> Targets { get; } = [];
        public int? State { get; set; }
        public bool Ambiguous { get; set; }

        /// <summary>The state variable of the dispatcher this edge was seen entering.</summary>
        public Local? StateLocal { get; set; }

        /// <summary>
        /// Whether two visits agreed on the case but not on the state that chose it, which the
        /// remainder makes possible. Erasing the arithmetic does not care, but assigning the state
        /// does, since there is then no single value to assign.
        /// </summary>
        public bool StateVaries { get; set; }

        /// <summary>
        /// How many values this edge has to stop pushing, being everything still on the stack after
        /// it that the dispatcher and anything between them would have consumed. It is one for an
        /// edge that hands the dispatcher its state directly, and more where the path merges into a
        /// fragment that consumes something on the way.
        /// </summary>
        public int? Surplus { get; set; }
    }

    /// <summary>
    /// Enumerates the reachable (instruction, stack, state) space, recording which case each
    /// instruction that hands control to a dispatcher selects.
    /// </summary>
    private sealed class Solver
    {
        private readonly MethodDef method;
        private readonly IList<Instruction> instructions;
        private readonly ConfuserExDispatcherOptions options;
        private readonly Dictionary<Instruction, int> indexOf = [];
        private readonly Dictionary<int, Site> siteByKeyIndex = [];
        private readonly Dictionary<Local, int> slotOf = [];
        private readonly Stack<Frame> work = new();
        private readonly HashSet<string> seen = [];
        private int steps;
        private int arm = -1;
        private int armDepth;

        public Solver(
            MethodDef method,
            IReadOnlyList<Site> sites,
            IReadOnlyList<Local> stateLocals,
            ConfuserExDispatcherOptions options)
        {
            this.method = method;
            this.options = options;
            instructions = method.Body.Instructions;
            for (var index = 0; index < instructions.Count; index++)
                indexOf[instructions[index]] = index;
            foreach (var site in sites)
                siteByKeyIndex[site.KeyIndex] = site;
            for (var slot = 0; slot < stateLocals.Count; slot++)
                slotOf[stateLocals[slot]] = slot;
        }

        public Dictionary<Instruction, Observation> Observations { get; } = [];

        /// <summary>
        /// The same observations, but attributed to the last instruction on the path that actually
        /// pushed the state rather than to whatever handed it to the dispatcher. The two differ only
        /// where paths merge before the dispatcher, which is where the coarser attribution is
        /// ambiguous and this one is not.
        /// </summary>
        public Dictionary<Instruction, Observation> Arms { get; } = [];

        /// <summary>Which arms were seen reaching each of the instructions in <see cref="Observations"/>.</summary>
        public Dictionary<Instruction, HashSet<Instruction>> Feeds { get; } = [];

        public bool TrySolve(out string? failure)
        {
            failure = null;
            work.Push(new Frame(0, [], new int?[slotOf.Count], -1, 0));
            foreach (var handler in method.Body.ExceptionHandlers)
            {
                var depth = handler.HandlerType is ExceptionHandlerType.Catch
                    or ExceptionHandlerType.Filter ? 1 : 0;
                Seed(handler.HandlerStart, depth);
                Seed(handler.FilterStart, 1);
            }

            while (work.Count > 0)
            {
                var frame = work.Pop();
                if (!seen.Add(frame.Key()))
                    continue;
                if (!Run(frame, out failure))
                    return false;
            }

            return true;
        }

        private void Seed(Instruction? instruction, int depth)
        {
            if (instruction is null || !indexOf.TryGetValue(instruction, out var index))
                return;
            var stack = new List<int?>();
            for (var slot = 0; slot < depth; slot++)
                stack.Add(null);
            work.Push(new Frame(index, stack, new int?[slotOf.Count], -1, 0));
        }

        private bool Run(Frame frame, out string? failure)
        {
            failure = null;
            var index = frame.Index;
            var stack = new List<int?>(frame.Stack);
            var state = (int?[])frame.State.Clone();
            var fellThrough = false;
            arm = frame.Arm;
            armDepth = frame.ArmDepth;

            while (true)
            {
                if (++steps > options.MaximumSteps)
                {
                    failure = "The reachable state space exceeded the analysis budget.";
                    return false;
                }

                if (index < 0 || index >= instructions.Count)
                    return true;
                if (stack.Count > options.MaximumStackDepth)
                {
                    failure = "The modelled evaluation stack grew past its limit.";
                    return false;
                }

                if (siteByKeyIndex.TryGetValue(index, out var site))
                {
                    // Only a fall-through can be attributed to the instruction before the key; a
                    // jump straight to it was already accounted for where the jump was taken.
                    var ingress = fellThrough && index > 0 ? instructions[index - 1] : null;
                    return EnterDispatcher(site, ingress, stack, state, out failure);
                }

                var instruction = instructions[index];
                switch (Step(instruction, stack, state, index, out failure))
                {
                    case Outcome.Failed:
                        return false;
                    case Outcome.Stopped:
                        return true;
                    case Outcome.Transferred:
                        return true;
                    case Outcome.Continued:
                    default:
                        // Whatever last put something on the stack is the arm; a fragment that only
                        // consumes is the merge the arms share, so it must not claim their state.
                        if (instruction.OpCode.Code is not (Code.Nop or Code.Pop))
                        {
                            arm = index;
                            armDepth = stack.Count;
                        }

                        index++;
                        fellThrough = true;
                        continue;
                }
            }
        }

        private bool EnterDispatcher(
            Site site,
            Instruction? ingress,
            List<int?> stack,
            int?[] state,
            out string? failure)
        {
            failure = null;
            if (stack.Count == 0)
            {
                failure = $"IL_{instructions[site.KeyIndex].Offset:X4}: the dispatcher was reached " +
                    "with nothing on the modelled stack.";
                return false;
            }

            var pushed = stack[^1];
            stack.RemoveAt(stack.Count - 1);
            var slot = slotOf[site.State];
            // How deep the stack is once the dispatcher has taken its state, which is what an edge
            // redirected past it has to leave behind.
            var settled = stack.Count;
            var reached = arm >= 0 ? instructions[arm] : null;
            if (ingress is not null && reached is not null)
            {
                if (!Feeds.TryGetValue(ingress, out var feeding))
                    Feeds[ingress] = feeding = [];
                feeding.Add(reached);
            }

            if (pushed is null)
            {
                if (ingress is not null)
                    Observe(Observations, ingress).Ambiguous = true;
                if (reached is not null)
                    Observe(Arms, reached).Ambiguous = true;
                state[slot] = null;
                foreach (var target in site.Cases)
                    Push(target, stack, state);
                return true;
            }

            var resolved = pushed.Value ^ site.Key;
            var selected = site.Cases[(int)((uint)resolved % (uint)site.Modulus)];
            state[slot] = resolved;
            if (ingress is not null)
                Record(Observe(Observations, ingress), site, selected, resolved, 1);
            if (reached is not null)
                Record(Observe(Arms, reached), site, selected, resolved, armDepth - settled);

            Push(selected, stack, state);
            return true;
        }

        private static void Record(
            Observation observation,
            Site site,
            Instruction selected,
            int resolved,
            int surplus)
        {
            observation.Targets.Add(selected);
            if (observation.State is { } already && already != resolved)
                observation.StateVaries = true;
            observation.State = resolved;
            // One instruction feeding two dispatchers would mean two state variables to keep
            // straight, and the case each chose could still coincide, so it is not caught by
            // counting targets.
            if (observation.StateLocal is { } other && other != site.State)
                observation.Ambiguous = true;
            observation.StateLocal = site.State;
            // Two paths through the same instruction that leave different amounts behind cannot both
            // be answered by erasing one run of instructions.
            if (surplus < 1 || (observation.Surplus is { } before && before != surplus))
                observation.Ambiguous = true;
            observation.Surplus = surplus;
        }

        private static Observation Observe(
            Dictionary<Instruction, Observation> observations,
            Instruction at)
        {
            if (observations.TryGetValue(at, out var existing))
                return existing;
            return observations[at] = new Observation();
        }

        private void Push(Instruction? target, List<int?> stack, int?[] state)
        {
            if (target is null || !indexOf.TryGetValue(target, out var index))
                return;
            work.Push(new Frame(index, new List<int?>(stack), (int?[])state.Clone(), arm, armDepth));
        }

        private Outcome Step(
            Instruction instruction,
            List<int?> stack,
            int?[] state,
            int index,
            out string? failure)
        {
            failure = null;
            var code = instruction.OpCode.Code;

            switch (code)
            {
                case Code.Nop:
                    return Outcome.Continued;
                case Code.Dup:
                    stack.Add(stack.Count > 0 ? stack[^1] : null);
                    return Outcome.Continued;
                case Code.Pop:
                    Pop(stack);
                    return Outcome.Continued;
                case Code.Ret:
                case Code.Throw:
                case Code.Rethrow:
                case Code.Endfinally:
                case Code.Endfilter:
                    return Outcome.Stopped;
                case Code.Leave:
                case Code.Leave_S:
                    Forget();
                    stack.Clear();
                    Push(instruction.Operand as Instruction, stack, state);
                    return Outcome.Transferred;
                case Code.Br:
                case Code.Br_S:
                    // A jump carries the arm with it, since it neither pushes nor consumes: that is
                    // what lets an arm be recognized across the fragments it passes through.
                    return Branch(instruction.Operand as Instruction, stack, state, instruction,
                        out failure);
                case Code.Switch:
                    Forget();
                    return SwitchStep(instruction, stack, state, index);
            }

            if (TryGetInt32(instruction, out var constant))
            {
                stack.Add(constant);
                return Outcome.Continued;
            }

            if (GetLoadedLocal(method, instruction) is { } loaded)
            {
                stack.Add(slotOf.TryGetValue(loaded, out var slot) ? state[slot] : null);
                return Outcome.Continued;
            }

            if (GetStoredLocal(method, instruction) is { } stored)
            {
                var value = Pop(stack);
                if (slotOf.TryGetValue(stored, out var slot))
                    state[slot] = value;
                return Outcome.Continued;
            }

            if (IsBinary(code))
            {
                var right = Pop(stack);
                var left = Pop(stack);
                stack.Add(Fold(code, left, right));
                return Outcome.Continued;
            }

            if (code is Code.Neg or Code.Not)
            {
                var operand = Pop(stack);
                stack.Add(operand is null
                    ? null
                    : code == Code.Neg ? unchecked(-operand.Value) : ~operand.Value);
                return Outcome.Continued;
            }

            if (code is Code.Conv_I4 or Code.Conv_U4)
                return Outcome.Continued;

            if (instruction.OpCode.FlowControl == FlowControl.Cond_Branch)
            {
                Forget();
                instruction.CalculateStackUsage(out _, out var popped);
                for (var count = 0; count < popped; count++)
                    Pop(stack);
                Push(instruction.Operand as Instruction, stack, state);
                if (index + 1 < instructions.Count)
                    Push(instructions[index + 1], stack, state);
                return Outcome.Transferred;
            }

            instruction.CalculateStackUsage(out var pushes, out var pops);
            if (pops < 0)
                stack.Clear();
            else
                for (var count = 0; count < pops; count++)
                    Pop(stack);
            for (var count = 0; count < pushes; count++)
                stack.Add(null);
            if (instruction.OpCode.FlowControl == FlowControl.Branch)
                Forget();
            return instruction.OpCode.FlowControl switch
            {
                FlowControl.Branch => Outcome.Transferred,
                FlowControl.Return or FlowControl.Throw => Outcome.Stopped,
                _ => Outcome.Continued
            };
        }

        /// <summary>
        /// Gives up on attributing the state to an arm, because control left in a way that a direct
        /// jump from the arm would not reproduce. Everything between an arm and the dispatcher is
        /// skipped when the arm is redirected, so it may only be jumps and stack housekeeping.
        /// </summary>
        private void Forget()
        {
            arm = -1;
            armDepth = 0;
        }

        private Outcome Branch(
            Instruction? target,
            List<int?> stack,
            int?[] state,
            Instruction branch,
            out string? failure)
        {
            failure = null;
            if (target is null || !indexOf.TryGetValue(target, out var targetIndex))
                return Outcome.Stopped;
            // A jump into a dispatcher is the edge a rewrite would redirect, so it is resolved here
            // rather than by stepping through the dispatcher.
            if (siteByKeyIndex.TryGetValue(targetIndex, out var site))
                return EnterDispatcher(site, branch, stack, state, out failure)
                    ? Outcome.Transferred
                    : Outcome.Failed;
            Push(target, stack, state);
            return Outcome.Transferred;
        }

        private Outcome SwitchStep(
            Instruction instruction,
            List<int?> stack,
            int?[] state,
            int index)
        {
            var cases = instruction.Operand as Instruction[] ?? [];
            var selector = Pop(stack);
            if (selector is { } value && value >= 0 && value < cases.Length)
            {
                Push(cases[value], stack, state);
                return Outcome.Transferred;
            }

            if (selector is not null)
            {
                if (index + 1 < instructions.Count)
                    Push(instructions[index + 1], stack, state);
                return Outcome.Transferred;
            }

            foreach (var target in cases)
                Push(target, stack, state);
            if (index + 1 < instructions.Count)
                Push(instructions[index + 1], stack, state);
            return Outcome.Transferred;
        }

        private static int? Pop(List<int?> stack)
        {
            if (stack.Count == 0)
                return null;
            var value = stack[^1];
            stack.RemoveAt(stack.Count - 1);
            return value;
        }

        private static bool IsBinary(Code code) =>
            code is Code.Add or Code.Sub or Code.Mul or Code.Xor or Code.And or Code.Or or
                Code.Shl or Code.Shr or Code.Shr_Un or Code.Div or Code.Div_Un or Code.Rem or
                Code.Rem_Un or Code.Add_Ovf or Code.Add_Ovf_Un or Code.Sub_Ovf or
                Code.Sub_Ovf_Un or Code.Mul_Ovf or Code.Mul_Ovf_Un;

        private static int? Fold(Code code, int? left, int? right)
        {
            if (left is null || right is null)
                return null;
            var a = left.Value;
            var b = right.Value;
            return code switch
            {
                Code.Add or Code.Add_Ovf or Code.Add_Ovf_Un => unchecked(a + b),
                Code.Sub or Code.Sub_Ovf or Code.Sub_Ovf_Un => unchecked(a - b),
                Code.Mul or Code.Mul_Ovf or Code.Mul_Ovf_Un => unchecked(a * b),
                Code.Xor => a ^ b,
                Code.And => a & b,
                Code.Or => a | b,
                Code.Shl => a << (b & 31),
                Code.Shr => a >> (b & 31),
                Code.Shr_Un => (int)((uint)a >> (b & 31)),
                Code.Div => b == 0 ? null : a / b,
                Code.Div_Un => b == 0 ? null : (int)((uint)a / (uint)b),
                Code.Rem => b == 0 ? null : a % b,
                Code.Rem_Un => b == 0 ? null : (int)((uint)a % (uint)b),
                _ => null
            };
        }

        private enum Outcome
        {
            Continued,
            Transferred,
            Stopped,
            Failed
        }

        // The arm is part of the identity of a path, not just baggage carried along it: two paths
        // that agree on everything else but reached here from different arms have to be walked
        // separately, or one arm's states would be recorded as if they were the whole story.
        private sealed record Frame(
            int Index,
            List<int?> Stack,
            int?[] State,
            int Arm,
            int ArmDepth)
        {
            public string Key()
            {
                var builder = new StringBuilder();
                Append(builder, Index);
                builder.Append('|');
                foreach (var value in Stack)
                    Append(builder, value);
                builder.Append('|');
                foreach (var value in State)
                    Append(builder, value);
                builder.Append('|');
                Append(builder, Arm);
                Append(builder, ArmDepth);
                return builder.ToString();
            }

            // Packed as raw chars rather than digits: the key is only ever compared with itself, and
            // formatting integers here would both cost more and depend on the current culture.
            private static void Append(StringBuilder builder, int? value)
            {
                if (value is null)
                {
                    builder.Append('\u0000');
                    return;
                }

                var bits = (uint)value.Value;
                builder.Append('\u0001')
                    .Append((char)(bits & 0xFFFF))
                    .Append((char)(bits >> 16));
            }
        }
    }
}
