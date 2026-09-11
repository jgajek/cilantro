using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

public enum DispatcherQualification
{
    NotCandidate,
    Ambiguous,
    Qualified
}

public sealed record DispatcherAnalysisOptions(
    int MaximumInstructions = 20_000,
    int MaximumExpressionNodes = 64,
    int MaximumHelperDepth = 3,
    int MaximumGraphVisits = 100_000);

public sealed record DispatcherEdgeRewrite(
    BasicBlock Source,
    Instruction Branch,
    Instruction Target,
    int State,
    IReadOnlyList<Instruction> RemovedInstructions);

/// <summary>
/// The shape a dispatcher rewrite reduces to, whichever analyzer proved it: erase the
/// instructions that computed the state, then send one instruction straight to the case the
/// state selected.
/// </summary>
/// <param name="RestoredStateLocal">
/// The state variable this edge has to assign on its way out, or <c>null</c> when nothing reads it.
/// Storing the state is what makes the redirect a local change: the dispatcher being bypassed is
/// what would have written that variable, so an edge that skips it and leaves the write undone is
/// only safe while no surviving instruction reads it. Naming the variable here lets the edge carry
/// the write itself instead, which is what allows edges to be redirected one at a time.
/// </param>
public sealed record DispatcherEdgeRedirect(
    Instruction Branch,
    Instruction Target,
    int State,
    IReadOnlyList<Instruction> RemovedInstructions,
    Local? RestoredStateLocal = null)
{
    public static DispatcherEdgeRedirect From(DispatcherEdgeRewrite rewrite)
    {
        ArgumentNullException.ThrowIfNull(rewrite);
        return new DispatcherEdgeRedirect(
            rewrite.Branch,
            rewrite.Target,
            rewrite.State,
            rewrite.RemovedInstructions);
    }
}

/// <summary>
/// How to move a dispatcher's incoming state off the evaluation stack and into a variable, so that
/// the dispatcher is entered with an empty stack from everywhere.
/// </summary>
/// <remarks>
/// ConfuserEx's dispatcher is entered with the next state pushed, so every jump into it is a branch
/// taken with something on the stack. CIL only permits that for a backward branch when a forward
/// path has already established the stack at the target (ECMA-335 III.1.7.5), and the forward path
/// is the single fragment that falls into the dispatcher rather than jumping to it. Redirecting that
/// fragment is what makes the remaining backward jumps illegal, so a method could stop verifying
/// after a partial rewrite even though each redirect was individually correct.
///
/// Passing the state in a variable removes the constraint instead of avoiding it: the dispatcher is
/// then entered empty from every edge, so no edge into it depends on another edge surviving.
/// </remarks>
/// <param name="Head">
/// The instruction the dispatcher is entered at, which loads its key. It becomes the load of the
/// variable, and the key moves behind it, so that everything already branching here still arrives
/// at the first instruction of the dispatcher.
/// </param>
/// <param name="Branches">
/// The unconditional branches into <paramref name="Head"/> that survive, each of which has to store
/// the state it computed before jumping.
/// </param>
/// <param name="FallsThrough">
/// Whether the fragment ahead of <paramref name="Head"/> still falls into it, and so needs the same
/// store placed between them.
/// </param>
public sealed record DispatcherEntryRelocation(
    Instruction Head,
    int Key,
    IReadOnlyList<Instruction> Branches,
    bool FallsThrough);

public sealed record DispatcherRewritePlan(
    MethodDef Method,
    Local StateLocal,
    BasicBlock Dispatcher,
    Instruction Switch,
    int InitialState,
    IReadOnlyList<DispatcherEdgeRewrite> Rewrites);

/// <summary>Why an individual edge into a dispatcher was left going through it.</summary>
public enum DispatcherEdgeDecline
{
    /// <summary>The assignment is not the last thing a block does before jumping away.</summary>
    UntailedAssignment,

    /// <summary>What the assignment stores could not be reduced to one constant.</summary>
    UnprovenExpression,

    /// <summary>The constant selects no case the switch declares.</summary>
    StateOutsideRange,

    /// <summary>A direct jump would enter or leave a try, filter or handler.</summary>
    ExceptionRegion,

    /// <summary>The block assigns the state more than once, so no one value leaves it.</summary>
    RepeatedAssignment
}

/// <summary>
/// The edges into a method's dispatchers that were proven one at a time, for a method the
/// whole-method proof in <see cref="DispatcherRewritePlan"/> could not close.
/// </summary>
/// <param name="Dispatchers">How many dispatchers in the method were looked at.</param>
/// <param name="Edges">How many edges into them were offered, proven or not.</param>
public sealed record DispatcherPartialPlan(
    MethodDef Method,
    int Dispatchers,
    int Edges,
    IReadOnlyList<DispatcherEdgeRedirect> Rewrites,
    IReadOnlyDictionary<DispatcherEdgeDecline, int> Declines)
{
    public int ResidualEdges => Edges - Rewrites.Count;
}

public sealed record DispatcherPartialResult(
    DispatcherQualification Qualification,
    DispatcherPartialPlan? Plan,
    IReadOnlyList<string> Diagnostics)
{
    public bool IsQualified =>
        Qualification == DispatcherQualification.Qualified && Plan is { Rewrites.Count: > 0 };
}

public sealed record DispatcherAnalysisResult(
    DispatcherQualification Qualification,
    DispatcherRewritePlan? Plan,
    IReadOnlyList<string> Diagnostics)
{
    public bool IsQualified => Qualification == DispatcherQualification.Qualified && Plan is not null;
}

/// <summary>
/// Recognizes only local-state switch flatteners for which every dispatcher ingress can be
/// replaced by a statically proven, same-EH-region direct branch.
/// </summary>
public sealed class DispatcherAnalyzer
{
    private readonly DispatcherAnalysisOptions options;

    public DispatcherAnalyzer(DispatcherAnalysisOptions? options = null)
    {
        this.options = options ?? new DispatcherAnalysisOptions();
    }

    public DispatcherAnalysisResult Analyze(MethodDef method)
    {
        ArgumentNullException.ThrowIfNull(method);
        if (!method.HasBody || method.Body.Instructions.Count == 0)
            return NotCandidate("Method has no CIL body.");
        if (method.Body.Instructions.Count > options.MaximumInstructions)
            return Ambiguous($"Method exceeds the {options.MaximumInstructions} instruction limit.");

        ControlFlowGraph graph;
        try
        {
            graph = ControlFlowGraph.Build(method);
        }
        catch (Exception ex)
        {
            return Ambiguous($"CFG construction failed: {ex.Message}");
        }

        var switches = method.Body.Instructions
            .Where(instruction => instruction.OpCode.Code == Code.Switch)
            .ToArray();
        if (switches.Length == 0)
            return NotCandidate("Method contains no switch.");
        var dispatcherLikeSwitches = switches.Where(switchInstruction =>
        {
            var meaningful = graph.BlockOf(switchInstruction).Instructions
                .Where(instruction => instruction.OpCode.Code != Code.Nop)
                .ToArray();
            return meaningful.Length == 2 &&
                   ReferenceEquals(meaningful[1], switchInstruction) &&
                   GetLoadedLocal(method, meaningful[0]) is not null;
        }).ToArray();
        if (dispatcherLikeSwitches.Length == 0)
            return NotCandidate("No switch block has the strict ldloc/switch shape.");

        var accepted = new List<DispatcherRewritePlan>();
        var rejected = new List<string>();
        foreach (var switchInstruction in dispatcherLikeSwitches)
        {
            if (TryQualify(method, graph, switchInstruction, out var plan, out var reason))
                accepted.Add(plan!);
            else
                rejected.Add($"IL_{switchInstruction.Offset:X4}: {reason}");
        }

        return accepted.Count switch
        {
            1 => new DispatcherAnalysisResult(
                DispatcherQualification.Qualified,
                accepted[0],
                ["Qualified one closed, local-state switch dispatcher."]),
            > 1 => Ambiguous("More than one switch satisfies dispatcher qualification."),
            _ => new DispatcherAnalysisResult(
                DispatcherQualification.Ambiguous,
                null,
                rejected.Count == 0 ? ["No switch could be qualified."] : rejected)
        };
    }

    /// <summary>
    /// Proves what it can of a method the whole-method plan could not close, one edge at a time.
    /// </summary>
    /// <remarks>
    /// <see cref="Analyze"/> proves a dispatcher out of existence: every ingress has to be a proven
    /// constant assignment, the entry has to select one initial state, and the state may not be read
    /// anywhere but the switch. Those conditions together let the assignments be erased, because
    /// nothing is left that could observe the state. One unprovable ingress fails all of them, and on
    /// real Reactor output that is the normal case — most flattened methods hold one assignment the
    /// analyzer cannot reduce, and the method is preserved whole because of it.
    ///
    /// An edge on its own needs far less. A block that ends <c>&lt;constant&gt;; stloc L; br
    /// DISPATCH</c> arrives at the dispatcher with <c>L</c> holding that constant, so the switch it
    /// is about to perform has one known outcome, and jumping straight there instead is the same
    /// thing. Nothing about the rest of the method enters that argument, so no other ingress and no
    /// other reader of <c>L</c> has to be proven for it to hold.
    ///
    /// What makes it local is keeping the assignment. The whole-method plan drops it, which is only
    /// sound once the dispatcher is unreachable; here the dispatcher stays, so the edge carries the
    /// store itself (<see cref="DispatcherEdgeRedirect.RestoredStateLocal"/>) and leaves <c>L</c>
    /// holding exactly what it would have. Every reader in the method, including the dispatcher on
    /// the paths that still reach it, sees the value it saw before.
    /// </remarks>
    public DispatcherPartialResult AnalyzePartial(MethodDef method)
    {
        ArgumentNullException.ThrowIfNull(method);
        if (!method.HasBody || method.Body.Instructions.Count == 0)
            return PartialNotCandidate("Method has no CIL body.");
        if (method.Body.Instructions.Count > options.MaximumInstructions)
            return PartialAmbiguous($"Method exceeds the {options.MaximumInstructions} instruction limit.");

        ControlFlowGraph graph;
        try
        {
            graph = ControlFlowGraph.Build(method);
        }
        catch (Exception ex)
        {
            return PartialAmbiguous($"CFG construction failed: {ex.Message}");
        }

        var dispatchers = method.Body.Instructions
            .Where(instruction => instruction.OpCode.Code == Code.Switch)
            .Select(switchInstruction => (
                Switch: switchInstruction,
                Block: graph.BlockOf(switchInstruction),
                Head: StateOf(method, graph, switchInstruction)))
            .Where(item => item.Head is not null)
            .Select(item => (item.Switch, item.Block, Head: item.Head!.Value))
            .ToArray();
        if (dispatchers.Length == 0)
            return PartialNotCandidate("No switch block reads a state variable and switches on it.");

        var rewrites = new List<DispatcherEdgeRedirect>();
        var declines = new Dictionary<DispatcherEdgeDecline, int>();
        var offered = 0;
        // An instruction can only be rewritten once, and a block reaching two dispatchers would
        // otherwise be planned twice over.
        var claimed = new HashSet<Instruction>();

        foreach (var (switchInstruction, dispatcher, head) in dispatchers)
        {
            var (state, bias) = head;
            var cases = (IList<Instruction>)switchInstruction.Operand;
            foreach (var source in dispatcher.Predecessors
                         .Where(edge => edge.Kind != ControlFlowEdgeKind.Exception)
                         .Select(edge => edge.Source)
                         .Distinct())
            {
                if (ReferenceEquals(source, dispatcher))
                    continue;
                offered++;
                if (TryPlanEdge(
                        method, graph, source, dispatcher, switchInstruction, cases, state, bias,
                        claimed, out var redirect, out var decline))
                {
                    rewrites.Add(redirect!);
                    continue;
                }

                if (decline is { } reason)
                    Decline(declines, reason);
                else
                    offered--;
            }
        }

        if (rewrites.Count == 0)
        {
            return new DispatcherPartialResult(
                DispatcherQualification.Ambiguous,
                null,
                ["No edge into a dispatcher could be proven on its own."]);
        }

        return new DispatcherPartialResult(
            DispatcherQualification.Qualified,
            new DispatcherPartialPlan(
                method,
                dispatchers.Length,
                offered,
                rewrites,
                declines),
            [$"Proved {rewrites.Count} of {offered} edges into {dispatchers.Length} dispatcher(s)."]);
    }

    /// <summary>
    /// The local a switch dispatches on and the constant subtracted from it first, when the block
    /// does nothing but read the local, bias it and switch.
    /// </summary>
    /// <remarks>
    /// Reactor's dispatchers are rarely the bare <c>ldloc; switch</c> the whole-method proof looks
    /// for. The states it numbers a method's blocks with do not start at zero, so the dispatcher
    /// subtracts where they do start and switches on the difference: <c>ldloc L; ldc.i4 K; sub;
    /// switch</c>. Reading that as no dispatcher at all is what left almost every flattened method
    /// in a real module untouched, so the bias is carried out of here and applied to the constant an
    /// edge assigns rather than being required to be absent.
    ///
    /// The same shape is what a C# compiler emits for a switch over a sparse enum, and this does
    /// not try to tell the two apart. It does not have to: an edge is only rewritten when a block
    /// assigns the state a constant and jumps straight here, which is a thing a flattener does and
    /// ordinary code does not, and rewriting one is sound either way.
    /// </remarks>
    private static (Local? State, int Bias)? StateOf(
        MethodDef method,
        ControlFlowGraph graph,
        Instruction switchInstruction)
    {
        if (switchInstruction.Operand is not IList<Instruction> cases || cases.Count < 2)
            return null;

        // The block has to hold the dispatcher and nothing else. An edge is redirected to a case
        // rather than to the block, so anything else standing in the block is something the
        // redirected path would no longer run.
        var meaningful = graph.BlockOf(switchInstruction).Instructions
            .Where(instruction => instruction.OpCode.Code != Code.Nop)
            .ToArray();
        if (!ReferenceEquals(meaningful[^1], switchInstruction))
            return null;

        // A dispatcher takes its state either from a variable it reads or from the stack, where
        // whatever jumped here left it. Both are flatteners; only the handover differs.
        var state = meaningful.Length > 1 ? GetLoadedLocal(method, meaningful[0]) : null;
        if (state is not null && state.Type.ElementType != ElementType.I4)
            return null;
        var read = state is null ? 0 : 1;

        if (meaningful.Length == read + 1)
            return (state, 0);
        if (meaningful.Length != read + 3 || !TryGetInt32Constant(meaningful[read], out var bias))
            return null;

        return meaningful[read + 1].OpCode.Code switch
        {
            Code.Sub => (state, bias),
            Code.Add => (state, -bias),
            _ => null
        };
    }

    /// <summary>
    /// Proves one block's handover to a dispatcher, or says what stopped it.
    /// </summary>
    /// <param name="decline">
    /// Why the edge was left alone, or <c>null</c> when the block does not hand over in a way this
    /// rewrite has anything to say about, which is not a shortfall to report.
    /// </param>
    private bool TryPlanEdge(
        MethodDef method,
        ControlFlowGraph graph,
        BasicBlock source,
        BasicBlock dispatcher,
        Instruction switchInstruction,
        IList<Instruction> cases,
        Local? state,
        int bias,
        HashSet<Instruction> claimed,
        out DispatcherEdgeRedirect? redirect,
        out DispatcherEdgeDecline? decline)
    {
        redirect = null;
        decline = null;
        var instructions = source.Instructions.ToArray();
        var meaningful = instructions
            .Where(instruction => instruction.OpCode.Code != Code.Nop)
            .ToArray();
        if (meaningful.Length == 0)
            return false;

        // Two ways a block hands over, and one instruction becomes the direct jump either way: the
        // branch it ends with, or, where it just runs off its end into the dispatcher, the last
        // instruction of the state expression itself.
        var last = meaningful[^1];
        var branches = last.OpCode.FlowControl == FlowControl.Branch &&
            last.OpCode.Code is not (Code.Leave or Code.Leave_S) &&
            last.Operand is Instruction target &&
            ReferenceEquals(target, dispatcher.Instructions[0]);
        if (!branches && !FallsInto(method, source, dispatcher))
            return false;

        // Where the state is a variable the block assigns, the assignment has to be the last thing
        // it does, so that what the dispatcher reads is what this block computed.
        var rewritten = last;
        var expressionEnd = Array.IndexOf(instructions, last) - 1;
        if (state is not null)
        {
            var store = branches ? (meaningful.Length > 1 ? meaningful[^2] : null) : last;
            if (store is null || !ReferenceEquals(GetStoredLocal(method, store), state))
            {
                decline = DispatcherEdgeDecline.UntailedAssignment;
                return false;
            }

            expressionEnd = Array.IndexOf(instructions, store) - 1;
        }
        else if (!branches)
        {
            // The block ends with the push the dispatcher pops, so that push becomes the jump.
            expressionEnd = Array.IndexOf(instructions, last);
        }

        if (!claimed.Add(rewritten))
        {
            decline = null;
            return false;
        }

        var budget = options.MaximumExpressionNodes;
        var helperStack = new HashSet<MethodDef>();
        if (expressionEnd < 0 ||
            !TryEvaluateBackward(
                method, instructions, expressionEnd, options.MaximumHelperDepth, helperStack,
                ref budget, out var expressionStart, out var value))
        {
            decline = DispatcherEdgeDecline.UnprovenExpression;
            return false;
        }

        // The dispatcher switches on the state less its bias, so that is the index the constant
        // selects. A state outside the range is not an unproven edge: a switch whose operand names
        // no case falls through to whatever follows it, so the destination is just as settled, and
        // declining it would leave the dispatcher standing for edges whose outcome is known.
        var selected = value - bias;
        var chosen = selected >= 0 && selected < cases.Count
            ? cases[selected]
            : FallsThroughTo(method, switchInstruction);
        if (chosen is null)
        {
            decline = DispatcherEdgeDecline.StateOutsideRange;
            return false;
        }

        if (!graph.HaveIdenticalExceptionRegions(rewritten, chosen))
        {
            decline = DispatcherEdgeDecline.ExceptionRegion;
            return false;
        }

        // Everything from the expression up to the instruction being repurposed goes, that being
        // exactly what the direct jump no longer needs computed.
        var erasedEnd = Array.IndexOf(instructions, rewritten) - 1;
        redirect = new DispatcherEdgeRedirect(
            rewritten,
            chosen,
            value,
            erasedEnd < expressionStart
                ? []
                : instructions.Skip(expressionStart).Take(erasedEnd - expressionStart + 1).ToArray(),
            state);
        return true;
    }

    /// <summary>Where a switch goes when its operand names no case.</summary>
    private static Instruction? FallsThroughTo(MethodDef method, Instruction switchInstruction)
    {
        var instructions = method.Body.Instructions;
        var at = instructions.IndexOf(switchInstruction);
        return at >= 0 && at + 1 < instructions.Count ? instructions[at + 1] : null;
    }

    /// <summary>Whether control leaves the block by running off its end into the dispatcher.</summary>
    private static bool FallsInto(MethodDef method, BasicBlock block, BasicBlock dispatcher)
    {
        var instructions = method.Body.Instructions;
        var last = instructions.IndexOf(block.Instructions[^1]);
        return last >= 0 && last + 1 < instructions.Count &&
            ReferenceEquals(instructions[last + 1], dispatcher.Instructions[0]);
    }

    private static void Decline(
        Dictionary<DispatcherEdgeDecline, int> declines,
        DispatcherEdgeDecline decline) =>
        declines[decline] = declines.GetValueOrDefault(decline) + 1;

    private bool TryQualify(
        MethodDef method,
        ControlFlowGraph graph,
        Instruction switchInstruction,
        out DispatcherRewritePlan? plan,
        out string reason)
    {
        plan = null;
        reason = string.Empty;
        var dispatcher = graph.BlockOf(switchInstruction);
        var meaningfulDispatcher = dispatcher.Instructions
            .Where(instruction => instruction.OpCode.Code != Code.Nop)
            .ToArray();
        if (meaningfulDispatcher.Length != 2 ||
            !ReferenceEquals(meaningfulDispatcher[1], switchInstruction) ||
            GetLoadedLocal(method, meaningfulDispatcher[0]) is not { } stateLocal)
        {
            reason = "switch block is not exactly ldloc/switch.";
            return false;
        }
        if (stateLocal.Type.ElementType != ElementType.I4)
        {
            reason = "dispatcher state is not an Int32 local.";
            return false;
        }
        if (switchInstruction.Operand is not IList<Instruction> cases || cases.Count < 2 ||
            cases.Distinct().Count() != cases.Count)
        {
            reason = "switch has fewer than two distinct case targets.";
            return false;
        }

        foreach (var instruction in method.Body.Instructions)
        {
            if (ReferencesLocalAddress(method, instruction, stateLocal))
            {
                reason = "dispatcher local address escapes.";
                return false;
            }
            var loaded = GetLoadedLocal(method, instruction);
            if (ReferenceEquals(loaded, stateLocal) &&
                !ReferenceEquals(instruction, meaningfulDispatcher[0]))
            {
                reason = "dispatcher local is read outside the switch block.";
                return false;
            }
        }

        var stores = method.Body.Instructions
            .Where(instruction => ReferenceEquals(GetStoredLocal(method, instruction), stateLocal))
            .ToArray();
        if (stores.Length < 2)
        {
            reason = "dispatcher local has fewer than two assignments.";
            return false;
        }

        var writers = new Dictionary<BasicBlock, (Instruction Store, Instruction Branch, int State,
            IReadOnlyList<Instruction> Remove)>();
        foreach (var store in stores)
        {
            var block = graph.BlockOf(store);
            var blockInstructions = block.Instructions.ToArray();
            var storeIndex = Array.IndexOf(blockInstructions, store);
            if (writers.ContainsKey(block))
            {
                reason = "multiple dispatcher assignments occur in one basic block.";
                return false;
            }
            var meaningful = block.Instructions
                .Where(instruction => instruction.OpCode.Code != Code.Nop)
                .ToArray();
            var storePosition = Array.IndexOf(meaningful, store);
            if (storePosition < 1 || storePosition != meaningful.Length - 2)
            {
                reason = "state assignment is not immediately followed by a terminating branch.";
                return false;
            }
            var branch = meaningful[^1];
            if (branch.OpCode.FlowControl != FlowControl.Branch ||
                branch.OpCode.Code is Code.Leave or Code.Leave_S ||
                branch.Operand is not Instruction branchTarget ||
                !ReferenceEquals(graph.BlockOf(branchTarget), dispatcher))
            {
                reason = "state assignment does not end in an unconditional branch to the dispatcher.";
                return false;
            }

            var budget = options.MaximumExpressionNodes;
            var helperStack = new HashSet<MethodDef>();
            if (!TryEvaluateBackward(
                    method,
                    block.Instructions,
                    storeIndex - 1,
                    options.MaximumHelperDepth,
                    helperStack,
                    ref budget,
                    out var expressionStart,
                    out var value))
            {
                reason = "state assignment is not a bounded constant integer expression.";
                return false;
            }
            if (value < 0 || value >= cases.Count)
            {
                reason = $"constant state {value} is outside the switch range.";
                return false;
            }

            var remove = block.Instructions
                .Skip(expressionStart)
                .Take(storeIndex - expressionStart + 1)
                .ToArray();
            writers.Add(block, (store, branch, value, remove));
        }

        if (dispatcher.Predecessors.Any(edge => edge.Kind == ControlFlowEdgeKind.Exception))
        {
            reason = "dispatcher has exceptional-control-flow ingress.";
            return false;
        }
        var normalPredecessors = dispatcher.Predecessors
            .Select(edge => edge.Source)
            .ToHashSet();
        if (!normalPredecessors.SetEquals(writers.Keys))
        {
            reason = "dispatcher has ingress not owned by a proven state assignment.";
            return false;
        }

        var writerBlocks = writers.Keys.ToHashSet();
        var initialWriters = ReachWriters(graph.Entry, dispatcher, writerBlocks);
        if (initialWriters.Count != 1)
        {
            reason = "method entry does not select exactly one initial dispatcher state.";
            return false;
        }
        var initial = initialWriters.Single();
        var transitionWriters = new HashSet<BasicBlock>();
        foreach (var target in cases)
            transitionWriters.UnionWith(ReachWriters(graph.BlockOf(target), dispatcher, writerBlocks));
        if (transitionWriters.Contains(initial) ||
            !transitionWriters.SetEquals(writers.Keys.Where(writer => !ReferenceEquals(writer, initial))))
        {
            reason = "initial and transition assignments are not uniquely separated.";
            return false;
        }

        var rewrites = new List<DispatcherEdgeRewrite>();
        foreach (var (source, writer) in writers)
        {
            var target = cases[writer.State];
            if (!graph.HaveIdenticalExceptionRegions(writer.Branch, target))
            {
                reason = "a direct target crosses an exception-region boundary.";
                return false;
            }
            rewrites.Add(new DispatcherEdgeRewrite(
                source,
                writer.Branch,
                target,
                writer.State,
                writer.Remove));
        }

        plan = new DispatcherRewritePlan(
            method,
            stateLocal,
            dispatcher,
            switchInstruction,
            writers[initial].State,
            rewrites.OrderBy(rewrite => rewrite.Source.Id).ToArray());
        return true;
    }

    private HashSet<BasicBlock> ReachWriters(
        BasicBlock start,
        BasicBlock dispatcher,
        HashSet<BasicBlock> writers)
    {
        var found = new HashSet<BasicBlock>();
        var visited = new HashSet<BasicBlock>();
        var work = new Stack<BasicBlock>();
        work.Push(start);
        var visits = 0;
        while (work.Count != 0 && visits++ < options.MaximumGraphVisits)
        {
            var block = work.Pop();
            if (!visited.Add(block) || ReferenceEquals(block, dispatcher))
                continue;
            if (writers.Contains(block))
            {
                found.Add(block);
                continue;
            }
            foreach (var edge in block.Successors.Where(edge =>
                         edge.Kind != ControlFlowEdgeKind.Exception))
                work.Push(edge.Target);
        }
        return visits >= options.MaximumGraphVisits ? [] : found;
    }

    private bool TryEvaluateBackward(
        MethodDef owner,
        IReadOnlyList<Instruction> instructions,
        int end,
        int helperDepth,
        HashSet<MethodDef> helperStack,
        ref int budget,
        out int start,
        out int value)
    {
        start = end;
        value = 0;
        while (start >= 0 && instructions[start].OpCode.Code == Code.Nop)
            start--;
        if (start < 0 || budget-- <= 0)
            return false;

        var instruction = instructions[start];
        if (TryGetInt32Constant(instruction, out value))
            return true;

        if (instruction.OpCode.Code is Code.Neg or Code.Not or Code.Conv_I4 or Code.Conv_U4)
        {
            if (!TryEvaluateBackward(owner, instructions, start - 1, helperDepth, helperStack,
                    ref budget, out var operandStart, out var operand))
                return false;
            start = operandStart;
            value = instruction.OpCode.Code switch
            {
                Code.Neg => unchecked(-operand),
                Code.Not => ~operand,
                _ => operand
            };
            return true;
        }

        if (IsBinary(instruction.OpCode.Code))
        {
            if (!TryEvaluateBackward(owner, instructions, start - 1, helperDepth, helperStack,
                    ref budget, out var rightStart, out var right) ||
                !TryEvaluateBackward(owner, instructions, rightStart - 1, helperDepth, helperStack,
                    ref budget, out var leftStart, out var left) ||
                !TryBinary(instruction.OpCode.Code, left, right, out value))
                return false;
            start = leftStart;
            return true;
        }

        if (instruction.OpCode.Code == Code.Call &&
            instruction.Operand is IMethod called &&
            called.ResolveMethodDef() is { } helper &&
            TryEvaluateHelper(helper, helperDepth, helperStack, ref budget, out value))
            return true;

        return false;
    }

    private bool TryEvaluateHelper(
        MethodDef helper,
        int depth,
        HashSet<MethodDef> helperStack,
        ref int budget,
        out int value)
    {
        value = 0;
        if (depth <= 0 || !helper.HasBody || !helper.IsStatic ||
            helper.HasGenericParameters || helper.MethodSig is null ||
            helper.MethodSig.Params.Count != 0 ||
            helper.MethodSig.RetType.ElementType != ElementType.I4 ||
            helper.Body.HasExceptionHandlers || helper.Body.Variables.Count != 0 ||
            helper.DeclaringType?.FindStaticConstructor() is not null ||
            !helperStack.Add(helper))
            return false;
        try
        {
            var meaningful = helper.Body.Instructions
                .Where(instruction => instruction.OpCode.Code != Code.Nop)
                .ToArray();
            if (meaningful.Length < 2 || meaningful[^1].OpCode.Code != Code.Ret)
                return false;
            if (!TryEvaluateBackward(helper, meaningful, meaningful.Length - 2, depth - 1,
                    helperStack, ref budget, out var start, out value))
                return false;
            return start == 0;
        }
        finally
        {
            helperStack.Remove(helper);
        }
    }

    private static bool TryBinary(Code code, int left, int right, out int result)
    {
        result = 0;
        if (right == 0 && code is Code.Div or Code.Div_Un or Code.Rem or Code.Rem_Un)
            return false;
        if (left == int.MinValue && right == -1 && code is Code.Div or Code.Rem)
            return false;
        result = code switch
        {
            Code.Add => unchecked(left + right),
            Code.Sub => unchecked(left - right),
            Code.Mul => unchecked(left * right),
            Code.Div => left / right,
            Code.Div_Un => unchecked((int)((uint)left / (uint)right)),
            Code.Rem => left % right,
            Code.Rem_Un => unchecked((int)((uint)left % (uint)right)),
            Code.Xor => left ^ right,
            Code.And => left & right,
            Code.Or => left | right,
            Code.Shl => left << right,
            Code.Shr => left >> right,
            Code.Shr_Un => unchecked((int)((uint)left >> right)),
            Code.Ceq => left == right ? 1 : 0,
            Code.Cgt => left > right ? 1 : 0,
            Code.Cgt_Un => (uint)left > (uint)right ? 1 : 0,
            Code.Clt => left < right ? 1 : 0,
            Code.Clt_Un => (uint)left < (uint)right ? 1 : 0,
            _ => 0
        };
        return true;
    }

    private static bool IsBinary(Code code) => code is
        Code.Add or Code.Sub or Code.Mul or Code.Div or Code.Div_Un or Code.Rem or Code.Rem_Un or
        Code.Xor or Code.And or Code.Or or Code.Shl or Code.Shr or Code.Shr_Un or
        Code.Ceq or Code.Cgt or Code.Cgt_Un or Code.Clt or Code.Clt_Un;

    private static bool TryGetInt32Constant(Instruction instruction, out int value)
    {
        value = instruction.OpCode.Code switch
        {
            Code.Ldc_I4_M1 => -1,
            Code.Ldc_I4_0 => 0,
            Code.Ldc_I4_1 => 1,
            Code.Ldc_I4_2 => 2,
            Code.Ldc_I4_3 => 3,
            Code.Ldc_I4_4 => 4,
            Code.Ldc_I4_5 => 5,
            Code.Ldc_I4_6 => 6,
            Code.Ldc_I4_7 => 7,
            Code.Ldc_I4_8 => 8,
            Code.Ldc_I4_S when instruction.Operand is sbyte small => small,
            Code.Ldc_I4 when instruction.Operand is int integer => integer,
            _ => 0
        };
        return instruction.OpCode.Code is
            Code.Ldc_I4_M1 or Code.Ldc_I4_0 or Code.Ldc_I4_1 or Code.Ldc_I4_2 or
            Code.Ldc_I4_3 or Code.Ldc_I4_4 or Code.Ldc_I4_5 or Code.Ldc_I4_6 or
            Code.Ldc_I4_7 or Code.Ldc_I4_8 or Code.Ldc_I4_S or Code.Ldc_I4;
    }

    private static Local? GetLoadedLocal(MethodDef method, Instruction instruction) =>
        instruction.OpCode.Code switch
        {
            Code.Ldloc or Code.Ldloc_S => instruction.Operand as Local,
            Code.Ldloc_0 => LocalAt(method, 0),
            Code.Ldloc_1 => LocalAt(method, 1),
            Code.Ldloc_2 => LocalAt(method, 2),
            Code.Ldloc_3 => LocalAt(method, 3),
            _ => null
        };

    private static Local? GetStoredLocal(MethodDef method, Instruction instruction) =>
        instruction.OpCode.Code switch
        {
            Code.Stloc or Code.Stloc_S => instruction.Operand as Local,
            Code.Stloc_0 => LocalAt(method, 0),
            Code.Stloc_1 => LocalAt(method, 1),
            Code.Stloc_2 => LocalAt(method, 2),
            Code.Stloc_3 => LocalAt(method, 3),
            _ => null
        };

    private static bool ReferencesLocalAddress(
        MethodDef method,
        Instruction instruction,
        Local local) =>
        instruction.OpCode.Code switch
        {
            Code.Ldloca or Code.Ldloca_S => ReferenceEquals(instruction.Operand, local),
            _ => false
        };

    private static Local? LocalAt(MethodDef method, int index) =>
        index < method.Body.Variables.Count ? method.Body.Variables[index] : null;

    private static DispatcherAnalysisResult NotCandidate(string diagnostic) =>
        new(DispatcherQualification.NotCandidate, null, [diagnostic]);

    private static DispatcherAnalysisResult Ambiguous(string diagnostic) =>
        new(DispatcherQualification.Ambiguous, null, [diagnostic]);

    private static DispatcherPartialResult PartialNotCandidate(string diagnostic) =>
        new(DispatcherQualification.NotCandidate, null, [diagnostic]);

    private static DispatcherPartialResult PartialAmbiguous(string diagnostic) =>
        new(DispatcherQualification.Ambiguous, null, [diagnostic]);
}
