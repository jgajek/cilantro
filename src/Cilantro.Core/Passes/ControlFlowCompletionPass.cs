using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Passes;

/// <summary>
/// Completes control-flow recovery by folding constant branches and deleting unreachable code.
/// </summary>
/// <remarks>
/// The dispatcher pass redirects each flattener edge to its proven target but leaves the switch
/// block and its dead state stores physically present; they simply become unreachable. This pass
/// finishes the job structurally: it folds branches whose condition is a proven constant, which is
/// how Reactor's opaque predicates collapse, and then deletes every instruction the trusted
/// reachability walk cannot reach, which removes the orphaned dispatcher and any junk it guarded.
/// Folding and deletion are iterated to a fixed point because each exposes more of the other.
///
/// Correctness rests on two invariants. Deletion only removes instructions outside the reachable
/// set, and that set is seeded from the method entry and every exception-clause entry, so live
/// handlers are never touched. Exception-clause boundary instructions are pinned even when
/// unreachable, so a try or handler extent can never be left dangling. Each method is rewritten in
/// its own transaction and rolled back unless structural verification passes, so a method this pass
/// cannot prove safe is preserved exactly as it was.
/// </remarks>
public class ControlFlowCompletionPass : DeobfuscationPass
{
    private const int MaximumRounds = 16;

    public override string Name => "control-flow-completion";
    public override IReadOnlyCollection<string> Dependencies =>
        ["dispatcher-deobfuscation", "cfg-dead-code"];

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        var foldedTotal = 0;
        var removedTotal = 0;
        var rewrittenMethods = 0;
        foreach (var method in context.Module.GetTypes()
                     .SelectMany(type => type.Methods)
                     .Where(item => item.HasBody && item.Body.Instructions.Count != 0))
        {
            var outcome = TryComplete(method);
            if (outcome is null)
                continue;
            foldedTotal += outcome.Value.Folded;
            removedTotal += outcome.Value.Removed;
            if (outcome.Value.Folded != 0 || outcome.Value.Removed != 0)
            {
                rewrittenMethods++;
                context.AddChange(new ChangeRecord(
                    Name,
                    "complete-control-flow",
                    $"{method.MDToken} {method.FullName}",
                    $"Folded {outcome.Value.Folded} constant branch(es) and removed " +
                    $"{outcome.Value.Removed} unreachable instruction(s)."));
            }
        }

        // Added to rather than assigned, because this pass is asked twice and the summary is about
        // the run. What the second pass finds is the remainder the first could not have reached, so
        // reporting it on its own would tell the analyst that less was simplified than was.
        Accumulate("cfg.constantBranchesFolded", foldedTotal);
        Accumulate("cfg.unreachableInstructionsRemoved", removedTotal);
        Accumulate("cfg.methodsSimplified", rewrittenMethods);
        return (PassStatus.Success, foldedTotal + removedTotal,
        [
            $"Folded {foldedTotal} constant branch(es) and removed {removedTotal} unreachable " +
            $"instruction(s) across {rewrittenMethods} method(s)."
        ]);

        void Accumulate(string fact, int found)
        {
            context.TryGetFact<int>(fact, out var already);
            context.SetFact(fact, already + found);
        }
    }

    /// <summary>
    /// Runs the fold/delete fixed point for one method under a rollback transaction.
    /// </summary>
    /// <remarks>
    /// Reachable from outside the pass because a body the tool writes itself, late, wants the same
    /// treatment as the ones that were in the file when this pass ran over the module.
    /// </remarks>
    internal static (int Folded, int Removed)? TryComplete(MethodDef method)
    {
        using var transaction = new BodyMutationTransaction(method);
        var folded = 0;
        var removed = 0;
        var wasDisputed = EvaluationStackAnalyzer.Analyze(method).Diagnostics.Count;
        try
        {
            for (var round = 0; round < MaximumRounds; round++)
            {
                var foldedThisRound = FoldConstantLocals(method) + FoldConstantBranches(method);
                var discardedThisRound = RemoveDiscardedValues(method);
                var removedThisRound = RemoveUnreachable(method) + discardedThisRound;
                folded += foldedThisRound;
                removed += removedThisRound;
                if (foldedThisRound == 0 && removedThisRound == 0)
                    break;
            }
            if (folded == 0 && removed == 0)
            {
                transaction.Rollback();
                return (0, 0);
            }
            method.Body.OptimizeBranches();
            if (!IsStructurallySound(method))
                throw new InvalidOperationException("Rewrite left the method body structurally invalid.");
            // Folding an entry edge can leave a dispatcher head that only a branch from below
            // reaches, which no single forward pass can name the stack at. That is not a reason to
            // keep the dispatcher: refusing the fold costs about seven in ten of them across the
            // corpus. StackHandoffPass moves the state into a local at the end of the run instead.

            // The shape check above says the branches and boundaries land somewhere; it says
            // nothing about what the stack holds when they do. A fold that deletes the arm which
            // consumed a value leaves the value where it was, and the block the other arm reaches
            // is then entered at two different depths depending on the path — which every reader of
            // this body downstream, decompiler and verifier alike, is entitled to reject.
            if (EvaluationStackAnalyzer.Analyze(method).Diagnostics.Count > wasDisputed)
                throw new InvalidOperationException(
                    "Rewrite left more places where the paths into a block disagree about the stack.");
            transaction.Commit();
            return (folded, removed);
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or ArgumentException or InvalidProgramException)
        {
            transaction.Rollback();
            return null;
        }
    }

    /// <summary>
    /// Rewrites conditional branches whose single-operand condition is a proven constant.
    /// </summary>
    /// <remarks>
    /// Only the leaf shapes are handled: a boolean branch over one constant, a switch over one
    /// integer, and a comparison branch over two. These are exactly the opaque-predicate forms
    /// Reactor emits, and each rewrite is stack-neutral because the constants the branch would have
    /// consumed are removed with it.
    ///
    /// A null constant decides a boolean branch as surely as a zero does, a reference being true
    /// exactly when it is not null. It cannot decide a switch, carrying no case number.
    ///
    /// The comparison branches are what a dispatcher's last edge hides behind once its state is
    /// known: the state is compared against the number standing for one block, and the answer
    /// decides whether the loop goes round again. They are also the one shape here that needs two
    /// constants rather than one, so the walk back runs twice, the second time from wherever the
    /// first stopped.
    /// </remarks>
    private static int FoldConstantBranches(MethodDef method)
    {
        var instructions = method.Body.Instructions;
        var entered = EntryPoints(method);
        var folded = 0;
        for (var index = 1; index < instructions.Count; index++)
        {
            var branch = instructions[index];
            if (Feeding(instructions, entered, index) is not { } producer)
                continue;
            var numbered = producer.IsLdcI4();
            if (!numbered && producer.OpCode.Code != Code.Ldnull)
                continue;
            var value = numbered ? producer.GetLdcI4Value() : 0;
            switch (branch.OpCode.Code)
            {
                case Code.Brtrue or Code.Brtrue_S when branch.Operand is Instruction trueTarget:
                    Neutralize(producer);
                    Retarget(branch, value != 0, trueTarget);
                    folded++;
                    break;
                case Code.Brfalse or Code.Brfalse_S when branch.Operand is Instruction falseTarget:
                    Neutralize(producer);
                    Retarget(branch, value == 0, falseTarget);
                    folded++;
                    break;
                case Code.Beq or Code.Beq_S or Code.Bne_Un or Code.Bne_Un_S or
                    Code.Bge or Code.Bge_S or Code.Bge_Un or Code.Bge_Un_S or
                    Code.Bgt or Code.Bgt_S or Code.Bgt_Un or Code.Bgt_Un_S or
                    Code.Ble or Code.Ble_S or Code.Ble_Un or Code.Ble_Un_S or
                    Code.Blt or Code.Blt_S or Code.Blt_Un or Code.Blt_Un_S
                    when numbered && branch.Operand is Instruction comparedTarget &&
                        Feeding(instructions, entered, instructions.IndexOf(producer)) is
                            { } compared && compared.IsLdcI4():
                    var decided = Compares(branch.OpCode.Code, compared.GetLdcI4Value(), value);
                    Neutralize(producer);
                    Neutralize(compared);
                    Retarget(branch, decided, comparedTarget);
                    folded++;
                    break;
                case Code.Switch when numbered && branch.Operand is IList<Instruction> cases:
                    Neutralize(producer);
                    if (value >= 0 && value < cases.Count)
                    {
                        branch.OpCode = OpCodes.Br;
                        branch.Operand = cases[value];
                    }
                    else
                    {
                        branch.OpCode = OpCodes.Nop;
                        branch.Operand = null;
                    }
                    folded++;
                    break;
            }
        }
        return folded;

        static void Retarget(Instruction branch, bool taken, Instruction target)
        {
            if (taken)
            {
                branch.OpCode = OpCodes.Br;
                branch.Operand = target;
            }
            else
            {
                branch.OpCode = OpCodes.Nop;
                branch.Operand = null;
            }
        }

        static void Neutralize(Instruction instruction)
        {
            instruction.OpCode = OpCodes.Nop;
            instruction.Operand = null;
        }
    }

    /// <summary>Whether a comparison branch over two known numbers is taken.</summary>
    private static bool Compares(Code code, int left, int right) => code switch
    {
        Code.Beq or Code.Beq_S => left == right,
        Code.Bne_Un or Code.Bne_Un_S => left != right,
        Code.Bge or Code.Bge_S => left >= right,
        Code.Bgt or Code.Bgt_S => left > right,
        Code.Ble or Code.Ble_S => left <= right,
        Code.Blt or Code.Blt_S => left < right,
        Code.Bge_Un or Code.Bge_Un_S => (uint)left >= (uint)right,
        Code.Bgt_Un or Code.Bgt_Un_S => (uint)left > (uint)right,
        Code.Ble_Un or Code.Ble_Un_S => (uint)left <= (uint)right,
        Code.Blt_Un or Code.Blt_Un_S => (uint)left < (uint)right,
        _ => throw new InvalidOperationException($"{code} does not compare two numbers.")
    };

    /// <summary>
    /// Replaces reads of a local that holds one number everywhere it is read with that number.
    /// </summary>
    /// <remarks>
    /// What is left of a dispatcher once its edges are direct is a local assigned a number once
    /// and a loop that compares the local against the numbers standing for its blocks. The switch
    /// over it no longer decides anything and neither do the comparisons, but nothing here could
    /// say so, because saying so means knowing what the local holds and the reads are reached
    /// round a back edge rather than fallen into. Knowing it needs no reasoning about the loop:
    /// there is one assignment, and the number it assigns is written into the instruction before
    /// it.
    ///
    /// The care is in the reads, not the assignment. A read the assignment has not run before
    /// sees whatever the local was initialized to instead, so every read has to be behind the
    /// assignment on every path there is — which is asked by walking the method with the
    /// assignment walled off and requiring that the walk reach no read at all.
    /// </remarks>
    private static int FoldConstantLocals(MethodDef method)
    {
        var constants = ConstantLocals(method);
        if (constants.Count == 0)
            return 0;
        var variables = method.Body.Variables;
        var folded = 0;
        foreach (var instruction in method.Body.Instructions)
        {
            if (!instruction.IsLdloc())
                continue;
            if (instruction.GetLocal(variables) is not { } local ||
                !constants.TryGetValue(local, out var value))
                continue;
            instruction.OpCode = OpCodes.Ldc_I4;
            instruction.Operand = value;
            folded++;
        }

        return folded;
    }

    /// <summary>The locals that hold one known number at every read, and the number.</summary>
    private static Dictionary<Local, int> ConstantLocals(MethodDef method)
    {
        var instructions = method.Body.Instructions;
        var variables = method.Body.Variables;
        var entered = EntryPoints(method);
        var constants = new Dictionary<Local, int>();
        foreach (var local in variables)
        {
            // An address taken is a way of writing the local that reading the instructions
            // cannot account for.
            if (instructions.Any(instruction =>
                    instruction.OpCode.Code is Code.Ldloca or Code.Ldloca_S &&
                    instruction.GetLocal(variables) == local))
                continue;

            Instruction? store = null;
            var stored = 0;
            var reads = new List<Instruction>();
            foreach (var instruction in instructions)
            {
                if (instruction.GetLocal(variables) != local)
                    continue;
                if (instruction.IsStloc())
                {
                    store = instruction;
                    stored++;
                }
                else if (instruction.IsLdloc())
                {
                    reads.Add(instruction);
                }
            }

            if (stored != 1 || store is null || reads.Count == 0)
                continue;
            if (Feeding(instructions, entered, instructions.IndexOf(store)) is not { } producer ||
                !producer.IsLdcI4())
                continue;
            if (!StoredBeforeEveryRead(method, store, reads))
                continue;
            constants[local] = producer.GetLdcI4Value();
        }

        return constants;
    }

    /// <summary>
    /// Whether every read of a local is somewhere the one assignment to it has already run.
    /// </summary>
    /// <remarks>
    /// Asked by walking the method from every way into it — the entry and each exception clause —
    /// with the assignment treated as a wall. Anything the walk still arrives at is arrived at
    /// without the assignment having run, so a read among them is a read of the local's initial
    /// value and the number the assignment writes is not the answer everywhere.
    /// </remarks>
    private static bool StoredBeforeEveryRead(
        MethodDef method,
        Instruction store,
        IReadOnlyCollection<Instruction> reads)
    {
        var instructions = method.Body.Instructions;
        if (instructions.Count == 0)
            return false;
        var index = new Dictionary<Instruction, int>();
        for (var at = 0; at < instructions.Count; at++)
            index[instructions[at]] = at;

        var seen = new HashSet<Instruction>();
        var work = new Stack<Instruction>();
        work.Push(instructions[0]);
        foreach (var handler in method.Body.ExceptionHandlers)
        {
            if (handler.TryStart is not null) work.Push(handler.TryStart);
            if (handler.HandlerStart is not null) work.Push(handler.HandlerStart);
            if (handler.FilterStart is not null) work.Push(handler.FilterStart);
        }

        while (work.Count != 0)
        {
            var current = work.Pop();
            if (current == store || !seen.Add(current))
                continue;
            if (reads.Contains(current))
                return false;
            switch (current.OpCode.FlowControl)
            {
                case FlowControl.Branch:
                    if (current.Operand is Instruction jumped)
                        work.Push(jumped);
                    break;
                case FlowControl.Cond_Branch:
                    if (current.Operand is Instruction target)
                        work.Push(target);
                    if (current.Operand is IList<Instruction> targets)
                        foreach (var one in targets)
                            work.Push(one);
                    Onward(current);
                    break;
                case FlowControl.Return:
                case FlowControl.Throw:
                    break;
                default:
                    Onward(current);
                    break;
            }
        }

        return true;

        void Onward(Instruction from)
        {
            var next = index[from] + 1;
            if (next < instructions.Count)
                work.Push(instructions[next]);
        }
    }

    /// <summary>
    /// Neutralizes values that are worked out and then thrown away.
    /// </summary>
    /// <remarks>
    /// Two things leave these behind. Reactor computes numbers it never uses, so that the arithmetic
    /// has to be read before it can be dismissed. And this tool keeps the store of a dispatcher's
    /// state when it makes one of that dispatcher's edges direct, because the state is still read by
    /// the switch the edge no longer goes through; once every edge is direct and the switch is gone,
    /// the store has no reader left and stands in the body as an assignment to a local nothing
    /// consults.
    ///
    /// Neither survives as something a reader can dismiss at a glance. A local nobody reads is
    /// printed as a named variable holding a number, indistinguishable from state that matters, and
    /// a discarded computation is printed as a discard of an expression. On the corpus libraries
    /// these outnumbered every other kind of leftover: against unprotected originals carrying two
    /// apiece, the cleaned copies carried one hundred and forty-four, two hundred and seventy-one,
    /// and two hundred and ninety-seven.
    ///
    /// What is removed has to be free of consequence, so only the pure part is walked: constants,
    /// reads of locals and arguments, and the arithmetic over them. A call, a field read or a load
    /// through a pointer stops the walk wherever it appears in the expression, and then nothing is
    /// removed at all.
    /// </remarks>
    private static int RemoveDiscardedValues(MethodDef method)
    {
        var instructions = method.Body.Instructions;
        var entered = EntryPoints(method);
        var read = ReadLocals(method);
        var removed = 0;
        for (var index = 1; index < instructions.Count; index++)
        {
            var consumer = instructions[index];
            var discards = consumer.OpCode.Code == Code.Pop ||
                (consumer.IsStloc() && consumer.GetLocal(method.Body.Variables) is { } local &&
                    !read.Contains(local.Index));
            if (!discards)
                continue;
            if (Peel(instructions, entered, index) is not { } expression)
                continue;
            foreach (var instruction in expression)
            {
                instruction.OpCode = OpCodes.Nop;
                instruction.Operand = null;
            }

            consumer.OpCode = OpCodes.Nop;
            consumer.Operand = null;
            removed += expression.Count + 1;
        }

        return removed;
    }

    /// <summary>Which locals are read somewhere, by index, addresses taken counting as reads.</summary>
    private static HashSet<int> ReadLocals(MethodDef method)
    {
        var read = new HashSet<int>();
        foreach (var instruction in method.Body.Instructions)
        {
            if (!instruction.IsLdloc() && instruction.OpCode.Code is not (Code.Ldloca or Code.Ldloca_S))
                continue;
            if (instruction.GetLocal(method.Body.Variables) is { } local)
                read.Add(local.Index);
        }

        return read;
    }

    /// <summary>
    /// The instructions working out the single value consumed at <paramref name="index"/>, or
    /// nothing if any of them could matter for a reason other than the value.
    /// </summary>
    private static List<Instruction>? Peel(
        IList<Instruction> instructions,
        Dictionary<Instruction, int> entered,
        int index)
    {
        var expression = new List<Instruction>();
        var wanted = 1;
        var at = index;
        while (wanted > 0)
        {
            if (Feeding(instructions, entered, at) is not { } producer)
                return null;
            if (!Pure(producer.OpCode.Code))
                return null;
            var pushes = producer.OpCode.StackBehaviourPush == StackBehaviour.Push0 ? 0 : 1;
            if (pushes == 0)
                return null;
            wanted = wanted - pushes + Consumed(producer.OpCode.StackBehaviourPop);
            expression.Add(producer);
            at = instructions.IndexOf(producer);
        }

        return expression;

        static int Consumed(StackBehaviour behaviour) => behaviour switch
        {
            StackBehaviour.Pop0 => 0,
            StackBehaviour.Pop1 or StackBehaviour.Popi => 1,
            _ => 2
        };
    }

    /// <summary>
    /// Whether an instruction does nothing but work out a value from constants, locals and arguments.
    /// </summary>
    /// <remarks>
    /// Deliberately short. A field read can run a type initializer, a load through a pointer can
    /// fault, a conversion that checks its range can throw, and a call can do anything; none of
    /// them is removable merely because what it produced was dropped.
    /// </remarks>
    private static bool Pure(Code code) => code is
        Code.Ldc_I4 or Code.Ldc_I4_S or Code.Ldc_I4_0 or Code.Ldc_I4_1 or Code.Ldc_I4_2 or
        Code.Ldc_I4_3 or Code.Ldc_I4_4 or Code.Ldc_I4_5 or Code.Ldc_I4_6 or Code.Ldc_I4_7 or
        Code.Ldc_I4_8 or Code.Ldc_I4_M1 or Code.Ldc_I8 or Code.Ldc_R4 or Code.Ldc_R8 or
        Code.Ldnull or Code.Ldstr or
        Code.Ldloc or Code.Ldloc_S or Code.Ldloc_0 or Code.Ldloc_1 or Code.Ldloc_2 or Code.Ldloc_3 or
        Code.Ldarg or Code.Ldarg_S or Code.Ldarg_0 or Code.Ldarg_1 or Code.Ldarg_2 or Code.Ldarg_3 or
        Code.Add or Code.Sub or Code.Mul or Code.And or Code.Or or Code.Xor or
        Code.Shl or Code.Shr or Code.Shr_Un or Code.Neg or Code.Not;

    /// <summary>
    /// Which instructions can be arrived at other than by falling into them.
    /// </summary>
    /// <remarks>
    /// Walking backwards from a consumer to whatever pushed what it consumes is only sound while
    /// there is one way in. Anything a branch, a switch case or an exception clause can arrive at
    /// may be arrived at holding something else, and what the instruction before it left behind
    /// says nothing about that.
    /// </remarks>
    private static Dictionary<Instruction, int> EntryPoints(MethodDef method)
    {
        var entered = new Dictionary<Instruction, int>();
        foreach (var instruction in method.Body.Instructions)
        {
            if (instruction.Operand is Instruction target)
                Enter(target);
            else if (instruction.Operand is IList<Instruction> targets)
                foreach (var branched in targets)
                    Enter(branched);
        }

        foreach (var boundary in CollectExceptionBoundaries(method))
            Enter(boundary);
        return entered;

        void Enter(Instruction at) => entered[at] = entered.GetValueOrDefault(at) + 1;
    }

    /// <summary>
    /// The instruction whose push reaches the one at <paramref name="index"/>, looked for past the
    /// padding left by earlier rewrites.
    /// </summary>
    /// <remarks>
    /// A fold neutralizes what it consumes rather than deleting it, and the dispatcher rewrite does
    /// the same to the state store and the read of it, so by the time this runs the constant and
    /// the branch it decides are routinely several instructions apart with nothing between them but
    /// padding and a jump straight to the next instruction. Insisting the two be adjacent therefore
    /// stopped finding exactly the branches the rest of the run had done the work to expose: the
    /// switch a bypassed dispatcher leaves standing over a constant nobody reads, which is an empty
    /// method body written as a switch on zero.
    ///
    /// The jump is followed because a jump whose target is the very next thing to be walked is not
    /// a choice about anything; what matters is only that nothing else arrives there, which is
    /// checked for every instruction stepped over.
    ///
    /// Walking backwards through the layout is not the same as walking backwards through the
    /// program, and where the two part company the layout is the wrong one to follow. A block
    /// nothing falls into is entered by jumping to it, and the jump can sit anywhere — including
    /// after the block, which is where the state assignment of a dispatcher inside a handler ends
    /// up. So where exactly one jump arrives and it is unconditional, the walk carries on from
    /// wherever that jump is, the stack it leaves being the stack the block begins with.
    /// </remarks>
    private static Instruction? Feeding(
        IList<Instruction> instructions,
        Dictionary<Instruction, int> entered,
        int index)
    {
        // The consumer and everything stepped over on the way back to the push.
        var path = new List<Instruction> { instructions[index] };
        var at = index;
        for (var hops = 0; ; hops++)
        {
            while (at > 0)
            {
                var previous = instructions[at - 1];
                var padding = previous.OpCode.Code == Code.Nop;
                var straight = previous.OpCode.Code is Code.Br or Code.Br_S &&
                    previous.Operand is Instruction jumped && jumped == instructions[at];
                if (!padding && !straight)
                    break;
                path.Add(previous);
                at--;
            }

            if (at == 0)
                return null;
            if (Falls(instructions[at - 1].OpCode))
                break;
            if (hops == Hops || Arriving(instructions, entered, instructions[at]) is not { } jump)
                return null;
            path.Add(jump);
            at = instructions.IndexOf(jump);
        }

        // Nothing from outside may arrive anywhere along it, an exception boundary included: a
        // second way in is a second thing the stack could be holding.
        foreach (var step in path)
        {
            var arrivals = entered.GetValueOrDefault(step);
            if (arrivals == 0)
                continue;
            var fromInside = path.Count(other =>
                other.Operand is Instruction one ? one == step :
                other.Operand is IList<Instruction> many && many.Contains(step));
            if (arrivals > fromInside)
                return null;
        }

        return instructions[at - 1];
    }

    /// <summary>How many jumps the walk will follow before giving up on reaching a push.</summary>
    private const int Hops = 4;

    /// <summary>Whether the path can run from an instruction into the one laid out after it.</summary>
    private static bool Falls(OpCode opcode) => opcode.FlowControl is not (
        FlowControl.Branch or FlowControl.Return or FlowControl.Throw);

    /// <summary>
    /// The one jump that arrives somewhere, where there is one and it is unconditional.
    /// </summary>
    /// <remarks>
    /// Anything else and the block has more than one stack it can begin with, or begins with one
    /// this cannot name: a conditional jump arrives having popped what it tested, and a switch
    /// case arrives having popped the number that chose it, neither of which is what the
    /// instruction before the jump left behind.
    /// </remarks>
    private static Instruction? Arriving(
        IList<Instruction> instructions,
        Dictionary<Instruction, int> entered,
        Instruction target)
    {
        if (entered.GetValueOrDefault(target) != 1)
            return null;
        Instruction? only = null;
        foreach (var instruction in instructions)
        {
            var names = instruction.Operand is Instruction one
                ? one == target
                : instruction.Operand is IList<Instruction> many && many.Contains(target);
            if (!names)
                continue;
            if (only is not null)
                return null;
            only = instruction;
        }

        return only?.OpCode.Code is Code.Br or Code.Br_S ? only : null;
    }

    /// <summary>
    /// Deletes instructions the reachability walk cannot reach, keeping exception boundaries pinned.
    /// </summary>
    private static int RemoveUnreachable(MethodDef method)
    {
        var reachable = CfgDeadCodePass.ComputeReachable(method);
        var pinned = CollectExceptionBoundaries(method);
        var doomed = method.Body.Instructions
            .Where(instruction => !reachable.Contains(instruction) && !pinned.Contains(instruction))
            .ToArray();
        foreach (var instruction in doomed)
            method.Body.Instructions.Remove(instruction);
        return doomed.Length;
    }

    private static HashSet<Instruction> CollectExceptionBoundaries(MethodDef method)
    {
        var pinned = new HashSet<Instruction>();
        foreach (var handler in method.Body.ExceptionHandlers)
        {
            Pin(handler.TryStart);
            Pin(handler.TryEnd);
            Pin(handler.HandlerStart);
            Pin(handler.HandlerEnd);
            Pin(handler.FilterStart);
        }
        return pinned;

        void Pin(Instruction? boundary)
        {
            if (boundary is not null)
                pinned.Add(boundary);
        }
    }

    /// <summary>
    /// Confirms a single rewritten body is self-consistent: every branch, switch, and exception
    /// boundary points inside the body, and no reachable call has a null operand.
    /// </summary>
    /// <remarks>
    /// This mirrors the per-method half of <see cref="AssemblyVerifier"/> without walking the whole
    /// module, which keeps the pass linear rather than quadratic on large assemblies.
    /// </remarks>
    private static bool IsStructurallySound(MethodDef method)
    {
        var instructions = method.Body.Instructions;
        var present = instructions.ToHashSet();
        foreach (var instruction in instructions)
        {
            if (instruction.Operand is Instruction target && !present.Contains(target))
                return false;
            if (instruction.Operand is IList<Instruction> targets &&
                targets.Any(target => !present.Contains(target)))
                return false;
        }

        foreach (var handler in method.Body.ExceptionHandlers)
        {
            if (!BoundaryValid(handler.TryStart, present, allowEndOfMethod: false) ||
                !BoundaryValid(handler.TryEnd, present, allowEndOfMethod: true) ||
                !BoundaryValid(handler.HandlerStart, present, allowEndOfMethod: false) ||
                !BoundaryValid(handler.HandlerEnd, present, allowEndOfMethod: true) ||
                (handler.FilterStart is not null &&
                 !BoundaryValid(handler.FilterStart, present, allowEndOfMethod: false)))
            {
                return false;
            }
        }

        var reachable = CfgDeadCodePass.ComputeReachable(method);
        return !reachable.Any(instruction =>
            instruction.OpCode.FlowControl == FlowControl.Call && instruction.Operand is null);

        static bool BoundaryValid(Instruction? boundary, HashSet<Instruction> present, bool allowEndOfMethod)
        {
            if (boundary is null)
                return allowEndOfMethod;
            return present.Contains(boundary);
        }
    }
}

/// <summary>
/// Folds the constant branches that only became constant once the loader's state was folded into
/// the methods reading it.
/// </summary>
/// <remarks>
/// An opaque predicate collapses in two steps, and until now only the first could happen late. The
/// read of the loader's state becomes a literal, and then the branch on that literal becomes a jump
/// or nothing at all. The early run of this pass does both, but where the loader is virtualized the
/// first step waits on the interpreter's program being written out as IL, which happens long after.
/// Without a second run the module is left holding ninety-one branches on literals — <c>if (0 == 0)</c>
/// spelled out in the decompiler's output, which is a worse thing to hand an analyst than the field
/// read it replaced, that at least having looked like it meant something.
///
/// It runs before the last look for flattening rather than after, because folding these is what
/// makes the shape underneath them visible: a state assignment followed by an unconditional jump to
/// the switch is a flattener edge, and the same thing with a branch on a literal in between is not
/// anything the dispatcher pass will recognise.
/// </remarks>
public sealed class ControlFlowRecompletionPass : ControlFlowCompletionPass
{
    public override string Name => "control-flow-recompletion";

    public override IReadOnlyCollection<string> Dependencies => ["global-predicate-recheck"];
}
