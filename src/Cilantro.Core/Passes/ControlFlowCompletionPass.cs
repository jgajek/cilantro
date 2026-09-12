using dnlib.DotNet;
using dnlib.DotNet.Emit;
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
        try
        {
            for (var round = 0; round < MaximumRounds; round++)
            {
                var foldedThisRound = FoldConstantBranches(method);
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
    /// Only the leaf shapes are handled: a boolean branch preceded immediately by a constant, and
    /// a switch preceded immediately by an integer one. These are exactly the opaque-predicate
    /// forms Reactor emits, and each rewrite is stack-neutral because the constant the branch would
    /// have consumed is removed with it.
    ///
    /// A null constant decides a boolean branch as surely as a zero does, a reference being true
    /// exactly when it is not null. It cannot decide a switch, carrying no case number.
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
    /// </remarks>
    private static Instruction? Feeding(
        IList<Instruction> instructions,
        Dictionary<Instruction, int> entered,
        int index)
    {
        // The consumer and everything stepped over on the way back to the push.
        var path = new List<Instruction> { instructions[index] };
        var at = index;
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
