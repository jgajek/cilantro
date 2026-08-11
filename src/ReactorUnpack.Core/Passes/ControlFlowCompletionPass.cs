using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core.Verification;

namespace ReactorUnpack.Core.Passes;

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
public sealed class ControlFlowCompletionPass : DeobfuscationPass
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

        context.SetFact("cfg.constantBranchesFolded", foldedTotal);
        context.SetFact("cfg.unreachableInstructionsRemoved", removedTotal);
        return (PassStatus.Success, foldedTotal + removedTotal,
        [
            $"Folded {foldedTotal} constant branch(es) and removed {removedTotal} unreachable " +
            $"instruction(s) across {rewrittenMethods} method(s)."
        ]);
    }

    /// <summary>
    /// Runs the fold/delete fixed point for one method under a rollback transaction.
    /// </summary>
    private static (int Folded, int Removed)? TryComplete(MethodDef method)
    {
        using var transaction = new BodyMutationTransaction(method);
        var folded = 0;
        var removed = 0;
        try
        {
            for (var round = 0; round < MaximumRounds; round++)
            {
                var foldedThisRound = FoldConstantBranches(method);
                var removedThisRound = RemoveUnreachable(method);
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
    /// Only the leaf shapes are handled: a boolean branch preceded immediately by an integer
    /// constant, and a switch preceded immediately by one. These are exactly the opaque-predicate
    /// forms Reactor emits, and each rewrite is stack-neutral because the constant the branch would
    /// have consumed is removed with it.
    /// </remarks>
    private static int FoldConstantBranches(MethodDef method)
    {
        var instructions = method.Body.Instructions;
        var folded = 0;
        for (var index = 1; index < instructions.Count; index++)
        {
            var branch = instructions[index];
            var producer = instructions[index - 1];
            if (!producer.IsLdcI4())
                continue;
            var value = producer.GetLdcI4Value();
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
                case Code.Switch when branch.Operand is IList<Instruction> cases:
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
