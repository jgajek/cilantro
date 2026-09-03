using dnlib.DotNet;
using Cilantro.Core.Passes;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Recovery;

/// <summary>
/// Gives a body built back from a virtualized method the cleanup every other body already had.
/// </summary>
/// <remarks>
/// Everything that makes a recovered assembly readable happens in the first half of the run:
/// constant helpers are folded, opaque branches collapse, unreachable junk goes. A virtualized
/// method is not a body at that point — it is a stub in front of an interpreter — so none of it
/// reaches the code that eventually goes there. The body arrives at the rebuild, near the end,
/// carrying every call to a constant helper the protector wrote into the program and every branch
/// those calls decide, and then the run finishes and hands it to a reader in that state.
///
/// That was the one body in the cleaned copy no pass had ever looked at, and it read like it. This
/// pass closes that gap by folding the same helpers and running the same fold-and-delete fixed
/// point, over the rebuilt bodies alone: the rest of the module was done long ago and is not
/// disturbed this late in a run for no reason.
///
/// A rebuilt body is a reading rather than a recovery, so the cleanup is held to the same standard
/// as everywhere else and no further: the folding is captured and rolled back if the module stops
/// verifying, and the fixed point keeps its own per-method transaction. What survives is what was
/// provable about a body that was itself never proved, which is the honest position to leave it in.
/// </remarks>
public sealed class RebuiltBodyCleanupPass : DeobfuscationPass
{
    public override string Name => "rebuilt-body-cleanup";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => ["virtualization-rebuild"];

    /// <summary>How many constant-helper calls the rebuilt bodies turned out to hold.</summary>
    internal const string FoldedFact = "virtualization.rebuiltCallsFolded";

    /// <summary>How many instructions went with them, once nothing reached them.</summary>
    internal const string RemovedFact = "virtualization.rebuiltInstructionsRemoved";

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        var rebuilt = RebuiltMethods.Of(context);
        if (rebuilt.Count == 0)
        {
            return (PassStatus.Success, 0,
                ["No body was built back, so there was none to clean up."]);
        }

        var folded = 0;
        using (var transaction = new InstructionMutationTransaction())
        {
            folded = ConstantHelperFolding.Fold(
                rebuilt,
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
                return (PassStatus.Partial, 0,
                    ["Folding the rebuilt bodies' constant helpers did not verify, and was undone."]);
            }
            transaction.Commit();
        }

        // Folding turns each of those calls into a constant a branch reads, which is the whole
        // reason to do it here: the fixed point below is what then removes the branch and the arm
        // nothing can now enter.
        var removed = 0;
        var completed = 0;
        foreach (var method in rebuilt)
        {
            var outcome = ControlFlowCompletionPass.TryComplete(method);
            if (outcome is null || (outcome.Value.Folded == 0 && outcome.Value.Removed == 0))
                continue;
            removed += outcome.Value.Removed;
            completed++;
            context.AddChange(new ChangeRecord(
                Name,
                "complete-control-flow",
                $"{method.MDToken} {method.FullName}",
                $"Folded {outcome.Value.Folded} constant branch(es) and removed " +
                $"{outcome.Value.Removed} unreachable instruction(s) from a rebuilt body."));
        }

        context.SetFact(FoldedFact, folded);
        context.SetFact(RemovedFact, removed);
        if (folded == 0 && removed == 0)
        {
            return (PassStatus.Success, 0,
                [$"The {rebuilt.Count} rebuilt body(s) held nothing left to fold."]);
        }

        return (PassStatus.Success, folded + removed,
        [
            $"Folded {folded} constant-helper call(s) and removed {removed} instruction(s) " +
            $"across {completed} of {rebuilt.Count} rebuilt body(s)."
        ]);
    }
}

/// <summary>The methods a run wrote a body into, resolved back from the tokens it recorded.</summary>
internal static class RebuiltMethods
{
    internal static IReadOnlyList<MethodDef> Of(ArtifactContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (!context.TryGetFact<IReadOnlySet<uint>>(
                VirtualizationRebuildPass.RebuiltFact, out var tokens) ||
            tokens is null)
        {
            return [];
        }

        return
        [
            .. tokens
                .OrderBy(token => token)
                .Select(token => context.Module.ResolveToken(token) as MethodDef)
                .Where(method => method is not null)
                .Select(method => method!)
        ];
    }
}
