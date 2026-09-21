using dnlib.DotNet;
using Cilantro.Core.Analysis;
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
        var foldedHelpers = new HashSet<MethodDef>();
        using (var transaction = new InstructionMutationTransaction())
        {
            folded = ConstantHelperFolding.Fold(
                rebuilt,
                ConstantHelperFolding.Catalog(context.Module),
                transaction,
                (method, instruction, value) => transaction.RecordChange(context, new ChangeRecord(
                    Name,
                    "fold-constant-helper",
                    $"{method.MDToken} IL_{instruction.Offset:X4}",
                    value.ToString())), foldedHelpers);

            var verification = AssemblyVerifier.Verify(context.Module);
            if (!verification.Passed)
            {
                transaction.Rollback();
                return (PassStatus.Partial, 0,
                    ["Folding the rebuilt bodies' constant helpers did not verify, and was undone."]);
            }
            transaction.Commit();
            RecoveryOrphans.Declare(context, foldedHelpers);
        }

        // Folding turns each of those calls into a constant a branch reads, which is the whole
        // reason to do it here: the fixed point below is what then removes the branch and the arm
        // nothing can now enter.
        var removed = 0;
        var completed = 0;
        var paths = 0;
        foreach (var method in rebuilt)
        {
            var methodFolded = 0;
            var methodRemoved = 0;
            var methodPaths = 0;
            // Rebuilt bodies arrive after the normal dispatcher passes.
            for (var round = 0; round <= 64; round++)
            {
                if (ControlFlowCompletionPass.TryComplete(method) is { } outcome)
                { methodFolded += outcome.Folded; methodRemoved += outcome.Removed; }
                if (round == 64) break;
                var changed = new DispatcherDeobfuscationPass().Rewrite(method).ChangedEdges;
                changed += DispatcherPathPass.Rewrite(method);
                if (changed == 0) break;
                methodPaths += changed;
            }
            if (methodFolded == 0 && methodRemoved == 0 && methodPaths == 0) continue;
            removed += methodRemoved;
            paths += methodPaths;
            completed++;
            context.AddChange(new ChangeRecord(Name, "complete-control-flow", $"{method.MDToken} {method.FullName}",
                $"Folded {methodFolded} branches, removed {methodRemoved} instructions and made {methodPaths} dispatcher paths direct."));
        }

        context.SetFact(FoldedFact, folded);
        context.SetFact(RemovedFact, removed);
        if (folded == 0 && removed == 0 && paths == 0)
        {
            return (PassStatus.Success, 0,
                [$"The {rebuilt.Count} rebuilt body(s) held nothing left to fold."]);
        }

        return (PassStatus.Success, folded + removed + paths,
        [
            $"Folded {folded} constant-helper call(s) and removed {removed} instruction(s) " +
            $"across {completed} of {rebuilt.Count} rebuilt body(s); made {paths} dispatcher paths direct."
        ]);
    }
}

/// <summary>The methods a run wrote a body into, found by the marker it put on each.</summary>
/// <remarks>
/// The marker is the key rather than the token because one of these methods may not have a token:
/// a program the interpreter was asked to run from a method that does other work is given a method
/// of its own, and a method made here has no row until the file is written. Its body is a reading
/// like any other and wants the same tidying and the same digest, so it has to be findable.
/// </remarks>
internal static class RebuiltMethods
{
    internal static IReadOnlyList<MethodDef> Of(ArtifactContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return
        [
            .. context.Module.GetTypes()
                .SelectMany(type => type.Methods)
                .Where(ReadingMarker.Marks)
                .OrderBy(method => method.MDToken.Raw)
                .ThenBy(method => method.FullName, StringComparer.Ordinal)
        ];
    }
}
