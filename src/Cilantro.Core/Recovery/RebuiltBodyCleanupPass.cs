using dnlib.DotNet;
using dnlib.DotNet.Emit;
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
    private const string ElidedLoaderSubtreeFact = "cleanup.provenElidedLoaderSubtree";
    private const string ReplacedStringResolverFact = "cleanup.provenReplacedStringResolver";
    private const string ResolverCleanupEnabledFact = "cleanup.rebuiltResolverRemovalEnabled";

    internal static void EnableResolverCleanup(ArtifactContext context) => context.SetFact(ResolverCleanupEnabledFact, true);

    internal static void RememberReplacedStringResolver(ArtifactContext context, MethodDef resolver)
    {
        // Unlike broad owning-type attribution, follow only actual dependencies
        // of the resolver whose final call was replaced. Sibling methods and
        // calls into application types do not acquire cleanup permission.
        var visited = new HashSet<MethodDef>();
        var pending = new Stack<MethodDef>();
        pending.Push(resolver);
        while (pending.TryPop(out var method))
        {
            if (method.DeclaringType != resolver.DeclaringType || !visited.Add(method) || !method.HasBody) continue;
            foreach (var instruction in method.Body.Instructions)
                if (instruction.OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj &&
                    instruction.Operand is IMethod called && called.ResolveMethodDef() is { } target)
                    pending.Push(target);
        }
        if (!context.TryGetFact<HashSet<MethodDef>>(ReplacedStringResolverFact, out var known) || known is null)
            context.SetFact(ReplacedStringResolverFact, known = []);
        known.UnionWith(visited);
    }

    internal static string? CleanupAttribution(ArtifactContext context, MethodDef method)
    {
        if (context.TryGetFact<HashSet<MethodDef>>(ElidedLoaderSubtreeFact, out var loader) && loader?.Contains(method) == true)
            return "a proven elided loader subtree";
        if (context.TryGetFact<HashSet<MethodDef>>(ReplacedStringResolverFact, out var resolver) && resolver?.Contains(method) == true)
            return "the direct dependencies of a fully replaced string resolver";
        return null;
    }

    internal static void RememberElidedLoaderSubtree(ArtifactContext context, IEnumerable<MethodDef> methods)
    {
        if (!context.TryGetFact<HashSet<MethodDef>>(ElidedLoaderSubtreeFact, out var known) || known is null)
            context.SetFact(ElidedLoaderSubtreeFact, known = []);
        known.UnionWith(methods);
    }

    internal static IReadOnlyCollection<MethodDef> ElidedLoaderMethods(ArtifactContext context) =>
        context.TryGetFact<HashSet<MethodDef>>(ElidedLoaderSubtreeFact, out var methods) && methods is not null ? methods : [];
    /// <summary>
    /// Reconstruction preserves application bodies as roots. A body whose original
    /// consumer recovery positively orphaned may instead undergo ordinary cleanup.
    /// This changes root policy only; visibility, reachability and reference checks
    /// still decide whether the body can actually be removed.
    /// </summary>
    internal static IReadOnlyList<MethodDef> CleanupRoots(ArtifactContext context)
        => Of(context).Except(CleanupCandidates(context)).ToArray();

    internal static IReadOnlySet<MethodDef> CleanupCandidates(ArtifactContext context)
    {
        var methods = Of(context);
        var orphans = RecoveryOrphans.Of(context);
        var attributed = new HashSet<MethodDef>();
        context.TryGetFact<bool>(ResolverCleanupEnabledFact, out var resolverCleanupEnabled);
        context.TryGetFact<HashSet<MethodDef>>(ElidedLoaderSubtreeFact, out var elided);
        attributed.UnionWith(methods.Where(method =>
            (elided?.Contains(method) == true ||
                resolverCleanupEnabled && CleanupAttribution(context, method) is not null) &&
            method.Rid != 0 && orphans.Contains(method.MDToken.Raw)));
        if (context.TryGetFact<IReadOnlyList<VirtualizationRebuildPass.LiftedRecipe>>(
                VirtualizationRebuildPass.LiftedRecipesFact, out var recipes) && recipes is not null)
        {
            foreach (var recipe in recipes.Where(recipe => methods.Contains(recipe.Holder) &&
                         (recipe.Caller & 0x00ffffff) != 0 && orphans.Contains(recipe.Caller)))
            {
                // Keep object identity: new bodies all report token zero, and assigning
                // a row here would alter the original-token verification contract.
                attributed.Add(recipe.Holder);
            }
        }
        return attributed;
    }

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
