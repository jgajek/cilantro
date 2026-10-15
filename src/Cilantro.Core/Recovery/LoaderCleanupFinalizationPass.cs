namespace Cilantro.Core.Recovery;

/// <summary>Rechecks initialization after obsolete reconstructed consumers have actually gone.</summary>
public sealed class LoaderCleanupFinalizationPass : LoaderCallElisionPass
{
    internal const string ChangedFact = "cleanup.loaderFinalizationChanged";
    public override string Name => "loader-cleanup-finalization";
    public override IReadOnlyCollection<string> Dependencies => ["unused-reactor-pools"];

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(ArtifactContext context)
    {
        context.SetFact(ChangedFact, false);
        if (!context.TryGetFact<bool>("options.removeRuntime", out var enabled) || !enabled ||
            !context.Changes.Any(change => change.Kind == "remove-orphaned-rebuilt-method"))
            return (PassStatus.Success, 0, ["No removed reconstructed consumer requires a final loader check."]);

        // Do this after the existing initialization and dispatcher proofs, whose
        // input graph must retain reconstructed consumers until declaration cleanup.
        var calls = base.Execute(context);
        if (calls.Status != PassStatus.Success)
        {
            context.SetFact(ChangedFact, calls.Changes != 0);
            return calls;
        }
        var bodies = ElideBodiesPreservingInitialization(context);
        var changes = calls.Changes + bodies.Changes;
        context.SetFact(ChangedFact, changes != 0);
        return (bodies.Status, changes, [.. calls.Diagnostics, .. bodies.Diagnostics]);
    }
}

/// <summary>Deletes dependencies made unused by the final loader proof.</summary>
public sealed class LoaderRuntimeCleanupPass : RuntimeCleanupPass
{
    public override string Name => "loader-runtime-cleanup";
    public override IReadOnlyCollection<string> Dependencies => ["loader-cleanup-finalization"];
    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context) =>
        context.TryGetFact<bool>(LoaderCleanupFinalizationPass.ChangedFact, out var changed) && changed
            ? base.Execute(context)
            : (PassStatus.Success, 0, ["No final loader rewrite requires declaration cleanup."]);
}
