namespace Cilantro.Core.Recovery;

/// <summary>Deletes string helpers whose ownership was proved after the first runtime cleanup.</summary>
public sealed class StringRuntimeCleanupPass : RuntimeCleanupPass
{
    public override string Name => "string-runtime-cleanup";
    public override IReadOnlyCollection<string> Dependencies => ["string-lookup-finalization"];
    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context) =>
        context.TryGetFact<bool>(StringLookupFinalizationPass.ChangedFact, out var changed) && changed
            ? base.Execute(context)
            : (PassStatus.Success, 0, ["No newly completed string helpers require declaration cleanup."]);
}
