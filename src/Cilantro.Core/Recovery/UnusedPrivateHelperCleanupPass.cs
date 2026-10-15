namespace Cilantro.Core.Recovery;

/// <summary>Prunes unused private application helpers without attributing them to Reactor.</summary>
public sealed class UnusedPrivateHelperCleanupPass : RuntimeCleanupPass
{
    public override string Name => "unused-private-helper-cleanup";
    public override IReadOnlyCollection<string> Dependencies => ["shared-initializer-runtime-cleanup"];
    protected override bool PruneUnusedPrivateHelpers => true;
}
