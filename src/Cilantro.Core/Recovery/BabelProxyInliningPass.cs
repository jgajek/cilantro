namespace Cilantro.Core.Recovery;

/// <summary>Revisits direct forwarders after verified Babel initialization retirement.</summary>
public sealed class BabelProxyInliningPass : MethodInliningPass
{
    public override string Name => "babel-proxy-inlining";
    public override IReadOnlyCollection<string> Dependencies => ["babel-proxy-initialization"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<int>(BabelProxyInitializationPass.RetiredFact, out var retired) || retired == 0 ||
            !context.TryGetFact<bool>("options.removeRuntime", out var enabled) || !enabled)
            return (PassStatus.Success, 0, ["No verified Babel initialization retirement requires forwarder completion."]);
        var first = base.Execute(context);
        if (first.Item1 is PassStatus.Failed or PassStatus.Unsupported) return first;
        var changes = BabelAdapterInlining.Run(context, out var diagnostic);
        return (first.Item1, first.Item2 + changes, [.. first.Item3, diagnostic]);
    }
}
