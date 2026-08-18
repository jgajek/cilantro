namespace ReactorUnpack.Core.Analysis;

/// <summary>The protector lineages this tool understands.</summary>
public enum ProtectorFamily
{
    None,
    Reactor,

    /// <summary>The Confuser/ConfuserEx lineage.</summary>
    Confuser
}

/// <summary>Which protector the run is dealing with, and how sure it is.</summary>
public sealed record ProtectorIdentity(
    ProtectorFamily Family,
    string Name,
    string Generation,
    double Confidence,
    IReadOnlyList<string> Capabilities)
{
    public static ProtectorIdentity Unrecognized { get; } =
        new(ProtectorFamily.None, "unrecognized", "unknown", 0, []);

    public bool Recognized => Family != ProtectorFamily.None;
}

/// <summary>
/// Settles which protector the module is under, so that one detector saying "not mine" is not
/// mistaken for the run having failed to recognize anything.
/// </summary>
/// <remarks>
/// Each detector answers about its own protector, and with more than one of them every run has at
/// least one detector that declines. Whether the run knows what it is looking at is therefore a
/// question about all of them together, and it is the answer to that question — not to any single
/// detector's — that decides whether a cleaned copy can be written.
/// </remarks>
public sealed class ProtectorIdentityPass : DeobfuscationPass
{
    public const string Fact = "protector.identity";

    public override string Name => "protector-identity";
    public override IReadOnlyCollection<string> Dependencies =>
        ["reactor-detection", "confuserex-detection"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var identity = Identify(context);
        context.SetFact(Fact, identity);
        if (!identity.Recognized)
        {
            return (PassStatus.Unsupported, 0,
                ["No supported protector was recognized in this module."]);
        }

        // Recorded as its own entry so that a reader of the report, and the summary that reads the
        // same evidence, get the protector's name rather than having to infer it from capabilities.
        context.AddEvidence(new Evidence(
            "protector-name",
            identity.Name,
            Confidence: identity.Confidence));
        return (PassStatus.Success, 0,
        [
            $"Protector: {identity.Name}",
            $"Detection confidence: {identity.Confidence:P0}",
            $"Capabilities: {string.Join(", ", identity.Capabilities)}"
        ]);
    }

    private static ProtectorIdentity Identify(ArtifactContext context)
    {
        context.TryGetFact<ReactorStructureFacts>("reactor.structure", out var reactor);
        context.TryGetFact<ConfuserExStructureFacts>("confuserex.structure", out var confuser);
        var reactorScore = reactor?.IsReactor6 == true ? reactor.Confidence : 0;
        var confuserScore = confuser?.IsConfuserExProtected == true ? confuser.Confidence : 0;

        if (confuserScore > reactorScore && confuser is not null)
        {
            return new ProtectorIdentity(
                ProtectorFamily.Confuser,
                "ConfuserEx",
                "confuserex-1.0",
                confuser.Confidence,
                confuser.CapabilityNames);
        }
        if (reactorScore > 0 && reactor is not null)
        {
            return new ProtectorIdentity(
                ProtectorFamily.Reactor,
                ".NET Reactor",
                reactor.Generation,
                reactor.Confidence,
                reactor.CapabilityNames);
        }
        return ProtectorIdentity.Unrecognized;
    }
}
