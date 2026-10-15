namespace Cilantro.Core.Passes;

/// <summary>Exposes contiguous caller expressions before closed type recovery.</summary>
public sealed class TypingPreparationPass : IlCompactionPass
{
    public override string Name => "typing-preparation";
    public override IReadOnlyCollection<string> Dependencies => ["shared-initializer-runtime-cleanup"];
}
