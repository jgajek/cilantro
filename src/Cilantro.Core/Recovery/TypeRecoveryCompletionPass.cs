using Cilantro.Core.Passes;

namespace Cilantro.Core.Recovery;

/// <summary>Rechecks closed type proofs after late control-flow and token cleanup.</summary>
public sealed class TypeRecoveryCompletionPass : DeobfuscationPass
{
    public override string Name => "type-recovery-completion";
    public override IReadOnlyCollection<string> Dependencies => ["token-runtime-cleanup"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        IDeobfuscationPass[] passes = [new TypeRestorationPass(addressedOnly: true), new ArrayParameterTypingPass(), new ReferenceParameterTypingPass(),
            new ArrayFieldTypingPass(), new ReferenceFieldTypingPass(), new ThisCastCompletionPass()];
        var changes = 0;
        var status = PassStatus.Success;
        var diagnostics = new List<string>();
        foreach (var pass in passes)
        {
            // An absent, disabled, unsupported or failed early pass must not be silently
            // enabled by this completion stage. In particular, preserve declaration skips.
            var previous = context.PassResults.LastOrDefault(result => result.Pass == pass.Name);
            if (previous?.Status is not (PassStatus.Success or PassStatus.Partial)) continue;
            var result = pass.Run(context);
            changes += result.Changes;
            diagnostics.AddRange(result.Diagnostics.Select(message => $"{pass.Name}: {message}"));
            if (result.Status == PassStatus.Failed) return (PassStatus.Failed, changes, diagnostics);
            if (result.Status != PassStatus.Success) status = PassStatus.Partial;
        }
        return (status, changes, diagnostics);
    }
}
