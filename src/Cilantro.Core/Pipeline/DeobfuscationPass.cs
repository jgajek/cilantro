namespace Cilantro.Core;

public interface IDeobfuscationPass
{
    string Name { get; }
    IReadOnlyCollection<string> Dependencies { get; }

    /// <summary>
    /// Whether an incomplete result from this pass must block emission.
    /// </summary>
    /// <remarks>
    /// Emission is gated on the emitted module being trustworthy, so a pass that provably never
    /// mutates the module cannot make it untrustworthy by declining. Side-artifact recovery
    /// (payloads, Costura assemblies, resource bundles) is therefore reported without withholding
    /// an otherwise fully verified assembly. Callers that want everything complete, artifacts
    /// included, ask for it with <see cref="PipelineOptions.FailOnPartial"/>.
    /// </remarks>
    bool GatesEmission { get; }

    PassResult Run(ArtifactContext context);
}

public abstract class DeobfuscationPass : IDeobfuscationPass
{
    public abstract string Name { get; }
    public virtual IReadOnlyCollection<string> Dependencies => [];
    public virtual bool GatesEmission => true;

    public PassResult Run(ArtifactContext context)
    {
        var started = DateTime.UtcNow;
        try
        {
            var (status, changes, diagnostics) = Execute(context);
            return new PassResult(Name, status, changes, diagnostics, DateTime.UtcNow - started);
        }
        catch (Exception ex)
        {
            return new PassResult(
                Name,
                PassStatus.Failed,
                0,
                [$"{ex.GetType().Name}: {ex.Message}"],
                DateTime.UtcNow - started);
        }
    }

    protected abstract (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context);
}
