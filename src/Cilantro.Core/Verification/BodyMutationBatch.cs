using dnlib.DotNet;

namespace Cilantro.Core.Verification;

/// <summary>Commits or restores a group of method bodies and their pending change records together.</summary>
internal sealed class BodyMutationBatch : IDisposable
{
    private readonly Dictionary<MethodDef, BodyMutationTransaction> bodies = new(ReferenceEqualityComparer.Instance);
    private readonly List<(ArtifactContext Context, ChangeRecord Change)> changes = [];
    private bool completed;

    public BodyMutationBatch(IEnumerable<MethodDef>? methods = null)
    {
        foreach (var method in methods ?? [])
            Capture(method);
    }

    public void Capture(MethodDef method)
    {
        ObjectDisposedException.ThrowIf(completed, this);
        if (!bodies.ContainsKey(method))
            bodies.Add(method, new BodyMutationTransaction(method));
    }

    public void RecordChange(ArtifactContext context, ChangeRecord change)
    {
        ObjectDisposedException.ThrowIf(completed, this);
        changes.Add((context, change));
    }

    public void Commit()
    {
        if (completed)
            return;
        foreach (var body in bodies.Values)
            body.Commit();
        foreach (var (context, change) in changes)
            context.AddChange(change);
        Complete();
    }

    public void Rollback()
    {
        if (completed)
            return;
        foreach (var body in bodies.Values)
            body.Rollback();
        Complete();
    }

    private void Complete()
    {
        completed = true;
        bodies.Clear();
        changes.Clear();
    }

    public void Dispose() => Rollback();
}
