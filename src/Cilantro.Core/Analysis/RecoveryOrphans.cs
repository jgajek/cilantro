using dnlib.DotNet;

namespace Cilantro.Core.Analysis;

/// <summary>
/// The methods recovery left without a caller, recorded by the pass that took the last one away.
/// </summary>
/// <remarks>
/// Cleanup needs to tell the protector's scaffolding apart from the program's own code, and
/// unreachability alone does not do it: a program can perfectly well contain an internal helper
/// nothing happens to call, and deleting that would be a change to the program rather than the
/// removal of an obfuscation. Nothing in the metadata marks who emitted a method either, so the
/// distinction has to come from somewhere else.
///
/// It comes from what recovery did. When a pass replaces a resolver call with the string it would
/// have returned, or redirects a call past a forwarder, it has both proved the target is the
/// protector's and destroyed the reason it existed. The pass that made a method pointless is
/// therefore the one that records it here, and cleanup removes only what has been recorded, so the
/// program's own unused code survives untouched.
/// </remarks>
public static class RecoveryOrphans
{
    private const string FactKey = "cleanup.orphanedMethods";

    /// <summary>
    /// Records that <paramref name="methods"/> exist only to serve uses recovery has removed.
    /// </summary>
    public static void Declare(ArtifactContext context, IEnumerable<MethodDef> methods)
    {
        if (!context.TryGetFact<HashSet<uint>>(FactKey, out var orphans) || orphans is null)
        {
            orphans = [];
            context.SetFact(FactKey, orphans);
        }
        foreach (var method in methods)
            orphans.Add(method.MDToken.Raw);
    }

    public static void Declare(ArtifactContext context, MethodDef method) =>
        Declare(context, [method]);

    /// <summary>
    /// Records <paramref name="roots"/> and everything they call, transitively.
    /// </summary>
    /// <remarks>
    /// A resolver is never alone: it has a table decoder, a cipher, a resource reader, and those
    /// exist for it alone. Declaring the subtree says the whole apparatus lost its purpose, which
    /// is the same claim as for the root and rests on the same evidence.
    ///
    /// Over-reaching here is contained by the caller. Attribution is necessary for a declaration to
    /// be removed but never sufficient, so naming a method that something else still calls changes
    /// nothing: reachability keeps it.
    /// </remarks>
    public static void DeclareSubtree(ArtifactContext context, IEnumerable<MethodDef> roots)
    {
        var visited = new HashSet<MethodDef>();
        var pending = new Queue<MethodDef>(roots);
        while (pending.Count != 0)
        {
            var method = pending.Dequeue();
            if (!visited.Add(method) || !method.HasBody)
                continue;
            foreach (var instruction in method.Body.Instructions)
            {
                if (instruction.Operand is IMethod called &&
                    called.ResolveMethodDef() is { } target &&
                    target.Module == method.Module)
                {
                    pending.Enqueue(target);
                }
            }
        }
        Declare(context, visited);
    }

    public static IReadOnlySet<uint> Of(ArtifactContext context) =>
        context.TryGetFact<HashSet<uint>>(FactKey, out var orphans) && orphans is not null
            ? orphans
            : new HashSet<uint>();
}
