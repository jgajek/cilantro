using dnlib.DotNet;
using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Passes;

/// <summary>
/// Puts the state a dispatcher was handed on the stack into a local, wherever folding its entry edge
/// left a block whose depth a single forward pass cannot name.
/// </summary>
/// <remarks>
/// This runs last among the passes that change IL, and it repairs rather than refuses. The
/// alternative was tried: making the folding passes undo any rewrite that strands a dispatcher head
/// costs about seven in ten of the redirected edges on every sample, which is most of what the tool
/// is for. The stranding is not a reason to keep a dispatcher — it is one instruction's worth of
/// bookkeeping about where the state lives, and moving it into a local is what the compiler would
/// have done before the protector took it out.
///
/// Nothing reports these bodies. ILVerify reads them without complaint and they run, because the
/// metadata writer, unable to make its own forward pass over the body, quietly writes whatever max
/// stack the protected body arrived with — which is large enough for now and for no stated reason.
/// The writer's complaints are in the report since this run, and this pass is why there are none.
/// </remarks>
public sealed class StackHandoffPass : DeobfuscationPass
{
    public override string Name => "stack-handoff";

    public override IReadOnlyCollection<string> Dependencies => ["dispatcher-deobfuscation"];

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        var repaired = 0;
        var bodies = 0;
        var left = 0;
        foreach (var type in context.Module.GetTypes())
        foreach (var method in type.Methods)
        {
            if (!method.HasBody || method.Body.Instructions.Count == 0)
                continue;
            var unnamed = ForwardScan.Unnamed(method);
            if (unnamed.Count == 0)
                continue;

            using var transaction = new BodyMutationTransaction(method);
            var here = 0;
            foreach (var head in unnamed)
            {
                if (StackHandoff.Repair(method, head))
                    here++;
            }

            var over = ForwardScan.Unnameable(method);
            if (here == 0 || over != 0)
            {
                // A method still holding one of these is a method this pass does not understand, and
                // half a repair is worse than none: it is the same body with a local added.
                transaction.Rollback();
                left += unnamed.Count;
                continue;
            }

            transaction.Commit();
            repaired += here;
            bodies++;
            context.AddChange(new ChangeRecord(
                Name,
                "hand-state-over-in-a-local",
                $"{method.MDToken} {method.FullName}",
                $"Moved into a local the state {here} block(s) were handed on the stack."));
        }

        var said = new List<string>();
        said.Add(repaired == 0
            ? "No block was handed its state on the stack."
            : $"Moved into a local the state {repaired} block(s) of {bodies} method(s) were handed " +
              "on the stack, which is what lets a single forward pass name the depth there.");
        if (left != 0)
        {
            said.Add(
                $"{left} block(s) were left as they were, this pass having nothing to say about " +
                "what they are handed.");
        }

        context.SetFact("stack.handedOverInLocals", repaired);
        return (PassStatus.Success, repaired, said);
    }
}
