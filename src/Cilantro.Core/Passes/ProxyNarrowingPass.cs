using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Proxy;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Passes;

/// <summary>
/// Puts back the conversions the delegate-proxy adapters were doing, at the end of the run.
/// </summary>
/// <remarks>
/// The pass that bypassed the adapters worked out what each site would need; this emits it. The two
/// are separate on purpose. Reaching an argument under another one means putting the one above it
/// into a temporary, and a `stloc` between the arguments and the call is a shape the passes that
/// come after the proxies would have to read through: the interpreter that reads the module's string
/// table stops at the first thing it cannot model, and it models the call it was given, not one with
/// a spill in front of it. Two thousand sites of one payload go through that reading. So the
/// conversions wait until nothing is going to read the IL again except a verifier and a decompiler,
/// which are exactly the readers that need them.
/// </remarks>
public sealed class ProxyNarrowingPass : DeobfuscationPass
{
    public override string Name => "proxy-argument-narrowing";
    public override IReadOnlyCollection<string> Dependencies => ["delegate-proxy-analysis"];

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        if (!context.TryGetFact<IReadOnlyList<ProxyNarrowingSite>>("proxy.narrowings", out var sites) ||
            sites is null ||
            sites.Count == 0)
        {
            return (PassStatus.Success, 0,
                ["No restored proxy call site needed a conversion putting back."]);
        }

        var applied = 0;
        var gone = 0;
        var refused = 0;
        foreach (var group in sites.GroupBy(site => site.Method))
        {
            var method = group.Key;
            if (!method.HasBody)
            {
                gone += group.Count();
                continue;
            }

            using var transaction = new BodyMutationTransaction(method);
            var wasDisputed = EvaluationStackAnalyzer.Analyze(method).Diagnostics.Count;
            var here = 0;
            foreach (var site in group)
            {
                // A site the rest of the run deleted, folded away or turned into padding is not a
                // site any more, and the conversion it was going to get belonged to a call that is
                // no longer being made.
                if (site.Call.OpCode.FlowControl != FlowControl.Call ||
                    method.Body.Instructions.IndexOf(site.Call) < 0)
                {
                    gone++;
                    continue;
                }

                ProxyArgumentNarrowing.Apply(method, site.Call, site.Narrowing);
                here++;
            }

            if (here == 0)
            {
                transaction.Rollback();
                continue;
            }
            if (EvaluationStackAnalyzer.Analyze(method).Diagnostics.Count > wasDisputed)
            {
                transaction.Rollback();
                refused += here;
                continue;
            }

            transaction.Commit();
            applied += here;
            context.AddChange(new ChangeRecord(
                Name,
                "narrow-proxy-arguments",
                $"{method.MDToken} {method.FullName}",
                $"Put back the conversion {here} bypassed adapter(s) were doing."));
        }

        var said = new List<string>
        {
            $"Put back the conversion {applied} bypassed adapter(s) were doing."
        };
        if (gone != 0)
        {
            said.Add(
                $"{gone} site(s) were no longer making the call by the time the run reached here, " +
                "so nothing was emitted for them.");
        }
        if (refused != 0)
        {
            said.Add(
                $"{refused} site(s) were left as they were, the temporaries they need leaving the " +
                "paths into a block disagreeing about the stack.");
        }

        context.SetFact("proxy.narrowedCallSites", applied);
        return (PassStatus.Success, applied, said);
    }
}
