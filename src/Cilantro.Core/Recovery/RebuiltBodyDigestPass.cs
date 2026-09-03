using dnlib.DotNet;
using Cilantro.Core.Analysis;

namespace Cilantro.Core.Recovery;

/// <summary>
/// Writes down what each rebuilt body reaches, where the person reading the body will see it.
/// </summary>
/// <remarks>
/// A body lifted out of a virtual program is correct and nearly unreadable. Its control flow is the
/// interpreter's jump table rather than anything a person wrote, every local is
/// <see cref="object"/> because the machine's slots were untyped, and the names around it are
/// whatever the protector generated. An analyst who opens it is looking at a page of state numbers
/// and casts with no way in.
///
/// There is a way in, and the tool already knows it. A protector renames what it generates but
/// cannot rename the framework, so the calls leaving the body still say
/// <c>SymmetricAlgorithm.CreateDecryptor</c> and <c>AssemblyName.GetPublicKeyToken</c> in full.
/// Reading those names off the body answers what it does in about a line, and reading them is
/// exactly what the tool is in a position to do while it has the module open. Leaving the analyst
/// to reconstruct it by hand, from information the run held and discarded, is the waste this pass
/// exists to stop.
///
/// It runs last of the rewrites on purpose. What calls a rebuilt method is not settled until cleanup
/// has finished deleting, and what anything is called is not settled until renaming has finished:
/// an account written before either one names members that are not in the file the reader opens.
/// That was a real defect — the report named the rebuilt method by a name renaming had already
/// replaced, so searching the cleaned copy for it found nothing.
/// </remarks>
public sealed class RebuiltBodyDigestPass : DeobfuscationPass
{
    /// <summary>How many members to name before summarising the rest as a count.</summary>
    /// <remarks>
    /// High enough that a real body lists everything it reaches. A tighter cap read better and cost
    /// the whole point of the list: the members are named in the order they sort, so cutting the
    /// list at a dozen dropped <c>SymmetricAlgorithm.CreateDecryptor</c> off the end of a body whose
    /// entire purpose was decryption, and kept <c>Convert.ToBoolean</c>. The cap survives only to
    /// stop a pathological body from writing a page into an attribute; the report is uncapped.
    /// </remarks>
    private const int MostToName = 40;

    public override string Name => "rebuilt-body-digest";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies =>
        ["rebuilt-body-cleanup", "runtime-cleanup", "symbol-renaming"];

    /// <summary>The account of each rebuilt body, for the report and the summary to pass on.</summary>
    internal const string DigestFact = "virtualization.rebuiltDigest";

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        var rebuilt = RebuiltMethods.Of(context);
        if (rebuilt.Count == 0)
            return (PassStatus.Success, 0, ["No body was built back, so there was none to describe."]);

        // Asked without the rebuilt methods as roots, so the answer is whether anything in the
        // cleaned copy actually calls them rather than whether the tool asked for them to be kept.
        var reachability = ModuleReachability.Compute(
            context.Module,
            typeInitializersAlwaysRun: false);

        var digests = new List<RebuiltMethodReport>(rebuilt.Count);
        foreach (var method in rebuilt)
        {
            var footprint = MethodBehaviour.Reached(method, context.Module);
            var reachable = reachability.IsReachable(method);
            var digest = new RebuiltMethodReport(
                method.FullName,
                footprint.Reaches,
                footprint.Writes,
                reachable,
                method.Body?.Instructions.Count ?? 0);
            digests.Add(digest);
            ReadingMarker.Redescribe(method, Said(digest));
            context.AddChange(new ChangeRecord(
                Name,
                "describe-rebuilt-body",
                $"{method.MDToken} {method.FullName}",
                $"Named the {footprint.Reaches.Count} member(s) the body reaches" +
                (reachable ? "." : ", and that nothing in the cleaned copy calls it.")));
        }

        context.SetFact<IReadOnlyList<RebuiltMethodReport>>(DigestFact, digests);
        var orphaned = digests.Count(digest => !digest.Reachable);
        var said = new List<string>
        {
            $"Described {digests.Count} rebuilt body(s) by the members they reach."
        };
        if (orphaned != 0)
        {
            said.Add(
                $"{orphaned} of them are called by nothing in the cleaned copy, recovery having " +
                "replaced what used to call them.");
        }

        return (PassStatus.Success, digests.Count, said);
    }

    /// <summary>
    /// The whole of what the attribute says: the warning, then the way in.
    /// </summary>
    private static string Said(RebuiltMethodReport digest)
    {
        var said = new List<string> { ReadingMarker.Warning };
        if (digest.Reaches.Count != 0)
            said.Add($"It reaches {Listed(digest.Reaches)}.");
        if (digest.Writes.Count != 0)
            said.Add($"It writes {Listed(digest.Writes)}.");
        if (!digest.Reachable)
        {
            said.Add(
                "Nothing in the cleaned copy calls it: what used to is gone, recovery having " +
                "replaced the code that needed it.");
        }

        return string.Join(" ", said);
    }

    private static string Listed(IReadOnlyList<string> members)
    {
        if (members.Count <= MostToName)
            return string.Join(", ", members);
        var named = string.Join(", ", members.Take(MostToName));
        return $"{named}, and {members.Count - MostToName} more";
    }
}
