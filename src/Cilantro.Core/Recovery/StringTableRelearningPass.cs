using dnlib.DotNet;
using Cilantro.Core.Analysis;
using Cilantro.Core.Passes;
using Cilantro.Core.Strings;

namespace Cilantro.Core.Recovery;

/// <summary>
/// Reads the string table again, this time with the numbering the engine itself gave up.
/// </summary>
/// <remarks>
/// The earlier reading has to assume a numbering, and on a build that renumbers its operations it
/// stops rather than misreads. The numbering could be learned instead — the semantics probe derives
/// it by making the engine perform each operation — but not there: learning it needs the engine's
/// proxy calls resolved, which needs the resources restored, which needs the strings. The
/// dependencies run in a circle, so no single ordering has both.
///
/// So the table is read twice rather than reordered: once early, cheaply, in case the numbering the
/// reading was written against is this build's too, and once here, where the engine has been read and
/// its own numbering is known. Only the second reading costs anything extra, and only on a build the
/// first could not read, because a build whose table was already captured is left alone.
///
/// What is restored is restored by the earlier pass's own code, so a string put back here is put
/// back under the same proof as one put back there: every call site's offset proven, every record
/// matched to exactly one boundary, and the rewrite abandoned whole if any part of it will not
/// verify.
/// </remarks>
public sealed class StringTableRelearningPass : DeobfuscationPass
{
    public override string Name => "string-table-relearning";

    /// <remarks>
    /// A reading that declines leaves the module exactly as it was, and one that restores strings
    /// either verifies or is rolled back and reported as a failure, which the pipeline already
    /// treats as fatal.
    /// </remarks>
    public override bool GatesEmission => false;

    /// <remarks>
    /// The disassembly is the dependency because its recovery is what learns the numbering. This
    /// also has to precede the cleanup that deletes the engine, which is what would otherwise take
    /// the resolver and its resource away before they could be read.
    /// </remarks>
    public override IReadOnlyCollection<string> Dependencies => ["virtualization-disassembly"];

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        if (context.TryGetFact<CapturedStringTable>("strings.table", out var already) &&
            already is not null)
        {
            return (PassStatus.Success, 0,
                ["The earlier reading already captured a table, so nothing was read again."]);
        }

        if (!context.TryGetFact<IReadOnlyList<VirtualProgram>>(
                "virtualization.programs", out var programs) ||
            programs is null ||
            programs.Count == 0)
        {
            return (PassStatus.Success, 0,
                ["No program was read back from the engine, so no numbering was learned."]);
        }

        var resolvers = StringResolverCandidates.In(context.Module);
        if (resolvers.Length == 0)
            return (PassStatus.Success, 0, ["No protected string resolver was detected."]);

        var diagnostics = new List<string>();
        var incomplete = false;
        // A shape is not a proof, so more than one method can look like the resolver, and which one
        // it is is settled by which one produces a table rather than by insisting beforehand that
        // only one looks the part. Declining instead left a build with eleven thousand protected
        // call sites unread because two application methods happened to take an int and return a
        // string, and neither of them so much as reads a resource.
        foreach (var resolver in resolvers)
        foreach (var program in programs)
        {
            if (program.Operations.Count == 0)
                continue;
            var reading = resolvers.Length == 1
                ? program.Method.Stub.Name.String
                : $"{resolver.Name} under {program.Method.Stub.Name}";
            if (!StaticStringTableInterpreter.TryCapture(
                    context.Module, context.OriginalImage, resolver, out var capture,
                    out var diagnostic, BootstrapMachine.Environment(context), program,
                    ProxyLoaderTable.Read(context)) ||
                capture is null)
            {
                diagnostics.Add($"{reading}: {diagnostic}");
                continue;
            }

            var table = StringTableRecoveryPass.MergeLoaderKeys(
                context,
                new CapturedStringTable(
                    capture.Source, capture.Bytes, capture.Records, capture.IntegerFields));
            diagnostics.Add(
                $"{reading}: {diagnostic} " +
                $"{capture.Records.Count} string(s), read under this build's own numbering.");

            // The rewrite is attempted before the table is recorded, because a table nothing was
            // rewritten from is not this module's table as far as anything after here is concerned:
            // a reading that cannot account for the call sites has not shown that the records belong
            // to them. Where it does account for them the fact is set, and the pass that reads it
            // next is reading a table whose every use has been proven.
            var (status, changes, said) = StringRecoveryPass.Restore(
                context, Name, resolver, table);
            // A rewrite that was never started is a decline; one that was started and rolled back is
            // a failure, and is reported as one — the module is as it was either way, but the second
            // says the reading was wrong rather than incomplete. A reading that could not account for
            // every use is not the end of the search either, because another candidate may account
            // for all of its own.
            if (status == PassStatus.Partial)
            {
                incomplete = true;
                diagnostics.AddRange(said);
                diagnostics.Add(
                    $"{reading}: the strings were left as they were. This reading restores what it " +
                    "can prove every use of, and it proved fewer than all of them.");
                continue;
            }

            context.SetFact("strings.table", table);
            context.AddEvidence(new Evidence(
                "string-table",
                $"Captured {capture.Records.Count} string(s) under the numbering the engine's own " +
                $"operations were read to have, from {capture.FrontEnd}.",
                capture.Source,
                1.0));
            return (status, changes, [.. diagnostics, .. said]);
        }

        if (incomplete)
            return (Owed(context), 0, diagnostics);

        return (Owed(context), 0,
        [
            .. diagnostics,
            "No string table was read under the numbering the engine gave up. The numbering covers " +
                "the operations the recovered program uses, and a table built by operations it does " +
                "not use needs those asked about as well."
        ]);
    }

    /// <summary>What a reading that got nowhere amounts to, which depends on what was asked of it.</summary>
    /// <remarks>
    /// Where the earlier reading captured the table, this one was only ever an opportunity to do
    /// better, and not doing better is not a failure — the strings are in hand either way. Where the
    /// earlier reading handed the table over because only this one could know the numbering, the
    /// strings are in nobody's hand, and this is the reading that has to say so. The alternative is
    /// a run in which two passes each point at the other and neither reports a gap.
    /// </remarks>
    private static PassStatus Owed(ArtifactContext context) =>
        context.TryGetFact<bool>("strings.deferred", out var deferred) && deferred
            ? PassStatus.Partial
            : PassStatus.Success;
}
