using System.Text.Json;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using Cilantro.Core.Strings;
using Cilantro.Core.Verification;

namespace Cilantro.Core;

public sealed class StringRecoveryPass : DeobfuscationPass
{
    public override string Name => "string-recovery";
    public override IReadOnlyCollection<string> Dependencies =>
        ["delegate-proxy-analysis", "string-table-recovery"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var candidates = StringResolverCandidates.In(context.Module);
        if (candidates.Length == 0)
            return (PassStatus.Success, 0, ["No protected string resolver was detected."]);
        // A deferral is answered before the field is counted. Where reading the table was left to
        // after the engine's numbering is learned, there is no table here to restore from however
        // many candidates there are, and the one that matters is the one the later reading settles
        // on. Counting first reported a build whose strings were merely not read yet as a build whose
        // resolver could not be told apart, and did it in the pass that had nothing to do either way.
        if (!context.TryGetFact<CapturedStringTable>("strings.table", out var table) ||
            table is null)
        {
            if (context.TryGetFact<bool>("strings.deferred", out var deferred) && deferred)
            {
                return (PassStatus.Success, 0,
                [
                    "Reading the table was deferred to after the engine's numbering is learned, so " +
                        "the sites it accounts for are restored there and none are restored here."
                ]);
            }
            if (candidates.Length != 1)
                return (PassStatus.Unsupported, 0,
                    [$"Detected {candidates.Length} ambiguous string resolver candidates."]);
            return (PassStatus.Partial, 0,
                ["No unique captured string table is available; no call site was modified."]);
        }
        if (candidates.Length != 1)
            return (PassStatus.Unsupported, 0,
                [$"Detected {candidates.Length} ambiguous string resolver candidates."]);

        return Restore(context, Name, candidates[0], table);
    }

    /// <summary>
    /// Puts the strings back at every call site the table accounts for, all of them or none.
    /// </summary>
    /// <remarks>
    /// This is shared with the later reading rather than repeated by it. A table read once the
    /// engine's own numbering is known arrives after this pass has already run and found nothing to
    /// do, and the restoration it then needs is this one exactly: the same proof of each offset, the
    /// same all-or-nothing rewrite, and the same refusal to leave a resolver reference behind.
    /// </remarks>
    internal static (PassStatus, int, IReadOnlyList<string>) Restore(
        ArtifactContext context,
        string pass,
        MethodDef resolver,
        CapturedStringTable table)
    {
        var aliases = ResolverAliasAnalysis.Resolve(context.Module, resolver);
        var callSites = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody)
            .SelectMany(method => method.Body.Instructions
                .Select((instruction, index) => (Method: method, Instruction: instruction, Index: index)))
            .Where(item => item.Instruction.Operand is IMethod called &&
                called.ResolveMethodDef() is { } resolved &&
                aliases.Contains(resolved))
            .Where(item => !ResolverAliasAnalysis.IsInternalForwardingCall(item.Method, aliases))
            .ToArray();
        if (callSites.Length == 0)
            return (PassStatus.Success, 0, ["No reachable string resolver call sites were found."]);

        var replacements = new List<(MethodDef Method, Instruction Call, string Value)>();
        foreach (var site in callSites)
        {
            if (!StringOffsetSlicer.TryEvaluate(
                    site.Method, site.Index, table.IntegerFields,
                    out var offset, out var sliceDiagnostic))
            {
                return (PassStatus.Partial, 0,
                [
                    $"Could not prove resolver argument at {site.Method.MDToken} " +
                    $"IL_{site.Instruction.Offset:X4}: {sliceDiagnostic}.",
                    $"Proved {replacements.Count} of {callSites.Length} resolver offset(s).",
                    "The assembly-wide string rewrite was not started."
                ]);
            }
            var matchingRecords = table.Records.Where(record => record.Offset == offset).ToArray();
            if (matchingRecords.Length != 1)
            {
                return (PassStatus.Partial, 0,
                [
                    $"Resolver argument at {site.Method.MDToken} IL_{site.Instruction.Offset:X4} " +
                    $"evaluated to {offset}, which matched {matchingRecords.Length} strict record boundaries.",
                    $"Proved {replacements.Count} of {callSites.Length} resolver offset(s).",
                    "The assembly-wide string rewrite was not started."
                ]);
            }
            replacements.Add((site.Method, site.Instruction, matchingRecords[0].Value));
        }

        var result = Rewrite(context, pass, aliases, callSites.Length, replacements);
        if (result.Item1 == PassStatus.Success && result.Item2 != 0)
            RebuiltMethods.RememberReplacedStringResolver(context, resolver);
        // Preserve the decoder's exact input identity for later resource cleanup. A successful
        // table read alone is not enough: publish this only after the atomic rewrite commits.
        if (result.Item1 == PassStatus.Success && table.Resource is { } origin && context.Module.Resources.OfType<EmbeddedResource>().Any(origin.Matches))
        {
            context.TryGetFact<IReadOnlyList<Cilantro.Core.Analysis.RecoveredResourceOrigin>>("strings.validatedResources", out var prior);
            context.SetFact<IReadOnlyList<Cilantro.Core.Analysis.RecoveredResourceOrigin>>(
                "strings.validatedResources", (prior ?? []).Append(origin).Distinct().ToArray());
            if (result.Item2 != 0)
            {
                DecodedResourceOwnership.Remember(context, origin, aliases);
                ReactorStringCacheWriters.Remember(context, resolver, table);
            }
        }
        return result;
    }

    /// <summary>
    /// Turns every proven resolver call into the string it hands back, all of them or none.
    /// </summary>
    /// <remarks>
    /// Split out from the proving above because a table of bytes is not the only thing a proof can
    /// come from. Where the strings are kept somewhere no run of bytes describes, they are read by
    /// asking the resolver instead, and what is then owed is this: the same all-or-nothing rewrite,
    /// the same verification of the module before anything is committed. Calls whose initialization
    /// effects must survive are retained explicitly; otherwise no resolver reference may remain.
    /// </remarks>
    internal static (PassStatus, int, IReadOnlyList<string>) Rewrite(
        ArtifactContext context,
        string pass,
        IReadOnlyCollection<MethodDef> aliases,
        int callSiteCount,
        IReadOnlyList<(MethodDef Method, Instruction Call, string Value)> replacements,
        bool preserveCalls = false)
    {
        using var transactions = new BodyMutationBatch(replacements.Select(item => item.Method));
        try
        {
            foreach (var replacement in replacements)
            {
                var instructions = replacement.Method.Body.Instructions;
                var callIndex = instructions.IndexOf(replacement.Call);
                if (callIndex < 0)
                    throw new InvalidOperationException("Resolver call disappeared during rewrite.");
                if (preserveCalls)
                {
                    // Retain the original argument evaluation and exact initialization trigger.
                    instructions.Insert(callIndex + 1, Instruction.Create(OpCodes.Pop));
                    instructions.Insert(callIndex + 2, Instruction.Create(OpCodes.Ldstr, replacement.Value));
                    replacement.Method.Body.SimplifyBranches();
                    replacement.Method.Body.KeepOldMaxStack = false;
                    continue;
                }
                instructions.Insert(callIndex, Instruction.Create(OpCodes.Pop));
                replacement.Call.OpCode = OpCodes.Ldstr;
                replacement.Call.Operand = replacement.Value;
            }
            // Only explicitly retained calls and internal forwarding references may remain.
            var remaining = context.Module.GetTypes()
                .SelectMany(type => type.Methods)
                .Where(method => method.HasBody)
                .SelectMany(method => method.Body.Instructions
                    .Select(instruction => (Method: method, Instruction: instruction)))
                .Where(item => item.Instruction.Operand is IMethod called &&
                    called.ResolveMethodDef() is { } resolved &&
                    aliases.Contains(resolved))
                .Where(item => !ResolverAliasAnalysis.IsInternalForwardingCall(item.Method, aliases))
                .ToArray();
            var retained = preserveCalls ? replacements.Select(replacement => replacement.Call).ToHashSet() : [];
            if (preserveCalls
                ? remaining.Length != retained.Count || remaining.Any(site => !retained.Contains(site.Instruction))
                : remaining.Length != 0)
                throw new InvalidOperationException(
                    $"{remaining.Length} targeted resolver reference(s) remained after rewrite.");
            var verification = AssemblyVerifier.Verify(
                context.Module,
                context.OriginalIdentity,
                context.OriginalStructure);
            if (!verification.Passed)
                throw new InvalidOperationException(string.Join("; ", verification.Diagnostics));
            transactions.Commit();
        }
        catch (Exception exception)
        {
            transactions.Rollback();
            return (PassStatus.Failed, 0,
                [$"Atomic string rewrite was rolled back: {exception.Message}"]);
        }

        foreach (var replacement in replacements)
            context.AddChange(new ChangeRecord(
                pass,
                "restore-string",
                $"{replacement.Method.MDToken} IL_{replacement.Call.Offset:X4}",
                JsonSerializer.Serialize(replacement.Value)));
        // Added to rather than set, because a module can keep its strings in more than one place and
        // each reading accounts for its own sites. A count that overwrote would report the last
        // reading's work as the whole run's.
        context.TryGetFact<int>("strings.callSites", out var countedBefore);
        context.TryGetFact<int>("strings.replacedSites", out var restoredBefore);
        context.SetFact("strings.callSites", countedBefore + callSiteCount);
        context.SetFact("strings.replacedSites", restoredBefore + replacements.Count);
        // Every call the resolver and its aliases existed to serve is now an ldstr. The getter
        // is not the decoding machinery: the table it reads is filled by a sibling initializer,
        // and the cipher and reader behind both live on the same type. Naming only the methods
        // that lost their callers left that type standing, unattributed, which is the bulk of
        // what a strings-only build then still asked the reader to page through.
        if (!preserveCalls)
        {
            RecoveryOrphans.DeclareOwningTypes(context, aliases);
            RecoveredStringForwarders.Remember(context, aliases);
        }
        return (PassStatus.Success, replacements.Count,
            [$"Atomically restored all {replacements.Count} proven string sites." +
                (preserveCalls ? " Original calls were retained to preserve type initialization effects." : "")]);
    }
}
