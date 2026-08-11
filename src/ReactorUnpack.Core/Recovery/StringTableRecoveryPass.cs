using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core.Interpretation;
using ReactorUnpack.Core.Strings;

namespace ReactorUnpack.Core.Recovery;

public sealed record CapturedStringTable(
    string Source,
    byte[] Bytes,
    IReadOnlyList<DecodedStringRecord> Records,
    IReadOnlyDictionary<uint, int> IntegerFields);

public sealed class StringTableRecoveryPass : DeobfuscationPass
{
    public override string Name => "string-table-recovery";
    public override IReadOnlyCollection<string> Dependencies => ["method-body-recovery"];

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        var resolvers = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody &&
                method.IsStatic &&
                method.ReturnType.ElementType == ElementType.String &&
                method.MethodSig?.Params.Count == 1 &&
                method.MethodSig.Params[0].ElementType == ElementType.I4 &&
                (method.Body.Instructions.Any(instruction =>
                    instruction.Operand is IMethod called &&
                    called.Name == "GetManifestResourceStream") ||
                 method.Body.Instructions.Any(instruction =>
                    instruction.OpCode.Code == dnlib.DotNet.Emit.Code.Ldsfld &&
                    instruction.Operand is IField field &&
                    field.FieldSig?.Type.ElementType is ElementType.SZArray or ElementType.Object)))
            .ToArray();
        if (resolvers.Length == 0)
            return (PassStatus.Success, 0, ["No protected string resolver was detected."]);
        if (resolvers.Length != 1)
            return (PassStatus.Partial, 0,
                [$"Detected {resolvers.Length} ambiguous protected string resolvers.",
                 "No string call site was modified."]);

        if (!context.TryGetFact<bool>("method-protection.complete", out var methodsComplete) ||
            !methodsComplete)
        {
            return (PassStatus.Partial, 0,
            [
                "String-table initialization was deferred because method-protection.complete is not true.",
                "ReasonLabs tables are never captured from unrestored protected initializers.",
                "No string call site was modified."
            ]);
        }

        var resolver = resolvers[0];
        var aliases = ResolverAliasAnalysis.Resolve(context.Module, resolver);
        var references = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody)
            .SelectMany(method => method.Body.Instructions.Select(instruction =>
                (Method: method, Instruction: instruction)))
            .Where(item => item.Instruction.Operand is IMethod called &&
                called.ResolveMethodDef() is { } resolved &&
                aliases.Contains(resolved))
            // The forwarding call inside an alias passes that alias's own parameter, so it is
            // accounted for by the alias's call sites rather than on its own.
            .Where(item => !ResolverAliasAnalysis.IsInternalForwardingCall(item.Method, aliases))
            .ToArray();
        var directCalls = references.Where(item =>
                item.Instruction.OpCode.Code is Code.Call or Code.Callvirt)
            .ToArray();
        if (directCalls.Length != references.Length)
        {
            return (PassStatus.Partial, 0,
            [
                $"Resolver accounting found {references.Length - directCalls.Length} non-call reference(s).",
                "Delegate or indirect resolver uses cannot be proven complete.",
                "No string call site was modified."
            ]);
        }

        var candidates = new List<CapturedStringTable>();
        var interpreterDiagnostic = string.Empty;
        if (StaticStringTableInterpreter.TryCapture(
                context.Module,
                context.OriginalImage,
                resolver,
                out var interpreted,
                out interpreterDiagnostic) &&
            interpreted is not null)
        {
            candidates.Add(new CapturedStringTable(
                interpreted.Source,
                interpreted.Bytes,
                interpreted.Records,
                interpreted.IntegerFields));
        }

        if (candidates.Count != 1)
        {
            if (PayloadResourceCodec.TryGetProfile(context.OriginalSha256, out _))
            {
                return (PassStatus.Success, 0,
                    ["Legacy profiled sample retains its regression-locked string strategy."]);
            }
            return (PassStatus.Partial, 0,
            [
                candidates.Count == 0
                    ? $"No unique pristine UTF-16 string table was statically captured: {interpreterDiagnostic}"
                    : $"Preserved {candidates.Count} ambiguous framed string-table candidates.",
                "No string call site was modified."
            ]);
        }

        var table = MergeLoaderKeys(context, candidates[0]);
        context.SetFact("strings.table", table);
        context.SetFact("strings.tableRecords", table.Records.Count);
        context.SetFact("strings.resolverToken", resolver.MDToken.Raw);
        context.SetFact("strings.expectedUses", directCalls.Length);
        context.SetFact<IReadOnlyList<uint>>(
            "strings.resolverAliases",
            aliases.Where(alias => alias != resolver).Select(alias => alias.MDToken.Raw).ToArray());
        context.AddEvidence(new Evidence(
            "string-table",
            $"Captured {table.Records.Count} strictly framed UTF-16 strings with " +
            $"{directCalls.Length} completely accounted resolver use(s).",
            table.Source,
            0.95));
        return (PassStatus.Success, 0,
            [$"Captured {table.Records.Count} strings from {table.Source}.",
             $"Accounted for all {directCalls.Length} direct resolver use(s).",
             $"Captured {table.IntegerFields.Count} unique VM-initialized integer field(s)."]);
    }

    /// <summary>
    /// Folds the loader-initialized resolver keys recovered while restoring method bodies into
    /// the captured table.
    /// </summary>
    /// <remarks>
    /// The string-table initializer only populates the table itself. The per-site XOR keys live
    /// in instance fields seeded by the JIT-hook bootstrap, so on those samples the two halves
    /// of the proof are produced by two different interpretations. A key captured by both must
    /// agree, otherwise it is dropped and its call sites stay unproven.
    /// </remarks>
    private static CapturedStringTable MergeLoaderKeys(
        ArtifactContext context,
        CapturedStringTable table)
    {
        if (!context.TryGetFact<IReadOnlyDictionary<uint, int>>(
                "bootstrap.integerFields", out var bootstrapKeys) ||
            bootstrapKeys is null ||
            bootstrapKeys.Count == 0)
        {
            return table;
        }

        var merged = new Dictionary<uint, int>(table.IntegerFields);
        foreach (var entry in bootstrapKeys)
        {
            if (merged.TryGetValue(entry.Key, out var existing))
            {
                if (existing != entry.Value)
                    merged.Remove(entry.Key);
                continue;
            }
            merged[entry.Key] = entry.Value;
        }
        return table with { IntegerFields = merged };
    }

    private static bool IsSameMethod(IMethod candidate, MethodDef expected) =>
        candidate.ResolveMethodDef() is { } definition
            ? definition == expected
            : candidate.MDToken.Raw == expected.MDToken.Raw;
}
