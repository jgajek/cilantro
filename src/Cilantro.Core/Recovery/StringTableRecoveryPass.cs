using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Strings;

namespace Cilantro.Core.Recovery;

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
        var resolvers = StringResolverCandidates.In(context.Module);
        if (resolvers.Length == 0)
            return (PassStatus.Success, 0, ["No protected string resolver was detected."]);

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

        // Taking a string for a number is a shape a resolver has, not a shape only a resolver has:
        // a cache that hands back what it was told earlier reads the same way. So each candidate is
        // asked to produce its table, and the one that does is the resolver. That is the difference
        // between recognizing a method and reading it, and only the second is proof.
        var stubs = Analysis.VirtualizedMethodDetector.Detect(context.Module)
            .Select(method => method.Stub.MDToken.Raw)
            .ToHashSet();
        var readings = new List<Reading>();
        var declined = new List<string>();
        foreach (var candidate in resolvers)
        {
            if (Read(context, candidate, out var reading, out var why) && reading is not null)
                readings.Add(reading);
            else
            {
                declined.Add(
                    $"{candidate.DeclaringType.Name}::{candidate.Name}: {why}{Behind(candidate, stubs)}");
            }
        }

        if (readings.Count != 1)
        {
            // A reading that stopped is worth leaving a note for the later one, which will have this
            // build's own numbering: these are the operations it will have to name, and the operand
            // each is given has to be one the program really carries.
            var carried = Needed(context, resolvers, declined);
            // Where the table is built by a program of the module's own virtual machine, this
            // reading is not the one that can read it: it has to assume a numbering for the
            // engine's operations, and only the reading that comes after the engine has been
            // studied knows this build's. The work is handed on rather than given up, so the gap
            // is recorded once, by the reading that was handed it, instead of once here and again
            // there.
            if (carried)
            {
                context.SetFact("strings.deferred", true);
                return (PassStatus.Success, 0,
                [
                    "The table is built by a program of the module's own virtual machine, so " +
                        "reading it was left to after the engine's own numbering has been learned.",
                    .. declined
                ]);
            }

            return (PassStatus.Partial, 0,
            [
                readings.Count == 0
                    ? $"None of the {resolvers.Length} candidate resolver(s) yielded a string table."
                    : $"{readings.Count} of the {resolvers.Length} candidate resolver(s) yielded a " +
                        "string table, so which one the program reads is not settled.",
                .. declined,
                "No string call site was modified."
            ]);
        }

        var (resolver, aliases, directCalls, captured) = readings[0];
        var table = MergeLoaderKeys(context, captured);
        context.SetFact("strings.table", table);
        context.SetFact("strings.tableRecords", table.Records.Count);
        context.SetFact("strings.resolverToken", resolver.MDToken.Raw);
        context.SetFact("strings.expectedUses", directCalls.Count);
        context.SetFact<IReadOnlyList<uint>>(
            "strings.resolverAliases",
            aliases.Where(alias => alias != resolver).Select(alias => alias.MDToken.Raw).ToArray());
        context.AddEvidence(new Evidence(
            "string-table",
            $"Captured {table.Records.Count} strictly framed UTF-16 strings with " +
            $"{directCalls.Count} completely accounted resolver use(s).",
            table.Source,
            0.95));
        return (PassStatus.Success, 0,
            [$"Captured {table.Records.Count} strings from {table.Source}.",
             $"Accounted for all {directCalls.Count} direct resolver use(s).",
             $"Captured {table.IntegerFields.Count} unique VM-initialized integer field(s)."]);
    }

    /// <summary>
    /// Records which operations the program behind the table performs, for the later reading.
    /// </summary>
    /// <remarks>
    /// Only reached where this reading produced nothing, because it costs another interpretation of
    /// the loader and there is nothing to carry when the table is already in hand. What is recorded
    /// is the program's own operands, not made-up ones: the reading of the engine asks it to perform
    /// each operation, and an operation that names a field or a type has to be given one that exists
    /// or the engine is within its rights to refuse.
    /// </remarks>
    /// <returns>
    /// Whether a serialized program was found behind the table, which is what says there is a later
    /// reading to hand the table to at all.
    /// </returns>
    private static bool Needed(ArtifactContext context, MethodDef[] resolvers, List<string> said)
    {
        foreach (var candidate in resolvers)
        {
            if (!StaticStringTableInterpreter.TryReadOperations(
                    context.Module, context.OriginalImage, candidate,
                    BootstrapMachine.Environment(context), out var operations, out var why,
                    ProxyLoaderTable.Read(context)) ||
                operations.Count == 0)
            {
                continue;
            }
            context.SetFact("strings.vmOperations", operations);
            said.Add($"{candidate.DeclaringType.Name}::{candidate.Name}: {why}");
            return true;
        }
        return false;
    }

    /// <summary>
    /// Says so where the table a candidate would produce is built by a virtualized method.
    /// </summary>
    /// <remarks>
    /// A resolver that fills its table by calling a method whose body was replaced by bytecode has
    /// put the table behind the virtual machine, and no amount of looking at the shape of the
    /// method that calls it will find one. Which is worth saying plainly rather than reporting the
    /// framing as unrecognized: the framing was recognized, and what it frames is somewhere this
    /// pass does not go.
    /// </remarks>
    private static string Behind(MethodDef candidate, HashSet<uint> stubs)
    {
        if (stubs.Count == 0 || !candidate.HasBody)
            return string.Empty;
        var called = candidate.Body.Instructions.Any(instruction =>
            instruction.Operand is IMethod method &&
            method.ResolveMethodDef() is { } resolved &&
            stubs.Contains(resolved.MDToken.Raw));
        return called
            ? "; it builds its table by calling a virtualized method, so the table is behind the " +
                "virtual machine"
            : string.Empty;
    }

    /// <summary>One candidate resolver, its uses, and the table it was watched producing.</summary>
    private sealed record Reading(
        MethodDef Resolver,
        IReadOnlyCollection<MethodDef> Aliases,
        IReadOnlyList<(MethodDef Method, Instruction Instruction)> DirectCalls,
        CapturedStringTable Table);

    /// <summary>
    /// Whether a candidate is the resolver, which is settled by reading its table.
    /// </summary>
    private static bool Read(
        ArtifactContext context,
        MethodDef candidate,
        out Reading? reading,
        out string why)
    {
        reading = null;
        var aliases = ResolverAliasAnalysis.Resolve(context.Module, candidate);
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
            why = $"{references.Length - directCalls.Length} of its {references.Length} use(s) are " +
                "not calls, so delegate or indirect uses cannot be proven complete";
            return false;
        }

        if (!StaticStringTableInterpreter.TryCapture(
                context.Module,
                context.OriginalImage,
                candidate,
                out var interpreted,
                out var interpreterDiagnostic,
                BootstrapMachine.Environment(context),
                learned: null,
                ProxyLoaderTable.Read(context)) ||
            interpreted is null)
        {
            why = interpreterDiagnostic;
            return false;
        }

        why = string.Empty;
        reading = new Reading(
            candidate,
            aliases,
            directCalls,
            new CapturedStringTable(
                interpreted.Source,
                interpreted.Bytes,
                interpreted.Records,
                interpreted.IntegerFields));
        return true;
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
    /// <summary>
    /// Adds the loader's own proven integers to the table's, so a call site's offset can be worked out.
    /// </summary>
    /// <remarks>
    /// Shared with the later reading, which needs it for the same reason: an offset is not always a
    /// constant at the call site. Where it is computed from a field the loader set, a table without
    /// that field cannot say which record the site asks for, and the rewrite stops with the offset
    /// looking like nonsense. A field the two readings disagree about is dropped rather than
    /// preferred, because there is nothing to choose between them.
    /// </remarks>
    internal static CapturedStringTable MergeLoaderKeys(
        ArtifactContext context,
        CapturedStringTable table)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(table);
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
