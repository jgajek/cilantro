using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Strings;

namespace Cilantro.Core.Recovery;

/// <summary>
/// Restores the strings a resolver still hands out, by asking it for each number its call sites pass.
/// </summary>
/// <remarks>
/// The readings before this one look for a table: a run of bytes, decrypted from a resource, that can
/// be framed into records and matched to the numbers the call sites carry. That is the right way round
/// for Reactor, whose table is exactly that. It finds nothing at all where the strings are kept
/// somewhere no run of bytes describes — a dictionary in a slot of the application domain, a field of
/// some other module's making, a literal decoded per call — which is how the layers underneath Reactor
/// tend to keep them, because a sample is often protected twice: once by whoever wrote it, and again
/// by whoever sold them the protector.
///
/// So this reading does not look for the table. It asks the resolver, which is the one thing that
/// knows where its strings are, for each number that reaches it, and takes the answer. Nothing is
/// executed to do it: the resolver is interpreted in the same bounded machine as everything else, and
/// an answer that depends on something the machine cannot know is refused rather than invented, which
/// is what keeps a wrong string from being written into the file.
///
/// It runs late deliberately. A layer underneath Reactor reaches its own resource through a Reactor
/// string, so asking it anything before Reactor's own strings are back means asking through the
/// virtual machine, and the machine then has to interpret the protector's interpreter running the
/// protector's loader. Once Reactor's layer is off, the same question is answered by ordinary code.
/// Peeling outside-in is not a preference here; it is the difference between minutes and seconds.
/// </remarks>
public sealed class StringLookupRecoveryPass : DeobfuscationPass
{
    public override string Name => "string-lookup-recovery";

    /// <remarks>
    /// A reading that declines leaves the module as it was, and one that restores strings either
    /// verifies or is rolled back and reported failed, which the pipeline already treats as fatal.
    /// </remarks>
    public override bool GatesEmission => false;

    /// <remarks>
    /// After the reading that knows the engine's numbering, so that Reactor's own strings are already
    /// back at their call sites and the layer underneath can be asked in plain code.
    /// </remarks>
    public override IReadOnlyCollection<string> Dependencies => ["string-table-relearning"];

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        var standing = Standing(context.Module);
        if (standing.Count == 0)
            return (PassStatus.Success, 0, ["No string lookup was left for this reading to ask."]);

        var lookups = new List<Lookup>();
        var unproven = 0;
        var said = new List<string>();
        var referring = Referring(context.Module);
        foreach (var candidate in standing)
        {
            if (Sited(context.Module, referring, candidate) is not { } lookup)
                continue;
            if (lookup.Calls == 0)
            {
                // Nothing is owed for these. What is left is not a call whose answer could have been
                // written in its place; it is the method's address, handed to a delegate that some
                // other code invokes. Counting those as strings left undone would put a number on the
                // report that no rewrite of call sites could ever bring down.
                said.Add(
                    $"{Say(candidate)}: nothing calls it — its {lookup.Taken} use(s) take its " +
                    "address for a delegate instead, so there is no call site here to write a " +
                    "literal into");
                continue;
            }
            if (lookup.Unproven.Count != 0)
            {
                unproven += lookup.Calls;
                said.Add(
                    $"{Say(candidate)}: {lookup.Unproven.Count} of its {lookup.Calls} " +
                    $"call(s) pass a number this reading could not settle ({lookup.Unproven[0]}), " +
                    "so none of them were asked about");
                continue;
            }
            lookups.Add(lookup);
        }

        if (lookups.Count == 0)
        {
            // Sites nobody could account for are counted anyway, so that a run which restored some
            // strings and left others cannot report itself as having restored them all.
            Owed(context, unproven);
            return (unproven == 0 ? PassStatus.Success : PassStatus.Partial, 0,
                [.. said, "No string lookup could be asked for the numbers reaching it."]);
        }

        if (!BootstrapMachine.TryRunInitializers(context, Steps, out var machine, out var why) ||
            machine is null)
        {
            Owed(context, unproven + lookups.Sum(lookup => lookup.Calls));
            return (PassStatus.Partial, 0,
                [.. said, "The module's own setup could not be interpreted, so no lookup could be " +
                    $"asked: {why}"]);
        }

        var changes = 0;
        var statuses = new List<PassStatus>();
        foreach (var lookup in lookups)
        {
            var (status, restored, reported) = Ask(context, machine, lookup);
            statuses.Add(status);
            changes += restored;
            said.AddRange(reported);
            if (status != PassStatus.Success)
                unproven += lookup.Calls;
        }

        Owed(context, unproven);
        var worst = statuses.Contains(PassStatus.Failed) ? PassStatus.Failed
            : statuses.Contains(PassStatus.Partial) ? PassStatus.Partial
            : unproven == 0 ? PassStatus.Success
            : PassStatus.Partial;
        return (worst, changes, said);
    }

    /// <summary>
    /// How far the machine is allowed to go, which is further than a table reading needs.
    /// </summary>
    /// <remarks>
    /// A lookup of this kind is answered out of a container its own setup builds, and the setup
    /// decrypts the whole table at once however few strings are then asked for. That work is paid for
    /// once and every later question is a dictionary read, so the allowance is for the setup rather
    /// than for the questions.
    /// </remarks>
    private const int Steps = 8_000_000;

    /// <summary>One lookup, the calls that reach it, and the number each of them passes.</summary>
    private sealed record Lookup(
        MethodDef Resolver,
        IReadOnlyCollection<MethodDef> Aliases,
        IReadOnlyList<(MethodDef Method, Instruction Call, int Key)> Sites,
        IReadOnlyList<string> Unproven,
        int Taken)
    {
        /// <summary>Every call that reaches it, whether or not its number could be settled.</summary>
        public int Calls => Sites.Count + Unproven.Count;
    }

    /// <summary>
    /// The methods that hand back a string for a number and are still being called.
    /// </summary>
    /// <remarks>
    /// A shape, not a proof, and a deliberately narrow one. The declaring type has to be one the
    /// assembly does not show the outside world, because a lookup of this kind is machinery rather
    /// than interface, and turning some public method's answer into a literal would be a change to
    /// the program rather than a reading of it. What settles whether a candidate is a lookup at all
    /// is whether every call that reaches it passes a number this reading can settle and whether the
    /// method then answers with a string — neither of which ordinary code obliges.
    /// </remarks>
    private static List<MethodDef> Standing(ModuleDef module) =>
        [.. module.GetTypes()
            .Where(type => !type.IsPublic && !type.IsNestedPublic && !type.IsGlobalModuleType)
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody &&
                method.IsStatic &&
                method.ReturnType.ElementType == ElementType.String &&
                method.MethodSig?.Params.Count == 1 &&
                method.MethodSig.Params[0].ElementType == ElementType.I4)];

    /// <summary>
    /// The calls reaching a candidate, with the number each passes worked out where it can be.
    /// </summary>
    /// <remarks>
    /// Returns nothing at all where nothing refers to the candidate, which is the ordinary case for
    /// the resolver an earlier reading already emptied out and for any method of the sample's own
    /// that merely happens to take a number and give back a string. Every other candidate is
    /// described whole, including the calls whose number could not be settled, because a reading that
    /// quietly dropped those would restore some of a lookup's sites and leave the rest calling a
    /// method the cleanup then has grounds to delete.
    /// </remarks>
    private static Lookup? Sited(
        ModuleDef module,
        IReadOnlyDictionary<MethodDef, List<Reference>> referring,
        MethodDef candidate)
    {
        if (!referring.ContainsKey(candidate))
            return null;
        var aliases = ResolverAliasAnalysis.Resolve(module, candidate);
        var references = aliases
            .SelectMany(alias => referring.TryGetValue(alias, out var found) ? found : [])
            .Where(reference =>
                !ResolverAliasAnalysis.IsInternalForwardingCall(reference.Method, aliases))
            .ToArray();
        if (references.Length == 0)
            return null;

        var sites = new List<(MethodDef, Instruction, int)>();
        var unproven = new List<string>();
        var taken = 0;
        foreach (var reference in references)
        {
            if (reference.Instruction.OpCode.Code is not (Code.Call or Code.Callvirt))
            {
                taken++;
                continue;
            }
            if (!StringOffsetSlicer.TryEvaluate(
                    reference.Method, reference.Index, EmptyKeys, out var key, out var slice))
            {
                unproven.Add(
                    $"{reference.Method.MDToken} IL_{reference.Instruction.Offset:X4}: {slice}");
                continue;
            }
            sites.Add((reference.Method, reference.Instruction, key));
        }
        return new Lookup(candidate, aliases, sites, unproven, taken);
    }

    /// <summary>One instruction naming a method, and where in its own body it sits.</summary>
    private sealed record Reference(MethodDef Method, Instruction Instruction, int Index);

    /// <summary>
    /// Every instruction in the module that names a method of the module, filed under the method.
    /// </summary>
    /// <remarks>
    /// Built once. Every candidate needs the same question answered about itself, and a module that
    /// happens to have fifty methods taking a number and giving back a string would otherwise be read
    /// through fifty times over to answer it.
    /// </remarks>
    private static Dictionary<MethodDef, List<Reference>> Referring(ModuleDef module)
    {
        var referring = new Dictionary<MethodDef, List<Reference>>();
        foreach (var method in module.GetTypes().SelectMany(type => type.Methods))
        {
            if (!method.HasBody)
                continue;
            var instructions = method.Body.Instructions;
            for (var index = 0; index < instructions.Count; index++)
            {
                if (instructions[index].Operand is not IMethod named ||
                    named.ResolveMethodDef() is not { } resolved)
                {
                    continue;
                }
                if (!referring.TryGetValue(resolved, out var found))
                    referring[resolved] = found = [];
                found.Add(new Reference(method, instructions[index], index));
            }
        }
        return referring;
    }

    /// <summary>
    /// Asks one lookup for every number reaching it and puts the answers back where they came from.
    /// </summary>
    /// <remarks>
    /// Each distinct number is asked once and the answer reused, because a lookup is answered out of
    /// a container built once and asking twice would cost the reading without adding to it. An answer
    /// that is not a string the machine holds concretely stops the whole lookup rather than that one
    /// site: a lookup half restored leaves the other half calling a decryptor whose table the cleanup
    /// is then entitled to take away.
    /// </remarks>
    private static (PassStatus, int, IReadOnlyList<string>) Ask(
        ArtifactContext context,
        StaticMachine machine,
        Lookup lookup)
    {
        var answers = new Dictionary<int, string>();
        foreach (var key in lookup.Sites.Select(site => site.Key).Distinct())
        {
            var asked = machine.Execute(lookup.Resolver, [StaticValue.FromInt32(key)]);
            if (!asked.Succeeded)
            {
                return (PassStatus.Partial, 0,
                [
                    $"{Say(lookup.Resolver)}: asked for {key}, it stopped at " +
                    $"{Trimmed(asked.Diagnostic)}",
                    $"Its {lookup.Sites.Count} use(s) were left as they were."
                ]);
            }
            if (!machine.State.Heap.TryGetString(asked.Value, out var answer) || answer is null)
            {
                return (PassStatus.Partial, 0,
                [
                    $"{Say(lookup.Resolver)}: asked for {key}, it answered with something other " +
                        "than a string this reading can hold",
                    $"Its {lookup.Sites.Count} use(s) were left as they were."
                ]);
            }
            answers[key] = answer;
        }

        var replacements = lookup.Sites
            .Select(site => (site.Method, site.Call, Value: answers[site.Key]))
            .ToArray();
        var (status, changes, said) = StringRecoveryPass.Rewrite(
            context, "string-lookup-recovery", lookup.Aliases, lookup.Sites.Count, replacements);
        if (status != PassStatus.Success)
            return (status, changes, said);

        context.AddEvidence(new Evidence(
            "string-lookup",
            $"Asked {Say(lookup.Resolver)} for each of the {answers.Count} number(s) reaching it " +
            $"and restored all {replacements.Length} of its use(s).",
            $"{lookup.Resolver.MDToken} {lookup.Resolver.FullName}",
            1.0));
        return (status, changes, said);
    }

    /// <summary>
    /// Counts the uses this reading could not account for, so the run's totals stay honest.
    /// </summary>
    /// <remarks>
    /// The summary reports restored sites out of counted sites, and a site nobody could read is a
    /// site all the same. Left uncounted, a module whose second layer of strings was never touched
    /// reports every string it has as recovered, which is the one thing a reader of the output must
    /// be able to rely on not happening.
    /// </remarks>
    private static void Owed(ArtifactContext context, int sites)
    {
        if (sites == 0)
            return;
        context.TryGetFact<int>("strings.callSites", out var counted);
        context.SetFact("strings.callSites", counted + sites);
    }

    private static readonly Dictionary<uint, int> EmptyKeys = [];

    private static string Say(MethodDef method) =>
        $"{method.DeclaringType.Name}::{method.Name}";

    /// <summary>The head of a refusal, without the provenance a summary has no room for.</summary>
    private static string Trimmed(string? diagnostic)
    {
        if (string.IsNullOrEmpty(diagnostic))
            return "nothing it could say";
        var said = diagnostic.Split(" | provenance:", StringSplitOptions.None)[0];
        var last = said.LastIndexOf(" -> ", StringComparison.Ordinal);
        return last < 0 ? said : said[(last + 4)..];
    }
}
