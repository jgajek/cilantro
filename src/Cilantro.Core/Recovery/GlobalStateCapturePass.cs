using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;

namespace Cilantro.Core.Recovery;

/// <summary>
/// The concrete integer values Reactor's loader leaves in module-wide state, proven by
/// interpretation.
/// </summary>
public sealed record CapturedGlobalState(
    IReadOnlyDictionary<uint, int> InstanceFields,
    IReadOnlyDictionary<uint, int> StaticFields)
{
    public int Count => InstanceFields.Count + StaticFields.Count;
}

/// <summary>
/// Proves the values Reactor's loader writes into its module-wide state object.
/// </summary>
/// <remarks>
/// Reactor allocates a singleton, roots it in a static field, and fills a hundred or so integer
/// fields from a control-flow-flattened initializer. Those fields are then read all over the module
/// as branch conditions, which is what makes so much of the assembly look conditional when it is
/// not. Recovering the values is therefore the precondition for collapsing those predicates, and
/// interpretation is the only way to get them: each one is computed by an arithmetic chain, so
/// there is no literal in the metadata to read.
///
/// The values are only published when two independent interpretations agree, which rules out any
/// dependence on interpretation order or on ambient state that happened to differ between runs. A
/// field the two runs disagree about is dropped rather than guessed, leaving its read sites
/// unproven.
///
/// This pass never mutates the module, so a failure to prove anything is reported without
/// withholding an otherwise verified assembly.
/// </remarks>
public sealed class GlobalStateCapturePass : DeobfuscationPass
{
    private const int MaximumSteps = 4_000_000;

    public override string Name => "global-state-capture";
    public override IReadOnlyCollection<string> Dependencies => ["method-body-recovery"];
    public override bool GatesEmission => false;

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        // The state this looks for is a Reactor loader's, so running the initializers of a module
        // under some other protector spends a budget on work that cannot find anything, and reports
        // whatever it ran out of steps on as though the run had been held up by it.
        if (!context.TryGetFact<ReactorStructureFacts>("reactor.structure", out var facts) ||
            facts is null ||
            !facts.IsReactor)
        {
            return (PassStatus.Success, 0,
                ["No Reactor structure was detected, so no loader state was interpreted."]);
        }

        if (!BootstrapMachine.TryRunInitializers(context, MaximumSteps, out var first, out var why) ||
            first is null ||
            !BootstrapMachine.TryRunInitializers(context, MaximumSteps, out var second, out _) ||
            second is null)
        {
            return (PassStatus.Unsupported, 0,
                [$"Loader state could not be interpreted: {why}."]);
        }

        var firstInstance = InitializedFieldCapture.CaptureInstanceIntegers(context.Module, first.State);
        var secondInstance = InitializedFieldCapture.CaptureInstanceIntegers(context.Module, second.State);
        var firstStatic = InitializedFieldCapture.CaptureStaticIntegers(context.Module, first.State);
        var secondStatic = InitializedFieldCapture.CaptureStaticIntegers(context.Module, second.State);
        if (!InitializedFieldCapture.CapturesAgree(firstInstance, secondInstance) ||
            !InitializedFieldCapture.CapturesAgree(firstStatic, secondStatic))
        {
            return (PassStatus.Unsupported, 0,
            [
                "Two independent interpretations of the loader disagreed on module-wide state.",
                "No value was published, so no predicate can be folded from it."
            ]);
        }

        // Method-body recovery interprets the same loader to recover resolver keys. Where both
        // captures saw a field they must agree, and a field they disagree about is dropped.
        var instance = MergeAgreeing(context, firstInstance);
        if (instance.Count == 0 && firstStatic.Count == 0)
            return (PassStatus.Success, 0, ["The loader initialized no provable module-wide state."]);

        var state = new CapturedGlobalState(instance, firstStatic);
        context.SetFact("globals.state", state);
        context.AddEvidence(new Evidence(
            "global-state",
            $"Proved {state.Count} loader-initialized integer field(s) that agreed across two " +
            "independent interpretations.",
            Confidence: 0.95));
        return (PassStatus.Success, 0,
        [
            $"Proved {instance.Count} instance and {firstStatic.Count} static integer field(s) of " +
            "loader-initialized state."
        ]);
    }

    private static Dictionary<uint, int> MergeAgreeing(
        ArtifactContext context,
        Dictionary<uint, int> captured)
    {
        if (!context.TryGetFact<IReadOnlyDictionary<uint, int>>(
                "bootstrap.integerFields", out var loaderKeys) ||
            loaderKeys is null)
        {
            return captured;
        }

        var merged = new Dictionary<uint, int>(captured);
        foreach (var entry in loaderKeys)
        {
            if (merged.TryGetValue(entry.Key, out var existing))
            {
                if (existing != entry.Value)
                    merged.Remove(entry.Key);
                continue;
            }
            merged[entry.Key] = entry.Value;
        }
        return merged;
    }
}
