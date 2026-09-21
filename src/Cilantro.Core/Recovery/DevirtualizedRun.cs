using dnlib.DotNet;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Pipeline;

namespace Cilantro.Core.Recovery;

/// <summary>What running the built bodies established about them.</summary>
public enum DevirtualizationCheck
{
    /// <summary>The comparison could not be made, and the notes say why.</summary>
    NotMade,

    /// <summary>The observed unpacking path matched and entered every reconstructed body under test.</summary>
    Agreed,

    /// <summary>They did something else.</summary>
    Disagreed
}

/// <summary>
/// Runs the module's own unpacking path twice â€” once as it shipped, once with the built bodies in
/// place of the stubs â€” and compares what came out.
/// </summary>
/// <remarks>
/// <para>
/// A body built from a virtual program is a claim: that this code does what the engine did when it
/// walked that program. Everything else the tool says about virtualization is a reading, and a
/// reading cannot be checked by reading it again. This is the one place the claim is tested
/// against something that did not come from the same reading.
/// </para>
/// <para>
/// The test is the sample's own work. These modules unpack an assembly at startup, and the
/// protected method is on the path that does it: it decrypts, it decompresses, it hands the result
/// to the runtime. So the module is prepared once, interpreted once as it shipped, then the built
/// bodies are put in place of the stubs and it is interpreted again. Both runs start from the same
/// state, in the same module, with the same everything, and the only difference between them is
/// the code the protected method holds. If the second run arrives at the same assembly â€” the same
/// megabyte of decrypted bytes, hash for hash â€” the built bodies did the work the engine did.
/// This is a comparison of the observed unpacking path, not proof of full behavioral
/// equivalence: unvisited branches and side effects outside the captured payload are not checked.
/// </para>
/// <para>
/// Two things would let this pass while testing nothing, and both are checked. If the run as it
/// shipped unpacks nothing there is no reference to compare against, and if the second run never
/// enters a built body then the rest of the module unpacked the payload on its own. Either way the
/// answer is that the check was not made, which is a different thing from the check passing.
/// </para>
/// </remarks>
internal static class DevirtualizedRun
{
    internal static (DevirtualizationCheck Verdict, IReadOnlyList<string> Said) Compare(
        ArtifactContext original,
        IReadOnlyList<VirtualProgram> programs)
    {
        // Payload absence skips only the extraction comparison. Direct method trials
        // can still expose reconstruction differences without an unpacking entry point.
        original.TryGetFact<PayloadChainRecovery.InterpretedChain>(
            PayloadChainRecovery.ChainFact, out var asked);

        // A second copy of the same input, prepared the same way, rather than the module the run
        // has been working on. That one has had the bodies written into it already and cannot be
        // interpreted twice to compare; and an assembly written back out moves everything in it,
        // while a Reactor-protected module reads its own image, so a copy on disk stops unpacking
        // for reasons that have nothing to do with the bodies. What is being checked is the
        // bodies, so they are put into a module that is otherwise the sample as the run found it.
        using var second = ArtifactContext.Load(
            original.InputPath,
            [.. original.Libraries.Select(library => library.Path)]);

        // The same world, so that a difference between the runs is a difference between the bodies.
        // The ledger is not shared: what stops this run is about this run, and the report of the
        // first has already been written.
        var world = BootstrapMachine.Environment(original);
        second.SetFact(
            BootstrapMachine.RunEnvironmentFact,
            new RunEnvironment(world.Host, world.Declarations, new BlockerLedger(), world.Strict));
        // Carried across from the first run: this loop is the second-largest thing the tool does, and
        // a run asked to stop while it is in here should stop here rather than at the end of it.
        original.TryGetFact<CancellationToken>(
            CilantroPipeline.CancellationFact, out var cancellation);
        Prepare(second, cancellation);

        var trials = new List<RebuiltMethodTrial.Result>();
        foreach (var program in programs.Take(8))
        {
            cancellation.ThrowIfCancellationRequested();
            if (second.Module.ResolveToken(program.Method.Stub.MDToken.Raw) is not MethodDef stub ||
                VirtualBody.Build(program, second.Module, stub).Body is not { } rebuilt) continue;
            for (var scenario = 0; scenario < 5; scenario++)
            {
                cancellation.ThrowIfCancellationRequested();
                var engine = (second.Module.ResolveToken(program.Method.Entry.MDToken.Raw) as IMethod)?.ResolveMethodDef();
                var trial = engine is null
                    ? new RebuiltMethodTrial.Result(DevirtualizationCheck.NotMade, "the original VM entry could not be resolved")
                    : RebuiltMethodTrial.Compare(second, stub, rebuilt, scenario, engine.MDToken.Raw);
                trials.Add(trial);
                original.AddEvidence(new Evidence("reconstruction-method-trial",
                    $"{stub.MDToken}, controlled input {scenario}" +
                    (scenario >= 3 ? $" (32-byte zero streams for object/stream arguments; debugger attached={scenario == 4})" : " (no host facts)") + $": {trial.Verdict}. {trial.Detail}. " +
                    "Bounded interpreter comparison, not proof for other inputs or initial states."));
            }
        }
        var payload = ComparePayload(original, programs, second, asked);
        var differing = trials.Count(t => t.Verdict == DevirtualizationCheck.Disagreed);
        var trialNote = $"Controlled-input method trials: {trials.Count(t => t.Verdict == DevirtualizationCheck.Agreed)} matched, " +
            $"{differing} differed, {trials.Count(t => t.Verdict == DevirtualizationCheck.NotMade)} inconclusive. " +
            "These compare bounded interpreter outcomes and observed state, not all inputs; see reconstruction-method-trial evidence.";
        return (differing > 0 ? DevirtualizationCheck.Disagreed : payload.Verdict, [trialNote, .. payload.Said]);
    }

    private static (DevirtualizationCheck Verdict, IReadOnlyList<string> Said) ComparePayload(
        ArtifactContext original, IReadOnlyList<VirtualProgram> programs, ArtifactContext second,
        PayloadChainRecovery.InterpretedChain? asked)
    {
        if (asked is { Unpacked.Count: 0 })
            return (DevirtualizationCheck.NotMade, [NothingToWatch(asked.Why)]);

        var shipped = Unpacked(second, [], out var whyShipped);
        if (shipped.Count == 0)
            return (DevirtualizationCheck.NotMade, [NothingToWatch(whyShipped)]);

        original.TryGetFact<IReadOnlySet<uint>>(VirtualizationRebuildPass.RebuiltFact, out var requested);
        requested ??= programs.Select(program => program.Method.Stub.MDToken.Raw).ToHashSet();
        original.TryGetFact<int>(VirtualizationRebuildPass.LiftedFact, out var lifted);
        var built = new HashSet<uint>();
        foreach (var program in programs)
        {
            if (!requested.Contains(program.Method.Stub.MDToken.Raw))
                continue;
            if (second.Module.ResolveToken(program.Method.Stub.MDToken.Raw) is not MethodDef stub)
                continue;
            if (VirtualBody.Build(program, second.Module, stub).Body is not { } body)
                continue;
            stub.Body = body;
            built.Add(stub.MDToken.Raw);
        }
        var installedLifted = VirtualizationRebuildPass.InstallLiftedCopies(original, second);
        built.UnionWith(installedLifted);
        requested = requested.Concat(installedLifted).ToHashSet();
        lifted -= installedLifted.Count;
        if (built.Count == 0)
        {
            return (DevirtualizationCheck.NotMade,
            [
                "The check was not made: the methods the bodies were built for are no longer in " +
                "the copy the check prepared."
            ]);
        }

        var entered = new HashSet<uint>();
        var again = Unpacked(second, built, out var whyAgain, token => entered.Add(token));
        var matched = again.SetEquals(shipped);
        original.AddEvidence(new Evidence("reconstruction-payload-comparison", matched
            ? "Both interpreter runs extracted identical assembly bytes."
            : "The interpreter runs produced different extracted assemblies."));
        var covered = requested.Count(token => built.Contains(token) && entered.Contains(token));
        original.AddEvidence(new Evidence("reconstruction-coverage",
            $"Reconstructed bodies exercised by this comparison: {covered} of {requested.Count + lifted}. " +
            (covered == 0 ? (matched ? "The matching extraction did not test the reconstructed code." : "No reconstructed body was exercised.")
                : covered < requested.Count + lifted ? "Unexercised bodies remain unvalidated." : "This only checks the observed unpacking path.")));
        var said = new List<string>();
        if (!matched)
        {
            said.Add(again.Count == 0
                ? "THE CHECK FAILED: with the built bodies in place, the module no longer unpacks " +
                    $"{Listed(shipped)}."
                : $"THE CHECK FAILED: with the built bodies in place, the module unpacks " +
                    $"{Listed(again)} where it unpacked {Listed(shipped)} before.");
            said.AddRange(whyAgain.Select(note => $"The run said: {Short(note)}"));
            said.Add(
                "That is either a body that does not do what the engine did, or something in it " +
                "the interpreter cannot follow. Read the built bodies before relying on them.");
            return (DevirtualizationCheck.Disagreed, said);
        }

        return Coverage(shipped, requested, built, entered, lifted);
    }

    /// <summary>
    /// Matching payloads only validate a reconstruction when every body under test was
    /// installed and entered. Repeated entries into one body cannot cover another body.
    /// The lifted count names helpers that could not be installed; installed helpers join
    /// the requested and installed token sets and must be entered like every other body.
    /// </summary>
    internal static (DevirtualizationCheck Verdict, IReadOnlyList<string> Said) Coverage(
        HashSet<string> payloads,
        IReadOnlySet<uint> requested,
        IReadOnlySet<uint> installed,
        IReadOnlySet<uint> entered,
        int lifted)
    {
        var covered = requested.Count(token => installed.Contains(token) && entered.Contains(token));
        var total = requested.Count + lifted;
        if (payloads.Count == 0 || total == 0 || covered != total)
        {
            return (DevirtualizationCheck.NotMade,
            [
                $"Reconstruction comparison covered {covered} of {total} rebuilt bodies. " +
                (payloads.Count > 0 ? "The interpreted runs extracted identical payload bytes. " : "No payload bytes were available to compare. ") +
                $"{requested.Count - covered} rebuilt body/bodies were not installed or entered; " +
                $"{lifted} lifted helper(s) were not substituted into the comparison. " +
                "This does not validate the unexercised bodies."
            ]);
        }
        return (DevirtualizationCheck.Agreed,
        [
            $"The interpreted runs extracted identical payload bytes ({Listed(payloads)}), " +
            $"and all {covered} reconstructed bodies under test were entered. " +
            "This checks the observed unpacking path, not every behavior of those bodies."
        ]);
    }

    /// <summary>That there is no reference to compare against, and what was said instead.</summary>
    private static string NothingToWatch(IReadOnlyList<string> why) =>
        "The check was not made: this module does not unpack anything the check can watch it " +
        $"unpack ({string.Join("; ", why.Select(Short))}), so there is nothing to compare the " +
        "built bodies against.";

    /// <summary>What the module unpacks when it is interpreted, and whether a built body ran.</summary>
    private static HashSet<string> Unpacked(
        ArtifactContext context,
        IReadOnlyCollection<uint> watched,
        out IReadOnlyList<string> why,
        Action<uint>? entered = null)
    {
        var recovered = PayloadChainRecovery.Recover(
            context,
            new PayloadChainRecovery.Watch(
                Repeat: false,
                Machine: machine => machine.FrameEntered = (method, _) =>
                {
                    if (watched.Contains(method.MDToken.Raw))
                        entered?.Invoke(method.MDToken.Raw);
                }),
            out why);
        return recovered.Select(item => item.Sha256).ToHashSet(StringComparer.Ordinal);
    }

    /// <summary>
    /// The passes that stand between a Reactor-protected module and a readable startup path.
    /// </summary>
    /// <remarks>
    /// Interpreting a module's loader is not something that works on the file as it shipped. The
    /// call to <c>Assembly.Load</c> is behind a delegate field until the proxies are resolved, the
    /// branches that lead to it are opaque until the loader's own state is folded, and the search
    /// for a starting point looks for a call it can see. The first run reached the payload with all
    /// of that already done, so this one has to have it done too.
    ///
    /// What is left out is what would cost more than it settles: reading the engine again, which is
    /// the reading being tested; the payload pass, run here by hand so the interpretation can be
    /// watched; and everything after it, one of which deletes methods nothing calls by name and
    /// would take the stubs with it.
    /// </remarks>
    private static readonly HashSet<string> Skipped = new(StringComparer.Ordinal)
    {
        "virtualization-disassembly",
        // The bodies this run is testing are put in by hand below, one at a time and with the
        // entries watched. Letting the pass do it would rebuild them from a second reading and
        // leave nothing watching whether they ran.
        "virtualization-rebuild",
        "string-table-relearning",
        "payload-extraction",
        "costura-extraction",
        "runtime-cleanup",
        "symbol-renaming",
        "metadata-sanitization"
    };

    private static void Prepare(ArtifactContext built, CancellationToken cancellation)
    {
        foreach (var planned in PipelinePlanner.Plan(CilantroPipeline.CreateDefaultPasses()))
        {
            cancellation.ThrowIfCancellationRequested();
            // Keep the entry calls whose replacement this comparison must exercise.
            if (planned.Pass is LoaderCallElisionPass) break;
            if (Skipped.Contains(planned.Pass.Name) ||
                !PipelinePlanner.Decide(planned, built).Execute)
                continue;
            built.AddPassResult(planned.Pass.Run(built));
        }
    }

    /// <summary>Why a run stopped, said in a line rather than in a trail.</summary>
    /// <remarks>
    /// A machine that stops says where it was and how it got there, and the trail runs to thousands
    /// of characters. It belongs in the report, where the pass that failed already records it in
    /// full; here it is one clause of a sentence about something else, and printing it whole buries
    /// the sentence and everything after it.
    /// </remarks>
    private static string Short(string said)
    {
        var text = said;
        var trail = text.IndexOf(" | provenance", StringComparison.Ordinal);
        if (trail > 0)
            text = text[..trail];
        text = text.Split('\n')[0].Trim();
        return text.Length <= Room ? text : $"{text[..Room]}...";
    }

    /// <summary>How much of a reason fits in a line.</summary>
    private const int Room = 200;

    private static string Listed(HashSet<string> hashes) =>
        hashes.Count == 0
            ? "nothing"
            : string.Join(" and ", hashes.Select(hash => $"SHA-256 {hash[..16]}"));
}
