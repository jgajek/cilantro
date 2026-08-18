using dnlib.DotNet;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Pipeline;

namespace Cilantro.Core.Recovery;

/// <summary>What running the built bodies established about them.</summary>
public enum DevirtualizationCheck
{
    /// <summary>The comparison could not be made, and the notes say why.</summary>
    NotMade,

    /// <summary>The built bodies did the same work the engine did.</summary>
    Agreed,

    /// <summary>They did something else.</summary>
    Disagreed
}

/// <summary>
/// Runs the module's own unpacking path twice — once as it shipped, once with the built bodies in
/// place of the stubs — and compares what came out.
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
/// the code the protected method holds. If the second run arrives at the same assembly — the same
/// megabyte of decrypted bytes, hash for hash — the built bodies did the work the engine did.
/// Nothing produces that by accident, and none of the several thousand operations behind it can be
/// misread without changing it.
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
        Prepare(second);

        var shipped = Unpacked(second, [], out var whyShipped);
        if (shipped.Count == 0)
        {
            return (DevirtualizationCheck.NotMade,
            [
                "The check was not made: this module does not unpack anything the check can watch " +
                $"it unpack ({string.Join("; ", whyShipped.Select(Short))}), so there is nothing " +
                "to compare the built bodies against."
            ]);
        }

        var built = new HashSet<uint>();
        foreach (var program in programs)
        {
            if (second.Module.ResolveToken(program.Method.Stub.MDToken.Raw) is not MethodDef stub)
                continue;
            if (VirtualBody.Build(program, second.Module, stub).Body is not { } body)
                continue;
            stub.Body = body;
            built.Add(stub.MDToken.Raw);
        }
        if (built.Count == 0)
        {
            return (DevirtualizationCheck.NotMade,
            [
                "The check was not made: the methods the bodies were built for are no longer in " +
                "the copy the check prepared."
            ]);
        }

        var entered = 0;
        var again = Unpacked(second, built, out var whyAgain, () => entered++);
        var said = new List<string>();
        if (!again.SetEquals(shipped))
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

        if (entered == 0)
        {
            said.Add(
                "The check was not made: the module unpacked the same assembly either way, but " +
                "the run never entered a built body, so that says nothing about them.");
            return (DevirtualizationCheck.NotMade, said);
        }

        said.Add(
            $"Checked by running it: with the built bodies in place of the stubs, the module " +
            $"unpacks {Listed(shipped)} — byte for byte what it unpacks as it shipped — and a " +
            $"built body was entered {entered} time(s) doing it.");
        return (DevirtualizationCheck.Agreed, said);
    }

    /// <summary>What the module unpacks when it is interpreted, and whether a built body ran.</summary>
    private static HashSet<string> Unpacked(
        ArtifactContext context,
        IReadOnlyCollection<uint> watched,
        out IReadOnlyList<string> why,
        Action? entered = null)
    {
        var recovered = PayloadChainRecovery.Recover(
            context,
            new PayloadChainRecovery.Watch(
                Repeat: false,
                Machine: machine => machine.FrameEntered = (method, _) =>
                {
                    if (watched.Contains(method.MDToken.Raw))
                        entered?.Invoke();
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

    private static void Prepare(ArtifactContext built)
    {
        foreach (var planned in PipelinePlanner.Plan(CilantroPipeline.CreateDefaultPasses()))
        {
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
