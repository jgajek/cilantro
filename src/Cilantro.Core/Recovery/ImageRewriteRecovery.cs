using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Recovery;

/// <summary>A method whose body a protector's rewrite of the mapped image is expected to bring
/// back, as the module declares it before the rewrite runs.</summary>
public sealed record RewriteTarget(uint Token, uint Rva);

/// <summary>
/// What one protector's in-place rewrite of its own mapped image is permitted to do, and what
/// counts as having undone it.
/// </summary>
/// <remarks>
/// Two protectors can decrypt their own code with the same interpretation and still owe entirely
/// different answers about what the result is allowed to look like. Reactor patches individual
/// method-body slots and must not touch a byte outside them; ConfuserEx decrypts a whole section
/// it owns and would fail a slot-shaped bound for doing exactly what it is supposed to do. The
/// bound is the part that cannot be shared, so it is the part that is asked for here.
/// </remarks>
public interface IImageRewritePolicy
{
    /// <summary>The protector whose rewrite this describes, for diagnostics.</summary>
    string Protector { get; }

    /// <summary>The methods the rewrite is expected to restore.</summary>
    IReadOnlyList<RewriteTarget> Targets { get; }

    /// <summary>
    /// Applies the write log to a copy of the file, refusing any write this protector had no
    /// business making, and naming which targets the writes account for.
    /// </summary>
    bool TryReplay(
        PeImageView image,
        IReadOnlyList<MappedImageWrite> writes,
        out byte[] restoredFile,
        out IReadOnlySet<uint> restoredTokens,
        out string? diagnostic);

    /// <summary>Whether a method still holds the protector's placeholder rather than real code.
    /// </summary>
    bool IsStillProtected(MethodDef method);

    /// <summary>
    /// Whether field data at this address is part of what the rewrite decrypted.
    /// </summary>
    /// <remarks>
    /// A protector that decrypts a whole region decrypts everything in it, and method bodies are
    /// not the only thing a region holds. ConfuserEx puts its constants table in the same section
    /// as the code, as field data the metadata points into, so a recovery that reinstated only the
    /// bodies would hand back a module whose code is readable and whose constants are still
    /// ciphertext — and nothing downstream would be able to tell.
    /// </remarks>
    bool CoversFieldData(uint rva, int length);
}

/// <summary>The outcome of one deterministic pair of bootstrap interpretations.</summary>
public sealed record InterpretedRewrite(
    StaticExecutionResult Result,
    IReadOnlyList<MappedImageWrite> Writes,
    IReadOnlyList<MappedImageWrite> ImageWrites,
    IReadOnlyDictionary<uint, int> IntegerFields,
    IReadOnlyDictionary<uint, IReadOnlyDictionary<int, int>> TokenMaps,
    LoaderInterpretationEvidence Evidence);

/// <summary>
/// What a replayed rewrite restored, and which of its candidates it turned out not to cover.
/// </summary>
/// <remarks>
/// The two are reported separately because they mean different things to a reader. A recovered
/// target is a method whose body the protector was holding and which is now back. An untouched one
/// is a method the catalog guessed at and the protector never encrypted, so it was already what it
/// appears to be. Counting them together would claim recovery of a body that was never taken away.
/// </remarks>
public sealed record AppliedRewrite(
    IReadOnlyList<RewriteTarget> Recovered,
    IReadOnlyList<RewriteTarget> Untouched);

public enum RewriteApplication
{
    /// <summary>The rewrite was replayed, grafted, and verified.</summary>
    Applied,

    /// <summary>The interpretation was sound but produced nothing to restore.</summary>
    NothingToApply,

    /// <summary>Something failed a gate; nothing was modified.</summary>
    Refused
}

/// <summary>
/// Recovers method bodies that a protector only writes into the image at run time, by
/// interpreting the code that writes them and replaying what it wrote.
/// </summary>
/// <remarks>
/// The interpretation is run twice and the two runs must agree on status, step count, write log,
/// captured fields, and observations before anything is replayed. A protector's decryptor that
/// reads something the environment does not model can still finish, having quietly taken a
/// different branch each time, and a single run cannot tell that from a decryptor that simply
/// works. Two runs that agree can, and the alternative to checking is grafting bodies derived
/// from a value the machine invented.
/// </remarks>
public static class ImageRewriteRecovery
{
    private const string MappedImageRegion = "MappedImage";

    /// <summary>
    /// Interprets the rewrite twice and returns it only if both runs agreed in every respect
    /// that the replay depends on.
    /// </summary>
    public static bool TryInterpret(
        ArtifactContext context,
        MethodDef executionRoot,
        StaticMachineLimits limits,
        out InterpretedRewrite? rewrite,
        out string? diagnostic)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(executionRoot);
        rewrite = null;
        if (!TryExecuteOnce(context, executionRoot, limits, out var first, out diagnostic) ||
            !TryExecuteOnce(context, executionRoot, limits, out var second, out diagnostic))
        {
            return false;
        }

        if (first!.Result.Status != second!.Result.Status ||
            first.Result.Steps != second.Result.Steps ||
            !MethodBodyRecoveryInfrastructure.WriteLogsEqual(first.Writes, second.Writes))
        {
            diagnostic = "The two bounded bootstrap interpretations produced different status, " +
                "step count, or write logs.";
            return false;
        }
        if (!InitializedFieldCapture.CapturesAgree(first.IntegerFields, second.IntegerFields))
        {
            diagnostic = "The two bounded bootstrap interpretations disagreed on " +
                "loader-initialized integer fields.";
            return false;
        }
        if (!InitializedFieldCapture.MapsAgree(first.TokenMaps, second.TokenMaps))
        {
            diagnostic = "The two bounded bootstrap interpretations disagreed on " +
                "loader-initialized token tables.";
            return false;
        }
        if (!first.Evidence.Agrees(second.Evidence))
        {
            diagnostic = "The two bounded bootstrap interpretations disagreed on loader " +
                "observations or effects.";
            return false;
        }

        rewrite = first;
        diagnostic = null;
        return true;
    }

    /// <summary>
    /// Replays the rewrite into a copy of the file under the policy's bound, reparses it, and
    /// grafts the recovered bodies as a single transaction that verifies or rolls back.
    /// </summary>
    public static RewriteApplication TryApply(
        ArtifactContext context,
        IImageRewritePolicy policy,
        IReadOnlyList<MappedImageWrite> imageWrites,
        out AppliedRewrite? applied,
        out IReadOnlyList<string> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(imageWrites);
        applied = null;
        if (imageWrites.Count == 0)
        {
            diagnostics =
                ["The bootstrap completed without concrete mapped-image writes; no restoration was applied."];
            return RewriteApplication.NothingToApply;
        }
        if (!policy.TryReplay(
                context.OriginalImage,
                imageWrites,
                out var restoredBytes,
                out var restoredTokens,
                out var replayDiagnostic))
        {
            diagnostics =
            [
                $"Deterministic mapped-image writes failed the replay gate: {replayDiagnostic}",
                "No method body or initializer was modified."
            ];
            return RewriteApplication.Refused;
        }

        // Only the targets the rewrite actually reached were protected. One it never touched is
        // genuinely what it appears to be and must be left alone.
        var recovered = policy.Targets
            .Where(target => restoredTokens.Contains(target.Token))
            .ToArray();
        var untouched = policy.Targets
            .Where(target => !restoredTokens.Contains(target.Token))
            .ToArray();
        if (recovered.Length == 0)
        {
            diagnostics = ["The bootstrap wrote no protected method body; no restoration was applied."];
            return RewriteApplication.NothingToApply;
        }

        ModuleDefMD? restoredModule = null;
        try
        {
            restoredModule = ModuleDefMD.Load(restoredBytes, new ModuleCreationOptions
            {
                TryToLoadPdbFromDisk = false,
                Context = ModuleDef.CreateModuleContext(),
            });
            if (!TryPrepareBodies(
                    context.Module,
                    restoredModule,
                    policy,
                    recovered,
                    out var replacements,
                    out var graftDiagnostic))
            {
                diagnostics =
                [
                    $"Reparsed-image validation failed: {graftDiagnostic}",
                    "No method body or initializer was modified."
                ];
                return RewriteApplication.Refused;
            }

            if (!TryPrepareFieldData(
                    context.Module,
                    restoredModule,
                    policy,
                    out var fieldData,
                    out var fieldDiagnostic))
            {
                diagnostics =
                [
                    $"Reparsed-image field data was rejected: {fieldDiagnostic}",
                    "No method body or initializer was modified."
                ];
                return RewriteApplication.Refused;
            }

            var snapshots = replacements.Keys
                .Distinct()
                .ToDictionary(method => method, MethodBodySnapshot.Capture);
            var originalFieldData = fieldData.Keys
                .ToDictionary(field => field, field => field.InitialValue);
            try
            {
                foreach (var replacement in replacements)
                    replacement.Key.Body = replacement.Value;
                foreach (var replacement in fieldData)
                    replacement.Key.InitialValue = replacement.Value;

                if (recovered.Any(target =>
                        context.Module.ResolveToken(target.Token) is not MethodDef restored ||
                        !restored.HasBody ||
                        policy.IsStillProtected(restored)))
                {
                    throw new InvalidOperationException(
                        $"At least one {policy.Protector} method remained protected after grafting.");
                }
                var verification = AssemblyVerifier.Verify(
                    context.Module,
                    context.OriginalIdentity,
                    context.OriginalStructure);
                if (!verification.Passed)
                {
                    throw new InvalidOperationException(
                        "Grafted module verification failed: " +
                        string.Join("; ", verification.Diagnostics));
                }
            }
            catch (Exception exception)
            {
                foreach (var snapshot in snapshots)
                    snapshot.Value.Restore(snapshot.Key);
                foreach (var original in originalFieldData)
                    original.Key.InitialValue = original.Value;
                diagnostics = [exception.Message, "All method-body changes were rolled back."];
                return RewriteApplication.Refused;
            }

            applied = new AppliedRewrite(recovered, untouched);
            var notes = new List<string>();
            if (fieldData.Count != 0)
                notes.Add($"Reinstated decrypted field data for {fieldData.Count} field(s).");
            if (untouched.Length != 0)
                notes.Add(DescribeUntouched(context, policy, untouched));
            diagnostics = notes;
            return RewriteApplication.Applied;
        }
        catch (Exception exception) when (
            exception is BadImageFormatException or IOException or InvalidOperationException or
                ArgumentException or OverflowException)
        {
            diagnostics =
            [
                $"Restored image could not be safely reparsed or grafted: {exception.Message}",
                "No method body or initializer was modified."
            ];
            return RewriteApplication.Refused;
        }
        finally
        {
            restoredModule?.Dispose();
        }
    }

    /// <summary>
    /// Says which catalogued targets the rewrite never wrote, by name.
    /// </summary>
    /// <remarks>
    /// A count on its own cannot be acted on. Whoever reads "one of 5,367 was not written" has to
    /// go and find out which before they can tell a method that was never encrypted from a recovery
    /// that quietly fell short, and that is the whole question. Naming them answers it in the
    /// report, and the names are bounded because a run where thousands went untouched is telling a
    /// reader something the list would only bury.
    /// </remarks>
    private static string DescribeUntouched(
        ArtifactContext context,
        IImageRewritePolicy policy,
        RewriteTarget[] untouched)
    {
        const int mostWorthNaming = 8;
        var named = untouched
            .Take(mostWorthNaming)
            .Select(target => context.Module.ResolveToken(target.Token) is MethodDef method
                ? $"0x{target.Token:X8} {method.FullName}"
                : $"0x{target.Token:X8}");
        var listed = string.Join("; ", named);
        if (untouched.Length > mostWorthNaming)
            listed += $"; and {untouched.Length - mostWorthNaming} more";
        return $"{untouched.Length} of {policy.Targets.Count} catalogued target(s) were never " +
            $"written, so {policy.Protector} was holding no body for them and they were left as " +
            $"they stand: {listed}.";
    }

    /// <summary>
    /// Seeds a machine with the run's environment and interprets the rewrite once, materializing
    /// the write log before anything else can add to it.
    /// </summary>
    private static bool TryExecuteOnce(
        ArtifactContext context,
        MethodDef executionRoot,
        StaticMachineLimits limits,
        out InterpretedRewrite? rewrite,
        out string? diagnostic)
    {
        rewrite = null;
        var machine = new StaticMachine(limits, modelTypeInitialization: true);
        // The same environment the rest of the run uses, so that a fact stated for the run is
        // answered here too and a refusal here lands in the run's ledger.
        if (!BootstrapMachine.TryTell(context, machine, out var seedDiagnostic))
        {
            diagnostic = $"The bootstrap could not be set up: {seedDiagnostic}.";
            return false;
        }

        var result = machine.Execute(executionRoot);
        // Materialize the write log before anything else runs: only the bootstrap's own writes
        // may be replayed into method-body slots.
        var writes = machine.State.Heap.ImageWrites
            .Select(MappedImageWrite.From)
            .ToArray();
        // Snapshot before the key holders run, so the evidence describes the bootstrap alone.
        var evidence = machine.State.LoaderEvidence;
        var integerFields = new Dictionary<uint, int>();
        var tokenMaps = new Dictionary<uint, IReadOnlyDictionary<int, int>>();
        if (result.Succeeded)
        {
            integerFields = CaptureResolverKeys(context.Module, machine);
            tokenMaps = InitializedFieldCapture.CaptureIntegerMaps(context.Module, machine.State);
        }
        if (machine.State.TypeInitializationEvents.Count != 0)
            result = result with { Diagnostic = DescribeTypeInitialization(machine, result) };

        rewrite = new InterpretedRewrite(
            result,
            writes,
            writes
                .Where(write => string.Equals(
                    write.RegionKind,
                    MappedImageRegion,
                    StringComparison.Ordinal))
                .ToArray(),
            integerFields,
            tokenMaps,
            evidence);
        diagnostic = null;
        return true;
    }

    private static string DescribeTypeInitialization(
        StaticMachine machine,
        StaticExecutionResult result)
    {
        const int mostWorthNaming = 24;
        var events = string.Join(
            ", ",
            machine.State.TypeInitializationEvents
                .Take(mostWorthNaming)
                .Select(item => $"{item.Sequence}:{item.Type}={item.Status}"));
        if (machine.State.TypeInitializationEvents.Count > mostWorthNaming)
            events += ", …";
        return $"Type initialization: {events}. {result.Diagnostic}";
    }

    /// <summary>
    /// Runs the resolver key holders' type initializers on the machine that just completed the
    /// bootstrap, then captures the integer keys they installed.
    /// </summary>
    /// <remarks>
    /// The keys must be read from a machine that has already run the bootstrap, because the
    /// holders' initializers call into loader runtime state the bootstrap establishes. Reusing
    /// this machine avoids a second expensive interpretation, and the write log has already been
    /// materialized so nothing these initializers do can reach the method-body replay gate.
    /// A holder that cannot be interpreted contributes no keys instead of failing recovery: its
    /// call sites simply stay unproven downstream.
    /// </remarks>
    private static Dictionary<uint, int> CaptureResolverKeys(
        ModuleDefMD module,
        StaticMachine machine)
    {
        foreach (var holder in module.GetTypes()
                     .Where(type => type != module.GlobalType &&
                         ReactorStructureDetector.IsResolverKeyHolder(type)))
        {
            if (holder.FindStaticConstructor() is { HasBody: true } initializer)
                machine.Execute(initializer);
        }
        return InitializedFieldCapture.CaptureInstanceIntegers(module, machine.State);
    }

    /// <summary>
    /// Collects the decrypted bytes for every field whose data the rewrite covered, matched to the
    /// destination field by token so that nothing is identified by position.
    /// </summary>
    private static bool TryPrepareFieldData(
        ModuleDefMD destinationModule,
        ModuleDefMD restoredModule,
        IImageRewritePolicy policy,
        out IReadOnlyDictionary<FieldDef, byte[]> replacements,
        out string? diagnostic)
    {
        var result = new Dictionary<FieldDef, byte[]>();
        foreach (var destination in destinationModule.GetTypes()
                     .SelectMany(type => type.Fields)
                     .Where(field => field.HasFieldRVA && field.RVA != 0))
        {
            var length = destination.InitialValue?.Length ?? 0;
            if (length == 0 || !policy.CoversFieldData((uint)destination.RVA, length))
                continue;
            if (restoredModule.ResolveToken(destination.MDToken.Raw) is not FieldDef source ||
                source.RVA != destination.RVA)
            {
                replacements = result;
                diagnostic = $"Field 0x{destination.MDToken.Raw:X8} is missing or moved in the " +
                    "reparsed image.";
                return false;
            }
            if (source.InitialValue is not { } decrypted || decrypted.Length != length)
            {
                replacements = result;
                diagnostic = $"Field 0x{destination.MDToken.Raw:X8} has {source.InitialValue?.Length ?? 0} " +
                    $"byte(s) of data in the reparsed image where the original has {length}.";
                return false;
            }
            result.Add(destination, decrypted);
        }
        replacements = result;
        diagnostic = null;
        return true;
    }

    /// <summary>
    /// Whether two bodies hold the same instructions, which is how a graft that recovered nothing
    /// is told from one that recovered real code.
    /// </summary>
    private static bool BodiesMatch(CilBody left, CilBody right) =>
        left.Instructions.Count == right.Instructions.Count &&
        left.Instructions.Zip(right.Instructions).All(pair =>
            pair.First.OpCode == pair.Second.OpCode &&
            string.Equals(
                pair.First.Operand?.ToString(),
                pair.Second.Operand?.ToString(),
                StringComparison.Ordinal));

    private static bool TryPrepareBodies(
        ModuleDefMD destinationModule,
        ModuleDefMD restoredModule,
        IImageRewritePolicy policy,
        IReadOnlyList<RewriteTarget> targets,
        out IReadOnlyDictionary<MethodDef, CilBody> replacements,
        out string? diagnostic)
    {
        var result = new Dictionary<MethodDef, CilBody>();
        foreach (var target in targets)
        {
            if (destinationModule.ResolveToken(target.Token) is not MethodDef destination ||
                destination.MDToken.Raw != target.Token)
                return PrepareFailure(
                    out replacements,
                    out diagnostic,
                    $"Destination MethodDef token 0x{target.Token:X8} is missing.");
            if (restoredModule.ResolveToken(target.Token) is not MethodDef source ||
                source.MDToken.Raw != target.Token ||
                !source.HasBody ||
                (uint)source.RVA != target.Rva)
                return PrepareFailure(
                    out replacements,
                    out diagnostic,
                    $"Restored MethodDef token 0x{target.Token:X8} is missing or moved.");
            if (policy.IsStillProtected(source))
                return PrepareFailure(
                    out replacements,
                    out diagnostic,
                    $"MethodDef token 0x{target.Token:X8} is still protected.");
            // A recovered body is not necessarily longer than the placeholder: a protector pads
            // its stubs, so a real accessor can decode to fewer instructions. What must hold is
            // that the body actually changed.
            if (destination.HasBody && BodiesMatch(destination.Body, source.Body))
            {
                // Two opposite things look identical here. Either the rewrite produced nothing and the
                // stub is still in place, which is what this guards, or the body being asked for is
                // already there because an earlier round grafted it — the ordinary case as soon as the
                // loader is interpreted more than once, because Reactor's own runtime is protected too
                // and reading it takes a second pass. Refusing that threw away every later round.
                if (policy.IsStillProtected(destination))
                    return PrepareFailure(
                        out replacements,
                        out diagnostic,
                        $"MethodDef token 0x{target.Token:X8} still holds its placeholder body.");
                continue;
            }

            result.Add(
                destination,
                MethodBodyRecoveryInfrastructure.CloneBody(
                    source,
                    destination,
                    destinationModule));
        }
        replacements = result;
        diagnostic = null;
        return true;
    }

    private static bool PrepareFailure(
        out IReadOnlyDictionary<MethodDef, CilBody> replacements,
        out string? diagnostic,
        string message)
    {
        replacements = new Dictionary<MethodDef, CilBody>();
        diagnostic = message;
        return false;
    }
}
