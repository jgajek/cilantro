using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Interpretation;
using ReactorUnpack.Core.Passes;
using ReactorUnpack.Core.Verification;

namespace ReactorUnpack.Core.Recovery;

public sealed record MethodRecoveryAttempt(
    uint BootstrapToken,
    StaticExecutionStatus ExecutionStatus,
    int Steps,
    int StubCount,
    int ImageWriteCount,
    int ImageWriteBytes,
    string? Diagnostic);

public sealed class MethodBodyRecoveryPass : DeobfuscationPass
{
    public override string Name => "method-body-recovery";
    public override IReadOnlyCollection<string> Dependencies =>
        ["method-protection", "resource-roles", "control-flow-analysis"];

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        context.SetFact("method-protection.complete", false);
        if (!context.TryGetFact<IReadOnlyList<ProtectedMethodStub>>(
                "method-protection.stubs",
                out var stubs) ||
            stubs is null ||
            stubs.Count == 0)
        {
            context.SetFact("method-protection.complete", true);
            return (PassStatus.Success, 0, ["No protected method bodies require restoration."]);
        }

        var bootstrap = FindBootstrap(context.Module);
        if (bootstrap is null)
            return (PassStatus.Unsupported, 0,
                ["No structurally qualified module-initializer patch bootstrap was found."]);

        if (!MethodBodyRecoveryInfrastructure.TryCatalogStubPrefixWindows(
                context.OriginalImage,
                stubs,
                out var windows,
                out var catalogDiagnostic))
        {
            return (PassStatus.Failed, 0,
                [$"Protected-stub prefix catalog rejected the input: {catalogDiagnostic}"]);
        }

        var limits = BootstrapMachine.Environment(context).Declarations.Budgets.Over(
            new StaticMachineLimits(
                MaximumSteps: 2_000_000,
                MaximumRecursionDepth: 64,
                MaximumAllocatedBytes: 256 * 1024 * 1024,
                MaximumArrayLength: 256 * 1024 * 1024,
                MaximumProvenanceNodes: 1_000_000,
                MaximumProvenanceDepth: 8_192,
                MaximumRenderedProvenanceNodes: 96));
        var executionRoot = context.Module.GlobalType.FindStaticConstructor() ?? bootstrap;
        if (!TryExecuteBootstrap(
                context,
                executionRoot,
                limits,
                out var firstResult,
                out var firstWrites,
                out var firstKeys,
                out var firstEvidence,
                out var setupDiagnostic) ||
            !TryExecuteBootstrap(
                context,
                executionRoot,
                limits,
                out var secondResult,
                out var secondWrites,
                out var secondKeys,
                out var secondEvidence,
                out setupDiagnostic))
        {
            return (PassStatus.Failed, 0, [setupDiagnostic!]);
        }
        var writes = firstWrites
            .Where(write => write.RegionKind == "MappedImage")
            .ToArray();
        var deterministic = firstResult.Status == secondResult.Status &&
            firstResult.Steps == secondResult.Steps &&
            MethodBodyRecoveryInfrastructure.WriteLogsEqual(firstWrites, secondWrites);
        if (!deterministic)
        {
            return (PassStatus.Failed, 0,
            [
                "The two bounded bootstrap interpretations produced different status, step count, or write logs.",
                "No method body or initializer was modified."
            ]);
        }
        if (!InitializedFieldCapture.CapturesAgree(firstKeys, secondKeys))
        {
            return (PassStatus.Failed, 0,
            [
                "The two bounded bootstrap interpretations disagreed on loader-initialized integer fields.",
                "No method body or initializer was modified."
            ]);
        }
        if (!firstEvidence.Agrees(secondEvidence))
        {
            return (PassStatus.Failed, 0,
            [
                "The two bounded bootstrap interpretations disagreed on loader observations or effects.",
                "No method body or initializer was modified."
            ]);
        }

        var attempt = new MethodRecoveryAttempt(
            bootstrap.MDToken.Raw,
            firstResult.Status,
            firstResult.Steps,
            stubs.Count,
            writes.Length,
            writes.Sum(write => write.Bytes.Length),
            firstResult.Diagnostic);
        context.SetFact("method-protection.attempt", attempt);
        context.AddEvidence(new Evidence(
            "method-recovery",
            $"Two deterministic static bootstrap executions: {firstResult.Status}, " +
            $"{firstResult.Steps} steps, {writes.Length} mapped-image writes.",
            $"{bootstrap.MDToken} {bootstrap.FullName}",
            firstResult.Succeeded ? 0.95 : 0.75));

        if (!firstResult.Succeeded)
        {
            return (PassStatus.Unsupported, 0,
            [
                $"Both bounded bootstrap interpretations stopped after {firstResult.Steps} steps: " +
                $"{firstResult.Status}.",
                firstResult.Diagnostic ?? "No diagnostic was provided.",
                "No method body or initializer was modified."
            ]);
        }

        // The loader seeds per-site resolver keys into instance fields of a singleton it roots
        // in a static field. Downstream string and boolean recovery cannot prove any call-site
        // argument without them, and this is the only interpretation that runs the bootstrap.
        if (firstKeys.Count != 0)
        {
            context.SetFact<IReadOnlyDictionary<uint, int>>("bootstrap.integerFields", firstKeys);
            context.AddEvidence(new Evidence(
                "loader-key-fields",
                $"Captured {firstKeys.Count} loader-initialized integer field(s) that agreed " +
                "across two independent bootstrap interpretations.",
                $"{bootstrap.MDToken} {bootstrap.FullName}",
                0.95));
        }
        context.SetFact("bootstrap.evidence", firstEvidence);
        context.SetFact("bootstrap.token", bootstrap.MDToken.Raw);
        foreach (var group in firstEvidence.Observations.GroupBy(item => item.Kind))
        {
            context.AddEvidence(new Evidence(
                "loader-observation",
                $"{group.Key}: {group.Count()} occurrence(s); " +
                string.Join("; ", group.Select(item => item.Verdict is null
                    ? item.Detail
                    : $"{item.Detail} => {item.Verdict}").Distinct().Take(4)),
                $"{bootstrap.MDToken} {bootstrap.FullName}",
                0.95));
        }

        if (writes.Length == 0)
            return (PassStatus.Unsupported, 0,
                ["The bootstrap completed without concrete mapped-image writes; no restoration was applied."]);
        if (!MethodBodyRecoveryInfrastructure.TryValidateAndReplayWrites(
                context.OriginalImage,
                windows,
                writes,
                out var restoredBytes,
                out var recoveredTokens,
                out var replayDiagnostic))
        {
            return (PassStatus.Failed, 0,
            [
                $"Deterministic mapped-image writes failed the replay gate: {replayDiagnostic}",
                "No method body or initializer was modified."
            ]);
        }

        // Only the stubs the bootstrap actually rewrote were JIT-protected. A stub-shaped
        // method the loader never touched is genuinely trivial and must be left alone.
        var recoveredStubs = stubs.Where(stub => recoveredTokens.Contains(stub.Token)).ToArray();
        if (recoveredStubs.Length == 0)
            return (PassStatus.Unsupported, 0,
                ["The bootstrap wrote no protected method body; no restoration was applied."]);

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
                    recoveredStubs,
                    out var replacements,
                    out var graftDiagnostic))
            {
                return (PassStatus.Failed, 0,
                [
                    $"Reparsed-image validation failed: {graftDiagnostic}",
                    "No method body or initializer was modified."
                ]);
            }

            var snapshots = replacements.Keys
                .Distinct()
                .ToDictionary(method => method, MethodBodySnapshot.Capture);
            try
            {
                foreach (var replacement in replacements)
                    replacement.Key.Body = replacement.Value;

                if (recoveredStubs.Any(stub =>
                        context.Module.ResolveToken(stub.Token) is not MethodDef restored ||
                        !restored.HasBody ||
                        ReactorStructureDetector.IsProtectedMethodStub(restored)))
                {
                    throw new InvalidOperationException(
                        "At least one protected method remained a stub after grafting.");
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
                return (PassStatus.Failed, 0,
                [
                    exception.Message,
                    "All method-body changes were rolled back."
                ]);
            }

            foreach (var stub in stubs)
            {
                context.AddChange(new ChangeRecord(
                    Name,
                    "restore-method-body",
                    $"0x{stub.Token:X8} {stub.Method}",
                    "Grafted deterministic statically restored CIL by unchanged MethodDef token."));
            }
            context.SetFact("method-protection.complete", true);
            context.SetFact("method-protection.restored", replacements.Count);
            return (PassStatus.Success, replacements.Count,
            [
                $"Restored and verified all {replacements.Count} protected method bodies.",
                $"Replayed {writes.Length} deterministic writes while preserving all bytes outside stub prefixes.",
                "Removing the loader bootstrap itself is left to anti-tamper neutralization."
            ]);
        }
        catch (Exception exception) when (
            exception is BadImageFormatException or IOException or InvalidOperationException or
                ArgumentException or OverflowException)
        {
            return (PassStatus.Failed, 0,
            [
                $"Restored image could not be safely reparsed or grafted: {exception.Message}",
                "No method body or initializer was modified."
            ]);
        }
        finally
        {
            restoredModule?.Dispose();
        }
    }

    private static bool TryExecuteBootstrap(
        ArtifactContext context,
        MethodDef bootstrap,
        StaticMachineLimits limits,
        out StaticExecutionResult result,
        out IReadOnlyList<MappedImageWrite> writes,
        out Dictionary<uint, int> integerFields,
        out LoaderInterpretationEvidence evidence,
        out string? diagnostic)
    {
        integerFields = [];
        evidence = LoaderInterpretationEvidence.Empty;
        var machine = new StaticMachine(limits, modelTypeInitialization: true);
        // The same environment the rest of the run uses, so that a fact stated for the run is
        // answered here too and a refusal here lands in the run's ledger.
        machine.State.RegisterRunEnvironment(BootstrapMachine.Environment(context));
        foreach (var resource in context.Module.Resources.OfType<EmbeddedResource>())
            machine.State.RegisterResource(resource.Name, resource.CreateReader().ToArray());
        machine.State.RegisterAssemblyIdentity(
            context.Module.Assembly?.Name ?? context.Module.Name,
            context.Module.Assembly?.PublicKeyToken?.Data ?? []);
        machine.State.RegisterPointerSize(context.OriginalImage.IsPe32Plus ? 8 : 4);
        machine.State.RegisterModuleFile(
            Path.GetFullPath(context.InputPath),
            context.OriginalBytes);
        if (!machine.State.TryRegisterImage(
                context.OriginalImage.CreateMappedImage(),
                context.OriginalImage.ImageBase))
        {
            result = new StaticExecutionResult(StaticExecutionStatus.AllocationLimitExceeded, default);
            writes = [];
            diagnostic = "Mapped PE image exceeded the interpreter allocation budget.";
            return false;
        }
        result = machine.Execute(bootstrap);
        // Materialize the write log before anything else runs: only the bootstrap's own writes
        // may be replayed into method-body slots.
        writes = machine.State.Heap.ImageWrites
            .Select(MappedImageWrite.From)
            .ToArray();
        // Snapshot before the key-holder initializers run so the evidence describes the loader
        // bootstrap alone.
        evidence = machine.State.LoaderEvidence;
        if (result.Succeeded)
            integerFields = CaptureResolverKeys(context.Module, machine);
        if (machine.State.TypeInitializationEvents.Count != 0)
        {
            var events = string.Join(
                ", ",
                machine.State.TypeInitializationEvents
                    .Take(24)
                    .Select(item =>
                        $"{item.Sequence}:{item.Type}={item.Status}"));
            if (machine.State.TypeInitializationEvents.Count > 24)
                events += ", …";
            result = result with
            {
                Diagnostic = $"Type initialization: {events}. {result.Diagnostic}"
            };
        }
        diagnostic = null;
        return true;
    }

    /// <summary>
    /// Runs the resolver key holders' type initializers on the machine that just completed the
    /// loader bootstrap, then captures the integer keys they installed.
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
        IReadOnlyList<ProtectedMethodStub> stubs,
        out IReadOnlyDictionary<MethodDef, CilBody> replacements,
        out string? diagnostic)
    {
        var result = new Dictionary<MethodDef, CilBody>();
        foreach (var stub in stubs)
        {
            if (destinationModule.ResolveToken(stub.Token) is not MethodDef destination ||
                destination.MDToken.Raw != stub.Token)
                return PrepareFailure(
                    out replacements,
                    out diagnostic,
                    $"Destination MethodDef token 0x{stub.Token:X8} is missing.");
            if (restoredModule.ResolveToken(stub.Token) is not MethodDef source ||
                source.MDToken.Raw != stub.Token ||
                !source.HasBody ||
                (uint)source.RVA != stub.Rva)
                return PrepareFailure(
                    out replacements,
                    out diagnostic,
                    $"Restored MethodDef token 0x{stub.Token:X8} is missing or moved.");
            if (ReactorStructureDetector.IsProtectedMethodStub(source))
                return PrepareFailure(
                    out replacements,
                    out diagnostic,
                    $"MethodDef token 0x{stub.Token:X8} is still a protected stub.");
            // A recovered body is not necessarily longer than the placeholder: Reactor pads its
            // stubs with nops, so a real accessor can decode to fewer instructions. What must
            // hold is that the body actually changed.
            if (destination.HasBody && BodiesMatch(destination.Body, source.Body))
                return PrepareFailure(
                    out replacements,
                    out diagnostic,
                    $"MethodDef token 0x{stub.Token:X8} still holds its stub body.");

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

    private static MethodDef? FindBootstrap(ModuleDef module)
    {
        var initializer = module.GlobalType.FindStaticConstructor();
        if (initializer?.HasBody != true)
            return null;
        return initializer.Body.Instructions
            .Where(instruction => instruction.OpCode.FlowControl == FlowControl.Call)
            .Select(instruction => (instruction.Operand as IMethod)?.ResolveMethodDef())
            .FirstOrDefault(method => method?.HasBody == true &&
                method.IsStatic &&
                method.MethodSig?.Params.Count == 0 &&
                method.Body.Instructions.Count >= 100);
    }
}
