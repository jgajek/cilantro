using System.Collections.ObjectModel;
using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using Cilantro.Core.Analysis;
using Cilantro.Core.Codec;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Native;
using Cilantro.Core.Passes;
using Cilantro.Core.Pipeline;
using Cilantro.Core.Proxy;
using Cilantro.Core.Recovery;
using Cilantro.Core.Strings;
using Cilantro.Core.Verification;
using Cilantro.Core.Payload;

namespace Cilantro.Core;

public sealed class CilantroPipeline
{
    public const string Version = "0.10.4";

    /// <summary>
    /// Where the run's cancellation token sits on the context, for the passes that run a pipeline of
    /// their own and cannot see the options.
    /// </summary>
    public const string CancellationFact = "options.cancellation";

    /// <summary>
    /// How everything the tool writes as JSON is written, so that all of it reads the same way.
    /// </summary>
    /// <remarks>
    /// Public because the reports on disk are not the only JSON a caller sees: <c>--json</c> puts a
    /// manifest of the run on standard output, and a caller that has learned how one of them spells
    /// things should not find the other spelling them differently.
    /// </remarks>
    public static JsonSerializerOptions ReportJsonOptions { get; } = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    private readonly IReadOnlyList<IDeobfuscationPass> _passes;

    public CilantroPipeline(IEnumerable<IDeobfuscationPass>? passes = null)
    {
        _passes = (passes ?? CreateDefaultPasses()).ToArray();
        ValidateDependencies(_passes);
    }

    public static IReadOnlyList<IDeobfuscationPass> CreateDefaultPasses() =>
    [
        new MetadataPreflightPass(),
        new ReactorDetectionPass(),
        new ConfuserExDetectionPass(),
        new ProtectorIdentityPass(),
        new MethodProtectionAnalysisPass(),
        new FieldRvaRecoveryPass(),
        new ResourceAnalysisPass(),
        new ResourceRolePass(),
        // ConfuserEx encrypts the bodies themselves, so nothing that reads a body can run before
        // this: it is the pass that makes the module readable at all.
        new ConfuserExAntiTamperPass(),
        // The control-flow census has to follow decryption. Run ahead of it, a ConfuserEx module
        // presents almost no readable bodies, so the pass reports a nearly flat-free module when
        // most of it is flattened.
        new ControlFlowAnalysisPass(),
        new MethodBodyRecoveryPass(),
        // Repair invalid attribute references before IL transforms invoke the verifier;
        // otherwise unrelated body rewrites roll back because of damaged input metadata.
        new MetadataSanitizationPass(),
        new StringTableRecoveryPass(),
        new BooleanRecoveryPass(),
        new AntiTamperNeutralizationPass(),
        // Bodies are all present by now, which is what makes the search for a field's writers
        // mean anything: a method still holding encrypted bytes could have held the write.
        new UnwrittenFieldFoldingPass(),
        new ConstantPredicatePass(),
        // Loader-initialized state is folded before the control-flow passes, because turning its
        // reads into constants is what makes Reactor's guards look like the constant branches those
        // passes already know how to collapse.
        new GlobalStateCapturePass(),
        new GlobalPredicateFoldingPass(),
        new DispatcherTailSeparationPass(),
        new DispatcherDeobfuscationPass(),
        new CfgDeadCodePass(),
        new ControlFlowCompletionPass(),
        new TypeRestorationPass(),
        new DelegateProxyPass(),
        new StringRecoveryPass(),
        // Strings the protector left to per-string decoders rather than to its table are folded
        // after the table, because a decoder can read a table entry but never the other way round.
        new ConstantStringPass(),
        new NumericTableRecoveryPass(),
        new IntegerHelperRecoveryPass(),
        // ConfuserEx keeps its literals in one buffer that its own getters read, which is neither a
        // table a reading can index nor a decoder per string. It runs beside the other two because
        // what it produces is the same thing: an ldstr where a call used to be.
        new ConfuserExConstantsPass(),
        // Forwarder redirection runs after the rewrites, not before: replacing a resolver call with
        // its string or a proxy dispatch with a direct call is what leaves many of Reactor's
        // wrappers as the bare pass-throughs this pass can prove and skip.
        new MethodInliningPass(),
        // Token recovery follows it for the same reason in reverse: the sites it reads are the ones
        // redirection just brought into view.
        new TokenRecoveryPass(),
        new VirtualizationDisassemblyPass(),
        // Reading the engine is what learns this build's numbering, so the one reading of the string
        // table that could not assume a numbering is only possible from here on.
        new StringTableRelearningPass(),
        new StringLookupRecoveryPass(),
        // Resource classification and payload extraction run last because a JIT-hook artifact hides
        // every resource consumer behind an encrypted body and an encrypted name literal. Last has to
        // mean after the late reading as well as after the early one: a build that renumbered its
        // engine has its strings restored there, so ahead of it the name a consumer loads is still a
        // call into the resolver and the resource it reads is attributed to nothing. Every resource
        // then falls to the entropy fallback and is called a method-patch stream, the bundle included,
        // and the reading that would decrypt it declines on a module that plainly has one.
        new ResourceRoleRefinementPass(),
        new ResourceRestorationPass(),
        new ResourceHookElisionPass(),
        // The first loader cut follows interpretation-based recovery. It also enables inlining
        // through initializers that have become empty. Reconstructed bodies get a later recheck.
        new LoaderCallElisionPass(),
        // Calls through an effectful type initializer could not safely be skipped earlier. Once
        // loader elision has proved and removed its work, the empty initializer no longer blocks them.
        new MethodInliningRecheckPass(),
        new NumericTableRecheckPass(),
        new IntegerHelperRecheckPass(),
        new PayloadExtractionPass(),
        new CosturaExtractionPass(),
        new ResourceEntryExtractionPass(),
        // Building the read-back methods precedes cleanup, which would otherwise delete the very
        // stubs the bodies go into, and follows the payload passes, which have to see the module
        // doing its own work rather than the tool's account of it.
        new VirtualizationRebuildPass(),
        // The body the rebuild just wrote has had none of the folding the rest of the module got,
        // every pass that does it having run while this method was still a stub. It gets it here.
        new RebuiltBodyCleanupPass(),
        // The loader's own state can be folded now and could not be before. Its values were proven
        // on the first run, but the writes were the engine's and named no field, so nothing could be
        // said about whether they were the last ones. The body just written says it.
        new GlobalPredicateRecheckPass(),
        // And the branches that fold left standing on literals are folded, which is both half of
        // the predicate the analyst would otherwise be handed and the thing hiding the flattening
        // the pass below looks for.
        new ControlFlowRecompletionPass(),
        new DispatcherPathPass(),
        // Flattening is looked for once more here, at the end. Every pass above takes something out
        // of the middle of a method body — a proxy call, a resolver call, a loader call — and until
        // they have, a dispatcher does not look like one. See DispatcherRecheckPass.
        new DispatcherRecheckPass(),

        // Final stack normalization: the conversions the bypassed proxy adapters were
        // doing go in once nothing else is going to read the bodies they go into, and the state the
        // folded dispatchers were handed on the stack goes into a local once no pass is going to
        // fold another edge and strand another head.
        new ProxyNarrowingPass(),
        new StackHandoffPass(),
        // Reconstruction can expose loader-owned writes and let the predicate recheck remove
        // their readers. Revisit initialization before cleanup decides which runtime helpers live.
        new LoaderCallRecheckPass(),
        new NumericTableCompletionPass(),
        // Earlier integer-helper discovery can see an obfuscated body that only becomes
        // provably pure after the final CFG and loader passes. Consume those constants now.
        new IntegerHelperCompletionPass(),
        new ControlFlowHelperCompletionPass(),
        // Generated factories must first lose proven constant guards. Reconstruct before
        // reachability cleanup so their discarded emitters no longer retain virtual targets.
        new EmittedMethodReconstructionPass(),
        new DispatcherPathCompletionPass(),
        new IntegrityVerdictPass(),
        new ReactorTrialGuardRemovalPass(),
        new RuntimeCleanupPass(),
        new UnwrittenGuardCompletionPass(),
        new NumericTableFinalizationPass(),
        new ControlFlowTableFinalizationPass(),
        // Cloning effectful paths earlier can obscure shapes needed by dispatcher recovery.
        new EffectfulDispatcherCompletionPass(),
        new SymbolRenamingPass(),
        new ReconstructionStateAuditPass(),
        // What a rebuilt body reaches is written down last, after cleanup has settled what calls it
        // and renaming has settled what everything is called, so the account names what a reader
        // will actually find rather than what the module said several passes ago.
        new RebuiltBodyDigestPass()
    ];

    /// <summary>Runs the pipeline over one assembly.</summary>
    /// <remarks>
    /// The run proper is <see cref="RunCore"/>; this wraps it in the reporting of its own progress,
    /// which is a separate concern and one with an exception path. Every way out of the pipeline has to
    /// leave a terminal status behind, or a caller polling the file would wait for a run that is not
    /// coming back — so the phase is recorded here, where all three ways out are visible at once,
    /// rather than at whichever point inside produced it.
    /// </remarks>
    public PipelineResult Run(string inputPath, PipelineOptions? options = null)
    {
        options ??= new PipelineOptions();
        // Planned up front rather than inside the loop, because the number of passes is the
        // denominator of the run's progress and a caller polling for it should not have to wait for
        // the first pass to learn how many there are.
        var plan = PipelinePlanner.Plan(_passes);
        if (options.StatusPath is not { } statusPath)
        {
            return Finish(RunCore(inputPath, options, plan, null), options);
        }

        using var status = RunStatusWriter.Begin(statusPath, inputPath, plan.Count);
        try
        {
            var result = Finish(RunCore(inputPath, options, plan, status), options, status);
            status.Finished(RunManifest.Of(result));
            return result;
        }
        catch (OperationCanceledException)
        {
            status.Cancelled();
            throw;
        }
        catch (Exception exception)
        {
            // The type is named as well as the message because the messages of the exceptions that
            // reach here are written for a developer reading a stack trace, and without the type some
            // of them do not say what went wrong.
            status.Failed($"{exception.GetType().Name}: {exception.Message}");
            throw;
        }
    }

    private PipelineResult Finish(PipelineResult result, PipelineOptions options, RunStatusWriter? status = null)
    {
        result = AnalystReport.Write(result, options.AnalyzeOnly);
        if (!options.RecoverEmbeddedAssemblies && result.Report.Protector != NativeBootstrapStage.BootstrapProtector)
            return result;
        // One traversal owns every stage and its budgets. Calling Run here would start
        // a new traversal for each native child, losing deduplication and depth limits.
        result = EmbeddedAssemblyRecovery.Run(result, options, (path, childOptions) =>
            AnalystReport.Write(RunCore(path, childOptions, PipelinePlanner.Plan(_passes), status),
                childOptions.AnalyzeOnly), nativeOnly: !options.RecoverEmbeddedAssemblies);
        return AnalystReport.Write(result, options.AnalyzeOnly);
    }

    private PipelineResult RunCore(
        string inputPath,
        PipelineOptions options,
        IReadOnlyList<PlannedPass> plan,
        RunStatusWriter? status)
    {
        options.Cancellation.ThrowIfCancellationRequested();
        // What the run was told is read before the module is, because a declarations file that
        // cannot be read is the caller's mistake and there is no point loading a sample to find out.
        var declarations = (options.DeclarationsPath is { } stated
            ? RunDeclarations.Load(stated)
            : RunDeclarations.None).Allowing(options.AllowDeclaredCalls);
        // A profile passed on its own is the facts section written in its own file. Passing both a
        // profile and a set of declarations that state facts is refused rather than resolved by a
        // precedence rule, because a caller who has written the same fact in two files and seen one
        // of them silently lose has learned nothing about which.
        if (options.HostProfilePath is not null && declarations.Stated)
        {
            throw new DeclarationException(
                "The facts are stated twice: once in the declarations and once in the profile " +
                $"{options.HostProfilePath}. Keep them in one file.");
        }

        // Told nothing about the machine, a triage run assumes a plausible one and a strict run assumes
        // as little as the tool can while still interpreting anything. Either way the report says which
        // and marks every answer as stated or assumed.
        var host = new HostEnvironment(options.HostProfilePath is { } profile
            ? HostProfile.Load(profile)
            : declarations.Stated
                ? declarations.Facts
                : options.Strict
                    ? HostProfile.Default
                    : HostProfile.Workstation);
        // Before the managed load, because a native bootstrap has nothing for it to load: the
        // assembly is inside the file rather than being the file. Finish follows the extracted
        // managed stage through the same passes while retaining this wrapper's provenance.
        if (NativeBootstrapStage.TryRun(inputPath, options, out var recovered))
            return recovered;

        using var context = ArtifactContext.Load(
            inputPath,
            [.. options.LibraryPaths ?? [], .. declarations.Libraries]);
        context.SetFact("options.removeRuntime", options.RemoveRuntime);

        // What the caller did not decide, the mode decides: a triage run does the things that make
        // the result easier to read, and a strict one leaves the assembly as close to what it can
        // prove as it can.
        context.SetFact("options.renameSymbols", options.Renames);
        context.SetFact("options.foldUnwrittenState", options.FoldsUnwrittenState);
        // A run asked only to say what is there builds nothing, so it does not pay for the building
        // or for the run that checks it.
        context.SetFact("options.devirtualize", options.Devirtualizes && !options.AnalyzeOnly);
        // Carried on the context because the second pass loop that checks the rebuilt bodies is
        // reached from inside a pass, which has the context and not the options.
        context.SetFact(CancellationFact, options.Cancellation);
        var environment = new RunEnvironment(host, declarations, strict: options.Strict);
        context.SetFact(BootstrapMachine.RunEnvironmentFact, environment);
        RecordLibraries(context);
        RecordDeclarations(context, declarations, options);

        for (var index = 0; index < plan.Count; index++)
        {
            // Between passes rather than within them. See PipelineOptions.Cancellation for why that
            // is bounded.
            options.Cancellation.ThrowIfCancellationRequested();
            var planned = plan[index];
            var pass = planned.Pass;
            // Said before the pass is decided rather than after, so that the count advances past the
            // passes a plan leaves out instead of stalling on them.
            status?.Entering(pass.Name, index);
            if (declarations.Skips(pass.Name))
            {
                // A pass left out is not a pass that succeeded, so this still withholds the clean
                // copy where the pass was one the emission depends on.
                context.AddPassResult(new PassResult(
                    pass.Name,
                    PassStatus.Unsupported,
                    0,
                    [$"The run's declarations left {pass.Name} out."],
                    TimeSpan.Zero));
                continue;
            }

            var dependencyFailed = pass.Dependencies.Any(dependency =>
                context.PassResults.Any(result =>
                    result.Pass == dependency && result.Status == PassStatus.Failed));
            if (dependencyFailed)
            {
                context.AddPassResult(new PassResult(
                    pass.Name,
                    PassStatus.Unsupported,
                    0,
                    ["A required pass failed."],
                    TimeSpan.Zero));
                continue;
            }

            var decision = PipelinePlanner.Decide(planned, context);
            if (!decision.Execute)
            {
                context.AddPassResult(new PassResult(
                    pass.Name,
                    PassStatus.Unsupported,
                    0,
                    [decision.Reason!],
                    TimeSpan.Zero));
                continue;
            }

            environment.Pass = pass.Name;
            context.AddPassResult(pass.Run(context));
            environment.Pass = null;
        }

        var allowance = BuildRewriteAllowance(context);
        var verification = AssemblyVerifier.Verify(
            context.Module,
            context.OriginalIdentity,
            context.OriginalStructure,
            allowance);
        var fatalFailure = context.PassResults.Any(result => result.Status == PassStatus.Failed);
        var emissionGates = _passes
            .Where(pass => pass.GatesEmission &&
                !(options.GenericRecovery && pass is ProtectorIdentityPass))
            .Select(pass => pass.Name)
            .ToHashSet(StringComparer.Ordinal);
        var incompleteRecovery = context.PassResults.Any(result =>
            (options.FailOnPartial || emissionGates.Contains(result.Pass)) &&
            result.Status is PassStatus.Partial or PassStatus.Unsupported);
        var canEmit = !options.AnalyzeOnly &&
            verification.Passed &&
            !fatalFailure &&
            !incompleteRecovery;

        if (options.GenericRecovery)
            context.AddEvidence(new Evidence("recovery-mode",
                "Generic recovery requested: protector identification is not required for emission; other recovery and verification gates still apply."));

        var inputDirectory = Path.GetDirectoryName(Path.GetFullPath(context.InputPath))!;
        var stem = Path.GetFileNameWithoutExtension(context.InputPath);
        // Reports and payloads go into a folder of their own so that running the tool on a sample
        // leaves two things beside it rather than five. The cleaned assembly is not one of them: it
        // is the thing the analyst came for, so it lands next to the input where it can be found.
        // The folder is not named after the sample because the files inside it already are, which
        // lets a directory of samples share one folder without any of them colliding.
        var reportDirectory = RunStatus.DirectoryFor(context.InputPath, options.ReportDirectory);
        Directory.CreateDirectory(reportDirectory);
        var analysisPath = Path.Combine(reportDirectory, $"{stem}.analysis.json");
        var changesPath = Path.Combine(reportDirectory, $"{stem}.changes.json");
        // A cleaned library is still a library. Naming every output `.exe` produced a file that
        // tools would refuse by extension alone.
        var outputPath = options.OutputPath is null
            ? Path.Combine(
                inputDirectory,
                $"{stem}.cleaned{Path.GetExtension(context.InputPath)}")
            : Path.GetFullPath(options.OutputPath);

        var payloadPaths = WritePayloads(context, reportDirectory, stem);
        var renameMapPath = WriteRenameMap(context, reportDirectory, stem);
        var virtualProgramPaths = WriteVirtualPrograms(context, reportDirectory, stem);
        var programsRunElsewhere =
            context.TryGetFact<IReadOnlyList<VirtualProgram>>(
                "virtualization.otherPrograms", out var runElsewhere) && runElsewhere is not null
                ? runElsewhere.Count
                : 0;

        // Emission happens before the report is written so that a module which verifies in memory
        // but not once serialized is explained rather than silently withheld. Round-tripping is the
        // only check that sees what the metadata writer actually produced.
        // Compact deleted rows instead of asking the writer to fill their gaps with dummy
        // declarations. Cleanup declines deletion while live numeric-token consumers remain.
        // Appended reconstruction metadata does not require renumbering existing rows.
        context.TryGetFact<int>("cleanup.removedTypeCount", out var removedTypeCount);
        context.TryGetFact<int>("cleanup.removedMethodCount", out var removedMethodCount);
        var preserveTokens = options.PreserveTokens &&
            removedTypeCount == 0 &&
            removedMethodCount == 0;

        if (canEmit)
        {
            var reformed = BranchForms.Reach(context.Module);
            var expectedShape = ModuleShape.Capture(context.Module);
            var complaints = WriteModule(context.Module, outputPath, preserveTokens);
            var outputVerification = AssemblyVerifier.VerifyRoundTrip(outputPath, expectedShape);

            // Said whether or not the emission is withheld over it. The writer complains about the
            // max stack of bodies Reactor wrote, which is what Reactor left rather than what the run
            // did, so a run is not refused for it — but a complaint nobody records is a complaint
            // nobody reads, and the last one to go unread cost three methods of a payload their
            // control flow.
            string[] emission =
            [
                .. reformed == 0
                    ? Array.Empty<string>()
                    : [$"Re-formed the branches of {reformed} method(s) whose short forms no " +
                       "longer reached their targets."],
                .. complaints.Select(said => $"The metadata writer reported: {said}")
            ];
            if (emission.Length != 0)
            {
                verification = verification with
                {
                    Diagnostics = [.. verification.Diagnostics, .. emission]
                };
                outputVerification = outputVerification with
                {
                    Diagnostics = [.. outputVerification.Diagnostics, .. emission]
                };
            }

            if (!outputVerification.Passed)
            {
                File.Delete(outputPath);
                canEmit = false;
                outputPath = null;
                verification = outputVerification with
                {
                    Diagnostics =
                    [
                        "The emitted module did not verify after serialization and was discarded.",
                        .. outputVerification.Diagnostics
                    ]
                };
            }
        }
        else
        {
            outputPath = null;
        }

        var resourceInfos = ResourceInspector.Inspect(context.Module);
        var report = BuildReport(context, resourceInfos, verification, payloadPaths);
        WriteJson(analysisPath, report);
        WriteJson(changesPath, context.Changes);
        var blockersPath = Path.Combine(reportDirectory, $"{stem}.blockers.json");
        WriteJson(blockersPath, new BlockerReport(
            Version,
            context.InputPath,
            context.OriginalSha256,
            declarations.Name,
            declarations.Sha256,
            declarations.CallsAllowed,
            environment.Blockers.Blockers,
            [.. declarations.Unconsulted.Select(call => $"{call.Method} {call.Describe()}")],
            options.Strict,
            environment.Blockers.Continuations));

        // Written only where there is something to write, so that its presence in the manifest is
        // itself the answer to whether the sample kept its constants out of the metadata.
        string? configPath = null;
        if (context.TryGetFact<IReadOnlyList<RecoveredConstant>>(
                "confuserex.constants", out var constants) &&
            constants is { Count: > 0 })
        {
            configPath = Path.Combine(reportDirectory, $"{stem}.config.json");
            WriteJson(configPath, new ConfigReport(
                Version,
                context.InputPath,
                context.OriginalSha256,
                context.TryGetFact<ProtectorIdentity>("protector.identity", out var identity) &&
                    identity is not null
                    ? identity.Name
                    : "unknown",
                constants));
        }

        // What the rebuild did is read back rather than done here: the bodies went into the module
        // during the run, before cleanup could delete the methods they belong to.
        context.TryGetFact<IReadOnlyList<string>>(
            VirtualizationRebuildPass.NotesFact, out var devirtualizationNotes);
        context.TryGetFact<DevirtualizationCheck>(
            VirtualizationRebuildPass.CheckFact, out var devirtualizationCheck);
        context.TryGetFact<IReadOnlySet<uint>>(
            VirtualizationRebuildPass.RebuiltFact, out var rebuiltMethods);
        context.TryGetFact<int>(VirtualizationRebuildPass.LiftedFact, out var liftedPrograms);

        return new PipelineResult(
            canEmit || options.AnalyzeOnly && !fatalFailure,
            analysisPath,
            changesPath,
            outputPath,
            payloadPaths,
            report)
        {
            VirtualProgramPaths = virtualProgramPaths,
            VirtualizedMethods = virtualProgramPaths
                .Count(path => path.EndsWith(".vmprogram.txt", StringComparison.Ordinal)) -
                programsRunElsewhere,
            ProgramsRunElsewhere = programsRunElsewhere,
            BlockerReportPath = blockersPath,
            ConfigReportPath = configPath,
            RenameMapPath = renameMapPath,
            DevirtualizationNotes = devirtualizationNotes ?? [],
            DevirtualizationCheck = devirtualizationCheck,
            // Only where the cleaned copy was written does the count describe something the analyst
            // has: the bodies went into the module either way, but a run that withheld the copy
            // delivered no code to read.
            LiftedPrograms = outputPath is null ? 0 : liftedPrograms,
            RebuiltMethods = outputPath is null ? 0 : rebuiltMethods?.Count ?? 0
        };
    }

    /// <param name="payloadPaths">
    /// Where each payload was written, in the order they were extracted, or empty where the run wrote
    /// none.
    /// </param>
    private static ArtifactReport BuildReport(
        ArtifactContext context,
        IReadOnlyList<ResourceInfo> resources,
        VerificationResult verification,
        List<string>? payloadPaths = null)
    {
        var types = context.Module.GetTypes().ToArray();
        var methods = types.SelectMany(type => type.Methods).ToArray();
        context.TryGetFact<IReadOnlyList<ExtractedPayload>>("payload.artifacts", out var payloads);
        context.TryGetFact<int>("method-protection.restored", out var restoredBodies);
        // Both protectors put bodies back into the same module by the same mechanism, so they are
        // counted together: a reader wants to know how much of the code arrived, not which layer
        // was holding it.
        context.TryGetFact<int>("confuserex.antitamper.restored", out var decryptedBodies);
        restoredBodies += decryptedBodies;
        context.TryGetFact<IReadOnlyList<ProtectedMethodStub>>(
            "method-protection.stubs",
            out var protectedStubs);
        context.TryGetFact<int>("strings.callSites", out var stringCallSites);
        context.TryGetFact<int>("strings.replacedSites", out var replacedStringSites);
        context.TryGetFact<int>("booleans.replacedSites", out var booleansRecovered);
        context.TryGetFact<int>("tokens.restored", out var tokensRestored);
        context.TryGetFact<int>("proxy.restoredCallSites", out var proxyCallsRestored);
        context.TryGetFact<int>("resources.restoredBundles", out var resourcesRestored);
        context.TryGetFact<int>("cfg.unreachableInstructionsRemoved", out var unreachableRemoved);
        context.TryGetFact<int>("cfg.methodsSimplified", out var controlFlowMethodsSimplified);
        context.TryGetFact<int>("cfg.constantBranchesFolded", out var constantBranchesFolded);
        context.TryGetFact<int>("cfg.dispatcherEdgesRedirected", out var redirectedEdges);
        context.TryGetFact<int>("cfg.dispatcherMethodsRewritten", out var dispatcherMethodsRestored);
        context.TryGetFact<int>("cfg.dispatcherCandidates", out var dispatcherMethodCandidates);
        context.TryGetFact<int>("cleanup.removedTypeCount", out var runtimeTypesRemoved);
        context.TryGetFact<IReadOnlyDictionary<string, string>>("rename.map", out var renameMap);
        context.TryGetFact<int>("virtualization.operations", out var virtualOperations);
        context.TryGetFact<int>("virtualization.operationsRead", out var virtualRead);
        context.TryGetFact<int>("virtualization.operationsWalked", out var virtualWalked);
        context.TryGetFact<int>("virtualization.depthDisagreements", out var virtualDisagreements);
        context.TryGetFact<int>("strings.constantSites", out var constantStringSites);
        context.TryGetFact<RunEnvironment>(
            BootstrapMachine.RunEnvironmentFact, out var environment);
        return new ArtifactReport(
            Version,
            context.InputPath,
            context.OriginalSha256,
            context.OriginalBytes.LongLength,
            context.Module.Name,
            context.Module.RuntimeVersion,
            context.Module.EntryPoint?.MDToken.Raw ?? 0,
            types.Length,
            methods.Length,
            methods.Count(method => method.HasBody),
            resources.Count,
            resources,
            payloads?.Select((payload, index) => payload.Info with
            {
                WrittenTo = payloadPaths is not null && index < payloadPaths.Count
                    ? payloadPaths[index]
                    : null
            }).ToArray() ?? [],
            context.Evidence,
            context.PassResults,
            new RecoveryReportMetrics(
                restoredBodies,
                Math.Max(0, (protectedStubs?.Count ?? 0) - restoredBodies),
                stringCallSites,
                replacedStringSites,
                context.Changes.Count,
                booleansRecovered,
                tokensRestored,
                resourcesRestored,
                unreachableRemoved,
                CountRemainingSwitchDispatchers(context.Module),
                redirectedEdges,
                runtimeTypesRemoved,
                renameMap?.Count ?? 0,
                CountRemainingUnreachableInstructions(context.Module),
                virtualOperations,
                virtualRead,
                virtualWalked,
                virtualDisagreements,
                constantStringSites,
                proxyCallsRestored,
                controlFlowMethodsSimplified,
                constantBranchesFolded,
                dispatcherMethodsRestored,
                dispatcherMethodCandidates),
            verification.Passed,
            verification.Diagnostics,
            Consulted(environment?.Host),
            environment?.Blockers.Blockers,
            Told(environment?.Declarations),
            environment?.Blockers.Continuations,
            environment?.Strict ?? true,
            context.TryGetFact<ProtectorIdentity>(ProtectorIdentityPass.Fact, out var protector) &&
                protector is not null
                ? protector.Token
                : "none",
            context.TryGetFact<IReadOnlyList<RebuiltMethodReport>>(
                RebuiltBodyDigestPass.DigestFact, out var rebuiltDigest)
                ? rebuiltDigest
                : null);
    }

    /// <summary>What the run was told, as the report says it.</summary>
    private static DeclarationReport? Told(RunDeclarations? declarations) => declarations is null
        ? null
        : new DeclarationReport(
            declarations.Name,
            declarations.Sha256,
            declarations.CallsAllowed,
            declarations.Libraries,
            declarations.SkippedPasses,
            [.. declarations.Consulted.Select(call => $"{call.Method} {call.Describe()}")],
            [.. declarations.Unconsulted.Select(call => $"{call.Method} {call.Describe()}")]);

    /// <summary>
    /// Says in the report which libraries the interpreter was allowed to run, and which build.
    /// </summary>
    /// <remarks>
    /// A result that depended on somebody else's code should name the copy of it that was used,
    /// because a different build of the same library is a different program. A build that is not
    /// the one the sample was compiled against is worth saying out loud rather than refusing over:
    /// the reference carries a version the loader would have redirected anyway, and the analyst who
    /// supplied the file is better placed than the tool to know whether it is close enough.
    /// </remarks>
    private static void RecordLibraries(ArtifactContext context)
    {
        foreach (var library in context.Libraries)
        {
            context.AddEvidence(new Evidence(
                "trusted-library",
                $"{library.Name} {library.Version} was supplied for the interpreter to run, from " +
                $"{Path.GetFileName(library.Path)} (SHA-256 {library.Sha256})." +
                (library.MatchesReference
                    ? string.Empty
                    : " The sample was built against a different version of it."),
                library.Path,
                library.MatchesReference ? 1.0 : 0.6));
        }
    }

    /// <summary>
    /// Says in the report what the run was told, so that a result which rests on a declaration says
    /// so on its own.
    /// </summary>
    /// <remarks>
    /// Declared call outcomes get their own line, and a louder one, because they are the only section
    /// that puts words in somebody else's code's mouth. A run that used none of them is a run whose
    /// result stands on the sample and the facts alone, and the difference should be visible without
    /// reading the file that was passed in.
    /// </remarks>
    private static void RecordDeclarations(
        ArtifactContext context,
        RunDeclarations declarations,
        PipelineOptions options)
    {
        if (options.DeclarationsPath is null)
            return;
        context.AddEvidence(new Evidence(
            "declarations",
            $"The run was given the declarations \"{declarations.Name}\" (SHA-256 " +
            $"{declarations.Sha256}), stating {declarations.Facts.Answers.Count} host fact(s), " +
            $"{declarations.Libraries.Count} library path(s), {declarations.Budgets.Describe()}, " +
            $"{declarations.SkippedPasses.Count} pass(es) to leave out and " +
            $"{declarations.Calls.Count} call outcome(s).",
            Path.GetFullPath(options.DeclarationsPath)));
        if (declarations.Calls.Count == 0)
            return;
        context.AddEvidence(new Evidence(
            "declarations",
            declarations.CallsAllowed
                ? "Declared call outcomes were allowed, so a call the interpreter does not model " +
                  "may have been answered from the declarations rather than from code. Every one " +
                  "that was is listed under the host and declaration report."
                : "The declarations state call outcomes, but they were not allowed for this run, " +
                  "so every unmodelled call was refused as usual. Pass --allow-declared-calls to " +
                  "use them.",
            Path.GetFullPath(options.DeclarationsPath),
            declarations.CallsAllowed ? 0.5 : 1.0));
    }

    private static HostProfileReport? Consulted(HostEnvironment? host) => host is null
        ? null
        : new HostProfileReport(
            host.Profile.Name,
            host.Profile.Sha256,
            host.Questions
                .Select(question => new HostFactReport(
                    question.Key,
                    question.Answer.Describe(),
                    question.Answer.IsAnswered,
                    question.Times,
                    question.Answer.Stated))
                .ToArray());

    /// <summary>
    /// Counts the switch-flattener-shaped methods that survive in the final module, so the corpus
    /// can gate on residual control-flow obfuscation.
    /// </summary>
    private static int CountRemainingSwitchDispatchers(ModuleDef module)
    {
        var analyzer = new DispatcherAnalyzer();
        var count = 0;
        foreach (var method in module.GetTypes().SelectMany(type => type.Methods))
        {
            if (!method.HasBody ||
                !method.Body.Instructions.Any(instruction => instruction.OpCode == OpCodes.Switch))
            {
                continue;
            }
            // Either shape counts: the metric is how much flattening a reader still faces, not
            // which protector put it there.
            if (analyzer.Analyze(method).Qualification != DispatcherQualification.NotCandidate ||
                ConfuserExDispatcherAnalyzer.HasDispatcherShape(method))
            {
                count++;
            }
        }

        return count;
    }

    /// <summary>
    /// Counts instructions the reachability walk cannot reach in the final module, so residual
    /// dead code can be gated even where a method body was not otherwise touched.
    /// </summary>
    private static int CountRemainingUnreachableInstructions(ModuleDef module)
    {
        var count = 0;
        foreach (var method in module.GetTypes().SelectMany(type => type.Methods))
        {
            if (!method.HasBody || method.Body.Instructions.Count == 0)
                continue;
            var reachable = CfgDeadCodePass.ComputeReachable(method);
            count += method.Body.Instructions.Count(instruction => !reachable.Contains(instruction));
        }

        return count;
    }

    internal static List<string> WritePayloads(
        ArtifactContext context,
        string reportDirectory,
        string stem)
    {
        if (!context.TryGetFact<IReadOnlyList<ExtractedPayload>>("payload.artifacts", out var payloads) ||
            payloads is null ||
            payloads.Count == 0)
        {
            return [];
        }

        var directory = Path.Combine(reportDirectory, $"{stem}.payloads");
        Directory.CreateDirectory(directory);
        var paths = new List<string>(payloads.Count);
        var usedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var payload in payloads)
        {
            var safeName = ArtifactStem(payload.Info.AssemblyName,
                Convert.ToHexStringLower(SHA256.HashData(payload.Bytes)), usedNames);
            var path = Path.Combine(directory, $"{safeName}.dll");
            File.WriteAllBytes(path, payload.Bytes);
            paths.Add(path);
        }

        return paths;
    }

    /// <summary>
    /// Writes one listing per virtualized method, beside the report rather than inside it.
    /// </summary>
    /// <remarks>
    /// These run to thousands of lines each, which would swamp a report meant to be read at a
    /// glance. A file per method is also what an analyst wants to open in an editor and search.
    /// </remarks>
    internal static List<string> WriteVirtualPrograms(
        ArtifactContext context,
        string reportDirectory,
        string stem)
    {
        context.TryGetFact<IReadOnlyList<VirtualProgram>>(
            "virtualization.programs", out var stubbed);
        // A program run from a method that does other work is listed alongside the rest. Nothing
        // can be built back into such a method, but the listing is read to find out what a method
        // does, and that question does not depend on the method being nothing but the program.
        context.TryGetFact<IReadOnlyList<VirtualProgram>>(
            "virtualization.otherPrograms", out var elsewhere);
        var programs = (IReadOnlyList<VirtualProgram>)[.. stubbed ?? [], .. elsewhere ?? []];
        if (programs.Count == 0)
            return [];

        var directory = Path.Combine(reportDirectory, $"{stem}.virtualized");
        Directory.CreateDirectory(directory);
        var paths = new List<string>(programs.Count);
        var usedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var program in programs)
        {
            var safeName = ArtifactStem(program.Method.Stub.Name.String,
                $"{program.Method.Stub.MDToken.Raw:X8}.{program.Method.ProgramId:X8}", usedNames);
            var path = Path.Combine(directory, $"{safeName}.vmprogram.txt");
            File.WriteAllLines(path, program.Render(context.Module));
            paths.Add(path);

            // The reading is kept in its own file rather than folded into the listing, because the
            // two answer different questions: the listing is the evidence, and this is what it
            // comes to.
            var lifted = Path.Combine(directory, $"{safeName}.lifted.il");
            File.WriteAllLines(lifted, VirtualLift.Render(program, context.Module));
            paths.Add(lifted);
        }

        return paths;
    }

    private static string ArtifactStem(string name, string identity, HashSet<string> used)
    {
        // Bound sample-controlled names and make both native and Windows-invalid characters safe.
        var invalid = Path.GetInvalidFileNameChars().Concat("<>:\"/\\|?*").ToHashSet();
        var readable = new string(name.Take(80)
            .Select(character => char.IsControl(character) || invalid.Contains(character) ? '_' : character)
            .ToArray()).TrimEnd('.', ' ');
        if (readable.Length == 0)
            readable = "artifact";
        var stem = $"{readable}.{identity}";
        var candidate = stem;
        for (var suffix = 2; !used.Add(candidate); suffix++)
            candidate = $"{stem}.{suffix}";
        return candidate;
    }

    /// <summary>
    /// Serializes the module, and reports what the writer complained about on the way.
    /// </summary>
    /// <remarks>
    /// The writer knows things about the bodies it is given that nothing else in the run does, and
    /// the one that matters is whether a branch still reaches its target in the form it is written
    /// in. A `br.s` carries a signed byte, so a pass that makes a body longer between a branch and
    /// the target behind it can put that target out of reach; the writer then says "short branch is
    /// too far away" and emits a jump to whatever the truncated displacement lands on. Silencing it
    /// — which is what a no-throw logger does — turns that into a file that loads, decompiles and
    /// goes somewhere else. Three methods of one payload left this way before anyone was listening.
    /// </remarks>
    private static IReadOnlyList<string> WriteModule(
        ModuleDef module,
        string outputPath,
        bool preserveTokens)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        var complaints = new WriterComplaints();
        var writerOptions = new ModuleWriterOptions(module)
        {
            Logger = complaints
        };
        if (preserveTokens)
        {
            writerOptions.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
        }

        var temporaryPath = $"{outputPath}.{Guid.NewGuid():N}.tmp";
        try
        {
            module.Write(temporaryPath, writerOptions);
            File.Move(temporaryPath, outputPath, true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }

        return complaints.Errors;
    }

    /// <summary>
    /// Keeps what the metadata writer reported instead of discarding it.
    /// </summary>
    private sealed class WriterComplaints : ILogger
    {
        private readonly List<string> errors = [];

        public IReadOnlyList<string> Errors => errors;

        public bool IgnoresEvent(LoggerEvent loggerEvent) => loggerEvent != LoggerEvent.Error;

        public void Log(object? sender, LoggerEvent loggerEvent, string format, params object?[] args)
        {
            if (loggerEvent != LoggerEvent.Error)
                return;
            var said = args.Length == 0
                ? format
                : string.Format(CultureInfo.InvariantCulture, format, args);
            if (!errors.Contains(said, StringComparer.Ordinal))
                errors.Add(said);
        }
    }

    internal static void WriteJson<T>(string path, T value)
    {
        File.WriteAllText(path, JsonSerializer.Serialize(value, ReportJsonOptions));
    }

    /// <summary>
    /// Assembles the declared identity and structural changes the opt-in passes recorded, so the
    /// final verification gate can accept exactly those edits and nothing more.
    /// </summary>
    internal static RewriteAllowance BuildRewriteAllowance(ArtifactContext context)
    {
        context.TryGetFact<IReadOnlySet<string>>("cleanup.removedResources", out var removedResources);
        context.TryGetFact<IReadOnlySet<string>>("resources.addedResources", out var addedResources);
        context.TryGetFact<IReadOnlySet<string>>("cleanup.removedPublicApi", out var cleanupRemovedApi);
        context.TryGetFact<IReadOnlySet<uint>>("cleanup.removedMethodTokens", out var removedMethods);
        context.TryGetFact<int>("cleanup.removedTypeCount", out var removedTypeCount);
        context.TryGetFact<int>("cleanup.removedFieldCount", out var removedFieldCount);
        context.TryGetFact<IReadOnlySet<string>>("rename.removedPublicApi", out var renameRemovedApi);
        context.TryGetFact<IReadOnlySet<string>>("rename.addedPublicApi", out var renameAddedApi);
        context.TryGetFact<int>(
            VirtualizationRebuildPass.AddedMethodsFact, out var addedMethodCount);
        context.TryGetFact<int>(VirtualizationRebuildPass.AddedTypesFact, out var addedTypeCount);

        var removedApi = Union(cleanupRemovedApi, renameRemovedApi);
        var addedApi = renameAddedApi;
        if (removedResources is null && addedResources is null && removedApi is null &&
            addedApi is null && removedMethods is null && removedTypeCount == 0 &&
            removedFieldCount == 0 && addedMethodCount == 0 && addedTypeCount == 0)
        {
            return RewriteAllowance.None;
        }

        return new RewriteAllowance(
            AddedResources: addedResources,
            RemovedResources: removedResources,
            RemovedPublicApi: removedApi,
            RemovedMethodTokens: removedMethods,
            RemovedTypeCount: removedTypeCount,
            RemovedFieldCount: removedFieldCount,
            AddedPublicApi: addedApi,
            AddedMethodCount: addedMethodCount,
            AddedTypeCount: addedTypeCount);
    }

    private static IReadOnlySet<string>? Union(IReadOnlySet<string>? left, IReadOnlySet<string>? right)
    {
        if (left is null)
            return right;
        if (right is null)
            return left;
        var union = new HashSet<string>(left, StringComparer.Ordinal);
        union.UnionWith(right);
        return union;
    }

    /// <summary>
    /// Emits the old-to-new symbol map beside the other JSON reports when renaming ran.
    /// </summary>
    private static string? WriteRenameMap(
        ArtifactContext context,
        string reportDirectory,
        string stem)
    {
        if (!context.TryGetFact<IReadOnlyDictionary<string, string>>("rename.map", out var map) ||
            map is null || map.Count == 0)
        {
            return null;
        }

        var path = Path.Combine(reportDirectory, $"{stem}.renames.json");
        WriteJson(path, map);
        return path;
    }

    private static void ValidateDependencies(IReadOnlyList<IDeobfuscationPass> passes)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var pass in passes)
        {
            if (!seen.Add(pass.Name))
            {
                throw new ArgumentException($"Duplicate pass name: {pass.Name}");
            }

            var missing = pass.Dependencies.Where(dependency => !seen.Contains(dependency)).ToArray();
            if (missing.Length != 0)
            {
                throw new ArgumentException(
                    $"Pass {pass.Name} has unavailable or forward dependencies: {string.Join(", ", missing)}");
            }
        }
    }
}
