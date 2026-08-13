using System.Collections.ObjectModel;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Codec;
using ReactorUnpack.Core.Interpretation;
using ReactorUnpack.Core.Passes;
using ReactorUnpack.Core.Pipeline;
using ReactorUnpack.Core.Recovery;
using ReactorUnpack.Core.Strings;
using ReactorUnpack.Core.Verification;
using ReactorUnpack.Core.Payload;

namespace ReactorUnpack.Core;

public enum PassStatus
{
    Success,
    Partial,
    Unsupported,
    Failed
}

public sealed record Evidence(
    string Category,
    string Message,
    string? Location = null,
    double Confidence = 1.0);

public sealed record ChangeRecord(
    string Pass,
    string Kind,
    string Location,
    string Description);

public sealed record PassResult(
    string Pass,
    PassStatus Status,
    int Changes,
    IReadOnlyList<string> Diagnostics,
    TimeSpan Duration);

public sealed record ResourceInfo(
    string Name,
    uint Length,
    double Entropy,
    string Sha256,
    string Classification);

public sealed record PayloadInfo(
    string SourceResource,
    string SourceSha256,
    int EncodedLength,
    string DecodedStreamSha256,
    int PayloadLength,
    string PayloadSha256,
    string AssemblyName,
    string ModuleName,
    uint EntryPointToken,
    IReadOnlyList<string> EmbeddedResources);

public sealed record ExtractedPayload(PayloadInfo Info, byte[] Bytes);

public sealed record ArtifactReport(
    string ToolVersion,
    string InputPath,
    string InputSha256,
    long InputLength,
    string? ModuleName,
    string? RuntimeVersion,
    uint EntryPointToken,
    int TypeCount,
    int MethodCount,
    int ConcreteMethodCount,
    int ResourceCount,
    IReadOnlyList<ResourceInfo> Resources,
    IReadOnlyList<PayloadInfo> Payloads,
    IReadOnlyList<Evidence> Evidence,
    IReadOnlyList<PassResult> Passes,
    RecoveryReportMetrics Recovery,
    bool VerificationPassed,
    IReadOnlyList<string> VerificationDiagnostics,
    HostProfileReport? HostProfile = null);

/// <summary>One thing the run was told about the host, and whether it was told it.</summary>
public sealed record HostFactReport(string Key, string Answer, bool Answered, int Times);

/// <summary>
/// Which host profile a run used and which of its facts the run actually consulted.
/// </summary>
/// <remarks>
/// Recovery can depend on these, so a reader has to be able to see them. Listing what was asked
/// rather than what the profile contains is the useful half: a profile describing forty things of
/// which a sample looked at two says that the other thirty-eight had no bearing on the result, and a
/// question that went unanswered names the fact that would carry the interpretation further.
/// </remarks>
public sealed record HostProfileReport(
    string Name,
    string Sha256,
    IReadOnlyList<HostFactReport> Consulted);

public sealed record RecoveryReportMetrics(
    int RestoredMethodBodies,
    int RemainingMethodStubs,
    int StringCallSites,
    int ReplacedStringSites,
    int MutationCount,
    int BooleansRecovered = 0,
    int TokensRestored = 0,
    int ResourcesRestored = 0,
    int UnreachableInstructionsRemoved = 0,
    int RemainingSwitchDispatchers = 0,
    int RuntimeTypesRemoved = 0,
    int SymbolsRenamed = 0,
    int RemainingUnreachableInstructions = 0,
    int VirtualOperations = 0,
    int VirtualOperationsRead = 0,
    int VirtualOperationsWalked = 0,
    int VirtualDepthDisagreements = 0,
    int ConstantStringSites = 0);

/// <summary>Raised when an assembly offered to the interpreter cannot be trusted as given.</summary>
public sealed class TrustedLibraryException : Exception
{
    public TrustedLibraryException()
    {
    }

    public TrustedLibraryException(string message) : base(message)
    {
    }

    public TrustedLibraryException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// An assembly of somebody else's that the interpreter is allowed to run the IL of.
/// </summary>
/// <remarks>
/// Interpreting a library is not the same kind of act as interpreting the sample. The sample is the
/// thing under examination and nothing about it is taken on trust; a library is a known quantity
/// whose behaviour is not in question, supplied because the sample calls into it and the call cannot
/// otherwise be followed. What is recorded here is the identity of the file that was supplied, so
/// that a reader can tell which build of it the result depended on and fetch the same one.
/// </remarks>
public sealed record TrustedLibrary(
    string Path,
    string Name,
    string Version,
    string PublicKeyToken,
    string Sha256,
    bool MatchesReference);

public sealed class ArtifactContext : IDisposable
{
    private readonly List<Evidence> _evidence = [];
    private readonly List<ChangeRecord> _changes = [];
    private readonly List<PassResult> _passResults = [];
    private readonly Dictionary<string, object> _facts = new(StringComparer.Ordinal);
    private readonly List<ModuleDefMD> _trustedModules = [];

    private ArtifactContext(string inputPath, byte[] originalBytes, ModuleDefMD module)
    {
        InputPath = inputPath;
        OriginalBytes = originalBytes;
        OriginalSha256 = Convert.ToHexStringLower(SHA256.HashData(originalBytes));
        Module = module;
        OriginalImage = new PeImageView(originalBytes);
        OriginalIdentity = ArtifactIdentitySnapshot.Capture(module);
        OriginalStructure = ArtifactStructuralSnapshot.Capture(module);
    }

    public string InputPath { get; }
    public byte[] OriginalBytes { get; }
    public string OriginalSha256 { get; }
    public ModuleDefMD Module { get; }
    public PeImageView OriginalImage { get; }
    public ArtifactIdentitySnapshot OriginalIdentity { get; }
    public ArtifactStructuralSnapshot OriginalStructure { get; }
    public IReadOnlyList<Evidence> Evidence => new ReadOnlyCollection<Evidence>(_evidence);
    public IReadOnlyList<ChangeRecord> Changes => new ReadOnlyCollection<ChangeRecord>(_changes);
    public IReadOnlyList<PassResult> PassResults => new ReadOnlyCollection<PassResult>(_passResults);

    /// <summary>The assemblies the interpreter may run the IL of besides the sample itself.</summary>
    public IReadOnlyList<TrustedLibrary> Libraries { get; private set; } = [];

    /// <summary>The metadata of those assemblies, which is what the machine is handed.</summary>
    public IReadOnlyList<ModuleDefMD> TrustedModules =>
        new ReadOnlyCollection<ModuleDefMD>(_trustedModules);

    public static ArtifactContext Load(string path, IReadOnlyList<string>? libraryPaths = null)
    {
        var fullPath = Path.GetFullPath(path);
        var bytes = File.ReadAllBytes(fullPath);
        // One resolution context for the sample and everything supplied alongside it, because a
        // reference from the sample into a library only resolves to a body the machine can run if
        // both of them were read by the same resolver.
        var resolution = ModuleDef.CreateModuleContext();
        var options = new ModuleCreationOptions
        {
            TryToLoadPdbFromDisk = false,
            Context = resolution
        };
        var module = ModuleDefMD.Load(bytes, options);
        var context = new ArtifactContext(fullPath, bytes, module);
        if (libraryPaths is { Count: > 0 })
            context.LoadLibraries(libraryPaths, resolution, options);
        return context;
    }

    private void LoadLibraries(
        IReadOnlyList<string> paths,
        ModuleContext resolution,
        ModuleCreationOptions options)
    {
        if (resolution.AssemblyResolver is not AssemblyResolver resolver)
            throw new TrustedLibraryException(
                "The resolver cannot be told about a library, so none can be trusted.");
        var referenced = Module.GetAssemblyRefs()
            .GroupBy(reference => reference.Name.String, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);
        var loaded = new List<TrustedLibrary>();
        foreach (var path in paths)
        {
            var full = Path.GetFullPath(path);
            if (!File.Exists(full))
                throw new TrustedLibraryException($"No such library: {path}");
            var bytes = File.ReadAllBytes(full);
            ModuleDefMD library;
            try
            {
                library = ModuleDefMD.Load(bytes, options);
            }
            catch (BadImageFormatException ex)
            {
                throw new TrustedLibraryException(
                    $"{Path.GetFileName(full)} is not a .NET assembly, so there is no IL in it " +
                    "to interpret.",
                    ex);
            }

            var assembly = library.Assembly;
            if (assembly is null)
            {
                library.Dispose();
                throw new TrustedLibraryException(
                    $"{Path.GetFileName(full)} is a module rather than an assembly.");
            }

            // A library the sample never mentions cannot be the one it calls into, so accepting it
            // would widen what the machine may run without widening what it can read. Saying so is
            // more useful than silently loading a file that will never be reached.
            if (!referenced.TryGetValue(assembly.Name.String, out var reference))
            {
                // The versions are listed too, because the reader of this message is deciding which
                // file to go and find.
                var names = string.Join(", ", referenced.Values
                    .Select(candidate => $"{candidate.Name} {candidate.Version}")
                    .Order(StringComparer.Ordinal));
                library.Dispose();
                throw new TrustedLibraryException(
                    $"{assembly.Name} is not referenced by {Module.Name}, which references: " +
                    $"{names}.");
            }

            resolver.AddToCache(assembly);
            _trustedModules.Add(library);
            loaded.Add(new TrustedLibrary(
                full,
                assembly.Name,
                assembly.Version.ToString(),
                Convert.ToHexStringLower(assembly.PublicKeyToken?.Data ?? []),
                Convert.ToHexStringLower(SHA256.HashData(bytes)),
                assembly.Version == reference.Version));
        }

        Libraries = loaded;
    }

    public void AddEvidence(Evidence evidence) => _evidence.Add(evidence);
    public void AddChange(ChangeRecord change) => _changes.Add(change);
    internal void AddPassResult(PassResult result) => _passResults.Add(result);
    public void SetFact<T>(string key, T value) where T : notnull => _facts[key] = value;
    public bool TryGetFact<T>(string key, out T? value)
    {
        if (_facts.TryGetValue(key, out var raw) && raw is T typed)
        {
            value = typed;
            return true;
        }

        value = default;
        return false;
    }

    public void Dispose()
    {
        Module.Dispose();
        foreach (var library in _trustedModules)
            library.Dispose();
    }
}

public interface IDeobfuscationPass
{
    string Name { get; }
    IReadOnlyCollection<string> Dependencies { get; }

    /// <summary>
    /// Whether an incomplete result from this pass must block emission.
    /// </summary>
    /// <remarks>
    /// Emission is gated on the emitted module being trustworthy, so a pass that provably never
    /// mutates the module cannot make it untrustworthy by declining. Side-artifact recovery
    /// (payloads, Costura assemblies, resource bundles) is therefore reported without withholding
    /// an otherwise fully verified assembly. Callers that want everything complete, artifacts
    /// included, ask for it with <see cref="PipelineOptions.FailOnPartial"/>.
    /// </remarks>
    bool GatesEmission { get; }

    PassResult Run(ArtifactContext context);
}

public abstract class DeobfuscationPass : IDeobfuscationPass
{
    public abstract string Name { get; }
    public virtual IReadOnlyCollection<string> Dependencies => [];
    public virtual bool GatesEmission => true;

    public PassResult Run(ArtifactContext context)
    {
        var started = DateTime.UtcNow;
        try
        {
            var (status, changes, diagnostics) = Execute(context);
            return new PassResult(Name, status, changes, diagnostics, DateTime.UtcNow - started);
        }
        catch (Exception ex)
        {
            return new PassResult(
                Name,
                PassStatus.Failed,
                0,
                [$"{ex.GetType().Name}: {ex.Message}"],
                DateTime.UtcNow - started);
        }
    }

    protected abstract (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context);
}

public sealed record PipelineOptions(
    bool AnalyzeOnly = false,
    bool PreserveTokens = true,
    bool FailOnPartial = false,
    bool RemoveRuntime = true,
    bool RenameSymbols = false,
    string? OutputPath = null,
    string? ReportDirectory = null,
    string? HostProfilePath = null,
    IReadOnlyList<string>? LibraryPaths = null);

public sealed record PipelineResult(
    bool Success,
    string AnalysisReportPath,
    string ChangesReportPath,
    string? OutputPath,
    IReadOnlyList<string> ExtractedPayloadPaths,
    ArtifactReport Report)
{
    /// <summary>Listings of the programs behind virtualized methods, one file per method.</summary>
    public IReadOnlyList<string> VirtualProgramPaths { get; init; } = [];
}

public sealed class ReactorPipeline
{
    public const string Version = "0.1.0";

    private static readonly JsonSerializerOptions ReportJsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    private readonly IReadOnlyList<IDeobfuscationPass> _passes;

    public ReactorPipeline(IEnumerable<IDeobfuscationPass>? passes = null)
    {
        _passes = (passes ?? CreateDefaultPasses()).ToArray();
        ValidateDependencies(_passes);
    }

    public static IReadOnlyList<IDeobfuscationPass> CreateDefaultPasses() =>
    [
        new MetadataPreflightPass(),
        new ReactorDetectionPass(),
        new MethodProtectionAnalysisPass(),
        new FieldRvaRecoveryPass(),
        new ResourceAnalysisPass(),
        new ResourceRolePass(),
        new ControlFlowAnalysisPass(),
        new MethodBodyRecoveryPass(),
        new StringTableRecoveryPass(),
        new BooleanRecoveryPass(),
        new AntiTamperNeutralizationPass(),
        new ConstantPredicatePass(),
        // Loader-initialized state is folded before the control-flow passes, because turning its
        // reads into constants is what makes Reactor's guards look like the constant branches those
        // passes already know how to collapse.
        new GlobalStateCapturePass(),
        new GlobalPredicateFoldingPass(),
        new DispatcherDeobfuscationPass(),
        new CfgDeadCodePass(),
        new ControlFlowCompletionPass(),
        new TypeRestorationPass(),
        new DelegateProxyPass(),
        new StringRecoveryPass(),
        // Strings the protector left to per-string decoders rather than to its table are folded
        // after the table, because a decoder can read a table entry but never the other way round.
        new ConstantStringPass(),
        // Forwarder redirection runs after the rewrites, not before: replacing a resolver call with
        // its string or a proxy dispatch with a direct call is what leaves many of Reactor's
        // wrappers as the bare pass-throughs this pass can prove and skip.
        new MethodInliningPass(),
        // Token recovery follows it for the same reason in reverse: the sites it reads are the ones
        // redirection just brought into view.
        new TokenRecoveryPass(),
        // Resource classification and payload extraction run last because a JIT-hook artifact
        // hides every resource consumer behind an encrypted body and an encrypted name literal.
        new ResourceRoleRefinementPass(),
        new ResourceRestorationPass(),
        new ResourceHookElisionPass(),
        // Cutting the loader loose comes last of the rewrites, because whether its state is still
        // observable depends on every recovery before it having replaced the code that read it.
        new LoaderCallElisionPass(),
        new VirtualizationDisassemblyPass(),
        new PayloadExtractionPass(),
        new CosturaExtractionPass(),
        new RuntimeCleanupPass(),
        new SymbolRenamingPass(),
        new MetadataSanitizationPass()
    ];

    public PipelineResult Run(string inputPath, PipelineOptions? options = null)
    {
        options ??= new PipelineOptions();
        using var context = ArtifactContext.Load(inputPath, options.LibraryPaths);
        context.SetFact("options.removeRuntime", options.RemoveRuntime);
        context.SetFact("options.renameSymbols", options.RenameSymbols);
        context.SetFact(
            BootstrapMachine.HostEnvironmentFact,
            new HostEnvironment(options.HostProfilePath is { } profile
                ? HostProfile.Load(profile)
                : HostProfile.Default));
        RecordLibraries(context);

        foreach (var planned in PipelinePlanner.Plan(_passes))
        {
            var pass = planned.Pass;
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

            context.AddPassResult(pass.Run(context));
        }

        var allowance = BuildRewriteAllowance(context);
        var verification = AssemblyVerifier.Verify(
            context.Module,
            context.OriginalIdentity,
            context.OriginalStructure,
            allowance);
        var fatalFailure = context.PassResults.Any(result => result.Status == PassStatus.Failed);
        var emissionGates = _passes
            .Where(pass => pass.GatesEmission)
            .Select(pass => pass.Name)
            .ToHashSet(StringComparer.Ordinal);
        var incompleteRecovery = context.PassResults.Any(result =>
            (options.FailOnPartial || emissionGates.Contains(result.Pass)) &&
            result.Status is PassStatus.Partial or PassStatus.Unsupported);
        var canEmit = !options.AnalyzeOnly &&
            verification.Passed &&
            !fatalFailure &&
            !incompleteRecovery;

        var inputDirectory = Path.GetDirectoryName(Path.GetFullPath(context.InputPath))!;
        var stem = Path.GetFileNameWithoutExtension(context.InputPath);
        // Reports and payloads go into a folder of their own so that running the tool on a sample
        // leaves two things beside it rather than five. The cleaned assembly is not one of them: it
        // is the thing the analyst came for, so it lands next to the input where it can be found.
        // The folder is not named after the sample because the files inside it already are, which
        // lets a directory of samples share one folder without any of them colliding.
        var reportDirectory = Path.GetFullPath(options.ReportDirectory ??
            Path.Combine(inputDirectory, "reactorunpack"));
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
        WriteRenameMap(context, reportDirectory, stem);
        var virtualProgramPaths = WriteVirtualPrograms(context, reportDirectory, stem);

        // Emission happens before the report is written so that a module which verifies in memory
        // but not once serialized is explained rather than silently withheld. Round-tripping is the
        // only check that sees what the metadata writer actually produced.
        // Deleting metadata rows and preserving row indexes cannot both hold: the writer has to
        // renumber whatever followed a removed row. Token preservation is dropped exactly when
        // cleanup deleted something, which is the only case where it is unachievable.
        context.TryGetFact<int>("cleanup.removedTypeCount", out var removedTypeCount);
        context.TryGetFact<int>("cleanup.removedMethodCount", out var removedMethodCount);
        var preserveTokens = options.PreserveTokens &&
            removedTypeCount == 0 &&
            removedMethodCount == 0;

        if (canEmit)
        {
            var expectedShape = ModuleShape.Capture(context.Module);
            WriteModule(context.Module, outputPath, preserveTokens);
            var outputVerification = AssemblyVerifier.VerifyRoundTrip(outputPath, expectedShape);
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
        var report = BuildReport(context, resourceInfos, verification);
        WriteJson(analysisPath, report);
        WriteJson(changesPath, context.Changes);

        return new PipelineResult(
            canEmit || options.AnalyzeOnly && !fatalFailure,
            analysisPath,
            changesPath,
            outputPath,
            payloadPaths,
            report)
        {
            VirtualProgramPaths = virtualProgramPaths
        };
    }

    private static ArtifactReport BuildReport(
        ArtifactContext context,
        IReadOnlyList<ResourceInfo> resources,
        VerificationResult verification)
    {
        var types = context.Module.GetTypes().ToArray();
        var methods = types.SelectMany(type => type.Methods).ToArray();
        context.TryGetFact<IReadOnlyList<ExtractedPayload>>("payload.artifacts", out var payloads);
        context.TryGetFact<int>("method-protection.restored", out var restoredBodies);
        context.TryGetFact<IReadOnlyList<ProtectedMethodStub>>(
            "method-protection.stubs",
            out var protectedStubs);
        context.TryGetFact<int>("strings.callSites", out var stringCallSites);
        context.TryGetFact<int>("strings.replacedSites", out var replacedStringSites);
        context.TryGetFact<int>("booleans.replacedSites", out var booleansRecovered);
        context.TryGetFact<int>("tokens.restored", out var tokensRestored);
        context.TryGetFact<int>("resources.restoredBundles", out var resourcesRestored);
        context.TryGetFact<int>("cfg.unreachableInstructionsRemoved", out var unreachableRemoved);
        context.TryGetFact<int>("cleanup.removedTypeCount", out var runtimeTypesRemoved);
        context.TryGetFact<IReadOnlyDictionary<string, string>>("rename.map", out var renameMap);
        context.TryGetFact<int>("virtualization.operations", out var virtualOperations);
        context.TryGetFact<int>("virtualization.operationsRead", out var virtualRead);
        context.TryGetFact<int>("virtualization.operationsWalked", out var virtualWalked);
        context.TryGetFact<int>("virtualization.depthDisagreements", out var virtualDisagreements);
        context.TryGetFact<int>("strings.constantSites", out var constantStringSites);
        context.TryGetFact<HostEnvironment>(
            BootstrapMachine.HostEnvironmentFact, out var host);
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
            payloads?.Select(payload => payload.Info).ToArray() ?? [],
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
                runtimeTypesRemoved,
                renameMap?.Count ?? 0,
                CountRemainingUnreachableInstructions(context.Module),
                virtualOperations,
                virtualRead,
                virtualWalked,
                virtualDisagreements,
                constantStringSites),
            verification.Passed,
            verification.Diagnostics,
            Consulted(host));
    }

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
                    question.Times))
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
            if (analyzer.Analyze(method).Qualification != DispatcherQualification.NotCandidate)
                count++;
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

    private static List<string> WritePayloads(
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
        foreach (var payload in payloads)
        {
            var safeName = string.Concat(payload.Info.AssemblyName.Select(character =>
                Path.GetInvalidFileNameChars().Contains(character) ? '_' : character));
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
    private static List<string> WriteVirtualPrograms(
        ArtifactContext context,
        string reportDirectory,
        string stem)
    {
        if (!context.TryGetFact<IReadOnlyList<VirtualProgram>>(
                "virtualization.programs", out var programs) ||
            programs is null ||
            programs.Count == 0)
        {
            return [];
        }

        var directory = Path.Combine(reportDirectory, $"{stem}.virtualized");
        Directory.CreateDirectory(directory);
        var paths = new List<string>(programs.Count);
        foreach (var program in programs)
        {
            var safeName = string.Concat(program.Method.Stub.Name.String.Select(character =>
                Path.GetInvalidFileNameChars().Contains(character) ? '_' : character));
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

    private static void WriteModule(ModuleDef module, string outputPath, bool preserveTokens)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        var writerOptions = new ModuleWriterOptions(module)
        {
            Logger = DummyLogger.NoThrowInstance
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
    }

    private static void WriteJson<T>(string path, T value)
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

        var removedApi = Union(cleanupRemovedApi, renameRemovedApi);
        var addedApi = renameAddedApi;
        if (removedResources is null && addedResources is null && removedApi is null &&
            addedApi is null && removedMethods is null && removedTypeCount == 0 &&
            removedFieldCount == 0)
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
            AddedPublicApi: addedApi);
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
    private static void WriteRenameMap(ArtifactContext context, string reportDirectory, string stem)
    {
        if (!context.TryGetFact<IReadOnlyDictionary<string, string>>("rename.map", out var map) ||
            map is null || map.Count == 0)
        {
            return;
        }

        WriteJson(Path.Combine(reportDirectory, $"{stem}.renames.json"), map);
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

public sealed class ReactorDetectionPass : DeobfuscationPass
{
    public override string Name => "reactor-detection";
    public override IReadOnlyCollection<string> Dependencies => ["metadata-preflight"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var facts = ReactorStructureDetector.Analyze(context.Module);
        var strategy = new StructuralReactor6Strategy().Match(context.Module, facts);
        context.SetFact("reactor.structure", facts);
        context.SetFact("reactor.delegateTypes", facts.DelegateProxyCount);
        context.SetFact("reactor.deadPrefixes", facts.DeadCallPrefixCount);
        context.AddEvidence(new Evidence(
            "protector",
            $".NET Reactor {facts.Generation}: {string.Join(", ", strategy.Evidence)}.",
            Confidence: facts.Confidence));
        foreach (var capability in facts.IsReactor6 ? facts.CapabilityNames : [])
        {
            context.AddEvidence(new Evidence(
                "capability",
                capability,
                Confidence: facts.Confidence));
        }

        // Naming the virtualized methods is worth more than counting them: an analyst who knows
        // which method is missing knows what the report does not cover.
        var virtualized = VirtualizedMethodDetector.Detect(context.Module);
        context.SetFact("virtualization.methods", virtualized);
        foreach (var method in virtualized)
        {
            context.AddEvidence(new Evidence(
                "virtualized-method",
                $"Body replaced by program {method.ProgramId} of the interpreter at " +
                $"{method.Entry.DeclaringType?.Name}::{method.Entry.Name}.",
                $"{method.Stub.MDToken} {method.Stub.FullName}",
                0.95));
        }

        var status = facts.IsReactor6 ? PassStatus.Success : PassStatus.Unsupported;
        return (status, 0,
        [
            $"Detection confidence: {facts.Confidence:P0}",
            $"Generation: {facts.Generation}",
            $"Capabilities: {string.Join(", ", facts.CapabilityNames)}",
            virtualized.Count == 0
                ? "No method was found to have been replaced by interpreter bytecode."
                : $"{virtualized.Count} method(s) were replaced by interpreter bytecode."
        ]);
    }

    public static bool IsDelegateProxy(TypeDef type) =>
        ReactorStructureDetector.IsDelegateProxy(type);

    internal static bool HasDeadCallPrefix(MethodDef method)
        => ReactorStructureDetector.HasDeadCallPrefix(method);
}

public sealed class CfgDeadCodePass : DeobfuscationPass
{
    public override string Name => "cfg-dead-code";
    public override IReadOnlyCollection<string> Dependencies => ["dispatcher-deobfuscation"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var changed = 0;
        foreach (var method in context.Module.GetTypes().SelectMany(type => type.Methods))
        {
            if (!ReactorDetectionPass.HasDeadCallPrefix(method))
            {
                continue;
            }

            var instructions = method.Body.Instructions;
            var location = $"{method.MDToken} {method.FullName}";
            instructions[0].OpCode = OpCodes.Nop;
            instructions[0].Operand = null;
            instructions[1].OpCode = OpCodes.Nop;
            instructions[1].Operand = null;
            method.Body.OptimizeBranches();
            context.AddChange(new ChangeRecord(
                Name,
                "remove-unreachable-invalid-call",
                location,
                "Replaced the proven dead branch/call prefix with nops."));
            changed++;
        }

        context.SetFact("cfg.normalizedMethods", changed);
        return (PassStatus.Success, changed, [$"Normalized {changed} method prefixes."]);
    }

    internal static HashSet<Instruction> ComputeReachable(MethodDef method)
    {
        var instructions = method.Body.Instructions;
        var reachable = new HashSet<Instruction>();
        if (instructions.Count == 0)
        {
            return reachable;
        }

        var work = new Stack<Instruction>();
        work.Push(instructions[0]);
        foreach (var handler in method.Body.ExceptionHandlers)
        {
            if (handler.TryStart is not null) work.Push(handler.TryStart);
            if (handler.HandlerStart is not null) work.Push(handler.HandlerStart);
            if (handler.FilterStart is not null) work.Push(handler.FilterStart);
        }

        var index = instructions
            .Select((instruction, i) => (instruction, i))
            .ToDictionary(item => item.instruction, item => item.i);
        while (work.Count != 0)
        {
            var current = work.Pop();
            if (!reachable.Add(current))
            {
                continue;
            }

            var currentIndex = index[current];
            switch (current.OpCode.FlowControl)
            {
                case FlowControl.Branch:
                    if (current.Operand is Instruction branchTarget) work.Push(branchTarget);
                    break;
                case FlowControl.Cond_Branch:
                    if (current.Operand is Instruction conditionalTarget) work.Push(conditionalTarget);
                    if (current.Operand is IList<Instruction> targets)
                    {
                        foreach (var target in targets) work.Push(target);
                    }
                    PushNext();
                    break;
                case FlowControl.Return:
                case FlowControl.Throw:
                    break;
                default:
                    PushNext();
                    break;
            }

            void PushNext()
            {
                if (currentIndex + 1 < instructions.Count)
                {
                    work.Push(instructions[currentIndex + 1]);
                }
            }
        }

        return reachable;
    }
}

public sealed record FieldData(uint Token, string Field, int Length, string Sha256, string Kind);

public sealed class FieldRvaRecoveryPass : DeobfuscationPass
{
    public override string Name => "field-rva-recovery";
    public override IReadOnlyCollection<string> Dependencies => ["method-protection"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var fields = context.Module.GetTypes()
            .SelectMany(type => type.Fields)
            .Where(field => field.HasFieldRVA && field.InitialValue is { Length: > 0 })
            .Select(field => new FieldData(
                field.MDToken.Raw,
                field.FullName,
                field.InitialValue.Length,
                Convert.ToHexStringLower(SHA256.HashData(field.InitialValue)),
                Classify(field.InitialValue)))
            .ToArray();
        context.SetFact("fieldRva.catalog", fields);
        foreach (var field in fields.Where(item => item.Kind is "aes-key-candidate" or "aes-iv-candidate"))
        {
            context.AddEvidence(new Evidence(
                "cryptography",
                $"{field.Kind} in {field.Field} ({field.Length} bytes).",
                $"0x{field.Token:X8}",
                0.7));
        }

        return (PassStatus.Success, 0, [$"Cataloged {fields.Length} initialized fields."]);
    }

    private static string Classify(byte[] data) => data.Length switch
    {
        16 when Entropy.Calculate(data) > 3.2 => "aes-iv-candidate",
        24 or 32 when Entropy.Calculate(data) > 3.5 => "aes-key-candidate",
        _ => "initialized-data"
    };
}

public sealed class ResourceAnalysisPass : DeobfuscationPass
{
    public override string Name => "resource-analysis";
    public override IReadOnlyCollection<string> Dependencies => ["field-rva-recovery"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var resources = ResourceInspector.Inspect(context.Module);
        context.SetFact("resources.catalog", resources);
        foreach (var resource in resources)
        {
            context.AddEvidence(new Evidence(
                "resource",
                $"{resource.Classification} resource, {resource.Length} bytes, entropy {resource.Entropy:F3}.",
                resource.Name,
                resource.Entropy > 7.5 ? 0.9 : 0.65));
        }

        return (PassStatus.Success, 0, [$"Cataloged {resources.Count} embedded resources."]);
    }
}

public static class ResourceInspector
{
    public static IReadOnlyList<ResourceInfo> Inspect(ModuleDef module) =>
        module.Resources
            .OfType<EmbeddedResource>()
            .Select(resource =>
            {
                var data = resource.CreateReader().ToArray();
                var entropy = Entropy.Calculate(data);
                var classification = Classify(data, entropy);
                return new ResourceInfo(
                    resource.Name,
                    (uint)data.Length,
                    entropy,
                    Convert.ToHexStringLower(SHA256.HashData(data)),
                    classification);
            })
            .ToArray();

    private static string Classify(byte[] data, double entropy)
    {
        if (data.Length >= 2 && data[0] == 0x1F && data[1] == 0x8B) return "gzip";
        if (data.Length >= 2 && data[0] == 0x4D && data[1] == 0x5A) return "portable-executable";
        if (entropy > 7.85) return "encrypted-or-compressed";
        if (entropy > 7.0) return "encoded";
        return "structured";
    }
}


public sealed class PayloadExtractionPass : DeobfuscationPass
{
    public override string Name => "payload-extraction";
    public override IReadOnlyCollection<string> Dependencies =>
        ["resource-role-refinement", "resource-restoration"];
    public override bool GatesEmission => false;

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (TryProveNoManagedPayload(context, out var accounting))
            return (PassStatus.Success, 0, accounting);

        // Asking the module to unpack itself is the general answer and the one that survives a
        // change of crypter, so it is tried before anything that reasons about a particular codec.
        if (TryRecoverByInterpretation(context, out var interpreted, out var declined))
            return interpreted;

        context.TryGetFact<ReactorStructureFacts>("reactor.structure", out var facts);
        if (facts is not null &&
            StructuralStreamDiscovery.TryDiscoverProxyProfile(
                context.Module,
                facts,
                out var proxyProfile) &&
            proxyProfile is not null &&
            StructuralStreamDiscovery.TryDiscoverOuterPayload(
                context.Module,
                proxyProfile,
                out var discovered) &&
            discovered is not null)
        {
            // The discovery already read the image to accept it, so this reads it again only for
            // what it says about itself, and cannot be the first to find it unreadable.
            PayloadStageValidator.TryValidateManaged(discovered.ManagedAssembly, out var read);
            var sourceBytes = discovered.Resource.CreateReader().ToArray();
            var structuralInfo = new PayloadInfo(
                discovered.Resource.Name,
                Convert.ToHexStringLower(SHA256.HashData(sourceBytes)),
                sourceBytes.Length,
                Convert.ToHexStringLower(SHA256.HashData(discovered.DecodedStream)),
                discovered.ManagedAssembly.Length,
                Convert.ToHexStringLower(SHA256.HashData(discovered.ManagedAssembly)),
                discovered.AssemblyName,
                read?.ModuleName ?? discovered.AssemblyName,
                read?.EntryPointToken ?? 0,
                read?.Resources ?? []);
            IReadOnlyList<ExtractedPayload> structuralPayloads =
                [new(structuralInfo, discovered.ManagedAssembly)];
            context.SetFact("payload.artifacts", structuralPayloads);
            context.AddEvidence(new Evidence(
                "extracted-payload",
                $"Structurally recovered managed assembly {structuralInfo.AssemblyName}.",
                discovered.Resource.Name,
                1.0));
            context.AddEvidence(new Evidence(
                "stream-constants",
                $"Derived keyed payload constants A=0x{discovered.A:X8}, D=0x{discovered.D:X8}.",
                discovered.Resource.Name,
                1.0));
            context.AddChange(new ChangeRecord(
                Name,
                "extract-managed-payload",
                discovered.Resource.Name,
                $"{structuralInfo.AssemblyName}, SHA-256 {structuralInfo.PayloadSha256}"));
            return (PassStatus.Success, 1,
            [
                $"Structurally extracted {structuralInfo.AssemblyName}.dll ({structuralInfo.PayloadLength} bytes).",
                $"SHA-256: {structuralInfo.PayloadSha256}"
            ]);
        }

        return (PassStatus.Unsupported, 0,
        [
            "No payload could be recovered by interpreting the module's own unpacker.",
            .. declined,
            "No structurally validated payload codec was found either."
        ]);
    }

    /// <summary>
    /// Recovers payloads by interpreting the unpacker the module carries.
    /// </summary>
    /// <remarks>
    /// See <see cref="PayloadChainRecovery"/> for why the anchor is the load rather than the codec.
    /// A decline says nothing about whether a payload was there, so the caller carries on to the
    /// narrower routes rather than concluding anything from it.
    /// </remarks>
    private bool TryRecoverByInterpretation(
        ArtifactContext context,
        out (PassStatus, int, IReadOnlyList<string>) outcome,
        out IReadOnlyList<string> declined)
    {
        outcome = default;
        var recovered = PayloadChainRecovery.Recover(context, out var why);
        declined = why;
        if (recovered.Count == 0)
            return false;

        var payloads = new List<ExtractedPayload>();
        var diagnostics = new List<string>
        {
            $"Interpreted the module's own unpacker and captured {recovered.Count} assembly load(s)."
        };
        foreach (var item in recovered)
        {
            var origin = $"{item.Root.DeclaringType?.Name}::{item.Root.Name}";

            // What the loader was watched handing to the runtime is only a payload if it is one.
            // A capture that will not read is reported as what it is rather than written out as an
            // assembly, and the others are extracted regardless of it.
            if (!PayloadStageValidator.TryValidateManaged(item.Image, out var read) || read is null)
            {
                diagnostics.Add(
                    $"{origin}: the {item.Image.Length} byte(s) handed to the runtime are not a " +
                    "managed image, so nothing was extracted from that load.");
                continue;
            }
            var info = new PayloadInfo(
                origin,
                context.OriginalSha256,
                context.OriginalBytes.Length,
                item.Sha256,
                item.Image.Length,
                item.Sha256,
                item.AssemblyName,
                read.ModuleName,
                read.EntryPointToken,
                read.Resources);
            payloads.Add(new ExtractedPayload(info, item.Image));
            context.AddEvidence(new Evidence(
                "extracted-payload",
                $"Recovered managed assembly {item.AssemblyName} ({item.Image.Length} bytes) " +
                "by interpreting the module's own loader.",
                origin,
                1.0));
            context.AddChange(new ChangeRecord(
                Name, "extract-managed-payload", origin,
                $"{item.AssemblyName}, SHA-256 {item.Sha256}"));
            diagnostics.Add(
                $"Extracted {item.AssemblyName} ({item.Image.Length} bytes), SHA-256 {item.Sha256}.");
        }

        var combined = context.TryGetFact<IReadOnlyList<ExtractedPayload>>(
                "payload.artifacts", out var existing) && existing is not null
            ? existing.Concat(payloads).ToArray()
            : payloads.ToArray();
        context.SetFact<IReadOnlyList<ExtractedPayload>>("payload.artifacts", combined);
        diagnostics.AddRange(why);
        outcome = (PassStatus.Success, payloads.Count, diagnostics);
        return true;
    }

    /// <summary>
    /// Decides whether the absence of a payload is a proven fact or an unsupported codec.
    /// </summary>
    /// <remarks>
    /// Reporting "no payload codec" for an assembly that simply never embedded one is a false
    /// negative, and because incomplete recovery withholds output it blocks otherwise complete
    /// artifacts. Not every Reactor build uses the embedded-assembly feature: protected libraries
    /// commonly ship only a method-patch stream, a string table, an integrity blob, and an
    /// encrypted resource bundle.
    ///
    /// The proof is completeness of attribution rather than absence of a signal. Every embedded
    /// resource must be attributed to a role established from recovered consumer IL, and none of
    /// those roles may be a managed payload. A single unattributed resource keeps the pass
    /// unsupported, because that blob is exactly where an unextracted assembly would hide.
    /// </remarks>
    private static bool TryProveNoManagedPayload(
        ArtifactContext context,
        out IReadOnlyList<string> diagnostics)
    {
        diagnostics = [];
        var resources = context.Module.Resources.OfType<EmbeddedResource>().ToArray();
        if (resources.Length == 0)
        {
            diagnostics = ["The module embeds no resource that could carry a managed payload."];
            return true;
        }
        if (!context.TryGetFact<IReadOnlyList<ResourceRoleFact>>("resource.roles", out var roles) ||
            roles is null)
        {
            return false;
        }

        var byName = roles.ToDictionary(role => role.Resource, StringComparer.Ordinal);
        var attributed = resources.All(resource =>
            byName.TryGetValue(resource.Name, out var role) && role.Role != ResourceRole.Unknown);
        if (!attributed || roles.Any(role => role.Role == ResourceRole.ManagedPayload))
            return false;

        diagnostics =
        [
            $"All {resources.Length} embedded resource(s) are attributed to non-payload roles.",
            "Roles: " + string.Join(
                ", ",
                roles.GroupBy(role => role.Role)
                    .OrderBy(group => group.Key.ToString(), StringComparer.Ordinal)
                    .Select(group => $"{group.Key}={group.Count()}")),
            "The module does not embed a managed assembly, so there is nothing to extract."
        ];
        return true;
    }

    private static byte[] ExtractByteArrayRecord(ReadOnlySpan<byte> resourceData, int expectedLength)
    {
        var matches = new List<byte[]>();
        for (var offset = 0; offset + 5 <= resourceData.Length; offset++)
        {
            if (resourceData[offset] != 0x20 ||
                System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(
                    resourceData[(offset + 1)..]) != expectedLength ||
                offset + 5 + expectedLength != resourceData.Length)
            {
                continue;
            }

            matches.Add(resourceData.Slice(offset + 5, expectedLength).ToArray());
        }

        return matches.Count == 1
            ? matches[0]
            : throw new InvalidDataException(
                $"Expected one terminal ByteArray record, found {matches.Count}.");
    }
}

/// <summary>
/// The samples whose string table the interpreter cannot yet frame on its own.
/// </summary>
/// <remarks>
/// Recognizing a sample by its hash is the opposite of what this tool is for, and everything these
/// entries once carried — the payload cipher, its keys, the expected outputs — is gone, because
/// interpreting the module's own unpacker now recovers those payloads without being told anything.
/// What remains is an admission: for these two the string-table capture reports ambiguous framing,
/// and without the older strategy they would produce no output at all. The entries should go when
/// the capture can frame a table the protector's virtual machine builds; until then, removing them
/// would trade a narrow piece of cheating for a wide loss.
/// </remarks>
public static class LegacyStringStrategySamples
{
    private static readonly HashSet<string> Recognized =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "ad0c3182b18b5d7ba8771d830f4d51b4ada7e26f8d05223f4379e6312aba65fa",
            "c405398fc582e33bbbd37222b7360a6cfdc526146622141503de1ccf9de6174a"
        };

    public static bool Includes(string inputSha256) => Recognized.Contains(inputSha256);
}

public sealed record ProxyDescriptor(
    uint TypeToken,
    string Type,
    uint? FieldToken,
    uint? WrapperToken,
    uint? InitializerToken);

public sealed record ProxyBinding(uint FieldToken, uint TargetToken, bool CallVirtual);

public sealed class DelegateProxyPass : DeobfuscationPass
{
    public override string Name => "delegate-proxy-analysis";
    public override IReadOnlyCollection<string> Dependencies => ["resource-analysis"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var proxyTypes = context.Module.GetTypes()
            .Where(ReactorDetectionPass.IsDelegateProxy)
            .ToArray();
        var proxies = proxyTypes
            .Select(type => new ProxyDescriptor(
                type.MDToken.Raw,
                type.FullName,
                type.Fields.FirstOrDefault(field => field.IsStatic)?.MDToken.Raw,
                type.Methods.FirstOrDefault(method => method.HasBody && !method.IsStaticConstructor)?.MDToken.Raw,
                type.FindStaticConstructor()?.MDToken.Raw))
            .ToArray();
        context.SetFact("proxy.catalog", proxies);

        var resolverCandidates = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody)
            .Where(method => method.Body.Instructions.Any(instruction =>
                instruction.Operand is IMethod called &&
                called.DeclaringType?.FullName == "System.Reflection.Module" &&
                called.Name.String.StartsWith("Resolve", StringComparison.Ordinal)))
            .ToArray();

        foreach (var candidate in resolverCandidates)
        {
            context.AddEvidence(new Evidence(
                "proxy-resolver",
                $"Token resolver candidate with {candidate.Body.Instructions.Count} IL instructions.",
                $"{candidate.MDToken} {candidate.FullName}",
                0.85));
        }

        if (proxies.Length == 0)
        {
            return (PassStatus.Success, 0, ["No delegate proxies were detected."]);
        }

        EmbeddedResource resource;
        IReadOnlyList<ProxyBinding> bindings;
        var profileSource = "structural";
        context.TryGetFact<ReactorStructureFacts>("reactor.structure", out var structureFacts);
        if (structureFacts is not null &&
            StructuralStreamDiscovery.TryDiscoverProxyProfile(
                context.Module,
                structureFacts,
                out var discovered) &&
            discovered is not null)
        {
            resource = discovered.Resource;
            bindings = discovered.Bindings;
            context.AddEvidence(new Evidence(
                "stream-constants",
                $"Derived proxy stream constants A=0x{discovered.A:X8}, D=0x{discovered.D:X8}.",
                discovered.EvidenceMethod,
                1.0));
        }
        else if (ProxyResourceCodec.TryGetProfile(context.OriginalSha256, out var profile))
        {
            profileSource = "known-regression";
            resource = context.Module.Resources
                .OfType<EmbeddedResource>()
                .FirstOrDefault(item =>
                    Convert.ToHexStringLower(SHA256.HashData(item.CreateReader().ToArray())) ==
                    profile.ResourceSha256)
                ?? throw new InvalidDataException("The profiled proxy mapping resource was not found.");
            var decoded = ProxyResourceCodec.Decode(resource.CreateReader().ToArray(), profile);
            if (Convert.ToHexStringLower(SHA256.HashData(decoded)) != profile.DecodedSha256)
                return (PassStatus.Failed, 0, ["Decoded proxy map failed its regression hash."]);
            bindings = ProxyResourceCodec.Parse(decoded);
        }
        else
        {
            return (PassStatus.Unsupported, 0,
            [
                $"Cataloged {proxies.Length} delegate proxies.",
                "No structurally validated proxy stream codec was found."
            ]);
        }

        var fields = proxyTypes
            .SelectMany(type => type.Fields)
            .Where(field => field.IsStatic)
            .ToDictionary(field => field.MDToken.Raw);
        if (bindings.Count != fields.Count ||
            bindings.Any(binding =>
                !fields.ContainsKey(binding.FieldToken) ||
                context.Module.ResolveToken(binding.TargetToken) is not IMethod))
        {
            return (PassStatus.Failed, 0, ["Proxy map failed metadata-token validation."]);
        }

        var bindingByField = bindings.ToDictionary(binding => binding.FieldToken);
        var adapterByField = new Dictionary<uint, MethodDef>();
        foreach (var binding in bindings)
        {
            var field = fields[binding.FieldToken];
            var adapter = field.DeclaringType.Methods.SingleOrDefault(method =>
                method.HasBody &&
                method.IsStatic &&
                !method.IsConstructor &&
                method.Parameters.Count > 0 &&
                method.Parameters[^1].Type.FullName == field.DeclaringType.FullName);
            if (adapter is not null)
            {
                adapterByField[binding.FieldToken] = adapter;
            }
        }

        var changes = 0;
        var bypassedAdapters = new HashSet<MethodDef>();
        foreach (var method in context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody))
        {
            var instructions = method.Body.Instructions;
            for (var index = 0; index + 1 < instructions.Count; index++)
            {
                var fieldLoad = instructions[index];
                var adapterCall = instructions[index + 1];
                if (fieldLoad.OpCode != OpCodes.Ldsfld ||
                    fieldLoad.Operand is not FieldDef field ||
                    !bindingByField.TryGetValue(field.MDToken.Raw, out var binding) ||
                    !adapterByField.TryGetValue(field.MDToken.Raw, out var adapter) ||
                    adapterCall.OpCode != OpCodes.Call ||
                    adapterCall.Operand is not IMethod called ||
                    called.MDToken.Raw != adapter.MDToken.Raw ||
                    context.Module.ResolveToken(binding.TargetToken) is not IMethod target)
                {
                    continue;
                }

                fieldLoad.OpCode = OpCodes.Nop;
                fieldLoad.Operand = null;
                adapterCall.OpCode = binding.CallVirtual ? OpCodes.Callvirt : OpCodes.Call;
                adapterCall.Operand = target;
                context.AddChange(new ChangeRecord(
                    Name,
                    "restore-proxy-call",
                    $"{method.MDToken} IL_{adapterCall.Offset:X4}",
                    $"{field.MDToken} -> 0x{binding.TargetToken:X8} ({adapterCall.OpCode.Name})"));
                changes++;
                bypassedAdapters.Add(adapter);
                index++;
            }
        }

        // The adapters existed to dispatch through the proxy fields these sites no longer load,
        // and the initialization behind them exists only to populate those fields.
        RecoveryOrphans.DeclareSubtree(context, bypassedAdapters);
        context.SetFact("proxy.bindings", bindings);
        context.AddEvidence(new Evidence(
            "proxy-map",
            $"Decoded and validated {bindings.Count} field-to-method bindings.",
            resource.Name,
            1.0));
        return (PassStatus.Success, changes,
        [
            $"Decoded {bindings.Count} proxy bindings.",
            $"Restored {changes} direct call sites.",
            $"Profile source: {profileSource}."
        ]);
    }
}

public sealed record ProxyCodecProfile(
    string ResourceSha256,
    string DecodedSha256,
    uint A,
    uint D);

public static class ProxyResourceCodec
{
    private static readonly Dictionary<string, ProxyCodecProfile> Profiles =
        new Dictionary<string, ProxyCodecProfile>(StringComparer.OrdinalIgnoreCase)
        {
            ["ad0c3182b18b5d7ba8771d830f4d51b4ada7e26f8d05223f4379e6312aba65fa"] =
                new(
                    "ce449eb84252e5af5cf132907dfd3061d59fa8d259500e6a9025243ce46274d2",
                    "c9082fc2408d149d5e7fa1064c7a7f5d80fc88eb07e3fbc8c5db1edcd9aac343",
                    0x14F5581E,
                    0x2C784A62),
            ["c405398fc582e33bbbd37222b7360a6cfdc526146622141503de1ccf9de6174a"] =
                new(
                    "9ef76059d278b7c90b228d145b722c77913751492ce79da82794427757e75f3b",
                    "13f268283b8084526fa0efc47237c7e66986d825e2a07349ca508ede2e6f7a18",
                    0x3DBE5B8B,
                    0x468A5E02)
        };

    public static bool TryGetProfile(string inputSha256, out ProxyCodecProfile profile) =>
        Profiles.TryGetValue(inputSha256, out profile!);

    public static byte[] Decode(ReadOnlySpan<byte> ciphertext, ProxyCodecProfile profile)
        => ReactorStreamMixer.DecodeProxy(ciphertext, profile.A, profile.D);

    public static IReadOnlyList<ProxyBinding> Parse(ReadOnlySpan<byte> decoded)
    {
        if (decoded.Length % 8 != 0)
        {
            throw new InvalidDataException("Proxy mapping length is not a multiple of eight.");
        }

        var bindings = new List<ProxyBinding>(decoded.Length / 8);
        for (var offset = 0; offset < decoded.Length; offset += 8)
        {
            var fieldToken = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(decoded[offset..]);
            var encoded = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(decoded[(offset + 4)..]);
            bindings.Add(new ProxyBinding(
                fieldToken,
                encoded & 0x3FFFFFFFu,
                (encoded & 0x40000000u) != 0));
        }

        return bindings;
    }
}

public sealed class StringRecoveryPass : DeobfuscationPass
{
    public override string Name => "string-recovery";
    public override IReadOnlyCollection<string> Dependencies =>
        ["delegate-proxy-analysis", "string-table-recovery"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var candidates = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody &&
                method.IsStatic &&
                method.ReturnType.FullName == "System.String" &&
                method.MethodSig?.Params.Count == 1 &&
                method.MethodSig.Params[0].ElementType == ElementType.I4)
            .Where(method => method.Body.Instructions.Any(instruction =>
                instruction.Operand is IMethod called &&
                called.Name == "GetManifestResourceStream") ||
                method.Body.Instructions.Any(instruction =>
                    instruction.OpCode.Code == Code.Ldsfld &&
                    instruction.Operand is IField field &&
                    field.FieldSig?.Type.ElementType == ElementType.SZArray))
            .ToArray();
        if (candidates.Length == 0)
            return (PassStatus.Success, 0, ["No protected string resolver was detected."]);
        if (candidates.Length != 1)
            return (PassStatus.Unsupported, 0,
                [$"Detected {candidates.Length} ambiguous string resolver candidates."]);
        if (!context.TryGetFact<CapturedStringTable>("strings.table", out var table) ||
            table is null)
        {
            if (LegacyStringStrategySamples.Includes(context.OriginalSha256))
                return RecoverLegacyStrings(context, candidates[0]);
            return (PassStatus.Partial, 0,
                ["No unique captured string table is available; no call site was modified."]);
        }

        var resolver = candidates[0];
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

        var transactions = replacements.Select(item => item.Method)
            .Distinct()
            .ToDictionary(method => method, method => new BodyMutationTransaction(method));
        try
        {
            foreach (var replacement in replacements)
            {
                var instructions = replacement.Method.Body.Instructions;
                var callIndex = instructions.IndexOf(replacement.Call);
                if (callIndex < 0)
                    throw new InvalidOperationException("Resolver call disappeared during rewrite.");
                instructions.Insert(callIndex, Instruction.Create(OpCodes.Pop));
                replacement.Call.OpCode = OpCodes.Ldstr;
                replacement.Call.Operand = replacement.Value;
            }
            // Every rewritten site is gone, so the only tolerable references left are the
            // forwarding calls inside aliases that now have no callers at all.
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
            if (remaining.Length != 0)
                throw new InvalidOperationException(
                    $"{remaining.Length} targeted resolver reference(s) remained after rewrite.");
            var verification = AssemblyVerifier.Verify(
                context.Module,
                context.OriginalIdentity,
                context.OriginalStructure);
            if (!verification.Passed)
                throw new InvalidOperationException(string.Join("; ", verification.Diagnostics));
            foreach (var transaction in transactions.Values)
                transaction.Commit();
        }
        catch (Exception exception)
        {
            foreach (var transaction in transactions.Values)
                transaction.Rollback();
            return (PassStatus.Failed, 0,
                [$"Atomic string rewrite was rolled back: {exception.Message}"]);
        }
        finally
        {
            foreach (var transaction in transactions.Values)
                transaction.Dispose();
        }

        foreach (var replacement in replacements)
            context.AddChange(new ChangeRecord(
                Name,
                "restore-string",
                $"{replacement.Method.MDToken} IL_{replacement.Call.Offset:X4}",
                JsonSerializer.Serialize(replacement.Value)));
        context.SetFact("strings.callSites", callSites.Length);
        context.SetFact("strings.replacedSites", replacements.Count);
        // Every call the resolver and its aliases existed to serve is now an ldstr, which leaves
        // the decoding machinery behind them with nothing to decode either.
        RecoveryOrphans.DeclareSubtree(context, aliases);
        return (PassStatus.Success, replacements.Count,
            [$"Atomically restored all {replacements.Count} proven string sites."]);
    }

    /// <summary>
    /// Names the resource the protected code asks for by name, so the older string strategy can put
    /// that name back at the call site that would have decrypted it.
    /// </summary>
    /// <remarks>
    /// Extraction runs after string recovery, so its record of which resource a payload came from is
    /// usually not there yet, and when it is it names the method the chain was entered through
    /// rather than a resource. The fallback is the module's own catalog: one embedded resource is
    /// both the largest and indistinguishable from random, and that is the encrypted stage. Requiring
    /// it to be strictly the largest keeps the answer from being a guess between two candidates.
    /// </remarks>
    private static string? ResolvePayloadResourceName(ArtifactContext context)
    {
        var names = context.Module.Resources.Select(resource => resource.Name.String).ToHashSet(StringComparer.Ordinal);
        if (context.TryGetFact<IReadOnlyList<ExtractedPayload>>("payload.artifacts", out var payloads) &&
            payloads is { Count: > 0 } &&
            names.Contains(payloads[0].Info.SourceResource))
        {
            return payloads[0].Info.SourceResource;
        }

        if (!context.TryGetFact<IReadOnlyList<ResourceInfo>>("resources.catalog", out var catalog) ||
            catalog is null)
        {
            return null;
        }

        var opaque = catalog
            .Where(resource => resource.Classification == "encrypted-or-compressed")
            .OrderByDescending(resource => resource.Length)
            .ToArray();
        return opaque.Length >= 2 && opaque[0].Length > opaque[1].Length ? opaque[0].Name : null;
    }

    private static (PassStatus, int, IReadOnlyList<string>) RecoverLegacyStrings(
        ArtifactContext context,
        MethodDef resolver)
    {
        var payloadResourceName = ResolvePayloadResourceName(context);
        var replacements = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody && method.Body.Instructions.Any(instruction =>
                instruction.Operand is IMethod called && IsSameMethod(called, resolver)))
            .Select(method => (
                Method: method,
                Value: InferString(context.Module, method, payloadResourceName)))
            .Where(item => item.Value is not null)
            .ToDictionary(item => item.Method.MDToken.Raw, item => item.Value!);
        var changed = 0;
        foreach (var method in context.Module.GetTypes()
                     .SelectMany(type => type.Methods)
                     .Where(method => method.HasBody))
        {
            if (!replacements.TryGetValue(method.MDToken.Raw, out var value))
                continue;
            var instructions = method.Body.Instructions;
            for (var index = 0; index < instructions.Count; index++)
            {
                var instruction = instructions[index];
                if (instruction.Operand is not IMethod called || !IsSameMethod(called, resolver))
                    continue;
                instruction.OpCode = OpCodes.Pop;
                instruction.Operand = null;
                instructions.Insert(index + 1, Instruction.Create(OpCodes.Ldstr, value));
                context.AddChange(new ChangeRecord(
                    "string-recovery",
                    "restore-string",
                    $"{method.MDToken} IL_{instruction.Offset:X4}",
                    JsonSerializer.Serialize(value)));
                changed++;
                index++;
            }
        }
        return changed == replacements.Count
            ? (PassStatus.Success, changed,
                [$"Regression-locked restoration recovered {changed} strings."])
            : (PassStatus.Partial, changed,
                [$"Recovered {changed} of {replacements.Count} profiled string sites."]);
    }

    private static string? InferString(
        ModuleDef module,
        MethodDef method,
        string? payloadResourceName)
    {
        var directCalls = method.Body.Instructions
            .Select(instruction => instruction.Operand as IMethod)
            .Where(called => called is not null)
            .Cast<IMethod>()
            .ToArray();
        if (payloadResourceName is not null &&
            method.IsStatic &&
            method.MethodSig?.Params.Count == 0 &&
            method.Body.Instructions.Count >= 100)
        {
            return payloadResourceName;
        }

        if (method.IsStatic &&
            method.MethodSig?.Params.Count == 1 &&
            method.ReturnType.ElementType == ElementType.Object &&
            directCalls.Any(called =>
                called.DeclaringType?.FullName == "System.String" &&
                called.Name == "Trim") &&
            directCalls.Any(called =>
                called.DeclaringType?.FullName == "System.Type" &&
                called.Name == "GetMethod"))
        {
            return "Load";
        }

        var relevantMethods = new HashSet<MethodDef> { method };
        for (var depth = 0; depth < 2; depth++)
        {
            var tokens = relevantMethods.Select(item => item.MDToken.Raw).ToHashSet();
            foreach (var caller in module.GetTypes().SelectMany(type => type.Methods)
                         .Where(candidate => candidate.HasBody))
            {
                if (caller.Body.Instructions.Any(instruction =>
                        instruction.Operand is IMethod called &&
                        tokens.Contains(called.MDToken.Raw)))
                {
                    relevantMethods.Add(caller);
                }
            }
        }

        var calls = relevantMethods
            .SelectMany(item => item.Body.Instructions)
            .Select(instruction => instruction.Operand as IMethod)
            .Where(called => called is not null)
            .Cast<IMethod>()
            .ToArray();
        if (payloadResourceName is not null &&
            calls.Any(called => called.Name == "GetManifestResourceStream"))
        {
            return payloadResourceName;
        }

        if (calls.Any(called =>
                called.DeclaringType?.FullName == "System.Reflection.Assembly" &&
                called.Name == "Load") &&
            calls.Any(called =>
                called.DeclaringType?.FullName == "System.String" &&
                called.Name == "Concat"))
        {
            return "Load";
        }

        return null;
    }

    private static bool IsSameMethod(IMethod candidate, MethodDef expected) =>
        ReferenceEquals(candidate, expected) ||
        ReferenceEquals(candidate.ResolveMethodDef(), expected) ||
        candidate.FullName == expected.FullName;
}

public sealed class MetadataSanitizationPass : DeobfuscationPass
{
    public override string Name => "metadata-sanitization";
    public override IReadOnlyCollection<string> Dependencies => ["string-recovery"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var poisoned = 0;
        foreach (var assemblyReference in context.Module.GetAssemblyRefs())
        {
            if (assemblyReference.Version is not null &&
                assemblyReference.Version.Major == ushort.MaxValue &&
                assemblyReference.Name == "mscorlib")
            {
                poisoned++;
                context.AddEvidence(new Evidence(
                    "metadata",
                    IsReferenced(context.Module, assemblyReference)
                        ? "Poisoned mscorlib AssemblyRef remains referenced and was preserved."
                        : "Unreferenced poisoned mscorlib AssemblyRef will be omitted by metadata rebuild.",
                    assemblyReference.FullName,
                    1.0));
            }
        }

        return (PassStatus.Success, 0, [$"Identified {poisoned} poisoned assembly references."]);
    }

    private static bool IsReferenced(ModuleDef module, AssemblyRef target) =>
        module.GetTypes().Any(type =>
            References(type.BaseType, target) ||
            type.Interfaces.Any(item => References(item.Interface, target)) ||
            type.Fields.Any(field => References(field.FieldType, target)) ||
            type.Methods.Any(method =>
                References(method.ReturnType, target) ||
                method.Parameters.Any(parameter => References(parameter.Type, target)) ||
                method.HasBody && method.Body.Instructions.Any(instruction =>
                    instruction.Operand is ITypeDefOrRef typeRef && References(typeRef, target))));

    private static bool References(IType? type, AssemblyRef target)
    {
        var scope = type?.Scope;
        return scope is AssemblyRef reference && ReferenceEquals(reference, target);
    }
}

public sealed record VerificationResult(bool Passed, IReadOnlyList<string> Diagnostics);

public static class AssemblyVerifier
{
    public static VerificationResult Verify(
        ModuleDef module,
        ArtifactIdentitySnapshot? originalIdentity = null,
        ArtifactStructuralSnapshot? originalStructure = null,
        RewriteAllowance? allowance = null)
    {
        var diagnostics = new List<string>();
        foreach (var method in module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody))
        {
            var instructions = method.Body.Instructions;
            var instructionSet = instructions.ToHashSet();
            foreach (var instruction in instructions)
            {
                if (instruction.Operand is Instruction target && !instructionSet.Contains(target))
                {
                    diagnostics.Add($"{method.MDToken}: branch target is outside the method.");
                }
                else if (instruction.Operand is IList<Instruction> targets &&
                         targets.Any(target => !instructionSet.Contains(target)))
                {
                    diagnostics.Add($"{method.MDToken}: switch target is outside the method.");
                }
            }

            foreach (var handler in method.Body.ExceptionHandlers)
            {
                VerifyBoundary(handler.TryStart, "try start");
                VerifyBoundary(handler.TryEnd, "try end", allowEndOfMethod: true);
                VerifyBoundary(handler.HandlerStart, "handler start");
                VerifyBoundary(handler.HandlerEnd, "handler end", allowEndOfMethod: true);
                if (handler.FilterStart is not null)
                    VerifyBoundary(handler.FilterStart, "filter start");
            }

            var reachable = CfgDeadCodePass.ComputeReachable(method);
            var invalidReachableCalls = reachable.Count(instruction =>
                instruction.OpCode.FlowControl == FlowControl.Call && instruction.Operand is null);
            if (invalidReachableCalls != 0)
            {
                diagnostics.Add($"{method.MDToken}: {invalidReachableCalls} reachable calls have invalid operands.");
            }

            void VerifyBoundary(
                Instruction? boundary,
                string kind,
                bool allowEndOfMethod = false)
            {
                if (boundary is null && allowEndOfMethod)
                    return;
                if (boundary is not null && instructionSet.Contains(boundary))
                    return;
                diagnostics.Add($"{method.MDToken}: {kind} is outside the method.");
            }
        }

        if (originalIdentity is not null)
        {
            var effective = allowance ?? RewriteAllowance.None;
            var current = ArtifactIdentitySnapshot.Capture(module);
            if (current.EntryPointToken != originalIdentity.EntryPointToken)
                diagnostics.Add("Entry point token changed during rewriting.");
            if (current.StrongNameSigned != originalIdentity.StrongNameSigned)
                diagnostics.Add("Strong-name signed state changed during rewriting.");
            if (!ApiMatches(originalIdentity.PublicApi, current.PublicApi, effective))
                diagnostics.Add("Public API changed during rewriting.");
            if (!SetMatches(
                    originalIdentity.ResourceNames, current.ResourceNames,
                    effective.AddedResourceSet, effective.RemovedResourceSet))
                diagnostics.Add("Embedded resource set changed during rewriting.");
        }

        if (originalStructure is not null)
        {
            var effective = allowance ?? RewriteAllowance.None;
            var current = ArtifactStructuralSnapshot.Capture(module);
            var removedMethods = effective.RemovedMethodTokenSet;
            var resourceDelta = effective.AddedResourceSet.Count - effective.RemovedResourceSet.Count;
            if (current.TypeCount != originalStructure.TypeCount - effective.RemovedTypeCount)
                diagnostics.Add("Type count changed during rewriting.");
            if (current.MethodCount != originalStructure.MethodCount - removedMethods.Count)
                diagnostics.Add("Method count changed during rewriting.");
            if (current.FieldCount != originalStructure.FieldCount - effective.RemovedFieldCount)
                diagnostics.Add("Field count changed during rewriting.");
            if (current.ResourceCount != originalStructure.ResourceCount + resourceDelta)
                diagnostics.Add("Resource count changed during rewriting.");
            if (!MethodTokensMatch(originalStructure.MethodRvas.Keys, current.MethodRvas.Keys, removedMethods))
                diagnostics.Add("Method token set changed during rewriting.");
        }

        return new VerificationResult(diagnostics.Count == 0, diagnostics);
    }

    /// <summary>
    /// Confirms the surviving method tokens are exactly the original set minus the declared removals.
    /// </summary>
    private static bool MethodTokensMatch(
        IEnumerable<uint> original,
        IEnumerable<uint> current,
        IReadOnlySet<uint> removed)
    {
        var expected = new HashSet<uint>(original);
        expected.ExceptWith(removed);
        return expected.SetEquals(current);
    }

    /// <summary>
    /// Confirms the current set equals the original plus declared additions minus declared removals.
    /// </summary>
    private static bool SetMatches(
        IReadOnlyList<string> original,
        IReadOnlyList<string> current,
        IReadOnlySet<string> added,
        IReadOnlySet<string> removed)
    {
        var expected = new HashSet<string>(original, StringComparer.Ordinal);
        foreach (var name in removed)
            expected.Remove(name);
        foreach (var name in added)
            expected.Add(name);
        return expected.SetEquals(current);
    }

    /// <summary>
    /// Confirms the public API changed only by the declared removals, additions, and renames.
    /// </summary>
    private static bool ApiMatches(
        IReadOnlyList<string> original,
        IReadOnlyList<string> current,
        RewriteAllowance allowance)
    {
        if (allowance.RemovedPublicApiSet.Count == 0 &&
            allowance.AddedPublicApiSet.Count == 0 &&
            allowance.RenamedPublicApiMap.Count == 0)
        {
            return current.SequenceEqual(original, StringComparer.Ordinal);
        }

        var expected = new HashSet<string>(original, StringComparer.Ordinal);
        foreach (var removed in allowance.RemovedPublicApiSet)
            expected.Remove(removed);
        foreach (var rename in allowance.RenamedPublicApiMap)
        {
            if (expected.Remove(rename.Key))
                expected.Add(rename.Value);
        }
        foreach (var added in allowance.AddedPublicApiSet)
            expected.Add(added);
        return expected.SetEquals(current);
    }

    public static VerificationResult VerifyFile(
        string path,
        ArtifactIdentitySnapshot? originalIdentity = null,
        ArtifactStructuralSnapshot? originalStructure = null,
        RewriteAllowance? allowance = null)
    {
        try
        {
            using var module = ModuleDefMD.Load(path);
            return Verify(module, originalIdentity, originalStructure, allowance);
        }
        catch (Exception ex)
        {
            return new VerificationResult(false, [$"Reload failed: {ex.Message}"]);
        }
    }

    /// <summary>
    /// Confirms the file on disk is the module that was in memory, and that it still reloads with
    /// sound method bodies.
    /// </summary>
    /// <remarks>
    /// This deliberately compares against the transformed module rather than the original. The
    /// in-memory gate has already established that the module differs from the original only by
    /// what the passes declared; establishing that the file matches that module carries the
    /// conclusion through to disk, and it is the only form the check can take once deletions have
    /// made the writer renumber tokens.
    /// </remarks>
    public static VerificationResult VerifyRoundTrip(string path, ModuleShape expected)
    {
        try
        {
            using var module = ModuleDefMD.Load(path);
            var diagnostics = new List<string>(Verify(module).Diagnostics);
            diagnostics.AddRange(expected.DifferencesFrom(ModuleShape.Capture(module)));
            return new VerificationResult(diagnostics.Count == 0, diagnostics);
        }
        catch (Exception ex)
        {
            return new VerificationResult(false, [$"Reload failed: {ex.Message}"]);
        }
    }
}

public static class Entropy
{
    public static double Calculate(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return 0;
        }

        Span<int> counts = stackalloc int[256];
        foreach (var value in data)
        {
            counts[value]++;
        }

        var entropy = 0.0;
        foreach (var count in counts)
        {
            if (count == 0) continue;
            var probability = (double)count / data.Length;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }
}

public static class ResourceTransforms
{
    public static byte[] AesCbcDecrypt(
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> iv,
        PaddingMode padding = PaddingMode.PKCS7)
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = padding;
        aes.Key = key.ToArray();
        aes.IV = iv.ToArray();
        return aes.DecryptCbc(ciphertext, iv, padding);
    }

    public static byte[] Xor(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
    {
        if (key.IsEmpty) throw new ArgumentException("The XOR key cannot be empty.", nameof(key));
        var output = new byte[data.Length];
        for (var index = 0; index < data.Length; index++)
        {
            output[index] = (byte)(data[index] ^ key[index % key.Length]);
        }

        return output;
    }

    public static byte[] Decompress(ReadOnlySpan<byte> data, string codec, int maximumLength = 256 * 1024 * 1024)
    {
        using var input = new MemoryStream(data.ToArray(), false);
        using Stream decoder = codec.ToLowerInvariant() switch
        {
            "gzip" => new GZipStream(input, CompressionMode.Decompress, false),
            "deflate" => new DeflateStream(input, CompressionMode.Decompress, false),
            "brotli" => new BrotliStream(input, CompressionMode.Decompress, false),
            _ => throw new NotSupportedException($"Unsupported compression codec: {codec}")
        };
        using var output = new MemoryStream();
        var buffer = new byte[81920];
        while (true)
        {
            var read = decoder.Read(buffer, 0, buffer.Length);
            if (read == 0) break;
            if (output.Length + read > maximumLength)
            {
                throw new InvalidDataException("Decompressed resource exceeds the configured limit.");
            }

            output.Write(buffer, 0, read);
        }

        return output.ToArray();
    }
}
