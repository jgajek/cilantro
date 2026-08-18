using System.Collections.ObjectModel;
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
using Cilantro.Core.Passes;
using Cilantro.Core.Pipeline;
using Cilantro.Core.Recovery;
using Cilantro.Core.Strings;
using Cilantro.Core.Verification;
using Cilantro.Core.Payload;

namespace Cilantro.Core;

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

/// <param name="WrittenTo">
/// The file the run wrote this payload to, once it has written it.
/// </param>
/// <remarks>
/// The path is in the report because the payload is what most callers came for, and a hash alone
/// leaves them matching an entry against a directory listing by convention. Naming the file makes the
/// report enough on its own: everything a caller does next is done to a file.
/// </remarks>
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
    IReadOnlyList<string> EmbeddedResources,
    string? WrittenTo = null);

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
    HostProfileReport? HostProfile = null,
    IReadOnlyList<Blocker>? Blockers = null,
    DeclarationReport? Declarations = null,

    /// <summary>What the run carried on past that a strict run would have stopped at.</summary>
    IReadOnlyList<Blocker>? ContinuedPast = null,

    /// <summary>
    /// Whether the run refused wherever it would otherwise have assumed its way past something.
    /// </summary>
    /// <remarks>
    /// Part of the report because everything else in it is conditional on the answer. Two reports of
    /// the same assembly that disagree are not a contradiction if one of them was assuming.
    /// </remarks>
    bool Strict = true,

    /// <summary>
    /// Which protector the run settled on, by the name a program uses, or "none".
    /// </summary>
    /// <remarks>
    /// Said outright because there is more than one protector now, and a reader that inferred it
    /// from the capability list was reading a set of names that two protectors can both produce.
    /// </remarks>
    string Protector = "none");

/// <summary>
/// What the run was told, and what came of it.
/// </summary>
/// <remarks>
/// The hash is here so that a report and the file that produced it can be matched up later, and the
/// unconsulted list is here because a declaration nobody asked about is the commonest way for a run to
/// look like it ignored what it was given.
/// </remarks>
public sealed record DeclarationReport(
    string Name,
    string Sha256,
    bool CallsAllowed,
    IReadOnlyList<string> Libraries,
    IReadOnlyList<string> SkippedPasses,
    IReadOnlyList<string> DeclaredCallsUsed,
    IReadOnlyList<string> DeclaredCallsUnused);

/// <summary>
/// The file an agent reads to find out what to do next: what stopped the run, and what to declare.
/// </summary>
/// <remarks>
/// Small and separate from the analysis report on purpose. Deciding whether to try again is a
/// question about the run rather than about the assembly, and it should not require parsing a report
/// that is mostly about the assembly. The hashes are carried so that a decision can be shown to have
/// been made about this input and these declarations rather than a previous pair.
/// </remarks>
public sealed record BlockerReport(
    string ToolVersion,
    string InputPath,
    string InputSha256,
    string DeclarationsName,
    string DeclarationsSha256,
    bool CallsAllowed,
    IReadOnlyList<Blocker> Blockers,
    IReadOnlyList<string> UnconsultedDeclarations,

    /// <summary>Whether the run refused where it could have assumed its way past something.</summary>
    bool Strict = true,

    /// <summary>
    /// What the run met and carried on past, which would have stopped it had it been strict.
    /// </summary>
    /// <remarks>
    /// Separate from <see cref="Blockers"/> because an agent deciding what to do next needs the two
    /// apart: a stop is why there is less output than there should be and is worth a declaration, while
    /// one of these is a place the reading rests on a call the tool declined to follow. Reading it is
    /// worth doing when the output looks wrong, and not otherwise.
    /// </remarks>
    IReadOnlyList<Blocker>? ContinuedPast = null);

/// <summary>
/// The values a protector kept out of the metadata, recovered and written down as values.
/// </summary>
/// <remarks>
/// The cleaned assembly is where recovered strings belong for reading code, and for most of them
/// that is enough. It is not enough for the rest. A protector that packs its constants into one
/// buffer keeps more there than text — keys, encrypted blobs, whole configuration records — and
/// those cannot be put back into IL as literals without re-emitting field data, which is a larger
/// change to the module than reading them justifies. They would then be recovered and unreadable,
/// which is the same as not recovered.
///
/// So they are written here instead, beside the assembly rather than inside it: every constant the
/// run proved, what asked for it, and where. It is a separate file for the reason the blocker
/// report is one — this is a question about the sample's contents rather than about the run, and a
/// caller after indicators should not have to read an analysis report to find them.
/// </remarks>
public sealed record ConfigReport(
    string ToolVersion,
    string InputPath,
    string InputSha256,
    string Protector,
    IReadOnlyList<RecoveredConstant> Constants);

/// <summary>One thing the run was told about the host, and whether it was told it.</summary>
/// <param name="Stated">
/// Whether a person said this, as against the tool having assumed it. A reader who wants to know how
/// much of a recovery rests on invention reads this column.
/// </param>
public sealed record HostFactReport(
    string Key,
    string Answer,
    bool Answered,
    int Times,
    bool Stated = false);

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

    /// <summary>
    /// Whether to give Reactor's generated names readable placeholders. Null follows the mode.
    /// </summary>
    /// <remarks>
    /// A triage run renames, because the analyst it is for is about to read the result and every
    /// name in it is a machine's. A strict run does not, because the names as they stand are what a
    /// signature is written against and what a second tool's output is compared with, and an expert
    /// who wants them changed can say so.
    /// </remarks>
    bool? RenameSymbols = null,
    string? OutputPath = null,
    string? ReportDirectory = null,
    string? HostProfilePath = null,
    IReadOnlyList<string>? LibraryPaths = null,
    string? DeclarationsPath = null,
    bool AllowDeclaredCalls = false,

    /// <summary>
    /// Whether to refuse wherever the run would otherwise assume its way past something.
    /// </summary>
    /// <remarks>
    /// Off by default, because the commonest reason a run of an unfamiliar sample produced nothing was
    /// a call on the way to the payload whose result nothing used. What the default costs is that some
    /// of what the report says rests on a machine nobody described and on calls nobody read, and the
    /// report says which. What it buys is measured in <c>docs/compatibility.md</c>.
    /// </remarks>
    bool Strict = false,

    /// <summary>
    /// Whether to build the virtualized methods back into code in the cleaned copy. Null follows
    /// the mode.
    /// </summary>
    /// <remarks>
    /// A triage run builds them, because a method nobody can read is the thing the analyst is
    /// stuck on, and a stub sitting in an otherwise readable assembly is exactly where they get
    /// stuck. A strict run does not, because it is the one thing the tool produces that it cannot
    /// prove: everything else in the cleaned assembly is the protector's own output, while a body
    /// built from a reading is the reading itself, and if the reading is wrong the body is wrong
    /// in a way no reader can see.
    ///
    /// Where they are built, each one is marked with an attribute saying so, which a decompiler
    /// shows above the method, and where the module's own work can test the bodies the tool runs
    /// that test and reports the verdict.
    /// </remarks>
    bool? Devirtualize = null)
{
    /// <summary>
    /// Whether this run gives Reactor's generated names readable placeholders.
    /// </summary>
    public bool Renames => RenameSymbols ?? !Strict;

    /// <summary>
    /// Whether this run builds the virtualized methods back into code in the cleaned copy.
    /// </summary>
    public bool Devirtualizes => Devirtualize ?? !Strict;
}

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

    /// <summary>Where the account of what stopped the run was written.</summary>
    public string? BlockerReportPath { get; init; }

    /// <summary>
    /// Where the constants the protector hid were written, or null where it hid none.
    /// </summary>
    public string? ConfigReportPath { get; init; }

    /// <summary>Where the old name of everything renamed was written, if anything was.</summary>
    public string? RenameMapPath { get; init; }

    /// <summary>How many virtualized methods the cleaned copy holds as code rather than as a stub.</summary>
    public int RebuiltMethods { get; init; }

    /// <summary>What came of building those bodies, method by method.</summary>
    public IReadOnlyList<string> DevirtualizationNotes { get; init; } = [];

    /// <summary>What running the built copy established about the bodies built into it.</summary>
    public DevirtualizationCheck DevirtualizationCheck { get; init; }
}

public sealed class CilantroPipeline
{
    public const string Version = "0.4.0";

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
        new ControlFlowAnalysisPass(),
        // ConfuserEx encrypts the bodies themselves, so nothing that reads a body can run before
        // this: it is the pass that makes the module readable at all.
        new ConfuserExAntiTamperPass(),
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
        // Resource classification and payload extraction run last because a JIT-hook artifact
        // hides every resource consumer behind an encrypted body and an encrypted name literal.
        new ResourceRoleRefinementPass(),
        new ResourceRestorationPass(),
        new ResourceHookElisionPass(),
        // Cutting the loader loose comes last of the rewrites, because whether its state is still
        // observable depends on every recovery before it having replaced the code that read it.
        new LoaderCallElisionPass(),
        new VirtualizationDisassemblyPass(),
        // Reading the engine is what learns this build's numbering, so the one reading of the string
        // table that could not assume a numbering is only possible from here on.
        new StringTableRelearningPass(),
        new StringLookupRecoveryPass(),
        new PayloadExtractionPass(),
        new CosturaExtractionPass(),
        // Building the read-back methods precedes cleanup, which would otherwise delete the very
        // stubs the bodies go into, and follows the payload passes, which have to see the module
        // doing its own work rather than the tool's account of it.
        new VirtualizationRebuildPass(),
        new RuntimeCleanupPass(),
        new SymbolRenamingPass(),
        new MetadataSanitizationPass()
    ];

    public PipelineResult Run(string inputPath, PipelineOptions? options = null)
    {
        options ??= new PipelineOptions();
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
        using var context = ArtifactContext.Load(
            inputPath,
            [.. options.LibraryPaths ?? [], .. declarations.Libraries]);
        context.SetFact("options.removeRuntime", options.RemoveRuntime);

        // What the caller did not decide, the mode decides: a triage run does the things that make
        // the result easier to read, and a strict one leaves the assembly as close to what it can
        // prove as it can.
        context.SetFact("options.renameSymbols", options.Renames);
        // A run asked only to say what is there builds nothing, so it does not pay for the building
        // or for the run that checks it.
        context.SetFact("options.devirtualize", options.Devirtualizes && !options.AnalyzeOnly);
        var environment = new RunEnvironment(host, declarations, strict: options.Strict);
        context.SetFact(BootstrapMachine.RunEnvironmentFact, environment);
        RecordLibraries(context);
        RecordDeclarations(context, declarations, options);

        foreach (var planned in PipelinePlanner.Plan(_passes))
        {
            var pass = planned.Pass;
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
            Path.Combine(inputDirectory, "cilantro"));
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

        // Emission happens before the report is written so that a module which verifies in memory
        // but not once serialized is explained rather than silently withheld. Round-tripping is the
        // only check that sees what the metadata writer actually produced.
        // Deleting metadata rows and preserving row indexes cannot both hold: the writer has to
        // renumber whatever followed a removed row. Token preservation is dropped exactly when
        // cleanup deleted something, which is the only case where it is unachievable.
        context.TryGetFact<int>("cleanup.removedTypeCount", out var removedTypeCount);
        context.TryGetFact<int>("cleanup.removedMethodCount", out var removedMethodCount);
        context.TryGetFact<int>(
            VirtualizationRebuildPass.AddedTypesFact, out var addedTypeCount);
        var preserveTokens = options.PreserveTokens &&
            removedTypeCount == 0 &&
            removedMethodCount == 0 &&
            addedTypeCount == 0;

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

        return new PipelineResult(
            canEmit || options.AnalyzeOnly && !fatalFailure,
            analysisPath,
            changesPath,
            outputPath,
            payloadPaths,
            report)
        {
            VirtualProgramPaths = virtualProgramPaths,
            BlockerReportPath = blockersPath,
            ConfigReportPath = configPath,
            RenameMapPath = renameMapPath,
            DevirtualizationNotes = devirtualizationNotes ?? [],
            DevirtualizationCheck = devirtualizationCheck,
            // Only where the cleaned copy was written does the count describe something the analyst
            // has: the bodies went into the module either way, but a run that withheld the copy
            // delivered no code to read.
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
        context.TryGetFact<int>("resources.restoredBundles", out var resourcesRestored);
        context.TryGetFact<int>("cfg.unreachableInstructionsRemoved", out var unreachableRemoved);
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
            Consulted(environment?.Host),
            environment?.Blockers.Blockers,
            Told(environment?.Declarations),
            environment?.Blockers.Continuations,
            environment?.Strict ?? true,
            context.TryGetFact<ProtectorIdentity>(ProtectorIdentityPass.Fact, out var protector) &&
                protector is not null
                ? protector.Token
                : "none");
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
        context.TryGetFact<IReadOnlySet<uint>>(
            VirtualizationRebuildPass.AddedMethodsFact, out var addedMethods);
        context.TryGetFact<int>(VirtualizationRebuildPass.AddedTypesFact, out var addedTypeCount);

        var removedApi = Union(cleanupRemovedApi, renameRemovedApi);
        var addedApi = renameAddedApi;
        if (removedResources is null && addedResources is null && removedApi is null &&
            addedApi is null && removedMethods is null && removedTypeCount == 0 &&
            removedFieldCount == 0 && addedMethods is null && addedTypeCount == 0)
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
            AddedMethodTokens: addedMethods,
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

public sealed class ReactorDetectionPass : DeobfuscationPass
{
    public override string Name => "reactor-detection";
    public override IReadOnlyCollection<string> Dependencies => ["metadata-preflight"];

    // A detector that finds its protector absent has answered, not failed. Whether the run
    // recognized anything at all is settled once, by protector-identity.
    public override bool GatesEmission => false;

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
            if (context.TryGetFact<bool>("strings.deferred", out var deferred) && deferred)
            {
                return (PassStatus.Success, 0,
                [
                    "Reading the table was deferred to after the engine's numbering is learned, so " +
                        "the sites it accounts for are restored there and none are restored here."
                ]);
            }
            return (PassStatus.Partial, 0,
                ["No unique captured string table is available; no call site was modified."]);
        }

        return Restore(context, Name, candidates[0], table);
    }

    /// <summary>
    /// Puts the strings back at every call site the table accounts for, all of them or none.
    /// </summary>
    /// <remarks>
    /// This is shared with the later reading rather than repeated by it. A table read once the
    /// engine's own numbering is known arrives after this pass has already run and found nothing to
    /// do, and the restoration it then needs is this one exactly: the same proof of each offset, the
    /// same all-or-nothing rewrite, and the same refusal to leave a resolver reference behind.
    /// </remarks>
    internal static (PassStatus, int, IReadOnlyList<string>) Restore(
        ArtifactContext context,
        string pass,
        MethodDef resolver,
        CapturedStringTable table)
    {
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

        return Rewrite(context, pass, aliases, callSites.Length, replacements);
    }

    /// <summary>
    /// Turns every proven resolver call into the string it hands back, all of them or none.
    /// </summary>
    /// <remarks>
    /// Split out from the proving above because a table of bytes is not the only thing a proof can
    /// come from. Where the strings are kept somewhere no run of bytes describes, they are read by
    /// asking the resolver instead, and what is then owed is this: the same all-or-nothing rewrite,
    /// the same refusal to leave a reference to the resolver behind, and the same verification of
    /// the module before anything is committed.
    /// </remarks>
    internal static (PassStatus, int, IReadOnlyList<string>) Rewrite(
        ArtifactContext context,
        string pass,
        IReadOnlyCollection<MethodDef> aliases,
        int callSiteCount,
        IReadOnlyList<(MethodDef Method, Instruction Call, string Value)> replacements)
    {
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
                pass,
                "restore-string",
                $"{replacement.Method.MDToken} IL_{replacement.Call.Offset:X4}",
                JsonSerializer.Serialize(replacement.Value)));
        // Added to rather than set, because a module can keep its strings in more than one place and
        // each reading accounts for its own sites. A count that overwrote would report the last
        // reading's work as the whole run's.
        context.TryGetFact<int>("strings.callSites", out var countedBefore);
        context.TryGetFact<int>("strings.replacedSites", out var restoredBefore);
        context.SetFact("strings.callSites", countedBefore + callSiteCount);
        context.SetFact("strings.replacedSites", restoredBefore + replacements.Count);
        // Every call the resolver and its aliases existed to serve is now an ldstr, which leaves
        // the decoding machinery behind them with nothing to decode either.
        RecoveryOrphans.DeclareSubtree(context, aliases);
        return (PassStatus.Success, replacements.Count,
            [$"Atomically restored all {replacements.Count} proven string sites."]);
    }
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
            var addedMethods = effective.AddedMethodTokenSet;
            var resourceDelta = effective.AddedResourceSet.Count - effective.RemovedResourceSet.Count;
            var typeDelta = effective.AddedTypeCount - effective.RemovedTypeCount;
            if (current.TypeCount != originalStructure.TypeCount + typeDelta)
                diagnostics.Add("Type count changed during rewriting.");
            if (current.MethodCount !=
                originalStructure.MethodCount - removedMethods.Count + addedMethods.Count)
            {
                diagnostics.Add("Method count changed during rewriting.");
            }
            if (current.FieldCount != originalStructure.FieldCount - effective.RemovedFieldCount)
                diagnostics.Add("Field count changed during rewriting.");
            if (current.ResourceCount != originalStructure.ResourceCount + resourceDelta)
                diagnostics.Add("Resource count changed during rewriting.");
            if (!MethodTokensMatch(
                    originalStructure.MethodRvas.Keys, current.MethodRvas.Keys,
                    removedMethods, addedMethods))
            {
                diagnostics.Add("Method token set changed during rewriting.");
            }
        }

        return new VerificationResult(diagnostics.Count == 0, diagnostics);
    }

    /// <summary>
    /// Confirms the surviving method tokens are exactly the original set, less what was declared
    /// removed and plus what was declared added.
    /// </summary>
    /// <remarks>
    /// A method the run added has no token yet: the writer assigns one, and until then dnlib reads
    /// it as the zero row of the method table. That is what the snapshot sees, so it is what the
    /// declaration names, and one addition is as far as this goes — two would be the same token
    /// twice and the snapshot would refuse to record them.
    /// </remarks>
    private static bool MethodTokensMatch(
        IEnumerable<uint> original,
        IEnumerable<uint> current,
        IReadOnlySet<uint> removed,
        IReadOnlySet<uint> added)
    {
        var expected = new HashSet<uint>(original);
        expected.ExceptWith(removed);
        expected.UnionWith(added);
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
