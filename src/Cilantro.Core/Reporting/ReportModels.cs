using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;

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

public enum PayloadOrigin
{
    Unknown,
    AssemblyLoad,
    ResourceBundle,
    EmbeddedDependency,
    NativeWrapper,
    ResourceCodec,
    NativeDependency
}

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
    string? WrittenTo = null,
    PayloadOrigin Origin = PayloadOrigin.Unknown);

public sealed record ExtractedPayload(PayloadInfo Info, byte[] Bytes);

public sealed record DecodedResourceInfo(string SourceResource, string SourceSha256,
    int DecodedLength, string DecodedSha256, string Decoder, string? WrittenTo = null);

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
    string Protector = "none",

    /// <summary>
    /// What each body built back from a virtual program reaches, named as the cleaned copy names it.
    /// </summary>
    IReadOnlyList<RebuiltMethodReport>? RebuiltMethods = null,
    IReadOnlyList<DecodedResourceInfo>? DecodedResources = null);

/// <summary>
/// The way into a body the tool built rather than recovered.
/// </summary>
/// <remarks>
/// A lifted body is faithful and hard to read: the interpreter's jump table for control flow,
/// <see cref="object"/> for every local because the machine's slots had no types, and generated
/// names throughout. What makes it tractable is that the framework calls leaving it were never
/// obfuscated in the first place, so listing them says what the method is for in a line. Everything
/// here is named as the cleaned copy names it, the account being written after renaming rather than
/// before.
/// </remarks>
public sealed record RebuiltMethodReport(
    string Method,

    /// <summary>The members the body reaches, through whatever forwarders stand in the way.</summary>
    IReadOnlyList<string> Reaches,

    /// <summary>The fields it assigns, which is where its work is left.</summary>
    IReadOnlyList<string> Writes,

    /// <summary>
    /// Whether anything in the cleaned copy calls it.
    /// </summary>
    /// <remarks>
    /// Often nothing does, and that is a result rather than a fault: recovery replaces the code that
    /// used to need the method, so the caller becomes dead and is removed. Saying so stops a reader
    /// concluding the body was not written.
    /// </remarks>
    bool Reachable,

    int Instructions);

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
    int RedirectedDispatcherEdges = 0,
    int RuntimeTypesRemoved = 0,
    int SymbolsRenamed = 0,
    int RemainingUnreachableInstructions = 0,
    int VirtualOperations = 0,
    int VirtualOperationsRead = 0,
    int VirtualOperationsWalked = 0,
    int VirtualDepthDisagreements = 0,
    int ConstantStringSites = 0,
    int ProxyCallsRestored = 0,
    int ControlFlowMethodsSimplified = 0,
    int ConstantBranchesFolded = 0,
    int DispatcherMethodsRestored = 0,
    int DispatcherMethodCandidates = 0);
