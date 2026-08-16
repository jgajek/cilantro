using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using dnlib.DotNet;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Interpretation;

namespace ReactorUnpack.Core.Corpus;

public sealed record CorpusManifest(
    int ManifestVersion,
    string Profile,
    string Description,
    IReadOnlyList<CorpusSample> Samples);

public sealed record CorpusSample(
    string Id,
    string Tier,
    string Sha256,
    string LocalName,
    string ExpectedDetection,
    IReadOnlyList<string> ExpectedCapabilities,
    string? OracleSha256,
    int? ExpectedRestoredBodyCount = null,
    int? MaximumRemainingStubs = null,
    double? MinimumStringSiteCoverage = null,
    int? MaximumMutationCount = null,
    bool RequireOracleParity = false,
    string? ExpectedOutputSha256 = null,
    int? MinimumBooleansRecovered = null,
    int? MinimumTokensRestored = null,
    int? MinimumResourcesRestored = null,
    int? MaximumRemainingSwitchDispatchers = null,
    int? MaximumUnreachableInstructions = null,
    string? ExpectUnsupportedReason = null,
    double? MinimumVirtualOperationsRead = null,
    double? MinimumVirtualOperationsWalked = null,
    bool RequireConsistentVirtualStack = false,
    int? MaximumSurplusMethods = null,
    int? MaximumProgramMethodSurplus = null,
    int? MaximumSurplusResources = null,
    bool RequireOracleResourceParity = false,
    int? MinimumConstantStringSites = null,
    string? HostProfile = null,
    IReadOnlyList<string>? Libraries = null,
    string? Declarations = null,
    bool AllowDeclaredCalls = false);

public sealed record CorpusSampleOutcome(
    string Id,
    string Tier,
    string Status,
    string Sha256,
    bool HashVerified,
    string Detection,
    IReadOnlyList<string> Capabilities,
    IReadOnlyList<NormalizedPassOutcome> Passes,
    RecoveryReportMetrics Recovery,
    string? OutputSha256,
    OracleComparison? Oracle,
    IReadOnlyList<string> Diagnostics);

public sealed record NormalizedPassOutcome(
    string Pass,
    PassStatus Status,
    int Changes,
    IReadOnlyList<string> Diagnostics);

/// <summary>
/// Structural comparison of recovered output against a deobfuscated validation oracle.
/// </summary>
/// <remarks>
/// The oracle is not original source: its own types are named <c>Class0</c> and
/// <c>Class3/Delegate9</c> because another deobfuscator renamed them. Comparing member names for
/// equality would therefore demand reproducing that tool's arbitrary numbering, which is not a
/// correctness property and is unreachable for any static tool.
///
/// What is meaningful splits in two. Names the protector never obfuscated survive in both
/// artifacts, so every such member the oracle kept must also exist in our output; losing one means
/// recovery deleted real program surface, and that is a hard failure. Everything else is scaffolding
/// the oracle removed and we have not yet proven dead, so it is reported as a surplus count that
/// gates against a ratchet and is expected to fall as cleanup improves.
///
/// Resources split the same way, and counting them alone hides the distinction. A module that
/// dropped the application's resources and one that kept them alongside the protector's bundle can
/// have the same resource count, so the oracle's resource names are compared as a subset the output
/// must contain, exactly as preserved member names are.
/// </remarks>
public sealed record OracleComparison(
    bool AssemblyIdentityMatches,
    bool EntryPointKindMatches,
    int OutputTypeCount,
    int OracleTypeCount,
    int OutputMethodCount,
    int OracleMethodCount,
    int SurplusMethods,
    int OutputResourceCount,
    int OracleResourceCount,
    int SurplusResources,
    int OraclePreservedNameMembers,
    int PreservedNameMembersPresent,
    bool PreservedNamesIntact,
    IReadOnlyList<string> MissingPreservedNameMembers,
    IReadOnlyList<string> MissingOracleResources,
    int ProgramMethodSurplus,
    int ProgramMethodDeficit);

public sealed record CorpusRunReport(
    int ManifestVersion,
    string Profile,
    IReadOnlyList<CorpusSampleOutcome> Samples,
    int Passed,
    int Failed,
    int Missing);

public static class CorpusRunner
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    public static CorpusManifest LoadManifest(string path)
    {
        var manifest = JsonSerializer.Deserialize<CorpusManifest>(
            File.ReadAllText(path),
            JsonOptions) ?? throw new InvalidDataException("Corpus manifest is empty.");
        if (manifest.ManifestVersion != 1)
            throw new InvalidDataException($"Unsupported manifest version {manifest.ManifestVersion}.");
        var duplicate = manifest.Samples.GroupBy(sample => sample.Id)
            .FirstOrDefault(group => group.Count() > 1);
        if (duplicate is not null)
            throw new InvalidDataException($"Duplicate corpus id '{duplicate.Key}'.");
        return manifest;
    }

    /// <summary>
    /// How many samples are analysed at once.
    /// </summary>
    /// <remarks>
    /// A sample is a closed unit of work: it reads one file, writes one directory named after
    /// itself, and shares nothing with its neighbours, since every module is loaded into a context
    /// of its own and no pass keeps state between runs. Running them together is therefore free of
    /// interference, and the outcome list is filled by position so the report reads the same whether
    /// one sample ran or all of them did.
    ///
    /// The cap is on memory rather than on cores. Interpreting a loader can hold a mapped image and
    /// a few hundred megabytes of heap model, so the useful width is set by how many of those fit at
    /// once, and past a handful there is nothing left to overlap anyway: a run is only ever as short
    /// as its slowest sample.
    ///
    /// Tracing is the one thing that does not survive the overlap, because the trace is a single
    /// ordered account of what one interpretation did and samples running together would shuffle
    /// their lines into each other. A run with tracing asked for therefore goes back to one at a
    /// time, which is the only way the file it produces means anything.
    /// </remarks>
    private static int SampleConcurrency => MachineTrace.Enabled
        ? 1
        : Math.Max(1, Math.Min(Environment.ProcessorCount, 4));

    public static CorpusRunReport Run(
        string manifestPath,
        string sampleDirectory,
        string outputDirectory,
        bool strict = false)
    {
        var manifest = LoadManifest(manifestPath);
        // A profile or a library named by an entry is named relative to the manifest that names it,
        // so a corpus is one thing that can be moved rather than a file plus a working directory.
        var manifestDirectory = Path.GetDirectoryName(Path.GetFullPath(manifestPath)) ?? ".";
        Directory.CreateDirectory(outputDirectory);
        var samplesByHash = manifest.Samples.ToDictionary(
            sample => sample.Sha256,
            StringComparer.OrdinalIgnoreCase);
        var scheduled = manifest.Samples
            .Where(sample => sample.Tier != "oracle")
            .OrderBy(sample => sample.Id, StringComparer.Ordinal)
            .ToArray();
        var outcomes = new CorpusSampleOutcome[scheduled.Length];
        Parallel.For(
            0,
            scheduled.Length,
            new ParallelOptions { MaxDegreeOfParallelism = SampleConcurrency },
            index =>
            {
                var sample = scheduled[index];
                var path = Path.Combine(sampleDirectory, sample.LocalName);
                outcomes[index] = RunSample(
                    sample,
                    path,
                    sampleDirectory,
                    outputDirectory,
                    manifestDirectory,
                    samplesByHash,
                    strict);
            });

        var report = new CorpusRunReport(
            manifest.ManifestVersion,
            manifest.Profile,
            outcomes,
            outcomes.Count(outcome => outcome.Status == "passed"),
            outcomes.Count(outcome => outcome.Status == "failed"),
            outcomes.Count(outcome => outcome.Status == "missing"));
        var reportPath = Path.Combine(outputDirectory, "corpus.outcomes.json");
        File.WriteAllText(reportPath, JsonSerializer.Serialize(report, JsonOptions));
        return report;
    }

    private static CorpusSampleOutcome RunSample(
        CorpusSample sample,
        string path,
        string sampleDirectory,
        string outputDirectory,
        string manifestDirectory,
        Dictionary<string, CorpusSample> samplesByHash,
        bool strict)
    {
        if (!File.Exists(path))
            return Missing(sample);
        var bytes = File.ReadAllBytes(path);
        var hash = Convert.ToHexStringLower(SHA256.HashData(bytes));
        if (!hash.Equals(sample.Sha256, StringComparison.OrdinalIgnoreCase))
            return FailedHash(sample, hash);

        var analysisOnly = sample.Tier is "negative" or "exploratory";
        var sampleOutputDirectory = Path.Combine(outputDirectory, sample.Id);
        var outputPath = Path.Combine(sampleOutputDirectory, "cleaned.bin");
        // The corpus exercises the default emission policy rather than the strict one, so an
        // outcome reflects what a caller actually gets. Rigor comes from the manifest's explicit
        // per-sample expectations and from every pass status being recorded in the outcome. The
        // interpretation mode is asked for by whoever runs the corpus rather than written into the
        // manifest, because the point of running it both ways is to compare the same expectations.
        // Renaming and building virtualized methods back are what a triage run does for the analyst
        // reading the result, and neither is what this harness measures: one rewrites the names an
        // outcome is compared by, and the other doubles the time a virtualized sample takes to say
        // something the manifest does not ask about. Both are pinned off so that an outcome means
        // the same thing in every run rather than following the mode.
        var result = new ReactorPipeline().Run(path, new PipelineOptions(
            AnalyzeOnly: analysisOnly,
            PreserveTokens: true,
            RenameSymbols: false,
            Devirtualize: false,
            OutputPath: outputPath,
            ReportDirectory: sampleOutputDirectory,
            HostProfilePath: Beside(manifestDirectory, sample.HostProfile),
            LibraryPaths: sample.Libraries
                ?.Select(library => Beside(manifestDirectory, library)!)
                .ToArray(),
            DeclarationsPath: Beside(manifestDirectory, sample.Declarations),
            AllowDeclaredCalls: sample.AllowDeclaredCalls,
            Strict: strict));
        var capabilities = result.Report.Evidence
            .Where(evidence => evidence.Category == "capability")
            .Select(evidence => evidence.Message)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var detected = capabilities.Length > 0 ? "reactor6" : "none";
        var diagnostics = new List<string>();
        if (detected != sample.ExpectedDetection)
            diagnostics.Add($"Expected detection {sample.ExpectedDetection}, observed {detected}.");
        var missingCapabilities = sample.ExpectedCapabilities
            .Except(capabilities, StringComparer.Ordinal)
            .ToArray();
        if (missingCapabilities.Length > 0)
            diagnostics.Add($"Missing capabilities: {string.Join(", ", missingCapabilities)}.");
        if (!analysisOnly && result.OutputPath is null)
            diagnostics.Add("Profiled sample did not emit verified output.");
        if (result.Report.Passes.Any(pass => pass.Status == PassStatus.Failed))
            diagnostics.Add("At least one pipeline pass failed.");
        if (sample.ExpectUnsupportedReason is string expectedReason)
        {
            var reported = result.Report.Passes.Any(pass =>
                pass.Status == PassStatus.Unsupported &&
                pass.Diagnostics.Any(diagnostic =>
                    diagnostic.Contains(expectedReason, StringComparison.OrdinalIgnoreCase)));
            if (!reported)
                diagnostics.Add($"Expected an unsupported diagnostic mentioning '{expectedReason}'.");
        }
        ValidateRecoveryExpectations(sample, result.Report.Recovery, diagnostics);

        OracleComparison? oracle = null;
        if (sample.OracleSha256 is not null &&
            samplesByHash.TryGetValue(sample.OracleSha256, out var oracleEntry))
        {
            var oraclePath = Path.Combine(sampleDirectory, oracleEntry.LocalName);
            if (File.Exists(oraclePath) &&
                Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(oraclePath)))
                    .Equals(oracleEntry.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                oracle = CompareAssemblies(result.OutputPath ?? path, oraclePath);
                if (sample.RequireOracleParity)
                    ValidateOracleParity(sample, oracle, diagnostics);
            }
            else
            {
                diagnostics.Add("Validation oracle is missing or failed hash verification.");
            }
        }

        var passes = result.Report.Passes
            .Select(pass => new NormalizedPassOutcome(
                pass.Pass,
                pass.Status,
                pass.Changes,
                pass.Diagnostics))
            .ToArray();
        var outputHash = result.OutputPath is not null && File.Exists(result.OutputPath)
            ? Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(result.OutputPath)))
            : null;
        if (sample.ExpectedOutputSha256 is not null &&
            !string.Equals(
                outputHash,
                sample.ExpectedOutputSha256,
                StringComparison.OrdinalIgnoreCase))
        {
            diagnostics.Add("Output hash did not match the regression lock.");
        }
        return new CorpusSampleOutcome(
            sample.Id,
            sample.Tier,
            diagnostics.Count == 0 ? "passed" : "failed",
            hash,
            true,
            detected,
            capabilities,
            passes,
            result.Report.Recovery,
            outputHash,
            oracle,
            diagnostics);
    }

    private static OracleComparison CompareAssemblies(string protectedPath, string oraclePath)
    {
        using var outputModule = ModuleDefMD.Load(protectedPath);
        using var oracleModule = ModuleDefMD.Load(oraclePath);
        var outputName = outputModule.Assembly?.Name.String ?? outputModule.Name.String;
        var oracleName = oracleModule.Assembly?.Name.String ?? oracleModule.Name.String;
        var outputMembers = PreservedNameMembers(outputModule);
        var oracleMembers = PreservedNameMembers(oracleModule);
        var missing = oracleMembers.Except(outputMembers, StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var outputMethods = outputModule.GetTypes().Sum(type => type.Methods.Count);
        var oracleMethods = oracleModule.GetTypes().Sum(type => type.Methods.Count);
        var outputResources = outputModule.Resources
            .Select(resource => resource.Name.String)
            .ToHashSet(StringComparer.Ordinal);
        var missingResources = oracleModule.Resources
            .Select(resource => resource.Name.String)
            .Where(name => !outputResources.Contains(name))
            .Order(StringComparer.Ordinal)
            .ToArray();
        var (programSurplus, programDeficit) = ProgramMethodDelta(outputModule, oracleModule);
        return new OracleComparison(
            outputName == oracleName,
            (outputModule.EntryPoint is null) == (oracleModule.EntryPoint is null),
            outputModule.GetTypes().Count(),
            oracleModule.GetTypes().Count(),
            outputMethods,
            oracleMethods,
            outputMethods - oracleMethods,
            outputModule.Resources.Count,
            oracleModule.Resources.Count,
            outputModule.Resources.Count - oracleModule.Resources.Count,
            oracleMembers.Count,
            oracleMembers.Count - missing.Length,
            missing.Length == 0,
            missing,
            missingResources,
            programSurplus,
            programDeficit);
    }

    /// <summary>
    /// Members whose names the protector left intact, keyed so renaming elsewhere cannot perturb
    /// them.
    /// </summary>
    /// <remarks>
    /// A member qualifies only when every component of its declaring type's name and its own name
    /// is neither Reactor-generated nor a deobfuscator's synthetic placeholder. The key uses the
    /// parameter count rather than parameter type names, because an overload's parameter types can
    /// themselves be renamed types while the overload is still the same member.
    ///
    /// Properties and events count as members in their own right rather than as their accessors.
    /// Their metadata rows are separable from the methods behind them, so an output that kept
    /// <c>get_Name</c> but lost the <c>Name</c> property would satisfy a method-only comparison
    /// while presenting a different API to a decompiler.
    /// </remarks>
    private static HashSet<string> PreservedNameMembers(ModuleDef module) =>
        module.GetTypes()
            .Where(type => HasPreservedName(type.FullName))
            .SelectMany(type => type.Methods
                .Where(method => HasPreservedName(method.Name))
                .Select(method =>
                    $"{type.FullName}::{method.Name}/{method.MethodSig?.Params.Count ?? 0}")
                .Concat(type.Properties
                    .Where(property => HasPreservedName(property.Name))
                    .Select(property => $"{type.FullName}::{property.Name}/property"))
                .Concat(type.Events
                    .Where(item => HasPreservedName(item.Name))
                    .Select(item => $"{type.FullName}::{item.Name}/event")))
            .ToHashSet(StringComparer.Ordinal);

    /// <summary>
    /// How the output and the oracle differ inside the types both name, counted in both directions.
    /// </summary>
    /// <remarks>
    /// The module-wide method surplus stopped being a safety net once cleanup began removing the
    /// protector runtime the oracle keeps. De4dot renames Reactor's runtime type rather than
    /// deleting it, so on these samples it contributes a hundred and forty methods to the oracle's
    /// total, and an output that removed it scores a negative surplus. A single signed number then
    /// reads the same whether the output dropped scaffolding the oracle kept or dropped program the
    /// oracle kept, which is the one distinction the gate exists to make.
    ///
    /// Restricting the comparison to types whose names both sides preserved isolates the program
    /// from the protector, because those are exactly the names Reactor did not obfuscate. Within
    /// them the two counts are comparable, and the direction carries the meaning: a surplus is
    /// Reactor's per-type helpers that cleanup cannot yet attribute, while a deficit is program the
    /// output no longer has.
    /// </remarks>
    private static (int Surplus, int Deficit) ProgramMethodDelta(
        ModuleDef outputModule,
        ModuleDef oracleModule)
    {
        var output = MethodsByPreservedType(outputModule);
        var surplus = 0;
        var deficit = 0;
        foreach (var (name, oracleCount) in MethodsByPreservedType(oracleModule))
        {
            var delta = output.GetValueOrDefault(name) - oracleCount;
            if (delta >= 0)
                surplus += delta;
            else
                deficit -= delta;
        }
        return (surplus, deficit);
    }

    private static Dictionary<string, int> MethodsByPreservedType(ModuleDef module) =>
        module.GetTypes()
            .Where(type => HasPreservedName(type.FullName))
            .ToDictionary(type => type.FullName, type => type.Methods.Count, StringComparer.Ordinal);

    private static bool HasPreservedName(string name) =>
        name.Split('.', '/', '`', '+')
            .Where(component => component.Length > 0)
            .All(component =>
                !ReactorNameHeuristics.IsGeneratedName(component) &&
                !IsDeobfuscatorPlaceholder(component));

    /// <summary>
    /// Recognizes the synthetic names a de4dot-lineage renamer assigns, such as <c>Class3</c> and
    /// <c>smethod_0</c>.
    /// </summary>
    /// <remarks>
    /// These read as ordinary identifiers, so the generated-name heuristic passes them. Treating
    /// them as real would demand that our output reproduce another tool's numbering. Types get a
    /// capitalized prefix and members an underscore-separated lowercase one.
    /// </remarks>
    private static bool IsDeobfuscatorPlaceholder(string component)
    {
        var digits = 0;
        while (digits < component.Length && char.IsAsciiDigit(component[^(digits + 1)]))
            digits++;
        if (digits == 0 || digits == component.Length)
            return false;
        return component[..^digits] is
            "Class" or "Delegate" or "Interface" or "Enum" or "Struct" or "Type" or
            "Method" or "Field" or "Prop" or "Property" or "Event" or "Param" or
            "GParam" or "Namespace" or
            "class_" or "type_" or "delegate_" or "enum_" or "interface_" or "struct_" or
            "method_" or "smethod_" or "vmethod_" or
            "field_" or "sfield_" or "prop_" or "event_" or
            "param_" or "gparam_" or "local_" or "arg_";
    }

    /// <summary>
    /// Applies the two oracle obligations: lose nothing real, and stay within the surplus ratchet.
    /// </summary>
    /// <remarks>
    /// Losing a preserved-name member always fails, because it means recovery deleted program
    /// surface the oracle kept, and so does losing a method from a type both sides name, which
    /// catches the unnamed private members that the preserved-name subset cannot see. The surplus
    /// limits are ratchets rather than absolutes: they record how much scaffolding still survives
    /// today so that any improvement is visible and any regression fails, and they are tightened as
    /// cleanup advances.
    /// </remarks>
    private static void ValidateOracleParity(
        CorpusSample sample,
        OracleComparison oracle,
        List<string> diagnostics)
    {
        if (!oracle.AssemblyIdentityMatches)
            diagnostics.Add("Assembly identity does not match the oracle.");
        if (!oracle.EntryPointKindMatches)
            diagnostics.Add("Entry-point kind does not match the oracle.");
        if (!oracle.PreservedNamesIntact)
        {
            diagnostics.Add(
                $"Recovery lost {oracle.MissingPreservedNameMembers.Count} preserved-name member(s) " +
                $"the oracle retains, starting with {oracle.MissingPreservedNameMembers[0]}.");
        }

        if (oracle.ProgramMethodDeficit != 0)
        {
            diagnostics.Add(
                $"Output is missing {oracle.ProgramMethodDeficit} method(s) from types the oracle " +
                "names, so cleanup removed program rather than scaffolding.");
        }

        if (sample.MaximumProgramMethodSurplus is int programLimit &&
            oracle.ProgramMethodSurplus > programLimit)
        {
            diagnostics.Add(
                $"Surplus of {oracle.ProgramMethodSurplus} method(s) inside named types exceeds " +
                $"{programLimit}.");
        }

        if (sample.MaximumSurplusMethods is int methodLimit &&
            oracle.SurplusMethods > methodLimit)
        {
            diagnostics.Add(
                $"Surplus of {oracle.SurplusMethods} method(s) over the oracle exceeds {methodLimit}.");
        }

        if (sample.MaximumSurplusResources is int resourceLimit &&
            oracle.SurplusResources > resourceLimit)
        {
            diagnostics.Add(
                $"Surplus of {oracle.SurplusResources} resource(s) over the oracle exceeds {resourceLimit}.");
        }

        if (sample.RequireOracleResourceParity && oracle.MissingOracleResources.Count != 0)
        {
            diagnostics.Add(
                $"Output is missing {oracle.MissingOracleResources.Count} resource(s) the oracle " +
                $"carries: {string.Join(", ", oracle.MissingOracleResources)}.");
        }
    }

    private static void ValidateRecoveryExpectations(
        CorpusSample sample,
        RecoveryReportMetrics recovery,
        List<string> diagnostics)
    {
        if (sample.ExpectedRestoredBodyCount is int restored &&
            recovery.RestoredMethodBodies != restored)
            diagnostics.Add($"Expected {restored} restored bodies, observed {recovery.RestoredMethodBodies}.");
        if (sample.MaximumRemainingStubs is int remaining &&
            recovery.RemainingMethodStubs > remaining)
            diagnostics.Add($"Remaining method stubs exceed {remaining}.");
        var coverage = recovery.StringCallSites == 0
            ? 1.0
            : (double)recovery.ReplacedStringSites / recovery.StringCallSites;
        if (sample.MinimumStringSiteCoverage is double minimum && coverage < minimum)
            diagnostics.Add($"String-site coverage {coverage:P2} is below {minimum:P2}.");
        if (sample.MaximumMutationCount is int mutations &&
            recovery.MutationCount > mutations)
            diagnostics.Add($"Mutation count {recovery.MutationCount} exceeds {mutations}.");
        if (sample.MinimumBooleansRecovered is int booleans &&
            recovery.BooleansRecovered < booleans)
            diagnostics.Add($"Recovered booleans {recovery.BooleansRecovered} is below {booleans}.");
        if (sample.MinimumTokensRestored is int tokens &&
            recovery.TokensRestored < tokens)
            diagnostics.Add($"Restored tokens {recovery.TokensRestored} is below {tokens}.");
        if (sample.MinimumResourcesRestored is int restoredResources &&
            recovery.ResourcesRestored < restoredResources)
            diagnostics.Add($"Restored resources {recovery.ResourcesRestored} is below {restoredResources}.");
        if (sample.MaximumRemainingSwitchDispatchers is int maxDispatchers &&
            recovery.RemainingSwitchDispatchers > maxDispatchers)
            diagnostics.Add(
                $"Remaining switch dispatchers {recovery.RemainingSwitchDispatchers} exceed {maxDispatchers}.");
        if (sample.MaximumUnreachableInstructions is int maxUnreachable &&
            recovery.RemainingUnreachableInstructions > maxUnreachable)
            diagnostics.Add(
                $"Remaining unreachable instructions {recovery.RemainingUnreachableInstructions} exceed {maxUnreachable}.");

        // A module whose strings are behind its own decoders rather than the protector's resolver has
        // no resolver coverage to gate on, and this is what stands in for it there.
        if (sample.MinimumConstantStringSites is int folded &&
            recovery.ConstantStringSites < folded)
            diagnostics.Add(
                $"Call sites replaced with the string they return {recovery.ConstantStringSites} " +
                $"is below {folded}.");
        CheckVirtualization(sample, recovery, diagnostics);
    }

    /// <summary>
    /// Holds a virtualized sample to the reading already reached for it, share by share.
    /// </summary>
    /// <remarks>
    /// Shares rather than counts, because the number of operations is a fact about the sample and
    /// the fraction read is a fact about the tool. The walk agreeing with itself is held separately
    /// and absolutely: a listing that reaches an operation at two depths has a mistake in it
    /// somewhere, and no amount of coverage makes up for that.
    /// </remarks>
    private static void CheckVirtualization(
        CorpusSample sample,
        RecoveryReportMetrics recovery,
        List<string> diagnostics)
    {
        if (recovery.VirtualOperations == 0)
        {
            if (sample.MinimumVirtualOperationsRead is not null ||
                sample.MinimumVirtualOperationsWalked is not null)
            {
                diagnostics.Add("No virtualized program was read back, so its gates cannot be met.");
            }
            return;
        }
        var read = (double)recovery.VirtualOperationsRead / recovery.VirtualOperations;
        var walked = (double)recovery.VirtualOperationsWalked / recovery.VirtualOperations;
        if (sample.MinimumVirtualOperationsRead is double leastRead && read < leastRead)
        {
            diagnostics.Add(
                $"Read {recovery.VirtualOperationsRead} of {recovery.VirtualOperations} virtual " +
                $"operation(s) as IL, below the required {leastRead:P0}.");
        }
        if (sample.MinimumVirtualOperationsWalked is double leastWalked && walked < leastWalked)
        {
            diagnostics.Add(
                $"The stack walk reaches {recovery.VirtualOperationsWalked} of " +
                $"{recovery.VirtualOperations} virtual operation(s), below the required " +
                $"{leastWalked:P0}.");
        }
        if (sample.RequireConsistentVirtualStack && recovery.VirtualDepthDisagreements > 0)
        {
            diagnostics.Add(
                $"{recovery.VirtualDepthDisagreements} virtual operation(s) are reached at two " +
                "different stack depths, so one of the readings is wrong.");
        }
    }

    /// <summary>Resolves a path the manifest named against the manifest's own folder.</summary>
    private static string? Beside(string manifestDirectory, string? path) => path is null
        ? null
        : Path.GetFullPath(Path.Combine(manifestDirectory, path));

    private static CorpusSampleOutcome Missing(CorpusSample sample) =>
        new(sample.Id, sample.Tier, "missing", sample.Sha256, false, "unknown", [], [],
            new RecoveryReportMetrics(0, 0, 0, 0, 0), null, null,
            [$"Missing sample: {sample.LocalName}"]);

    private static CorpusSampleOutcome FailedHash(CorpusSample sample, string actual) =>
        new(sample.Id, sample.Tier, "failed", actual, false, "unknown", [], [],
            new RecoveryReportMetrics(0, 0, 0, 0, 0), null, null,
            [$"SHA-256 mismatch; expected {sample.Sha256}."]);
}
