using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using dnlib.DotNet;
using ReactorUnpack.Core.Analysis;

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
    string? ExpectedOutputSha256 = null);

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

public sealed record OracleComparison(
    bool AssemblyIdentityMatches,
    bool EntryPointKindMatches,
    int ProtectedPublicApiCount,
    int OraclePublicApiCount,
    int ProtectedResourceCount,
    int OracleResourceCount,
    int MatchingMethodSignatures,
    int ProtectedMethodSignatures,
    int OracleMethodSignatures,
    bool PublicApiMatches,
    bool ResourcesMatch);

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

    public static CorpusRunReport Run(
        string manifestPath,
        string sampleDirectory,
        string outputDirectory)
    {
        var manifest = LoadManifest(manifestPath);
        Directory.CreateDirectory(outputDirectory);
        var samplesByHash = manifest.Samples.ToDictionary(
            sample => sample.Sha256,
            StringComparer.OrdinalIgnoreCase);
        var outcomes = new List<CorpusSampleOutcome>();
        foreach (var sample in manifest.Samples
                     .Where(sample => sample.Tier != "oracle")
                     .OrderBy(sample => sample.Id, StringComparer.Ordinal))
        {
            var path = Path.Combine(sampleDirectory, sample.LocalName);
            outcomes.Add(RunSample(sample, path, sampleDirectory, outputDirectory, samplesByHash));
        }

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
        Dictionary<string, CorpusSample> samplesByHash)
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
        var result = new ReactorPipeline().Run(path, new PipelineOptions(
            AnalyzeOnly: analysisOnly,
            PreserveTokens: true,
            FailOnPartial: true,
            OutputPath: outputPath,
            ReportDirectory: sampleOutputDirectory));
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
                if (sample.RequireOracleParity &&
                    (!oracle.AssemblyIdentityMatches ||
                     !oracle.EntryPointKindMatches ||
                     !oracle.PublicApiMatches ||
                     !oracle.ResourcesMatch ||
                     oracle.MatchingMethodSignatures != oracle.OracleMethodSignatures))
                {
                    diagnostics.Add("Required normalized oracle parity was not achieved.");
                }
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
        using var protectedModule = ModuleDefMD.Load(protectedPath);
        using var oracleModule = ModuleDefMD.Load(oraclePath);
        var protectedName = protectedModule.Assembly?.Name.String ?? protectedModule.Name.String;
        var oracleName = oracleModule.Assembly?.Name.String ?? oracleModule.Name.String;
        var protectedSignatures = MethodSignatures(protectedModule);
        var oracleSignatures = MethodSignatures(oracleModule);
        var protectedApi = PublicApi(protectedModule);
        var oracleApi = PublicApi(oracleModule);
        var protectedResources = protectedModule.Resources.Select(resource => resource.Name.String)
            .Order(StringComparer.Ordinal).ToArray();
        var oracleResources = oracleModule.Resources.Select(resource => resource.Name.String)
            .Order(StringComparer.Ordinal).ToArray();
        return new OracleComparison(
            protectedName == oracleName,
            (protectedModule.EntryPoint is null) == (oracleModule.EntryPoint is null),
            CountPublicApi(protectedModule),
            CountPublicApi(oracleModule),
            protectedModule.Resources.Count,
            oracleModule.Resources.Count,
            protectedSignatures.Intersect(oracleSignatures, StringComparer.Ordinal).Count(),
            protectedSignatures.Count,
            oracleSignatures.Count,
            protectedApi.SetEquals(oracleApi),
            protectedResources.SequenceEqual(oracleResources, StringComparer.Ordinal));
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
    }

    private static HashSet<string> MethodSignatures(ModuleDef module) =>
        module.GetTypes().SelectMany(type => type.Methods)
            .Select(method => method.FullName)
            .ToHashSet(StringComparer.Ordinal);

    private static HashSet<string> PublicApi(ModuleDef module) =>
        module.GetTypes().SelectMany(type =>
            type.Methods.Where(method => method.IsPublic).Select(method => method.FullName)
                .Concat(type.Fields.Where(field => field.IsPublic).Select(field => field.FullName)))
            .ToHashSet(StringComparer.Ordinal);

    private static int CountPublicApi(ModuleDef module) =>
        module.GetTypes().Sum(type =>
            (type.IsPublic || type.IsNestedPublic ? 1 : 0) +
            type.Methods.Count(method => method.IsPublic) +
            type.Fields.Count(field => field.IsPublic) +
            type.Properties.Count(property =>
                property.GetMethod?.IsPublic == true || property.SetMethod?.IsPublic == true));

    private static CorpusSampleOutcome Missing(CorpusSample sample) =>
        new(sample.Id, sample.Tier, "missing", sample.Sha256, false, "unknown", [], [],
            new RecoveryReportMetrics(0, 0, 0, 0, 0), null, null,
            [$"Missing sample: {sample.LocalName}"]);

    private static CorpusSampleOutcome FailedHash(CorpusSample sample, string actual) =>
        new(sample.Id, sample.Tier, "failed", actual, false, "unknown", [], [],
            new RecoveryReportMetrics(0, 0, 0, 0, 0), null, null,
            [$"SHA-256 mismatch; expected {sample.Sha256}."]);
}
