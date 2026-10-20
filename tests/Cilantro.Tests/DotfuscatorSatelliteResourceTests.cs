using System.Security.Cryptography;
using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Corpus;
using Cilantro.Core.Pipeline;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class DotfuscatorSatelliteResourceTests
{
    private static readonly string[] Cultures = ["fr", "fr-CA"];
    private static string ManifestPath => Path.Combine(Checkout.Root, "corpus", "dotfuscator-7-satellite-resources.manifest.json");
    private static string Samples => Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_RESOURCE_SAMPLES")!;

    [Fact]
    public void ManifestPinsLocalizedCapturesOnThreeFrameworks()
    {
        var samples = CorpusRunner.LoadManifest(ManifestPath).Samples;
        Assert.Equal(6, samples.Count);
        Assert.Equal(3, samples.Count(sample => sample.Tier == "oracle"));
        Assert.All(samples.Where(sample => sample.Tier != "oracle"), sample => Assert.True(sample.RequireOracleResourceParity));
    }

    [DotfuscatorResourceCorpusFact]
    [Trait(Cost.Key, Cost.High)]
    public void CompletePipelineRestoresMainAndCultureResources()
    {
        InTemporaryDirectory(directory =>
        {
            var outcome = CorpusRunner.Run(ManifestPath, Samples, directory);
            Assert.True(outcome.Passed == 3 && outcome.Failed == 0 && outcome.Missing == 0,
                JsonSerializer.Serialize(outcome, CilantroPipeline.ReportJsonOptions));
            var manifest = CorpusRunner.LoadManifest(ManifestPath);
            foreach (var sample in manifest.Samples.Where(sample => sample.Tier != "oracle"))
            {
                var result = outcome.Samples.Single(result => result.Id == sample.Id);
                Assert.Equal(3, result.Recovery.ResourcesRestored);
                Assert.Contains(result.Passes, pass => pass.Pass == "dotfuscator-resources" && pass.Status == PassStatus.Success && pass.Changes == 15);
                var sourceDirectory = Path.GetDirectoryName(Path.Combine(Samples, sample.LocalName))!;
                var oracle = manifest.Samples.Single(candidate => candidate.Sha256 == sample.OracleSha256);
                var oracleDirectory = Path.GetDirectoryName(Path.Combine(Samples, oracle.LocalName))!;
                AssertCompanionPins(sourceDirectory, oracleDirectory, sample.Id[..^"-resources".Length]);
                foreach (var culture in Cultures)
                {
                    var relative = Path.Combine(culture, "SatelliteProbe.resources.dll");
                    using var restored = ModuleDefMD.Load(Path.Combine(directory, sample.Id, relative));
                    using var original = ModuleDefMD.Load(Path.Combine(oracleDirectory, relative));
                    using var protectedModule = ModuleDefMD.Load(Path.Combine(sourceDirectory, relative));
                    Assert.Equal(protectedModule.Assembly.FullName, restored.Assembly.FullName);
                    Assert.Equal(ResourceHashes(original), ResourceHashes(restored));
                    Assert.NotEqual(ResourceHashes(protectedModule), ResourceHashes(restored));
                }
            }
        });
    }

    [DotfuscatorResourceCorpusFact]
    public void DefaultOutputKeepsProtectedSatellitesIntactAndReportsRestoredPaths()
    {
        InTemporaryDirectory(directory =>
        {
            var input = CopyFixture(directory);
            var before = Directory.GetFiles(directory, "*.dll", SearchOption.AllDirectories).ToDictionary(path => path, Hash);
            var result = new CilantroPipeline().Run(input, new PipelineOptions());
            Assert.True(result.Success, string.Join(";", result.Report.VerificationDiagnostics));
            Assert.Equal(Path.Combine(directory, "SatelliteProbe.cleaned", "SatelliteProbe.cleaned.exe"), result.OutputPath);
            Assert.Equal(2, result.ResourceSatellitePaths.Count);
            Assert.All(before, item => Assert.Equal(item.Value, Hash(item.Key)));
            Assert.Equal(result.ResourceSatellitePaths, RunManifest.Of(result).Wrote.ResourceSatellites);
            Assert.All(result.ResourceSatellitePaths, path => Assert.True(File.Exists(path)));
            Assert.Contains("Restored resource satellites", File.ReadAllText(result.ReadableReportPath!));
        });
    }

    [DotfuscatorResourceCorpusFact]
    public void CollidingSatelliteWithholdsMainOutputWithoutChangingSourceOrExistingOutput()
    {
        InTemporaryDirectory(directory =>
        {
            var input = CopyFixture(directory);
            var output = Path.Combine(directory, "keep.exe");
            File.WriteAllBytes(output, [1, 2, 3]);
            var before = Directory.GetFiles(directory, "*", SearchOption.AllDirectories).ToDictionary(path => path, Hash);
            var result = new CilantroPipeline().Run(input, new PipelineOptions(OutputPath: output, ReportDirectory: Path.Combine(directory, "reports")));
            Assert.False(result.Success);
            Assert.Null(result.OutputPath);
            Assert.Empty(result.ResourceSatellitePaths);
            Assert.All(before, item => Assert.Equal(item.Value, Hash(item.Key)));
            Assert.Contains(result.Report.VerificationDiagnostics, diagnostic => diagnostic.Contains("Satellite output already exists", StringComparison.Ordinal));
        });
    }

    [DotfuscatorResourceCorpusTheory]
    [InlineData("code")]
    [InlineData("culture")]
    [InlineData("version")]
    [InlineData("identity")]
    [InlineData("resource")]
    public void UnreviewedSatelliteDeclinesAtomically(string change)
    {
        InTemporaryDirectory(directory =>
        {
            var input = CopyFixture(directory);
            var satellite = Path.Combine(directory, "fr", "SatelliteProbe.resources.dll");
            byte[] changed;
            using (var module = ModuleDefMD.Load(satellite))
            {
                switch (change)
                {
                    case "code": module.Types.Add(new TypeDefUser("ApplicationCode", module.CorLibTypes.Object.TypeDefOrRef)); break;
                    case "culture": module.Assembly.Culture = "de"; break;
                    case "version": module.Assembly.Version = new Version(99, 0); break;
                    case "identity": module.Assembly.Name = "Foreign.resources"; break;
                    case "resource":
                        var resource = Assert.IsAssignableFrom<EmbeddedResource>(module.Resources[0]);
                        module.Resources[0] = new EmbeddedResource(resource.Name, new byte[] { 1, 2, 3 }, resource.Attributes);
                        break;
                }
                using var output = new MemoryStream(); module.Write(output); changed = output.ToArray();
            }
            File.WriteAllBytes(satellite, changed);
            using var context = ArtifactContext.Load(input);
            var resources = ResourceHashes(context.Module);
            var methods = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody)
                .ToDictionary(method => method, MethodBodySnapshot.Capture);
            new Cilantro.Core.Analysis.DotfuscatorDetectionPass().Run(context);
            var result = new DotfuscatorResourcePass().Run(context);
            Assert.Equal(PassStatus.Unsupported, result.Status);
            Assert.Equal(0, result.Changes);
            Assert.Equal(resources, ResourceHashes(context.Module));
            Assert.All(methods, item => Assert.True(item.Value.StructurallyEquals(item.Key)));
            Assert.False(context.TryGetFact<IReadOnlyList<DotfuscatorResourceSatellites.Restored>>(DotfuscatorResourceSatellites.Fact, out _));
        });
    }

    [Fact]
    public void CompanionEmissionPreflightsAllDestinationsAndReusesIdenticalBytes()
    {
        InTemporaryDirectory(directory =>
        {
            var input = Path.Combine(directory, "Input.dll");
            using (var module = new ModuleDefUser("Input.dll") { Kind = ModuleKind.Dll }) module.Write(input);
            using var context = ArtifactContext.Load(input);
            var restored = new[]
            {
                new DotfuscatorResourceSatellites.Restored("unused", "fr", "Input.resources.dll", [1,2], 1, "unused"),
                new DotfuscatorResourceSatellites.Restored("unused", "de", "Input.resources.dll", [3,4], 1, "unused")
            };
            context.SetFact<IReadOnlyList<DotfuscatorResourceSatellites.Restored>>(DotfuscatorResourceSatellites.Fact, restored);
            var output = Path.Combine(directory, "output", "Input.cleaned.dll");
            Directory.CreateDirectory(Path.Combine(directory, "output", "de"));
            var conflict = Path.Combine(directory, "output", "de", "Input.resources.dll");
            File.WriteAllBytes(conflict, [9]);
            Assert.False(ResourceSatelliteEmission.TryWrite(context, output, out var paths, out _));
            Assert.Empty(paths);
            Assert.False(Directory.Exists(Path.Combine(directory, "output", "fr")));
            File.Delete(conflict);
            Assert.True(ResourceSatelliteEmission.TryWrite(context, output, out paths, out var why), why);
            Assert.Equal(2, paths.Count);
            var hashes = paths.ToDictionary(path => path, Hash);
            Assert.True(ResourceSatelliteEmission.TryWrite(context, output, out _, out why), why);
            Assert.All(hashes, item => Assert.Equal(item.Value, Hash(item.Key)));
        });
    }

    private static string CopyFixture(string directory)
    {
        var fixture = CorpusRunner.LoadManifest(ManifestPath).Samples.Single(sample => sample.Id == "net48-resources");
        var source = Path.GetDirectoryName(Path.Combine(Samples, fixture.LocalName))!;
        foreach (var path in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
        {
            var destination = Path.Combine(directory, Path.GetRelativePath(source, path));
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            File.Copy(path, destination);
        }
        return Path.Combine(directory, "SatelliteProbe.exe");
    }

    private static void AssertCompanionPins(string source, string oracle, string framework)
    {
        using var provenance = JsonDocument.Parse(File.ReadAllText(Path.Combine(Checkout.Root, "corpus", "dotfuscator-7-satellite-resources.provenance.json")));
        var capture = provenance.RootElement.GetProperty("fixtures").EnumerateArray()
            .Single(fixture => fixture.GetProperty("Framework").GetString() == framework);
        var companions = capture.GetProperty("Companions").EnumerateArray().ToArray();
        Assert.Equal(4, companions.Length);
        foreach (var companion in companions)
        {
            var relative = companion.GetProperty("path").GetString()!;
            var root = relative.StartsWith("protected/", StringComparison.Ordinal) ? source : oracle;
            Assert.Equal(companion.GetProperty("sha256").GetString(), Hash(Path.Combine(root, relative[(relative.IndexOf('/') + 1)..])));
        }
    }

    private static string[] ResourceHashes(ModuleDef module) => module.Resources.OfType<EmbeddedResource>()
        .Select(resource => resource.Name + ":" + Convert.ToHexStringLower(SHA256.HashData(resource.CreateReader().ToArray()))).ToArray();
    private static string Hash(string path) => Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));
    private static void InTemporaryDirectory(Action<string> action)
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.DotfuscatorSatellite.").FullName;
        try { action(directory); } finally { Directory.Delete(directory, true); }
    }
}

public sealed class DotfuscatorResourceCorpusTheoryAttribute : TheoryAttribute
{
    public DotfuscatorResourceCorpusTheoryAttribute()
    {
        if (Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_RESOURCE_SAMPLES") is not { Length: > 0 })
            Skip = "Set CILANTRO_DOTFUSCATOR_RESOURCE_SAMPLES to the hash-pinned resource corpus directory.";
    }
}
