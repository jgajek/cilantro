using System.Security.Cryptography;
using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Corpus;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DotfuscatorResourceCorpusTests
{
    private static string Samples => Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_RESOURCE_SAMPLES")!;
    private static string ManifestPath => Path.Combine(Checkout.Root, "corpus", "dotfuscator-7-resources.manifest.json");

    [Fact]
    public void ResourceManifestPinsThreeFrameworksWithOracleParity()
    {
        var manifest = CorpusRunner.LoadManifest(ManifestPath);
        Assert.Equal(6, manifest.Samples.Count);
        Assert.Equal(3, manifest.Samples.Count(sample => sample.Tier == "oracle"));
        Assert.All(manifest.Samples.Where(sample => sample.Tier != "oracle"), sample => Assert.True(sample.RequireOracleResourceParity));
    }

    [DotfuscatorResourceCorpusFact]
    [Trait(Cost.Key, Cost.High)]
    public void CapturedResourcesRecoverInTheFullPipeline()
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.DotfuscatorResources.").FullName;
        try
        {
            var outcome = CorpusRunner.Run(ManifestPath, Samples, directory);
            Assert.True(outcome.Passed == 3 && outcome.Failed == 0 && outcome.Missing == 0,
                JsonSerializer.Serialize(outcome, CilantroPipeline.ReportJsonOptions));
            foreach (var sample in CorpusRunner.LoadManifest(ManifestPath).Samples.Where(sample => sample.Tier != "oracle"))
            {
                Assert.Contains(outcome.Samples.Single(entry => entry.Id == sample.Id).Passes,
                    pass => pass.Pass == "dotfuscator-resources" && pass.Status == PassStatus.Success && pass.Changes == 5);
                var output = Path.Combine(directory, sample.Id, "cleaned.bin");
                if (!sample.Id.StartsWith("net48", StringComparison.Ordinal)) continue;
                var difference = IlVerification.Against(IlVerification.Read(Path.Combine(Samples, sample.LocalName)), IlVerification.Read(output));
                Assert.Empty(difference.Broken.Except(difference.Was.Unreadable));
                Assert.Empty(difference.Worsened);
            }
        }
        finally { Directory.Delete(directory, true); }
    }

    [DotfuscatorResourceCorpusFact]
    public void AlteredRuntimeCodeIsNotBypassed()
    {
        Refuses(module =>
        {
            var manager = Assert.Single(DotfuscatorResourceShape.Find(module)).Manager;
            var method = manager.Methods.First(method => method.Name == "GetString");
            method.Body.Instructions.Insert(0, OpCodes.Nop.ToInstruction());
        });
    }

    [DotfuscatorResourceCorpusFact]
    public void MalformedResourceLeavesAllResourcesAndHooksIntact()
    {
        Refuses(module =>
        {
            var resource = module.Resources.OfType<EmbeddedResource>().Single(resource => resource.Name.String.EndsWith(".resources", StringComparison.Ordinal));
            module.Resources[module.Resources.IndexOf(resource)] = new EmbeddedResource(resource.Name, new byte[] { 1, 2, 3 }, resource.Attributes);
        });
    }

    private static void Refuses(Action<ModuleDefMD> modify)
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.DotfuscatorResourceRefusal.").FullName;
        try
        {
            var sample = CorpusRunner.LoadManifest(ManifestPath).Samples.Single(sample => sample.Id == "net48-resources");
            var path = Path.Combine(directory, "ResourceProbe.exe");
            using (var module = ModuleDefMD.Load(Path.Combine(Samples, sample.LocalName))) { modify(module); module.Write(path); }
            using var context = ArtifactContext.Load(path);
            var methods = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody)
                .ToDictionary(method => method, MethodBodySnapshot.Capture);
            var resources = context.Module.Resources.OfType<EmbeddedResource>().ToDictionary(resource => resource.Name.String,
                resource => SHA256.HashData(resource.CreateReader().ToArray()));
            new DotfuscatorDetectionPass().Run(context);
            var result = new DotfuscatorResourcePass().Run(context);
            Assert.Equal(PassStatus.Unsupported, result.Status);
            Assert.Equal(0, result.Changes);
            Assert.All(methods, entry => Assert.True(entry.Value.StructurallyEquals(entry.Key)));
            Assert.All(context.Module.Resources.OfType<EmbeddedResource>(), resource =>
                Assert.Equal(resources[resource.Name], SHA256.HashData(resource.CreateReader().ToArray())));
        }
        finally { Directory.Delete(directory, true); }
    }
}

public sealed class DotfuscatorResourceCorpusFactAttribute : FactAttribute
{
    public DotfuscatorResourceCorpusFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_RESOURCE_SAMPLES") is not { Length: > 0 })
            Skip = "Set CILANTRO_DOTFUSCATOR_RESOURCE_SAMPLES to the hash-pinned resource corpus directory.";
    }
}
