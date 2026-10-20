using System.Security.Cryptography;
using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Corpus;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class DotfuscatorResourceContractTests
{
    private static readonly string[] Cultures = ["fr", "fr-CA"];
    private static string ManifestPath => Path.Combine(Checkout.Root, "corpus", "dotfuscator-7-resource-contracts.manifest.json");
    private static string Samples => Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_RESOURCE_SAMPLES")!;

    [Theory]
    [InlineData("1.0.0.0", "1.0.0.0")]
    [InlineData("1.2", "1.2.0.0")]
    [InlineData("1.2.3", "1.2.3.0")]
    [InlineData("65535.65535.65535.65535", "65535.65535.65535.65535")]
    public void ContractVersionComesFromTheFrameworkAttribute(string text, string expected)
    {
        using var module = Fixture();
        AddContract(module, text);
        Assert.Equal(new Version(expected), DotfuscatorResourceSatellites.ContractVersion(module.Assembly));
        Assert.Equal(new Version(2, 0, 0, 0), module.Assembly.Version);
    }

    [Fact]
    public void AnAbsentContractUsesTheOwnerVersion()
    {
        using var module = Fixture();
        Assert.Equal(module.Assembly.Version, DotfuscatorResourceSatellites.ContractVersion(module.Assembly));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("bad")]
    [InlineData("-1.0")]
    [InlineData("1.0.0.0.0")]
    [InlineData("65536.0.0.0")]
    public void InvalidVersionValuesDecline(string? text)
    {
        using var module = Fixture();
        AddContract(module, text);
        Assert.Throws<InvalidDataException>(() => DotfuscatorResourceSatellites.ContractVersion(module.Assembly));
    }

    [Theory]
    [InlineData("foreign")]
    [InlineData("unsigned")]
    [InlineData("culture")]
    [InlineData("static")]
    [InlineData("varargs")]
    [InlineData("argument")]
    [InlineData("duplicate")]
    public void UnreviewedContractIdentityOrSignatureDeclines(string change)
    {
        using var module = Fixture();
        var attribute = AddContract(module, "1.0.0.0");
        var constructor = Assert.IsType<MemberRefUser>(attribute.Constructor);
        switch (change)
        {
            case "foreign": constructor.Class = new TypeRefUser(module, "System.Resources", "SatelliteContractVersionAttribute", new AssemblyRefUser("Foreign.Framework")); break;
            case "unsigned": constructor.Class = new TypeRefUser(module, "System.Resources", "SatelliteContractVersionAttribute", new AssemblyRefUser("mscorlib")); break;
            case "culture":
                var scope = new AssemblyRefUser("mscorlib", new Version(4, 0, 0, 0), new PublicKeyToken("b77a5c561934e089"), "fr");
                constructor.Class = new TypeRefUser(module, "System.Resources", "SatelliteContractVersionAttribute", scope);
                break;
            case "static": constructor.MethodSig = MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.String); break;
            case "varargs": constructor.MethodSig.CallingConvention |= CallingConvention.VarArg; break;
            case "argument": constructor.MethodSig = MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Int32); break;
            case "duplicate": module.Assembly.CustomAttributes.Add(attribute); break;
        }
        Assert.Throws<InvalidDataException>(() => DotfuscatorResourceSatellites.ContractVersion(module.Assembly));
    }

    [Fact]
    public void ManifestPinsBothLayoutsOnThreeFrameworks()
    {
        var samples = CorpusRunner.LoadManifest(ManifestPath).Samples;
        Assert.Equal(12, samples.Count);
        Assert.Equal(6, samples.Count(sample => sample.Tier == "oracle"));
        Assert.All(samples.Where(sample => sample.Tier != "oracle"), sample =>
        {
            Assert.True(sample.RequireOracleResourceParity);
            Assert.Equal(sample.Id.EndsWith("-satellite-only", StringComparison.Ordinal) ? 2 : 3, sample.MinimumResourcesRestored);
        });
    }

    [DotfuscatorResourceCorpusFact]
    [Trait(Cost.Key, Cost.High)]
    public void VersionedAndSatelliteOnlyCapturesRecoverAndPreserveFallbackMetadata()
    {
        Temporary(directory =>
        {
            var manifest = CorpusRunner.LoadManifest(ManifestPath);
            AssertCompanionPins(manifest);
            var outcome = CorpusRunner.Run(ManifestPath, Samples, directory);
            Assert.True(outcome.Passed == 6 && outcome.Failed == 0 && outcome.Missing == 0,
                JsonSerializer.Serialize(outcome, CilantroPipeline.ReportJsonOptions));
            foreach (var sample in manifest.Samples.Where(sample => sample.Tier != "oracle"))
            {
                var satelliteOnly = sample.Id.EndsWith("-satellite-only", StringComparison.Ordinal);
                var entry = outcome.Samples.Single(entry => entry.Id == sample.Id);
                Assert.Contains(entry.Passes, pass => pass.Pass == "dotfuscator-resources" && pass.Status == PassStatus.Success && pass.Changes == (satelliteOnly ? 10 : 15));
                var oracle = Path.Combine(Samples, manifest.Samples.Single(oracle => oracle.Sha256 == sample.OracleSha256).LocalName);
                var output = Path.Combine(directory, sample.Id, "cleaned.bin");
                using var original = ModuleDefMD.Load(oracle);
                using var restored = ModuleDefMD.Load(output);
                Assert.Equal(original.Assembly.FullName, restored.Assembly.FullName);
                Assert.Equal(satelliteOnly ? 0 : 1, restored.Resources.Count);
                Assert.Equal(ResourceHashes(original), ResourceHashes(restored));
                Assert.Equal(new Version(1, 0, 0, 0), DotfuscatorResourceSatellites.ContractVersion(restored.Assembly));
                Assert.Equal(satelliteOnly ? "fr" : null, DotfuscatorResourceSatellites.RequiredNeutralSatellite(restored.Assembly));
                Assert.DoesNotContain(restored.GetTypes(), type => type.Name.String is "CRManager" or "DRReader");
                foreach (var culture in Cultures)
                {
                    using var sourceCulture = ModuleDefMD.Load(Path.Combine(Path.GetDirectoryName(oracle)!, culture, "ContractProbe.resources.dll"));
                    using var restoredCulture = ModuleDefMD.Load(Path.Combine(directory, sample.Id, culture, "ContractProbe.resources.dll"));
                    Assert.Equal(sourceCulture.Assembly.FullName, restoredCulture.Assembly.FullName);
                    Assert.Equal(new Version(1, 0, 0, 0), restoredCulture.Assembly.Version);
                    Assert.Equal(ResourceHashes(sourceCulture), ResourceHashes(restoredCulture));
                }
                if (!sample.Id.StartsWith("net48", StringComparison.Ordinal)) continue;
                var difference = IlVerification.Against(IlVerification.Read(Path.Combine(Samples, sample.LocalName)), IlVerification.Read(output));
                Assert.Empty(difference.Broken.Except(difference.Was.Unreadable));
                Assert.Empty(difference.Worsened);
            }
        });
    }

    [DotfuscatorResourceCorpusTheory]
    [InlineData("missing-neutral")]
    [InlineData("wrong-version")]
    [InlineData("invalid-contract")]
    [InlineData("duplicate-contract")]
    [InlineData("fallback-location")]
    [InlineData("duplicate-neutral")]
    [InlineData("foreign-neutral")]
    [InlineData("invalid-culture")]
    public void UnavailableOrInvalidContractDeclinesBeforeChangingResourcesOrHooks(string change)
    {
        Temporary(directory =>
        {
            var sample = CorpusRunner.LoadManifest(ManifestPath).Samples.Single(sample => sample.Id == "net48-satellite-only");
            var source = Path.GetDirectoryName(Path.Combine(Samples, sample.LocalName))!;
            foreach (var file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
            {
                var destination = Path.Combine(directory, Path.GetRelativePath(source, file));
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!); File.Copy(file, destination);
            }
            var input = Path.Combine(directory, "ContractProbe.exe");
            if (change == "missing-neutral") File.Delete(Path.Combine(directory, "fr", "ContractProbe.resources.dll"));
            else if (change == "wrong-version") Rewrite(Path.Combine(directory, "fr", "ContractProbe.resources.dll"), module => module.Assembly.Version = new Version(2, 0, 0, 0));
            else Rewrite(input, module =>
            {
                var contract = module.Assembly.CustomAttributes.Single(attribute => attribute.TypeFullName == "System.Resources.SatelliteContractVersionAttribute");
                if (change == "invalid-contract") contract.ConstructorArguments[0] = new CAArgument(module.CorLibTypes.String, new UTF8String("invalid"));
                else if (change == "duplicate-contract") module.Assembly.CustomAttributes.Add(contract);
                else
                {
                    var neutral = module.Assembly.CustomAttributes.Single(attribute => attribute.TypeFullName == "System.Resources.NeutralResourcesLanguageAttribute");
                    if (change == "duplicate-neutral") module.Assembly.CustomAttributes.Add(neutral);
                    else if (change == "foreign-neutral")
                        Assert.IsAssignableFrom<MemberRef>(neutral.Constructor).Class = new TypeRefUser(module, "System.Resources", "NeutralResourcesLanguageAttribute", new AssemblyRefUser("Foreign.Framework"));
                    else if (change == "invalid-culture") neutral.ConstructorArguments[0] = new CAArgument(module.CorLibTypes.String, new UTF8String("fr/../"));
                    else neutral.ConstructorArguments[1] = new CAArgument(neutral.ConstructorArguments[1].Type, 99);
                }
            });
            using var context = ArtifactContext.Load(input);
            var resources = ResourceHashes(context.Module);
            var methods = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody).ToDictionary(method => method, MethodBodySnapshot.Capture);
            new DotfuscatorDetectionPass().Run(context);
            var result = new DotfuscatorResourcePass().Run(context);
            Assert.Equal(PassStatus.Unsupported, result.Status);
            Assert.Equal(0, result.Changes);
            Assert.Equal(resources, ResourceHashes(context.Module));
            Assert.All(methods, item => Assert.True(item.Value.StructurallyEquals(item.Key)));
        });
    }

    private static ModuleDefUser Fixture()
    {
        var module = new ModuleDefUser("Contract.dll");
        new AssemblyDefUser("Contract", new Version(2, 0, 0, 0)).Modules.Add(module);
        return module;
    }
    private static CustomAttribute AddContract(ModuleDef module, string? text)
    {
        var attribute = new CustomAttribute(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String),
            new TypeRefUser(module, "System.Resources", "SatelliteContractVersionAttribute", module.CorLibTypes.AssemblyRef)));
        attribute.ConstructorArguments.Add(new CAArgument(module.CorLibTypes.String, text is null ? null : new UTF8String(text)));
        module.Assembly.CustomAttributes.Add(attribute); return attribute;
    }
    private static void AssertCompanionPins(CorpusManifest manifest)
    {
        using var proof = JsonDocument.Parse(File.ReadAllText(Path.Combine(Checkout.Root, "corpus", "dotfuscator-7-resource-contracts.provenance.json")));
        var fixtures = proof.RootElement.GetProperty("fixtures").EnumerateArray().ToArray();
        Assert.Equal(6, fixtures.Length);
        foreach (var fixture in fixtures)
        {
            var id = fixture.GetProperty("Framework").GetString() + "-" + fixture.GetProperty("Layout").GetString();
            var protectedRoot = Path.GetDirectoryName(Path.Combine(Samples, manifest.Samples.Single(sample => sample.Id == id).LocalName))!;
            var oracleRoot = Path.GetDirectoryName(Path.Combine(Samples, manifest.Samples.Single(sample => sample.Id == id + "-oracle").LocalName))!;
            var companions = fixture.GetProperty("Companions").EnumerateArray().ToArray();
            Assert.Equal(4, companions.Length);
            foreach (var companion in companions)
            {
                var relative = companion.GetProperty("path").GetString()!;
                var root = relative.StartsWith("oracle/", StringComparison.Ordinal) ? oracleRoot : protectedRoot;
                Assert.Equal(companion.GetProperty("sha256").GetString(), Hash(File.ReadAllBytes(Path.Combine(root, relative[(relative.IndexOf('/') + 1)..]))));
            }
        }
    }
    private static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    private static string[] ResourceHashes(ModuleDef module) => module.Resources.OfType<EmbeddedResource>().Select(resource => resource.Name + ":" + Hash(resource.CreateReader().ToArray())).ToArray();
    private static void Rewrite(string path, Action<ModuleDefMD> change)
    {
        byte[] bytes;
        using (var module = ModuleDefMD.Load(path)) { change(module); using var output = new MemoryStream(); module.Write(output); bytes = output.ToArray(); }
        File.WriteAllBytes(path, bytes);
    }
    private static void Temporary(Action<string> action)
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.ResourceContracts.").FullName;
        try { action(directory); } finally { Directory.Delete(directory, true); }
    }
}
