using System.Security.Cryptography;
using dnlib.DotNet;
using Cilantro.Core;

namespace Cilantro.Tests;

/// <summary>Strict completion refusal preserves the payload bytes recovered from pinned samples.</summary>
/// <remarks>CorpusTests separately verifies ordinary emission and deterministic corpus outcomes.</remarks>
public sealed class PipelineTests
{
    public static TheoryData<string, string, string, int, string, int> Samples => new()
    {
        {
            "embedded_dotnet_Mlfhntkcvb.exe",
            "ad0c3182b18b5d7ba8771d830f4d51b4ada7e26f8d05223f4379e6312aba65fa",
            "7fa1a9d74dad14fd686ad7b2e794111d1093de3fefe97c51d1908e44586d04de",
            485376,
            "81cf796c987dbffeb950e38d7e4bc01e85bec2ef4b5a9750d9642843f8460c2a",
            858112
        },
        {
            "embedded_dotnet_Qafcakg.exe",
            "c405398fc582e33bbbd37222b7360a6cfdc526146622141503de1ccf9de6174a",
            "1db4e9c40d83bb790b89963888fd9a112b1d2467f7194dc55b6c35e14e443429",
            86528,
            "e4e746f968a3ec89027484ab233d3d38c7778458a898d30f31bb74a2c97059d2",
            154112
        }
    };

    [SampleTheory]
    [Trait(Cost.Key, Cost.High)]
    [MemberData(nameof(Samples))]
    public void FailOnPartialPreservesPayloadsAndRefusesIncompleteStartup(
        string filename,
        string expectedHash,
        string expectedPayloadHash,
        int expectedPayloadLength,
        string expectedFinalHash,
        int expectedFinalLength)
    {
        var sample = FindSample(filename);
        var reportDirectory = CreateTemporaryDirectory();
        var output = Path.Combine(reportDirectory, "cleaned.exe");

        try
        {
            // Isolate strict completion refusal from naming and VM reconstruction.
            var result = new CilantroPipeline().Run(sample, new PipelineOptions(
                OutputPath: output,
                ReportDirectory: reportDirectory,
                RenameSymbols: false,
                Devirtualize: false,
                FailOnPartial: true));

            // Both payload identities are recoverable, but a later reflective startup operation
            // is unsupported. The strict completion policy must not emit a cleaned application.
            Assert.False(result.Success);
            Assert.Null(result.OutputPath);
            Assert.False(File.Exists(output));
            Assert.Equal(expectedHash, result.Report.InputSha256);
            Assert.True(result.Report.VerificationPassed);
            var partial = Assert.Single(result.Report.Passes,
                pass => pass.Status != PassStatus.Success);
            Assert.Equal("payload-extraction", partial.Pass);
            Assert.Equal(PassStatus.Partial, partial.Status);
            Assert.Contains(partial.Diagnostics,
                diagnostic => diagnostic.Contains("Assembly operation GetType is denied", StringComparison.Ordinal));
            Assert.Equal(6, result.Report.ResourceCount);
            Assert.Equal(356, result.Report.Recovery.DispatcherMethodsRestored);
            Assert.Equal(357, result.Report.Recovery.DispatcherMethodCandidates);
            Assert.Equal(2643, result.Report.Recovery.ProxyCallsRestored);
            Assert.Equal(23, result.Report.Recovery.ReplacedStringSites);
            Assert.Equal(2, result.Report.Payloads.Count);
            var payload = Assert.Single(result.Report.Payloads,
                item => item.PayloadSha256 == expectedPayloadHash);
            Assert.Equal(expectedPayloadHash, payload.PayloadSha256);
            Assert.Equal(expectedPayloadLength, payload.PayloadLength);
            var finalPayload = Assert.Single(result.Report.Payloads,
                item => item.PayloadSha256 == expectedFinalHash);
            Assert.Equal(expectedFinalLength, finalPayload.PayloadLength);
            Assert.Equal(2, result.ExtractedPayloadPaths.Count);
            Assert.All(result.ExtractedPayloadPaths, path => Assert.True(File.Exists(path)));
            var payloadPath = Assert.Single(result.ExtractedPayloadPaths,
                path => path == payload.WrittenTo);
            using (var payloadModule = ModuleDefMD.Load(payloadPath))
            {
                Assert.Null(payloadModule.EntryPoint);
                Assert.NotEmpty(payloadModule.Resources);
            }
            Assert.True(File.Exists(result.AnalysisReportPath));
            Assert.True(File.Exists(result.ChangesReportPath));
            // Hash the actual extracted files as well as checking the report's inventory.
            Assert.Equal(expectedPayloadHash, Convert.ToHexStringLower(
                SHA256.HashData(File.ReadAllBytes(payloadPath))));
            Assert.Equal(expectedFinalHash, Convert.ToHexStringLower(
                SHA256.HashData(File.ReadAllBytes(finalPayload.WrittenTo!))));
        }
        finally
        {
            Directory.Delete(reportDirectory, true);
        }
    }

    [SampleFact]
    public void ProxyCodecDecodesAndValidatesAllRecords()
    {
        var sample = FindSample("embedded_dotnet_Mlfhntkcvb.exe");
        var inputHash = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(sample)));
        Assert.True(ProxyResourceCodec.TryGetProfile(inputHash, out var profile));

        using var module = ModuleDefMD.Load(sample);
        var resource = module.Resources
            .OfType<EmbeddedResource>()
            .Single(item =>
                Convert.ToHexStringLower(SHA256.HashData(item.CreateReader().ToArray())) ==
                profile.ResourceSha256);
        var decoded = ProxyResourceCodec.Decode(resource.CreateReader().ToArray(), profile);
        var bindings = ProxyResourceCodec.Parse(decoded);

        Assert.Equal(profile.DecodedSha256, Convert.ToHexStringLower(SHA256.HashData(decoded)));
        Assert.Equal(279, bindings.Count);
        Assert.Equal(279, bindings.Select(binding => binding.FieldToken).Distinct().Count());
        Assert.Equal(172, bindings.Count(binding => binding.CallVirtual));
        Assert.All(bindings, binding => Assert.NotNull(module.ResolveToken(binding.TargetToken)));
    }

    [Fact]
    public void ResourceTransformsRoundTripAndEnforceLimits()
    {
        var plaintext = "reactor-resource-fixture"u8.ToArray();
        var key = SHA256.HashData("key"u8);
        var iv = SHA256.HashData("iv"u8)[..16];
        using var aes = Aes.Create();
        aes.Key = key;
        var encrypted = aes.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);

        Assert.Equal(plaintext, ResourceTransforms.AesCbcDecrypt(encrypted, key, iv));
        Assert.Equal(plaintext, ResourceTransforms.Xor(
            ResourceTransforms.Xor(plaintext, "xor"u8),
            "xor"u8));
        Assert.Equal(0, Entropy.Calculate([]));
        Assert.Equal(0, Entropy.Calculate(new byte[32]));
    }

    private static string FindSample(string filename) => Checkout.Sample(filename);

    private static string CreateTemporaryDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), $"Cilantro.Tests.{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }
}
