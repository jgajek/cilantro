using System.Security.Cryptography;
using dnlib.DotNet;
using ReactorUnpack.Core;

namespace ReactorUnpack.Tests;

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
    [MemberData(nameof(Samples))]
    public void PipelineRecoversProfiledSamples(
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
            var result = new ReactorPipeline().Run(sample, new PipelineOptions(
                OutputPath: output,
                ReportDirectory: reportDirectory,
                FailOnPartial: true));

            Assert.True(result.Success);
            Assert.Equal(expectedHash, result.Report.InputSha256);
            Assert.True(result.Report.VerificationPassed);
            Assert.Equal(4, result.Report.ResourceCount);
            // Down from the 374 types and 2126 methods the input carries: what remains is the
            // program plus whatever recovery could not attribute to the protector.
            Assert.Equal(115, result.Report.TypeCount);
            Assert.Equal(1057, result.Report.MethodCount);
            Assert.All(result.Report.Passes, pass => Assert.Equal(PassStatus.Success, pass.Status));
            Assert.Equal(1341, Pass(result, "cfg-dead-code").Changes);
            // Proxy restoration reaches every validated site because it runs before forwarder
            // redirection, which then finds little left to redirect beyond the wrappers that hide a
            // framework call behind an object-typed signature.
            Assert.Equal(2643, Pass(result, "delegate-proxy-analysis").Changes);
            Assert.Equal(16, Pass(result, "method-inlining").Changes);
            Assert.Equal(2, Pass(result, "string-recovery").Changes);
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
                path => Path.GetFileNameWithoutExtension(path) == payload.AssemblyName);
            using (var payloadModule = ModuleDefMD.Load(payloadPath))
            {
                Assert.Null(payloadModule.EntryPoint);
                Assert.NotEmpty(payloadModule.Resources);
            }
            Assert.True(File.Exists(result.AnalysisReportPath));
            Assert.True(File.Exists(result.ChangesReportPath));
            Assert.True(File.Exists(output));

            using var original = ModuleDefMD.Load(sample);
            using var cleaned = ModuleDefMD.Load(output);
            // Deleting rows makes the writer renumber, so identity is by name rather than by token.
            Assert.Equal(original.EntryPoint?.FullName, cleaned.EntryPoint?.FullName);

            // Everything cleanup removed is gone, and nothing else is.
            var survivors = cleaned.GetTypes().Select(type => type.FullName).ToHashSet(StringComparer.Ordinal);
            var removed = original.GetTypes()
                .Select(type => type.FullName)
                .Where(name => !survivors.Contains(name))
                .ToArray();
            Assert.Equal(original.GetTypes().Count() - cleaned.GetTypes().Count(), removed.Length);
            Assert.Equal(259, removed.Length);
        }
        finally
        {
            Directory.Delete(reportDirectory, true);
        }
    }

    [SampleTheory]
    [MemberData(nameof(Samples))]
    public void EmissionIsDeterministic(
        string filename,
        string _,
        string expectedPayloadHash,
        int expectedPayloadLength,
        string expectedFinalHash,
        int expectedFinalLength)
    {
        var sample = FindSample(filename);
        var firstDirectory = CreateTemporaryDirectory();
        var secondDirectory = CreateTemporaryDirectory();
        var first = Path.Combine(firstDirectory, "cleaned.exe");
        var second = Path.Combine(secondDirectory, "cleaned.exe");

        try
        {
            var pipeline = new ReactorPipeline();
            pipeline.Run(sample, new PipelineOptions(OutputPath: first, ReportDirectory: firstDirectory));
            pipeline.Run(sample, new PipelineOptions(OutputPath: second, ReportDirectory: secondDirectory));

            Assert.Equal(
                SHA256.HashData(File.ReadAllBytes(first)),
                SHA256.HashData(File.ReadAllBytes(second)));
            var firstPayloads = Directory.GetFiles(
                Path.Combine(firstDirectory, $"{Path.GetFileNameWithoutExtension(filename)}.payloads"));
            var secondPayloads = Directory.GetFiles(
                Path.Combine(secondDirectory, $"{Path.GetFileNameWithoutExtension(filename)}.payloads"));
            Assert.Equal(2, firstPayloads.Length);
            Assert.Equal(2, secondPayloads.Length);
            AssertPayload(firstPayloads, expectedPayloadHash, expectedPayloadLength);
            AssertPayload(firstPayloads, expectedFinalHash, expectedFinalLength);
            Assert.Equal(
                firstPayloads.Order().Select(File.ReadAllBytes).Select(SHA256.HashData),
                secondPayloads.Order().Select(File.ReadAllBytes).Select(SHA256.HashData));
        }
        finally
        {
            Directory.Delete(firstDirectory, true);
            Directory.Delete(secondDirectory, true);
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

    private static PassResult Pass(PipelineResult result, string name) =>
        Assert.Single(result.Report.Passes, pass => pass.Pass == name);

    private static void AssertPayload(IEnumerable<string> paths, string expectedHash, int expectedLength)
    {
        var path = Assert.Single(paths, candidate =>
            Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(candidate))) == expectedHash);
        Assert.Equal(expectedLength, new FileInfo(path).Length);
    }

    private static string FindSample(string filename) => Checkout.Sample(filename);

    private static string CreateTemporaryDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), $"ReactorUnpack.Tests.{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }
}
