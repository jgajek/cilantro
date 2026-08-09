using System.Security.Cryptography;
using dnlib.DotNet;
using ReactorUnpack.Core;

namespace ReactorUnpack.Tests;

public sealed class PipelineTests
{
    public static TheoryData<string, string> Samples => new()
    {
        {
            "embedded_dotnet_Mlfhntkcvb.exe",
            "ad0c3182b18b5d7ba8771d830f4d51b4ada7e26f8d05223f4379e6312aba65fa"
        },
        {
            "embedded_dotnet_Qafcakg.exe",
            "c405398fc582e33bbbd37222b7360a6cfdc526146622141503de1ccf9de6174a"
        }
    };

    [Theory]
    [MemberData(nameof(Samples))]
    public void PipelineRecoversProfiledSamples(string filename, string expectedHash)
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
            Assert.Equal(374, result.Report.TypeCount);
            Assert.Equal(2126, result.Report.MethodCount);
            Assert.All(result.Report.Passes, pass => Assert.Equal(PassStatus.Success, pass.Status));
            Assert.Equal(1341, Pass(result, "cfg-dead-code").Changes);
            Assert.Equal(2643, Pass(result, "delegate-proxy-analysis").Changes);
            Assert.Equal(2, Pass(result, "string-recovery").Changes);
            Assert.True(File.Exists(result.AnalysisReportPath));
            Assert.True(File.Exists(result.ChangesReportPath));
            Assert.True(File.Exists(output));

            using var original = ModuleDefMD.Load(sample);
            using var cleaned = ModuleDefMD.Load(output);
            Assert.Equal(original.EntryPoint?.MDToken, cleaned.EntryPoint?.MDToken);
            Assert.Equal(original.GetTypes().Count(), cleaned.GetTypes().Count());
        }
        finally
        {
            Directory.Delete(reportDirectory, true);
        }
    }

    [Theory]
    [MemberData(nameof(Samples))]
    public void EmissionIsDeterministic(string filename, string _)
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
        }
        finally
        {
            Directory.Delete(firstDirectory, true);
            Directory.Delete(secondDirectory, true);
        }
    }

    [Fact]
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

    private static string FindSample(string filename)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "samples", filename);
            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new FileNotFoundException($"Could not locate test sample {filename}.");
    }

    private static string CreateTemporaryDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), $"ReactorUnpack.Tests.{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }
}
