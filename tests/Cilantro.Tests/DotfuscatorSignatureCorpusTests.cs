using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Corpus;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DotfuscatorSignatureCorpusTests
{
    private static string Manifest => Path.Combine(Checkout.Root, "corpus", "dotfuscator-7-signatures.manifest.json");

    [Fact]
    public void ManifestPinsSignatureControlsAndRenamedInteractions()
    {
        var manifest = CorpusRunner.LoadManifest(Manifest);
        Assert.Equal(9, manifest.Samples.Count);
        Assert.Equal(3, manifest.Samples.Count(sample => sample.Tier == "oracle"));
        Assert.Equal(3, manifest.Samples.Count(sample => sample.MinimumRecoveredStringSites == 17));
        Assert.Equal(19, manifest.Samples.Single(sample => sample.Id == "net48-all-signatures").MinimumRecoveredStringSites);
        Assert.Equal(2, manifest.Samples.Count(sample => sample.MinimumRecoveredStringSites == 20));
    }

    [DotfuscatorV2CorpusFact]
    public void SignatureCorpusRecoversAllSitesAndRetiresTheNativeBridge()
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.DotfuscatorSignatures.").FullName;
        try
        {
            var samples = Environment.GetEnvironmentVariable("CILANTRO_DOTFUSCATOR_V2_SAMPLES")!;
            var outcome = CorpusRunner.Run(Manifest, samples, directory);
            Assert.True(outcome.Passed == 6 && outcome.Failed == 0 && outcome.Missing == 0,
                JsonSerializer.Serialize(outcome.Samples.Where(sample => sample.Status != "passed"), CilantroPipeline.ReportJsonOptions));
            var manifest = CorpusRunner.LoadManifest(Manifest);
            foreach (var sample in manifest.Samples.Where(sample => sample.Tier != "oracle"))
            {
                var input = Path.Combine(samples, sample.LocalName);
                var output = Path.Combine(directory, sample.Id, "cleaned.bin");
                using var original = ModuleDefMD.Load(input);
                using var cleaned = ModuleDefMD.Load(output);
                Assert.DoesNotContain(cleaned.GetTypes(), type => type.FullName == "PreEmptive.Protection.Runtime.Native.NativeCPP");
                using var oracle = ModuleDefMD.Load(Path.Combine(samples, manifest.Samples.Single(entry => entry.Sha256 == sample.OracleSha256).LocalName));
                var missing = Literals(oracle).Except(Literals(cleaned)).Order(StringComparer.Ordinal).ToArray();
                if (sample.Id.EndsWith("all-signatures", StringComparison.Ordinal))
                {
                    var expected = sample.Id.StartsWith("net48-", StringComparison.Ordinal)
                        ? new[] { "SIG_MATRIX", "SIG_POINTER" }
                        : new[] { "SIG_FUNCTION_POINTER", "SIG_MATRIX", "SIG_POINTER" };
                    Assert.Equal(expected, missing);
                }
                else Assert.Empty(missing);
                if (sample.Id.StartsWith("net48-", StringComparison.Ordinal))
                {
                    var difference = IlVerification.Against(IlVerification.Read(input), IlVerification.Read(output));
                    Assert.Empty(difference.Broken.Except(difference.Was.Unreadable)); Assert.Empty(difference.Worsened);
                }
            }
        }
        finally { Directory.Delete(directory, true); }
    }

    private static HashSet<string> Literals(ModuleDef module) => module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody)
        .SelectMany(method => method.Body.Instructions).Where(instruction => instruction.OpCode.Code == Code.Ldstr)
        .Select(instruction => (string)instruction.Operand).ToHashSet(StringComparer.Ordinal);
}
