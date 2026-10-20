using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Corpus;

namespace Cilantro.Tests;

public sealed class BabelPasswordCorpusTests
{
    private static string Manifest => Path.Combine(Checkout.Root, "corpus", "babel-12-password.manifest.json");

    [Fact]
    public void ManifestRequiresRecoveredBodiesAndNoRemainingEncryptedStubs()
    {
        var samples = CorpusRunner.LoadManifest(Manifest).Samples;
        Assert.Equal(6, samples.Count); Assert.Equal(3, samples.Count(s => s.Tier == "oracle"));
        Assert.All(samples.Where(s => s.Tier == "profiled"), sample =>
        {
            Assert.Equal(1, sample.ExpectedRestoredBodyCount);
            Assert.Equal(0, sample.MaximumRemainingStubs);
            Assert.Equal(0, sample.MaximumRemainingSwitchDispatchers);
            Assert.Equal(0, sample.MaximumUnreachableInstructions);
        });
    }

    [Babel12CorpusFact]
    [Trait(Cost.Key, Cost.High)]
    public void PasswordProtectedMethodImagesRecoverWithoutNewVerifierFindings()
    {
        var root = Environment.GetEnvironmentVariable("CILANTRO_BABEL12_SAMPLES")!;
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelPassword.").FullName;
        try
        {
            var outcome = CorpusRunner.Run(Manifest, root, directory);
            Assert.True(outcome.Passed == 3 && outcome.Failed == 0 && outcome.Missing == 0,
                JsonSerializer.Serialize(outcome.Samples.Where(s => s.Status != "passed"), CilantroPipeline.ReportJsonOptions));
            var sample = CorpusRunner.LoadManifest(Manifest).Samples.Single(s => s.Id == "net48-password");
            var difference = IlVerification.Against(IlVerification.Read(Path.Combine(root, sample.LocalName)),
                IlVerification.Read(Path.Combine(directory, sample.Id, "cleaned.bin")));
            Assert.Empty(difference.Broken.Except(difference.Was.Unreadable));
            Assert.Empty(difference.Worsened); Assert.Empty(difference.Is.Unreadable);
        }
        finally { Directory.Delete(directory, true); }
    }
}
