using System.Security.Cryptography;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Native;

namespace Cilantro.Tests;

public sealed class NativeBootstrapTests
{
    private const string Stub = "WindowsManagement.exe";

    /// <summary>
    /// The assembly inside the stub, which is in the corpus in its own right. Recovering it byte for
    /// byte is what makes this reader checkable at all: the answer was known before the reader
    /// existed, so a table built slightly wrong cannot pass by producing something plausible.
    /// </summary>
    private const string InnerAssemblySha256 =
        "83ba5d833eba38f578eb8478f8961a0bddb63ff35016b40d8e0536b164ee1ed3";

    [SampleFact]
    public void TheAssemblyInsideANativeBootstrapComesOutByteForByte()
    {
        var bytes = File.ReadAllBytes(Checkout.Sample(Stub));

        Assert.True(NativeBootstrap.TryUnpack(bytes, out var findings, out var reason), reason);
        Assert.NotNull(findings);
        Assert.Equal(InnerAssemblySha256, Sha256(findings.Assembly));
    }

    [SampleFact]
    public void ItSaysWhereTheKeyCameFromAndWhatItWentThrough()
    {
        var bytes = File.ReadAllBytes(Checkout.Sample(Stub));

        Assert.True(NativeBootstrap.TryUnpack(bytes, out var findings, out _));
        Assert.NotNull(findings);
        // The route matters as much as the bytes: this sample keeps its assembly one layer further
        // in, behind a loader, and a report that did not say so would describe the wrong file.
        Assert.True(findings.CameFromLoader);
        Assert.Equal("v4.0.30319", findings.ClrVersion);
        Assert.Equal("10/__/0", findings.Resource);
        Assert.Equal(6 * 2, findings.KeyBytes.Length);
        Assert.True(findings.KeyFileOffset > 0);
        Assert.True(findings.InflatedLength > findings.EncryptedLength);
    }

    [SampleFact]
    public void ANativeBootstrapIsRecognisedAndAnOrdinaryManagedAssemblyIsNot()
    {
        Assert.True(NativeBootstrap.Looks(File.ReadAllBytes(Checkout.Sample(Stub))));
        Assert.False(NativeBootstrap.Looks(File.ReadAllBytes(Checkout.Sample("Qbjuef.exe"))));
    }

    [Fact]
    public void SomethingThatIsNotAPeImageIsNotMistakenForABootstrap()
    {
        Assert.False(NativeBootstrap.Looks("This is not a PE image at all."u8));
        Assert.False(NativeBootstrap.TryUnpack("MZ but nothing else"u8, out _, out var reason));
        Assert.Contains("not a PE image", reason, StringComparison.Ordinal);
    }

    [SampleFact]
    public void AManagedImageIsTurnedAwayAsManagedRatherThanTriedAndFailed()
    {
        var bytes = File.ReadAllBytes(Checkout.Sample("Qbjuef.exe"));

        Assert.False(NativeBootstrap.TryUnpack(bytes, out _, out var reason));
        Assert.Contains("CLR header", reason, StringComparison.Ordinal);
    }

    [SampleFact]
    public void APayloadResourceThatHasBeenTamperedWithIsRefusedRatherThanGuessedAt()
    {
        // One flipped byte in the encrypted resource. The substitution carries no integrity check of
        // its own, so what has to catch this is the declared length and the inflate behind it —
        // which is exactly the check that would otherwise let a wrong key write a wrong assembly.
        var bytes = File.ReadAllBytes(Checkout.Sample(Stub));
        var payload = Locate(bytes);
        bytes[payload] ^= 0xFF;

        Assert.False(NativeBootstrap.TryUnpack(bytes, out var findings, out var reason));
        Assert.Null(findings);
        Assert.NotEmpty(reason);
    }

    [SampleFact]
    public void AStubWhoseDecryptRoutineIsGoneSaysThatIsWhatIsMissing()
    {
        var bytes = File.ReadAllBytes(Checkout.Sample(Stub));

        Assert.True(NativeBootstrap.TryUnpack(bytes, out var findings, out _));
        Assert.NotNull(findings);
        // Break the matched head of the routine the successful run just named.
        bytes[findings.KeyFileOffset] ^= 0xFF;

        Assert.False(NativeBootstrap.TryUnpack(bytes, out _, out var reason));
        Assert.Contains("decrypt routine was not found", reason, StringComparison.Ordinal);
    }

    [SampleFact]
    [Trait(Cost.Key, Cost.High)]
    public void ARunOnABootstrapPreservesTheRawAssemblyAndContinuesManagedRecovery()
    {
        var directory = Temporary();
        var stub = Path.Combine(directory, Stub);
        File.Copy(Checkout.Sample(Stub), stub);

        var output = Path.Combine(directory, "managed.cleaned.dll");
        var result = new CilantroPipeline().Run(stub, new PipelineOptions(ReportDirectory: directory, OutputPath: output));

        Assert.True(result.Success);
        // The native wrapper remains the root; the managed result has its own report.
        Assert.Null(result.OutputPath);
        var child = Assert.Single(result.EmbeddedRecovery!.Nodes.Skip(1));
        Assert.Equal("recovered", child.Status);
        Assert.Equal(output, child.Run!.Wrote.Cleaned);
        Assert.True(File.Exists(output));
        var payload = Assert.Single(result.ExtractedPayloadPaths);
        Assert.Equal(InnerAssemblySha256, Sha256(File.ReadAllBytes(payload)));

        var reported = Assert.Single(result.Report.Payloads);
        Assert.Equal(InnerAssemblySha256, reported.PayloadSha256);
        Assert.Equal(payload, reported.WrittenTo);
        // The wrapper's classification is independent of its managed child's classification.
        Assert.Equal("reactor-bootstrap", result.Report.Protector);
        // The stub's own resources are described, since it has no managed ones to describe.
        Assert.Contains(result.Report.Resources, resource => resource.Name == "10/__/0");
    }

    [SampleFact]
    public void ABootstrapThatCannotBeOpenedIsNotReportedAsSimplyNotDotNet()
    {
        var directory = Temporary();
        var stub = Path.Combine(directory, Stub);
        var bytes = File.ReadAllBytes(Checkout.Sample(Stub));
        bytes[Locate(bytes)] ^= 0xFF;
        File.WriteAllBytes(stub, bytes);

        var failure = Assert.Throws<NativeBootstrapException>(() =>
            new CilantroPipeline().Run(stub, new PipelineOptions(ReportDirectory: directory)));

        Assert.Contains("native bootstrap", failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("is not a .NET assembly", failure.Message, StringComparison.Ordinal);
    }

    [SampleFact]
    public void AnOrdinaryManagedAssemblyStillRunsThroughTheWholePipeline()
    {
        var directory = Temporary();
        var sample = Path.Combine(directory, "Qbjuef.exe");
        File.Copy(Checkout.Sample("Qbjuef.exe"), sample);

        var result = new CilantroPipeline().Run(
            sample, new PipelineOptions(AnalyzeOnly: true, ReportDirectory: directory));

        // The stage in front of the managed load must be invisible to everything that is not a
        // bootstrap: this run should have read a module and reported passes, not stopped early.
        Assert.NotEmpty(result.Report.Passes);
        Assert.NotNull(result.Report.ModuleName);
    }

    private static string Temporary()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"cilantro-native-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        return directory;
    }

    /// <summary>Finds the first byte of the encrypted payload resource in the file.</summary>
    private static int Locate(byte[] bytes)
    {
        Assert.True(PeImageView.TryParse(bytes, out var image));
        Assert.NotNull(image);
        var resource = Win32ResourceTable
            .Read(image)
            .Single(entry => entry.IsNamed(Win32Resource.RcDataType, NativeBootstrap.PayloadResourceName));
        Assert.True(image.TryRvaToFileOffset(resource.DataRva, out var offset));
        return offset;
    }

    private static string Sha256(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
