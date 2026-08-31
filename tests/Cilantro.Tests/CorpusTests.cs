using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Codec;
using Cilantro.Core.Corpus;

namespace Cilantro.Tests;

public sealed class CorpusTests
{
    /// <summary>
    /// Every manifest in the corpus directory, found rather than listed, so that adding one puts it
    /// under the checks below without anybody having to remember to.
    /// </summary>
    public static TheoryData<string> Manifests
    {
        get
        {
            var found = new TheoryData<string>();
            foreach (var path in Directory
                         .EnumerateFiles(Path.Combine(Checkout.Root, "corpus"), "*.manifest.json")
                         .Order(StringComparer.Ordinal))
            {
                found.Add(Path.GetFileName(path));
            }

            return found;
        }
    }

    [Theory]
    [MemberData(nameof(Manifests))]
    public void EveryManifestNamesEachSampleOnceAndByHash(string file)
    {
        var manifest = CorpusRunner.LoadManifest(Path.Combine(Checkout.Root, "corpus", file));

        Assert.Equal(1, manifest.ManifestVersion);
        Assert.NotEmpty(manifest.Samples);
        Assert.Equal(manifest.Samples.Count,
            manifest.Samples.Select(sample => sample.Sha256).Distinct().Count());
        Assert.All(manifest.Samples,
            sample => Assert.Matches("^[a-f0-9]{64}$", sample.Sha256));
        // A gate that asserts nothing about what the run recovered is a gate that would pass on an
        // unprotected file. A capability list is the usual way to assert something; pinning the hash
        // of a recovered payload is the other, and is what a native bootstrap has instead, since its
        // capabilities belong to the assembly inside it and this run never reads that.
        Assert.All(manifest.Samples, sample => Assert.True(
            sample.ExpectedDetection == "none" ||
            sample.ExpectedCapabilities.Count > 0 ||
            sample.ExpectedPayloadSha256 is { Count: > 0 },
            $"{sample.Id} expects a protector but asserts nothing it must recover."));
    }

    [Fact]
    public void ManifestDefinesUniqueHashVerifiedTiers()
    {
        var manifest = CorpusRunner.LoadManifest(
            Path.Combine(Checkout.Root, "corpus", "reactor-6-nonvirt.manifest.json"));

        Assert.Equal(1, manifest.ManifestVersion);
        Assert.Equal(12, manifest.Samples.Count);
        Assert.Equal(manifest.Samples.Count,
            manifest.Samples.Select(sample => sample.Sha256).Distinct().Count());
        Assert.Contains(manifest.Samples, sample => sample.Tier == "profiled");
        Assert.Contains(manifest.Samples, sample => sample.Tier == "detected");
        Assert.Contains(manifest.Samples, sample => sample.Tier == "negative");
        Assert.Contains(manifest.Samples, sample => sample.Tier == "exploratory");
        Assert.All(manifest.Samples,
            sample => Assert.Matches("^[a-f0-9]{64}$", sample.Sha256));
    }

    [SampleFact]
    public void StructuralDiscoveryDerivesQbjuefProxyCodec()
    {
        using var context = ArtifactContext.Load(Checkout.Sample("Qbjuef.exe"));
        var facts = ReactorStructureDetector.Analyze(context.Module);

        Assert.True(facts.IsReactor);
        Assert.Equal("delegate-runtime", facts.Generation);
        Assert.Contains("delegate-proxy", facts.CapabilityNames);
        Assert.True(StructuralStreamDiscovery.TryDiscoverProxyProfile(
            context.Module,
            facts,
            out var profile));
        Assert.NotNull(profile);
        Assert.Equal(0x64875CD0u, profile.A);
        Assert.Equal(0x7511923Au, profile.D);
        Assert.Equal(146, profile.Bindings.Count);
    }

    [SampleFact]
    [Trait(Cost.Key, Cost.High)]
    public void MethodProtectedGenerationIsDetectedAndFullyRecovered()
    {
        var sample = Checkout.Sample("Reason.PAC.dll");
        var outputDirectory = Path.Combine(
            Path.GetTempPath(),
            $"Cilantro.CorpusTests.{Guid.NewGuid():N}");
        try
        {
            var result = new CilantroPipeline().Run(sample, new PipelineOptions(
                AnalyzeOnly: true,
                ReportDirectory: outputDirectory));

            Assert.True(result.Success);
            Assert.Null(result.OutputPath);
            var protection = Assert.Single(
                result.Report.Passes,
                pass => pass.Pass == "method-protection");
            Assert.Equal(PassStatus.Success, protection.Status);
            var recovery = Assert.Single(
                result.Report.Passes,
                pass => pass.Pass == "method-body-recovery");
            Assert.Equal(PassStatus.Success, recovery.Status);
            Assert.Equal(312, result.Report.Recovery.RestoredMethodBodies);
            Assert.Equal(0, result.Report.Recovery.RemainingMethodStubs);
            Assert.Contains(result.Report.Evidence,
                evidence => evidence.Category == "method-encryption");
        }
        finally
        {
            Directory.Delete(outputDirectory, true);
        }
    }

    [SampleFact]
    [Trait(Cost.Key, Cost.High)]
    public void ReactorSevenNecroBitFrameworkBodiesAreStaticallyRecovered()
    {
        var sample = Checkout.Sample("reactor7-probe-net48.necrobit.exe");
        var outputDirectory = Path.Combine(
            Path.GetTempPath(),
            $"Cilantro.NecroBitTests.{Guid.NewGuid():N}");
        var outputPath = Path.Combine(outputDirectory, "cleaned.exe");
        try
        {
            var result = new CilantroPipeline().Run(sample, new PipelineOptions(
                PreserveTokens: true,
                RenameSymbols: false,
                Devirtualize: false,
                OutputPath: outputPath,
                ReportDirectory: outputDirectory));

            // NecroBit encrypts every body and hands the plaintext to the JIT from a managed table the
            // loader fills before it hooks the JIT. Recovery reads that table and the header writes the
            // loader makes, so a full run must decrypt every body and emit a verified clean copy.
            Assert.True(result.Success);
            Assert.Equal("reactor", result.Report.Protector);
            Assert.NotNull(result.OutputPath);
            var recovery = Assert.Single(
                result.Report.Passes,
                pass => pass.Pass == "method-body-recovery");
            Assert.Equal(PassStatus.Success, recovery.Status);
            Assert.Equal(13, result.Report.Recovery.RestoredMethodBodies);
            Assert.Equal(0, result.Report.Recovery.RemainingMethodStubs);

            // The header writes carry back each method's locals-signature token and, for the one body
            // that had them, its exception clauses; loading the clean copy proves both survived the
            // graft rather than leaving a stub, a body missing its locals, or a try without its finally.
            using var cleaned = dnlib.DotNet.ModuleDefMD.Load(result.OutputPath);
            var program = cleaned.Types.Single(type => type.Name == "Program");
            var checksum = program.Methods.Single(method => method.Name == "ComputeChecksum");
            Assert.Equal(4, checksum.Body.Variables.Count);
            Assert.True(checksum.Body.Instructions.Count > 3);
            var secret = program.Methods.Single(method => method.Name == "ReadEmbeddedSecret");
            Assert.Equal(2, secret.Body.ExceptionHandlers.Count);
            Assert.All(
                secret.Body.ExceptionHandlers,
                handler => Assert.Equal(
                    dnlib.DotNet.Emit.ExceptionHandlerType.Finally,
                    handler.HandlerType));
        }
        finally
        {
            Directory.Delete(outputDirectory, true);
        }
    }

    [SampleFact]
    [Trait(Cost.Key, Cost.High)]
    public void ReactorSevenVirtualizedFullBuildIsFullyRecovered()
    {
        var sample = Checkout.Sample("reactor7-probe-net48.full.exe");
        var outputDirectory = Path.Combine(
            Path.GetTempPath(),
            $"Cilantro.VirtualizedFullTests.{Guid.NewGuid():N}");
        var outputPath = Path.Combine(outputDirectory, "cleaned.exe");
        try
        {
            var result = new CilantroPipeline().Run(sample, new PipelineOptions(
                PreserveTokens: true,
                RenameSymbols: false,
                Devirtualize: true,
                OutputPath: outputPath,
                ReportDirectory: outputDirectory));

            // The full build stacks a virtualization layer over NecroBit: the same 680 bodies are
            // decrypted, but the string table and the delegate-proxy map are behind the module's own
            // VM, and a date-based trial guard throws under any clock the interpreter injects. A full
            // run resolves the proxies, learns the engine's numbering (including the operations only
            // the string table's own program uses), neutralises the guard by shape, and reads the
            // table out, so every protected-string site is restored and a verified copy is written.
            Assert.True(result.Success);
            Assert.Equal("reactor", result.Report.Protector);
            Assert.NotNull(result.OutputPath);

            var recovery = Assert.Single(
                result.Report.Passes,
                pass => pass.Pass == "method-body-recovery");
            Assert.Equal(PassStatus.Success, recovery.Status);
            Assert.Equal(680, result.Report.Recovery.RestoredMethodBodies);
            Assert.Equal(0, result.Report.Recovery.RemainingMethodStubs);

            // Every protected-string call site comes back, which is what the virtualization work was
            // for: the table it produces is only reachable once the engine's numbering is learned.
            Assert.Equal(20, result.Report.Recovery.StringCallSites);
            Assert.Equal(20, result.Report.Recovery.ReplacedStringSites);

            // The engine was read whole and its stack walk agreed with itself, and the initializer
            // it stands for was built back into the cleaned copy from that reading.
            Assert.Equal(
                result.Report.Recovery.VirtualOperations,
                result.Report.Recovery.VirtualOperationsRead);
            Assert.Equal(0, result.Report.Recovery.VirtualDepthDisagreements);
            Assert.True(result.RebuiltMethods >= 1);

            using var cleaned = dnlib.DotNet.ModuleDefMD.Load(result.OutputPath);

            // The virtualized loader initializer holds real IL where it shipped as a stub, and it
            // says so about itself with the marker every rebuilt body carries.
            var rebuilt = cleaned.GetTypes()
                .SelectMany(type => type.Methods)
                .Single(method => method.Name == "KMP0OXI4h");
            Assert.NotNull(rebuilt.Body);
            Assert.True(rebuilt.Body.Instructions.Count > 100);
            Assert.Contains(
                rebuilt.CustomAttributes,
                attribute => attribute.TypeFullName.Contains("RebuiltFromReading"));

            // The recovered plaintext is the probe's own planted strings, present at the call sites
            // the resolver used to hide. Their presence in the cleaned copy is the byte-level proof
            // that the table was read correctly rather than merely that some count came out right.
            var literals = cleaned.GetTypes()
                .SelectMany(type => type.Methods)
                .Where(method => method.HasBody)
                .SelectMany(method => method.Body.Instructions)
                .Where(instruction => instruction.OpCode == dnlib.DotNet.Emit.OpCodes.Ldstr)
                .Select(instruction => instruction.Operand as string)
                .ToHashSet(StringComparer.Ordinal);
            Assert.Contains("PROBE_STR_01 probe entry point", literals);
            Assert.Contains("Probe.Secret.txt", literals);
            Assert.Contains(
                literals,
                literal => literal is not null && literal.Contains("probe.invalid:8443/gate"));

            // Neutralising the trial guard also lets the module's own bundle reader finish, so the
            // encrypted managed-resource bundle is decrypted statically rather than stopping in the
            // module initializer. The two streams it holds are the probe's own resources.
            var resources = Assert.Single(
                result.Report.Passes,
                pass => pass.Pass == "resource-restoration");
            Assert.Equal(PassStatus.Success, resources.Status);
            Assert.Contains(
                result.Report.Payloads,
                payload => payload.PayloadLength == 2048);
        }
        finally
        {
            Directory.Delete(outputDirectory, true);
        }
    }

    [SampleFact]
    [Trait(Cost.Key, Cost.High)]
    public void CorpusOutcomesAreDeterministic()
    {
        var first = Path.Combine(Path.GetTempPath(), $"reactor-corpus-{Guid.NewGuid():N}");
        var second = Path.Combine(Path.GetTempPath(), $"reactor-corpus-{Guid.NewGuid():N}");
        try
        {
            var manifest = Path.Combine(Checkout.Root, "corpus", "reactor-6-nonvirt.manifest.json");
            var samples = Checkout.Samples;
            // The two runs go at once, which is the point rather than a shortcut. A run already
            // analyses several samples in parallel, so overlapping the pair leaves the two copies
            // of each sample interleaved differently against everything else in flight; agreeing
            // afterwards is then evidence that the outcome does not depend on what ran beside it.
            var directories = new[] { first, second };
            var reports = new CorpusRunReport[directories.Length];
            Parallel.For(
                0,
                directories.Length,
                index => reports[index] = CorpusRunner.Run(manifest, samples, directories[index]));

            var firstReport = reports[0];
            Assert.Equal(12, firstReport.Passed);
            Assert.Equal(0, firstReport.Failed);
            Assert.Equal(0, firstReport.Missing);

            // Recovery must never delete a member whose name the protector left intact; that is
            // program surface, not scaffolding. Surplus over the oracle is allowed to remain and is
            // bounded by the manifest ratchet instead.
            foreach (var outcome in firstReport.Samples.Where(sample => sample.Oracle is not null))
            {
                Assert.True(
                    outcome.Oracle!.PreservedNamesIntact,
                    $"{outcome.Id} lost preserved-name members: " +
                    string.Join(", ", outcome.Oracle.MissingPreservedNameMembers));
            }

            Assert.Equal(
                File.ReadAllBytes(Path.Combine(first, "corpus.outcomes.json")),
                File.ReadAllBytes(Path.Combine(second, "corpus.outcomes.json")));
        }
        finally
        {
            Directory.Delete(first, true);
            Directory.Delete(second, true);
        }
    }

    /// <summary>
    /// The second protector's corpus, held to the same gates as the first.
    /// </summary>
    /// <remarks>
    /// Both samples encrypt every method body and every literal, so nothing about them can be read
    /// without interpreting their own decrypters. That makes these two the check on the claim the
    /// tool makes about ConfuserEx: the bodies came back, the literals came back, and the run said
    /// which protector it was dealing with rather than being asked to assume.
    /// </remarks>
    [SampleFact]
    [Trait(Cost.Key, Cost.High)]
    public void ConfuserExSamplesAreDecryptedAndRead()
    {
        var output = Path.Combine(Path.GetTempPath(), $"confuserex-corpus-{Guid.NewGuid():N}");
        try
        {
            var report = CorpusRunner.Run(
                Path.Combine(Checkout.Root, "corpus", "confuserex-1-static.manifest.json"),
                Checkout.Samples,
                output);

            Assert.Equal(0, report.Missing);
            Assert.All(report.Samples, outcome => Assert.Equal("passed", outcome.Status));
            Assert.Equal(2, report.Passed);
            Assert.Equal(0, report.Failed);
            Assert.All(report.Samples,
                outcome => Assert.Equal("confuserex", outcome.Detection));
        }
        finally
        {
            Directory.Delete(output, true);
        }
    }
}
