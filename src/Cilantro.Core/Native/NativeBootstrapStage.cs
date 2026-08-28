using System.Security.Cryptography;
using Cilantro.Core.Analysis;
using Cilantro.Core.Payload;

namespace Cilantro.Core.Native;

/// <summary>
/// Raised where the input is a Reactor native bootstrap that this tool could not open.
/// </summary>
/// <remarks>
/// Distinct from the <see cref="BadImageFormatException"/> an ordinary native file gets, because the
/// two want opposite things from the caller. "Not a .NET assembly" is the end of the matter; this is
/// a file whose managed half was found and not reached, and saying so is what stops an analyst
/// concluding the sample is unmanaged and moving on.
/// </remarks>
public sealed class NativeBootstrapException : Exception
{
    public NativeBootstrapException(string message) : base(message)
    {
    }

    public NativeBootstrapException(string message, Exception inner) : base(message, inner)
    {
    }

    public NativeBootstrapException()
    {
    }
}

/// <summary>
/// The stage that runs before anything is loaded as managed code, for the one kind of input where
/// there is nothing managed to load until this tool has made it.
/// </summary>
/// <remarks>
/// A run that gets this far stops here rather than carrying on into the pass pipeline. What comes
/// out of a bootstrap is a whole protected assembly — a stage in its own right, of unknown size and
/// with its own protections — and it is reported the way every other recovered stage is: written
/// beside the report, named in the manifest, and left for the caller to run the tool on. Continuing
/// automatically would make one invocation mean two different amounts of work depending on how the
/// sample was packed, and would bury the recovered assembly's own findings under the stub's.
/// </remarks>
internal static class NativeBootstrapStage
{
    /// <summary>What a program sees in the report's protector field for a bootstrap run.</summary>
    internal const string BootstrapProtector = "reactor-bootstrap";

    public static bool TryRun(
        string inputPath,
        PipelineOptions options,
        out PipelineResult result)
    {
        result = null!;
        var fullPath = Path.GetFullPath(inputPath);
        var fileBytes = File.ReadAllBytes(fullPath);
        if (!NativeBootstrap.Looks(fileBytes))
            return false;

        if (!NativeBootstrap.TryUnpack(fileBytes, out var findings, out var reason) ||
            findings is null)
        {
            throw new NativeBootstrapException(
                $"{Path.GetFileName(fullPath)} is a .NET Reactor native bootstrap — the managed " +
                $"assembly is inside it — but it could not be opened. {reason}");
        }

        if (!PayloadStageValidator.TryValidateManaged(findings.Assembly, out var payload) ||
            payload is null)
        {
            throw new NativeBootstrapException(
                $"{Path.GetFileName(fullPath)} is a .NET Reactor native bootstrap, and what came " +
                "out of it is not a managed assembly. Nothing was written.");
        }

        var stem = Path.GetFileNameWithoutExtension(fullPath);
        var reportDirectory = RunStatus.DirectoryFor(fullPath, options.ReportDirectory);
        Directory.CreateDirectory(reportDirectory);

        var payloadDirectory = Path.Combine(reportDirectory, $"{stem}.payloads");
        Directory.CreateDirectory(payloadDirectory);
        var safeName = string.Concat(payload.AssemblyName.Select(character =>
            Path.GetInvalidFileNameChars().Contains(character) ? '_' : character));
        var payloadPath = Path.Combine(payloadDirectory, $"{safeName}.dll");
        File.WriteAllBytes(payloadPath, payload.Bytes);

        var inputSha = Sha256(fileBytes);
        var report = Describe(
            fullPath, fileBytes, inputSha, findings, payload, payloadPath, options.Strict);

        var analysisPath = Path.Combine(reportDirectory, $"{stem}.analysis.json");
        var changesPath = Path.Combine(reportDirectory, $"{stem}.changes.json");
        var blockersPath = Path.Combine(reportDirectory, $"{stem}.blockers.json");
        CilantroPipeline.WriteJson(analysisPath, report);
        CilantroPipeline.WriteJson(changesPath, Array.Empty<ChangeRecord>());
        // Written even though it is empty, because an agent's loop reads this file to decide whether
        // to try again, and a missing file is not an answer to that question. Nothing here is
        // declarable: what would help is not a fact about the machine but the recovered assembly.
        CilantroPipeline.WriteJson(blockersPath, new BlockerReport(
            CilantroPipeline.Version,
            fullPath,
            inputSha,
            "none",
            string.Empty,
            CallsAllowed: false,
            [],
            [],
            options.Strict,
            []));

        result = new PipelineResult(
            Success: true,
            analysisPath,
            changesPath,
            // No cleaned copy: nothing was undone here. The stub is what it always was, and the
            // thing worth having is the payload beside the report.
            OutputPath: null,
            [payloadPath],
            report)
        {
            BlockerReportPath = blockersPath
        };
        return true;
    }

    private static ArtifactReport Describe(
        string inputPath,
        byte[] fileBytes,
        string inputSha,
        NativeBootstrapFindings findings,
        ValidatedManagedPayload payload,
        string payloadPath,
        bool strict)
    {
        var evidence = new List<Evidence>
        {
            new("native-bootstrap",
                "The file is a .NET Reactor native bootstrap: native code with no CLR header, " +
                $"carrying the managed assembly in resource {findings.Resource}."),
            new("native-bootstrap",
                $"The substitution key was read from the bootstrap's decrypt routine at file " +
                $"offset 0x{findings.KeyFileOffset:X} (key {findings.KeyBytes}).",
                Location: $"0x{findings.KeyFileOffset:X}"),
            new("native-bootstrap",
                $"{findings.EncryptedLength} encrypted bytes inflated to {findings.InflatedLength}.")
        };

        if (findings.CandidateRoutines > 1)
        {
            evidence.Add(new Evidence(
                "native-bootstrap",
                $"{findings.CandidateRoutines} routines matched the pattern; the one that produced " +
                "an assembly was used."));
        }

        if (findings.CameFromLoader)
        {
            evidence.Add(new Evidence(
                "native-bootstrap",
                "The inflated data was a loader assembly for runtime " +
                $"{findings.ClrVersion ?? "an unnamed version"}; the assembly was taken from the " +
                "resource it embeds."));
        }

        // The stub's Win32 resources, since it has no managed ones: the payload blob is the
        // interesting one, and a reader comparing this report with the recovered assembly's should
        // be able to see the resource the assembly came out of.
        var resources = Inspect(fileBytes);

        return new ArtifactReport(
            CilantroPipeline.Version,
            inputPath,
            inputSha,
            fileBytes.LongLength,
            // No managed module was read, so every field describing one is left empty rather than
            // filled in from the assembly that came out: that one is a payload, not this input.
            ModuleName: null,
            findings.ClrVersion,
            EntryPointToken: 0,
            TypeCount: 0,
            MethodCount: 0,
            ConcreteMethodCount: 0,
            ResourceCount: resources.Count,
            Resources: resources,
            Payloads:
            [
                new PayloadInfo(
                    findings.Resource,
                    inputSha,
                    findings.EncryptedLength,
                    Sha256(payload.Bytes),
                    payload.Bytes.Length,
                    Sha256(payload.Bytes),
                    payload.AssemblyName,
                    payload.ModuleName,
                    payload.EntryPointToken,
                    payload.Resources,
                    payloadPath)
            ],
            evidence,
            Passes:
            [
                new PassResult(
                    "native-bootstrap",
                    PassStatus.Success,
                    1,
                    ["The managed assembly was recovered from the native bootstrap."],
                    TimeSpan.Zero)
            ],
            new RecoveryReportMetrics(0, 0, 0, 0, 0),
            // Nothing was rewritten, so there is nothing to have verified. Said true rather than
            // false because false is how this report would announce a failure that did not happen.
            VerificationPassed: true,
            VerificationDiagnostics: [],
            Strict: strict,
            // Its own token rather than the one a Reactor 6 assembly gets. Which generation
            // protected the assembly inside is decided by reading that assembly, which this run
            // deliberately did not do, and "reactor6" here would be a claim nothing checked.
            Protector: BootstrapProtector);
    }

    private static List<ResourceInfo> Inspect(byte[] fileBytes)
    {
        if (!PeImageView.TryParse(fileBytes, out var image) || image is null)
            return [];

        var described = new List<ResourceInfo>();
        foreach (var resource in Win32ResourceTable.Read(image))
        {
            if (!Win32ResourceTable.TryReadBytes(image, resource, out var bytes))
                continue;
            var data = bytes.ToArray();
            var entropy = Entropy.Calculate(data);
            described.Add(new ResourceInfo(
                resource.Describe(),
                (uint)data.Length,
                entropy,
                Sha256(data),
                ResourceInspector.Classify(data, entropy)));
        }

        return described;
    }

    private static string Sha256(byte[] bytes) =>
        Convert.ToHexStringLower(SHA256.HashData(bytes));
}
