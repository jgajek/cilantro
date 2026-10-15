using System.Security.Cryptography;
using Cilantro.Core.Analysis;
using Cilantro.Core.Payload;
using dnlib.DotNet;

namespace Cilantro.Core;

internal sealed record ManagedBootstrapChild(string InputSha256, string OutputPath, string OutputSha256);

internal static class ManagedBootstrapReassembly
{
    internal static PipelineResult? TryComplete(PipelineResult root, PipelineOptions options,
        IReadOnlyList<EmbeddedRecoveryNode> nodes, IReadOnlyList<EmbeddedRecoveryLink> links,
        Func<string, PipelineOptions, PipelineResult> recover)
    {
        if (options.AnalyzeOnly || root.Report.Protector != "none" || !root.Report.VerificationPassed ||
            root.Report.Passes.Any(p => p.Status == PassStatus.Failed) ||
            nodes.Skip(1).Any(n => n.Status is not ("recovered" or "preserved-reference"))) return null;
        var direct = links.Where(l => l.Parent == 0).Select(l => l.Child).Distinct().ToArray();
        if (direct.Length != 1 || nodes[direct[0]] is not { Sha256: { } inputHash, Run: { Success: true, Verified: true, Wrote.Cleaned: { } output } }) return null;
        try
        {
            var rootBytes = File.ReadAllBytes(root.Report.InputPath);
            if (Convert.ToHexStringLower(SHA256.HashData(rootBytes)) != root.Report.InputSha256) return null;
            using var module = ModuleDefMD.Load(rootBytes);
            if (!ManagedBootstrapShape.Matches(module)) return null;
            var resource = (EmbeddedResource)module.Resources[0];
            if (Convert.ToHexStringLower(SHA256.HashData(resource.CreateReader().ToArray())) != inputHash ||
                new FileInfo(output).Length > EmbeddedAssemblyReplacement.MaximumAssemblyBytes) return null;
            var replacementHash = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(output)));
            var rebuilt = recover(root.Report.InputPath, options with {
                RecoverEmbeddedAssemblies = false,
                ManagedBootstrapReplacement = new(inputHash,output,replacementHash), StatusPath = null
            });
            // Keep original extraction provenance and links; the replacement is separately recorded as a change.
            rebuilt = rebuilt with { ExtractedPayloadPaths = root.ExtractedPayloadPaths,
                Report = rebuilt.Report with { Payloads = root.Report.Payloads } };
            CilantroPipeline.WriteJson(rebuilt.AnalysisReportPath, rebuilt.Report);
            return rebuilt;
        }
        catch (Exception exception) when (ManagedImage.Rejects(exception) || exception is UnauthorizedAccessException)
        {
            return null;
        }
    }

    internal static PassResult Apply(ArtifactContext context, ManagedBootstrapChild child)
    {
        try
        {
            if (new FileInfo(child.OutputPath).Length > EmbeddedAssemblyReplacement.MaximumAssemblyBytes)
                throw new InvalidDataException("Recovered child exceeds the byte limit.");
            var bytes = File.ReadAllBytes(child.OutputPath);
            if (Convert.ToHexStringLower(SHA256.HashData(bytes)) != child.OutputSha256)
                throw new InvalidDataException("Recovered child changed before wrapper reassembly.");
            if (!ManagedBootstrapShape.Matches(context.Module))
                throw new InvalidDataException("Unsupported managed bootstrap body.");
            var candidates = context.Module.GetTypes().SelectMany(t=>t.Methods).Where(m=>m.HasBody)
                .SelectMany(m=>m.Body.Variables.Select(v=>(Method:m,Buffer:v)))
                .Where(pair=>RawAssemblyBufferUse.ResourceName(pair.Method,pair.Buffer) is not null).ToArray();
            if (candidates.Length != 1) throw new InvalidDataException("Ambiguous managed bootstrap resource source.");
            var source = candidates[0];
            var replacement = EmbeddedAssemblyReplacement.PrepareForLoader(source.Method,source.Buffer,child.InputSha256,bytes);
            var original = context.Module.Resources.Single(r=>r.Name==replacement.Name);
            context.Module.Resources[context.Module.Resources.IndexOf(original)] = replacement;
            var detail = $"Replaced embedded assembly {child.InputSha256} with verified recovered child {child.OutputSha256}; retained the supported wrapper startup and resolution code.";
            context.AddChange(new("managed-bootstrap-reassembly","replace-protected-child",replacement.Name,detail));
            context.AddEvidence(new("managed-bootstrap-reassembly",detail));
            context.SetFact("managed-bootstrap.reassembled",true);
            return new("managed-bootstrap-reassembly",PassStatus.Success,1,[detail],TimeSpan.Zero);
        }
        catch (Exception exception) when (ManagedImage.Rejects(exception) || exception is UnauthorizedAccessException)
        {
            return new("managed-bootstrap-reassembly",PassStatus.Failed,0,[exception.Message],TimeSpan.Zero);
        }
    }
}
