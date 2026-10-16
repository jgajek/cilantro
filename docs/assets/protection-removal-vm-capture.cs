using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using Cilantro.Core;
using Cilantro.Core.Recovery;
using dnlib.DotNet;

// Static capture only. The sample is parsed and interpreted, never loaded into the host CLR.
if (args.Length == 3 && args[0] == "--readable")
{
    using var context = ArtifactContext.Load(args[1]);
    var cleanup = new RebuiltBodyCleanupPass().Run(context);
    var renaming = new SymbolRenamingPass().Run(context);
    context.Module.Write(args[2]);
    Console.WriteLine($"Cleanup={cleanup.Status}; changes={cleanup.Changes}; renaming={renaming.Status}");
    return;
}
if (args.Length != 3) throw new ArgumentException("Usage: vm-capture INPUT OUTPUT_DIRECTORY HEX_METHOD_TOKEN");
var input = Path.GetFullPath(args[0]);
var directory = Path.GetFullPath(args[1]);
var token = Convert.ToUInt32(args[2], 16);
Directory.CreateDirectory(directory);
var passes = CilantroPipeline.CreateDefaultPasses().Select(pass => pass.Name == "virtualization-rebuild"
    ? (IDeobfuscationPass)new VmCapture(pass, directory, token) : pass);
var result = new CilantroPipeline(passes).Run(input, new PipelineOptions(
    ReportDirectory: directory, OutputPath: Path.Combine(directory, "cleaned" + Path.GetExtension(input))));
File.WriteAllText(Path.Combine(directory, "run.json"), JsonSerializer.Serialize(RunManifest.Of(result), CilantroPipeline.ReportJsonOptions));
Console.WriteLine($"Success={result.Success}; verified={result.Report.VerificationPassed}");

sealed class VmCapture(IDeobfuscationPass inner, string directory, uint token) : IDeobfuscationPass
{
    public string Name => inner.Name;
    public System.Collections.Generic.IReadOnlyCollection<string> Dependencies => inner.Dependencies;
    public bool GatesEmission => inner.GatesEmission;
    public PassResult Run(ArtifactContext context)
    {
        var method = context.Module.ResolveToken(token) as MethodDef ?? throw new ArgumentException("Method not found");
        object Snapshot() {
            method.Body.UpdateInstructionOffsets();
            return new { Token=token.ToString("X8"), Name=method.FullName, Instructions=method.Body.Instructions.Count,
                CIL=string.Join("\n",method.Body.Instructions.Select(i=>i.ToString())) };
        }
        var before = Snapshot();
        var result = inner.Run(context);
        var after = Snapshot();
        var checkpoint = Path.Combine(directory, "reconstructed" + Path.GetExtension(context.InputPath));
        context.Module.Write(checkpoint);
        File.WriteAllText(Path.Combine(directory,"vm-capture.json"),JsonSerializer.Serialize(new {
            ToolVersion=CilantroPipeline.Version, InputSha256=context.OriginalSha256, Before=before, After=after,
            CheckpointSha256=Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(checkpoint))),
            result.Status, result.Diagnostics
        },CilantroPipeline.ReportJsonOptions));
        return result;
    }
}
