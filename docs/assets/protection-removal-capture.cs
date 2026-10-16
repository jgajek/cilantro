using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cilantro.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

// Snapshot recognized managed roots without executing them. Not a CLI replacement.
if (args.Length is < 2 or > 3)
    throw new ArgumentException("Usage: protection-capture INPUT OUTPUT_DIRECTORY [TOKEN,TOKEN,...]");
var input = Path.GetFullPath(args[0]);
var directory = Path.GetFullPath(args[1]);
var tokens = new HashSet<string>(args.Length == 3 ? args[2].Split(',') : [], StringComparer.OrdinalIgnoreCase);
Directory.CreateDirectory(directory);
var frames = new List<object>();
var selected = new HashSet<string> {
    "method-body-recovery", "confuserex-antitamper", "string-recovery", "confuserex-constants",
    "boolean-recovery", "constant-predicates", "global-predicate-folding", "dispatcher-deobfuscation",
    "delegate-proxy-analysis", "token-recovery", "resource-restoration", "antitamper-neutralization",
    "virtualization-rebuild", "loader-call-elision", "runtime-cleanup", "symbol-renaming", "protector-resource-cleanup"
};
var passes = CilantroPipeline.CreateDefaultPasses().Select(pass =>
    selected.Contains(pass.Name) ? (IDeobfuscationPass)new CapturePass(pass, frames, tokens) : pass);
var result = new CilantroPipeline(passes).Run(input, new PipelineOptions(
    ReportDirectory: directory,
    OutputPath: Path.Combine(directory, "cleaned" + Path.GetExtension(input))));
File.WriteAllText(Path.Combine(directory, "run.json"), JsonSerializer.Serialize(RunManifest.Of(result), CilantroPipeline.ReportJsonOptions));
File.WriteAllText(Path.Combine(directory, "frames.json"), JsonSerializer.Serialize(frames, CilantroPipeline.ReportJsonOptions));
File.WriteAllText(Path.Combine(directory, "identity.json"), JsonSerializer.Serialize(new {
    ToolVersion=CilantroPipeline.Version, Input=input, InputSha256=result.Report.InputSha256,
    Output=result.OutputPath, OutputSha256=result.OutputPath is null ? null : Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(result.OutputPath))),
    result.Success, result.Report.VerificationPassed, result.RebuiltMethods, result.VirtualizedMethods,
    result.Report.Recovery, SelectedMethodTokens=tokens
}, CilantroPipeline.ReportJsonOptions));
Console.WriteLine($"{Path.GetFileName(input)}: success={result.Success}, verified={result.Report.VerificationPassed}, rebuilt={result.RebuiltMethods}; {directory}");

sealed record Body(string Token, string Name, int Count, int Switches, string IL);
sealed class CapturePass(IDeobfuscationPass inner, List<object> frames, HashSet<string> tokens) : IDeobfuscationPass
{
    public string Name => inner.Name;
    public IReadOnlyCollection<string> Dependencies => inner.Dependencies;
    public bool GatesEmission => inner.GatesEmission;
    public PassResult Run(ArtifactContext context)
    {
        var before = Snapshot(context.Module);
        var beforeTypes = context.Module.GetTypes().ToDictionary(t => t, t => $"{t.MDToken}: {Safe(t.FullName)}");
        var resources = Resources(context.Module);
        var result = inner.Run(context);
        var after = Snapshot(context.Module);
        var differences = before.Where(pair => after.TryGetValue(pair.Key, out var body) && pair.Value != body)
            .Select(pair => new { Before=pair.Value, After=after[pair.Key] })
            .Where(pair => tokens.Count > 0 ? tokens.Contains(pair.Before.Token) : pair.Before.Count <= 2500 && pair.After.Count <= 500)
            .OrderBy(pair => pair.After.Count < 3 ? 1 : 0)
            .ThenBy(pair => pair.Before.Count > 450 ? 1 : 0)
            .ThenBy(pair => Math.Abs(pair.After.Count - 16)).Take(tokens.Count > 0 ? int.MaxValue : 8).ToArray();
        frames.Add(new {
            Pass=Name, result.Status, result.Changes, result.Diagnostics,
            BeforeTypes=beforeTypes.Count, AfterTypes=context.Module.GetTypes().Count(),
            BeforeMethods=before.Count, AfterMethods=after.Count,
            BeforeResources=resources, AfterResources=Resources(context.Module),
            RemovedTypes=beforeTypes.Where(pair => !context.Module.GetTypes().Contains(pair.Key)).Select(pair => pair.Value).ToArray(),
            RemovedMethods=before.Where(pair => !after.ContainsKey(pair.Key)).Select(pair => pair.Value).Take(8).ToArray(),
            Methods=differences,
            Evidence=context.Evidence.Where(e => e.Category is "virtualized-method" or "virtualized-program" or "runtime-removal" or "protector-retirement").ToArray()
        });
        Console.WriteLine($"  {Name}: {result.Changes} changes; {differences.Length} examples");
        return result;
    }
    static Dictionary<MethodDef,Body> Snapshot(ModuleDef module) => module.GetTypes().SelectMany(t=>t.Methods)
        .ToDictionary(m=>m, Read);
    static Body Read(MethodDef method)
    {
        try {
            if (method.Body is not { } body) return new(method.MDToken.ToString(), Safe(method.FullName), 0,0,"<no CIL body>");
            var offsets = new Dictionary<Instruction,uint>();
            uint offset=0;
            foreach(var i in body.Instructions) { offsets[i]=offset; offset+=(uint)i.GetSize(); }
            string Operand(object operand) => operand switch {
                Instruction target => offsets.TryGetValue(target,out var value) ? $"IL_{value:X4}" : "<external-target>",
                IList<Instruction> targets => "("+string.Join(", ",targets.Select(t=>Operand(t)))+")",
                string text => JsonSerializer.Serialize(text),
                null => "",
                _ => Safe(operand.ToString() ?? "")
            };
            var il = string.Join("\n",body.Instructions.Take(1200).Select(i=>$"IL_{offsets[i]:X4}: {i.OpCode.Name} {Operand(i.Operand)}".TrimEnd()));
            if(body.Instructions.Count>1200) il+="\n... [capture truncated]";
            return new(method.MDToken.ToString(),Safe(method.FullName),body.Instructions.Count,body.Instructions.Count(i=>i.OpCode.Code==Code.Switch),il);
        } catch(Exception error) { return new(method.MDToken.ToString(),Safe(method.FullName),-1,0,"<unreadable body: "+error.GetType().Name+">"); }
    }
    static object[] Resources(ModuleDef module) => module.Resources.Select(r => r is EmbeddedResource e
        ? (object)new { Name=Safe(r.Name), Bytes=e.CreateReader().Length, Sha256=Convert.ToHexStringLower(SHA256.HashData(e.CreateReader().ToArray())) }
        : new { Name=Safe(r.Name), Bytes=0u, Sha256="" }).ToArray();
    static string Safe(string value) => string.Concat(value.Select(c=>c<32 || c>126 ? $"\\u{(int)c:X4}" : c.ToString()));
}
