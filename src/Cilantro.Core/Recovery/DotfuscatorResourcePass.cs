using System.Security.Cryptography;
using Cilantro.Core.Analysis;
using Cilantro.Core.Codec;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Restores resources and retires the reviewed generated ResourceManager decryptor.</summary>
public sealed class DotfuscatorResourcePass : DeobfuscationPass
{
    public override string Name => "dotfuscator-resources";
    public override IReadOnlyCollection<string> Dependencies => ["dotfuscator-detection", "dotfuscator-native-strings"];
    public override bool GatesEmission => true;

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<DotfuscatorStructureFacts>("dotfuscator.structure", out var facts) || facts?.IsDotfuscator != true)
            return (PassStatus.Success, 0, ["No Dotfuscator resource runtime detected."]);
        using var original = ModuleDefMD.Load(context.OriginalBytes);
        var runtimes = DotfuscatorResourceShape.Find(original).ToArray();
        if (runtimes.Length == 0) return (PassStatus.Success, 0, ["No generated Dotfuscator ResourceManager found."]);
        if (runtimes.Length != 1 || !DotfuscatorResourceShape.Supported(runtimes[0]))
            return (PassStatus.Unsupported, 0, ["Unreviewed Dotfuscator resource runtime; preserved: " + string.Join(", ", runtimes.Select(item => item.Fingerprint))]);
        var runtime = runtimes[0];
        var canRebind = RetiredDotfuscatorResourceRuntime.CanRebind(context, runtime);
        if (!canRebind) return (PassStatus.Unsupported, 0, ["Unreviewed complete Dotfuscator resource family metadata or code; resources and hooks preserved."]);
        if (!DotfuscatorResourceSatellites.TryRestore(context, runtime, out var satellites, out var satelliteReason))
            return (PassStatus.Unsupported, 0, ["Satellite resource restoration declined; " + satelliteReason]);
        if (context.Module.ResolveToken(runtime.Manager.MDToken) is not TypeDef manager)
            return (PassStatus.Unsupported, 0, ["Generated resource manager is unavailable."]);
        var resources = new List<(EmbeddedResource Before, EmbeddedResource After, int Entries)>();
        foreach (var source in context.Module.Resources.OfType<EmbeddedResource>().Where(resource => resource.Name.String.EndsWith(".resources", StringComparison.OrdinalIgnoreCase)))
        {
            if (source.Length > DotfuscatorResourceCodec.MaximumLength)
                return (PassStatus.Unsupported, 0, [$"{source.Name}: resource length exceeds the bound."]);
            if (!DotfuscatorResourceCodec.TryRestore(source.CreateReader().ToArray(), runtime.Seed, runtime.Keys, out var bytes, out var count, out var why))
                return (PassStatus.Unsupported, 0, [$"{source.Name}: resource restoration declined; {why}"]);
            resources.Add((source, new EmbeddedResource(source.Name, bytes, source.Attributes), count));
        }
        if (resources.Count == 0 && satellites.Count == 0) return (PassStatus.Unsupported, 0, ["Resource manager has no local resource container; companion resources are required."]);
        using var batch = new BodyMutationBatch();
        foreach (var source in runtime.Manager.Methods.Where(method => method.IsInstanceConstructor || method.IsVirtual))
        {
            if (context.Module.ResolveToken(source.MDToken) is not MethodDef method)
                return (PassStatus.Unsupported, 0, ["Generated resource method is unavailable."]);
            batch.Capture(method);
            var body = new CilBody();
            foreach (var parameter in method.Parameters) body.Instructions.Add(OpCodes.Ldarg.ToInstruction(parameter));
            body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(context.Module, source.Name,
                new Importer(context.Module).Import(source.MethodSig), manager.BaseType)));
            body.Instructions.Add(OpCodes.Ret.ToInstruction());
            method.Body = body;
            if (!EvaluationStackAnalyzer.Analyze(method).Valid)
                return (PassStatus.Unsupported, 0, ["Restored resource-manager forwarding method did not verify."]);
        }
        foreach (var resource in resources) context.Module.Resources[context.Module.Resources.IndexOf(resource.Before)] = resource.After;
        batch.Commit();
        RetiredDotfuscatorResourceRuntime.RebindAndRemember(context, manager);
        context.SetFact(DotfuscatorResourceSatellites.Fact, satellites);
        var total = resources.Sum(resource => resource.Entries) + satellites.Sum(satellite => satellite.Entries);
        context.SetFact("dotfuscator.resources.restoredEntries", total);
        context.SetFact("dotfuscator.resources.restoredContainers", resources.Count + satellites.Sum(satellite => satellite.Containers));
        foreach (var resource in resources)
        {
            var hash = Convert.ToHexStringLower(SHA256.HashData(resource.After.CreateReader().ToArray()));
            context.AddChange(new(Name, "restore-dotfuscator-resource", resource.After.Name, $"Restored {resource.Entries} entries; SHA-256 {hash}."));
        }
        foreach (var satellite in satellites)
            context.AddChange(new(Name, "restore-dotfuscator-satellite", satellite.Culture + "/" + satellite.FileName,
                $"Restored {satellite.Entries} entries from SHA-256 {satellite.SourceSha256}; output SHA-256 {Convert.ToHexStringLower(SHA256.HashData(satellite.Bytes))}."));
        return (PassStatus.Success, total, [$"Restored {total} entries in {resources.Count} local containers and {satellites.Count} satellites; replaced generated decryption hooks with ResourceManager forwarding methods."]);
    }
}
