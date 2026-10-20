using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Recovery;

/// <summary>Restores resources moved into ConfuserEx's encrypted, resource-only assembly.</summary>
public sealed class ConfuserExResourcePass : DeobfuscationPass
{
    public override string Name => "confuserex-resources";
    public override IReadOnlyCollection<string> Dependencies => ["confuserex-antitamper"];
    public override bool GatesEmission => false;

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<ConfuserExStructureFacts>("confuserex.structure", out var facts) ||
            facts?.IsConfuserExProtected != true)
            return (PassStatus.Success, 0, ["Not ConfuserEx-protected."]);

        var linked = context.Module.Resources.OfType<AssemblyLinkedResource>().ToArray();
        if (linked.Length == 0)
            return (PassStatus.Success, 0, ["No assembly-linked ConfuserEx resources."]);

        var names = linked.Select(resource => resource.Name.String).ToHashSet(StringComparer.Ordinal);
        var candidates = context.Module.GlobalType.Methods.Where(method =>
            method.IsStatic && method.HasBody && method.MethodSig?.Params.Count == 0 &&
            method.Body.Instructions.Any(instruction =>
                instruction.Operand is IMethod called && called.Name == "Load" &&
                called.DeclaringType?.FullName == "System.Reflection.Assembly") &&
            method.Body.Instructions.Any(instruction =>
                instruction.Operand is IMethod called && called.Name == "add_AssemblyResolve"))
            .ToArray();
        if (candidates.Length != 1)
            return (PassStatus.Unsupported, 0,
                [$"Expected one resource loader; found {candidates.Length}."]);

        var initializer = candidates[0];
        var first = Capture(context, initializer, names, out var why);
        var second = first is null ? null : Capture(context, initializer, names, out why);
        if (first is null || second is null || !first.AsSpan().SequenceEqual(second))
            return (PassStatus.Unsupported, 0, [$"Resource loader could not be verified: {why}"]);

        using var satellite = ModuleDefMD.Load(first);
        var entries = satellite.Resources.OfType<EmbeddedResource>()
            .ToDictionary(resource => resource.Name.String,
                resource => (Bytes: resource.CreateReader().ToArray(), resource.Attributes),
                StringComparer.Ordinal);
        var removeRuntime = context.TryGetFact<bool>("options.removeRuntime", out var enabled) && enabled;
        var calls = context.Module.GetTypes().SelectMany(type => type.Methods)
            .Where(method => method.HasBody)
            .SelectMany(method => method.Body.Instructions
                .Where(instruction => instruction.OpCode.Code == Code.Call &&
                    (instruction.Operand as IMethod)?.ResolveMethodDef() == initializer)
                .Select(instruction => (Method: method, Instruction: instruction)))
            .ToArray();
        if (removeRuntime && (calls.Length != 1 ||
            calls[0].Method.DeclaringType != context.Module.GlobalType))
            return (PassStatus.Unsupported, 0,
                [$"The resource initializer has unexpected callers: {string.Join(", ", calls.Select(call => call.Method.MDToken.ToString()))}."]);

        using var batch = new BodyMutationBatch();
        var originals = linked.Select(resource => (Resource: resource, Index: context.Module.Resources.IndexOf(resource))).ToArray();
        var replacements = new List<EmbeddedResource>();
        var committed = false;
        try
        {
            foreach (var (resource, index) in originals)
            {
                var entry = entries[resource.Name.String];
                var replacement = new EmbeddedResource(resource.Name, entry.Bytes, entry.Attributes);
                context.Module.Resources[index] = replacement;
                replacements.Add(replacement);
            }
            if (removeRuntime)
            {
                batch.Capture(calls[0].Method);
                calls[0].Instruction.OpCode = OpCodes.Nop;
                calls[0].Instruction.Operand = null;
                batch.Capture(initializer);
                initializer.Body = new CilBody();
                initializer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            }
            if (!AssemblyVerifier.Verify(context.Module, context.OriginalIdentity,
                    context.OriginalStructure, CilantroPipeline.BuildRewriteAllowance(context)).Passed)
                return (PassStatus.Unsupported, 0,
                    ["Restored resources failed structural verification; changes rolled back."]);
            batch.Commit();
            committed = true;
        }
        finally
        {
            if (!committed)
                foreach (var (resource, index) in originals)
                    context.Module.Resources[index] = resource;
        }

        context.SetFact("resources.restoredBundles", 1);
        foreach (var resource in replacements)
            context.AddChange(new ChangeRecord(Name, "restore-resource", resource.Name,
                $"Restored {resource.Length} bytes from the verified ConfuserEx resource assembly."));
        context.AddEvidence(new Evidence("confuserex-resources",
            $"Two interpretations agreed on a resource-only assembly containing {replacements.Count} original stream(s).",
            $"{initializer.MDToken}", 0.95));
        if (removeRuntime)
            RecoveryOrphans.DeclareOwningTypes(context, [initializer]);
        return (PassStatus.Success, replacements.Count,
            [$"Restored {replacements.Count} assembly-linked resource(s).",
             removeRuntime ? "Removed the verified resource loader call." : "Kept the runtime loader."]);
    }

    private static byte[]? Capture(ArtifactContext context, MethodDef initializer,
        IReadOnlySet<string> names, out string why)
    {
        why = "no verified resource assembly was loaded";
        if (!BootstrapMachine.TrySeed(context, 64_000_000, out var machine, out why) || machine is null)
            return null;
        machine.State.TryBeginTypeInitialization(context.Module.GlobalType);
        var result = machine.Execute(initializer);
        if (!result.Succeeded || machine.State.CapturedAssemblyLoads.Count != 1)
        {
            why = result.Diagnostic ?? result.Status.ToString();
            return null;
        }
        var image = machine.State.CapturedAssemblyLoads[0];
        if (image.Length > 32 * 1024 * 1024)
        {
            why = "loaded resource assembly exceeds 32 MiB";
            return null;
        }
        try
        {
            using var satellite = ModuleDefMD.Load(image);
            if (BabelResourceRestorationPass.IsResourceOnly(satellite, names))
                return image;
            why = "loaded assembly is not a resource-only satellite matching linked names";
        }
        catch (Exception exception) when (exception is IOException or BadImageFormatException or ArgumentException)
        {
            why = exception.Message;
        }
        return null;
    }
}
