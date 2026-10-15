using System.Security.Cryptography;
using System.Text.Json;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Restores ordinary resource enumeration after a private satellite has been reattached.</summary>
public sealed class ResourceEnumerationCompletionPass : DeobfuscationPass
{
    internal const string ChangedFact = "resources.enumerationCompleted";
    public override string Name => "resource-enumeration-completion";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => ["resource-hook-elision"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("options.removeRuntime", out var enabled) || !enabled ||
            !context.TryGetFact<IReadOnlyList<RestoredResourceBundle>>("resources.validatedBundles", out var bundles) || bundles is null)
            return (PassStatus.Success, 0, ["No restored bundle requires enumeration completion."]);
        var methods = context.Module.GetTypes().SelectMany(t => t.Methods).ToArray();
        var exposed = ModuleReachability.Compute(context.Module).ReflectivelyExposedTypes;
        var notes = new List<string>(); var changes = 0;
        foreach (var adapter in methods.Select(ResourceEnumerationAdapter.Match).OfType<ResourceEnumerationAdapter>())
        {
            var owner = adapter.Wrapper.DeclaringType;
            if (MemberVisibility.IsExternallyVisible(owner) || exposed.Contains(owner)) continue;
            var names = owner.Methods.Select(m => m.Name.String).Concat(owner.Fields.Select(f => f.Name.String))
                .Append(owner.Name.String).Append(owner.FullName).ToHashSet(StringComparer.Ordinal);
            if (methods.Where(m => m.DeclaringType != owner && m.HasBody).Any(m => m.Body.Instructions.Any(i => i.Operand is string text && names.Contains(text)))) continue;
            var matching = bundles.Where(b => b.IsPreserved(context.Module) && adapter.Initializer.Body.Instructions
                .Any(i => i.OpCode.Code == Code.Ldstr && i.Operand is string name && name == b.Source.Name)).ToArray();
            if (matching.Length != 1) continue;
            var bundle = matching[0];
            var sources = context.Module.Resources.OfType<EmbeddedResource>().Where(bundle.Source.Matches).ToArray();
            if (sources.Length != 1 || context.Module.Resources.Count(r => r.Name == bundle.Source.Name) != 1) continue;
            var sites = methods.Where(m => m.HasBody).SelectMany(m => m.Body.Instructions.Select(i => (Method: m, Instruction: i)))
                .Where(p => p.Instruction.Operand is IMethod call && call.ResolveMethodDef() == adapter.Wrapper).ToArray();
            if (sites.Length == 0 || sites.Any(p => p.Method.DeclaringType == owner || p.Instruction.OpCode.Code != Code.Call || p.Instruction.Operand != adapter.Wrapper) ||
                context.Module.GetMemberRefs().Any(r => r.IsMethodRef && r.ResolveMethodDef() == adapter.Wrapper)) continue;
            using var transaction = new BodyMutationBatch(sites.Select(p => p.Method));
            var getNames = adapter.Wrapper.Body.Instructions.Select(i => i.Operand).OfType<IMethod>()
                .First(m => m.Name == "GetManifestResourceNames");
            foreach (var site in sites) { site.Instruction.OpCode = OpCodes.Callvirt; site.Instruction.Operand = getNames; }
            // Every surviving declaration must release the cache owner after replacement.
            // This includes field/address references and other adapters on the same holder.
            if (!RuntimeCleanupPass.ComputeUnreferenced(context.Module, new HashSet<TypeDef> { owner }).Contains(owner)) continue;
            if (!Prove(context, adapter, bundle, sources[0], out var reason))
            { notes.Add(owner.FullName + ": " + reason); continue; }
            var check = AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
                CilantroPipeline.BuildRewriteAllowance(context));
            if (!check.Passed) { notes.Add(owner.FullName + ": structural verification refused replacement."); continue; }
            transaction.Commit();
            DecodedResourceOwnership.Remember(context, bundle.Source, [adapter.Initializer], bundle: bundle);
            RecoveryOrphans.DeclareSubtree(context, owner.Methods);
            changes += sites.Length;
            context.AddChange(new(Name, "restore-resource-enumeration", adapter.Wrapper.FullName,
                $"Replaced {sites.Length} adapter call(s) with ordinary assembly resource enumeration; {bundle.Entries.Count} restored streams are byte-preserved. " +
                "Two complete initializer trials agree and write only the now-unreferenced cache holder; the captured satellite contains resources only."));
        }
        context.SetFact(ChangedFact, changes != 0);
        return (notes.Count == 0 ? PassStatus.Success : PassStatus.Partial, changes,
            [$"Restored {changes} resource enumeration call(s).", .. notes]);
    }

    private static bool Prove(ArtifactContext context, ResourceEnumerationAdapter adapter, RestoredResourceBundle bundle,
        EmbeddedResource source, out string reason)
    {
        reason = "initializer proof did not complete";
        LoaderInterpretationEvidence? first = null; string? firstPayload = null;
        var fields = adapter.Wrapper.DeclaringType.Fields.Select(f => f.FullName).ToHashSet(StringComparer.Ordinal);
        for (var trial = 0; trial < 2; trial++)
        {
            if (!BootstrapMachine.TrySeed(context, ResourceRestorationPass.Budget(source), out var machine, out reason) || machine is null) return false;
            var result = machine.Execute(adapter.Initializer);
            var evidence = machine.State.LoaderEvidence;
            var effects = evidence.EffectsOf(adapter.Initializer.MDToken.Raw);
            if (!result.Succeeded || evidence.ObservationsTruncated || !effects.AllInvocationsCompleted || effects.WroteMappedImage ||
                effects.WroteScratchRegion || effects.Registrations.Count != 0 || effects.StaticFieldsWritten.Any(f => !fields.Contains(f)))
            { reason = "initializer has incomplete or non-private effects"; return false; }
            if (evidence.Observations.Count == 0 || evidence.Observations.Any(o => o.Kind != LoaderObservationKind.ManagedResourceRead ||
                JsonSerializer.Deserialize<ManagedResourceRead>(o.Detail) is not { } read || read.Name != bundle.Source.Name ||
                read.Sha256 != bundle.Source.Sha256 || read.Length != source.CreateReader().Length))
            { reason = "initializer observations are not confined to the attributed bundle"; return false; }
            var payloads = machine.State.CapturedAssemblyLoads;
            if (payloads.Count != 1 || !IsPreservedResourceSatellite(payloads[0], bundle))
            { reason = "loaded satellite is not exactly the restored resource-only assembly"; return false; }
            var hash = Convert.ToHexString(SHA256.HashData(payloads[0]));
            if (first is not null && (!first.Agrees(evidence) || hash != firstPayload))
            { reason = "independent initializer trials disagree"; return false; }
            first = evidence; firstPayload = hash;
        }
        reason = ""; return true;
    }

    internal static bool IsPreservedResourceSatellite(byte[] bytes, RestoredResourceBundle bundle)
    {
        try
        {
            using var module = ModuleDefMD.Load(bytes, new ModuleCreationOptions { TryToLoadPdbFromDisk = false });
            var types = module.GetTypes().ToArray();
            if (module.EntryPoint is not null || types.Length != 1 || !types[0].IsGlobalModuleType ||
                types[0].Methods.Count != 0 || types[0].Fields.Count != 0 || module.Resources.Count != bundle.Entries.Count) return false;
            return bundle.Entries.Count != 0 && bundle.Entries.All(e => module.Resources.Count(r => r.Name == e.Name) == 1 &&
                module.Resources.OfType<EmbeddedResource>().Count(e.Matches) == 1);
        }
        catch (BadImageFormatException) { return false; }
    }
}

public sealed class ResourceEnumerationRuntimeCleanupPass : RuntimeCleanupPass
{
    public override string Name => "resource-enumeration-runtime-cleanup";
    public override IReadOnlyCollection<string> Dependencies => ["resource-enumeration-completion"];
    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context) =>
        context.TryGetFact<bool>(ResourceEnumerationCompletionPass.ChangedFact, out var changed) && changed
            ? base.Execute(context) : (PassStatus.Success, 0, ["No resource adapter was replaced."]);
}
