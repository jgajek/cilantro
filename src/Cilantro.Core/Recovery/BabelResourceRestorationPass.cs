using System.Security.Cryptography;
using System.Text.Json;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Restores complete resource-only satellites and retires their reviewed Babel chooser.</summary>
public sealed class BabelResourceRestorationPass : DeobfuscationPass
{
    public override string Name => "babel-resource-restoration";
    public override IReadOnlyCollection<string> Dependencies => ["babel-resource-completion", "babel-checks"];
    internal const string AddedFact = "babel.resources.added";
    internal const string RestoredFact = "babel.resources.restored";
    private sealed record Entry(string Name, byte[] Bytes, ManifestResourceAttributes Attributes);
    private sealed record Capture(RecoveredResourceOrigin Source, IReadOnlyList<Entry> Entries, byte[] Image);

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<BabelStructureFacts>("babel.structure", out var facts) || facts?.IsBabel != true ||
            !context.TryGetFact<bool>("options.removeRuntime", out var enabled) || !enabled)
            return (PassStatus.Success, 0, ["Babel resource restoration/runtime removal is not enabled."]);
        using var original = ModuleDefMD.Load(context.OriginalBytes);
        var resolvers = BabelResourceShape.Find(original).ToArray();
        if (resolvers.Length == 0) return (PassStatus.Success, 0, ["No closed Babel resource chooser found."]);
        if (resolvers.Length > 8) return (PassStatus.Unsupported, 0, ["Babel resource chooser count exceeds its bound."]);
        var captures = new List<(BabelResourceShape.Resolver Resolver, Capture Data, string Fingerprint)>();
        var work = new StaticWorkBudget(64_000_000);
        foreach (var resolver in resolvers)
        {
            using var proof = ModuleDefMD.Load(context.OriginalBytes);
            var shape = BabelResourceShape.Find(proof).Single(candidate => candidate.Handler.MDToken == resolver.Handler.MDToken);
            if (!BabelResourceShape.TryDescribe(shape, out var fingerprint) || !BabelResourceShape.Reviewed(fingerprint))
                return (PassStatus.Unsupported, 0, [$"Unreviewed Babel resource chooser {fingerprint}; encrypted resources and hooks retained."]);
            var first = Read(context, resolver.Handler.MDToken.Raw, 0, work, out var why);
            var second = first is null ? null : Read(context, resolver.Handler.MDToken.Raw, 7919, work, out why);
            if (first is null || second is null || !Agrees(first, second))
                return (PassStatus.Unsupported, 0, [$"Babel resource chooser could not be completely verified: {Short(why)}"]);
            captures.Add((resolver, first, fingerprint));
        }
        var entries = new Dictionary<string, Entry>(StringComparer.Ordinal);
        foreach (var entry in captures.SelectMany(capture => capture.Data.Entries))
        {
            if (entries.TryGetValue(entry.Name, out var duplicate) && !duplicate.Bytes.AsSpan().SequenceEqual(entry.Bytes))
                return (PassStatus.Unsupported, 0, ["Babel resource choosers disagree on a resource name."]);
            entries[entry.Name] = entry;
            var existing = context.Module.Resources.Where(resource => resource.Name == entry.Name).ToArray();
            if (existing.Length > 1 || existing.Length == 1 && (existing[0] is not EmbeddedResource embedded || !embedded.CreateReader().ToArray().AsSpan().SequenceEqual(entry.Bytes)))
                return (PassStatus.Unsupported, 0, [$"Babel resource '{entry.Name}' conflicts with existing metadata; no changes made."]);
        }
        var added = new List<EmbeddedResource>();
        using var batch = new BodyMutationBatch();
        var committed = false;
        try
        {
            foreach (var entry in entries.Values.Where(entry => !context.Module.Resources.Any(resource => resource.Name == entry.Name)))
            {
                var resource = new EmbeddedResource(entry.Name, entry.Bytes, entry.Attributes);
                context.Module.Resources.Add(resource); added.Add(resource);
            }
            foreach (var capture in captures)
            {
                var initializer = (MethodDef)context.Module.ResolveToken(capture.Resolver.Initializer.MDToken);
                foreach (var caller in context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody))
                    foreach (var call in caller.Body.Instructions.Where(instruction => instruction.OpCode.Code == Code.Call &&
                                 instruction.Operand is IMethod called && called.ResolveMethodDef() == initializer).ToArray())
                    { batch.Capture(caller); call.OpCode = OpCodes.Nop; call.Operand = null; }
                batch.Capture(initializer); initializer.Body = new CilBody(); initializer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            }
            var old = CilantroPipeline.BuildRewriteAllowance(context);
            var allowed = old.AddedResourceSet.Concat(added.Select(resource => resource.Name.String)).ToHashSet(StringComparer.Ordinal);
            if (!AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure, old with { AddedResources = allowed }).Passed)
                return (PassStatus.Unsupported, 0, ["Babel resource restoration did not pass structural verification; all changes rolled back."]);
            batch.Commit(); committed = true;
        }
        finally { if (!committed) foreach (var resource in added) context.Module.Resources.Remove(resource); }
        context.TryGetFact<IReadOnlySet<string>>(AddedFact, out var previous);
        context.SetFact<IReadOnlySet<string>>(AddedFact, (previous ?? new HashSet<string>()).Concat(added.Select(resource => resource.Name.String)).ToHashSet(StringComparer.Ordinal));
        context.SetFact(RestoredFact, captures.Count);
        foreach (var capture in captures)
        {
            var initializer = (MethodDef)context.Module.ResolveToken(capture.Resolver.Initializer.MDToken);
            var reader = (MethodDef)context.Module.ResolveToken(capture.Resolver.Reader.MDToken);
            var bundle = new RestoredResourceBundle(capture.Data.Source, capture.Data.Entries.Select(entry => new RecoveredResourceOrigin(entry.Name, Hash(entry.Bytes))).ToArray());
            DecodedResourceOwnership.Remember(context, capture.Data.Source, [reader], bundle: bundle);
            RecoveryOrphans.DeclareOwningTypes(context, [initializer]);
            context.AddChange(new(Name, "restore-babel-resource-satellite", initializer.FullName,
                $"Restored {capture.Data.Entries.Count} resources and retired the reviewed ResourceResolve initializer; graph {capture.Fingerprint}."));
        }
        return (PassStatus.Success, added.Count, [$"Restored {added.Count} named resources from {captures.Count} resource-only Babel satellites; retired their reviewed resolve hooks."]);
    }

    private static Capture? Read(ArtifactContext context, uint handler, int seed, StaticWorkBudget work, out string why)
    {
        why = "resource interpretation did not complete";
        using var module = ModuleDefMD.Load(context.OriginalBytes);
        var embeddedResources = module.Resources.OfType<EmbeddedResource>().ToArray();
        if (embeddedResources.Length > 64 || embeddedResources.Sum(resource => (long)resource.Length) > 64 * 1024 * 1024)
        { why = "resource input exceeds the construction budget"; return null; }
        var resolver = BabelResourceShape.Find(module).Single(candidate => candidate.Handler.MDToken.Raw == handler);
        var graph = GeneratedRuntimeShape.Read(resolver.Handler);
        if (graph.Types.Count > 32 || graph.Fingerprint.Contains(' ')) return null;
        var allowedFields = resolver.Initializer.DeclaringType.Fields.Select(field => field.FullName).ToHashSet(StringComparer.Ordinal);
        var machine = new StaticMachine(BootstrapMachine.Limits(64_000_000), modelTypeInitialization: true);
        machine.State.RegisterModuleMetadata(module);
        // Portable images must agree under both supported CLR pointer sizes.
        var pointerSize = context.OriginalImage.IsPe32Plus ? 8 : module.Is32BitRequired || seed == 0 ? 4 : 8;
        machine.State.RegisterPointerSize(pointerSize);
        machine.State.RegisterAssemblyIdentity(module.Assembly?.Name ?? module.Name, module.Assembly?.PublicKeyToken?.Data ?? []);
        machine.State.RegisterModuleFile(context.InputPath, context.OriginalBytes);
        machine.State.RegisterRunEnvironment(new(new(HostProfile.Parse($"{{\"facts\":{{\"guid:Seed\":{seed}}}}}", "Babel resource construction"))));
        foreach (var resource in embeddedResources) machine.State.RegisterResource(resource.Name, resource.CreateReader().ToArray());
        var startup = machine.Execute(resolver.Initializer, [], work);
        if (!startup.Succeeded) { why = startup.Diagnostic ?? startup.Status.ToString(); return null; }
        if (!machine.State.Heap.TryAllocateObject("System.ResolveEventArgs", out var raised)) return null;
        StaticExecutionResult Invoke(string name)
        {
            if (!machine.State.Heap.TryAllocateString(name, out var text)) throw new InvalidOperationException("Resource name allocation failed.");
            machine.State.Heap.TrySetModelValue(raised, "Name", text);
            return machine.Execute(resolver.Handler, [StaticValue.Null, raised], work);
        }
        try
        {
            var cold = Invoke("Cilantro.ResourceResolution.Probe");
            if (!cold.Succeeded) { why = cold.Diagnostic ?? cold.Status.ToString(); return null; }
            if (machine.State.CapturedAssemblyLoads.Count != 1 || !machine.State.Heap.TryGetLength(machine.State.ReadStaticField(resolver.Names), out var count) || count is < 1 or > 1024)
                return null;
            var names = new HashSet<string>(StringComparer.Ordinal);
            for (var index = 0; index < count; index++)
            {
                if (!machine.State.Heap.TryReadArray(machine.State.ReadStaticField(resolver.Names), index, out var value) ||
                    !machine.State.Heap.TryGetString(value, out var name) || name is not { Length: > 0 and <= 4096 } || !names.Add(name)) return null;
            }
            var image = machine.State.CapturedAssemblyLoads[0];
            if (image.Length > 32 * 1024 * 1024) return null;
            using var satellite = ModuleDefMD.Load(image);
            if (!IsResourceOnly(satellite, names)) { why = "loaded assembly is not a complete resource-only satellite matching the chooser table"; return null; }
            foreach (var name in names)
            {
                var reply = Invoke(name);
                if (!reply.Succeeded || !machine.State.Heap.TryGetModelValue<byte[]>(reply.Value, "LoadedImage", out var returned) || returned is null || !returned.AsSpan().SequenceEqual(image)) return null;
            }
            var missing = "Cilantro.ResourceResolution.Missing";
            while (names.Contains(missing)) missing += "_";
            var absent = Invoke(missing);
            if (!absent.Succeeded || absent.Value.Kind != StaticValueKind.Null || machine.State.CapturedAssemblyLoads.Count != 1) return null;
            var evidence = machine.State.LoaderEvidence;
            if (evidence.ObservationsTruncated || evidence.Effects.Values.Any(effect => effect.WroteMappedImage || effect.WroteScratchRegion ||
                    effect.StaticFieldsWritten.Any(field => !allowedFields.Contains(field)) || effect.Registrations.Any(registration => registration != "AppDomain.ResourceResolve")) ||
                evidence.EffectsOf(resolver.Handler.MDToken.Raw).Registrations.Count != 0 ||
                evidence.Observations.Any(observation => observation.Kind is LoaderObservationKind.DeclaredCall or LoaderObservationKind.SteppedCall or LoaderObservationKind.HostQuestion or LoaderObservationKind.Termination))
            { why = "resource construction changed state outside the reviewed chooser or used an unbound host input"; return null; }
            var reads = evidence.Observations.Where(observation => observation.Kind == LoaderObservationKind.ManagedResourceRead)
                .Select(observation => JsonSerializer.Deserialize<ManagedResourceRead>(observation.Detail)).OfType<ManagedResourceRead>().Distinct().ToArray();
            if (reads.Length != 1 || !module.Resources.OfType<EmbeddedResource>().Any(resource => resource.Name == reads[0].Name && Hash(resource.CreateReader().ToArray()) == reads[0].Sha256)) return null;
            var entries = satellite.Resources.OfType<EmbeddedResource>().Select(resource => new Entry(resource.Name, resource.CreateReader().ToArray(), resource.Attributes)).ToArray();
            why = "independent resource trials disagreed";
            return new(new(reads[0].Name, reads[0].Sha256), entries, image);
        }
        catch (Exception exception) when (exception is InvalidOperationException or ArgumentException or IOException or BadImageFormatException)
        { why = exception.Message; return null; }
    }

    internal static bool IsResourceOnly(ModuleDef satellite, IReadOnlySet<string> names) => satellite.Assembly is not null && satellite.IsILOnly &&
        satellite.EntryPoint is null && (uint)satellite.NativeEntryPoint == 0 && names.Count > 0 &&
        satellite.GetTypes().All(type => type.IsGlobalModuleType && type.Methods.Count == 0 && type.Fields.Count == 0) &&
        satellite.Resources.Count == names.Count && satellite.Resources.All(resource => resource is EmbeddedResource) &&
        names.SetEquals(satellite.Resources.Select(resource => resource.Name.String));

    private static bool Agrees(Capture first, Capture second) => first.Source == second.Source && first.Image.AsSpan().SequenceEqual(second.Image) &&
        first.Entries.Count == second.Entries.Count && first.Entries.Zip(second.Entries).All(pair => pair.First.Name == pair.Second.Name &&
            pair.First.Attributes == pair.Second.Attributes && pair.First.Bytes.AsSpan().SequenceEqual(pair.Second.Bytes));
    private static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    private static string Short(string text) => text.Length > 1200 ? text[..1200] + "…" : text;
}
