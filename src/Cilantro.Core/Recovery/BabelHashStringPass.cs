using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Materializes reviewed eager hash caches without interning their strings.</summary>
public sealed class BabelHashStringPass : DeobfuscationPass
{
    public override string Name => "babel-hash-strings";
    public override IReadOnlyCollection<string> Dependencies => ["babel-resource-restoration"];
    internal const string RecoveredFact = "babel.hashStrings.recovered";
    internal sealed record Entry(int Key, string Text, int Identity);
    private sealed record Capture(Entry[] Entries, RecoveredResourceOrigin Source);

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<BabelStructureFacts>("babel.structure", out var facts) || facts?.IsBabel != true ||
            !context.TryGetFact<bool>("options.removeRuntime", out var enabled) || !enabled)
            return (PassStatus.Success, 0, ["Babel hash cache removal is not enabled."]);
        using var original = ModuleDefMD.Load(context.OriginalBytes);
        var candidates = BabelHashStringShape.Find(original).ToArray();
        if (candidates.Length == 0) return (PassStatus.Success, 0, ["No eager Babel hash cache found."]);
        if (candidates.Length > 8) return (PassStatus.Unsupported, 0, ["Hash cache count exceeds the construction bound."]);
        var captures = new List<(BabelHashStringShape.Cache Cache, Capture Data)>();
        var work = new StaticWorkBudget(64_000_000);
        foreach (var candidate in candidates)
        {
            using var proof = ModuleDefMD.Load(context.OriginalBytes);
            var cache = BabelHashStringShape.Find(proof).Single(item => item.Wrapper.MDToken == candidate.Wrapper.MDToken);
            if (!BabelHashStringShape.TryDescribeCodec(cache.StreamDecoder, out var codec) || !BabelHashStringShape.ReviewedCodec(codec) ||
                !BabelHashStringShape.TryDescribe(cache, out var fingerprint) || !BabelHashStringShape.Reviewed(fingerprint))
                return (PassStatus.Unsupported, 0, ["Unreviewed Babel hash cache or stream codec; original cache retained."]);
            var first = Read(context, candidate.Wrapper.MDToken.Raw, 0, work, out var why);
            var second = first is null ? null : Read(context, candidate.Wrapper.MDToken.Raw, 7919, work, out why);
            if (first is null || second is null || first.Source != second.Source || !first.Entries.SequenceEqual(second.Entries))
                return (PassStatus.Unsupported, 0, [$"Babel hash cache construction could not be verified: {why}"]);
            captures.Add((candidate, first));
        }
        using var batch = new BodyMutationBatch();
        var orphaned = new List<MethodDef>();
        var ownedTypes = new HashSet<TypeDef>();
        foreach (var capture in captures)
        {
            var cache = BabelHashStringShape.Find(context.Module).Single(item => item.Wrapper.MDToken == capture.Cache.Wrapper.MDToken);
            // Save the old closure before removing its only construction edge.
            orphaned.AddRange(GeneratedRuntimeShape.Read(cache.StreamDecoder).Types.SelectMany(type => type.Methods));
            // The original complete codec was reviewed above. Include its methodless
            // layout helpers without extending ownership to new current-code edges.
            ownedTypes.UnionWith(GeneratedRuntimeShape.Read(capture.Cache.StreamDecoder).Types
                .Select(type => context.Module.ResolveToken(type.MDToken)).OfType<TypeDef>());
            orphaned.Add(cache.NamesDecoder);
            orphaned.AddRange(cache.Wrapper.DeclaringType.NestedTypes.Where(type => type != cache.Getter.DeclaringType).SelectMany(type => type.Methods));
            batch.Capture(cache.Constructor); batch.Capture(cache.Initializer);
            cache.Constructor.Body = BuildConstructor(cache, capture.Data.Entries);
            cache.Initializer.Body = new CilBody();
            cache.Initializer.Body.Instructions.Add(OpCodes.Newobj.ToInstruction(cache.Constructor));
            cache.Initializer.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(cache.Singleton));
            cache.Initializer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        }
        if (!AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure, CilantroPipeline.BuildRewriteAllowance(context)).Passed)
            return (PassStatus.Unsupported, 0, ["Materialized hash cache failed structural verification; original bodies restored."]);
        batch.Commit();
        RecoveryOrphans.Declare(context, orphaned);
        RecoveryOrphans.DeclareTypes(context, ownedTypes);
        var count = captures.Sum(capture => capture.Data.Entries.Length);
        context.SetFact(RecoveredFact, count);
        foreach (var capture in captures)
        {
            var cache = new BabelHashStringShape.Cache(
                (MethodDef)context.Module.ResolveToken(capture.Cache.Wrapper.MDToken),
                (MethodDef)context.Module.ResolveToken(capture.Cache.Getter.MDToken),
                (MethodDef)context.Module.ResolveToken(capture.Cache.Constructor.MDToken),
                (MethodDef)context.Module.ResolveToken(capture.Cache.Initializer.MDToken),
                (MethodDef)context.Module.ResolveToken(capture.Cache.NamesDecoder.MDToken),
                (MethodDef)context.Module.ResolveToken(capture.Cache.StreamDecoder.MDToken),
                (FieldDef)context.Module.ResolveToken(capture.Cache.Singleton.MDToken),
                (FieldDef)context.Module.ResolveToken(capture.Cache.Dictionary.MDToken));
            RetiredBabelHashResource.Remember(context, capture.Data.Source, cache);
            context.AddChange(new(Name, "materialize-babel-hash-cache", capture.Cache.Wrapper.FullName,
                $"Materialized {capture.Data.Entries.Length} integer-keyed strings after two complete original-byte construction trials; preserved dictionary lookup and non-interned string identity."));
        }
        return (PassStatus.Success, count, [$"Materialized {count} strings in {captures.Count} eager Babel hash caches."]);
    }

    private static Capture? Read(ArtifactContext context, uint wrapper, int seed, StaticWorkBudget work, out string why)
    {
        why = "incomplete or inconsistent construction";
        using var module = ModuleDefMD.Load(context.OriginalBytes);
        var cache = BabelHashStringShape.Find(module).Single(item => item.Wrapper.MDToken.Raw == wrapper);
        var resources = module.Resources.OfType<EmbeddedResource>().ToArray();
        if (resources.Length > 64 || resources.Sum(resource => (long)resource.Length) > 64 * 1024 * 1024) return null;
        var allowed = GeneratedRuntimeShape.Read(cache.StreamDecoder).Types.Concat([cache.Getter.DeclaringType])
            .SelectMany(type => type.Fields).Select(field => field.FullName).ToHashSet(StringComparer.Ordinal);
        var resolvers = BabelResourceShape.Find(module).ToArray();
        foreach (var resolver in resolvers)
        {
            using var proof = ModuleDefMD.Load(context.OriginalBytes);
            var copy = BabelResourceShape.Find(proof).Single(item => item.Handler.MDToken == resolver.Handler.MDToken);
            if (!BabelResourceShape.TryDescribe(copy, out var fingerprint) || !BabelResourceShape.Reviewed(fingerprint))
            { why = "unreviewed resource resolver"; return null; }
            allowed.UnionWith(resolver.Initializer.DeclaringType.Fields.Select(field => field.FullName));
        }
        var machine = new StaticMachine(BootstrapMachine.Limits(64_000_000), modelTypeInitialization: true);
        machine.State.RegisterModuleMetadata(module);
        machine.State.RegisterPointerSize(context.OriginalImage.IsPe32Plus ? 8 : module.Is32BitRequired || seed == 0 ? 4 : 8);
        machine.State.RegisterAssemblyIdentity(module.Assembly?.Name ?? module.Name, module.Assembly?.PublicKeyToken?.Data ?? []);
        machine.State.RegisterModuleFile(context.InputPath, context.OriginalBytes);
        machine.State.RegisterRunEnvironment(new(new(HostProfile.Parse($"{{\"facts\":{{\"guid:Seed\":{seed}}}}}", "Babel hash cache construction"))));
        foreach (var resource in resources) machine.State.RegisterResource(resource.Name, resource.CreateReader().ToArray());
        foreach (var resolver in resolvers)
            if (!machine.Execute(resolver.Initializer, [], work).Succeeded) return null;
        var result = machine.Execute(cache.Initializer, [], work);
        if (!result.Succeeded) { why = result.Diagnostic ?? result.Status.ToString(); return null; }
        var evidence = machine.State.LoaderEvidence;
        if (evidence.ObservationsTruncated || evidence.Effects.Values.Any(effect => !effect.AllInvocationsCompleted || effect.WroteMappedImage || effect.WroteScratchRegion ||
                effect.StaticFieldsWritten.Any(field => !allowed.Contains(field)) || effect.Registrations.Any(registration => registration != "AppDomain.ResourceResolve")) ||
            evidence.Observations.Any(observation => observation.Kind is LoaderObservationKind.DeclaredCall or LoaderObservationKind.SteppedCall or LoaderObservationKind.HostQuestion or LoaderObservationKind.Termination))
        { why = "construction used foreign state or unbound host input"; return null; }
        foreach (var image in machine.State.CapturedAssemblyLoads)
        {
            if (image.Length > 32 * 1024 * 1024) return null;
            using var satellite = ModuleDefMD.Load(image);
            if (!BabelResourceRestorationPass.IsResourceOnly(satellite, satellite.Resources.Select(resource => resource.Name.String).ToHashSet(StringComparer.Ordinal)))
            { why = "resource resolver loaded an assembly containing code"; return null; }
        }
        // Attribute the direct table read, not a satellite container read by a nested resolver.
        var reads = evidence.Observations.Where(observation => observation.Kind == LoaderObservationKind.ManagedResourceRead &&
                observation.CallStack.Count != 0 && observation.CallStack[^1] == cache.Constructor.MDToken.Raw)
            .Select(observation => System.Text.Json.JsonSerializer.Deserialize<ManagedResourceRead>(observation.Detail)).ToArray();
        if (reads.Length != 1 || reads[0] is not { } read) return null;
        var source = new RecoveredResourceOrigin(read.Name, read.Sha256);
        if (context.Module.Resources.Count(resource => resource.Name == source.Name) != 1 ||
            !context.Module.Resources.OfType<EmbeddedResource>().Any(resource => source.Matches(resource) && resource.Length == read.Length))
        { why = "the exact observed encrypted table is unavailable in current metadata"; return null; }
        if (!machine.State.Heap.TryReadField(machine.State.ReadStaticField(cache.Singleton), cache.Dictionary, out var dictionary) ||
            !machine.State.Heap.TryGetModelValue<List<KeyValuePair<StaticValue, StaticValue>>>(dictionary, "Pairs", out var pairs) || pairs is null || pairs.Count is < 1 or > 4096) return null;
        var entries = new List<Entry>();
        var identities = new Dictionary<StaticValue, int>();
        var keys = new HashSet<int>();
        foreach (var pair in pairs)
        {
            if (pair.Key.Kind != StaticValueKind.Int32 || !keys.Add(pair.Key.AsInt32()) ||
                !machine.State.Heap.TryGetString(pair.Value, out var text) || text is null) return null;
            if (!identities.TryGetValue(pair.Value, out var identity)) identities.Add(pair.Value, identity = identities.Count);
            entries.Add(new(pair.Key.AsInt32(), text, identity));
        }
        // Bound emitted CIL as well as interpreted work. Large caches remain intact.
        if (entries.Sum(entry => (long)entry.Text.Length) > 65_536) { why = "materialized CIL exceeds its size bound"; return null; }
        return new(entries.ToArray(), source);
    }

    internal static CilBody BuildConstructor(BabelHashStringShape.Cache cache, IReadOnlyList<Entry> entries)
    {
        var module = cache.Constructor.Module;
        var calls = cache.Constructor.Body.Instructions.Select(instruction => instruction.Operand).OfType<IMethod>().ToArray();
        var objectCtor = calls.First(call => call.Name == ".ctor" && call.DeclaringType.FullName == "System.Object");
        var dictionaryCtor = calls.Single(call => call.Name == ".ctor" && call.DeclaringType.FullName == cache.Dictionary.FieldType.FullName);
        var add = calls.Single(call => call.Name == "Add" && call.DeclaringType.FullName == cache.Dictionary.FieldType.FullName);
        var stringCtor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, new SZArraySig(module.CorLibTypes.Char)), module.CorLibTypes.String.TypeDefOrRef);
        var body = new CilBody { InitLocals = true };
        var il = body.Instructions;
        il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Call.ToInstruction(objectCtor));
        il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Newobj.ToInstruction(dictionaryCtor)); il.Add(OpCodes.Stfld.ToInstruction(cache.Dictionary));
        var locals = new Dictionary<int, Local>();
        foreach (var entry in entries)
        {
            if (!locals.TryGetValue(entry.Identity, out var local))
            {
                local = new Local(module.CorLibTypes.String); locals.Add(entry.Identity, local); body.Variables.Add(local);
                il.Add(Instruction.CreateLdcI4(entry.Text.Length)); il.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Char.TypeDefOrRef));
                for (var index = 0; index < entry.Text.Length; index++)
                {
                    il.Add(OpCodes.Dup.ToInstruction()); il.Add(Instruction.CreateLdcI4(index));
                    il.Add(Instruction.CreateLdcI4(entry.Text[index])); il.Add(OpCodes.Stelem_I2.ToInstruction());
                }
                il.Add(OpCodes.Newobj.ToInstruction(stringCtor)); il.Add(OpCodes.Stloc.ToInstruction(local));
            }
            il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Ldfld.ToInstruction(cache.Dictionary));
            il.Add(Instruction.CreateLdcI4(entry.Key)); il.Add(OpCodes.Ldloc.ToInstruction(local)); il.Add(OpCodes.Callvirt.ToInstruction(add));
        }
        il.Add(OpCodes.Ret.ToInstruction()); return body;
    }
}
