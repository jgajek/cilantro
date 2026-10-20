using System.Buffers.Binary;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Replaces a completely recovered Babel bundle with ordinary dependency files.</summary>
public sealed class BabelDependencyDeploymentPass : DeobfuscationPass
{
    internal const string Fact = "babel.dependencies.deployment";
    internal sealed record Dependency(string Name, byte[] Bytes);
    public override string Name => "babel-dependency-deployment";
    public override IReadOnlyCollection<string> Dependencies => ["embedded-dependency-recovery"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("options.removeRuntime", out var enabled) || !enabled ||
            !context.TryGetFact<IReadOnlyList<EmbeddedDependencyRecoveryPass.ValidatedIndex>>(EmbeddedDependencyRecoveryPass.IndexesFact, out var indexes) || indexes is null)
            return (PassStatus.Success, 0, ["No complete Babel dependency deployment is available."]);
        var notes = new List<string>(); var deployed = new List<Dependency>(); var retired = new HashSet<MethodDef>();
        foreach (var index in indexes)
        {
            var shape = BabelEmbeddingShape.Find(context.Module).SingleOrDefault(s => s.Resolve == index.Resolver && s.Index == index.Constructor);
            if (shape is null || !index.SourceClosed || !index.ConsumersClosed) continue;
            using var original = ModuleDefMD.Load(context.OriginalBytes);
            using var current = Copy(context.Module);
            var before = BabelEmbeddingShape.Find(original).SingleOrDefault(s => s.Install.MDToken == shape.Install.MDToken);
            var now = BabelEmbeddingShape.Find(current).SingleOrDefault(s => s.Install.FullName == shape.Install.FullName);
            var sourceDescription = before is null ? null : BabelEmbeddingShape.Describe(before);
            var description = now is null ? null : BabelEmbeddingShape.Describe(now);
            if (sourceDescription is null || description is null || sourceDescription.Data != description.Data ||
                !BabelEmbeddingShape.ReviewedPair(sourceDescription.Fingerprint, description.Fingerprint))
            { notes.Add("The complete original/current Babel assembly loader is unreviewed; retained its bundle and hook."); continue; }
            if (!TryDependencies(context, index, shape, description.LengthKey, out var files, out var initializers, out var why))
            { notes.Add(why); continue; }
            if (deployed.Concat(files).GroupBy(d => d.Name, StringComparer.OrdinalIgnoreCase).Any(g => g.Skip(1).Any(d => !d.Bytes.AsSpan().SequenceEqual(g.First().Bytes))))
            { notes.Add("Conflicting dependency names prevent ordinary deployment."); continue; }
            var family = new[] { shape.Install.DeclaringType }.Concat(shape.Install.DeclaringType.NestedTypes).ToHashSet();
            var survivors = context.Module.GetTypes().Where(t => !family.Contains(t)).ToArray();
            if (survivors.SelectMany(t => t.Methods).Where(m => m.HasBody).SelectMany(m => m.Body.Instructions).Any(i => i.Operand is string text &&
                family.Any(t => text == t.FullName || text == t.ReflectionFullName || text.StartsWith(t.ReflectionFullName + ",", StringComparison.Ordinal)))) continue;
            var calls = survivors.SelectMany(t => t.Methods).Where(m => m.HasBody).SelectMany(m => m.Body.Instructions.Select(i => (Method: m, Instruction: i)))
                .Where(p => p.Instruction.OpCode.Code == Code.Call && p.Instruction.Operand is IMethod call && call.ResolveMethodDef() == shape.Install).ToArray();
            if (calls.Length == 0) continue;
            using var batch = new BodyMutationBatch(calls.Select(p => p.Method).Distinct());
            foreach (var call in calls)
            {
                var replacement = initializers.SelectMany(type => new[] { OpCodes.Ldtoken.ToInstruction(type), OpCodes.Call.ToInstruction(new MemberRefUser(context.Module,
                    "RunClassConstructor", MethodSig.CreateStatic(context.Module.CorLibTypes.Void, new ValueTypeSig(context.Module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle"))),
                    context.Module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "RuntimeHelpers"))) }).ToArray();
                if (replacement.Length == 0) { call.Instruction.OpCode = OpCodes.Nop; call.Instruction.Operand = null; }
                else
                {
                    var il = call.Method.Body.Instructions; var at = il.IndexOf(call.Instruction);
                    call.Instruction.OpCode = replacement[0].OpCode; call.Instruction.Operand = replacement[0].Operand;
                    for (var n = 1; n < replacement.Length; n++) il.Insert(at + n, replacement[n]);
                }
            }
            if (RuntimeCleanupPass.CollectReferencedCandidates(context.Module, survivors, family).Count != 0) continue;
            var owner = shape.Install.DeclaringType; var position = context.Module.Types.IndexOf(owner);
            if (position < 0) continue;
            var methods = family.SelectMany(t => t.Methods).ToArray();
            var methodTokens = methods.Where(m => m.Rid != 0).Select(m => m.MDToken.Raw).ToHashSet();
            var api = family.SelectMany(ArtifactIdentitySnapshot.PublicApiEntries).ToHashSet(StringComparer.Ordinal);
            var fields = family.Sum(t => t.Fields.Count);
            var resourceOwner = new DecodedResourceOwnership(index.Index.Source, [shape.Resolve], [], null);
            var allowance = CilantroPipeline.BuildRewriteAllowance(context);
            var committed = false;
            try
            {
                context.Module.Types.Remove(owner);
                var result = AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
                    allowance with { RemovedTypeCount = allowance.RemovedTypeCount + family.Count, RemovedFieldCount = allowance.RemovedFieldCount + fields,
                        RemovedMethodTokens = allowance.RemovedMethodTokenSet.Concat(methodTokens).ToHashSet(), RemovedPublicApi = allowance.RemovedPublicApiSet.Concat(api).ToHashSet(StringComparer.Ordinal) });
                if (!result.Passed) { notes.Add("Babel loader removal failed structural verification: " + string.Join("; ", result.Diagnostics.Take(2))); continue; }
                batch.RecordChange(context, new(Name, "deploy-babel-dependencies", owner.FullName,
                    $"Retired the complete assembly resolver and {calls.Length} registration call(s); preserved {initializers.Count} closed shared initializer(s) and deploy {files.Count} recovered dependency file(s) for ordinary runtime binding."));
                batch.Commit(); committed = true;
                Add("cleanup.removedTypeCount", family.Count); Add("cleanup.removedFieldCount", fields);
                context.SetFact<IReadOnlySet<uint>>("cleanup.removedMethodTokens", allowance.RemovedMethodTokenSet.Concat(methodTokens).ToHashSet());
                context.SetFact<IReadOnlySet<string>>("cleanup.removedPublicApi", allowance.RemovedPublicApiSet.Concat(api).ToHashSet(StringComparer.Ordinal));
                context.TryGetFact<IReadOnlyList<DecodedResourceOwnership>>(DecodedResourceOwnership.Fact, out var resources);
                context.SetFact<IReadOnlyList<DecodedResourceOwnership>>(DecodedResourceOwnership.Fact, [.. resources ?? [], resourceOwner]);
                RecoveryOrphans.DeclareOwningTypes(context, [shape.Codec]);
                deployed.AddRange(files); retired.Add(index.Resolver);
            }
            finally { if (!committed) context.Module.Types.Insert(position, owner); }
        }
        context.SetFact<IReadOnlyList<Dependency>>(Fact, deployed.DistinctBy(d => d.Name, StringComparer.OrdinalIgnoreCase).ToArray());
        context.SetFact<IReadOnlyList<EmbeddedDependencyRecoveryPass.ValidatedIndex>>(EmbeddedDependencyRecoveryPass.IndexesFact, indexes.Where(i => !retired.Contains(i.Resolver)).ToArray());
        return (PassStatus.Success, retired.Count, [$"Replaced {retired.Count} complete Babel bundle loader(s) with {deployed.Count} ordinary dependency file(s).", .. notes]);

        void Add(string fact, int value) { context.TryGetFact<int>(fact, out var old); context.SetFact(fact, old + value); }
    }

    private static bool TryDependencies(ArtifactContext context, EmbeddedDependencyRecoveryPass.ValidatedIndex index, BabelEmbeddingShape.Resolver shape,
        int key, out IReadOnlyList<Dependency> files, out IReadOnlyList<TypeDef> initializers, out string why)
    {
        files = []; initializers = []; why = "Babel dependency table or decoder is not completely closed.";
        var source = context.Module.Resources.OfType<EmbeddedResource>().SingleOrDefault(index.Index.Source.Matches);
        if (source is null || !DependencyIndexConstruction.TryRead(index.Constructor, source, out var snapshot, out _) || snapshot is null ||
            !DependencyIndexCompletionPass.Equivalent(index.Index, snapshot) || !DependencyIndexSource.Check(index.Resolver, index.Constructor, snapshot, out _) ||
            !DependencyIndexConsumers.Check(index.Resolver, index.Constructor, snapshot, out _)) return false;
        var data = source.CreateReader().ToArray(); var dependencies = new List<Dependency>(); var initialization = new List<TypeDef>();
        foreach (var entry in snapshot.Entries)
        {
            var offsets = entry.Values.Where(p => p.Key.FieldType.ElementType == ElementType.I8).Select(p => p.Value).ToArray();
            if (offsets.Length != 1 || entry.Values.Where(p => p.Key.FieldType.ElementType == ElementType.I4).Any(p => p.Value != 0) ||
                offsets[0] < 0 || offsets[0] > data.Length - 4) return false;
            var offset = (int)offsets[0]; var length = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset, 4)) ^ key;
            if (length < 0 || length > data.Length - offset - 4 || length > 16 * 1024 * 1024) return false;
            if (!ClosedDependencyDecoder.TryRead(context, shape.Codec, data.AsSpan(offset + 4, length).ToArray(), out var decoded, out why) || decoded is null) return false;
            foreach (var type in decoded.Initializers) if (!initialization.Contains(type)) initialization.Add(type);
            using var image = ModuleDefMD.Load(decoded.Bytes);
            if (image.Assembly is not { } assembly || assembly.FullName != entry.Name || !string.IsNullOrEmpty(assembly.Culture.String) ||
                assembly.Name.String is not { Length: > 0 and <= 200 } name || name is "." or ".." || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
                name.Contains('/') || name.Contains('\\') || name.Equals(context.Module.Assembly?.Name.String, StringComparison.OrdinalIgnoreCase))
            { why = $"Dependency identity mismatch: table={entry.Name}; image={image.Assembly?.FullName}; culture={image.Assembly?.Culture}."; return false; }
            if (!EmbeddedDependencyRecoveryPass.TryRead(context, shape.Resolve, entry.Name, new StaticWorkBudget(64_000_000), out var capture, out why) ||
                capture is null || capture.Source != index.Index.Source || !capture.Payload.Bytes.AsSpan().SequenceEqual(decoded.Bytes)) return false;
            dependencies.Add(new(name + ".dll", decoded.Bytes));
        }
        if (dependencies.Count == 0 || dependencies.Select(d => d.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() != dependencies.Count) return false;
        files = dependencies; initializers = initialization; return true;
    }

    private static ModuleDefMD Copy(ModuleDef module)
    {
        var forms = module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody).SelectMany(m => m.Body.Instructions)
            .Where(i => i.OpCode.OperandType == OperandType.ShortInlineBrTarget).Select(i => (Instruction: i, i.OpCode)).ToArray();
        try { BranchForms.Reach(module); using var bytes = new MemoryStream(); module.Write(bytes); return ModuleDefMD.Load(bytes.ToArray()); }
        finally { foreach (var form in forms) form.Instruction.OpCode = form.OpCode; }
    }
}
