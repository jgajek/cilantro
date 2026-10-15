using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Materializes a closed resource-backed index without its string/offset decoding loop.</summary>
public sealed class DependencyIndexCompletionPass : DeobfuscationPass
{
    internal const string MaterializedFact = "dependency.materializedIndexes";
    internal sealed record Materialized(EmbeddedDependencyRecoveryPass.ValidatedIndex Index, IReadOnlyList<Instruction> Body);
    public override string Name => "dependency-index-completion";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => ["dependency-decoder-completion"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("options.removeRuntime", out var enabled) || !enabled ||
            !context.TryGetFact<IReadOnlyList<EmbeddedDependencyRecoveryPass.ValidatedIndex>>(
                EmbeddedDependencyRecoveryPass.IndexesFact, out var indexes) || indexes is null)
            return (PassStatus.Success, 0, ["No dependency index requires materialization."]);
        var count = 0;
        var materialized = new List<Materialized>();
        var notes = new List<string>();
        foreach (var candidate in indexes.DistinctBy(i => i.Constructor).Take(4))
        {
            var resources = context.Module.Resources.OfType<EmbeddedResource>().Where(candidate.Index.Source.Matches).ToArray();
            if (resources.Length != 1 || !DependencyIndexConstruction.TryRead(candidate.Constructor, resources[0], out var index, out _) ||
                index is null || !index.CanMaterialize || !DependencyIndexSource.Check(candidate.Resolver, candidate.Constructor, index, out _) ||
                !DependencyIndexConsumers.Check(candidate.Resolver, candidate.Constructor, index, out _)) continue;
            using var edit = new BodyMutationBatch([candidate.Constructor]);
            candidate.Constructor.Body = Materialize(candidate.Constructor, index);
            // Re-evaluate the emitted construction as well. Compare integer values,
            // publication sequence, record aliasing and final source-stream position.
            if (!DependencyIndexConstruction.TryRead(candidate.Constructor, resources[0], out var after, out var reason) || after is null ||
                !Equivalent(index, after))
            { notes.Add($"{candidate.Constructor.FullName}: replacement construction did not agree: {reason}"); continue; }
            var verification = AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
                CilantroPipeline.BuildRewriteAllowance(context));
            if (!verification.Passed)
            { notes.Add($"{candidate.Constructor.FullName}: replacement failed structural verification."); continue; }
            edit.RecordChange(context, new ChangeRecord(Name, "materialize-dependency-index", candidate.Constructor.FullName,
                $"Replaced bundle-index decoding with {index.Publications.Count} explicit table publication(s); preserved constructor arguments, record aliases and source-stream position."));
            edit.Commit(); count++;
            materialized.Add(new(new(candidate.Resolver, candidate.Constructor, after, true, true), candidate.Constructor.Body.Instructions.ToArray()));
        }
        context.SetFact<IReadOnlyList<Materialized>>(MaterializedFact, materialized);
        return (PassStatus.Success, count, [$"Materialized {count} closed dependency index(es).", .. notes.Take(6)]);
    }

    internal static bool Equivalent(DependencyIndexConstruction.Snapshot before, DependencyIndexConstruction.Snapshot after) =>
        before.Source == after.Source && before.Table == after.Table && before.Position == after.Position &&
        before.Entries.Count == after.Entries.Count && before.Entries.Zip(after.Entries).All(p => Same(p.First, p.Second)) &&
        before.Publications.Count == after.Publications.Count && before.Publications.Zip(after.Publications).All(p => Same(p.First, p.Second));

    private static bool Same(DependencyIndexConstruction.Entry a, DependencyIndexConstruction.Entry b) =>
        a.Name == b.Name && a.Type == b.Type && a.Values.Count == b.Values.Count &&
        a.Values.All(v => b.Values.TryGetValue(v.Key, out var value) && value == v.Value) &&
        a.Allocation is { } x && b.Allocation is { } y && x.Constructor == y.Constructor &&
        x.Identity == y.Identity && x.Arguments.SequenceEqual(y.Arguments);

    internal static CilBody Materialize(MethodDef method, DependencyIndexConstruction.Snapshot index)
    {
        var module = method.Module;
        var body = new CilBody { InitLocals = true };
        var il = body.Instructions;
        var table = module.CorLibTypes.GetTypeRef("System.Collections", "Hashtable");
        var text = module.CorLibTypes.String.TypeDefOrRef;
        var objects = new Dictionary<int, Local>();
        il.Add(OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), table)));
        il.Add(OpCodes.Stsfld.ToInstruction(index.Table));
        foreach (var entry in index.Publications)
        {
            var allocation = entry.Allocation!;
            il.Add(OpCodes.Ldsfld.ToInstruction(index.Table));
            il.Add(OpCodes.Ldstr.ToInstruction(entry.Name));
            // Decoded nonempty keys were fresh strings, not interned literals.
            il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "ToCharArray",
                MethodSig.CreateInstance(new SZArraySig(module.CorLibTypes.Char)), text)));
            il.Add(OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void, new SZArraySig(module.CorLibTypes.Char)), text)));
            if (objects.TryGetValue(allocation.Identity, out var instance)) il.Add(OpCodes.Ldloc.ToInstruction(instance));
            else
            {
                for (var n = 0; n < allocation.Arguments.Count; n++)
                    il.Add(allocation.Constructor.MethodSig.Params[n].ElementType == ElementType.I8
                        ? OpCodes.Ldc_I8.ToInstruction(allocation.Arguments[n]) : Instruction.CreateLdcI4(unchecked((int)allocation.Arguments[n])));
                il.Add(OpCodes.Newobj.ToInstruction(allocation.Constructor));
                foreach (var field in index.PostConstructionFields.Where(f => f.DeclaringType == entry.Type).OrderBy(f => f.MDToken.Raw))
                {
                    il.Add(OpCodes.Dup.ToInstruction());
                    il.Add(field.FieldType.ElementType == ElementType.I8 ? OpCodes.Ldc_I8.ToInstruction(entry.Values[field])
                        : Instruction.CreateLdcI4(unchecked((int)entry.Values[field])));
                    il.Add(OpCodes.Stfld.ToInstruction(field));
                }
                instance = new Local(entry.Type.ToTypeSig()); body.Variables.Add(instance); objects.Add(allocation.Identity, instance);
                il.Add(OpCodes.Dup.ToInstruction()); il.Add(OpCodes.Stloc.ToInstruction(instance));
            }
            il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "set_Item",
                MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.Object), table)));
        }
        var stream = module.CorLibTypes.GetTypeRef("System.IO", "Stream");
        il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Castclass.ToInstruction(stream));
        il.Add(OpCodes.Ldc_I8.ToInstruction(index.Position)); il.Add(OpCodes.Ldc_I4_0.ToInstruction());
        il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "Seek",
            MethodSig.CreateInstance(module.CorLibTypes.Int64, module.CorLibTypes.Int64,
                new ValueTypeSig(module.CorLibTypes.GetTypeRef("System.IO", "SeekOrigin"))), stream)));
        il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction());
        return body;
    }
}
