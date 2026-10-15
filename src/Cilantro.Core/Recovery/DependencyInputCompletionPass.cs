using Cilantro.Core.Verification;
using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Removes fixed bundle reads whose contents no longer reach application behavior.</summary>
public sealed class DependencyInputCompletionPass : DeobfuscationPass
{
    internal const string RetiredResourcesFact = "dependency.retiredBundleReads";
    public override string Name => "dependency-input-completion";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => ["dependency-index-completion"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("options.removeRuntime", out var enabled) || !enabled ||
            !context.TryGetFact<IReadOnlyList<DependencyDecoderCompletionPass.Replacement>>(
                DependencyDecoderCompletionPass.ReplacementsFact, out var replacements) || replacements is null ||
            !context.TryGetFact<IReadOnlyList<DependencyIndexCompletionPass.Materialized>>(
                DependencyIndexCompletionPass.MaterializedFact, out var indexes) || indexes is null)
            return (PassStatus.Success, 0, ["No completed dependency input path requires retirement."]);
        var count = 0;
        var notes = new List<string>();
        var retired = new List<RecoveredResourceOrigin>();
        var proofs = new List<RetiredDependencyResource>();
        foreach (var replacement in replacements.Take(2))
        {
            var matching = indexes.Where(i => i.Index.Constructor == replacement.Index.Constructor && i.Index.Resolver == replacement.Index.Resolver).ToArray();
            if (matching.Length != 1) continue;
            var index = matching[0].Index;
            var constructor = index.Constructor;
            // Only the exact materialized body from this run may lose its source
            // position update. Revalidate its semantics and complete source uses.
            if (!constructor.Body.Instructions.SequenceEqual(matching[0].Body) ||
                !DependencyIndexSource.Check(index.Resolver, constructor, index.Index, out _) ||
                !DependencyIndexConsumers.Check(index.Resolver, constructor, index.Index, out _) ||
                !DependencySliceSource.TryDiscard(index, replacement.Helper, out var plan, out var reason) || plan is null) continue;
            var resource = context.Module.Resources.OfType<EmbeddedResource>().SingleOrDefault(index.Index.Source.Matches);
            if (resource is null || !DependencyIndexConstruction.TryRead(constructor, resource, out var current, out _) || current is null ||
                !DependencyIndexCompletionPass.Equivalent(index.Index, current)) continue;
            var tail = constructor.Body.Instructions.TakeLast(7).ToArray();
            if (!IsPositionTail(constructor, tail, current.Position) || constructor.Body.Instructions.SkipLast(7)
                .Any(i => i.IsLdarg() || i.OpCode.Code is Code.Ldarga or Code.Ldarga_S or Code.Starg or Code.Starg_S)) continue;
            using var edit = new BodyMutationBatch([index.Resolver, constructor]);
            foreach (var read in plan.Reads)
                Replace(index.Resolver.Body, read.Call, [.. Enumerable.Range(0, read.Pops).Select(_ => OpCodes.Pop.ToInstruction()),
                    read.Wide ? OpCodes.Ldc_I8.ToInstruction(read.Value) : Instruction.CreateLdcI4(unchecked((int)read.Value)),
                    .. read.Native ? new[] { OpCodes.Conv_U.ToInstruction() } : []]);
            foreach (var allocation in plan.UnobservedAllocations)
                Replace(index.Resolver.Body, allocation, [OpCodes.Pop.ToInstruction(), OpCodes.Ldnull.ToInstruction()]);
            foreach (var cast in plan.RedundantCasts) { cast.OpCode = OpCodes.Nop; cast.Operand = null; }
            // Keep a fresh, non-null Stream identity. The proof forbids runtime
            // type inspection, escapes and any unmodeled use of this reference.
            Replace(index.Resolver.Body, plan.Open, [OpCodes.Pop.ToInstruction(), OpCodes.Pop.ToInstruction(),
                OpCodes.Newobj.ToInstruction(new MemberRefUser(context.Module, ".ctor", MethodSig.CreateInstance(context.Module.CorLibTypes.Void),
                    context.Module.CorLibTypes.GetTypeRef("System.IO", "MemoryStream")))]);
            foreach (var instruction in tail.Take(6)) { instruction.OpCode = OpCodes.Nop; instruction.Operand = null; }
            var verification = AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
                CilantroPipeline.BuildRewriteAllowance(context));
            if (!verification.Passed)
            { notes.Add($"{index.Resolver.FullName}: unused-input retirement failed structural verification."); continue; }
            edit.RecordChange(context, new ChangeRecord(Name, "retire-dependency-input", index.Resolver.FullName,
                $"Removed the {index.Index.Source.Name} bundle open, {plan.Reads.Count} fixed read/seek/length operation(s) and {plan.UnobservedAllocations.Count} unobserved input allocation(s); retained observed identities, selection, caching and loading."));
            edit.Commit(); count++;
            retired.Add(index.Index.Source);
            if (DependencyArrayCompletion.Apply(context, replacement.Helper) &&
                RetiredDependencyResource.Capture(index.Index.Source, index.Resolver, constructor, replacement.Helper) is { } proof)
                proofs.Add(proof);
        }
        context.SetFact<IReadOnlyList<RecoveredResourceOrigin>>(RetiredResourcesFact, retired);
        context.SetFact<IReadOnlyList<RetiredDependencyResource>>(RetiredDependencyResource.Fact, proofs);
        return (PassStatus.Success, count, [$"Retired {count} unused encrypted dependency input path(s). Resources require separate ownership checks.", .. notes.Take(6)]);
    }

    private static bool IsPositionTail(MethodDef method, Instruction[] tail, long position) => tail.Length == 7 &&
        tail[0].OpCode.Code == Code.Ldarg_0 && tail[1].OpCode.Code == Code.Castclass && tail[1].Operand is TypeRef stream &&
        stream.FullName == "System.IO.Stream" && stream.DefinitionAssembly?.FullName == method.Module.CorLibTypes.AssemblyRef.FullName &&
        tail[2].OpCode.Code == Code.Ldc_I8 && (long)tail[2].Operand == position && tail[3].IsLdcI4() && tail[3].GetLdcI4Value() == 0 &&
        tail[4].OpCode.Code == Code.Callvirt && tail[4].Operand is IMethod call &&
        call.FullName == "System.Int64 System.IO.Stream::Seek(System.Int64,System.IO.SeekOrigin)" &&
        call.DeclaringType.DefinitionAssembly?.FullName == method.Module.CorLibTypes.AssemblyRef.FullName &&
        tail[5].OpCode.Code == Code.Pop && tail[6].OpCode.Code == Code.Ret;

    private static void Replace(CilBody body, Instruction target, IReadOnlyList<Instruction> replacement)
    {
        // Keep the original instruction object for branch and EH boundary references.
        target.OpCode = replacement[0].OpCode; target.Operand = replacement[0].Operand;
        var at = body.Instructions.IndexOf(target);
        for (var n = 1; n < replacement.Count; n++) body.Instructions.Insert(at + n, replacement[n]);
    }
}
