using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Replaces closed bundle decoding with recovered bytes, retaining resolver behavior.</summary>
public sealed class DependencyDecoderCompletionPass : DeobfuscationPass
{
    internal const string ChangedFact = "dependency.decoderRetired";
    internal const string AddedMethodsFact = "dependency.addedMethods";
    internal const string AddedTypesFact = "dependency.addedTypes";
    internal const string AddedFieldsFact = "dependency.addedFields";
    internal const string ReplacementsFact = "dependency.decoderReplacements";
    internal sealed record Replacement(EmbeddedDependencyRecoveryPass.ValidatedIndex Index, MethodDef Helper);
    public override string Name => "dependency-decoder-completion";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => ["embedded-dependency-recovery"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        context.SetFact(ChangedFact, false);
        if (!context.TryGetFact<bool>("options.removeRuntime", out var enabled) || !enabled ||
            !context.TryGetFact<IReadOnlyList<EmbeddedDependencyRecoveryPass.ValidatedDecoderInput>>(
                EmbeddedDependencyRecoveryPass.DecoderInputsFact, out var inputs) || inputs is null)
            return (PassStatus.Success, 0, ["No closed embedded dependency decoder requires replacement."]);
        var changed = 0;
        var replacements = new List<Replacement>();
        var notes = new List<string>();
        foreach (var input in inputs.DistinctBy(p => p.Decoder).Take(2))
        {
            // Facts are hints; validate source bytes, all callers, index ownership,
            // and consumers again against the current module before any mutation.
            var index = input.Index;
            var resources = context.Module.Resources.OfType<EmbeddedResource>().Where(index.Index.Source.Matches).ToArray();
            if (resources.Length != 1 || !DependencyIndexConstruction.TryRead(index.Constructor, resources[0], out var current, out _) || current is null ||
                !DependencyIndexSource.Check(index.Resolver, index.Constructor, current, out _) ||
                !DependencyIndexConsumers.Check(index.Resolver, index.Constructor, current, out _)) continue;
            index = new(index.Resolver, index.Constructor, current, true, true);
            if (!DependencySliceSource.TryRead(index, input.Decoder, out var slices, out _) || slices.Count == 0 ||
                slices.Any(s => !s.Bytes.AsSpan().SequenceEqual(slices[0].Bytes) || !OnlyToArray(index.Resolver, s.Call))) continue;
            if (!ClosedDependencyDecoder.TryRead(context, input.Decoder, slices[0].Bytes, out var decoded, out var reason) || decoded is null)
            { notes.Add($"{input.Decoder.FullName}: {reason}"); continue; }
            if (decoded.Bytes.Length > 1024 * 1024)
            { notes.Add($"{input.Decoder.FullName}: recovered data exceeds the 1 MiB replacement bound."); continue; }
            var holder = BuildHolder(context.Module, decoded);
            using var edit = new BodyMutationBatch([index.Resolver]);
            context.Module.Types.Add(holder);
            var committed = false;
            try
            {
                foreach (var slice in slices) slice.Call.Operand = holder.Methods[0];
                var allowance = CilantroPipeline.BuildRewriteAllowance(context);
                var verification = AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
                    allowance with { AddedTypeCount = allowance.AddedTypeCount + 1 + holder.NestedTypes.Count,
                        AddedMethodCount = allowance.AddedMethodCount + 1, AddedFieldCount = allowance.AddedFieldCount + holder.Fields.Count });
                if (!verification.Passed)
                { notes.Add($"{input.Decoder.FullName}: replacement failed structural verification: {string.Join("; ", verification.Diagnostics.Take(3))}"); continue; }
                edit.RecordChange(context, new ChangeRecord(Name, "replace-dependency-decoder", input.Decoder.FullName,
                    $"Replaced fixed bundle decoding with {decoded.Bytes.Length} recovered bytes; preserved {decoded.Initializers.Count} shared initializer(s) and all resolver selection/loading code."));
                edit.Commit(); committed = true;
                AddCount(AddedMethodsFact, 1);
                AddCount(AddedTypesFact, 1 + holder.NestedTypes.Count);
                AddCount(AddedFieldsFact, holder.Fields.Count);
                RecoveryOrphans.DeclareOwningTypes(context, [input.Decoder]);
                replacements.Add(new(index, holder.Methods[0]));
                changed++;
            }
            finally { if (!committed) { edit.Rollback(); context.Module.Types.Remove(holder); } }
        }
        context.SetFact(ChangedFact, changed != 0);
        context.SetFact<IReadOnlyList<Replacement>>(ReplacementsFact, replacements);
        return (PassStatus.Success, changed, [$"Replaced {changed} closed dependency decoder(s).", .. notes.Take(6)]);

        void AddCount(string fact, int count)
        {
            context.TryGetFact<int>(fact, out var previous);
            context.SetFact(fact, previous + count);
        }
    }

    internal static bool OnlyToArray(MethodDef caller, Instruction call)
    {
        if (!caller.HasBody) return false;
        var il = caller.Body.Instructions;
        var index = il.IndexOf(call);
        if (index < 0) return false;
        var consumed = new HashSet<Instruction>();
        Instruction? Next()
        {
            while (++index < il.Count)
            {
                consumed.Add(il[index]);
                if (il[index].OpCode.Code != Code.Nop) return il[index];
            }
            return null;
        }
        var use = Next();
        var casts = 0;
        while (use?.OpCode.Code == Code.Castclass)
        {
            if (use.Operand is not TypeRef type || type.FullName != "System.IO.MemoryStream" ||
                !DependencyFrameworkScope.Matches(type, caller.Module)) return false;
            casts++;
            use = Next();
        }
        if (casts == 0) return false;
        if (use?.OpCode.Code != Code.Callvirt || use.Operand is not MemberRef method ||
            method.FullName != "System.Byte[] System.IO.MemoryStream::ToArray()" ||
            !DependencyFrameworkScope.Matches(method.DeclaringType, caller.Module)) return false;
        return !il.Any(i => i.Operand is Instruction target && consumed.Contains(target) ||
            i.Operand is IList<Instruction> targets && targets.Any(consumed.Contains)) &&
            !caller.Body.ExceptionHandlers.Any(h => new[] { h.TryStart, h.TryEnd, h.HandlerStart, h.HandlerEnd, h.FilterStart }.Any(i => i is not null && consumed.Contains(i)));
    }

    internal static TypeDef BuildHolder(ModuleDef module, ClosedDependencyDecoder.Result decoded)
    {
        var name = "RecoveredDependency";
        var suffix = 0;
        while (module.Types.Any(t => t.Namespace == "Cilantro.Recovered" && t.Name == name)) name = "RecoveredDependency" + ++suffix;
        var holder = new TypeDefUser("Cilantro.Recovered", name, module.CorLibTypes.Object.TypeDefOrRef)
        { Attributes = TypeAttributes.NotPublic | TypeAttributes.Abstract | TypeAttributes.Sealed };
        FieldDef? data = null;
        if (decoded.Bytes.Length != 0)
        {
            var dataType = new TypeDefUser("", "Data", module.CorLibTypes.GetTypeRef("System", "ValueType"))
            { Attributes = TypeAttributes.NestedPrivate | TypeAttributes.Sealed | TypeAttributes.ExplicitLayout,
                ClassLayout = new ClassLayoutUser(1, (uint)decoded.Bytes.Length) };
            holder.NestedTypes.Add(dataType);
            data = new FieldDefUser("Bytes", new FieldSig(new ValueTypeSig(dataType)),
                FieldAttributes.Private | FieldAttributes.Static | FieldAttributes.InitOnly | FieldAttributes.HasFieldRVA)
            { InitialValue = decoded.Bytes.ToArray() };
            holder.Fields.Add(data);
        }
        var method = new MethodDefUser("Open", MethodSig.CreateStatic(module.CorLibTypes.GetTypeRef("System.IO", "Stream").ToTypeSig(), module.CorLibTypes.Object))
        { Attributes = MethodAttributes.Assembly | MethodAttributes.Static, Body = new CilBody() };
        holder.Methods.Add(method);
        var il = method.Body.Instructions;
        var helpers = module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "RuntimeHelpers");
        foreach (var type in decoded.Initializers)
        {
            il.Add(OpCodes.Ldtoken.ToInstruction(type));
            il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "RunClassConstructor",
                MethodSig.CreateStatic(module.CorLibTypes.Void, new ValueTypeSig(module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle"))), helpers)));
        }
        il.Add(Instruction.CreateLdcI4(decoded.Bytes.Length));
        il.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Byte.TypeDefOrRef));
        if (data is not null)
        {
            il.Add(OpCodes.Dup.ToInstruction()); il.Add(OpCodes.Ldtoken.ToInstruction(data));
            il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "InitializeArray",
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.GetTypeRef("System", "Array").ToTypeSig(),
                    new ValueTypeSig(module.CorLibTypes.GetTypeRef("System", "RuntimeFieldHandle"))), helpers)));
        }
        il.Add(OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void, new SZArraySig(module.CorLibTypes.Byte)), module.CorLibTypes.GetTypeRef("System.IO", "MemoryStream"))));
        il.Add(OpCodes.Ret.ToInstruction());
        return holder;
    }
}

public sealed class DependencyRuntimeCleanupPass : RuntimeCleanupPass
{
    public override string Name => "dependency-runtime-cleanup";
    public override IReadOnlyCollection<string> Dependencies => ["dependency-input-completion"];
    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context) =>
        context.TryGetFact<bool>(DependencyDecoderCompletionPass.ChangedFact, out var changed) && changed
            ? base.Execute(context) : (PassStatus.Success, 0, ["No dependency decoder was replaced."]);
}
