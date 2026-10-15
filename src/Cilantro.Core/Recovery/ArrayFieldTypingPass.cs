using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Restores array stack types from typed producers at every closed field writer.</summary>
public class ArrayFieldTypingPass : DeobfuscationPass
{
    public override string Name => "array-field-typing";
    public override IReadOnlyCollection<string> Dependencies => ["array-parameter-typing"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var methods = context.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody).ToArray();
        var exposed = ModuleReachability.Compute(context.Module).ReflectivelyExposedTypes.ToHashSet();
        foreach (var instruction in methods.SelectMany(m => m.Body.Instructions))
            if (instruction.OpCode.Code == Code.Ldtoken && instruction.Operand is ITypeDefOrRef type && type.ResolveTypeDef() is { } definition)
                exposed.Add(definition);
        var names = methods.SelectMany(m => m.Body.Instructions).Select(i => i.Operand).OfType<string>().ToHashSet(StringComparer.Ordinal);
        var candidates = context.Module.GetTypes().Where(t => !t.HasGenericParameters && !t.IsExplicitLayout && !t.IsSerializable && !exposed.Contains(t))
            .SelectMany(t => t.Fields).Where(f => f.FieldType.ElementType == ElementType.Object && !f.IsLiteral &&
                !(MemberVisibility.IsExternallyVisible(f.DeclaringType) && (f.IsPublic || f.IsFamily || f.IsFamilyOrAssembly)) &&
                !names.Contains(f.Name.String) && !names.Contains(f.FullName)).ToHashSet();
        // A field handle/address or unresolved metadata alias can hide an additional
        // writer. Keep signatures intact and refuse these cases rather than guessing.
        foreach (var reference in context.Module.GetMemberRefs().Where(r => r.IsFieldRef))
            if (reference.ResolveFieldDef() is { } field) candidates.Remove(field);
        var restoredFields = TypeLabel == "array" ? RestoreAddressedArrayFields(context, methods, candidates) : 0;
        candidates.RemoveWhere(f => f.FieldType.ElementType != ElementType.Object);
        var arrays = new Dictionary<FieldDef, TypeSig>();
        var reads = new List<(MethodDef Method, Instruction Read, FieldDef Field)>();
        foreach (var method in methods)
        {
            var graph = ControlFlowGraph.Build(method);
            var il = method.Body.Instructions;
            for (var index = 0; index < il.Count; index++)
            {
                var instruction = il[index];
                if (instruction.Operand is not IField reference || reference.ResolveFieldDef() is not { } field || !candidates.Contains(field)) continue;
                if (reference != field || instruction.OpCode.Code is not (Code.Ldfld or Code.Ldsfld or Code.Stfld or Code.Stsfld))
                { candidates.Remove(field); continue; }
                if (instruction.OpCode.Code is Code.Ldfld or Code.Ldsfld)
                { reads.Add((method, instruction, field)); continue; }
                var previous = index - 1;
                while (previous >= 0 && il[previous].OpCode.Code == Code.Nop) previous--;
                if (previous < 0)
                { candidates.Remove(field); continue; }
                // Null is also the default value before any writer has run. At least
                // one concrete typed producer is still needed to establish the type.
                if (il[previous].OpCode.Code == Code.Ldnull && graph.BlockOf(il[previous]) == graph.BlockOf(instruction)) continue;
                if (!TryStoredType(method, index, graph, out var array))
                { candidates.Remove(field); continue; }
                if (arrays.TryGetValue(field, out var old) && !new SigComparer().Equals(old, array)) candidates.Remove(field);
                else arrays[field] = array;
            }
        }
        var plans = reads.Where(p => candidates.Contains(p.Field) && arrays.ContainsKey(p.Field) &&
            !AlreadyTyped(p.Method, p.Read, arrays[p.Field])).ToArray();
        if (plans.Length == 0) return (PassStatus.Success, restoredFields, [restoredFields > 0 ? $"Restored {restoredFields} private array field signature(s) from closed array-reference evidence." : $"No erased {TypeLabel} field had closed, consistently typed writers."]);
        using var transaction = new BodyMutationBatch(plans.Select(p => p.Method).Distinct().ToArray());
        foreach (var plan in plans)
            plan.Method.Body.Instructions.Insert(plan.Method.Body.Instructions.IndexOf(plan.Read) + 1,
                OpCodes.Castclass.ToInstruction(arrays[plan.Field].ToTypeDefOrRef()));
        foreach (var method in plans.Select(p => p.Method).Distinct()) method.Body.SimplifyBranches();
        var verification = AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
            CilantroPipeline.BuildRewriteAllowance(context));
        if (!verification.Passed) return (PassStatus.Partial, restoredFields, [$"{TypeLabel} field typing rolled back after structural verification."]);
        transaction.Commit();
        foreach (var group in plans.GroupBy(p => p.Field))
            context.AddChange(new(Name, ChangeKind, group.Key.FullName,
                $"Restored {arrays[group.Key].FullName} at {group.Count()} field read(s); every writer already supplies this {TypeLabel} type or null. Field signature unchanged."));
        return (PassStatus.Success, plans.Length + restoredFields, [$"Restored {TypeLabel} stack types at {plans.Length} field read(s)."]);
    }

    private int RestoreAddressedArrayFields(ArtifactContext context, MethodDef[] methods, HashSet<FieldDef> candidates)
    {
        var uses = methods.SelectMany(m => m.Body.Instructions.Where(i => i.Operand is IField)
            .Select(i => (Method: m, Instruction: i, Field: ((IField)i.Operand).ResolveFieldDef()))).ToLookup(u => u.Field);
        var graphs = new Dictionary<MethodDef, ControlFlowGraph>();
        ControlFlowGraph Graph(MethodDef method)
        {
            if (!graphs.TryGetValue(method, out var graph)) graphs[method] = graph = ControlFlowGraph.Build(method);
            return graph;
        }
        var plans = new Dictionary<FieldDef, TypeSig>();
        foreach (var field in candidates.Where(f => HasPrivateBoundary(f) && !f.IsInitOnly && f.DeclaringType.IsAutoLayout && !f.DeclaringType.IsValueType))
        {
            var references = uses[field].ToArray();
            TypeSig? array = null;
            var valid = references.Length != 0;
            foreach (var use in references)
            {
                if (use.Instruction.Operand != field) { valid = false; break; }
                if (use.Instruction.OpCode.Code is Code.Ldfld or Code.Ldsfld or Code.Stfld or Code.Stsfld) continue;
                if (use.Instruction.OpCode.Code is not (Code.Ldflda or Code.Ldsflda) ||
                    !(ResizeAddressType(use.Method, use.Instruction, Graph(use.Method), out var type) || ClosedArrayReferenceUse.TryGetType(use.Method, use.Instruction, Graph(use.Method), out type)) ||
                    array is not null && !new SigComparer().Equals(array, type)) { valid = false; break; }
                array = type;
            }
            if (!valid || array is null) continue;
            foreach (var use in references.Where(u => u.Instruction.OpCode.Code is Code.Stfld or Code.Stsfld))
            {
                var il = use.Method.Body.Instructions;
                var index = il.IndexOf(use.Instruction);
                var previous = index - 1;
                while (previous >= 0 && il[previous].OpCode.Code == Code.Nop) previous--;
                if (previous >= 0 && il[previous].OpCode.Code == Code.Ldnull &&
                    Graph(use.Method).BlockOf(il[previous]) == Graph(use.Method).BlockOf(use.Instruction)) continue;
                if (!TryStoredType(use.Method, index, Graph(use.Method), out var stored) || !new SigComparer().Equals(array, stored))
                { valid = false; break; }
            }
            if (valid) plans[field] = array;
        }
        if (plans.Count == 0) return 0;
        var originals = plans.Keys.ToDictionary(f => f, f => f.FieldSig);
        var committed = false;
        try
        {
            foreach (var plan in plans) plan.Key.FieldSig = new FieldSig(plan.Value);
            if (!AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
                CilantroPipeline.BuildRewriteAllowance(context)).Passed) return 0;
            committed = true;
        }
        finally
        {
            if (!committed) foreach (var original in originals) original.Key.FieldSig = original.Value;
        }
        foreach (var plan in plans)
            context.AddChange(new(Name, "restore-addressed-array-field-type", plan.Key.FullName,
                "Restored private array field signature: all address uses are exact Array.Resize calls or verified local array-reference consumers, and all direct writers supply the same array type or null."));
        return plans.Count;
    }

    private static bool HasPrivateBoundary(FieldDef field)
    {
        if (field.IsPrivate) return true;
        for (var owner = field.DeclaringType; owner is not null; owner = owner.DeclaringType)
            if (owner.IsNestedPrivate) return true;
        return false;
    }
    private static bool ResizeAddressType(MethodDef method, Instruction address, ControlFlowGraph graph, out TypeSig type)
    {
        type = null!;
        var block = graph.BlockOf(address).Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        var at = Array.IndexOf(block, address);
        if (at < 0 || at + 2 >= block.Length) return false;
        var size = block[at + 1];
        var sizeType = size.IsLdarg() ? size.GetParameter(method.Parameters)?.Type :
            size.IsLdloc() ? size.GetLocal(method.Body.Variables)?.Type : null;
        if (!size.IsLdcI4() && sizeType?.ElementType != ElementType.I4) return false;
        if (block[at + 2].OpCode.Code != Code.Call || block[at + 2].Operand is not MethodSpec call ||
            call.Name != "Resize" || call.DeclaringType is not TypeRef owner || owner.FullName != "System.Array" ||
            owner.DefinitionAssembly?.FullName != method.Module.CorLibTypes.AssemblyRef.FullName ||
            call.GenericInstMethodSig?.GenericArguments is not { Count: 1 } arguments || arguments[0].ContainsGenericParameter ||
            arguments[0].ElementType is ElementType.ByRef or ElementType.Ptr or ElementType.FnPtr or ElementType.TypedByRef or ElementType.Void ||
            call.Method.MethodSig is not { HasThis: false, ExplicitThis: false, GenParamCount: 1, Params.Count: 2 } signature ||
            !signature.Generic || (signature.CallingConvention & CallingConvention.Mask) != CallingConvention.Default ||
            signature.ParamsAfterSentinel?.Count is > 0 || signature.RetType.ElementType != ElementType.Void ||
            signature.Params[0] is not ByRefSig { Next: SZArraySig { Next: GenericMVar { Number: 0 } } } ||
            signature.Params[1].ElementType != ElementType.I4) return false;
        type = new SZArraySig(arguments[0]);
        return true;
    }
    protected virtual string TypeLabel => "array";
    protected virtual string ChangeKind => "restore-array-field-stack-type";
    protected virtual bool TryStoredType(MethodDef method, int store, ControlFlowGraph graph, out TypeSig type)
    {
        var il = method.Body.Instructions;
        type = null!;
        var block = graph.BlockOf(il[store]);
        var slot = 0;
        for (var index = store - 1; index >= 0 && graph.BlockOf(il[index]) == block; index--)
        {
            var instruction = il[index];
            instruction.CalculateStackUsage(out var pushes, out var pops);
            if (pops < 0) return false;
            if (slot < pushes)
            {
                if (instruction.OpCode.Code == Code.Dup) { slot = 0; continue; }
                TypeSig? produced = instruction.IsLdarg() ? instruction.GetParameter(method.Parameters)?.Type :
                    instruction.IsLdloc() ? instruction.GetLocal(method.Body.Variables)?.Type :
                    instruction.OpCode.Code is Code.Castclass or Code.Isinst && instruction.Operand is ITypeDefOrRef cast ? cast.ToTypeSig() :
                    instruction.OpCode.Code == Code.Newarr && instruction.Operand is ITypeDefOrRef element ? new SZArraySig(element.ToTypeSig()) :
                    instruction.OpCode.Code is Code.Call or Code.Callvirt && instruction.Operand is IMethod call ? ArrayParameterTypingPass.ReturnedType(call) : null;
                if (produced is not (SZArraySig or ArraySig) || produced.ContainsGenericParameter) return false;
                type = produced;
                return true;
            }
            slot = slot - pushes + pops;
        }
        return false;
    }
    private static bool AlreadyTyped(MethodDef method, Instruction read, TypeSig array)
    {
        var index = method.Body.Instructions.IndexOf(read) + 1;
        while (index < method.Body.Instructions.Count && method.Body.Instructions[index].OpCode.Code == Code.Nop) index++;
        return index < method.Body.Instructions.Count && method.Body.Instructions[index] is { OpCode.Code: Code.Castclass, Operand: ITypeDefOrRef type } &&
            new SigComparer().Equals(type.ToTypeSig(), array);
    }
}
