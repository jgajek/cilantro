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
        foreach (var (method, instruction, index) in methods.SelectMany(m => m.Body.Instructions.Select((i, n) => (m, i, n))))
            if (instruction.OpCode.Code == Code.Ldtoken && instruction.Operand is ITypeDefOrRef type && type.ResolveTypeDef() is { } definition &&
                !ModuleReachability.IsInitializerOnlyHandle(method, index) && !ResourceLookupTypeHandleUse.IsClosed(method, index) &&
                !TypeIdentityHandleUse.IsClosed(method, index))
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
        var restoredFields = RestoreAddressedFields(context, methods, candidates);
        candidates.RemoveWhere(f => f.FieldType.ElementType != ElementType.Object);
        var arrays = new Dictionary<FieldDef, TypeSig>();
        var reads = new List<(MethodDef Method, Instruction Read, FieldDef Field)>();
        var writers = new Dictionary<FieldDef, List<(MethodDef Method, int Index, ControlFlowGraph Graph)>>();
        var flowGraphs = new Dictionary<MethodDef, ControlFlowGraph>();
        foreach (var method in methods)
        {
            var graph = flowGraphs[method] = ControlFlowGraph.Build(method);
            var il = method.Body.Instructions;
            for (var index = 0; index < il.Count; index++)
            {
                var instruction = il[index];
                if (instruction.Operand is not IField reference || reference.ResolveFieldDef() is not { } field || !candidates.Contains(field)) continue;
                if (reference != field || instruction.OpCode.Code is not (Code.Ldfld or Code.Ldsfld or Code.Stfld or Code.Stsfld))
                { candidates.Remove(field); continue; }
                if (instruction.OpCode.Code is Code.Ldfld or Code.Ldsfld)
                { reads.Add((method, instruction, field)); continue; }
                if (!writers.TryGetValue(field, out var sites)) writers[field] = sites = [];
                sites.Add((method, index, graph));
            }
        }
        // A closed field with no non-null writer has independent null evidence.
        // Its consumer may select a reference stack type because casting null
        // cannot change the value. Unknown writers/addresses still veto it.
        var nullProofAllowed = !methods.SelectMany(m => m.Body.Instructions).Select(i => i.Operand)
            .OfType<IMethod>().Any(call => call.MethodSig is not null &&
                (call.DeclaringType.FullName.StartsWith("System.Reflection.Emit.", StringComparison.Ordinal) ||
                 call.Name.String is "SetValue" or "SetValueDirect" && call.DeclaringType.FullName is "System.Reflection.FieldInfo" or "System.Reflection.RtFieldInfo"));
        var readsByField = reads.ToLookup(r => r.Field);
        foreach (var field in candidates.Where(f => nullProofAllowed && HasClosedSignatureBoundary(f) && !f.HasConstant && !f.HasFieldRVA && !f.HasMarshalType))
        {
            if (writers.TryGetValue(field, out var sites) && sites.Any(s =>
                StoredProducer(s.Method, s.Index, s.Graph)?.OpCode.Code != Code.Ldnull)) continue;
            TypeSig? common = null;
            var valid = true;
            foreach (var read in readsByField[field])
            {
                var type = NullOnlyReadType(read.Method, read.Read, flowGraphs[read.Method]);
                if (type is null || common is not null && !new SigComparer().Equals(common, type)) { valid = false; break; }
                common = type;
            }
            if (valid && common is not null) arrays[field] = common;
        }
        IReadOnlyDictionary<Parameter, ArrayParameterTypingPass.CallerValue[]>? parameterInputs = null;
        // Prove all writers before publishing a field's type. A copy may become
        // concrete in a later round, but an unknown/conflicting writer must never
        // be ignored. Cycles without a proved source remain unknown.
        for (var round = 0; round < 32; round++)
        {
            var before = arrays.Count;
            foreach (var field in candidates.Where(f => !arrays.ContainsKey(f)))
            {
                if (!writers.TryGetValue(field, out var sites)) continue;
                TypeSig? agreed = null;
                var valid = true;
                var pending = new Stack<FieldDef>(); pending.Push(field);
                var stores = new Stack<(MethodDef Method, int Index, ControlFlowGraph Graph)>();
                var values = new Stack<ArrayParameterTypingPass.CallerValue>();
                var visitedParameters = new HashSet<Parameter>();
                var valueCount = 0;
                var visited = new HashSet<FieldDef>();
                var visitedLocals = new HashSet<(MethodDef, Local)>();
                var visitedStores = new HashSet<(MethodDef, int)>();
                while (valid && (pending.Count != 0 || stores.Count != 0 || values.Count != 0))
                {
                    if (pending.TryPop(out var source))
                    {
                        if (!visited.Add(source)) continue;
                        if (visited.Count > 512 || !writers.TryGetValue(source, out sites)) { valid = false; break; }
                        foreach (var site in sites) stores.Push(site);
                        continue;
                    }
                    if (values.TryPop(out var value))
                    {
                        if (++valueCount > 16384) { valid = false; break; }
                        if (value.IsNull) continue;
                        if (value.Type is { ContainsGenericParameter: false } supplied &&
                            (TypeLabel == "array" ? supplied is SZArraySig or ArraySig :
                                supplied.ElementType == ElementType.String || supplied is ClassSig || supplied is GenericInstSig { GenericType: ClassSig }))
                        {
                            if (agreed is not null && !new SigComparer().Equals(agreed, supplied)) { valid = false; break; }
                            agreed = supplied;
                        }
                        else if (value.Field is { } copied && candidates.Contains(copied)) pending.Push(copied);
                        else if (value.Source is { } parameter)
                        {
                            // Analyze current call sites rather than caching origins across
                            // intervening rewrites. Eligibility includes reflection/handle and
                            // visibility checks, and every caller and starg assignment.
                            parameterInputs ??= ArrayParameterTypingPass.ClosedInputs(context);
                            if (!parameterInputs.TryGetValue(parameter, out var suppliedInputs)) { valid = false; break; }
                            if (!visitedParameters.Add(parameter)) continue;
                            if (visitedParameters.Count > 512) { valid = false; break; }
                            foreach (var input in suppliedInputs) values.Push(input);
                        }
                        else if (value.LocalMethod is { } localMethod && value.Local is { } local)
                        {
                            var body = localMethod.Body;
                            if (!body.InitLocals || body.Instructions.Any(i =>
                                i.OpCode.Code is Code.Ldloca or Code.Ldloca_S && i.Operand == local)) { valid = false; break; }
                            if (!visitedLocals.Add((localMethod, local))) continue;
                            if (visitedLocals.Count > 512) { valid = false; break; }
                            var graph = flowGraphs[localMethod];
                            foreach (var assignment in body.Instructions.Where(i => i.IsStloc() && i.GetLocal(body.Variables) == local))
                                stores.Push((localMethod, body.Instructions.IndexOf(assignment), graph));
                        }
                        else { valid = false; break; }
                        continue;
                    }
                    var storedAt = stores.Pop();
                    if (!visitedStores.Add((storedAt.Method, storedAt.Index))) continue;
                    // Bound the combined field/local graph, including diamonds and cycles.
                    if (visitedStores.Count > 16384) { valid = false; break; }
                    var il = storedAt.Method.Body.Instructions;
                    var previous = storedAt.Index - 1;
                    while (previous >= 0 && il[previous].OpCode.Code == Code.Nop) previous--;
                    if (previous >= 0 && il[previous].OpCode.Code == Code.Ldnull &&
                        storedAt.Graph.BlockOf(il[previous]) == storedAt.Graph.BlockOf(il[storedAt.Index])) continue;
                    if (TryStoredType(storedAt.Method, storedAt.Index, storedAt.Graph, out var stored, arrays))
                    {
                        if (agreed is not null && !new SigComparer().Equals(agreed, stored)) { valid = false; break; }
                        agreed = stored;
                    }
                    else if (StoredField(storedAt.Method, storedAt.Index, storedAt.Graph) is { } copied && candidates.Contains(copied))
                        pending.Push(copied);
                    else if (StoredProducer(storedAt.Method, storedAt.Index, storedAt.Graph) is { } producer)
                    {
                        if (producer.IsLdarg()) values.Push(new(null, Source: producer.GetParameter(storedAt.Method.Parameters)));
                        else if (producer.IsLdloc()) values.Push(new(null, LocalMethod: storedAt.Method,
                            Local: producer.GetLocal(storedAt.Method.Body.Variables)));
                        else { valid = false; break; }
                    }
                    else { valid = false; break; }
                }
                if (valid && agreed is not null) arrays.Add(field, agreed);
            }
            if (arrays.Count == before) break;
        }
        var plans = reads.Where(p => candidates.Contains(p.Field) && arrays.ContainsKey(p.Field) &&
            !AlreadyTyped(p.Method, p.Read, arrays[p.Field])).ToArray();
        if (plans.Length == 0) return (PassStatus.Success, restoredFields, [restoredFields > 0 ? $"Restored {restoredFields} closed {TypeLabel} field signature(s) from verified reference consumers." : $"No erased {TypeLabel} field had closed, consistently typed writers."]);
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

    private int RestoreAddressedFields(ArtifactContext context, MethodDef[] methods, HashSet<FieldDef> candidates)
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
        foreach (var field in candidates.Where(f => HasClosedSignatureBoundary(f) && !f.IsInitOnly && f.DeclaringType.IsAutoLayout && !f.DeclaringType.IsValueType))
        {
            var references = uses[field].ToArray();
            TypeSig? array = null;
            var valid = references.Length != 0;
            foreach (var use in references)
            {
                if (use.Instruction.Operand != field) { valid = false; break; }
                if (use.Instruction.OpCode.Code is Code.Ldfld or Code.Ldsfld or Code.Stfld or Code.Stsfld) continue;
                if (use.Instruction.OpCode.Code is not (Code.Ldflda or Code.Ldsflda) ||
                    !(TypeLabel == "array" && ResizeAddressType(use.Method, use.Instruction, Graph(use.Method), out var type) || ClosedArrayReferenceUse.TryGetType(use.Method, use.Instruction, Graph(use.Method), out type, references: TypeLabel == "reference")) ||
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
                if (!TryStoredType(use.Method, index, Graph(use.Method), out var stored) ||
                    !(new SigComparer().Equals(array, stored) || TypeLabel == "array" &&
                        ClosedArrayReferenceUse.IsCoreArray(array, context.Module) && stored is SZArraySig or ArraySig))
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
            context.AddChange(new(Name, $"restore-addressed-{TypeLabel}-field-type", plan.Key.FullName,
                $"Restored closed {TypeLabel} field signature: all address uses are verified local reference consumers, exact array resize calls or explicit COM SAFEARRAY output contracts, and all direct writers supply compatible types or null."));
        return plans.Count;
    }

    private static bool HasClosedSignatureBoundary(FieldDef field)
    {
        if (field.IsPrivate) return true;
        for (var owner = field.DeclaringType; owner is not null; owner = owner.DeclaringType)
            if (owner.IsNestedPrivate) return true;
        // Internal fields/types are closed only when no friend assembly can use
        // their signatures. Public/protected fields on public types were excluded
        // above; serialization, reflection handles and metadata aliases also veto.
        return (field.IsAssembly || field.IsFamilyAndAssembly) && field.Module.Assembly is { } assembly &&
            !assembly.CustomAttributes.Any(a => a.TypeFullName == "System.Runtime.CompilerServices.InternalsVisibleToAttribute") &&
            !ArtifactIdentitySnapshot.InPublicApi(field);
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
    protected virtual TypeSig? NullOnlyReadType(MethodDef method, Instruction read, ControlFlowGraph graph) => null;
    private static FieldDef? StoredField(MethodDef method, int store, ControlFlowGraph graph) =>
        StoredProducer(method, store, graph) is { OpCode.Code: Code.Ldfld or Code.Ldsfld, Operand: FieldDef source } &&
        !source.DeclaringType.HasGenericParameters ? source : null;

    protected static Instruction? StoredProducer(MethodDef method, int store, ControlFlowGraph graph)
    {
        var il = method.Body.Instructions;
        var block = graph.BlockOf(il[store]);
        var slot = 0;
        for (var n = store - 1; n >= 0 && graph.BlockOf(il[n]) == block; n--)
        {
            var instruction = il[n];
            instruction.CalculateStackUsage(out var pushes, out var pops);
            if (pops < 0) return null;
            if (slot < pushes)
            {
                if (instruction.OpCode.Code == Code.Dup) { slot = 0; continue; }
                return instruction;
            }
            slot = slot - pushes + pops;
        }
        return null;
    }

    protected static TypeSig? IndirectReferenceType(MethodDef method, int read, ControlFlowGraph graph)
    {
        // A declared managed reference establishes the pointee type independently
        // of the field's consumers. Never guess across a block boundary.
        var producer = StoredProducer(method, read, graph);
        if (producer is null) return null;
        TypeSig? address = producer.IsLdarg() ? producer.GetParameter(method.Parameters)?.Type :
            producer.IsLdloc() ? producer.GetLocal(method.Body.Variables)?.Type :
            producer.OpCode.Code is Code.Ldflda or Code.Ldsflda && producer.Operand is IField field &&
                !field.DeclaringType.ToTypeSig().ContainsGenericParameter ? new ByRefSig(field.FieldSig.Type) :
            producer.OpCode.Code == Code.Ldelema && producer.Operand is ITypeDefOrRef element ? new ByRefSig(element.ToTypeSig()) :
            producer.OpCode.Code is Code.Call or Code.Callvirt && producer.Operand is IMethod call ? ArrayParameterTypingPass.ReturnedType(call) : null;
        return address is ByRefSig reference ? reference.Next : null;
    }

    protected virtual bool TryStoredType(MethodDef method, int store, ControlFlowGraph graph, out TypeSig type,
        IReadOnlyDictionary<FieldDef, TypeSig>? provenFields = null)
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
                    instruction.OpCode.Code is Code.Ldfld or Code.Ldsfld && instruction.Operand is FieldDef source &&
                        !source.DeclaringType.HasGenericParameters ? provenFields?.GetValueOrDefault(source, source.FieldType) ?? source.FieldType :
                    instruction.OpCode.Code is Code.Castclass or Code.Isinst && instruction.Operand is ITypeDefOrRef cast ? cast.ToTypeSig() :
                    instruction.OpCode.Code == Code.Newobj && instruction.Operand is IMethod constructor ? constructor.DeclaringType.ToTypeSig() :
                    instruction.OpCode.Code == Code.Newarr && instruction.Operand is ITypeDefOrRef element ? new SZArraySig(element.ToTypeSig()) :
                    instruction.OpCode.Code is Code.Call or Code.Callvirt && instruction.Operand is IMethod call ? ArrayParameterTypingPass.ReturnedType(call) :
                    instruction.OpCode.Code == Code.Ldind_Ref ? IndirectReferenceType(method, index, graph) : null;
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
