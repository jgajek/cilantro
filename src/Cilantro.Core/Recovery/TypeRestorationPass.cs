using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Passes;
using Cilantro.Core.Verification;
using Cilantro.Core.Analysis;

namespace Cilantro.Core.Recovery;

/// <summary>
/// Restores concrete declared types to <c>System.Object</c> fields whose use is unambiguous.
/// </summary>
/// <remarks>
/// Reactor widens field declarations to <c>object</c> to erase type information, forcing readers
/// to guess. When every write to such a field provably stores the same concrete reference type,
/// that type is the field's real type and can be put back. The rewrite is deliberately minimal: it
/// changes only the field's signature, never any instruction. That is what keeps it sound without a
/// type checker. A reference upcast to <c>object</c> at read sites remains implicitly valid, an
/// existing <c>castclass</c> to the recovered type becomes redundant but stays legal, and because
/// no write boxes a value type, no <c>unbox</c> is ever stranded.
///
/// The pass is conservative on purpose. It touches only non-public fields, so the public-API
/// identity gate is never at stake; it promotes only to reference types, since a value-type
/// promotion would require rewriting box and unbox sites this pass will not attempt; and it demands
/// unanimous agreement across all writers, declining silently on any disagreement or any writer it
/// cannot attribute to a single type.
/// </remarks>
public sealed class TypeRestorationPass : DeobfuscationPass
{
    private readonly bool addressedOnly;
    public TypeRestorationPass() { }
    internal TypeRestorationPass(bool addressedOnly) => this.addressedOnly = addressedOnly;
    public override string Name => "type-restoration";
    public override IReadOnlyCollection<string> Dependencies => ["method-body-recovery"];

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        var addressed = context.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody)
            .SelectMany(m => m.Body.Instructions).Where(i => i.OpCode.Code is Code.Ldflda or Code.Ldsflda)
            .Select(i => (i.Operand as IField)?.ResolveFieldDef()).ToHashSet();
        var eligible = context.Module.GetTypes()
            .SelectMany(type => type.Fields)
            .Where(IsObjectTypedNonPublicField)
            .Where(field => !addressedOnly || addressed.Contains(field))
            .ToArray();
        if (eligible.Length == 0)
            return (PassStatus.Success, 0, ["No object-typed non-public field was eligible for restoration."]);

        var writers = IndexFieldWriters(context.Module);
        // Separate MemberRef signatures would also need rewriting. Managed addresses
        // additionally require a closed proof of every use and indirect writer.
        var excluded = context.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody)
            .SelectMany(m => m.Body.Instructions)
            .Where(i => i.Operand is IField and not FieldDef)
            .Select(i => (i.Operand as IField)?.ResolveFieldDef()).ToHashSet();
        var exposed = addressed.Count == 0 ? [] : ModuleReachability.Compute(context.Module).ReflectivelyExposedTypes.ToHashSet();
        var inferred = new Dictionary<FieldDef, TypeSig>();
        // Infer before mutating metadata. A copy can become concrete after its
        // source field is proved; cycles without a concrete source stay unknown.
        for (var round = 0; round < 32; round++)
        {
            var before = inferred.Count;
            foreach (var field in eligible)
                if (!inferred.ContainsKey(field) && !excluded.Contains(field) &&
                    TryProveSingleWrittenType(field, writers, inferred, out var concrete) && concrete is not null &&
                    (!addressed.Contains(field) || ProveClosedAddresses(field, concrete, inferred, exposed)))
                    inferred.Add(field, concrete);
            if (inferred.Count == before) break;
        }
        var promotions = inferred.Select(p => (Field: p.Key, Type: p.Value)).ToList();
        if (promotions.Count == 0)
        {
            return (PassStatus.Success, 0,
                ["No object-typed field had a unanimous concrete reference type across its writers."]);
        }

        var originals = promotions.ToDictionary(item => item.Field, item => item.Field.FieldSig.Type);
        try
        {
            foreach (var promotion in promotions)
                promotion.Field.FieldSig.Type = promotion.Type;
            var verification = AssemblyVerifier.Verify(
                context.Module, context.OriginalIdentity, context.OriginalStructure, CilantroPipeline.BuildRewriteAllowance(context));
            if (!verification.Passed)
                throw new InvalidOperationException(string.Join("; ", verification.Diagnostics));
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or ArgumentException)
        {
            foreach (var original in originals)
                original.Key.FieldSig.Type = original.Value;
            return (PassStatus.Failed, 0,
                [$"Type restoration was rolled back: {exception.Message}"]);
        }

        foreach (var promotion in promotions)
        {
            context.AddChange(new ChangeRecord(
                Name,
                "restore-field-type",
                $"{promotion.Field.MDToken} {promotion.Field.DeclaringType.Name}::{promotion.Field.Name}",
                $"Promoted System.Object to {promotion.Type.FullName} on unanimous writer agreement."));
        }
        context.SetFact("types.restoredFields", promotions.Count);
        return (PassStatus.Success, promotions.Count,
            [$"Restored concrete types to {promotions.Count} object-typed field(s)."]);
    }

    /// <summary>
    /// A field whose declaration can be changed without the identity gate being at stake.
    /// </summary>
    /// <remarks>
    /// The question is asked of the gate rather than answered again here, because a field this pass
    /// thought private and the gate thought public would be refused on every run and the message
    /// would be about an API change rather than about the disagreement. Reactor puts the locals of a
    /// rewritten method into a nested class and declares all of them public, so which reading is
    /// used decides real fields: one written once from <c>Path::Combine</c> and read only where a
    /// <c>string</c> is wanted sits on such a class.
    /// </remarks>
    private static bool IsObjectTypedNonPublicField(FieldDef field) =>
        !ArtifactIdentitySnapshot.InPublicApi(field) &&
        !field.IsLiteral &&
        field.FieldSig?.Type.ElementType == ElementType.Object;

    private static ILookup<uint, (MethodDef Method, int Index)> IndexFieldWriters(ModuleDef module) =>
        module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody)
            .SelectMany(method => method.Body.Instructions
                .Select((instruction, index) => (method, instruction, index))
                .Where(item => item.instruction.OpCode.Code is Code.Stfld or Code.Stsfld &&
                    item.instruction.Operand is IField)
                .Select(item => (
                    Token: (((IField)item.instruction.Operand).ResolveFieldDef() ?? (IField)item.instruction.Operand).MDToken.Raw,
                    Method: item.method,
                    Index: item.index)))
            .ToLookup(item => item.Token, item => (item.Method, item.Index));

    /// <summary>
    /// Proves that every write to <paramref name="field"/> stores the same concrete reference type.
    /// </summary>
    private static bool TryProveSingleWrittenType(
        FieldDef field,
        ILookup<uint, (MethodDef Method, int Index)> writers,
        IReadOnlyDictionary<FieldDef, TypeSig> inferred,
        out TypeSig? concrete)
    {
        concrete = null;
        var sites = writers[field.MDToken.Raw].ToArray();
        if (sites.Length == 0)
            return false;
        TypeSig? agreed = null;
        foreach (var site in sites)
        {
            if (!TryTypeOfStoredValue(site.Method, site.Index, inferred, out var stored))
                return false;
            if (stored is null)
                continue; // a null store is compatible with any reference type
            if (agreed is null)
            {
                agreed = stored;
                continue;
            }
            if (!TypeEquals(agreed, stored))
                return false;
        }
        if (agreed is null || !IsRestorableReferenceType(agreed))
            return false;
        concrete = agreed;
        return true;
    }

    /// <summary>
    /// Reads the concrete type of the value feeding a store, or null when the value is a null
    /// literal. Returns false when the producing instruction does not pin down a single type.
    /// </summary>
    private static bool TryTypeOfStoredValue(MethodDef method, int storeIndex,
        IReadOnlyDictionary<FieldDef, TypeSig> inferred, out TypeSig? type)
    {
        type = null;
        var index = storeIndex - 1;
        while (index >= 0 && method.Body.Instructions[index].OpCode.Code == Code.Nop)
            index--;
        if (index < 0)
            return false;
        // Adjacency alone is insufficient: a branch or handler can enter the store
        // (or its nop padding) with a different value already on the stack.
        var interior = method.Body.Instructions.Skip(index + 1).Take(storeIndex - index).ToHashSet();
        if (method.Body.Instructions.Any(i => i.Operand is Instruction target && interior.Contains(target) ||
                i.Operand is IList<Instruction> targets && targets.Any(interior.Contains)) ||
            method.Body.ExceptionHandlers.Any(h => interior.Contains(h.TryStart) || interior.Contains(h.HandlerStart) ||
                h.FilterStart is not null && interior.Contains(h.FilterStart))) return false;
        var producer = method.Body.Instructions[index];
        switch (producer.OpCode.Code)
        {
            case Code.Ldnull:
                type = null;
                return true;
            case Code.Ldstr:
                type = method.Module.CorLibTypes.String;
                return true;
            case Code.Newarr when producer.Operand is ITypeDefOrRef element:
                var elementType = element.ToTypeSig();
                if (elementType.ContainsGenericParameter) return false;
                type = new SZArraySig(elementType);
                return true;
            case Code.Ldfld or Code.Ldsfld when producer.Operand is FieldDef sourceField:
                if (sourceField.DeclaringType.HasGenericParameters) return false;
                type = inferred.TryGetValue(sourceField, out var known) ? known : sourceField.FieldType;
                return IsRestorableReferenceType(type);
            case Code.Ldloc or Code.Ldloc_S or Code.Ldloc_0 or Code.Ldloc_1 or Code.Ldloc_2 or Code.Ldloc_3:
                var local = producer.GetLocal(method.Body.Variables);
                // A typed local is an existing stack-type guarantee. An object
                // local needs a separate local-signature rewrite, so do not infer
                // through it and leave an object-to-concrete store behind.
                if (local is null || !IsRestorableReferenceType(local.Type) || local.Type.ContainsGenericParameter) return false;
                type = local.Type;
                return true;
            case Code.Ldarg_0 or Code.Ldarg_1 or Code.Ldarg_2 or Code.Ldarg_3 or Code.Ldarg or Code.Ldarg_S:
                var argument = producer.OpCode.Code switch
                {
                    Code.Ldarg_0 => 0, Code.Ldarg_1 => 1, Code.Ldarg_2 => 2, Code.Ldarg_3 => 3,
                    _ => producer.Operand is Parameter parameter ? parameter.Index : -1
                };
                if (argument < 0 || argument >= method.Parameters.Count) return false;
                var source = method.Parameters[argument];
                if (method.Body.Instructions.Any(i =>
                    i.OpCode.Code is Code.Starg or Code.Starg_S or Code.Ldarga or Code.Ldarga_S &&
                    i.Operand == source)) return false;
                type = source.Type;
                return true;
            case Code.Newobj when producer.Operand is IMethod constructor &&
                constructor.DeclaringType is { } declaring:
                type = declaring.ToTypeSig();
                return true;
            case Code.Castclass when producer.Operand is ITypeDefOrRef cast:
                type = cast.ToTypeSig();
                return true;
            case Code.Call or Code.Callvirt when producer.Operand is IMethod called:
                var returnType = ArrayParameterTypingPass.ReturnedType(called);
                if (returnType is null || returnType.ElementType == ElementType.Void)
                    return false;
                type = returnType;
                return true;
            default:
                // A box produces an object from a value type; refusing it keeps the pass to
                // reference-type promotions that need no unbox rewrite.
                return false;
        }
    }

    private static bool IsRestorableReferenceType(TypeSig type)
    {
        if (type.ElementType == ElementType.Object)
            return false;
        return type.ElementType is
            ElementType.Class or ElementType.String or ElementType.Array or ElementType.SZArray ||
            (type.TryGetTypeDef() is { IsValueType: false } definition && !definition.IsInterface) ||
            type.TryGetTypeDef() is { IsInterface: true };
    }

    private static bool TypeEquals(TypeSig left, TypeSig right) =>
        new SigComparer().Equals(left, right);

    private static bool ProveClosedAddresses(FieldDef field, TypeSig concrete,
        IReadOnlyDictionary<FieldDef, TypeSig> inferred, HashSet<TypeDef> exposed)
    {
        var owner = field.DeclaringType;
        if (owner.HasGenericParameters || owner.IsExplicitLayout || owner.IsSerializable ||
            field.HasCustomAttributes || concrete.ContainsGenericParameter || exposed.Contains(owner)) return false;
        if (field.Module.GetMemberRefs().Any(r => r.IsFieldRef && r.ResolveFieldDef() == field)) return false;
        foreach (var method in field.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
        {
            var graph = ControlFlowGraph.Build(method);
            var il = method.Body.Instructions;
            for (var n = 0; n < il.Count; n++)
            {
                var instruction = il[n];
                if (instruction.Operand is string name && (name == field.Name || name == field.FullName)) return false;
                if (instruction.OpCode.Code == Code.Ldtoken && instruction.Operand is ITypeDefOrRef type &&
                    type.ResolveTypeDef() == owner) return false;
                if (instruction.Operand is not IField reference || reference.ResolveFieldDef() != field) continue;
                if (reference != field) return false;
                if (instruction.OpCode.Code is Code.Ldfld or Code.Ldsfld or Code.Stfld or Code.Stsfld) continue;
                if (instruction.OpCode.Code is not (Code.Ldflda or Code.Ldsflda)) return false;
                var next = n + 1;
                while (next < il.Count && il[next].OpCode.Code == Code.Nop) next++;
                if (next == il.Count || graph.BlockOf(instruction) != graph.BlockOf(il[next]) ||
                    il[next].OpCode.Code != Code.Call || il[next].Operand is not MethodDef target ||
                    target.Module != field.Module || !target.IsStatic || !target.HasBody || target.HasGenericParameters ||
                    target.DeclaringType.HasGenericParameters || target.Parameters.Count == 0 ||
                    target.Parameters[^1].Type is not ByRefSig address || !TypeEquals(address.Next, concrete) ||
                    !ProveIndirectUses(target, target.Parameters[^1], concrete, inferred)) return false;
            }
        }
        return true;
    }

    private static bool ProveIndirectUses(MethodDef method, Parameter parameter, TypeSig concrete,
        IReadOnlyDictionary<FieldDef, TypeSig> inferred)
    {
        var graph = ControlFlowGraph.Build(method);
        var il = method.Body.Instructions;
        for (var n = 0; n < il.Count; n++)
        {
            if (il[n].Operand == parameter && !il[n].IsLdarg()) return false;
            if (!il[n].IsLdarg() || il[n].GetParameter(method.Parameters) != parameter) continue;
            // Follow this one address until it is consumed. Never let it escape via
            // a call, local, return, duplicate or a control-flow merge.
            var slot = 0;
            var consumed = false;
            for (var at = n + 1; at < il.Count && graph.BlockOf(il[at]) == graph.BlockOf(il[n]); at++)
            {
                var use = il[at];
                if (use.OpCode.Code == Code.Dup && slot == 0) return false;
                use.CalculateStackUsage(out var pushes, out var pops);
                if (pops < 0) return false;
                if (slot < pops)
                {
                    if (use.OpCode.Code == Code.Ldind_Ref && slot == 0) consumed = true;
                    else if (use.OpCode.Code == Code.Stind_Ref && slot == 1 &&
                        TryTypeOfStoredValue(method, at, inferred, out var stored) &&
                        (stored is null || TypeEquals(stored, concrete))) consumed = true;
                    if (!consumed) return false;
                    break;
                }
                slot = slot - pops + pushes;
            }
            if (!consumed) return false;
        }
        return true;
    }
}
