using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Passes;
using Cilantro.Core.Verification;

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
    public override string Name => "type-restoration";
    public override IReadOnlyCollection<string> Dependencies => ["method-body-recovery"];

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        var eligible = context.Module.GetTypes()
            .SelectMany(type => type.Fields)
            .Where(IsObjectTypedNonPublicField)
            .ToArray();
        if (eligible.Length == 0)
            return (PassStatus.Success, 0, ["No object-typed non-public field was eligible for restoration."]);

        var writers = IndexFieldWriters(context.Module);
        var promotions = new List<(FieldDef Field, TypeSig Type)>();
        foreach (var field in eligible)
        {
            if (TryProveSingleWrittenType(field, writers, out var concrete) && concrete is not null)
                promotions.Add((field, concrete));
        }
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
                context.Module, context.OriginalIdentity, context.OriginalStructure);
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

    private static bool IsObjectTypedNonPublicField(FieldDef field) =>
        !field.IsPublic &&
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
                    Token: ((IField)item.instruction.Operand).MDToken.Raw,
                    Method: item.method,
                    Index: item.index)))
            .ToLookup(item => item.Token, item => (item.Method, item.Index));

    /// <summary>
    /// Proves that every write to <paramref name="field"/> stores the same concrete reference type.
    /// </summary>
    private static bool TryProveSingleWrittenType(
        FieldDef field,
        ILookup<uint, (MethodDef Method, int Index)> writers,
        out TypeSig? concrete)
    {
        concrete = null;
        var sites = writers[field.MDToken.Raw].ToArray();
        if (sites.Length == 0)
            return false;
        TypeSig? agreed = null;
        foreach (var site in sites)
        {
            if (!TryTypeOfStoredValue(site.Method, site.Index, out var stored))
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
    private static bool TryTypeOfStoredValue(MethodDef method, int storeIndex, out TypeSig? type)
    {
        type = null;
        var index = storeIndex - 1;
        while (index >= 0 && method.Body.Instructions[index].OpCode.Code == Code.Nop)
            index--;
        if (index < 0)
            return false;
        var producer = method.Body.Instructions[index];
        switch (producer.OpCode.Code)
        {
            case Code.Ldnull:
                type = null;
                return true;
            case Code.Newobj when producer.Operand is IMethod constructor &&
                constructor.DeclaringType is { } declaring:
                type = declaring.ToTypeSig();
                return true;
            case Code.Castclass when producer.Operand is ITypeDefOrRef cast:
                type = cast.ToTypeSig();
                return true;
            case Code.Call or Code.Callvirt when producer.Operand is IMethod called:
                var returnType = called.MethodSig?.RetType;
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
        string.Equals(left.FullName, right.FullName, StringComparison.Ordinal);
}
