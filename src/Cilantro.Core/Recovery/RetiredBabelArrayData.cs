using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using dnlib.DotNet;

namespace Cilantro.Core.Recovery;

/// <summary>Exact encrypted RVA inputs superseded by verified fresh array literals.</summary>
internal sealed class RetiredBabelArrayData
{
    internal const string Fact = "babel.numericArrays.retiredData";
    internal FieldDef Source { get; }
    internal TypeDef Storage { get; }
    private readonly string signature;
    private readonly FieldAttributes attributes;
    private readonly byte[] bytes;
    private readonly TypeAttributes storageAttributes;
    private readonly ushort packing;
    private readonly uint size;
    private readonly (MethodDef Method, string Name, MethodAttributes Attributes, MethodImplAttributes Implementation, MethodBodySnapshot Body)[] replacements;
    private sealed record Literal(FieldDef Field, string Name, FieldAttributes Attributes, byte[] Bytes,
        TypeAttributes LayoutAttributes, ushort Packing, uint Size);
    private readonly Literal[] literals;

    private RetiredBabelArrayData(FieldDef source, IEnumerable<MethodDef> callers, IEnumerable<FieldDef> data)
    {
        Source = source; signature = source.FullName; attributes = source.Attributes;
        bytes = source.InitialValue.ToArray();
        Storage = source.FieldType.ToTypeDefOrRef().ResolveTypeDef();
        storageAttributes = Storage.Attributes; packing = Storage.ClassLayout.PackingSize; size = Storage.ClassLayout.ClassSize;
        replacements = callers.Distinct().Select(method => (method, method.FullName, method.Attributes, method.ImplAttributes, MethodBodySnapshot.Capture(method))).ToArray();
        literals = data.Distinct().Select(field => new Literal(field, field.FullName, field.Attributes, field.InitialValue.ToArray(),
            field.DeclaringType.Attributes, field.DeclaringType.ClassLayout.PackingSize, field.DeclaringType.ClassLayout.ClassSize)).ToArray();
    }

    internal static void Remember(ArtifactContext context, FieldDef source, IEnumerable<MethodDef> callers, IEnumerable<FieldDef> data)
    {
        if (!Eligible(source)) return;
        context.TryGetFact<IReadOnlyList<RetiredBabelArrayData>>(Fact, out var prior);
        context.SetFact<IReadOnlyList<RetiredBabelArrayData>>(Fact, [.. prior ?? [], new(source, callers, data)]);
    }

    private static bool Eligible(FieldDef field) => field is
        { IsStatic: true, IsInitOnly: true, HasFieldRVA: true, HasCustomAttributes: false, HasConstant: false, HasMarshalType: false, InitialValue: not null } &&
        (field.IsPrivate || field.IsAssembly && !MemberVisibility.IsExternallyVisible(field.DeclaringType)) &&
        field.FieldType.ToTypeDefOrRef()?.ResolveTypeDef() is { IsValueType: true, IsEnum: false, IsExplicitLayout: true, HasGenericParameters: false, ClassLayout: not null };

    internal bool IsPreserved(ModuleDef module)
    {
        var types = module.GetTypes().ToHashSet();
        return Eligible(Source) && Source.Module == module && types.Contains(Source.DeclaringType) && Source.DeclaringType.Fields.Contains(Source) &&
            Source.FullName == signature && Source.Attributes == attributes && Source.InitialValue.AsSpan().SequenceEqual(bytes) &&
            Source.FieldType.ToTypeDefOrRef()?.ResolveTypeDef() == Storage && types.Contains(Storage) &&
            Storage.Attributes == storageAttributes && Storage.ClassLayout is { } layout && layout.PackingSize == packing && layout.ClassSize == size &&
            replacements.All(item => types.Contains(item.Method.DeclaringType) && item.Method.DeclaringType.Methods.Contains(item.Method) &&
                item.Method.FullName == item.Name && item.Method.Attributes == item.Attributes && item.Method.ImplAttributes == item.Implementation && item.Body.StructurallyEquals(item.Method)) &&
            literals.All(item => types.Contains(item.Field.DeclaringType) && item.Field.DeclaringType.Fields.Contains(item.Field) &&
                item.Field.FullName == item.Name && item.Field.Attributes == item.Attributes && !item.Field.HasCustomAttributes &&
                item.Field.InitialValue is { } value && value.AsSpan().SequenceEqual(item.Bytes) &&
                item.Field.DeclaringType is { IsValueType: true, IsEnum: false, HasCustomAttributes: false, ClassLayout: { } literalLayout } holder &&
                holder.Attributes == item.LayoutAttributes && literalLayout.PackingSize == item.Packing && literalLayout.ClassSize == item.Size &&
                holder.BaseType?.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName);
    }

    internal static IEnumerable<RetiredBabelArrayData> Unused(ArtifactContext context, ModuleReachability reachability)
    {
        if (!context.TryGetFact<IReadOnlyList<RetiredBabelArrayData>>(Fact, out var proofs) || proofs is null) yield break;
        var references = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody)
            .SelectMany(method => method.Body.Instructions).Select(instruction => instruction.Operand).OfType<IField>()
            .Select(field => field.ResolveFieldDef()).OfType<FieldDef>().ToHashSet();
        foreach (var proof in proofs.DistinctBy(proof => proof.Source))
            if (proof.IsPreserved(context.Module) && !references.Contains(proof.Source) &&
                !reachability.IsReflectivelyExposed(proof.Source.DeclaringType)) yield return proof;
    }

    // A shared layout is retained by ComputeUnreferenced; application-bearing types never qualify.
    internal bool EmptyStorage(ModuleReachability reachability) => Storage.Attributes == storageAttributes &&
        !MemberVisibility.IsExternallyVisible(Storage) && !reachability.IsReflectivelyExposed(Storage) &&
        !Storage.HasCustomAttributes && Storage.Fields.Count == 0 && Storage.Methods.Count == 0 && Storage.NestedTypes.Count == 0 &&
        Storage.Properties.Count == 0 && Storage.Events.Count == 0 && Storage.Interfaces.Count == 0;
}
