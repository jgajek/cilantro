using System.Security.Cryptography;
using Cilantro.Core.Analysis;
using Cilantro.Core.Payload;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>A run-local retirement proof, invalidated by changes to its replacement or consumers.</summary>
internal sealed class RetiredDependencyResource
{
    internal const string Fact = "dependency.retiredResourceProofs";
    private readonly (MethodDef Method, string Signature, MethodBodySnapshot Body)[] methods;
    private readonly FieldDef data;
    private readonly string dataSignature;
    private readonly string payloadHash;
    private readonly uint size;
    private readonly ushort packing;
    internal RecoveredResourceOrigin Source { get; }

    private RetiredDependencyResource(RecoveredResourceOrigin source, FieldDef field, MethodDef[] owners)
    {
        Source = source; data = field; dataSignature = field.FullName;
        payloadHash = Convert.ToHexString(SHA256.HashData(field.InitialValue));
        var layout = field.FieldType.ToTypeDefOrRef().ResolveTypeDef().ClassLayout;
        size = layout.ClassSize; packing = layout.PackingSize;
        methods = owners.Distinct().Select(m => (m, m.FullName, MethodBodySnapshot.Capture(m))).ToArray();
    }

    // Called only after the source/index/slice proofs and array replacement have committed.
    internal static RetiredDependencyResource? Capture(RecoveredResourceOrigin source, MethodDef resolver,
        MethodDef index, MethodDef helper)
    {
        var fields = helper.Body.Instructions.Where(i => i.OpCode.Code == Code.Ldtoken)
            .Select(i => i.Operand).OfType<FieldDef>().Distinct().ToArray();
        if (helper.ReturnType.FullName != "System.Byte[]" || fields.Length != 1 ||
            fields[0].DeclaringType != helper.DeclaringType || !ValidData(fields[0]) ||
            !PayloadStageValidator.TryValidateManaged(fields[0].InitialValue, out _)) return null;
        return new(source, fields[0], [resolver, index, helper]);
    }

    internal bool IsPreserved(ModuleDef module) =>
        module.Resources.Count(r => r.Name == Source.Name) == 1 &&
        module.Resources.OfType<EmbeddedResource>().Any(Source.Matches) &&
        methods.All(p => p.Method.Module == module && p.Method.DeclaringType.Methods.Contains(p.Method) &&
            module.GetTypes().Contains(p.Method.DeclaringType) && p.Method.FullName == p.Signature && p.Body.StructurallyEquals(p.Method)) &&
        data.Module == module && data.DeclaringType.Fields.Contains(data) && ValidData(data) && data.FullName == dataSignature &&
        data.FieldType.ToTypeDefOrRef().ResolveTypeDef().ClassLayout is { } layout && layout.ClassSize == size && layout.PackingSize == packing &&
        Convert.ToHexString(SHA256.HashData(data.InitialValue)) == payloadHash;

    private static bool ValidData(FieldDef field) => field.IsStatic && field.IsInitOnly && field.HasFieldRVA &&
        field.InitialValue is { Length: > 0 } bytes && field.FieldType.ToTypeDefOrRef()?.ResolveTypeDef() is { IsExplicitLayout: true, ClassLayout: { } layout } &&
        layout.ClassSize == bytes.Length;
}
