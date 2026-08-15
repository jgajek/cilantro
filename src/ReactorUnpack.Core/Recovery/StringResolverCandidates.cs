using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace ReactorUnpack.Core.Recovery;

/// <summary>
/// The methods shaped like the one that hands back a string for a number.
/// </summary>
/// <remarks>
/// Shared so that the two readings of the table and the restoration all mean the same thing by "the
/// resolver". A shape is not a proof — a cache that hands back what it was told earlier reads the
/// same way — so this only narrows the field, and which candidate is the resolver is settled by
/// which one produces a table.
/// </remarks>
internal static class StringResolverCandidates
{
    public static MethodDef[] In(ModuleDef module)
    {
        ArgumentNullException.ThrowIfNull(module);
        return [.. module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody &&
                method.IsStatic &&
                method.ReturnType.ElementType == ElementType.String &&
                method.MethodSig?.Params.Count == 1 &&
                method.MethodSig.Params[0].ElementType == ElementType.I4 &&
                (method.Body.Instructions.Any(instruction =>
                    instruction.Operand is IMethod called &&
                    called.Name == "GetManifestResourceStream") ||
                 method.Body.Instructions.Any(instruction =>
                    instruction.OpCode.Code == Code.Ldsfld &&
                    instruction.Operand is IField field &&
                    field.FieldSig?.Type.ElementType is ElementType.SZArray or ElementType.Object)))];
    }
}
