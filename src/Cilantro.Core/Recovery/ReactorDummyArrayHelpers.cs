using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Recognizes the complete unused array decoys emitted in Reactor runtime owners.</summary>
internal static class ReactorDummyArrayHelpers
{
    internal static IReadOnlyList<MethodDef> Find(ArtifactContext context) =>
        ReactorIntegrityHelpers.Owners(context).SelectMany(t => t.Methods).Where(Recognize).ToArray();

    internal static bool Recognize(MethodDef method)
    {
        if (method.IsStatic || method.IsConstructor || method.IsVirtual || method.HasGenericParameters ||
            method.DeclaringType.HasGenericParameters || method.HasCustomAttributes || !method.HasBody ||
            method.MethodSig.Params.Count != 0 || !method.MethodSig.HasThis ||
            method.ReturnType is not SZArraySig { Next.ElementType: ElementType.U1 } ||
            method.Body.HasExceptionHandlers || method.Body.Variables.Count != 0) return false;
        var il = method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        if (il.Length is not (14 or 16) || il[0].OpCode.Code != Code.Ldstr || il[0].Operand is not string) return false;
        var tokens = ReactorCryptoHelpers.Tokens(method, []);
        if (tokens is null) return false;
        // A prior simplifier can remove the independent ldc.i4.0/pop pair.
        // Match both complete bodies without accepting arbitrary junk regions.
        if (tokens.Count == 16)
        {
            if (tokens[2] != "int0" || tokens[3] != "Pop") return false;
            tokens.RemoveRange(2, 2);
        }
        tokens[0] = "literal";
        return tokens.SequenceEqual(Body);
    }

    private static readonly string[] Body =
    [
        "literal", "Callvirt:System.Int32 System.String::get_Length()", "Pop", "int2", "Newarr:System.Byte",
        "Dup", "int0", "int1", "Stelem_I1", "Dup", "int1", "int2", "Stelem_I1", "Ret"
    ];
}
