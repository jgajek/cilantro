using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>The complete Reactor Base64/UTF-16 utility, including its discarded literal prefix.</summary>
internal static class ReactorEncodingHelpers
{
    internal static IReadOnlyList<MethodDef> Find(ArtifactContext context) =>
        ReactorIntegrityHelpers.Owners(context).SelectMany(t => t.Methods).Where(Recognize).ToArray();

    internal static bool Recognize(MethodDef method)
    {
        if (!method.IsStatic || method.IsConstructor || method.IsVirtual || method.HasGenericParameters ||
            method.DeclaringType.HasGenericParameters || method.HasCustomAttributes || !method.HasBody ||
            method.Body.HasExceptionHandlers || method.Parameters.Count != 1 ||
            method.Parameters[0].Type.ElementType is not (ElementType.Object or ElementType.String) ||
            method.ReturnType.ElementType != ElementType.String || method.Body.Variables.Count != 1 ||
            method.Body.Variables[0].Type is not SZArraySig { Next.ElementType: ElementType.U1 }) return false;
        var il = method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        if (il.Length != Body.Length || il[0].OpCode.Code != Code.Ldstr || il[0].Operand is not string) return false;
        var tokens = ReactorCryptoHelpers.Tokens(method, []);
        if (tokens is null) return false;
        // The literal is consumed only by Trim/pop. Its contents neither identify
        // a sample nor flow into the decoded value.
        tokens[0] = "literal";
        return tokens.SequenceEqual(Body);
    }

    private static readonly string[] Body =
    [
        "literal", "Call:System.String System.String::Trim()", "Pop", "arg0",
        "Call:System.Byte[] System.Convert::FromBase64String(System.String)", "store0",
        "Call:System.Text.Encoding System.Text.Encoding::get_Unicode()", "load0", "int0", "load0",
        "Ldlen", "Conv_I4", "Callvirt:System.String System.Text.Encoding::GetString(System.Byte[],System.Int32,System.Int32)", "Ret"
    ];
}
