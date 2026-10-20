using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using dnlib.DotNet;

namespace Cilantro.Core.Codec;

/// <summary>The reviewed 7.9 v2 context framing, signed environment and XOR stream.</summary>
internal static class DotfuscatorV2Codec
{
    internal const string NativeSha256 = "1b1f5d593b308ffd6746e333b86719e0ba057cf0ccaa5f009dd076a1d40daac2";
    internal const string NativeX86Sha256 = "07e9dd691839f9fd4f49267c72ddc620b76fa37a217c2f9c7b83a13fa3e762c9";
    internal const string NativeLinuxX64Sha256 = "e2ed9c4a49a80293bc5341b7a4e6fe30eb6dcdb52eb8b7d2c548d3490ca5edd4";
    internal const string NativeLinuxArm64Sha256 = "a8927d23c2d1e9cabc0e1435818f6a850261a609987aca5c2f03a38bf621ee31";
    internal const string NativeMacOsX64Sha256 = "f0cbfe9a0e8c80627fcd87c779cb2c5155377d0cb0e0f765fcb581c4ea55c852";
    internal const string NativeMacOsArm64Sha256 = "764d3343142ca5bde865aaed719a6913a154a7619434e4ce3eae468175b44d81";
    private const string EnvironmentPublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXtnLJJ7AQxYEJszM4i/lMQ0GYn3higaD7wtO+ussf+Fp/EsTCNMPwZdSmZg2XYd8Mg1ELxPstOOzZoRhY/K+8w==";
    internal const int MaximumStringBytes = 1_048_576;

    internal static bool ValidateEnvironment(ReadOnlySpan<byte> bytes, uint managedSeed, out string reason)
    {
        reason = "Invalid Dotfuscator v2 environment length or framing.";
        if (bytes.Length != 20480 || !bytes[..4].SequenceEqual(new byte[] { 0x31, 0x9a, 0xff, 0xa2 }) ||
            !bytes[^4..].SequenceEqual(new byte[] { 0x44, 0x5a, 0x4d, 0xaa })) return false;
        using var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(EnvironmentPublicKey), out _);
        reason = "Dotfuscator v2 environment signature did not verify.";
        if (!key.VerifyData(bytes[..18432], bytes.Slice(18432, 64), HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) return false;
        reason = "Dotfuscator v2 environment belongs to a different decoder seed.";
        if ((BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(16384, 4)) ^ 0x3b527b1cU) != managedSeed) return false;
        reason = "";
        return true;
    }

    internal static byte[] Key(string assemblyName, string methodSignature)
    {
        byte[] Utf8(string text) => Encoding.UTF8.GetBytes(text.Normalize(NormalizationForm.FormC));
        var assembly = Utf8(assemblyName);
        var signature = Utf8(methodSignature);
        var context = SHA256.HashData(Utf8($"DFSE2|v2|Ctx|{assemblyName}|{methodSignature}"));
        using var frame = new MemoryStream();
        // The native function deliberately consumes twelve bytes of its domain literal.
        frame.Write("DFSE2|v2|Key"u8);
        Span<byte> length = stackalloc byte[4];
        foreach (var part in new[] { assembly, signature, context })
        {
            frame.WriteByte(0);
            BinaryPrimitives.WriteInt32BigEndian(length, part.Length);
            frame.Write(length);
            frame.Write(part);
        }
        // Native and managed xorshift masks cancel when the signed seed matches.
        // Recovery selects the native routine's clean runtime-check verdict.
        return SHA256.HashData(frame.ToArray());
    }

    internal static bool TryDecode(string encoded, int offset, ReadOnlySpan<byte> key, out string text)
    {
        text = "";
        if (key.Length != 32 || offset < 0 || encoded.Length > (MaximumStringBytes + 2L) / 3 * 4) return false;
        try
        {
            var bytes = Convert.FromBase64String(encoded);
            if (bytes.Length > MaximumStringBytes || offset > int.MaxValue - bytes.Length) return false;
            for (var at = 0; at < bytes.Length; at++) bytes[at] ^= key[(at + offset) % key.Length];
            // The emitted decoder uses Encoding.UTF8's replacement fallback,
            // including for ciphertext already broken by the protecting build.
            text = Encoding.UTF8.GetString(bytes);
            return true;
        }
        catch (Exception exception) when (exception is FormatException or DecoderFallbackException) { return false; }
    }

    internal static string? Signature(MethodDef method)
    {
        string? Name(TypeSig sig) => sig.RemovePinnedAndModifiers() switch
        {
            GenericVar variable => variable.Number < method.DeclaringType.GenericParameters.Count
                ? method.DeclaringType.GenericParameters[(int)variable.Number].Name.String : null,
            GenericMVar variable => variable.Number < method.GenericParameters.Count
                ? method.GenericParameters[(int)variable.Number].Name.String : null,
            GenericInstSig generic => generic.GenericType.TypeDefOrRef.Name.String,
            SZArraySig array => Name(array.Next) is { } element ? element + "[]" : null,
            ArraySig array when array.Rank is > 0 and <= 32 => Name(array.Next) is { } element
                ? element + (array.Rank == 1 ? "[*]" : "[" + new string(',', (int)array.Rank - 1) + "]") : null,
            ByRefSig reference => Name(reference.Next) is { } element ? element + "&" : null,
            PtrSig pointer => Name(pointer.Next) is { } element ? element + "*" : null,
            // The reviewed CoreCLR Type.Name for a function pointer is empty.
            // Its display signature is different and is not the decoder's input.
            FnPtrSig { Signature: MethodSig } when method.Module.CorLibTypes.AssemblyRef.Name.String == "System.Runtime" &&
                method.Module.CorLibTypes.AssemblyRef.Version.Major is 8 or 10 => "",
            TypeDefOrRefSig type => type.TypeDefOrRef.Name.String,
            _ => null
        };
        var result = method.IsConstructor ? "Void" : Name(method.ReturnType);
        var parameters = method.MethodSig.Params.Select(Name).ToArray();
        return result is null || parameters.Any(p => p is null) ? null :
            $"{method.Name}|{result} {method.Name}({string.Join(", ", parameters)})";
    }
}
