using dnlib.DotNet;

namespace Cilantro.Core.Pipeline;

/// <summary>Uses explicitly supplied matching private keys to sign rewritten managed images.</summary>
internal static class StrongNameEmission
{
    internal static bool TryPrepare(ModuleDef module, IReadOnlyList<string>? paths, out StrongNameKey? key, out string why)
    {
        key = null; why = "";
        if (paths is not { Count: > 0 } || !module.IsStrongNameSigned) return true;
        if (paths.Count > 16) { why = "At most sixteen strong-name keys may be supplied."; return false; }
        if (module.Assembly is not { } assembly || assembly.CustomAttributes.Any(a => a.TypeFullName == "System.Reflection.AssemblySignatureKeyAttribute"))
        { why = "Re-signing requires a normal strong-name assembly identity."; return false; }
        if (assembly.PublicKey?.Data is not { Length: > 0 } publicKey)
        { why = "The signed input has no public key to match."; return false; }
        try
        {
            var algorithm = new StrongNamePublicKey(publicKey).HashAlgorithm;
            foreach (var path in paths)
            {
                if (new FileInfo(path).Length > 64 * 1024) throw new IOException("Strong-name key exceeds the 64 KiB input bound.");
                var candidate = new StrongNameKey(File.ReadAllBytes(path)).WithHashAlgorithm(algorithm);
                if (!(assembly.PublicKey?.Data ?? []).AsSpan().SequenceEqual(candidate.PublicKey)) continue;
                using var rsa = candidate.CreateRSA();
                _ = rsa.ExportParameters(includePrivateParameters: true);
                key = candidate; return true;
            }
            why = "No supplied private key matches this assembly's public key."; return false;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or
            System.Security.Cryptography.CryptographicException or InvalidOperationException or InvalidKeyException)
        { why = "The supplied strong-name private key could not be read or validated (" + exception.GetType().Name + ")."; return false; }
    }

    internal static bool Verify(string path, StrongNameKey key, out string why)
    {
        why = "";
        try
        {
            using var module = ModuleDefMD.Load(path);
            var directory = module.Metadata.ImageCor20Header.StrongNameSignature;
            if (!module.IsStrongNameSigned || !(module.Assembly?.PublicKey?.Data ?? []).AsSpan().SequenceEqual(key.PublicKey) ||
                directory.Size != key.SignatureSize)
            { why = "The emitted strong-name identity or signature size changed."; return false; }
            var offset = module.Metadata.PEImage.ToFileOffset(directory.VirtualAddress);
            var actual = module.Metadata.PEImage.CreateReader(offset, directory.Size).ToArray();
            using var stream = File.OpenRead(path);
            var expected = new StrongNameSigner(stream).CalculateSignature(key, (long)offset);
            if (!actual.AsSpan().SequenceEqual(expected)) { why = "The emitted strong-name signature did not verify."; return false; }
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or BadImageFormatException or
            System.Security.Cryptography.CryptographicException or InvalidOperationException)
        { why = "Strong-name verification failed (" + exception.GetType().Name + ")."; return false; }
    }
}
