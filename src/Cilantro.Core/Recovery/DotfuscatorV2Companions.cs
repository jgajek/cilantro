using System.Security.Cryptography;
using Cilantro.Core.Codec;
using dnlib.DotNet;
using dnlib.PE;

namespace Cilantro.Core.Recovery;

/// <summary>Authenticate eligible reviewed native implementations without loading them.</summary>
internal static class DotfuscatorV2Companions
{
    internal static bool TryValidateNative(string directory, ModuleDef module, out string detail)
    {
        detail = "Dotfuscator v2 requires a reviewed native companion for the input architecture.";
        var eligible = module.Machine switch
        {
            Machine.I386 when module.Is32BitRequired => new[] { "win-x86" },
            Machine.I386 => ["win-x86", "win-x64", "linux-x64", "linux-arm64", "osx-x64", "osx-arm64"],
            Machine.AMD64 => ["win-x64", "linux-x64", "osx-x64"],
            Machine.ARM64 => ["linux-arm64", "osx-arm64"],
            _ => []
        };
        if (eligible.Length == 0) return false;
        var validated = new List<string>();
        foreach (var rid in eligible)
        {
            var file = rid.StartsWith("linux-", StringComparison.Ordinal) ? "Runtime.Extensions.so" :
                rid.StartsWith("osx-", StringComparison.Ordinal) ? "Runtime.Extensions.dylib" : "Runtime.Extensions.dll";
            var path = Path.Combine(directory, "runtimes", rid, "native", file);
            if (!File.Exists(path)) continue;
            detail = $"Unsupported Dotfuscator v2 {rid} native-library identity; calls preserved.";
            if (new FileInfo(path).Length > 16 * 1024 * 1024) return false;
            var hash = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));
            var expected = rid switch
            {
                "win-x86" => DotfuscatorV2Codec.NativeX86Sha256,
                "linux-x64" => DotfuscatorV2Codec.NativeLinuxX64Sha256,
                "linux-arm64" => DotfuscatorV2Codec.NativeLinuxArm64Sha256,
                "osx-x64" => DotfuscatorV2Codec.NativeMacOsX64Sha256,
                "osx-arm64" => DotfuscatorV2Codec.NativeMacOsArm64Sha256,
                _ => DotfuscatorV2Codec.NativeSha256
            };
            if (hash != expected) return false;
            validated.Add($"{rid} SHA-256 {hash}");
        }
        if (validated.Count == 0) return false;
        detail = string.Join("; ", validated);
        return true;
    }
}
