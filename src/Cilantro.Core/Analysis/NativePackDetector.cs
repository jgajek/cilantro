using dnlib.DotNet;
using dnlib.DotNet.MD;

namespace Cilantro.Core.Analysis;

/// <summary>Detects native-code boundaries that a managed-only rewrite cannot preserve.</summary>
/// <remarks>
/// These headers also occur in ordinary C++/CLI and precompiled assemblies. They
/// establish a rewrite boundary, not evidence of Reactor or any other protector.
/// Dedicated native-wrapper recovery performs its own structural recognition.
/// </remarks>
public static class NativePackDetector
{
    public static bool TryDescribe(ModuleDefMD module, out string reason)
    {
        var header = module.Metadata.ImageCor20Header;
        var flags = header.Flags;

        if ((flags & ComImageFlags.NativeEntryPoint) != 0 || module.NativeEntryPoint != 0)
        {
            reason = "The COR20 header declares a native entry point; preserving native code requires a native-aware rewrite.";
            return true;
        }

        if (header.HasNativeHeader)
        {
            reason = "The image carries a managed native header; preserving its precompiled code requires a native-aware rewrite.";
            return true;
        }

        if ((flags & ComImageFlags.ILOnly) == 0)
        {
            reason = "The COR20 header is not IL-only; managed-only rewriting cannot establish preservation of native code.";
            return true;
        }

        reason = string.Empty;
        return false;
    }
}
