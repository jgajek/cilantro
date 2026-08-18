using dnlib.DotNet;
using dnlib.DotNet.MD;

namespace Cilantro.Core.Analysis;

/// <summary>
/// Recognizes Reactor inputs whose real code is a native stub rather than managed IL.
/// </summary>
/// <remarks>
/// A file that reaches this point already parsed as a managed module, so the concern is mixed-mode
/// and native-entry images: Reactor's native protection (NecroBit native / native EXE) clears the
/// IL-only flag, points the COR20 entry at native code, or attaches a managed native header. None of
/// those can be recovered by static managed analysis, so they are reported as an explicit,
/// deferred-capability boundary instead of being processed into a damaged output.
/// </remarks>
public static class NativePackDetector
{
    public static bool TryDescribe(ModuleDefMD module, out string reason)
    {
        var header = module.Metadata.ImageCor20Header;
        var flags = header.Flags;

        if ((flags & ComImageFlags.NativeEntryPoint) != 0 || module.NativeEntryPoint != 0)
        {
            reason = "The COR20 header declares a native entry point; the input is native-packed.";
            return true;
        }

        if (header.HasNativeHeader)
        {
            reason = "The image carries a managed native header; the input is native-packed.";
            return true;
        }

        if ((flags & ComImageFlags.ILOnly) == 0)
        {
            reason = "The COR20 header is not IL-only; the input is a mixed-mode/native-packed image.";
            return true;
        }

        reason = string.Empty;
        return false;
    }
}
