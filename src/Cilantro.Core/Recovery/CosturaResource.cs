using System.Reflection.PortableExecutable;
using dnlib.DotNet;
using Cilantro.Core.Analysis;
using Cilantro.Core.Passes;
using Cilantro.Core.Payload;

namespace Cilantro.Core.Recovery;

internal static class CosturaResource
{
    internal const int MaximumLength = 256 * 1024 * 1024;

    internal static ResourceRole Classify(EmbeddedResource resource)
    {
        if (!IsCandidate(resource.Name) || resource.CreateReader().Length > MaximumLength)
            return ResourceRole.Unknown;
        try
        {
            var bytes = resource.CreateReader().ToArray();
            if (resource.Name.String.EndsWith(".compressed", StringComparison.OrdinalIgnoreCase))
                bytes = ResourceTransforms.Decompress(bytes, "deflate", MaximumLength);
            if (TryNative(bytes, out _)) return ResourceRole.NativePayload;
            using var module = ModuleDefMD.Load(bytes);
            return ResourceRole.ManagedPayload;
        }
        catch (Exception exception) when (ManagedImage.Rejects(exception))
        {
            return ResourceRole.Unknown;
        }
    }

    internal static bool HasPrefix(string name) =>
        name.StartsWith("costura.", StringComparison.OrdinalIgnoreCase) ||
         name.StartsWith("costura32.", StringComparison.OrdinalIgnoreCase) ||
         name.StartsWith("costura64.", StringComparison.OrdinalIgnoreCase);

    internal static bool IsCandidate(string name) => HasPrefix(name) &&
        (name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
         name.EndsWith(".dll.compressed", StringComparison.OrdinalIgnoreCase));

    internal static bool TryNative(byte[] image, out bool upx)
    {
        upx = false;
        try
        {
            using var pe = new PEReader(new MemoryStream(image, writable: false));
            var headers = pe.PEHeaders;
            if (headers.PEHeader is not { } optional || pe.HasMetadata ||
                optional.CorHeaderTableDirectory.RelativeVirtualAddress != 0 ||
                optional.CorHeaderTableDirectory.Size != 0 || headers.SectionHeaders.Length == 0)
                return false;
            foreach (var section in headers.SectionHeaders)
                if (section.SizeOfRawData < 0 || section.PointerToRawData < 0 ||
                    (long)section.PointerToRawData + section.SizeOfRawData > image.Length)
                    return false;
            upx = headers.SectionHeaders.Any(section => section.Name == "UPX0") &&
                  headers.SectionHeaders.Any(section => section.Name == "UPX1");
            return true;
        }
        catch (BadImageFormatException) { return false; }
        catch (IOException) { return false; }
    }
}
