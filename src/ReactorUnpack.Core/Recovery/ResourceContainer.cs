using dnlib.DotNet;
using ReactorUnpack.Core.Payload;

namespace ReactorUnpack.Core.Recovery;

/// <summary>
/// Reads the plaintext bundle Reactor serves an assembly's managed resources from.
/// </summary>
/// <remarks>
/// The bundle is not a bespoke archive: Reactor moves the original <c>.resources</c> streams into a
/// satellite assembly, encrypts that assembly, and hands it back to the runtime from a resolve hook,
/// so the resources are simply the satellite's own resources. Reading the bundle is therefore a
/// metadata parse rather than a reverse-engineered layout, which is what keeps it independent of the
/// cipher, key schedule, and packaging a given version happens to use.
///
/// Parsing doubles as the test for whether a candidate buffer is the bundle. A decryptor allocates
/// many intermediate buffers, and only one of them is a loadable assembly carrying resources, so
/// requiring a successful parse picks the plaintext out without having to trace which buffer the
/// decryptor considered its result.
/// </remarks>
public static class ResourceContainer
{
    public sealed record Entry(string Name, byte[] Data);

    public static bool LooksLikeContainer(byte[] bundle) =>
        TryParse(bundle, out var entries) && entries.Count != 0;

    /// <summary>
    /// Reads the named resource streams out of a plaintext bundle, or reports that it is not one.
    /// </summary>
    public static bool TryParse(byte[] bundle, out IReadOnlyList<Entry> entries)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        entries = [];
        if (bundle.Length < 0x40 || bundle[0] != 'M' || bundle[1] != 'Z')
            return false;
        ModuleDefMD? module = null;
        try
        {
            module = ModuleDefMD.Load(bundle);
            var parsed = module.Resources
                .OfType<EmbeddedResource>()
                .Select(resource => new Entry(
                    resource.Name.String, resource.CreateReader().ToArray()))
                .ToArray();
            if (parsed.Length == 0)
                return false;
            entries = parsed;
            return true;
        }
        catch (Exception exception) when (ManagedImage.Rejects(exception))
        {
            return false;
        }
        finally
        {
            module?.Dispose();
        }
    }
}
