using System.Buffers.Binary;
using dnlib.DotNet;

namespace Cilantro.Core.Payload;

public sealed record ValidatedManagedPayload(
    byte[] Bytes,
    string AssemblyName,
    string ModuleName,
    uint EntryPointToken,
    IReadOnlyList<string> Resources);

public static class PayloadStageValidator
{
    public static bool TryInflateManaged(
        ReadOnlySpan<byte> compressed,
        string codec,
        out ValidatedManagedPayload? payload)
    {
        payload = null;
        byte[] bytes;
        try
        {
            bytes = ResourceTransforms.Decompress(compressed, codec);
        }
        catch (InvalidDataException)
        {
            return false;
        }

        return TryValidateManaged(bytes, out payload);
    }

    public static bool TryValidateManaged(
        byte[] bytes,
        out ValidatedManagedPayload? payload)
    {
        payload = null;
        if (bytes.Length < 2 || bytes[0] != 'M' || bytes[1] != 'Z')
            return false;
        try
        {
            using var module = ModuleDefMD.Load(bytes);
            payload = new ValidatedManagedPayload(
                bytes,
                module.Assembly?.Name.String ?? module.Name.String,
                module.Name,
                module.EntryPoint?.MDToken.Raw ?? 0,
                module.Resources.Select(resource => resource.Name.String).ToArray());
            return true;
        }
        catch (Exception failure) when (ManagedImage.Rejects(failure))
        {
            payload = null;
            return false;
        }
    }

    public static bool TryExtractTerminalByteArray(
        ReadOnlySpan<byte> resourceData,
        out byte[] value)
    {
        value = [];
        var matches = new List<byte[]>();
        for (var offset = 0; offset + 5 <= resourceData.Length; offset++)
        {
            if (resourceData[offset] != 0x20)
                continue;
            var length = BinaryPrimitives.ReadInt32LittleEndian(resourceData[(offset + 1)..]);
            if (length < 0 || offset + 5 + length != resourceData.Length)
                continue;
            matches.Add(resourceData.Slice(offset + 5, length).ToArray());
        }

        if (matches.Count != 1)
            return false;
        value = matches[0];
        return true;
    }
}
