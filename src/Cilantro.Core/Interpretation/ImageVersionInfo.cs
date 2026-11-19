using System.Buffers.Binary;
using System.Text;
using Cilantro.Core.Analysis;

namespace Cilantro.Core.Interpretation;

/// <summary>Reads version data from registered PE bytes, never the analysis host's filesystem.</summary>
internal sealed record ImageVersionInfo(IReadOnlyDictionary<string, string> Strings, uint FileHigh = 0,
    uint FileLow = 0, uint ProductHigh = 0, uint ProductLow = 0)
{
    internal static bool TryRead(byte[] bytes, out ImageVersionInfo info)
    {
        info = new(new Dictionary<string, string>());
        try
        {
            var image = new PeImageView(bytes);
            var resources = Win32ResourceTable.Read(image).Where(r => r.TypeName is null && r.TypeId == 16).ToArray();
            if (resources.Length == 0) return true;
            // Choosing a translation requires a modeled Windows language preference.
            if (resources.Length != 1) return false;
            return Win32ResourceTable.TryReadBytes(image, resources[0], out var data) && TryParse(data.Span, out info);
        }
        catch (BadImageFormatException) { return false; }
    }

    internal static bool TryParse(ReadOnlySpan<byte> data, out ImageVersionInfo info)
    {
        info = new(new Dictionary<string, string>());
        var count = 0;
        if (!Read(data, 0, data.Length, 0, ref count, out var root) || root.Key != "VS_VERSION_INFO") return false;
        uint high = 0, low = 0, productHigh = 0, productLow = 0;
        if (root.Value.Length != 0)
        {
            if (root.Value.Length != 52 || BinaryPrimitives.ReadUInt32LittleEndian(root.Value) != 0xFEEF04BD) return false;
            high = BinaryPrimitives.ReadUInt32LittleEndian(root.Value.AsSpan(8));
            low = BinaryPrimitives.ReadUInt32LittleEndian(root.Value.AsSpan(12));
            productHigh = BinaryPrimitives.ReadUInt32LittleEndian(root.Value.AsSpan(16));
            productLow = BinaryPrimitives.ReadUInt32LittleEndian(root.Value.AsSpan(20));
        }
        var strings = new Dictionary<string, string>(StringComparer.Ordinal);
        // Keep one language table together instead of mixing values from different translations.
        var tables = root.Children.FirstOrDefault(n => n.Key == "StringFileInfo")?.Children;
        if (tables is { Count: > 1 }) return false;
        var table = tables is { Count: > 0 } ? tables[0] : null;
        foreach (var item in table?.Children ?? [])
        {
            if (item.Type != 1 || item.Value.Length % 2 != 0) return false;
            strings.TryAdd(item.Key, Encoding.Unicode.GetString(item.Value).TrimEnd('\0'));
        }
        info = new(strings, high, low, productHigh, productLow);
        return true;
    }

    private sealed record Node(string Key, ushort Type, byte[] Value, IReadOnlyList<Node> Children);

    private static bool Read(ReadOnlySpan<byte> data, int start, int limit, int depth, ref int count, out Node node)
    {
        node = null!;
        if (depth > 4 || ++count > 512 || limit - start < 6) return false;
        var length = BinaryPrimitives.ReadUInt16LittleEndian(data[start..]);
        var valueLength = BinaryPrimitives.ReadUInt16LittleEndian(data[(start + 2)..]);
        var type = BinaryPrimitives.ReadUInt16LittleEndian(data[(start + 4)..]);
        if (length < 6 || length > limit - start || type > 1) return false;
        var end = start + length;
        var position = start + 6;
        var keyStart = position;
        while (position + 2 <= end && position - keyStart <= 1024 &&
               BinaryPrimitives.ReadUInt16LittleEndian(data[position..]) != 0) position += 2;
        if (position + 2 > end || position - keyStart > 1024) return false;
        var key = Encoding.Unicode.GetString(data[keyStart..position]);
        position = (position + 2 + 3) & ~3;
        var size = type == 1 ? valueLength * 2 : valueLength;
        if (position > end || size > end - position) return false;
        var value = data.Slice(position, size).ToArray();
        position = (position + size + 3) & ~3;
        var children = new List<Node>();
        while (position < end)
        {
            if (!Read(data, position, end, depth + 1, ref count, out var child)) return false;
            children.Add(child);
            position = (position + BinaryPrimitives.ReadUInt16LittleEndian(data[position..]) + 3) & ~3;
        }
        node = new(key, type, value, children);
        return true;
    }
}
