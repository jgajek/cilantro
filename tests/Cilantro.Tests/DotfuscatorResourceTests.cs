using System.Resources;
using Cilantro.Core.Codec;

namespace Cilantro.Tests;

public sealed class DotfuscatorResourceTests
{
    [Fact]
    public void CapturedStringAndBinaryEntriesDecodeWithoutLoadingTheRuntime()
    {
        // Captured from the source-built net48 resource probe, Dotfuscator 7.9.
        var container = Container(writer =>
        {
            writer.AddResource("Message", Convert.FromHexString("019ECDA0E4A2F0A4EAA6F2A8FBAAE8ACE8AEF0B0E1B2E1B4FAB6F5B8FCBA9BBCCDBECDC0AEC2B7C4A0C6A4C8BDCAAECCA9CEEFD0A3D2B6D4A6D6B8D8ACDAA9DCBEDEBA"));
            writer.AddResource("Bytes", Convert.FromHexString("009E9FA0A0A2DCA425A659A856"));
            writer.AddResource("Empty", new byte[] { 1 });
            writer.AddResource("Unselected", new byte[] { 1, 0x63, 0x61, 0x66, 0xc3, 0xa9 });
            writer.AddResource("RawBytes", new byte[] { 0, 0, 0xff });
        });
        Assert.True(DotfuscatorResourceCodec.TryRestore(container, 1236847774,
            new HashSet<string>(["Message", "Bytes", "Empty"], StringComparer.Ordinal), out var restored, out var count, out var why), why);
        Assert.Equal(5, count);
        using var reader = new ResourceReader(new MemoryStream(restored));
        var entries = reader.Cast<System.Collections.DictionaryEntry>().ToDictionary(entry => (string)entry.Key, entry => entry.Value);
        Assert.Equal("RESOURCE_PROBE protected resource", entries["Message"]);
        Assert.Equal(new byte[] { 0, 1, 127, 128, 254, 255 }, entries["Bytes"]);
        Assert.Equal("", entries["Empty"]);
        Assert.Equal("café", entries["Unselected"]);
        Assert.Equal(new byte[] { 0, 255 }, entries["RawBytes"]);
    }

    [Theory]
    [InlineData("0100")]
    [InlineData("02")]
    [InlineData("")]
    public void InvalidEntryLayoutsDecline(string encoded)
    {
        var input = Container(writer => writer.AddResource("Entry", Convert.FromHexString(encoded)));
        Assert.False(DotfuscatorResourceCodec.TryRestore(input, 1, new HashSet<string>(["Entry"]), out var bytes, out var count, out _));
        Assert.Empty(bytes);
        Assert.Equal(0, count);
    }

    [Fact]
    public void ProducerPrimitiveTextPayloadsRemainBytes()
    {
        var texts = new[] { "-1234567", "True", "12345.6789", "-1.25", "Ω", "9223372036854775807" };
        var input = Container(writer =>
        {
            foreach (var text in texts)
                writer.AddResource(text, new byte[] { 0 }.Concat(System.Text.Encoding.UTF8.GetBytes(text)).ToArray());
        });
        Assert.True(DotfuscatorResourceCodec.TryRestore(input, 0, new HashSet<string>(), out var restored, out var count, out var why), why);
        Assert.Equal(texts.Length, count);
        using var reader = new ResourceReader(new MemoryStream(restored));
        var values = reader.Cast<System.Collections.DictionaryEntry>().ToDictionary(entry => (string)entry.Key, entry => entry.Value);
        foreach (var text in texts)
            Assert.Equal(System.Text.Encoding.UTF8.GetBytes(text), Assert.IsType<byte[]>(values[text]));
    }

    [Fact]
    public void UserDefinedResourceTypesAreRejectedWithoutDeserialization()
    {
        var input = Container(writer => writer.AddResourceData("Entry", "Unknown.Payload, Unavailable.Assembly", [1, 2, 3]));
        Assert.False(DotfuscatorResourceCodec.TryRestore(input, 1, new HashSet<string>(), out _, out _, out var why));
        Assert.Contains("wrapped byte-array", why);
    }

    private static byte[] Container(Action<ResourceWriter> populate)
    {
        using var output = new MemoryStream();
        using var writer = new ResourceWriter(output);
        populate(writer);
        writer.Generate();
        return output.ToArray();
    }
}
