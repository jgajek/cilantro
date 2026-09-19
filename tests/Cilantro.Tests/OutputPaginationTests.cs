using System.Text;
using System.Text.Json.Nodes;
using Cilantro.Mcp;

namespace Cilantro.Tests;

public sealed class OutputPaginationTests
{
    [Theory]
    [InlineData(-1L)]
    [InlineData(100000L)]
    [InlineData(2147483648L)]
    [InlineData(4294967296L)]
    [InlineData(long.MaxValue)]
    public void InvalidOffsetsProduceToolErrorsInsteadOfProtocolErrors(long offset)
    {
        WithFile("hello", path =>
        {
            var result = Read(path, JsonValue.Create(offset));
            Assert.True(result["isError"]!.GetValue<bool>());
        });
    }

    [Theory]
    [InlineData("\"invalid\"")]
    [InlineData("1.5")]
    [InlineData("{}")]
    public void InvalidOffsetTypesAreReportedToTheCaller(string json)
    {
        WithFile("hello", path => Assert.True(Read(path, JsonNode.Parse(json))["isError"]!.GetValue<bool>()));
    }

    [Theory]
    [InlineData("é", 65535)]
    [InlineData("€", 65535)]
    [InlineData("😀", 65534)]
    [InlineData("😀", 65533)]
    public void ContinuationsDoNotSplitUtf8Characters(string character, int prefixLength)
    {
        var prefix = new string('a', prefixLength);
        WithFile(prefix + character + "Z", path =>
        {
            var first = Text(Read(path, JsonValue.Create(0L)));
            Assert.StartsWith(prefix + "\n\n[", first, StringComparison.Ordinal);
            Assert.Contains($"from: {prefixLength}", first, StringComparison.Ordinal);
            Assert.DoesNotContain("\uFFFD", first, StringComparison.Ordinal);
            Assert.Equal(character + "Z", Text(Read(path, JsonValue.Create((long)prefixLength))));
            Assert.True(Read(path, JsonValue.Create((long)prefixLength + 1))["isError"]!.GetValue<bool>());
        });
    }

    [Theory]
    [InlineData("")]
    [InlineData("hello")]
    public void ReadingAtEofReturnsEmptyText(string contents)
    {
        WithFile(contents, path => Assert.Equal("", Text(Read(path, JsonValue.Create((long)Encoding.UTF8.GetByteCount(contents))))));
    }

    private static JsonNode Read(string path, JsonNode? from)
    {
        var request = new JsonObject
        {
            ["jsonrpc"] = "2.0", ["id"] = 1, ["method"] = "tools/call",
            ["params"] = new JsonObject { ["name"] = "read_output", ["arguments"] = new JsonObject { ["path"] = path, ["from"] = from } }
        };
        using var output = new StringWriter();
        new Server(new Rpc(new StringReader(request.ToJsonString()), output)).Serve();
        var reply = JsonNode.Parse(output.ToString())!;
        Assert.Null(reply["error"]);
        return reply["result"]!;
    }

    private static string Text(JsonNode result) => result["content"]![0]!["text"]!.GetValue<string>();

    private static void WithFile(string contents, Action<string> check)
    {
        var directory = Directory.CreateTempSubdirectory("cilantro-pagination");
        try
        {
            var path = Path.Combine(directory.FullName, "text.txt");
            File.WriteAllText(path, contents, new UTF8Encoding(false));
            check(path);
        }
        finally { directory.Delete(recursive: true); }
    }
}
