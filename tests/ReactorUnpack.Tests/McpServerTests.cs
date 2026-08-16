using System.Text.Json;
using System.Text.Json.Nodes;
using ReactorUnpack.Core;
using ReactorUnpack.Mcp;

namespace ReactorUnpack.Tests;

/// <summary>
/// Covers the server an agent talks to, driven the way a client drives it.
/// </summary>
/// <remarks>
/// Through the protocol rather than around it. A server whose tools are all correct and whose framing
/// is not answers nothing at all, and the framing is the half that has no other test: one JSON object
/// per line, an answer for everything with an id, silence for everything without one, and nothing
/// whatsoever on the stream that is not protocol.
/// </remarks>
public sealed class McpServerTests
{
    /// <summary>
    /// A client says hello and is told what it is talking to, in the version it asked for.
    /// </summary>
    [Fact]
    public void ItAnswersAHelloInTheVersionTheClientAskedFor()
    {
        var said = Session("""
            {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}
            """);

        var result = Assert.Single(said)["result"]!;
        Assert.Equal("2024-11-05", result["protocolVersion"]!.GetValue<string>());
        Assert.Equal("reactorunpack", result["serverInfo"]!["name"]!.GetValue<string>());
        Assert.Equal(
            ReactorPipeline.Version,
            result["serverInfo"]!["version"]!.GetValue<string>());
        Assert.NotNull(result["capabilities"]!["tools"]);
    }

    /// <summary>
    /// A version nobody here speaks gets the newest one rather than a refusal, which leaves the
    /// client to decide whether it can work with it.
    /// </summary>
    [Fact]
    public void AVersionItDoesNotSpeakIsAnsweredWithTheOneItDoes()
    {
        var said = Session("""
            {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}
            """);

        Assert.Equal(
            "2025-06-18",
            Assert.Single(said)["result"]!["protocolVersion"]!.GetValue<string>());
    }

    /// <summary>
    /// A notification is not a question. Answering one puts a message on the stream the client is
    /// not waiting for, and clients differ in how badly they take that.
    /// </summary>
    [Fact]
    public void ANotificationIsNotAnswered()
    {
        var said = Session("""
            {"jsonrpc":"2.0","method":"notifications/initialized"}
            {"jsonrpc":"2.0","id":7,"method":"ping"}
            """);

        Assert.Equal(7, Assert.Single(said)["id"]!.GetValue<int>());
    }

    /// <summary>
    /// Every tool says what it is for and what it takes, because the thing reading the list is
    /// choosing between them on the strength of exactly that.
    /// </summary>
    [Fact]
    public void EveryToolSaysWhatItIsForAndWhatItTakes()
    {
        var said = Session("""{"jsonrpc":"2.0","id":1,"method":"tools/list"}""");

        var tools = Assert.Single(said)["result"]!["tools"]!.AsArray();
        Assert.Equal(
            ["next_declarations", "read_output", "unpack"],
            tools.Select(tool => tool!["name"]!.GetValue<string>()).Order());
        foreach (var tool in tools)
        {
            Assert.False(string.IsNullOrWhiteSpace(tool!["description"]!.GetValue<string>()));
            Assert.Equal("object", tool["inputSchema"]!["type"]!.GetValue<string>());
            Assert.NotEmpty(tool["inputSchema"]!["properties"]!.AsObject());
        }
    }

    /// <summary>
    /// A tool that cannot do what it was asked says so in its answer rather than as a protocol
    /// error, because the call was well formed and the reason is something the caller can act on.
    /// </summary>
    [Fact]
    public void ARefusalComesBackAsAnAnswerAndSaysWhy()
    {
        var said = Session("""
            {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"unpack","arguments":{"path":"/nonexistent/nothing.exe"}}}
            """);

        var result = Assert.Single(said)["result"]!;
        Assert.True(result["isError"]!.GetValue<bool>());
        Assert.Contains(
            "No such file",
            result["content"]![0]!["text"]!.GetValue<string>(),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// A method the server does not have is a protocol error, which is the one case that is.
    /// </summary>
    [Fact]
    public void AMethodItDoesNotHaveIsAProtocolError()
    {
        var said = Session("""{"jsonrpc":"2.0","id":1,"method":"resources/subscribe"}""");

        Assert.Equal(-32601, Assert.Single(said)["error"]!["code"]!.GetValue<int>());
    }

    /// <summary>
    /// The step between two runs, done through the server: a stop that carries a figure is written
    /// into a file the declarations parser then accepts.
    /// </summary>
    [Fact]
    public void ItTurnsWhatStoppedARunIntoTheFileForTheNextOne()
    {
        var directory = Directory.CreateTempSubdirectory("reactorunpack-mcp");
        try
        {
            var blockers = Path.Combine(directory.FullName, "sample.blockers.json");
            File.WriteAllText(blockers, Stopped());
            var into = Path.Combine(directory.FullName, "next.json");

            var said = Session(Ask("next_declarations", new JsonObject
            {
                ["blockers"] = blockers,
                ["into"] = into,
                ["answers"] = new JsonObject { ["env:MachineName"] = "DESKTOP-7QK2" }
            }));

            var answered = JsonNode.Parse(
                Assert.Single(said)["result"]!["content"]![0]!["text"]!.GetValue<string>())!;
            Assert.Equal(into, answered["WrittenTo"]!.GetValue<string>());
            Assert.Empty(answered["Wanted"]!.AsArray());
            Assert.True(File.Exists(into));
            // The file is the point, and a file the tool would then refuse is no use at all.
            var declarations = ReactorUnpack.Core.Interpretation.RunDeclarations.Load(into);
            Assert.Equal(1_500_000, declarations.Budgets.Steps);
            Assert.True(declarations.Facts.TryAnswer("env:MachineName", out var machine));
            Assert.Equal("DESKTOP-7QK2", machine.Text);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    /// <summary>
    /// A loop needs to be told when to stop. A report whose stops no file will close comes back
    /// saying so, rather than as an empty declarations file the caller would run again for nothing.
    /// </summary>
    [Fact]
    public void AStopNoFileWillCloseIsSaidToBeTheEndOfTheLoop()
    {
        var directory = Directory.CreateTempSubdirectory("reactorunpack-mcp");
        try
        {
            var blockers = Path.Combine(directory.FullName, "sample.blockers.json");
            File.WriteAllText(blockers, Stuck());

            var said = Session(Ask("next_declarations", new JsonObject { ["blockers"] = blockers }));

            var answered = JsonNode.Parse(
                Assert.Single(said)["result"]!["content"]![0]!["text"]!.GetValue<string>())!;
            Assert.Empty(answered["Applied"]!.AsArray());
            Assert.Empty(answered["Wanted"]!.AsArray());
            Assert.Single(answered["Beyond"]!.AsArray());
            Assert.Contains(
                "change to the tool",
                answered["Advice"]!.GetValue<string>(),
                StringComparison.Ordinal);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    /// <summary>
    /// It will not hand back an extracted payload. Those are malware, and the run already named the
    /// path and the hash so that something built to hold them can be pointed at the file.
    /// </summary>
    [Fact]
    public void ItWillNotHandBackSomethingThatIsNotText()
    {
        var directory = Directory.CreateTempSubdirectory("reactorunpack-mcp");
        try
        {
            var payload = Path.Combine(directory.FullName, "payload.dll");
            File.WriteAllBytes(payload, [0x4D, 0x5A, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00]);

            var said = Session(Ask("read_output", new JsonObject { ["path"] = payload }));

            var result = Assert.Single(said)["result"]!;
            Assert.True(result["isError"]!.GetValue<bool>());
            Assert.Contains(
                "not text",
                result["content"]![0]!["text"]!.GetValue<string>(),
                StringComparison.Ordinal);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    /// <summary>
    /// Nothing but protocol reaches the stream. A line of prose on standard output does not read as
    /// a bug to a client; it reads as a server that cannot be talked to.
    /// </summary>
    [Fact]
    public void NothingButProtocolReachesTheStream()
    {
        var said = Session("""
            not json at all
            {"jsonrpc":"2.0","id":1,"method":"ping"}
            """);

        Assert.Equal(1, Assert.Single(said)["id"]!.GetValue<int>());
    }

    /// <summary>One tool call, as the line a client would send.</summary>
    private static string Ask(string tool, JsonObject arguments) => new JsonObject
    {
        ["jsonrpc"] = "2.0",
        ["id"] = 1,
        ["method"] = "tools/call",
        ["params"] = new JsonObject { ["name"] = tool, ["arguments"] = arguments }
    }.ToJsonString();

    /// <summary>One session, its messages in and everything the server said back.</summary>
    private static List<JsonObject> Session(string sent)
    {
        var written = new StringWriter();
        new Server(new Rpc(new StringReader(sent), written)).Serve();
        return [.. written.ToString()
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(line => (JsonObject)JsonNode.Parse(line)!)];
    }

    /// <summary>A blocker report holding one stop of each kind that matters here.</summary>
    private static string Stopped() =>
        """
        {
          "ToolVersion": "0.1.0",
          "InputPath": "sample.exe",
          "InputSha256": "0000000000000000000000000000000000000000000000000000000000000000",
          "DeclarationsName": "none",
          "DeclarationsSha256": "",
          "CallsAllowed": false,
          "Blockers": [
            {
              "Kind": "budget",
              "Key": "steps",
              "Detail": "Execution exhausted its 750000-step budget.",
              "Remedy": {
                "Section": "budgets", "Name": "steps", "Value": 1500000,
                "Wants": null, "Flag": null
              },
              "Where": null, "Pass": "string-table-recovery", "Times": 1
            },
            {
              "Kind": "unstatedFact",
              "Key": "env:MachineName",
              "Detail": "Nobody said what the machine is called.",
              "Remedy": {
                "Section": "facts", "Name": "env:MachineName", "Value": null,
                "Wants": "value", "Flag": null
              },
              "Where": null, "Pass": "constant-strings", "Times": 4
            }
          ],
          "UnconsultedDeclarations": [],
          "Strict": false,
          "ContinuedPast": []
        }
        """;

    /// <summary>A blocker report holding one stop that no declarations file will get past.</summary>
    private static string Stuck() =>
        """
        {
          "ToolVersion": "0.1.0",
          "InputPath": "sample.exe",
          "InputSha256": "0000000000000000000000000000000000000000000000000000000000000000",
          "DeclarationsName": "none",
          "DeclarationsSha256": "",
          "CallsAllowed": false,
          "Blockers": [
            {
              "Kind": "threw",
              "Key": "System.InvalidCastException from Lqcuzgc IL_0EF1",
              "Detail": "The method threw where it was interpreted.",
              "Remedy": null,
              "Where": null, "Pass": "payload-extraction", "Times": 1
            }
          ],
          "UnconsultedDeclarations": [],
          "Strict": false,
          "ContinuedPast": []
        }
        """;
}
