using System.Text.Json;
using System.Text.Json.Nodes;
using Cilantro.Core;
using Cilantro.Mcp;

namespace Cilantro.Tests;

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
        Assert.Equal("cilantro", result["serverInfo"]!["name"]!.GetValue<string>());
        Assert.Equal(
            CilantroPipeline.Version,
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
            [
                "cancel_unpack",
                "next_declarations",
                "read_output",
                "start_unpack",
                "unpack",
                "unpack_status"
            ],
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
        var directory = Directory.CreateTempSubdirectory("cilantro-mcp");
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
            var declarations = Cilantro.Core.Interpretation.RunDeclarations.Load(into);
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
        var directory = Directory.CreateTempSubdirectory("cilantro-mcp");
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
        var directory = Directory.CreateTempSubdirectory("cilantro-mcp");
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

    /// <summary>
    /// The whole point of the asynchronous surface: the call that starts a run returns while the run is
    /// still going, and what happened to it is learned by asking rather than by waiting.
    /// </summary>
    /// <remarks>
    /// Driven with a file that is not an assembly, because that reaches a terminal phase in
    /// milliseconds and this test is about the mechanism rather than about a pipeline. A run that ends
    /// badly is the harder case anyway: the outcome has to travel from a thread nobody is holding, out
    /// through a file, to a caller that arrives afterwards.
    /// </remarks>
    [Fact]
    public void AStartedRunReturnsAtOnceAndItsOutcomeIsLearnedByPolling()
    {
        var directory = Directory.CreateTempSubdirectory("cilantro-mcp");
        try
        {
            var sample = Path.Combine(directory.FullName, "notanassembly.exe");
            File.WriteAllText(sample, "This is not a .NET assembly.");
            var reports = Path.Combine(directory.FullName, "reports");

            var started = Answered(Session(Ask("start_unpack", new JsonObject
            {
                ["path"] = sample,
                ["reportDir"] = reports
            })));

            var statusPath = started["StatusPath"]!.GetValue<string>();
            Assert.Equal(RunStatus.PathFor(sample, reports), statusPath);
            Assert.Contains(
                "unpack_status",
                started["Advice"]!.GetValue<string>(),
                StringComparison.Ordinal);

            var watching = PollUntilEnded(statusPath);
            var run = watching["Run"]!;
            Assert.Equal("failed", run["Phase"]!.GetValue<string>());
            Assert.Contains(
                "BadImageFormatException",
                run["Error"]!.GetValue<string>(),
                StringComparison.Ordinal);
            // Nothing was recovered, so there is no manifest to hand back. A caller that branched on
            // the phase would never look, but one that read Result first must not find a half of one.
            Assert.Null(run["Result"]);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    /// <summary>
    /// A second run into a report directory another run is still writing is refused, and told where to
    /// look instead.
    /// </summary>
    /// <remarks>
    /// The refusal rests on the file rather than on this server's own bookkeeping, because the run that
    /// is already going may belong to a different process — a command-line run, or this server before
    /// it was restarted. Two pipelines writing one report directory would interleave their payloads and
    /// leave a result that looks complete and describes neither sample.
    /// </remarks>
    [Fact]
    public void ARunIntoADirectoryAnotherRunIsUsingIsRefused()
    {
        var directory = Directory.CreateTempSubdirectory("cilantro-mcp");
        try
        {
            var sample = Path.Combine(directory.FullName, "sample.exe");
            File.WriteAllText(sample, "not an assembly");
            var reports = Path.Combine(directory.FullName, "reports");
            Directory.CreateDirectory(reports);
            File.WriteAllText(
                RunStatus.PathFor(sample, reports),
                Underway(DateTimeOffset.UtcNow, pass: "method-body-recovery"));

            var said = Session(Ask("start_unpack", new JsonObject
            {
                ["path"] = sample,
                ["reportDir"] = reports
            }));

            var result = Assert.Single(said)["result"]!;
            Assert.True(result["isError"]!.GetValue<bool>());
            var why = result["content"]![0]!["text"]!.GetValue<string>();
            Assert.Contains("already running", why, StringComparison.Ordinal);
            Assert.Contains("method-body-recovery", why, StringComparison.Ordinal);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    /// <summary>
    /// A run that has said nothing for a long time is not a run any more. Saying so is what stops a
    /// caller waiting out a process that is already gone.
    /// </summary>
    [Fact]
    public void ARunThatHasGoneQuietIsReportedAsLostRatherThanSlow()
    {
        var directory = Directory.CreateTempSubdirectory("cilantro-mcp");
        try
        {
            var statusPath = Path.Combine(directory.FullName, "sample.status.json");
            File.WriteAllText(
                statusPath,
                Underway(DateTimeOffset.UtcNow.AddHours(-1), pass: "resource-restoration"));

            var watching = Answered(Session(Ask("unpack_status", new JsonObject
            {
                ["statusPath"] = statusPath
            })));

            Assert.True(watching["Stalled"]!.GetValue<bool>());
            Assert.False(watching["Live"]!.GetValue<bool>());
            Assert.Contains(
                "is lost",
                watching["Advice"]!.GetValue<string>(),
                StringComparison.Ordinal);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    /// <summary>
    /// Asked about a run that never existed, it says so rather than describing an absence as a phase.
    /// </summary>
    [Fact]
    public void AStatusCallAboutNoRunAtAllSaysSo()
    {
        var said = Session(Ask("unpack_status", new JsonObject
        {
            ["statusPath"] = "/nonexistent/sample.status.json"
        }));

        var result = Assert.Single(said)["result"]!;
        Assert.True(result["isError"]!.GetValue<bool>());
        Assert.Contains(
            "No run has written a status",
            result["content"]![0]!["text"]!.GetValue<string>(),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// Both of the polling tools need to know which run they are about, and neither guesses.
    /// </summary>
    [Theory]
    [InlineData("unpack_status")]
    [InlineData("cancel_unpack")]
    public void PollingWithoutSayingWhichRunIsRefused(string tool)
    {
        var said = Session(Ask(tool, []));

        var result = Assert.Single(said)["result"]!;
        Assert.True(result["isError"]!.GetValue<bool>());
        Assert.Contains(
            "statusPath",
            result["content"]![0]!["text"]!.GetValue<string>(),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// A run this server did not start cannot be stopped by it, and the refusal names the process that
    /// could, rather than reporting a success that would leave a caller waiting for a phase that is
    /// never coming.
    /// </summary>
    [Fact]
    public void ItWillNotClaimToHaveStoppedARunItDoesNotOwn()
    {
        var directory = Directory.CreateTempSubdirectory("cilantro-mcp");
        try
        {
            var statusPath = Path.Combine(directory.FullName, "sample.status.json");
            File.WriteAllText(statusPath, Underway(DateTimeOffset.UtcNow, pass: "string-recovery"));

            var said = Session(Ask("cancel_unpack", new JsonObject { ["statusPath"] = statusPath }));

            var result = Assert.Single(said)["result"]!;
            Assert.True(result["isError"]!.GetValue<bool>());
            Assert.Contains(
                "not to this server",
                result["content"]![0]!["text"]!.GetValue<string>(),
                StringComparison.Ordinal);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    /// <summary>Polls the way a caller is told to, and hands back the answer that ended it.</summary>
    private static JsonNode PollUntilEnded(string statusPath)
    {
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (true)
        {
            var watching = Answered(Session(Ask("unpack_status", new JsonObject
            {
                ["statusPath"] = statusPath
            })));
            if (watching["Run"] is { } run && run["Ended"]!.GetValue<bool>())
            {
                return watching;
            }

            Assert.True(DateTime.UtcNow < deadline, $"The run never ended: {watching.ToJsonString()}");
            Thread.Sleep(25);
        }
    }

    /// <summary>The JSON a tool handed back, given the session it was asked in.</summary>
    private static JsonNode Answered(List<JsonObject> said) =>
        JsonNode.Parse(Assert.Single(said)["result"]!["content"]![0]!["text"]!.GetValue<string>())!;

    /// <summary>A status file left behind by a run in progress, as another process would have written it.</summary>
    private static string Underway(DateTimeOffset observed, string pass) =>
        JsonSerializer.Serialize(
            new RunStatus(
                RunStatus.Current,
                CilantroPipeline.Version,
                RunPhase.Running,
                "sample.exe",
                pass,
                12,
                40,
                observed.AddMinutes(-2),
                observed,
                // Not this process, so that a cancel has to refuse rather than finding itself the owner.
                Environment.ProcessId + 1,
                120,
                null,
                null),
            CilantroPipeline.ReportJsonOptions);

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
