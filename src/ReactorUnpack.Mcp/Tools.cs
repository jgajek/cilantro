using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ReactorUnpack.Core;
using ReactorUnpack.Core.Interpretation;

namespace ReactorUnpack.Mcp;

/// <summary>
/// The three things an agent can ask for: run it, work out what to declare next, read what it wrote.
/// </summary>
/// <remarks>
/// <para>
/// Three rather than one for each thing the tool can do, because a caller choosing between fifteen
/// tools spends its first turn choosing. The shape of the work is a loop — run, read what stopped it,
/// answer what only you can answer, run again — and these are its three steps.
/// </para>
/// <para>
/// The descriptions are written for the thing that reads them, which is a model deciding what to call
/// and with what. They say what the tool does, what it costs, and what to do with the answer, because
/// a description that says only what a parameter is named leaves all three to be guessed at.
/// </para>
/// </remarks>
internal static class Tools
{
    /// <summary>
    /// How much of a text file will be handed back at once.
    /// </summary>
    /// <remarks>
    /// A listing of a virtualized method runs to thousands of lines, and the ones this tool produces
    /// are the largest text it produces. Handing back a megabyte of it fills a caller's context with
    /// something it mostly did not want; a slice with a note saying how much was left is the more
    /// useful refusal.
    /// </remarks>
    private const int Most = 64 * 1024;

    public static JsonArray Listed() =>
    [
        new JsonObject
        {
            ["name"] = "unpack",
            ["description"] =
                "Recover readable code and hidden payloads from a .NET Reactor protected assembly. " +
                "The file is read, never run. Returns one JSON object: Wrote names every file " +
                "produced, including the cleaned copy a decompiler can open; Payloads names what was " +
                "hidden inside, each with its SHA-256 and the path it was written to; Blockers says " +
                "what stopped the run and what to declare to get past it; MoreToDeclare says whether " +
                "running again with a fuller declarations file could do better. Takes a few seconds " +
                "for most samples. Set devirtualize to rebuild methods that shipped as bytecode for " +
                "a custom interpreter, which is worth it when the code itself is the question and " +
                "costs a minute or two.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["required"] = new JsonArray("path"),
                ["properties"] = new JsonObject
                {
                    ["path"] = Text("The .NET executable or library to look at."),
                    ["strict"] = Flag(
                        "Refuse rather than assume anything about the Windows machine the sample " +
                        "expects, and leave names and virtualized methods as they are. Off by " +
                        "default, which gets further on its own and says what it assumed."),
                    ["analyzeOnly"] = Flag("Report what is there without writing a cleaned copy."),
                    ["devirtualize"] = Flag(
                        "Rebuild methods that are bytecode for a custom interpreter back into code " +
                        "in the cleaned copy, and check the result by unpacking with it. Off here " +
                        "by default because it costs minutes; RebuiltCheck says what came of it."),
                    ["rename"] = Flag(
                        "Give Reactor's meaningless names readable placeholders. On unless the run " +
                        "is strict."),
                    ["declarations"] = Text(
                        "Path to a declarations file stating what the tool cannot work out for " +
                        "itself. Produce one with next_declarations."),
                    ["allowDeclaredCalls"] = Flag(
                        "Let that file also say what calls the tool cannot read do. Needed whenever " +
                        "a remedy names it, and ignored otherwise."),
                    ["reportDir"] = Text(
                        "Where to write the reports and payloads. Defaults to a reactorunpack " +
                        "folder beside the input."),
                    ["output"] = Text("Where to write the cleaned copy.")
                }
            }
        },
        new JsonObject
        {
            ["name"] = "next_declarations",
            ["description"] =
                "Turn what stopped a run into the declarations file to run with next. Applies every " +
                "remedy the tool can answer itself — a budget, a call that returns nothing — and " +
                "hands back, under Wanted, the ones only you can answer, each naming the kind of " +
                "value it wants. Supply those in answers, keyed by the name the remedy asked under, " +
                "and they are written in. Builds on an existing file rather than replacing it, so a " +
                "loop accumulates. Writes nothing unless into is given, and runs nothing either way: " +
                "whether another run is worth the time is yours to decide.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["required"] = new JsonArray("blockers"),
                ["properties"] = new JsonObject
                {
                    ["blockers"] = Text(
                        "Path to the blocker report a run wrote, which unpack names under " +
                        "Wrote.Blockers."),
                    ["answers"] = new JsonObject
                    {
                        ["type"] = "object",
                        ["description"] =
                            "What you know, keyed by the remedy's Name: a fact key such as " +
                            "env:MachineName, or the signature of a call. A call takes the value it " +
                            "returns, or { \"inert\": true } to say it does nothing. Anything here " +
                            "that was not asked for is written in anyway."
                    },
                    ["from"] = Text(
                        "Path to a declarations file to build on. Pass the one the last run used."),
                    ["into"] = Text("Where to write the result. Omit to be handed it without it being written."),
                    ["name"] = Text("What the declarations file should call itself, for the report.")
                }
            }
        },
        new JsonObject
        {
            ["name"] = "read_output",
            ["description"] =
                "Read something a run wrote: a report, a rename map, or a listing of the program " +
                "behind a virtualized method. Text only. It will not hand back an extracted payload, " +
                "which is malware and is left on disk for a sandbox to be pointed at.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["required"] = new JsonArray("path"),
                ["properties"] = new JsonObject
                {
                    ["path"] = Text("A path from Wrote, or from Payloads if you want to be told no."),
                    ["from"] = new JsonObject
                    {
                        ["type"] = "integer",
                        ["description"] = "Byte to start at, for reading a long listing in pieces.",
                        ["minimum"] = 0
                    }
                }
            }
        }
    ];

    public static JsonObject Call(string name, JsonObject arguments) => name switch
    {
        "unpack" => Unpack(arguments),
        "next_declarations" => Next(arguments),
        "read_output" => Read(arguments),
        _ => Failed($"This server has no {name}. It has unpack, next_declarations and read_output.")
    };

    private static JsonObject Unpack(JsonObject arguments)
    {
        if (Word(arguments, "path") is not { } path)
            return Failed("unpack needs a path.");
        if (Directory.Exists(path))
            return Failed($"That is a folder, not a file: {path}");
        if (!File.Exists(path))
            return Failed($"No such file: {path}");

        try
        {
            var result = new ReactorPipeline().Run(path, new PipelineOptions(
                AnalyzeOnly: Yes(arguments, "analyzeOnly") ?? false,
                RenameSymbols: Yes(arguments, "rename"),
                OutputPath: Word(arguments, "output"),
                ReportDirectory: Word(arguments, "reportDir"),
                DeclarationsPath: Word(arguments, "declarations"),
                AllowDeclaredCalls: Yes(arguments, "allowDeclaredCalls") ?? false,
                Strict: Yes(arguments, "strict") ?? false,
                // Off unless asked for, unlike a run at the command line. The caller here is working
                // through samples rather than looking at one, and a minute a sample is a different
                // price when nobody is watching it go by.
                Devirtualize: Yes(arguments, "devirtualize") ?? false));

            return Said(JsonSerializer.Serialize(
                RunManifest.Of(result), ReactorPipeline.ReportJsonOptions));
        }
        catch (BadImageFormatException)
        {
            return Failed(
                $"{Path.GetFileName(path)} is not a .NET assembly. ReactorUnpack only reads .NET " +
                "executables and libraries.");
        }
        catch (Exception ex) when (
            ex is HostProfileException or TrustedLibraryException or DeclarationException)
        {
            return Failed(ex.Message);
        }
    }

    private static JsonObject Next(JsonObject arguments)
    {
        if (Word(arguments, "blockers") is not { } path)
            return Failed("next_declarations needs the path of a blocker report.");
        if (!File.Exists(path))
            return Failed($"No such file: {path}");

        BlockerReport? report;
        try
        {
            report = JsonSerializer.Deserialize<BlockerReport>(
                File.ReadAllText(path), ReactorPipeline.ReportJsonOptions);
        }
        catch (JsonException ex)
        {
            return Failed($"{path} is not a blocker report: {ex.Message}");
        }

        if (report is null)
            return Failed($"{path} is empty.");

        var from = Word(arguments, "from");
        if (from is not null && !File.Exists(from))
            return Failed($"No such file: {from}");

        var draft = NextDeclarations.From(
            report.Blockers,
            Answers(arguments["answers"] as JsonObject),
            from is null ? null : File.ReadAllText(from),
            Word(arguments, "name"));

        var into = Word(arguments, "into");
        if (into is not null)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(into))!);
            File.WriteAllText(into, draft.Json);
        }

        return Said(JsonSerializer.Serialize(
            new Prepared(
                into,
                JsonNode.Parse(draft.Json),
                draft.Applied,
                [.. draft.Wanted.Select(remedy =>
                    new Asking(remedy.Section, remedy.Name, remedy.Wants))],
                [.. draft.Beyond.Select(blocker =>
                    new Unanswerable(blocker.Kind, blocker.Key, blocker.Detail))],
                draft.Flags,
                draft.Wanted.Count > 0
                    ? "Answer what is under Wanted and call this again, or run with what is here " +
                        "and get further before deciding."
                    : draft.Applied.Count > 0
                        ? draft.Beyond.Count > 0
                            ? "Nothing is left to decide. Run again with this file, and expect what " +
                                "is under Beyond to stop it again: that needs a change to the tool."
                            : "Nothing is left to decide. Run again with this file."
                        : "Nothing here would change the next run. What is under Beyond needs a " +
                            "change to the tool, not a declaration."),
            ReactorPipeline.ReportJsonOptions));
    }

    /// <summary>What next_declarations hands back: the file, and an account of what it settles.</summary>
    private sealed record Prepared(
        string? WrittenTo,
        JsonNode? Declarations,
        IReadOnlyList<string> Applied,
        IReadOnlyList<Asking> Wanted,
        IReadOnlyList<Unanswerable> Beyond,
        IReadOnlyList<string> Flags,
        string Advice);

    /// <summary>A stop waiting on something only the caller can say.</summary>
    private sealed record Asking(string Section, string Name, string? Wants);

    /// <summary>A stop no declarations file will close.</summary>
    private sealed record Unanswerable(BlockerKind Kind, string Key, string Detail);

    private static JsonObject Read(JsonObject arguments)
    {
        if (Word(arguments, "path") is not { } path)
            return Failed("read_output needs a path.");
        if (!File.Exists(path))
            return Failed($"No such file: {path}");

        var length = new FileInfo(path).Length;
        var from = (int)Math.Max(0, arguments["from"]?.GetValue<long>() ?? 0);
        using var stream = File.OpenRead(path);
        var head = new byte[Math.Min(length, Most)];
        var read = stream.Read(head, 0, head.Length);
        if (Binary(head.AsSpan(0, read)))
        {
            return Failed(
                $"{Path.GetFileName(path)} is not text. Extracted payloads are malware and are not " +
                "handed back as bytes; the run named the path and the SHA-256 so that a sandbox can " +
                "be pointed at the file instead.");
        }

        stream.Position = from;
        var slice = new byte[Math.Min(length - from, Most)];
        read = stream.Read(slice, 0, slice.Length);
        var text = Encoding.UTF8.GetString(slice, 0, read);
        var next = from + read;
        return Said(next < length
            ? text + $"\n\n[{next} of {length} bytes. Call again with from: {next} for the rest.]"
            : text);
    }

    /// <summary>What a tool call says when it worked.</summary>
    private static JsonObject Said(string text) => new()
    {
        ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = text })
    };

    /// <summary>
    /// What it says when it did not.
    /// </summary>
    /// <remarks>
    /// A refusal comes back as a result rather than as a protocol error, which is what the protocol
    /// asks for: the call was made correctly and the answer is that it cannot be done, and a caller
    /// that can read the reason can decide what to do about it.
    /// </remarks>
    public static JsonObject Failed(string why) => new()
    {
        ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = why }),
        ["isError"] = true
    };

    private static JsonObject Text(string description) =>
        new() { ["type"] = "string", ["description"] = description };

    private static JsonObject Flag(string description) =>
        new() { ["type"] = "boolean", ["description"] = description };

    private static string? Word(JsonObject arguments, string name) =>
        arguments[name] is JsonValue value && value.TryGetValue<string>(out var text) &&
        !string.IsNullOrWhiteSpace(text)
            ? text
            : null;

    private static bool? Yes(JsonObject arguments, string name) =>
        arguments[name] is JsonValue value && value.TryGetValue<bool>(out var flag) ? flag : null;

    private static Dictionary<string, JsonNode?>? Answers(JsonObject? answers) =>
        answers?.ToDictionary(entry => entry.Key, entry => entry.Value, StringComparer.Ordinal);

    /// <summary>
    /// Whether what was read is bytes rather than text, judged the way it has to be judged.
    /// </summary>
    /// <remarks>
    /// A null byte inside the first stretch of a file is what tells an assembly from a listing, and
    /// every text this tool writes is JSON or plain text with none in it.
    /// </remarks>
    private static bool Binary(ReadOnlySpan<byte> head) => head.Contains((byte)0);
}
