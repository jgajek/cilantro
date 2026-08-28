using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Cilantro.Core;
using Cilantro.Core.Interpretation;

namespace Cilantro.Mcp;

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
                ["properties"] = Knobs()
            }
        },
        new JsonObject
        {
            ["name"] = "start_unpack",
            ["description"] =
                "The same recovery as unpack, started in the background instead of waited for. Takes " +
                "the same arguments and returns at once with a statusPath; poll it with unpack_status " +
                "until Run.Phase is finished, which is when the full manifest arrives. Use this " +
                "whenever the run might take more than a couple of minutes — a large sample, or " +
                "devirtualize set — because a call that outlives your timeout is killed with the " +
                "analysis unfinished and everything it had left to write unwritten. The work carries " +
                "on inside this server, so the run survives a poll that times out; it does not " +
                "survive the server exiting.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["required"] = new JsonArray("path"),
                ["properties"] = Knobs()
            }
        },
        new JsonObject
        {
            ["name"] = "unpack_status",
            ["description"] =
                "How far a background run has got. Cheap, and safe to call every few seconds. Run." +
                "Phase is one of starting, running, finished, failed or cancelled, and Advice says " +
                "what to do about it. While it is running you also get the pass it is in and how many " +
                "of how many are done; when it is finished you get the whole manifest under " +
                "Run.Result, so a poll that sees the end needs no further call. Stalled means nothing " +
                "has been written for a while, which is how a killed run looks — the analysis is gone " +
                "and the files it had written are still there.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["properties"] = new JsonObject
                {
                    ["statusPath"] = Text("The statusPath start_unpack returned. The usual way in."),
                    ["path"] = Text(
                        "The sample instead, if you no longer have the statusPath. Give the same " +
                        "reportDir the run was started with."),
                    ["reportDir"] = Text("The run's reportDir, where path is being used.")
                }
            }
        },
        new JsonObject
        {
            ["name"] = "cancel_unpack",
            ["description"] =
                "Stop a background run. It stops at the end of the pass it is in, so this returns " +
                "before the run has actually finished — poll unpack_status until Phase is cancelled. " +
                "What it had already written to disk stays written, but there is no manifest and no " +
                "cleaned copy, because half a pipeline has nothing to claim. Only runs this server " +
                "started can be stopped.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["properties"] = new JsonObject
                {
                    ["statusPath"] = Text("The statusPath start_unpack returned."),
                    ["path"] = Text("The sample instead, with the reportDir it was started with."),
                    ["reportDir"] = Text("The run's reportDir, where path is being used.")
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
        "start_unpack" => Start(arguments),
        "unpack_status" => Status(arguments),
        "cancel_unpack" => Stop(arguments),
        "next_declarations" => Next(arguments),
        "read_output" => Read(arguments),
        _ => Failed(
            $"This server has no {name}. It has unpack, start_unpack, unpack_status, " +
            "cancel_unpack, next_declarations and read_output.")
    };

    /// <summary>
    /// How long a run may say nothing before a watcher should stop expecting it to say anything.
    /// </summary>
    /// <remarks>
    /// The run writes a heartbeat every few seconds, so anything past a minute is not slowness. It is
    /// set this far above the heartbeat because the alternative error is much worse: calling a live run
    /// dead invites a caller to start a second one on the same sample, and two pipelines writing to one
    /// report directory would leave neither of their results trustworthy.
    /// </remarks>
    private static readonly TimeSpan StaleAfter = TimeSpan.FromSeconds(60);

    /// <summary>
    /// The arguments a run takes, listed once because unpack and start_unpack take the same ones and a
    /// caller that learned one should not have to learn the other.
    /// </summary>
    private static JsonObject Knobs() => new()
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
            "by default because it costs minutes; RebuiltCheck says what came of it. " +
            "Turn it on with start_unpack rather than unpack."),
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
            "Where to write the reports and payloads. Defaults to a cilantro " +
            "folder beside the input."),
        ["output"] = Text("Where to write the cleaned copy.")
    };

    private static PipelineOptions Settings(
        JsonObject arguments,
        string? statusPath,
        CancellationToken cancellation) => new(
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
            Devirtualize: Yes(arguments, "devirtualize") ?? false,
            StatusPath: statusPath,
            Cancellation: cancellation);

    /// <summary>Whatever a run can be handed that is the caller's mistake rather than the sample's.</summary>
    private static JsonObject? Refused(JsonObject arguments, string tool, out string path)
    {
        path = Word(arguments, "path") ?? string.Empty;
        if (path.Length == 0)
            return Failed($"{tool} needs a path.");
        if (Directory.Exists(path))
            return Failed($"That is a folder, not a file: {path}");
        return File.Exists(path) ? null : Failed($"No such file: {path}");
    }

    private static JsonObject Unpack(JsonObject arguments)
    {
        if (Refused(arguments, "unpack", out var path) is { } refusal)
            return refusal;

        try
        {
            var result = new CilantroPipeline().Run(
                path, Settings(arguments, null, CancellationToken.None));

            return Said(JsonSerializer.Serialize(
                RunManifest.Of(result), CilantroPipeline.ReportJsonOptions));
        }
        catch (BadImageFormatException)
        {
            return Failed(
                $"{Path.GetFileName(path)} is not a .NET assembly. CILantro only reads .NET " +
                "executables and libraries.");
        }
        catch (Exception ex) when (
            ex is HostProfileException or TrustedLibraryException or DeclarationException)
        {
            return Failed(ex.Message);
        }
    }

    /// <summary>
    /// Starts a run and returns without waiting for it.
    /// </summary>
    /// <remarks>
    /// What can be refused is refused here, while there is still a caller listening: a path that is not
    /// a file, and a run already under way that this one would write over. Everything after that is the
    /// sample's business and is reported through the status file, because by then this call has
    /// returned.
    /// </remarks>
    private static JsonObject Start(JsonObject arguments)
    {
        if (Refused(arguments, "start_unpack", out var path) is { } refusal)
            return refusal;

        var reportDirectory = Word(arguments, "reportDir");
        var statusPath = RunStatus.PathFor(path, reportDirectory);
        if (Underway(statusPath) is { } underway)
            return Failed(underway);

        // Made here rather than left to the run, so that a run which cannot write where it was told
        // fails now, to a caller that can be told, instead of on a thread nobody is watching.
        try
        {
            Directory.CreateDirectory(RunStatus.DirectoryFor(path, reportDirectory));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Failed($"Cannot write to the report directory: {ex.Message}");
        }

        var settings = Settings(arguments, statusPath, CancellationToken.None);
        if (!Unpacks.TryStart(
                statusPath,
                cancellation => new CilantroPipeline().Run(
                    path, settings with { Cancellation = cancellation })))
        {
            return Failed(
                $"A run on {Path.GetFileName(path)} is already going in this server. Poll it with " +
                $"unpack_status on {statusPath}.");
        }

        return Said(JsonSerializer.Serialize(
            new Started(
                statusPath,
                RunStatus.DirectoryFor(path, reportDirectory),
                "Started. Poll unpack_status on statusPath every 10 to 15 seconds. Phase goes " +
                "finished when the manifest is ready, and the manifest comes back with that poll. " +
                "A sample of any size takes minutes, so expect to poll a good few times before " +
                "anything changes."),
            CilantroPipeline.ReportJsonOptions));
    }

    /// <summary>Why a new run here would be a mistake, or null where it would not.</summary>
    /// <remarks>
    /// Two runs writing one report directory would interleave their payloads and their reports, and the
    /// result would look like a complete analysis of neither sample. So a live run is grounds for
    /// refusing a second, whether this server is the one running it or not — which is why the file is
    /// consulted and not only the registry.
    /// </remarks>
    private static string? Underway(string statusPath)
    {
        if (Unpacks.Owns(statusPath))
        {
            return $"A run is already going in this server. Poll it with unpack_status on {statusPath}.";
        }

        if (RunStatus.Read(statusPath) is not { } status || status.Ended)
        {
            return null;
        }

        var since = DateTimeOffset.UtcNow - status.ObservedUtc;
        return since > StaleAfter
            ? null
            : $"Process {status.ProcessId} is already running this sample and was in " +
                $"{status.Pass ?? "startup"} {(int)since.TotalSeconds}s ago. Poll it with " +
                $"unpack_status on {statusPath}, or point reportDir somewhere else.";
    }

    /// <summary>What start_unpack hands back: where to look, and how often.</summary>
    private sealed record Started(string StatusPath, string ReportDir, string Advice);

    private static JsonObject Status(JsonObject arguments)
    {
        if (Where(arguments, "unpack_status", out var statusPath) is { } refusal)
            return refusal;

        var live = Unpacks.Owns(statusPath);
        if (RunStatus.Read(statusPath) is not { } status)
        {
            return live
                // The window between claiming the slot and writing the first status is short, but a
                // caller that polls straight after starting can land in it, and "no such run" would
                // be the wrong thing to tell it.
                ? Said(JsonSerializer.Serialize(
                    new Watching(null, true, 0, false, "Just started and has not written yet. Poll again."),
                    CilantroPipeline.ReportJsonOptions))
                : Failed(
                    $"No run has written a status to {statusPath}. Check the path, or start one with " +
                    "start_unpack.");
        }

        var since = DateTimeOffset.UtcNow - status.ObservedUtc;
        var stalled = !status.Ended && since > StaleAfter;
        return Said(JsonSerializer.Serialize(
            new Watching(
                status,
                live,
                Math.Round(since.TotalSeconds, 1),
                stalled,
                Counsel(status, stalled)),
            CilantroPipeline.ReportJsonOptions));
    }

    /// <summary>What unpack_status hands back: the run, and what to do about it.</summary>
    /// <param name="Live">
    /// Whether this server is the one doing the work, which is what says whether cancel_unpack would
    /// have anything to cancel.
    /// </param>
    /// <param name="Stalled">
    /// Whether the run has gone quiet for long enough that it is not coming back. Computed here rather
    /// than left to the caller, because working it out means comparing a timestamp against a heartbeat
    /// interval the caller has no reason to know.
    /// </param>
    private sealed record Watching(
        RunStatus? Run,
        bool Live,
        double SecondsSinceObserved,
        bool Stalled,
        string Advice);

    private static string Counsel(RunStatus status, bool stalled) => stalled
        ? $"Nothing written for {(int)(DateTimeOffset.UtcNow - status.ObservedUtc).TotalSeconds}s, " +
            $"so process {status.ProcessId} is gone and this analysis is lost. Whatever it had " +
            "written is still in the report directory. Starting again will begin from the beginning."
        : status.Phase switch
        {
            RunPhase.Finished =>
                "Done. Run.Result is the full manifest: Wrote names every file, Payloads names what " +
                "was hidden inside with the path each was written to, and Blockers with MoreToDeclare " +
                "says whether another run with fuller declarations would do better.",
            RunPhase.Failed =>
                $"The run threw and there is no manifest: {status.Error}",
            RunPhase.Cancelled =>
                $"Stopped on request. {status.Error} There is no manifest, and no cleaned copy.",
            RunPhase.Starting =>
                "Loading the assembly. Poll again in 10 to 15 seconds.",
            _ =>
                $"Running {status.Pass}, {status.PassesDone} of {status.PassesTotal} passes decided " +
                $"after {(int)status.ElapsedSeconds}s. Poll again in 10 to 15 seconds. The slowest " +
                "passes take minutes on their own, so a pass name that has not changed is not a sign " +
                "of trouble."
        };

    private static JsonObject Stop(JsonObject arguments)
    {
        if (Where(arguments, "cancel_unpack", out var statusPath) is { } refusal)
            return refusal;

        if (Unpacks.TryStop(statusPath))
        {
            return Said(
                "Asked it to stop. It stops at the end of the pass it is in, which can take a " +
                $"minute or two, so poll unpack_status on {statusPath} until Phase is cancelled.");
        }

        var status = RunStatus.Read(statusPath);
        return Failed(status switch
        {
            null => $"No run has written a status to {statusPath}, so there is nothing to stop.",
            { Ended: true } => $"That run is already over: {status.Phase}. Read it with unpack_status.",
            _ => $"That run belongs to process {status.ProcessId}, not to this server, so this " +
                "server cannot stop it."
        });
    }

    /// <summary>
    /// Works out which run a status or cancel call is about, from either the path it was handed or the
    /// sample it was started on.
    /// </summary>
    private static JsonObject? Where(JsonObject arguments, string tool, out string statusPath)
    {
        if (Word(arguments, "statusPath") is { } stated)
        {
            statusPath = Path.GetFullPath(stated);
            return null;
        }

        if (Word(arguments, "path") is { } path)
        {
            statusPath = RunStatus.PathFor(path, Word(arguments, "reportDir"));
            return null;
        }

        statusPath = string.Empty;
        return Failed(
            $"{tool} needs either statusPath, which start_unpack returned, or path and the reportDir " +
            "the run was started with.");
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
                File.ReadAllText(path), CilantroPipeline.ReportJsonOptions);
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
            CilantroPipeline.ReportJsonOptions));
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
