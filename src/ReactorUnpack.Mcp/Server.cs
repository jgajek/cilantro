using System.Text.Json.Nodes;
using ReactorUnpack.Core;

namespace ReactorUnpack.Mcp;

/// <summary>
/// ReactorUnpack as something an agent can call, rather than something a person runs.
/// </summary>
/// <remarks>
/// <para>
/// The same pipeline, reached the same way, with nothing loosened. What the server adds is the part
/// of driving the tool that is otherwise the caller's to write: it names every file a run produced
/// rather than leaving them to be worked out from a naming convention, and it turns what stopped a
/// run into the file the next run should be given.
/// </para>
/// <para>
/// What it deliberately does not add is a decision. It never runs a sample, it never retries on its
/// own, and it never invents a value for a stop that needs one. Whether another run is worth the time
/// is the caller's to judge, because the caller is the one that knows what the answer is for.
/// </para>
/// </remarks>
internal sealed class Server(Rpc rpc)
{
    /// <summary>
    /// The versions of the protocol this speaks. A client asking for one of them gets it back;
    /// anything else is answered with the newest, which the protocol allows and which lets a client
    /// decide whether to carry on.
    /// </summary>
    private static readonly string[] Spoken = ["2025-06-18", "2025-03-26", "2024-11-05"];

    public void Serve()
    {
        while (rpc.Read() is { } message)
        {
            var method = message["method"]?.GetValue<string>();
            var id = message["id"];
            if (method is null)
                continue;

            // A notification has no id and takes no answer, which includes the one the client sends
            // to say it has finished starting up.
            if (id is null)
                continue;

            try
            {
                Answer(method, id, message["params"] as JsonObject);
            }
            catch (Exception ex)
            {
                rpc.Refuse(id, Rpc.Codes.Internal, $"{ex.GetType().Name}: {ex.Message}");
            }
        }
    }

    private void Answer(string method, JsonNode id, JsonObject? parameters)
    {
        switch (method)
        {
            case "initialize":
                rpc.Reply(id, Greeting(parameters));
                break;
            case "ping":
                rpc.Reply(id, new JsonObject());
                break;
            case "tools/list":
                rpc.Reply(id, new JsonObject { ["tools"] = Tools.Listed() });
                break;
            case "tools/call":
                rpc.Reply(id, Called(parameters));
                break;
            // Nothing is offered under these, and saying so is better than a method-not-found, which
            // some clients read as a broken server rather than as an empty shelf.
            case "resources/list":
                rpc.Reply(id, new JsonObject { ["resources"] = new JsonArray() });
                break;
            case "prompts/list":
                rpc.Reply(id, new JsonObject { ["prompts"] = new JsonArray() });
                break;
            default:
                rpc.Refuse(id, Rpc.Codes.MethodNotFound, $"This server has no {method}.");
                break;
        }
    }

    private static JsonObject Greeting(JsonObject? parameters)
    {
        var asked = parameters?["protocolVersion"]?.GetValue<string>();
        return new JsonObject
        {
            ["protocolVersion"] = asked is not null && Spoken.Contains(asked) ? asked : Spoken[0],
            ["capabilities"] = new JsonObject { ["tools"] = new JsonObject() },
            ["serverInfo"] = new JsonObject
            {
                ["name"] = "reactorunpack",
                ["version"] = ReactorPipeline.Version
            },
            ["instructions"] =
                "Recovers readable code and hidden payloads from .NET Reactor protected assemblies " +
                "by reading them, never by running them. Call unpack on a file; read Wrote for what " +
                "it produced and Payloads for what was hidden inside. Where MoreToDeclare is true, " +
                "next_declarations turns what stopped the run into the file to run with next."
        };
    }

    private static JsonObject Called(JsonObject? parameters)
    {
        var name = parameters?["name"]?.GetValue<string>();
        if (name is null)
            return Tools.Failed("A tool call has to say which tool.");
        var arguments = parameters?["arguments"] as JsonObject ?? [];
        return Tools.Call(name, arguments);
    }
}
