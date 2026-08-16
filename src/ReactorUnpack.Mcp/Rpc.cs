using System.Text.Json;
using System.Text.Json.Nodes;

namespace ReactorUnpack.Mcp;

/// <summary>
/// The JSON-RPC that the Model Context Protocol is carried in, over standard input and output.
/// </summary>
/// <remarks>
/// <para>
/// Written out here rather than taken from a package. What a server offering three tools has to
/// understand is one framing rule and five method names, and the whole of it is shorter than the
/// paragraph that would explain which version of a dependency it is pinned to. The tool's one
/// dependency is a metadata library it cannot do without; this is not that.
/// </para>
/// <para>
/// The framing rule is the one thing worth stating: over standard input and output, each message is
/// one JSON object on one line, and nothing else may be written to standard output. Anything the
/// server wants to say to a person goes to standard error. A stray print on standard output does not
/// look like a bug to the client — it looks like a protocol violation, and the session ends.
/// </para>
/// </remarks>
internal sealed class Rpc(TextReader input, TextWriter output)
{
    /// <summary>Reads the next message, or null at end of input.</summary>
    public JsonObject? Read()
    {
        while (input.ReadLine() is { } line)
        {
            if (string.IsNullOrWhiteSpace(line))
                continue;
            JsonNode? parsed;
            try
            {
                parsed = JsonNode.Parse(line);
            }
            catch (JsonException)
            {
                // A line that is not JSON cannot be answered, because an answer needs the id that
                // was in it. Saying so on standard error is all that can be done.
                Console.Error.WriteLine("reactorunpack-mcp: ignoring a line that is not JSON.");
                continue;
            }

            if (parsed is JsonObject message)
                return message;
        }

        return null;
    }

    /// <summary>Answers a request.</summary>
    public void Reply(JsonNode? id, JsonNode? result) => Send(new JsonObject
    {
        ["jsonrpc"] = "2.0",
        ["id"] = id?.DeepClone(),
        ["result"] = result
    });

    /// <summary>Refuses a request, in the way the protocol says to.</summary>
    public void Refuse(JsonNode? id, int code, string message) => Send(new JsonObject
    {
        ["jsonrpc"] = "2.0",
        ["id"] = id?.DeepClone(),
        ["error"] = new JsonObject { ["code"] = code, ["message"] = message }
    });

    private void Send(JsonObject message)
    {
        output.WriteLine(message.ToJsonString());
        output.Flush();
    }

    /// <summary>The error codes JSON-RPC defines, which are the only ones this uses.</summary>
    public static class Codes
    {
        public const int MethodNotFound = -32601;
        public const int InvalidParams = -32602;
        public const int Internal = -32603;
    }
}
