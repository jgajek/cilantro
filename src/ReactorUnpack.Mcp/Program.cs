using ReactorUnpack.Core;
using ReactorUnpack.Mcp;

// One JSON object per line in, one per line out, and nothing else on standard output ever. A client
// reads this stream as protocol, so a stray print would not read as a bug — it would end the session.
if (args.Any(argument => argument is "-h" or "--help" or "/?"))
{
    Console.Error.WriteLine(
        $$"""
        ReactorUnpack MCP {{ReactorPipeline.Version}}

        A Model Context Protocol server, spoken over standard input and output. It is not
        meant to be run by hand: point an MCP client at it, as

          "reactorunpack": { "command": "/path/to/ReactorUnpackMcp" }

        It offers three tools. unpack recovers readable code and hidden payloads from a
        .NET Reactor protected assembly, by reading it rather than running it.
        next_declarations turns what stopped a run into the file to run with next.
        read_output reads back a report or a listing.

        For a person at a terminal, the CLI is the same pipeline with a summary written
        for reading: ReactorUnpack --help, or --json for the same object this returns.

        Docs: docs/agents.md
        """);
    return 0;
}

if (args.Any(argument => argument is "--version"))
{
    Console.WriteLine(ReactorPipeline.Version);
    return 0;
}

new Server(new Rpc(Console.In, Console.Out)).Serve();
return 0;
