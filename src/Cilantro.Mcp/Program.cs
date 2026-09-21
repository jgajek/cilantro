using Cilantro.Core;
using Cilantro.Mcp;

// One JSON object per line in, one per line out, and nothing else on standard output ever. A client
// reads this stream as protocol, so a stray print would not read as a bug — it would end the session.
if (args.Any(argument => argument is "-h" or "--help" or "/?"))
{
    Console.Error.WriteLine(
        $$"""
        CILantro MCP {{CilantroPipeline.Version}}

        A Model Context Protocol server, spoken over standard input and output. It is not
        meant to be run by hand: point an MCP client at it, as

          "cilantro": { "command": "/path/to/cilantro-mcp" }

        unpack performs static recovery on supported Reactor and ConfuserEx samples.
        start_unpack, unpack_status, and cancel_unpack manage longer background runs.
        next_declarations prepares declarations from blockers and supplied answers.
        read_output reads reports and listings as text; it does not return binaries.

        Recovery can be partial. Structural verification and reconstruction comparisons
        are separate results. VM reconstruction is opt-in here (devirtualize: true).

        For a person at a terminal, the CLI is the same pipeline with a summary written
        for reading: cilantro --help, or --json for the same object this returns.

        Docs: docs/agents.md
        """);
    return 0;
}

if (args.Any(argument => argument is "--version"))
{
    Console.WriteLine(CilantroPipeline.Version);
    return 0;
}

new Server(new Rpc(Console.In, Console.Out)).Serve();
return 0;
