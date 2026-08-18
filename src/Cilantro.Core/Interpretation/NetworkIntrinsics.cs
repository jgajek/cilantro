using System.Globalization;
using dnlib.DotNet;

namespace Cilantro.Core.Interpretation;

/// <summary>
/// Answers what a URL is made of, by asking the framework the same question.
/// </summary>
/// <remarks>
/// Parsing a URL is arithmetic on text: the same string yields the same host, port and path on every
/// machine, under every culture, whether or not anything is listening at the other end. So these are
/// not questions about the host and there is nothing to state about them — the framework's own parser
/// answers, which is also the only way to be sure the answer is the one the sample would have got.
/// A string the parser rejects is refused rather than answered, because what a program does with a
/// malformed address is throw, and that is a path this does not follow.
/// </remarks>
public sealed class UriIntrinsic : IStaticIntrinsic
{
    private const string Parsed = "Uri";

    public bool Matches(IMethod method) => method?.DeclaringType?.FullName == "System.Uri";

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(arguments);
        var heap = context.State.Heap;
        var name = method.Name.String;

        switch (name)
        {
            case "CheckHostName" when arguments.Count == 1 &&
                heap.TryGetString(arguments[0], out var host):
                return IntrinsicResult.Completed(StaticValue.FromInt32((int)Uri.CheckHostName(host)));
            case "CheckSchemeName" when arguments.Count == 1 &&
                heap.TryGetString(arguments[0], out var scheme):
                return IntrinsicResult.Completed(
                    StaticValue.FromInt32(Uri.CheckSchemeName(scheme) ? 1 : 0));
            case "IsWellFormedUriString" when arguments.Count == 2 &&
                heap.TryGetString(arguments[0], out var candidate):
                return IntrinsicResult.Completed(StaticValue.FromInt32(
                    Uri.IsWellFormedUriString(candidate, (UriKind)arguments[1].AsInt32()) ? 1 : 0));
            case "EscapeDataString" or "UnescapeDataString" when arguments.Count == 1 &&
                heap.TryGetString(arguments[0], out var raw):
                return heap.TryAllocateString(
                    name == "EscapeDataString"
                        ? Uri.EscapeDataString(raw)
                        : Uri.UnescapeDataString(raw),
                    out var escaped)
                    ? IntrinsicResult.Completed(escaped)
                    : IntrinsicResult.Invalid("Could not allocate the escaped text.");
            case ".ctor" when arguments.Count >= 2:
            {
                if (!heap.TryGetString(arguments[1], out var spelled))
                    return IntrinsicResult.Invalid("The address being parsed is not a known string.");
                var kind = arguments.Count >= 3 && arguments[2].IsInteger
                    ? (UriKind)arguments[2].AsInt32()
                    : UriKind.Absolute;
                if (!Uri.TryCreate(spelled, kind, out var made))
                {
                    return IntrinsicResult.Invalid(
                        $"\"{spelled}\" is not an address the framework would accept, so the " +
                        "program throws here.");
                }

                heap.TrySetModelValue(arguments[0], Parsed, made);
                return IntrinsicResult.Completed();
            }

            case "TryCreate" when arguments.Count == 3:
            {
                if (!heap.TryGetString(arguments[0], out var spelled))
                    return IntrinsicResult.Invalid("The address being parsed is not a known string.");
                var made = Uri.TryCreate(spelled, (UriKind)arguments[1].AsInt32(), out var built);
                if (arguments[2].Kind != StaticValueKind.ManagedReference)
                    return IntrinsicResult.Invalid("TryCreate was not given somewhere to write.");
                var written = StaticValue.Null;
                if (made && built is not null)
                {
                    if (!heap.TryAllocateObject("System.Uri", out written))
                        return IntrinsicResult.Invalid("Could not allocate the parsed address.");
                    heap.TrySetModelValue(written, Parsed, built);
                }

                heap.TryWriteManaged(arguments[2], written);
                return IntrinsicResult.Completed(StaticValue.FromInt32(made ? 1 : 0));
            }

            default:
                return Describe(context, name, arguments);
        }
    }

    /// <summary>Answers one question about an address this machine has already parsed.</summary>
    private static IntrinsicResult Describe(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (arguments.Count == 0 || !heap.TryGetModelValue<Uri>(arguments[0], Parsed, out var uri) ||
            uri is null)
            return IntrinsicResult.Invalid($"Unsupported address operation {name}.");
        switch (name)
        {
            case "get_Port":
                return IntrinsicResult.Completed(StaticValue.FromInt32(uri.Port));
            case "get_IsDefaultPort":
                return IntrinsicResult.Completed(StaticValue.FromInt32(uri.IsDefaultPort ? 1 : 0));
            case "get_IsLoopback":
                return IntrinsicResult.Completed(StaticValue.FromInt32(uri.IsLoopback ? 1 : 0));
            case "get_IsAbsoluteUri":
                return IntrinsicResult.Completed(StaticValue.FromInt32(uri.IsAbsoluteUri ? 1 : 0));
            case "get_HostNameType":
                return IntrinsicResult.Completed(StaticValue.FromInt32((int)uri.HostNameType));
            default:
                var text = name switch
                {
                    "get_Host" => uri.Host,
                    "get_DnsSafeHost" => uri.DnsSafeHost,
                    "get_Scheme" => uri.Scheme,
                    "get_AbsolutePath" => uri.AbsolutePath,
                    "get_AbsoluteUri" => uri.AbsoluteUri,
                    "get_PathAndQuery" => uri.PathAndQuery,
                    "get_Query" => uri.Query,
                    "get_Fragment" => uri.Fragment,
                    "get_Authority" => uri.Authority,
                    "get_OriginalString" => uri.OriginalString,
                    "ToString" => uri.ToString(),
                    _ => null
                };
                if (text is null)
                    return IntrinsicResult.Invalid($"Unsupported address operation {name}.");
                return heap.TryAllocateString(text, out var written)
                    ? IntrinsicResult.Completed(written)
                    : IntrinsicResult.Invalid("Could not allocate the part of the address asked for.");
        }
    }
}

/// <summary>
/// Models the outbound side of a program: everything up to the connection, and then a stop that says
/// where the connection was going.
/// </summary>
/// <remarks>
/// <para>
/// A stager that keeps its next stage on a server reaches it through here, and the address is the
/// thing worth reporting about such a sample — more than the fact that it failed to be unpacked. So
/// the parts that only arrange a connection are modeled: an endpoint is an address and a port, a
/// socket is a set of options, and none of that touches the network. What does touch it stops, and
/// the refusal names the host and port it was about to reach, which is the intelligence the run
/// produces even though the payload is not here to recover.
/// </para>
/// <para>
/// A name lookup is a question about the network the machine is on, so a profile may answer it, and
/// one that does not leaves the refusal naming the host that was being resolved. Nothing is invented:
/// an unreachable server is not reported as an empty response, because a program handed an empty
/// response goes on to do something with it and would be doing that for a reason this machine made
/// up.
/// </para>
/// </remarks>
public sealed class SocketIntrinsic : IStaticIntrinsic
{
    private const string Address = "Address";
    private const string Port = "Port";

    public bool Matches(IMethod method) =>
        method?.DeclaringType?.FullName is
            "System.Net.Sockets.Socket" or
            "System.Net.Sockets.TcpClient" or
            "System.Net.Sockets.NetworkStream" or
            "System.Net.IPEndPoint" or
            "System.Net.IPAddress" or
            "System.Net.Dns";

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(arguments);
        var heap = context.State.Heap;
        var name = method.Name.String;
        var declaring = method.DeclaringType?.FullName ?? string.Empty;

        if (declaring == "System.Net.Dns")
            return Resolve(context, name, arguments);
        if (declaring == "System.Net.IPAddress")
            return Numbered(context, name, arguments);
        if (declaring == "System.Net.IPEndPoint")
            return Endpoint(context, name, arguments);

        switch (name)
        {
            // Making a socket, choosing its options and closing it all happen without a connection.
            case ".ctor" or "SetSocketOption" or "Close" or "Dispose" or "Shutdown" or "Bind" or
                "Listen":
                return IntrinsicResult.Completed();
            case var _ when name.StartsWith("set_", StringComparison.Ordinal):
                return IntrinsicResult.Completed();
            case "Connect" or "ConnectAsync" or "BeginConnect" or "Send" or "SendTo" or "SendAsync" or
                "Receive" or "ReceiveFrom" or "ReceiveAsync" or "Poll" or "Accept" or "Read" or
                "Write" or "get_Connected" or "get_Available" or "GetStream":
            {
                var where = Reached(heap, arguments);
                var doing = name.StartsWith("Connect", StringComparison.Ordinal) ||
                    name == "BeginConnect"
                        ? "opens a connection"
                        : "uses a connection";
                return new IntrinsicResult(
                    StaticExecutionStatus.Unsupported,
                    StaticValue.Unknown,
                    $"the program {doing}{where}, and there is no network here, so what comes back " +
                    "over it is not known");
            }

            default:
                return IntrinsicResult.Invalid($"Unsupported socket operation {name}.");
        }
    }

    /// <summary>Where a call was about to reach, as far as its arguments say.</summary>
    private static string Reached(StaticHeap heap, IReadOnlyList<StaticValue> arguments)
    {
        for (var index = 1; index < arguments.Count; index++)
        {
            if (heap.TryGetModelValue<string>(arguments[index], Address, out var held) &&
                held is not null)
            {
                return heap.TryGetModelValue<int>(arguments[index], Port, out var port) && port != 0
                    ? $" to {held}:{port}"
                    : $" to {held}";
            }

            if (!heap.TryGetString(arguments[index], out var host))
                continue;
            return index + 1 < arguments.Count && arguments[index + 1].IsInteger
                ? $" to {host}:{arguments[index + 1].AsInt32()}"
                : $" to {host}";
        }

        return string.Empty;
    }

    /// <summary>Answers a name lookup, which is a question about the network the machine is on.</summary>
    private static IntrinsicResult Resolve(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (arguments.Count == 0 || !heap.TryGetString(arguments[0], out var host))
            return IntrinsicResult.Invalid($"Unsupported name lookup {name}.");
        var key = $"net:dns:{host}";
        if (!HostFacts.TryAsk(context, key, out var stated) ||
            stated.Kind != HostAnswerKind.Text)
            return HostFacts.Refuse(context, key);
        if (!heap.TryAllocateObject("System.Net.IPAddress", out var address))
            return IntrinsicResult.Invalid("Could not allocate the resolved address.");
        heap.TrySetModelValue(address, Address, stated.Text);
        // Both lookups answer with a list; a profile states one machine, so the list holds one.
        if (name is not ("GetHostAddresses" or "GetHostAddressesAsync"))
            return IntrinsicResult.Invalid($"Unsupported name lookup {name}.");
        if (!heap.TryAllocateArray(null, 1, out var addresses) ||
            !heap.TryWriteArray(addresses, 0, address))
            return IntrinsicResult.Invalid("Could not allocate the resolved addresses.");
        return IntrinsicResult.Completed(HostFacts.Stated(context, key, addresses));
    }

    /// <summary>Models an address, which is text until something tries to reach it.</summary>
    private static IntrinsicResult Numbered(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        switch (name)
        {
            case "Parse" or "TryParse" when arguments.Count >= 1 &&
                heap.TryGetString(arguments[0], out var spelled):
            {
                var known = System.Net.IPAddress.TryParse(spelled, out var parsed);
                if (!known && name == "Parse")
                {
                    return IntrinsicResult.Invalid(
                        $"\"{spelled}\" is not an address, so the program throws here.");
                }

                var written = StaticValue.Null;
                if (known && heap.TryAllocateObject("System.Net.IPAddress", out written))
                    heap.TrySetModelValue(written, Address, parsed!.ToString());
                if (name == "Parse")
                    return IntrinsicResult.Completed(written);
                if (arguments.Count < 2 || arguments[1].Kind != StaticValueKind.ManagedReference)
                    return IntrinsicResult.Invalid("TryParse was not given somewhere to write.");
                heap.TryWriteManaged(arguments[1], written);
                return IntrinsicResult.Completed(StaticValue.FromInt32(known ? 1 : 0));
            }

            case "ToString" when arguments.Count == 1 &&
                heap.TryGetModelValue<string>(arguments[0], Address, out var held) && held is not null:
                return heap.TryAllocateString(held, out var text)
                    ? IntrinsicResult.Completed(text)
                    : IntrinsicResult.Invalid("Could not allocate the address text.");
            default:
                return IntrinsicResult.Invalid($"Unsupported address operation {name}.");
        }
    }

    /// <summary>Models an endpoint, which is an address and a port and nothing else.</summary>
    private static IntrinsicResult Endpoint(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        switch (name)
        {
            case ".ctor" when arguments.Count == 3:
            {
                var address = heap.TryGetModelValue<string>(arguments[1], Address, out var held)
                    ? held
                    : arguments[1].IsInteger
                        ? new System.Net.IPAddress(
                            BitConverter.GetBytes((uint)arguments[1].AsInt64())).ToString()
                        : null;
                if (address is null)
                    return IntrinsicResult.Invalid("The endpoint's address is not modeled.");
                heap.TrySetModelValue(arguments[0], Address, address);
                heap.TrySetModelValue(arguments[0], Port, arguments[2].AsInt32());
                return IntrinsicResult.Completed();
            }

            case "get_Port" when arguments.Count == 1 &&
                heap.TryGetModelValue<int>(arguments[0], Port, out var port):
                return IntrinsicResult.Completed(StaticValue.FromInt32(port));
            case "ToString" when arguments.Count == 1 &&
                heap.TryGetModelValue<string>(arguments[0], Address, out var spelled) &&
                spelled is not null:
            {
                heap.TryGetModelValue<int>(arguments[0], Port, out var port);
                return heap.TryAllocateString(
                    string.Create(CultureInfo.InvariantCulture, $"{spelled}:{port}"),
                    out var text)
                    ? IntrinsicResult.Completed(text)
                    : IntrinsicResult.Invalid("Could not allocate the endpoint text.");
            }

            default:
                return IntrinsicResult.Invalid($"Unsupported endpoint operation {name}.");
        }
    }
}
