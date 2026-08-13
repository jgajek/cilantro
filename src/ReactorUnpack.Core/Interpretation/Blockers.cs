using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace ReactorUnpack.Core.Interpretation;

/// <summary>What kind of thing stopped an interpretation short.</summary>
/// <remarks>
/// The kinds are not a list of error codes; they are the answers to "what would get past this". A
/// fact nobody stated is closed by stating it, a call nobody modelled is closed by modelling it or by
/// declaring what it does, a budget is closed by raising it, and a platform call is a boundary rather
/// than a gap. Sorting refusals this way is what lets whoever is driving the tool act on one without
/// reading the interpretation.
/// </remarks>
public enum BlockerKind
{
    /// <summary>The host profile was asked something it does not say.</summary>
    UnstatedFact,

    /// <summary>A managed call the machine has no model for.</summary>
    UnmodeledCall,

    /// <summary>A call that leaves the runtime for the operating system.</summary>
    PlatformCall,

    /// <summary>The run reached one of its limits on work.</summary>
    Budget,

    /// <summary>An instruction the machine does not execute.</summary>
    UnsupportedInstruction,

    /// <summary>A method whose body or handlers the machine cannot run.</summary>
    UnsupportedBody,

    /// <summary>A decision the machine could not make, because a value was not known.</summary>
    UnknownValue,

    /// <summary>The interpreted program threw, and nothing caught it.</summary>
    Threw
}

/// <summary>
/// One thing that stopped a run, said in a form somebody can act on.
/// </summary>
/// <remarks>
/// <para>
/// The interpretation already explains itself, at length: the diagnostics carry the frames, the
/// arguments and the provenance of everything involved. That is the right thing for a person reading
/// why a recovery failed and the wrong thing for anyone deciding what to do next, because the one
/// sentence that matters — what to write down to get further — is buried in the middle of it.
/// </para>
/// <para>
/// So a refusal is recorded where it happens, while the method, the offset and the reason are all
/// still in hand, and it carries <see cref="Declare"/>: the exact text of the declaration that would
/// answer it, or nothing where no declaration can. A kind that cannot be declared away is still worth
/// recording, because knowing that the next step is a change to the tool rather than to a file is
/// itself the answer.
/// </para>
/// </remarks>
/// <param name="Kind">Which sort of stop this is.</param>
/// <param name="Key">
/// What the stop is about — a fact key, a method signature, a native entry point, a budget name —
/// which is also what makes two occurrences the same occurrence.
/// </param>
/// <param name="Detail">The refusal in the words the interpretation used.</param>
/// <param name="Declare">
/// The declaration that would answer it, spelled as it goes in the file, or null where the answer is
/// a change to the tool rather than a line in a file.
/// </param>
/// <param name="Where">The method the stop happened in, and the offset within it.</param>
/// <param name="Pass">Which pass was interpreting at the time.</param>
/// <param name="Times">How often this same stop came up.</param>
public sealed record Blocker(
    BlockerKind Kind,
    string Key,
    string Detail,
    string? Declare,
    string? Where,
    string? Pass,
    int Times);

/// <summary>
/// The account of everything that stopped a run, gathered once for the whole run.
/// </summary>
/// <remarks>
/// <para>
/// One ledger for the run rather than one per machine, because a sample stops the same way in four
/// passes and a reader wants to see the stop once with a count beside it. Recurrences are counted
/// rather than listed for the same reason the host questions are: a loader that asks the same thing
/// in a loop has said everything it is going to say the first time.
/// </para>
/// <para>
/// The order is the order things were first hit, which makes the ledger a story of the run and, less
/// obviously, makes it comparable: the tool interprets everything twice and compares, so an account
/// of a run has to come out the same way both times or it would be the thing that makes two identical
/// runs look different.
/// </para>
/// </remarks>
public sealed class BlockerLedger
{
    /// <summary>
    /// How many distinct stops are worth keeping. A run that hits thousands of different refusals
    /// has one problem, not thousands, and the first few name it.
    /// </summary>
    private const int MostWorthKeeping = 256;

    private readonly Tally _stopped = new();
    private readonly Tally _continued = new();

    /// <summary>What the run is doing at the moment, so a stop can say which pass hit it.</summary>
    public string? Pass { get; set; }

    /// <summary>How many distinct stops have been recorded.</summary>
    public int Count => _stopped.Count;

    /// <summary>
    /// Where the interpretation is, for the refusals raised somewhere that cannot see it.
    /// </summary>
    /// <remarks>
    /// A modeled call refuses from inside the model, which knows what was asked and not where the
    /// asking happened. The machine knows, and leaves it here as it dispatches, so that a stop over an
    /// unstated fact says which of the sample's methods wanted it — which is what an analyst reads
    /// before deciding whether the answer matters.
    /// </remarks>
    public (MethodDef? Method, Instruction? At) Site { get; set; }

    /// <summary>
    /// Records a stop, or counts another occurrence of one already recorded.
    /// </summary>
    /// <remarks>
    /// The first occurrence keeps its detail and its location. A later one adds only to the count,
    /// because the first is where the run got to before anything else went wrong, and a stop
    /// re-described from a deeper frame reads as though it were a different problem.
    /// </remarks>
    public void Record(
        BlockerKind kind,
        string key,
        string detail,
        string? declare = null,
        string? where = null) =>
        _stopped.Add(kind, key, detail, declare, where ?? Reached(), Pass);

    /// <summary>
    /// Records something the run would once have stopped for and instead carried on past.
    /// </summary>
    /// <remarks>
    /// Kept apart from the stops rather than mixed in with them, because the two ask different things
    /// of a reader. A stop is why there is less output than there should be, and needs acting on. This
    /// is a place where the reading rests on the tool having assumed a call did not matter, which needs
    /// reading only if the result looks wrong — but it has to be there to be read, because a reading
    /// that silently skipped a call would be the tool's own kind of lie.
    /// </remarks>
    public void Continued(
        BlockerKind kind,
        string key,
        string detail,
        string? declare = null,
        string? where = null) =>
        _continued.Add(kind, key, detail, declare, where ?? Reached(), Pass);

    /// <summary>Where the machine had got to, spelled out only when a stop is first recorded.</summary>
    private string? Reached() => Site.Method is not { } method
        ? null
        : Site.At is { } at
            ? $"{method.FullName} IL_{at.Offset:X4}"
            : method.FullName;

    /// <summary>Everything that stopped the run, in the order it was first hit.</summary>
    public IReadOnlyList<Blocker> Blockers => _stopped.Entries;

    /// <summary>Everything the run carried on past, in the order it was first hit.</summary>
    public IReadOnlyList<Blocker> Continuations => _continued.Entries;

    /// <summary>One set of tallied occurrences, kept in the order they were first hit.</summary>
    private sealed class Tally
    {
        private readonly Dictionary<(BlockerKind, string), Entry> _entries = [];
        private readonly List<(BlockerKind, string)> _order = [];

        public int Count => _entries.Count;

        public void Add(
            BlockerKind kind,
            string key,
            string detail,
            string? declare,
            string? where,
            string? pass)
        {
            ArgumentException.ThrowIfNullOrEmpty(key);
            var identity = (kind, key);
            if (_entries.TryGetValue(identity, out var seen))
            {
                seen.Times++;
                return;
            }

            if (_entries.Count >= MostWorthKeeping)
                return;
            _entries[identity] = new Entry(detail, declare, where, pass);
            _order.Add(identity);
        }

        public IReadOnlyList<Blocker> Entries => [.. _order.Select(identity => new Blocker(
            identity.Item1,
            identity.Item2,
            _entries[identity].Detail,
            _entries[identity].Declare,
            _entries[identity].Where,
            _entries[identity].Pass,
            _entries[identity].Times))];
    }

    private sealed class Entry(string detail, string? declare, string? where, string? pass)
    {
        public string Detail { get; } = detail;
        public string? Declare { get; } = declare;
        public string? Where { get; } = where;
        public string? Pass { get; } = pass;
        public int Times { get; set; } = 1;
    }
}

/// <summary>How a stop names the declaration that would answer it.</summary>
/// <remarks>
/// The fragments are written out in full, braces and all, because the reader of them is as likely to
/// be a program pasting them into a file as a person retyping them, and a program should not have to
/// know the file's shape to use what it was told.
/// </remarks>
public static class Declaring
{
    /// <summary>The line that would state a host fact.</summary>
    public static string Fact(string key) => $"\"facts\": {{ \"{Escaped(key)}\": <value> }}";

    /// <summary>
    /// The line that would declare what a call does, in the form that call can be declared in.
    /// </summary>
    /// <remarks>
    /// A call that hands nothing back is declared inert and a call that returns something has to be
    /// told what to return, and offering the wrong one of the two is how a reader ends up writing a
    /// declaration the tool then refuses.
    /// </remarks>
    public static string Call(string signature, bool returnsSomething = true) =>
        $"\"calls\": {{ \"{Escaped(signature)}\": " +
        (returnsSomething ? "{ \"returns\": <value> }" : "{ \"inert\": true }") +
        " }, with --allow-declared-calls";

    /// <summary>The line that would raise a budget.</summary>
    public static string Budget(string budget, long beyond) =>
        $"\"budgets\": {{ \"{budget}\": <more than {beyond}> }}";

    /// <summary>The line that would leave a pass out of the run.</summary>
    public static string Skip(string pass) => $"\"passes\": {{ \"skip\": [\"{Escaped(pass)}\"] }}";

    private static string Escaped(string text) =>
        text.Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal);
}
