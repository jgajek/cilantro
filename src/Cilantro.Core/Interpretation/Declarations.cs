using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Cilantro.Core.Interpretation;

/// <summary>Raised when a declarations file cannot be read or does not say what it must.</summary>
public sealed class DeclarationException : Exception
{
    public DeclarationException()
    {
    }

    public DeclarationException(string message) : base(message)
    {
    }

    public DeclarationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>How much work a run is allowed to do, where somebody has said something about it.</summary>
/// <remarks>
/// The budgets exist so that a program which loops forever stops rather than running forever, and the
/// figures in the code are what has been enough for every sample measured so far. A sample that needs
/// more is not a sample the tool should refuse on principle — it is one whose loader does more work —
/// so the figures can be raised for a run, and the report says they were.
/// </remarks>
public sealed record DeclaredBudgets(int? Steps = null, long? AllocatedBytes = null, int? Depth = null)
{
    public static DeclaredBudgets None { get; } = new();

    public bool Stated => Steps is not null || AllocatedBytes is not null || Depth is not null;

    /// <summary>
    /// A pass's own limits, with whatever was stated about them put in place of them.
    /// </summary>
    /// <remarks>
    /// Each pass has its own figures because each does a different amount of work, and a declaration
    /// speaks about the run rather than about one pass, so it replaces the figure wherever it is set
    /// rather than becoming a figure of its own. A raised allocation budget carries the largest single
    /// array up with it, since a budget that allows a hundred megabytes and an array limit that
    /// allows ten would refuse the very read the budget was raised for.
    ///
    /// Steps are the exception, and only raise: a declared figure that is lower than a pass's own is
    /// ignored by it. That is because one pass now works its ceiling out from the sample — the loader
    /// bootstrap costs what it costs per protected method — so it can want more than a caller writing
    /// a single number for the whole run would think to ask for. Replacing it there would let a
    /// caller applying the remedy the tool itself printed come away with less recovery than they
    /// started with, which is the one thing a loop built on those remedies cannot afford. Doing less
    /// work is asked for by leaving passes out, not by shrinking what the ones that run may spend.
    /// </remarks>
    public StaticMachineLimits Over(StaticMachineLimits given)
    {
        ArgumentNullException.ThrowIfNull(given);
        return !Stated
            ? given
            : given with
            {
                MaximumSteps = Steps is { } steps
                    ? Math.Max(steps, given.MaximumSteps)
                    : given.MaximumSteps,
                MaximumRecursionDepth = Depth ?? given.MaximumRecursionDepth,
                MaximumAllocatedBytes = AllocatedBytes ?? given.MaximumAllocatedBytes,
                MaximumArrayLength = AllocatedBytes is { } bytes
                    ? (int)Math.Min(Math.Max(bytes, given.MaximumArrayLength), int.MaxValue)
                    : given.MaximumArrayLength
            };
    }

    public string Describe()
    {
        var parts = new List<string>();
        if (Steps is { } steps)
            parts.Add($"{steps.ToString("N0", CultureInfo.InvariantCulture)} steps");
        if (AllocatedBytes is { } bytes)
            parts.Add($"{bytes.ToString("N0", CultureInfo.InvariantCulture)} bytes");
        if (Depth is { } depth)
            parts.Add($"{depth} frames deep");
        return parts.Count == 0 ? "the built-in budgets" : string.Join(", ", parts);
    }
}

/// <summary>What a call the machine does not model was declared to do.</summary>
/// <remarks>
/// Either it produces a value, or it does nothing observable. Both are assertions about somebody
/// else's code rather than readings of the sample's, which is why they are only consulted where the
/// interpretation was going to stop, and why every one that is used is named in the report.
/// </remarks>
public sealed record DeclaredCall(string Method, HostAnswer Returns, bool Inert)
{
    public string Describe() => Inert ? "does nothing" : $"returns {Returns.Describe()}";
}

/// <summary>
/// Everything a run was told, in the one file a caller hands over.
/// </summary>
/// <remarks>
/// <para>
/// A new sample stops the tool somewhere new. That is the design working — nothing is guessed — but
/// it leaves whoever is driving the tool with a choice between writing code and giving up, and for
/// most of what a sample stops on there is a third answer: the thing that stopped it is a fact
/// somebody knows. The machine name. The registry value holding the next stage. The library the
/// sample calls into. How much work its loader does before it gets anywhere.
/// </para>
/// <para>
/// So a run can be handed all of that at once, in a file it can be given again unchanged to
/// reproduce the run. The sections are what the tool can be told rather than what it can be asked to
/// assume: facts about the machine, libraries whose IL may be read, budgets, passes to leave out, and
/// — only when the caller has said so out loud — what an unmodelled call does. Nothing here widens
/// what the machine will do on its own; each section answers a question the machine already knows how
/// to ask, and a section nobody writes leaves the refusal exactly where it was.
/// </para>
/// </remarks>
public sealed class RunDeclarations
{
    private readonly Dictionary<string, DeclaredCall> _calls;
    private readonly HashSet<string> _skipped;
    private readonly HashSet<string> _consulted = new(StringComparer.Ordinal);

    private RunDeclarations(
        string name,
        HostProfile facts,
        IReadOnlyList<string> libraries,
        DeclaredBudgets budgets,
        HashSet<string> skipped,
        Dictionary<string, DeclaredCall> calls,
        string source)
    {
        Name = name;
        Facts = facts;
        Libraries = libraries;
        Budgets = budgets;
        _skipped = skipped;
        _calls = calls;
        Sha256 = Digest(source);
    }

    private RunDeclarations(RunDeclarations other, bool calls)
    {
        Name = other.Name;
        Facts = other.Facts;
        Libraries = other.Libraries;
        Budgets = other.Budgets;
        Sha256 = other.Sha256;
        _skipped = other._skipped;
        _calls = other._calls;
        CallsAllowed = calls;
    }

    /// <summary>What a run was told when nobody told it anything.</summary>
    public static RunDeclarations None { get; } = new(
        "none",
        HostProfile.Default,
        [],
        DeclaredBudgets.None,
        new HashSet<string>(StringComparer.Ordinal),
        new Dictionary<string, DeclaredCall>(StringComparer.Ordinal),
        string.Empty);

    public string Name { get; }

    /// <summary>A hash of what was declared, so a report identifies the run's inputs.</summary>
    public string Sha256 { get; }

    public HostProfile Facts { get; }

    /// <summary>
    /// Whether anybody stated a fact here, as opposed to the facts being what the tool assumes.
    /// </summary>
    /// <remarks>
    /// The facts section starts from the built-in answers and overlays what was written, so "did
    /// somebody write anything" is not the same question as "are there any facts". It is asked because
    /// a run told nothing about the machine may assume one, and a run told something must not have that
    /// assumption layered over what it was told.
    /// </remarks>
    public bool Stated => Facts.Answers.Values.Any(answer => answer.Stated);

    public IReadOnlyList<string> Libraries { get; }
    public DeclaredBudgets Budgets { get; }
    public IReadOnlyList<string> SkippedPasses => [.. _skipped.Order(StringComparer.Ordinal)];
    public IReadOnlyCollection<DeclaredCall> Calls => _calls.Values;

    /// <summary>
    /// Whether declared call outcomes may be used, which is a decision of the caller's rather than
    /// of the file's.
    /// </summary>
    /// <remarks>
    /// A file can be written by anyone and passed around; consenting to have a call answered from it
    /// rather than from the sample's own code is a separate act, so it is a flag on the run and not a
    /// line in the file. A file whose calls are never allowed still parses, and the report says the
    /// declarations were there and went unused.
    /// </remarks>
    public bool CallsAllowed { get; }

    /// <summary>The same declarations, with the caller's decision about their calls attached.</summary>
    public RunDeclarations Allowing(bool calls) => new(this, calls);

    public static RunDeclarations Load(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        string text;
        try
        {
            text = File.ReadAllText(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new DeclarationException(
                $"The declarations file {path} could not be read: {ex.Message}",
                ex);
        }

        // A library is written down beside the declarations that mention it, so the paths are read
        // as the author of the file would have meant them rather than as wherever the tool was run.
        return Parse(
            text,
            Path.GetFileNameWithoutExtension(path),
            Path.GetDirectoryName(Path.GetFullPath(path)));
    }

    public static RunDeclarations Parse(string json, string name, string? beside = null)
    {
        ArgumentNullException.ThrowIfNull(json);
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException ex)
        {
            throw new DeclarationException($"The declarations are not valid JSON: {ex.Message}", ex);
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                throw new DeclarationException("Declarations must be a JSON object.");
            // The name is read first because the facts are built wearing it, and a file that states
            // its name after them would otherwise have to be read twice.
            if (root.TryGetProperty("name", out var named) &&
                named.ValueKind != JsonValueKind.String)
                throw new DeclarationException("The declarations' name must be text.");
            var declared = named.ValueKind == JsonValueKind.String
                ? named.GetString() ?? name
                : name;
            var facts = HostProfile.Default;
            var libraries = new List<string>();
            var budgets = DeclaredBudgets.None;
            var skipped = new HashSet<string>(StringComparer.Ordinal);
            var calls = new Dictionary<string, DeclaredCall>(StringComparer.Ordinal);
            foreach (var section in root.EnumerateObject())
            {
                switch (section.Name)
                {
                    case "name":
                        break;
                    case "facts":
                        facts = HostProfile.FromFacts(section.Value, declared);
                        break;
                    case "libraries":
                        libraries.AddRange(Listed(section, beside));
                        break;
                    case "budgets":
                        budgets = Allowance(section.Value);
                        break;
                    case "passes":
                        foreach (var pass in Skipping(section.Value))
                            skipped.Add(pass);
                        break;
                    case "calls":
                        foreach (var call in Answering(section.Value))
                            calls[call.Method] = call;
                        break;
                    default:
                        throw new DeclarationException(
                            $"Declarations have no \"{section.Name}\" section; they have " +
                            "\"name\", \"facts\", \"libraries\", \"budgets\", \"passes\" and " +
                            "\"calls\".");
                }
            }

            return new RunDeclarations(
                declared,
                facts,
                libraries,
                budgets,
                skipped,
                calls,
                Canonical(declared, facts, libraries, budgets, skipped, calls));
        }
    }

    /// <summary>Whether a pass was declared to be left out of the run.</summary>
    public bool Skips(string pass) => _skipped.Contains(pass);

    /// <summary>
    /// What a call was declared to do, when calls may be answered and this one was declared.
    /// </summary>
    public bool TryAnswerCall(string signature, out DeclaredCall declared)
    {
        declared = default!;
        if (!CallsAllowed || !_calls.TryGetValue(signature, out var stated))
            return false;
        declared = stated;
        _consulted.Add(signature);
        return true;
    }

    /// <summary>
    /// What was declared and never used, which is usually a key spelled differently from the one the
    /// run asked about.
    /// </summary>
    /// <remarks>
    /// An agent driving the tool learns as much from this as from the refusals: a declaration that
    /// answered nothing did not fail to work, it was never asked, and the two call for different
    /// fixes. Facts are accounted for separately, by the record of what the profile was asked.
    /// </remarks>
    public IReadOnlyList<DeclaredCall> Unconsulted => [.. _calls
        .Where(entry => !_consulted.Contains(entry.Key))
        .OrderBy(entry => entry.Key, StringComparer.Ordinal)
        .Select(entry => entry.Value)];

    /// <summary>The calls that were consulted, in the order a report should list them.</summary>
    public IReadOnlyList<DeclaredCall> Consulted => [.. _calls
        .Where(entry => _consulted.Contains(entry.Key))
        .OrderBy(entry => entry.Key, StringComparer.Ordinal)
        .Select(entry => entry.Value)];

    private static IEnumerable<string> Listed(JsonProperty section, string? beside)
    {
        if (section.Value.ValueKind != JsonValueKind.Array)
            throw new DeclarationException("The declared libraries must be a list of file paths.");
        foreach (var entry in section.Value.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.String || entry.GetString() is not { } path ||
                path.Length == 0)
            {
                throw new DeclarationException("Each declared library must be a file path.");
            }

            yield return beside is null || Path.IsPathRooted(path)
                ? path
                : Path.GetFullPath(Path.Combine(beside, path));
        }
    }

    private static DeclaredBudgets Allowance(JsonElement stated)
    {
        if (stated.ValueKind != JsonValueKind.Object)
        {
            throw new DeclarationException(
                "The declared budgets must be an object of \"steps\", \"allocatedBytes\" and " +
                "\"depth\".");
        }

        var budgets = DeclaredBudgets.None;
        foreach (var budget in stated.EnumerateObject())
        {
            var figure = Positive(budget);
            budgets = budget.Name switch
            {
                "steps" => budgets with { Steps = (int)Math.Min(figure, int.MaxValue) },
                "allocatedBytes" => budgets with { AllocatedBytes = figure },
                "depth" => budgets with { Depth = (int)Math.Min(figure, int.MaxValue) },
                _ => throw new DeclarationException(
                    $"There is no \"{budget.Name}\" budget; there are \"steps\", " +
                    "\"allocatedBytes\" and \"depth\".")
            };
        }

        return budgets;
    }

    private static long Positive(JsonProperty budget)
    {
        if (budget.Value.ValueKind != JsonValueKind.Number ||
            !budget.Value.TryGetInt64(out var figure) ||
            figure <= 0)
        {
            throw new DeclarationException(
                $"The \"{budget.Name}\" budget must be a whole number above zero.");
        }

        return figure;
    }

    private static IEnumerable<string> Skipping(JsonElement stated)
    {
        if (stated.ValueKind != JsonValueKind.Object)
            throw new DeclarationException("The declared passes must be an object of \"skip\".");
        foreach (var entry in stated.EnumerateObject())
        {
            if (entry.Name != "skip")
            {
                throw new DeclarationException(
                    $"There is nothing to declare about passes but \"skip\"; \"{entry.Name}\" is " +
                    "not it.");
            }

            if (entry.Value.ValueKind != JsonValueKind.Array)
                throw new DeclarationException("\"skip\" must be a list of pass names.");
            foreach (var pass in entry.Value.EnumerateArray())
            {
                if (pass.ValueKind != JsonValueKind.String || pass.GetString() is not { } named ||
                    named.Length == 0)
                {
                    throw new DeclarationException("Each skipped pass must be named.");
                }

                yield return named;
            }
        }
    }

    /// <summary>
    /// Reads the declared outcomes of calls, keyed by the signature the refusal named.
    /// </summary>
    /// <remarks>
    /// The key is the method as the machine spells it, which is the spelling the refusal prints, so
    /// what an agent writes down is what it was just told rather than a translation of it.
    /// </remarks>
    private static IEnumerable<DeclaredCall> Answering(JsonElement stated)
    {
        if (stated.ValueKind != JsonValueKind.Object)
        {
            throw new DeclarationException(
                "The declared calls must be an object of method signature to outcome.");
        }

        foreach (var call in stated.EnumerateObject())
        {
            if (!call.Name.Contains("::", StringComparison.Ordinal) ||
                !call.Name.Contains('(', StringComparison.Ordinal))
            {
                throw new DeclarationException(
                    $"\"{call.Name}\" is not a method signature; one reads like " +
                    "\"System.Boolean Some.Type::Method(System.String)\", exactly as the refusal " +
                    "that named it spelled it.");
            }

            if (call.Value.ValueKind != JsonValueKind.Object)
            {
                throw new DeclarationException(
                    $"\"{call.Name}\" must say what it does: {{ \"returns\": ... }} or " +
                    "{ \"inert\": true }.");
            }

            var members = call.Value.EnumerateObject().ToList();
            if (members.Count != 1)
            {
                throw new DeclarationException(
                    $"\"{call.Name}\" must say either what it returns or that it is inert, and " +
                    "only one of the two.");
            }

            yield return members[0].Name switch
            {
                "returns" => new DeclaredCall(
                    call.Name,
                    HostProfile.Read(call.Name, members[0].Value),
                    Inert: false),
                "inert" when members[0].Value.ValueKind == JsonValueKind.True =>
                    new DeclaredCall(call.Name, HostAnswer.Absent, Inert: true),
                "inert" => throw new DeclarationException(
                    $"\"{call.Name}\" is either inert or it is not; write \"inert\": true or " +
                    "state what it returns."),
                _ => throw new DeclarationException(
                    $"\"{call.Name}\" has no \"{members[0].Name}\"; it has \"returns\" and " +
                    "\"inert\".")
            };
        }
    }

    /// <summary>
    /// Renders what was declared in one order and one spelling, so that two files saying the same
    /// thing hash alike and a report naming a hash names the content rather than the formatting.
    /// </summary>
    private static string Canonical(
        string name,
        HostProfile facts,
        IReadOnlyList<string> libraries,
        DeclaredBudgets budgets,
        HashSet<string> skipped,
        Dictionary<string, DeclaredCall> calls)
    {
        var canonical = new StringBuilder(name).Append('\n')
            .Append("facts\0").Append(facts.Sha256).Append('\n');
        foreach (var library in libraries.Order(StringComparer.Ordinal))
            canonical.Append("library\0").Append(library).Append('\n');
        if (budgets.Stated)
            canonical.Append("budgets\0").Append(budgets).Append('\n');
        foreach (var pass in skipped.Order(StringComparer.Ordinal))
            canonical.Append("skip\0").Append(pass).Append('\n');
        foreach (var (signature, call) in calls.OrderBy(entry => entry.Key, StringComparer.Ordinal))
        {
            canonical.Append("call\0").Append(signature).Append('\0')
                .Append(call.Inert ? "inert" : call.Returns.Kind + "\0" + call.Returns.Text)
                .Append('\n');
        }

        return canonical.ToString();
    }

    private static string Digest(string canonical) => canonical.Length == 0
        ? "0000000000000000000000000000000000000000000000000000000000000000"
        : Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
}
