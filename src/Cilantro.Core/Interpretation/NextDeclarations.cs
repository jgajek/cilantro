using System.Text.Json;
using System.Text.Json.Nodes;

namespace Cilantro.Core.Interpretation;

/// <summary>
/// Turns what stopped a run into the declarations file the next one should be given.
/// </summary>
/// <remarks>
/// <para>
/// Every stop already names its own cure, so the step between one run and the next is mechanical for
/// most of them and a decision for the rest. Sorting the two apart by hand is where a caller working
/// through a sample loses its way: it applies the budget, forgets the call it also needed, and reads
/// the same refusal a second time.
/// </para>
/// <para>
/// So this does the mechanical half and refuses to guess at the other. A remedy the tool could fill
/// in is applied; a remedy that wants an answer is applied only where the caller supplied one, and
/// otherwise comes back named, so the caller knows exactly what it is being asked for. Nothing here
/// runs anything or decides that another run is worth the time — it prepares the file and hands it
/// back.
/// </para>
/// </remarks>
public static class NextDeclarations
{
    /// <summary>
    /// The declarations to run with next, given what stopped the last run.
    /// </summary>
    /// <param name="blockers">What stopped it, remedies and all.</param>
    /// <param name="answers">
    /// What the caller knows, keyed by the name the remedy asked under: a fact key, or the signature
    /// of a call. Anything not asked for is carried into the file anyway, because a caller that knows
    /// something before being asked should not have to wait to be asked.
    /// </param>
    /// <param name="from">
    /// A declarations file to build on, as its text, so that a loop accumulates rather than starting
    /// over each time.
    /// </param>
    /// <param name="name">What the file should call itself.</param>
    public static Draft From(
        IEnumerable<Blocker> blockers,
        IReadOnlyDictionary<string, JsonNode?>? answers = null,
        string? from = null,
        string? name = null)
    {
        ArgumentNullException.ThrowIfNull(blockers);
        var file = Existing(from);
        if (name is not null)
            file["name"] = name;
        var applied = new List<string>();
        var wanted = new List<Remedy>();
        var beyond = new List<Blocker>();
        var flags = new SortedSet<string>(StringComparer.Ordinal);
        var used = new HashSet<string>(StringComparer.Ordinal);

        foreach (var blocker in blockers)
        {
            if (blocker.Remedy is not { } remedy)
            {
                beyond.Add(blocker);
                continue;
            }

            var told = answers is not null && answers.TryGetValue(remedy.Name, out var answer);
            if (remedy.Wants is not null && !told)
            {
                wanted.Add(remedy);
                continue;
            }

            Put(file, remedy, told ? Answer(answers!, remedy.Name) : null);
            applied.Add($"{remedy.Section}.{remedy.Name}");
            used.Add(remedy.Name);
            if (remedy.Flag is { } flag)
                flags.Add(flag);
        }

        // Something the caller knew and was never asked about still belongs in the file. A run only
        // reports the first stop on a path, so the fact that closes the second one is not going to be
        // asked for until the first is out of the way.
        if (answers is not null)
        {
            foreach (var (key, value) in answers)
            {
                if (used.Contains(key))
                    continue;
                var unasked = Unasked(key);
                Put(file, unasked, value);
                applied.Add($"{unasked.Section}.{key}");
                if (unasked.Flag is { } switched)
                    flags.Add(switched);
            }
        }

        return new Draft(
            file.ToJsonString(Writing),
            applied,
            wanted,
            beyond,
            [.. flags]);
    }

    /// <summary>How the file is written: indented, because a person reads these too.</summary>
    private static readonly JsonSerializerOptions Writing = new() { WriteIndented = true };

    /// <summary>The file being built on, or an empty one.</summary>
    private static JsonObject Existing(string? from)
    {
        if (string.IsNullOrWhiteSpace(from))
            return [];
        JsonNode? parsed;
        try
        {
            parsed = JsonNode.Parse(from);
        }
        catch (JsonException ex)
        {
            throw new DeclarationException(
                $"The declarations to build on are not valid JSON: {ex.Message}",
                ex);
        }

        return parsed as JsonObject ??
            throw new DeclarationException("Declarations must be a JSON object.");
    }

    /// <summary>
    /// Writes one remedy into the file, putting the caller's answer where the remedy left a gap.
    /// </summary>
    /// <remarks>
    /// A remedy is complete or it holds exactly one null, and those are the only two shapes there
    /// are, so filling one in is either replacing the whole value or replacing the null inside the
    /// object. Anything else would mean the remedy and this had drifted apart, and the answer is
    /// dropped in whole rather than half-written.
    /// </remarks>
    private static void Put(JsonObject file, Remedy remedy, JsonNode? answer)
    {
        if (file[remedy.Section] is not JsonObject section)
        {
            section = [];
            file[remedy.Section] = section;
        }

        var value = JsonNode.Parse(remedy.Value.Text);
        if (remedy.Wants is null)
        {
            section[remedy.Name] = value;
            return;
        }

        if (value is JsonObject holding &&
            holding.FirstOrDefault(entry => entry.Value is null) is { Key: { } gap })
        {
            // A caller that hands back the whole shape means it. Somebody answering a call with
            // { "inert": true } is saying the call does nothing, not that it returns an object.
            section[remedy.Name] = answer is JsonObject given && Shaped(given)
                ? given.DeepClone()
                : Filled(holding, gap, answer);
            return;
        }

        section[remedy.Name] = answer?.DeepClone();
    }

    private static JsonObject Filled(JsonObject holding, string gap, JsonNode? answer)
    {
        holding[gap] = answer?.DeepClone();
        return holding;
    }

    /// <summary>Whether an answer is already a whole statement about a call rather than a value.</summary>
    private static bool Shaped(JsonObject answer) =>
        answer.Count == 1 && (answer.ContainsKey("returns") || answer.ContainsKey("inert"));

    /// <summary>
    /// What to make of something the caller volunteered, read from how the key is spelled.
    /// </summary>
    /// <remarks>
    /// A fact key is a family and a name — <c>env:MachineName</c> — and a call is a signature, which
    /// always has a return type and a space in front of the type it is declared on. The two cannot be
    /// mistaken for each other, and guessing wrong is caught the moment the file is parsed rather
    /// than becoming a declaration nothing consults.
    /// </remarks>
    private static Remedy Unasked(string key) => key.Contains(' ', StringComparison.Ordinal)
        ? Declaring.Call(key)
        : Declaring.Fact(key);

    private static JsonNode? Answer(IReadOnlyDictionary<string, JsonNode?> answers, string key) =>
        answers.TryGetValue(key, out var answer) ? answer : null;
}

/// <summary>
/// The next declarations file, and an account of what it does and does not close.
/// </summary>
/// <param name="Json">The file, ready to be written.</param>
/// <param name="Applied">What was written into it, as section and key.</param>
/// <param name="Wanted">
/// The stops that need an answer nobody has supplied. Each names what it wants and what kind of
/// value would be believed.
/// </param>
/// <param name="Beyond">
/// The stops no declaration will close. A caller looping on a sample stops when these are all that
/// is left; the detail and the location are what a bug report needs.
/// </param>
/// <param name="Flags">
/// Switches the next run needs as well as the file, which is <c>--allow-declared-calls</c> or
/// nothing.
/// </param>
public sealed record Draft(
    string Json,
    IReadOnlyList<string> Applied,
    IReadOnlyList<Remedy> Wanted,
    IReadOnlyList<Blocker> Beyond,
    IReadOnlyList<string> Flags);
