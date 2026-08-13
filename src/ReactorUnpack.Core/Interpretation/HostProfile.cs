using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ReactorUnpack.Core.Interpretation;

/// <summary>What kind of thing the profile says in answer to a question.</summary>
public enum HostAnswerKind
{
    /// <summary>The profile carries no answer, so the question stops the interpretation.</summary>
    Unanswered,
    Text,
    Number,
    Boolean,

    /// <summary>
    /// The profile answers that the thing asked about is not there, which is an answer.
    /// </summary>
    /// <remarks>
    /// A registry value that does not exist and a registry value nobody has described are different
    /// situations, and code that branches on the first behaves differently from code that cannot be
    /// interpreted at all. Spelling the absence out is what lets a profile say "this machine has no
    /// such key" without the machine having to treat that as a gap in its own knowledge.
    /// </remarks>
    Absent,

    /// <summary>The profile answers with bytes, stated as base64.</summary>
    /// <remarks>
    /// Some of what a machine holds is not text or a number: a stager keeps its next stage in a
    /// binary registry value, and reading it back is how the stage is found. An analyst who has that
    /// value has the payload, and without a way to state it there is nowhere to put it — the run
    /// stops at the read and the bytes sit in a file nobody can hand to the interpretation.
    /// </remarks>
    Bytes
}

/// <summary>One thing a host profile says about the machine the sample believes it is running on.</summary>
public sealed record HostAnswer(HostAnswerKind Kind, string Text, long Number)
{
    /// <summary>
    /// Whether a person said this, as opposed to it being what the tool assumes.
    /// </summary>
    /// <remarks>
    /// Per answer rather than per profile, because a supplied profile inherits everything it did not
    /// mention. Somebody who states a machine name has not thereby vouched for the clock reading
    /// 2020, and a report that credited them with it would be putting words in their mouth.
    /// </remarks>
    public bool Stated { get; init; }

    public static HostAnswer Unanswered { get; } = new(HostAnswerKind.Unanswered, string.Empty, 0);
    public static HostAnswer Absent { get; } = new(HostAnswerKind.Absent, string.Empty, 0);

    public static HostAnswer Of(string text) =>
        new(HostAnswerKind.Text, text ?? string.Empty, 0);

    public static HostAnswer Of(long number) => new(
        HostAnswerKind.Number,
        number.ToString(CultureInfo.InvariantCulture),
        number);

    public static HostAnswer Of(bool flag) =>
        new(HostAnswerKind.Boolean, flag ? "true" : "false", flag ? 1 : 0);

    /// <summary>
    /// An answer of bytes, held as the base64 it was stated in so that the profile hashes over
    /// exactly what was written.
    /// </summary>
    public static HostAnswer Of(byte[] bytes) => new(
        HostAnswerKind.Bytes,
        Convert.ToBase64String(bytes ?? []),
        bytes?.Length ?? 0);

    public bool IsAnswered => Kind != HostAnswerKind.Unanswered;
    public bool Flag => Number != 0;

    /// <summary>The bytes this answer stands for, or none when it is not an answer of bytes.</summary>
    public byte[] Data => Kind == HostAnswerKind.Bytes ? Convert.FromBase64String(Text) : [];

    /// <summary>How the answer reads in a report.</summary>
    public string Describe() => Kind switch
    {
        HostAnswerKind.Unanswered => "unanswered",
        HostAnswerKind.Absent => "absent",
        HostAnswerKind.Text => $"\"{Text}\"",
        HostAnswerKind.Bytes => $"{Number} byte(s)",
        _ => Text
    };
}

/// <summary>Raised when a host profile cannot be read or does not say what it must.</summary>
public sealed class HostProfileException : Exception
{
    public HostProfileException()
    {
    }

    public HostProfileException(string message) : base(message)
    {
    }

    public HostProfileException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// What the machine says when interpreted code asks about the computer it is running on.
/// </summary>
/// <remarks>
/// The machine has always had to answer some of these. A protected assembly asks the time, asks
/// whether a debugger is attached, and asks which modules its process has loaded, and refusing every
/// such question would stop the interpretation on paths the program merely passes through. So the
/// answers existed already — they were simply written into the intrinsics as literals, where nobody
/// reading a report could see them.
///
/// A profile is those same answers, named, gathered in one place, and printable. Two things follow
/// from that. The report can say which of them a run actually consulted, so a reader knows what the
/// result rests on. And a caller who knows better — because the sample came from a machine whose
/// details are known, or because a sandbox has already run it — can say so, instead of being stuck
/// with whatever the tool would have guessed. That matters more than it sounds: this tool runs on
/// Linux, and the questions are about Windows, so there is no real host to read the answers off even
/// if reading them off were desirable.
///
/// What the profile does not do is invent. A question it has no answer for is refused exactly as it
/// was before, and the refusal names the key that would answer it, so the gap is a thing that can be
/// closed rather than a thing to be worked around. The built-in default therefore answers only what
/// the intrinsics already answered on their own; everything else has to be said out loud by somebody
/// who knows it.
/// </remarks>
public sealed class HostProfile
{
    /// <summary>
    /// The families of question a profile may answer, which is how a mistyped key is caught.
    /// </summary>
    /// <remarks>
    /// The keys within a family are open — an environment variable, a WMI property, and a registry
    /// value can each be named anything — so there is no list of legal keys to check against. The
    /// family is checkable, and it catches the mistake worth catching: a key written in a spelling
    /// nothing will ever ask for, sitting in a profile that looks like it is doing something.
    /// </remarks>
    private static readonly HashSet<string> Families = new(StringComparer.Ordinal)
    {
        "env",
        "time",
        "guid",
        "debugger",
        "process",
        "runtime",
        "native",
        "wmi",
        "registry",
        "volume",
        "net"
    };

    private readonly Dictionary<string, HostAnswer> _answers;

    private HostProfile(string name, Dictionary<string, HostAnswer> answers)
    {
        Name = name;
        _answers = answers;
        Sha256 = Digest(name, answers);
    }

    /// <summary>What this profile is called, for the report to name.</summary>
    public string Name { get; }

    /// <summary>A hash of the profile's contents, so a report identifies which one was used.</summary>
    public string Sha256 { get; }

    public IReadOnlyDictionary<string, HostAnswer> Answers => _answers;

    /// <summary>
    /// The answers the intrinsics gave before any of this existed, and no others.
    /// </summary>
    /// <remarks>
    /// Deliberately not a portrait of a plausible workstation. A default that answered more than the
    /// tool used to would quietly change what every sample recovers, and the change would be
    /// invisible in the diff of a run. Anyone who wants the fuller picture passes
    /// <c>profiles/windows-10-workstation.json</c>, and then the report says they did.
    /// </remarks>
    public static HostProfile Default { get; } = new("default", new(StringComparer.Ordinal)
    {
        // An arbitrary fixed instant, so that a run is not a function of when it happened.
        ["time:UtcNow"] = HostAnswer.Of("2020-01-01T00:00:00Z"),
        ["guid:Seed"] = HostAnswer.Of(0),
        ["debugger:IsAttached"] = HostAnswer.Of(false),
        ["debugger:IsLogging"] = HostAnswer.Of(false),
        ["debugger:CanLaunch"] = HostAnswer.Of(false),
        ["process:Id"] = HostAnswer.Of(1),
        // One process means a name nothing else has taken; see MutexIntrinsic.
        ["process:MutexHeld"] = HostAnswer.Of(false),
        ["runtime:ModuleName"] = HostAnswer.Of("clrjit.dll"),
        ["runtime:FileVersion"] = HostAnswer.Of("4.8.9037.0"),
        ["runtime:VersionMajor"] = HostAnswer.Of(4),
        ["runtime:VersionMinor"] = HostAnswer.Of(8),
        ["runtime:VersionBuild"] = HostAnswer.Of(9037),
        ["runtime:VersionPrivate"] = HostAnswer.Of(0),
        ["runtime:FipsEnforced"] = HostAnswer.Of(false)
    });

    /// <summary>
    /// A plausible Windows workstation, which is what the tool assumes when nobody describes one.
    /// </summary>
    /// <remarks>
    /// Every answer here is an invention, and none of it is checkable against anything. It is still
    /// the better default: a sample nobody has met before asks these questions on the way to the part
    /// worth reading, and refusing them loses the program rather than leaving the tool neutral. What
    /// keeps it honest is that the report says which of these a run consulted and marks each as
    /// assumed rather than stated, so a reading that rests on one can be seen to.
    ///
    /// It states nothing that could be material. There is no registry value holding bytes and no file
    /// content, because a made-up machine name costs a reader a plausible detail whereas a made-up
    /// payload would cost them a wrong answer to the only question they asked.
    /// </remarks>
    public static HostProfile Workstation { get; } = Embedded();

    public static HostProfile Load(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        string text;
        try
        {
            text = File.ReadAllText(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new HostProfileException($"The host profile {path} could not be read: {ex.Message}", ex);
        }

        return Parse(text, Path.GetFileNameWithoutExtension(path));
    }

    /// <summary>
    /// Reads a profile, starting from the default so that a profile only has to say what differs.
    /// </summary>
    /// <remarks>
    /// A profile describing a workstation has no opinion about which instant the clock reads, and
    /// making it restate the defaults to avoid losing them would mean every profile carrying answers
    /// its author never thought about. Overlaying instead keeps a profile to the size of what it is
    /// actually asserting.
    /// </remarks>
    public static HostProfile Parse(string json, string name) => Parse(json, name, stated: true);

    /// <summary>
    /// Reads a profile, saying whether what it holds is somebody's assertion or the tool's own.
    /// </summary>
    /// <remarks>
    /// The built-in portrait of a workstation is written as a profile and read by this same code, so
    /// that what ships and what a caller may pass are the same kind of thing. It is not stated by
    /// anybody, though, which is the one thing that has to differ.
    /// </remarks>
    internal static HostProfile Parse(string json, string name, bool stated)
    {
        ArgumentNullException.ThrowIfNull(json);
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException ex)
        {
            throw new HostProfileException($"The host profile is not valid JSON: {ex.Message}", ex);
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                throw new HostProfileException("A host profile must be a JSON object.");
            var declared = name;
            var answers = new Dictionary<string, HostAnswer>(Default._answers, StringComparer.Ordinal);
            var facts = default(JsonElement?);
            foreach (var property in root.EnumerateObject())
            {
                switch (property.Name)
                {
                    case "name":
                        if (property.Value.ValueKind != JsonValueKind.String)
                            throw new HostProfileException("The host profile's name must be text.");
                        declared = property.Value.GetString() ?? name;
                        break;
                    case "facts":
                        if (property.Value.ValueKind != JsonValueKind.Object)
                            throw new HostProfileException(
                                "The host profile's facts must be a JSON object of key to value.");
                        facts = property.Value;
                        break;
                    default:
                        throw new HostProfileException(
                            $"A host profile has no \"{property.Name}\" section; it has " +
                            "\"name\" and \"facts\".");
                }
            }

            if (facts is not { } written)
                throw new HostProfileException("A host profile must have a \"facts\" section.");
            foreach (var fact in written.EnumerateObject())
                answers[Checked(fact.Name)] = Read(fact.Name, fact.Value) with { Stated = stated };
            return new HostProfile(declared, answers);
        }
    }

    /// <summary>
    /// Reads the facts stated inside a larger document, such as a run's declarations.
    /// </summary>
    /// <remarks>
    /// The facts are the same facts wherever they are written down, so they are read by the same
    /// code: a family that is checked in a profile is checked in declarations, and an answer of bytes
    /// is spelled the one way in both.
    /// </remarks>
    public static HostProfile FromFacts(JsonElement facts, string name)
    {
        if (facts.ValueKind != JsonValueKind.Object)
            throw new HostProfileException("The stated facts must be a JSON object of key to value.");
        var answers = new Dictionary<string, HostAnswer>(Default._answers, StringComparer.Ordinal);
        foreach (var fact in facts.EnumerateObject())
            answers[Checked(fact.Name)] = Read(fact.Name, fact.Value) with { Stated = true };
        return new HostProfile(name, answers);
    }

    public bool TryAnswer(string key, out HostAnswer answer)
    {
        answer = _answers.GetValueOrDefault(key, HostAnswer.Unanswered);
        return answer.IsAnswered;
    }

    /// <summary>Reads the workstation portrait out of the assembly it ships inside.</summary>
    private static HostProfile Embedded()
    {
        const string resource = "ReactorUnpack.Core.Profiles.Workstation.json";
        using var stream = typeof(HostProfile).Assembly.GetManifestResourceStream(resource) ??
            throw new HostProfileException(
                $"The built-in profile {resource} is missing from this build.");
        using var reader = new StreamReader(stream);
        return Parse(reader.ReadToEnd(), "windows-10-workstation", stated: false);
    }

    private static string Checked(string key)
    {
        var separator = key.IndexOf(':', StringComparison.Ordinal);
        if (separator <= 0 || separator == key.Length - 1)
            throw new HostProfileException(
                $"\"{key}\" is not a host profile key; a key reads like \"env:MachineName\".");
        var family = key[..separator];
        if (!Families.Contains(family))
            throw new HostProfileException(
                $"\"{key}\" asks about \"{family}\", which is not something a host profile " +
                $"describes. It describes: {string.Join(", ", Families.Order(StringComparer.Ordinal))}.");
        return key;
    }

    /// <summary>
    /// Reads one stated value, in any of the shapes a fact may take.
    /// </summary>
    /// <remarks>
    /// Shared with the declarations, so that what a call was declared to return is written the same
    /// way as what a registry value was declared to hold.
    /// </remarks>
    internal static HostAnswer Read(string key, JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => HostAnswer.Of(value.GetString() ?? string.Empty),
        JsonValueKind.True => HostAnswer.Of(true),
        JsonValueKind.False => HostAnswer.Of(false),
        JsonValueKind.Null => HostAnswer.Absent,
        JsonValueKind.Number when value.TryGetInt64(out var number) => HostAnswer.Of(number),
        JsonValueKind.Number => throw new HostProfileException(
            $"\"{key}\" is a number the machine cannot hold; host facts are whole numbers."),
        JsonValueKind.Object => Encoded(key, value),
        _ => throw new HostProfileException(
            $"\"{key}\" must be text, a whole number, true, false, null for absent, or " +
            "{ \"base64\": \"...\" } for bytes.")
    };

    /// <summary>Reads an answer of bytes, which a profile states as base64 and nothing else.</summary>
    private static HostAnswer Encoded(string key, JsonElement value)
    {
        var stated = value.EnumerateObject().ToList();
        if (stated.Count != 1 ||
            stated[0].Name != "base64" ||
            stated[0].Value.ValueKind != JsonValueKind.String)
        {
            throw new HostProfileException(
                $"\"{key}\" is stated as an object, so it must read " +
                "{ \"base64\": \"...\" } and say nothing else.");
        }

        try
        {
            return HostAnswer.Of(Convert.FromBase64String(stated[0].Value.GetString() ?? string.Empty));
        }
        catch (FormatException ex)
        {
            throw new HostProfileException($"\"{key}\" is not valid base64: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Hashes the answers rather than the file, so two spellings of the same profile hash alike.
    /// </summary>
    private static string Digest(string name, Dictionary<string, HostAnswer> answers)
    {
        var canonical = new StringBuilder(name).Append('\n');
        foreach (var (key, answer) in answers.OrderBy(entry => entry.Key, StringComparer.Ordinal))
            canonical.Append(key).Append('\0').Append(answer.Kind).Append('\0')
                .Append(answer.Text).Append('\n');
        return Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(canonical.ToString())));
    }
}

/// <summary>What one question was asked, what it was told, and how often it came up.</summary>
public sealed record HostQuestion(string Key, HostAnswer Answer, int Times);

/// <summary>
/// A profile together with the record of what a run actually asked it.
/// </summary>
/// <remarks>
/// The profile is what could be answered; this is what was. The difference is the whole point of
/// keeping it: a profile listing forty facts of which a sample consulted two tells a reader that the
/// other thirty-eight had no bearing on the result, and a refused question tells them exactly which
/// line to add to get further. One of these is shared by every machine a run stands up, so the
/// account covers the run rather than whichever pass happened to ask first.
/// </remarks>
public sealed class HostEnvironment
{
    private readonly Dictionary<string, int> _asked = new(StringComparer.Ordinal);
    private readonly Dictionary<string, HostAnswer> _answered = new(StringComparer.Ordinal);

    public HostEnvironment(HostProfile profile) =>
        Profile = profile ?? throw new ArgumentNullException(nameof(profile));

    public HostProfile Profile { get; }

    public bool TryAnswer(string key, out HostAnswer answer)
    {
        var known = Profile.TryAnswer(key, out answer);
        _asked[key] = _asked.GetValueOrDefault(key) + 1;
        _answered[key] = answer;
        return known;
    }

    /// <summary>Everything the run asked about the host, in key order.</summary>
    public IReadOnlyList<HostQuestion> Questions => _asked
        .OrderBy(entry => entry.Key, StringComparer.Ordinal)
        .Select(entry => new HostQuestion(
            entry.Key,
            _answered.GetValueOrDefault(entry.Key, HostAnswer.Unanswered),
            entry.Value))
        .ToArray();

    /// <summary>
    /// Whether the answer to this question is the tool's assumption rather than somebody's statement.
    /// </summary>
    public bool Assumed(string key) =>
        !Profile.TryAnswer(key, out var answer) || !answer.Stated;

    /// <summary>Everything the run assumed rather than was told, in key order.</summary>
    public IReadOnlyList<HostQuestion> Assumptions => Questions
        .Where(question => question.Answer.IsAnswered && !question.Answer.Stated)
        .ToArray();

    /// <summary>
    /// How a question nobody has answered is refused, which is by naming what would answer it.
    /// </summary>
    public string Unanswered(string key) =>
        $"the host profile \"{Profile.Name}\" does not say {key}; add \"{key}\" to a profile " +
        "and pass it with --host-profile to answer this";
}
