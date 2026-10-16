using System.Text;
using Cilantro.Core;
using Cilantro.Core.Interpretation;

namespace Cilantro.Cli;

/// <summary>
/// Turns a pipeline report into something an analyst can read without knowing how the tool works.
/// </summary>
internal static class Explain
{
    /// <summary>
    /// What each protection means for the person reading the code, whichever protector applied it.
    /// </summary>
    private static readonly (string Capability, string Meaning)[] Protections =
    [
        ("jit-hook",
            "Method bodies are encrypted, and decrypted in memory as they run (NecroBit)"),
        ("method-stubs",
            "Methods were replaced by stubs that get filled in at run time"),
        ("protected-strings",
            "Some strings are encrypted and decoded at run time"),
        ("dispatcher-control-flow",
            "Control-flow obfuscation makes decompiled code harder to follow"),
        ("invalid-call-junk",
            "Junk instructions are woven in to make decompilers give up"),
        ("delegate-proxy",
            "Calls are routed through lookup tables that hide what is being called"),
        ("anti-tamper",
            "The file checks itself for modification and can refuse to run"),
        ("resource-container",
            "Other files are hidden inside this one, encrypted"),
        ("clrjit",
            "The .NET compiler itself is hooked to intercept code as it is prepared"),
        ("virtualization",
            "Some methods are bytecode for a custom interpreter, not code a decompiler can show"),
        ("encrypted-section",
            "The method bodies were moved into an encrypted section and are decrypted on startup"),
        ("invisible-names",
            "Types and methods are named with invisible characters, so names cannot be told apart"),
        ("constants-table",
            "Numbers and text come from one encrypted table rather than appearing in the code"),
        ("switch-dispatch-control-flow",
            "Methods use state-machine dispatch to obscure their execution order"),
        ("anti-debug",
            "The file checks for a debugger and behaves differently when it finds one")
    ];

    public static void Summarize(
        PipelineResult result, string inputPath, bool verbose = false) =>
        Summarize(result, inputPath, Console.Out, verbose, ConsoleTheme.ForOutput());

    /// <summary>The same summary, written where a test can read it.</summary>
    internal static void Summarize(
        PipelineResult result, string inputPath, TextWriter output, bool verbose = false, bool color = false)
    {
        var report = result.Report;
        var summary = AnalystSummary.Of(result);
        var home = Path.GetDirectoryName(Path.GetFullPath(inputPath))!;
        output.WriteLine();
        output.WriteLine($"  CILantro {CilantroPipeline.Version}");
        ConsoleTheme.Line(output, $"  RESULT   {summary.Outcome}",
            result.Success ? ConsoleTone.Green : ConsoleTone.Amber, color);
        output.WriteLine($"  Protection: {summary.Protection}");
        output.WriteLine($"  File: {Path.GetFileName(inputPath)}");
        output.WriteLine();
        foreach (var section in summary.Sections.Where(section => section.Items.Count > 0 && (!section.DetailsOnly || verbose || report.Strict)))
        {
            ConsoleTheme.Line(output, $"  {section.Title.ToUpperInvariant()}", section.Title switch
            {
                "Needs review" => ConsoleTone.Amber,
                "Remaining" => ConsoleTone.Amber,
                "Validation" when !report.VerificationPassed => ConsoleTone.Red,
                "What changed in the input" => ConsoleTone.Green,
                _ => ConsoleTone.Cyan
            }, color);
            if (section.Title == "Artifacts" && !verbose)
            {
                foreach (var item in section.Items.Where(item => item.Text.Contains(" -> ", StringComparison.Ordinal)))
                    WriteParagraph(output, item.Text);
                WriteParagraph(output, "Open the HTML report for extraction provenance, individual files, and child reports.");
                output.WriteLine();
                continue;
            }
            foreach (var item in section.Items)
            {
                WriteParagraph(output, item.Text);
                if (item.Path is { } path && (verbose || section.Title != "Remaining"))
                    ConsoleTheme.Line(output, $"      {Path.GetFullPath(path)}", ConsoleTone.Cyan, color);
            }
            output.WriteLine();
        }
        if (!verbose)
            output.WriteLine("  Full artifact inventory and diagnostics: open the HTML report. Use --verbose for technical output.");
        if (verbose || report.Strict)
        {
            output.WriteLine($"  SHA-256  {report.InputSha256}");
            output.WriteLine(report.Strict
                ? "  Reading  strict: no implicit host assumptions; unsupported interpretation stops"
                : "  Reading  triage: a plausible machine assumed, unreadable calls stepped over");
            var capabilities = report.Evidence.Where(e => e.Category == "capability")
                .Select(e => e.Message).ToHashSet(StringComparer.Ordinal);
            Protection(capabilities, summary.Protection, output);
            Rebuilt(report, output);
            Assumed(report, output);
            Blocked(result, home, output);
        }
    }

    // Paths and copyable commands stay intact; ordinary prose fits a typical terminal.
    private static void WriteParagraph(TextWriter output, string text)
    {
        if (text.StartsWith("cilantro ", StringComparison.Ordinal))
        {
            output.WriteLine($"    {text}");
            return;
        }
        var line = new StringBuilder();
        foreach (var word in text.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (line.Length > 0 && line.Length + word.Length + 1 > 92)
            {
                output.WriteLine($"    {line}");
                line.Clear();
            }
            if (line.Length > 0) line.Append(' ');
            line.Append(word);
        }
        if (line.Length > 0) output.WriteLine($"    {line}");
    }

    /// <summary>
    /// What stopped the run, and the exact thing to write down to get past it.
    /// </summary>
    private static void Blocked(PipelineResult result, string home, TextWriter output)
    {
        if (result.Report.Blockers is not { Count: > 0 } blockers)
            return;
        output.WriteLine("  BLOCKED   what stopped the run, and what would get past it");
        output.WriteLine();
        const int shown = 6;
        foreach (var blocker in blockers.Take(shown))
        {
            output.WriteLine(
                $"    {blocker.Kind}  {blocker.Key}" +
                (blocker.Times > 1 ? $"  (x{blocker.Times})" : string.Empty));

            if (Beyond(blocker.Detail, blocker.Key) is { Length: > 0 } detail)
                output.WriteLine($"      {detail}");
            if (blocker.Where is { } where && !string.Equals(where, blocker.Key, StringComparison.Ordinal))
            {
                output.WriteLine(Beyond(where, blocker.Key) is { Length: > 0 } within
                    ? $"      at {within}"
                    : $"      in {where}");
            }
            output.WriteLine(blocker.Declare is { } declare
                ? $"      declare: {declare}"
                : blocker.Kind == BlockerKind.Threw
                    ? "      the program threw here; that is its own decision, not a missing model"
                    : "      no declaration fixes this; it needs a change to the tool");
        }

        if (blockers.Count > shown)
            output.WriteLine($"    ... and {blockers.Count - shown} more");
        if (result.BlockerReportPath is { } path)
        {
            output.WriteLine();
            output.WriteLine($"    All of them, in full: {Near(path, home)}");
        }

        output.WriteLine();
    }

    private static string? Beyond(string text, string prefix)
    {
        if (!text.StartsWith(prefix, StringComparison.Ordinal))
            return text;
        var rest = text[prefix.Length..].TrimStart();
        return rest.Length == 0 ? null : rest;
    }

    private static void Assumed(ArtifactReport report, TextWriter output)
    {
        var declarations = report.Declarations;
        if (report.HostProfile is { Consulted.Count: > 0 } profile)
        {
            var answered = profile.Consulted.Where(fact => fact.Answered).ToArray();
            var refused = profile.Consulted.Where(fact => !fact.Answered).ToArray();
            output.WriteLine($"  ASSUMED   about the machine, from the \"{profile.Name}\" profile");
            output.WriteLine();
            var width = Math.Min(56, profile.Consulted.Max(fact => fact.Key.Length));
            foreach (var fact in answered)
            {
                output.WriteLine(
                    $"    {fact.Key.PadRight(width)}   {fact.Answer}" +
                    (fact.Stated ? "  (you stated this)" : "  (assumed)"));
            }

            foreach (var fact in refused)
                output.WriteLine($"    {fact.Key.PadRight(width)}   not stated, so the code that asked was not read");
            output.WriteLine();
        }

        if (report.ContinuedPast is { Count: > 0 } continued)
        {
            output.WriteLine("  ASSUMED   not to matter: what the tool could not read, carried on past");
            output.WriteLine();
            const int shown = 6;
            foreach (var call in continued.Take(shown))
            {
                output.WriteLine(
                    $"    {call.Key}" +
                    (call.Times > 1 ? $"  (x{call.Times})" : string.Empty));
            }

            if (continued.Count > shown)
                output.WriteLine($"    ... and {continued.Count - shown} more");
            output.WriteLine();
            output.WriteLine("    Each was answered with nothing the run could know. Run again with --strict");
            output.WriteLine("    to stop at these instead of assuming past them.");
            output.WriteLine();
        }

        if (declarations is null)
            return;
        if (declarations.DeclaredCallsUsed.Count > 0)
        {
            output.WriteLine("  ASSUMED   about calls the tool does not model, because you said so");
            output.WriteLine();
            foreach (var call in declarations.DeclaredCallsUsed)
                output.WriteLine($"    {call}");
            output.WriteLine();
        }

        if (declarations.DeclaredCallsUnused.Count == 0)
            return;
        output.WriteLine("  UNUSED    declared, but nothing asked");
        output.WriteLine();
        foreach (var call in declarations.DeclaredCallsUnused)
            output.WriteLine($"    {call}");
        if (!declarations.CallsAllowed)
            output.WriteLine("    (declared calls were not allowed; pass --allow-declared-calls)");
        output.WriteLine();
    }

    private static string Near(string path, string home)
    {
        var relative = Path.GetRelativePath(home, path);
        return relative.StartsWith("..", StringComparison.Ordinal) ? path : relative;
    }

    private static void Protection(HashSet<string> capabilities, string protector, TextWriter output)
    {
        output.WriteLine($"  PROTECTION   {protector}");
        output.WriteLine();
        foreach (var (capability, meaning) in Protections)
        {
            if (capabilities.Contains(capability))
                output.WriteLine($"    - {meaning}");
        }

        output.WriteLine();
    }

    /// <summary>
    /// The way into each body the tool built rather than recovered.
    /// </summary>
    /// <remarks>
    /// A lifted body is the hardest thing in the cleaned copy to read: the interpreter's jump table
    /// where structured control flow should be, <c>object</c> for every local, and generated names
    /// throughout. What makes it tractable is that the framework calls leaving it were never
    /// obfuscated, so naming them says what the method is for in a line or two. That is printed on
    /// an ordinary run rather than held back for <c>--verbose</c>, because it is not a caveat about
    /// the recovery — it is the most useful thing the run has to say about the code it produced.
    /// </remarks>
    private static void Rebuilt(ArtifactReport report, TextWriter output)
    {
        if (report.RebuiltMethods is not { Count: > 0 } rebuilt)
            return;

        output.WriteLine("  DEVIRTUALIZED METHODS");
        output.WriteLine();
        output.WriteLine(
            "    CILantro converted methods protected by code virtualization into readable");
        output.WriteLine(
            "    .NET code. These are reconstructions from the virtual machine's instructions,");
        output.WriteLine(
            "    not the original method bodies.");
        output.WriteLine();
        foreach (var method in rebuilt)
        {
            output.WriteLine($"    {Short(method.Method)}");
            if (method.Reaches.Count != 0)
                Wrapped(output, "uses", method.Reaches);
            if (method.Writes.Count != 0)
                Wrapped(output, "changes", method.Writes);
            if (!method.Reachable)
            {
                output.WriteLine(
                    "      status    nothing in the cleaned copy calls this: recovery replaced the");
                output.WriteLine(
                    "                code that used to, so its caller went with it");
            }

            output.WriteLine();
        }
    }

    /// <summary>Prints a long list of members over as many lines as it needs.</summary>
    private static void Wrapped(TextWriter output, string label, IReadOnlyList<string> members)
    {
        const int Room = 62;
        var line = new StringBuilder();
        var first = true;
        foreach (var member in members)
        {
            if (line.Length != 0 && line.Length + member.Length + 2 > Room)
            {
                output.WriteLine($"      {(first ? label.PadRight(8) : "        ")}  {line},");
                line.Clear();
                first = false;
            }

            if (line.Length != 0)
                line.Append(", ");
            line.Append(member);
        }

        if (line.Length != 0)
            output.WriteLine($"      {(first ? label.PadRight(8) : "        ")}  {line}");
    }

    /// <summary>
    /// A method's full name as a reader would say it: where to find it, and what it is called.
    /// </summary>
    /// <remarks>
    /// dnlib spells a full name with the return type in front and the whole signature behind, which
    /// is what a compiler needs and about four times what fits on the line. The namespace stays,
    /// being the first thing to expand in a decompiler tree.
    /// </remarks>
    private static string Short(string fullName)
    {
        var name = fullName;
        var space = name.IndexOf(' ', StringComparison.Ordinal);
        if (space >= 0 && space < name.Length - 1)
            name = name[(space + 1)..];
        var arguments = name.IndexOf('(', StringComparison.Ordinal);
        return arguments < 0 ? name : name[..arguments];
    }

    public static void PassLog(ArtifactReport report) => PassLog(report, Console.Out);

    internal static void PassLog(ArtifactReport report, TextWriter output)
    {
        output.WriteLine("  STEPS");
        output.WriteLine();
        foreach (var pass in report.Passes)
        {
            output.WriteLine(
                $"    [{pass.Status.ToString().ToLowerInvariant(),-11}] {pass.Pass}: " +
                $"{pass.Changes} change(s)");
            foreach (var diagnostic in pass.Diagnostics)
                output.WriteLine($"                  {diagnostic}");
        }

        output.WriteLine();
    }
}
