using System.Globalization;
using Cilantro.Core;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;

namespace Cilantro.Cli;

/// <summary>
/// Turns a pipeline report into something an analyst can read without knowing how the tool works.
/// </summary>
/// <remarks>
/// Someone who has just pulled a suspicious file out of a sandbox wants three things in this
/// order: whether the run worked, what was recovered, and where the readable copy is. The default
/// summary says those and stops. How the reading was licensed — assumed host facts, calls stepped
/// over, whether a rebuilt body was cross-checked — is the business of <c>--strict</c> and
/// <c>--verbose</c>, because printing it on an ordinary successful run is what made a finished
/// recovery look like a failure.
///
/// Everything printed here is read off the report rather than restated, so the summary cannot drift
/// from what actually happened.
/// </remarks>
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
            "Every method was replaced by an empty stub that gets filled in at run time"),
        ("protected-strings",
            "Text is encrypted, so no readable strings appear in the file"),
        ("dispatcher-control-flow",
            "Control flow is scrambled, so decompiled code reads as nonsense"),
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
            "Each method was turned into a state machine, so its steps appear in no useful order"),
        ("anti-debug",
            "The file checks for a debugger and behaves differently when it finds one")
    ];

    public static void Summarize(
        PipelineResult result, string inputPath, bool verbose = false) =>
        Summarize(result, inputPath, Console.Out, verbose);

    /// <summary>The same summary, written where a test can read it.</summary>
    internal static void Summarize(
        PipelineResult result, string inputPath, TextWriter output, bool verbose = false)
    {
        var report = result.Report;
        var home = Path.GetDirectoryName(Path.GetFullPath(inputPath))!;
        // Strict asked for the assumptions to be named. Verbose asked for the reasoning. Either
        // one is a request for the long form; a default run is not.
        var detail = verbose || report.Strict;
        output.WriteLine();
        output.WriteLine($"  File     {Path.GetFileName(inputPath)}  ({Size(report.InputLength)})");
        output.WriteLine($"  SHA-256  {report.InputSha256}");
        if (detail)
        {
            output.WriteLine(report.Strict
                ? "  Reading  strict: nothing assumed, stopping wherever the tool cannot follow"
                : "  Reading  triage: a plausible machine assumed, unreadable calls stepped over");
        }

        output.WriteLine();

        var capabilities = report.Evidence
            .Where(evidence => evidence.Category == "capability")
            .Select(evidence => evidence.Message)
            .ToHashSet(StringComparer.Ordinal);
        var protector = report.Evidence
            .FirstOrDefault(evidence => evidence.Category == "protector-name")?.Message
            ?? "an unrecognized protector";

        if (report.Evidence.Any(evidence => evidence.Category == "native-bootstrap"))
        {
            Verdict(output, "Recovered the hidden assembly");
            Bootstrap(result, home, output);
            return;
        }

        if (capabilities.Count == 0)
        {
            Verdict(output, "Not protected");
            output.WriteLine(
                "  This file is not protected by anything this tool knows.");
            output.WriteLine();
            output.WriteLine("    There is nothing to undo, so no cleaned copy was written.");
            output.WriteLine("    If you expected protection here, the report lists what was");
            output.WriteLine($"    checked: {Near(result.AnalysisReportPath, home)}");
            output.WriteLine();
            return;
        }

        Verdict(output, result.Success ? "Recovered" : "Failed");
        Protection(capabilities, protector, output);
        Recovered(report, output);
        if (detail)
            Assumed(report, output);
        if (detail || !result.Success)
            Blocked(result, home, output);
        Written(result, home, output, detail);
        Caveats(result, output, detail);
    }

    /// <summary>The one line that says whether the run worked.</summary>
    private static void Verdict(TextWriter output, string result)
    {
        output.WriteLine($"  RESULT   {result}");
        output.WriteLine();
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

    private static void Recovered(ArtifactReport report, TextWriter output)
    {
        var recovery = report.Recovery;
        var lines = new List<(string Label, string Value)>();
        if (recovery.RestoredMethodBodies > 0 || recovery.RemainingMethodStubs > 0)
        {
            var total = recovery.RestoredMethodBodies + recovery.RemainingMethodStubs;
            lines.Add(("Method bodies decrypted", $"{recovery.RestoredMethodBodies:N0} of {total:N0}"));
        }

        if (recovery.StringCallSites > 0)
        {
            lines.Add(("Strings decrypted",
                $"{recovery.ReplacedStringSites:N0} of {recovery.StringCallSites:N0}"));
        }

        Add(lines, "String calls decoded", recovery.ConstantStringSites);
        Add(lines, "Hidden calls resolved", recovery.TokensRestored);
        Add(lines, "Hidden true/false values resolved", recovery.BooleansRecovered);
        Add(lines, "Junk instructions removed", recovery.UnreachableInstructionsRemoved);
        Add(lines, "Encrypted resources restored", recovery.ResourcesRestored);
        Add(lines, "Protector types deleted", recovery.RuntimeTypesRemoved);
        Add(lines, "Obfuscated names replaced", recovery.SymbolsRenamed);
        if (lines.Count == 0)
            return;

        output.WriteLine("  RECOVERED");
        output.WriteLine();
        var width = lines.Max(line => line.Label.Length);
        foreach (var (label, value) in lines)
            output.WriteLine($"    {label.PadRight(width)}   {value}");
        output.WriteLine();
    }

    private static void Add(List<(string, string)> lines, string label, int value)
    {
        if (value > 0)
            lines.Add((label, value.ToString("N0", CultureInfo.InvariantCulture)));
    }

    private static void Bootstrap(PipelineResult result, string home, TextWriter output)
    {
        var report = result.Report;
        output.WriteLine(
            "  PROTECTION   .NET Reactor, native bootstrap. The file is native code with the");
        output.WriteLine(
            "               managed assembly encrypted inside it.");
        output.WriteLine();

        output.WriteLine("  WROTE");
        output.WriteLine();
        foreach (var payload in report.Payloads)
        {
            output.WriteLine(
                $"    Assembly        {payload.AssemblyName} ({Size(payload.PayloadLength)}), " +
                $"SHA-256 {payload.PayloadSha256}");
            if (payload.WrittenTo is { } path)
                output.WriteLine($"                    {Near(path, home)}");
        }

        output.WriteLine();
        output.WriteLine("  HOW");
        output.WriteLine();
        foreach (var evidence in report.Evidence.Where(item => item.Category == "native-bootstrap"))
            output.WriteLine($"    {evidence.Message}");

        output.WriteLine();
        output.WriteLine("  NEXT");
        output.WriteLine();
        output.WriteLine("    The recovered assembly is protected in its own right and has not");
        output.WriteLine("    been read. Run this tool on it to undo what is on it:");
        foreach (var payload in report.Payloads.Where(item => item.WrittenTo is not null))
            output.WriteLine($"      cilantro {Near(payload.WrittenTo!, home)}");
        output.WriteLine();
    }

    private static void Written(PipelineResult result, string home, TextWriter output, bool detail)
    {
        output.WriteLine("  WROTE");
        output.WriteLine();
        output.WriteLine(result.OutputPath is null
            ? "    Cleaned copy    none"
            : $"    Cleaned copy    {Near(result.OutputPath, home)}");
        if (result.ExtractedPayloadPaths.Count > 0)
        {
            var folder = Near(Path.GetDirectoryName(result.ExtractedPayloadPaths[0])!, home);
            output.WriteLine(
                $"    Hidden files    {result.ExtractedPayloadPaths.Count} in {folder}");
        }

        if (result.VirtualProgramPaths.Count > 0)
        {
            var folder = Near(Path.GetDirectoryName(result.VirtualProgramPaths[0])!, home);
            output.WriteLine(
                $"    Hidden code     {result.VirtualProgramPaths.Count} listing(s) in {folder}");
        }

        if (result.RebuiltMethods > 0)
        {
            var rebuilt = result.RebuiltMethods == 1
                ? "1 method in the cleaned copy"
                : $"{result.RebuiltMethods} methods in the cleaned copy";
            if (result.DevirtualizationCheck == DevirtualizationCheck.Disagreed)
            {
                output.WriteLine($"    Built back      {rebuilt} — did not match the original");
                foreach (var note in result.DevirtualizationNotes)
                    output.WriteLine($"                      {note}");
            }
            else if (detail)
            {
                var standing = result.DevirtualizationCheck switch
                {
                    DevirtualizationCheck.Agreed => "they unpacked the same payload as the original",
                    _ => "a reading, unchecked"
                };
                output.WriteLine(
                    $"    Built back      {result.RebuiltMethods} method(s) in the cleaned copy, " +
                    $"marked [RebuiltFromReading] ({standing})");
                foreach (var note in result.DevirtualizationNotes)
                    output.WriteLine($"                      {note}");
            }
            else
            {
                output.WriteLine($"    Built back      {rebuilt}");
            }
        }
        else if (detail &&
            result.DevirtualizationNotes.Count > 0 &&
            result.VirtualProgramPaths.Count > 0)
        {
            output.WriteLine("    Built back      nothing, and here is why:");
            foreach (var note in result.DevirtualizationNotes)
                output.WriteLine($"                      {note}");
        }

        if (result.ConfigReportPath is { } config)
            output.WriteLine($"    Constants       {Near(config, home)}");
        output.WriteLine($"    Full report     {Near(result.AnalysisReportPath, home)}");
        output.WriteLine();
    }

    private static void Caveats(PipelineResult result, TextWriter output, bool detail)
    {
        var failed = result.Report.Passes
            .Where(pass => pass.Status == PassStatus.Failed)
            .ToArray();
        var unsupported = detail
            ? result.Report.Passes
                .Where(pass => pass.Status is PassStatus.Unsupported or PassStatus.Partial)
                .Where(pass => !DeclinedAnotherProtector(pass))
                .ToArray()
            : [];
        if (failed.Length == 0 && unsupported.Length == 0 && result.OutputPath is not null)
        {
            output.WriteLine("  Open the cleaned copy in dnSpyEx or ILSpy to read the code.");
            output.WriteLine();
            return;
        }

        if (failed.Length == 0 && unsupported.Length == 0 && result.OutputPath is null)
        {
            output.WriteLine("    No cleaned copy was written.");
            output.WriteLine();
            return;
        }

        output.WriteLine("  NOTES");
        output.WriteLine();
        foreach (var pass in failed)
            output.WriteLine($"    ! {pass.Pass} failed: {First(pass)}");
        foreach (var pass in unsupported)
            output.WriteLine($"    - {pass.Pass} was incomplete: {First(pass)}");
        if (result.OutputPath is null)
        {
            output.WriteLine();
            output.WriteLine("    No cleaned copy was written.");
        }

        output.WriteLine();
    }

    private static bool DeclinedAnotherProtector(PassResult pass) =>
        pass.Pass is "reactor-detection" or "confuserex-detection";

    private static string First(PassResult pass) =>
        pass.Diagnostics.Count > 0 ? pass.Diagnostics[0] : "no detail recorded";

    private static string Size(long bytes) => bytes switch
    {
        >= 1024 * 1024 => $"{bytes / (1024.0 * 1024.0):0.#} MB",
        >= 1024 => $"{bytes / 1024.0:0.#} KB",
        _ => $"{bytes} bytes"
    };

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
