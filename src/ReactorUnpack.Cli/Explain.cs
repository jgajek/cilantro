using System.Globalization;
using ReactorUnpack.Core;

namespace ReactorUnpack.Cli;

/// <summary>
/// Turns a pipeline report into something an analyst can read without knowing how the tool works.
/// </summary>
/// <remarks>
/// The pass log the tool used to print is a record of its own reasoning, and it answers questions
/// nobody arrives with. Someone who has just pulled a suspicious file out of a sandbox wants three
/// things in this order: whether the file is protected and by what, how much of the original code
/// came back, and where the readable copy is. The pass log answers none of those directly, so it
/// moves behind <c>--verbose</c> and this takes the front.
///
/// Everything printed here is read off the report rather than restated, so the summary cannot drift
/// from what actually happened: the counts come from the recovery metrics, the protections come
/// from the capabilities detection recorded, and the caveats come from pass status. What this file
/// adds is only the English.
/// </remarks>
internal static class Explain
{
    /// <summary>
    /// What each protection Reactor applies means for the person reading the code.
    /// </summary>
    /// <remarks>
    /// The names on the left are the tool's internal vocabulary and appear in the JSON report, so
    /// they are worth keeping somewhere a reader can map them; the sentences on the right avoid
    /// .NET terms wherever a plain one exists. "Method body" survives because there is no shorter
    /// true way to say it and an analyst meets the phrase everywhere else too.
    /// </remarks>
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
            "Some methods are bytecode for a custom interpreter (listed, not turned back into code)")
    ];

    public static void Summarize(PipelineResult result, string inputPath)
    {
        var report = result.Report;
        var home = Path.GetDirectoryName(Path.GetFullPath(inputPath))!;
        Console.WriteLine();
        Console.WriteLine($"  File     {Path.GetFileName(inputPath)}  ({Size(report.InputLength)})");
        Console.WriteLine($"  SHA-256  {report.InputSha256}");
        Console.WriteLine();

        var capabilities = report.Evidence
            .Where(evidence => evidence.Category == "capability")
            .Select(evidence => evidence.Message)
            .ToHashSet(StringComparer.Ordinal);
        if (capabilities.Count == 0)
        {
            // Finding nothing is a real answer and the commonest one on a file somebody guessed
            // about, so it gets said outright. Reporting it as a string of incomplete stages would
            // read as a malfunction, when in fact every stage declined for the same good reason.
            Console.WriteLine("  PROTECTION   None. This file is not protected by .NET Reactor.");
            Console.WriteLine();
            Console.WriteLine("    There is nothing to undo, so no cleaned copy was written.");
            Console.WriteLine("    If you expected protection here, the report lists what was");
            Console.WriteLine($"    checked: {Near(result.AnalysisReportPath, home)}");
            Console.WriteLine();
            return;
        }

        Protection(capabilities);
        Recovered(report);
        Assumed(report);
        Written(result, home);
        Caveats(result);
    }

    /// <summary>
    /// What the run was told about the machine, as opposed to what it worked out from the file.
    /// </summary>
    /// <remarks>
    /// A recovered string that came out of a decrypter is a fact about the sample. A recovered
    /// string that came out of a decrypter keyed on the computer's serial number is a fact about the
    /// sample and a serial number somebody typed in, and a reader who does not know the second half
    /// cannot judge the first. Only what was consulted is listed, because a profile mostly describes
    /// things this sample never asked about.
    /// </remarks>
    private static void Assumed(ArtifactReport report)
    {
        if (report.HostProfile is not { } profile || profile.Consulted.Count == 0)
            return;
        var answered = profile.Consulted.Where(fact => fact.Answered).ToArray();
        var refused = profile.Consulted.Where(fact => !fact.Answered).ToArray();
        Console.WriteLine($"  ASSUMED   about the machine, from the \"{profile.Name}\" profile");
        Console.WriteLine();
        var width = profile.Consulted.Max(fact => fact.Key.Length);
        foreach (var fact in answered)
            Console.WriteLine($"    {fact.Key.PadRight(width)}   {fact.Answer}");
        foreach (var fact in refused)
            Console.WriteLine($"    {fact.Key.PadRight(width)}   not stated, so the code that asked was not read");
        Console.WriteLine();
    }

    /// <summary>
    /// Shortens a path to how it reads from where the sample sits, which is where the reader is.
    /// </summary>
    private static string Near(string path, string home)
    {
        var relative = Path.GetRelativePath(home, path);
        return relative.StartsWith("..", StringComparison.Ordinal) ? path : relative;
    }

    private static void Protection(HashSet<string> capabilities)
    {
        Console.WriteLine("  PROTECTION   .NET Reactor");
        Console.WriteLine();
        foreach (var (capability, meaning) in Protections)
        {
            if (capabilities.Contains(capability))
                Console.WriteLine($"    - {meaning}");
        }

        Console.WriteLine();
    }

    private static void Recovered(ArtifactReport report)
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

        // Counted separately from the line above because it is a different protection: the strings
        // are behind the program's own decoder rather than behind Reactor's resolver, so there is no
        // set of call sites to have covered all of, only calls read and replaced.
        Add(lines, "String calls decoded", recovery.ConstantStringSites);
        Add(lines, "Hidden calls resolved", recovery.TokensRestored);
        Add(lines, "Hidden true/false values resolved", recovery.BooleansRecovered);
        Add(lines, "Junk instructions removed", recovery.UnreachableInstructionsRemoved);
        Add(lines, "Encrypted resources restored", recovery.ResourcesRestored);
        Add(lines, "Protector types deleted", recovery.RuntimeTypesRemoved);
        Add(lines, "Obfuscated names replaced", recovery.SymbolsRenamed);
        if (lines.Count == 0)
            return;

        Console.WriteLine("  RECOVERED");
        Console.WriteLine();
        var width = lines.Max(line => line.Label.Length);
        foreach (var (label, value) in lines)
            Console.WriteLine($"    {label.PadRight(width)}   {value}");
        Console.WriteLine();
    }

    private static void Add(List<(string, string)> lines, string label, int value)
    {
        if (value > 0)
            lines.Add((label, value.ToString("N0", CultureInfo.InvariantCulture)));
    }

    private static void Written(PipelineResult result, string home)
    {
        Console.WriteLine("  WROTE");
        Console.WriteLine();
        Console.WriteLine(result.OutputPath is null
            ? "    Cleaned copy    none - see the notes below"
            : $"    Cleaned copy    {Near(result.OutputPath, home)}");
        if (result.ExtractedPayloadPaths.Count > 0)
        {
            var folder = Near(Path.GetDirectoryName(result.ExtractedPayloadPaths[0])!, home);
            Console.WriteLine(
                $"    Hidden files    {result.ExtractedPayloadPaths.Count} in {folder}");
        }

        if (result.VirtualProgramPaths.Count > 0)
        {
            var folder = Near(Path.GetDirectoryName(result.VirtualProgramPaths[0])!, home);
            Console.WriteLine(
                $"    Hidden code     {result.VirtualProgramPaths.Count} listing(s) in {folder}");
        }

        Console.WriteLine($"    Full report     {Near(result.AnalysisReportPath, home)}");
        Console.WriteLine();
    }

    /// <summary>
    /// What the tool could not do, said plainly, because a silent gap is the dangerous kind.
    /// </summary>
    private static void Caveats(PipelineResult result)
    {
        var unsupported = result.Report.Passes
            .Where(pass => pass.Status is PassStatus.Unsupported or PassStatus.Partial)
            .ToArray();
        var failed = result.Report.Passes
            .Where(pass => pass.Status == PassStatus.Failed)
            .ToArray();
        if (unsupported.Length == 0 && failed.Length == 0 && result.OutputPath is not null)
        {
            Console.WriteLine("  Open the cleaned copy in dnSpyEx or ILSpy to read the code.");
            Console.WriteLine();
            return;
        }

        Console.WriteLine("  NOTES");
        Console.WriteLine();
        foreach (var pass in failed)
            Console.WriteLine($"    ! {pass.Pass} failed: {First(pass)}");
        foreach (var pass in unsupported)
            Console.WriteLine($"    - {pass.Pass} was incomplete: {First(pass)}");
        if (result.OutputPath is null)
        {
            Console.WriteLine();
            Console.WriteLine("    No cleaned copy was written. ReactorUnpack only writes one when it");
            Console.WriteLine("    can show the result still matches the original, so a partial result");
            Console.WriteLine("    is reported instead of being handed over as if it were complete.");
            Console.WriteLine("    The full report above records everything that was learned.");
        }

        Console.WriteLine();
    }

    private static string First(PassResult pass) =>
        pass.Diagnostics.Count > 0 ? pass.Diagnostics[0] : "no detail recorded";

    private static string Size(long bytes) => bytes switch
    {
        >= 1024 * 1024 => $"{bytes / (1024.0 * 1024.0):0.#} MB",
        >= 1024 => $"{bytes / 1024.0:0.#} KB",
        _ => $"{bytes} bytes"
    };

    /// <summary>
    /// The pass-by-pass log, kept for anyone who wants to see the tool's reasoning.
    /// </summary>
    public static void PassLog(ArtifactReport report)
    {
        Console.WriteLine("  STEPS");
        Console.WriteLine();
        foreach (var pass in report.Passes)
        {
            Console.WriteLine(
                $"    [{pass.Status.ToString().ToLowerInvariant(),-11}] {pass.Pass}: " +
                $"{pass.Changes} change(s)");
            foreach (var diagnostic in pass.Diagnostics)
                Console.WriteLine($"                  {diagnostic}");
        }

        Console.WriteLine();
    }
}
