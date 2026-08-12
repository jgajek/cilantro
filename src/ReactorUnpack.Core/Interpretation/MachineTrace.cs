using dnlib.DotNet;

namespace ReactorUnpack.Core.Interpretation;

/// <summary>Opt-in execution trace for diagnosing why a bootstrap interpretation diverges.
/// Set <c>REACTOR_TRACE_FILE</c> to record dispatcher state transitions and framed resource
/// reads; the trace is inert and allocation-free when the variable is unset.</summary>
internal static class MachineTrace
{
    private static readonly string? Path =
        Environment.GetEnvironmentVariable("REACTOR_TRACE_FILE");
    private static readonly System.Text.StringBuilder Buffer = new();

    static MachineTrace()
    {
        if (Enabled)
            AppDomain.CurrentDomain.ProcessExit += (_, _) => Flush();
        if (Profiling)
            AppDomain.CurrentDomain.ProcessExit += (_, _) => DumpProfile();
    }

    public static bool Enabled => !string.IsNullOrEmpty(Path);

    public static void Line(string text)
    {
        if (!Enabled)
            return;
        Buffer.AppendLine(text);
        if (Buffer.Length > 1 << 20)
            Flush();
    }

    public static void Flush()
    {
        if (!Enabled || Buffer.Length == 0)
            return;
        File.AppendAllText(Path!, Buffer.ToString());
        Buffer.Clear();
    }

    /// <summary>
    /// The instructions most recently executed, kept so a failure can say what led to it.
    /// </summary>
    /// <remarks>
    /// Writing every instruction to the trace would bury the interesting moment in millions of
    /// lines and turn a run into a disk-bound one, but a failure deep inside an obfuscator's own
    /// interpreter is unreadable without knowing what it just did. A ring keeps the cost of a step
    /// at one array store and still has the approach to any failure when one happens.
    /// </remarks>
    private static readonly string?[] Recent = new string[Enabled ? Depth() : 0];

    /// <summary>
    /// How many steps to keep, from <c>REACTOR_TRACE_DEPTH</c> when a longer run-up is needed.
    /// </summary>
    private static int Depth() =>
        int.TryParse(
            Environment.GetEnvironmentVariable("REACTOR_TRACE_DEPTH"),
            out var requested) && requested > 0
            ? requested
            : 4096;
    private static int _written;

    public static void Step(string description)
    {
        if (Recent.Length == 0)
            return;
        Recent[_written++ % Recent.Length] = description;
    }

    private static readonly string? ProfilePath =
        Environment.GetEnvironmentVariable("REACTOR_PROFILE_FILE");

    /// <summary>
    /// Where a run spends its steps, per method, when <c>REACTOR_PROFILE_FILE</c> asks.
    /// </summary>
    /// <remarks>
    /// An obfuscator's interpreter is unmistakable in a profile and easy to miss by reading names:
    /// it is the one method that executes tens of millions of steps while everything around it
    /// executes thousands. Separating a frame's own steps from those of the frames it calls is what
    /// distinguishes a dispatcher from the entry point that merely contains one.
    /// </remarks>
    private static readonly Dictionary<MethodDef, (long Self, long Total, long Calls)> Frames = [];

    public static bool Profiling => !string.IsNullOrEmpty(ProfilePath);

    public static void Frame(MethodDef method, long self, long total)
    {
        if (!Profiling)
            return;
        Frames.TryGetValue(method, out var running);
        Frames[method] = (running.Self + self, running.Total + total, running.Calls + 1);
    }

    public static void DumpProfile()
    {
        if (!Profiling || Frames.Count == 0)
            return;
        var lines = Frames
            .OrderByDescending(entry => entry.Value.Self)
            .Select(entry =>
                $"{entry.Value.Self,14} {entry.Value.Total,14} {entry.Value.Calls,9}  " +
                $"{entry.Key.MDToken} {entry.Key.FullName}");
        File.WriteAllLines(
            ProfilePath!,
            new[] { $"{"self",14} {"total",14} {"calls",9}  method" }.Concat(lines));
        Frames.Clear();
    }

    /// <summary>
    /// Writes the approach to a failure, oldest first, and forgets it.
    /// </summary>
    public static void DumpRecent(string reason)
    {
        if (Recent.Length == 0 || _written == 0)
            return;
        var kept = Math.Min(_written, Recent.Length);
        Line($"--- last {kept} steps before {reason} ---");
        for (var age = kept; age > 0; age--)
            Line(Recent[(_written - age) % Recent.Length]!);
        Line($"--- end of approach to {reason} ---");
        _written = 0;
        Flush();
    }
}
