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
}
