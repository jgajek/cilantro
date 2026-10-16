namespace Cilantro.Cli;

internal enum ConsoleTone { Plain, Green, Cyan, Amber, Red, Muted }

internal static class ConsoleTheme
{
    internal static bool Enabled(bool redirected, string? noColor, string? term, bool disabled) =>
        !redirected && noColor is null && term != "dumb" && !disabled;

    internal static bool ForOutput(bool disabled = false) => Enabled(
        Console.IsOutputRedirected, Environment.GetEnvironmentVariable("NO_COLOR"),
        Environment.GetEnvironmentVariable("TERM"), disabled);

    internal static bool ForError(bool disabled = false) => Enabled(
        Console.IsErrorRedirected, Environment.GetEnvironmentVariable("NO_COLOR"),
        Environment.GetEnvironmentVariable("TERM"), disabled);

    internal static string Paint(string text, ConsoleTone tone, bool color)
    {
        if (!color || tone == ConsoleTone.Plain) return text;
        var code = tone switch
        {
            ConsoleTone.Green => "92",
            ConsoleTone.Cyan => "96",
            ConsoleTone.Amber => "93",
            ConsoleTone.Red => "91",
            _ => "90"
        };
        return $"\u001b[{code}m{text}\u001b[0m";
    }

    internal static void Line(TextWriter writer, string text, ConsoleTone tone, bool color) =>
        writer.WriteLine(Paint(text, tone, color));
}
