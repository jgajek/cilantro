using System.Diagnostics;
using System.Globalization;
using Cilantro.Core;

namespace Cilantro.Cli;

/// <summary>A sequential transcript: no cursor animation, so logs remain useful when redirected.</summary>
internal sealed class AnalysisConsole(TextWriter output, bool color)
{
    private readonly Stopwatch _elapsed = Stopwatch.StartNew();
    private string? _input;
    private PipelineStage? _stage;
    private bool _passOpen;

    internal void Banner(string input, bool analyzeOnly, bool strict)
    {
        output.WriteLine();
        // ASCII only: keep the leaf and wordmark legible in classic Windows consoles.
        string[] logo =
        [
            "             +#+",
            "          ++#####++",
            "         ###########",
            "        ++#########++",
            "       #######+#######",
            "       ######+ +######",
            "       ####### #######",
            "    ++ + ++### ###++ + ++",
            " #########+ +#+#+ +#########",
            "###########+ +#  +###########",
            "+#### +#####  #  #####+ ####+",
            " #######+++##+#+##+++#######",
            " +##########+###+##########+",
            "   ++######+ +#+ +######++",
            "    +####+   +#    +####+",
            "      +      +#       +",
            "              #+"
        ];
        for (var index = 0; index < logo.Length; index++)
        {
            var caption = index switch
            {
                3 => "  ____ ___ _             _",
                4 => " / ___|_ _| | __ _ _ __ | |_ _ __ ___",
                5 => "| |    | || |/ _` | '_ \\| __| '__/ _ \\",
                6 => "| |___ | || | (_| | | | | |_| | | (_) |",
                7 => " \\____|___|_|\\__,_|_| |_|\\__|_|  \\___/",
                10 => $"CILantro {CilantroPipeline.Version}  /  .NET code recovery",
                12 => "Reveal the code. Follow the payload.",
                13 => "Static analysis / bounded interpretation",
                _ => string.Empty
            };
            output.WriteLine(ConsoleTheme.Paint("  " + logo[index].PadRight(33), ConsoleTone.Green, color) +
                ConsoleTheme.Paint(caption, index is >= 3 and <= 7 ? ConsoleTone.Green :
                    index == 10 ? ConsoleTone.Cyan : ConsoleTone.Muted, color));
        }
        output.WriteLine();
        Line($"  INPUT   {Path.GetFullPath(input)}", ConsoleTone.Cyan);
        Line($"  MODE    {(analyzeOnly ? "Analysis only" : "Recovery")} / {(strict ? "strict" : "default")}", ConsoleTone.Muted);
        output.WriteLine();
        output.Flush();
    }

    internal void Report(PipelineProgress progress)
    {
        if (progress.Stage == PipelineStage.Finished)
        {
            EndOpenPass();
            return;
        }
        if (_input != progress.InputPath || _stage != progress.Stage)
        {
            EndOpenPass();
            if (_input != progress.InputPath)
            {
                Line($"  TARGET  {Path.GetFullPath(progress.InputPath)}", ConsoleTone.Cyan);
                _input = progress.InputPath;
            }
            _stage = progress.Stage;
            Line($"  [{Label(progress.Stage)}] {Description(progress.Stage)}", ConsoleTone.Cyan);
        }
        if (progress.Pass is not null)
        {
            if (progress.Result is not { } result)
            {
                EndOpenPass();
                output.Write($"    [{progress.PassNumber:000}/{progress.PassesTotal:000}] {progress.Pass} ... ");
                _passOpen = true;
            }
            else
            {
                var (label, tone) = progress.Skipped ? ("SKIP", ConsoleTone.Muted) : result.Status switch
                {
                    PassStatus.Success => ("OK", ConsoleTone.Green),
                    PassStatus.Partial => ("PARTIAL", ConsoleTone.Amber),
                    PassStatus.Unsupported => ("UNSUPPORTED", ConsoleTone.Amber),
                    _ => ("FAILED", ConsoleTone.Red)
                };
                Line($"{label}  {result.Changes} changes  {result.Duration.TotalSeconds.ToString("0.00", CultureInfo.InvariantCulture)}s", tone);
                _passOpen = false;
            }
        }
        output.Flush();
    }

    internal void Complete(PipelineResult result)
    {
        EndOpenPass();
        output.WriteLine();
        Line($"  [{(result.Success ? "DONE" : "INCOMPLETE")}] Analysis finished in {_elapsed.Elapsed.TotalSeconds.ToString("0.00", CultureInfo.InvariantCulture)}s",
            result.Success ? ConsoleTone.Green : ConsoleTone.Amber);
    }

    internal void Failed()
    {
        EndOpenPass();
        Line($"  [FAILED] Analysis stopped during {_stage?.ToString() ?? "startup"}; see the error below.", ConsoleTone.Red);
    }

    private void EndOpenPass()
    {
        if (!_passOpen) return;
        Line("INTERRUPTED", ConsoleTone.Red);
        _passOpen = false;
    }

    private void Line(string text, ConsoleTone tone) => ConsoleTheme.Line(output, text, tone, color);

    private static string Label(PipelineStage stage) => stage switch
    {
        PipelineStage.EmbeddedRecovery => "CHILDREN",
        _ => stage.ToString().ToUpperInvariant()
    };

    private static string Description(PipelineStage stage) => stage switch
    {
        PipelineStage.Loading => "Read input, declarations and native-wrapper metadata",
        PipelineStage.Unpacking => "Unpack the native wrapper and validate the managed stage",
        PipelineStage.Recovery => "Detect protection, recover code and simplify the assembly",
        PipelineStage.Verification => "Check assembly structure before emission",
        PipelineStage.Extraction => "Write extracted payloads, symbol maps and VM listings",
        PipelineStage.Emission => "Write the cleaned assembly and verify serialized output",
        PipelineStage.Reporting => "Write analysis evidence and the offline HTML report",
        PipelineStage.EmbeddedRecovery => "Follow extracted assemblies within traversal limits",
        _ => "Reports and artifact inventory are ready"
    };
}
