using System.Text.Json;
using Cilantro.Cli;
using Cilantro.Core;
using Cilantro.Core.Corpus;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Native;

return CilantroCommand.Run(args);

internal static class CilantroCommand
{
    public static int Run(string[] args)
    {
        var switches = args.TakeWhile(argument => argument != "--").ToArray();
        _json = switches.Contains("--json");
        _noColor = switches.Contains("--no-color");
        _analysisConsole = null;
        if (args.Length >= 2 && args[0] == "corpus" && args[1] == "run")
            return RunCorpus(args[2..]);
        string? input = null;
        try
        {
            var command = AnalysisArguments.Parse(args);
            if (command.Version)
            {
                Console.WriteLine(CilantroPipeline.Version);
                return 0;
            }
            if (args.Length == 0 || command.Help || command.HelpAll)
            {
                PrintUsage(command.HelpAll);
                return args.Length == 0 ? 2 : 0;
            }
            input = command.Input;
            _json = command.Json;
            _noColor = command.NoColor;
            var options = command.PreparePipelineOptions();
            if (!_json)
            {
                _analysisConsole = new AnalysisConsole(Console.Out, ConsoleTheme.ForOutput(_noColor));
                _analysisConsole.Banner(input!, command.AnalyzeOnly, command.Strict);
            }
            var result = new CilantroPipeline().Run(input!, options with
            {
                Progress = _analysisConsole is { } terminal ? terminal.Report : null
            });
            if (_json)
            {
                Console.WriteLine(JsonSerializer.Serialize(RunManifest.Of(result), CilantroPipeline.ReportJsonOptions));
                return result.Success ? 0 : 1;
            }
            _analysisConsole?.Complete(result);
            Explain.Summarize(result, input!, Console.Out, command.Verbose, ConsoleTheme.ForOutput(_noColor));
            if (command.Verbose) Explain.PassLog(result.Report);
            if (!result.Report.VerificationPassed)
                foreach (var diagnostic in result.Report.VerificationDiagnostics)
                    ConsoleTheme.Line(Console.Error, $"verify: {diagnostic}", ConsoleTone.Red, ConsoleTheme.ForError(_noColor));
            return result.Success ? 0 : 1;
        }
        catch (NativeBootstrapException failure) { return Fail(failure.Message); }
        catch (BadImageFormatException)
        {
            return Fail($"{Path.GetFileName(input)} is not a supported .NET assembly or Reactor native wrapper.");
        }
        catch (Exception ex) when (ex is ArgumentException or HostProfileException or TrustedLibraryException or DeclarationException)
        {
            return Fail(ex.Message);
        }
        catch (Exception ex) { return Fail($"{ex.GetType().Name}: {ex.Message}"); }
    }

    private static bool TryTakeValue(string[] args, ref int index, out string? value)
    {
        if (index + 1 >= args.Length || args[index + 1].StartsWith('-'))
        {
            value = null;
            return false;
        }

        value = args[++index];
        return true;
    }

    /// <summary>Whether this run answers in JSON, which changes how a refusal is said as well.</summary>
    private static bool _json;
    private static bool _noColor;
    private static AnalysisConsole? _analysisConsole;

    private static int Fail(string message)
    {
        if (_json)
        {
            Console.WriteLine(JsonSerializer.Serialize(
                new RunFailure(message), CilantroPipeline.ReportJsonOptions));
            return 2;
        }

        _analysisConsole?.Failed();
        ConsoleTheme.Line(Console.Error, $"error: {message}", ConsoleTone.Red, ConsoleTheme.ForError(_noColor));
        Console.Error.WriteLine("Run cilantro --help for usage.");
        return 2;
    }

    private static int RunCorpus(string[] args)
    {
        var manifest = "corpus/reactor-6-nonvirt.manifest.json";
        var samples = "samples";
        var output = "artifacts/corpus";
        var strict = false;
        try
        {
            for (var index = 0; index < args.Length; index++)
            {
                switch (args[index])
                {
                    case "--manifest":
                        if (!TryTakeValue(args, ref index, out manifest))
                            return Fail("--manifest needs a file path after it.");
                        break;
                    case "--samples":
                        if (!TryTakeValue(args, ref index, out samples))
                            return Fail("--samples needs a folder path after it.");
                        break;
                    case "--output":
                        if (!TryTakeValue(args, ref index, out output))
                            return Fail("--output needs a folder path after it.");
                        break;
                    case "--strict":
                        strict = true;
                        break;
                    default:
                        return Fail($"Unknown corpus option: {args[index]}");
                }
            }

            var report = CorpusRunner.Run(manifest!, samples!, output!, strict);
            Console.WriteLine($"Corpus:  {Path.GetFullPath(manifest!)}");
            Console.WriteLine(
                $"Results: {Path.GetFullPath(Path.Combine(output!, "corpus.outcomes.json"))}");
            Console.WriteLine($"Passed: {report.Passed}; failed: {report.Failed}; missing: {report.Missing}");
            return report.Failed == 0 && report.Missing == 0 ? 0 : 1;
        }
        catch (Exception ex)
        {
            return Fail($"{ex.GetType().Name}: {ex.Message}");
        }
    }

    private static void PrintUsage(bool all = false)
    {
        Console.WriteLine(
            $"""
            CILantro {CilantroPipeline.Version} - recover readable code from protected .NET

            Usage: cilantro FILE [options]

              cilantro sample.exe                  Recover the sample and embedded assemblies
              cilantro sample.exe -o case/run-01   Put every output in this case folder
              cilantro sample.exe --analyze-only   Reports and extracted files; no cleaned copies
              cilantro sample.exe --strict         Retry without assumed machine settings

            By default, recover supported code and strings, rebuild VM-backed methods, assign
            readable names, remove proven protector code, and follow embedded assemblies within
            fixed limits. The sample is interpreted statically; it is never launched.

            All outputs go in FILESTEM.cilantro beside the input, with -2, -3, ... for repeat runs.
            Use -o DIR for a chosen empty/new folder. The input is preserved. Progress and a status
            file are automatic. Follow OUTPUT to the cleaned assembly, HTML report and case folder.

            Common options:
              -o, --output DIR    Case folder for cleaned files, extracted stages and reports
                  --analyze-only  Recover information without writing cleaned assemblies
                  --strict        Stop at unknown behavior; keep names and VM stubs unchanged
              -v, --verbose       Include technical diagnostics and per-pass details
                  --json          One JSON run/error object instead of human console output
                  --no-color      Plain text (also automatic for redirection and NO_COLOR)
              -h, --help          Show common workflows and options
                  --help-all      Include specialist analysis controls
                  --version       Print only the version

            Success means the configured run finished, not complete unprotection or equivalent
            behavior. Review NEEDS REVIEW, REMAINING and VALIDATION before relying on the code.
            Exit codes: 0 configured success; 1 incomplete/failed run; 2 argument/input/error.
            Docs: docs/quick-start.md   Issues: https://github.com/jgajek/cilantro
            """);
        if (all)
            Console.WriteLine(
                """

                Specialist controls:
                  --no-recursion                Extract children without cleaning further stages;
                                                native wrappers still continue to their managed stage
                  --keep-names                  Preserve obfuscated identifiers for name comparisons
                  --keep-runtime                Retain protector helpers for investigating protection
                  --no-devirtualize             Keep VM stubs; still write supported VM listings
                  --generic-recovery            Attempt verified cleanup without a recognized protector
                  --fail-on-partial             Withhold success/cleaned output on incomplete passes
                  --library FILE                Read this managed dependency statically (repeatable)
                  --host-profile FILE           Supply facts about the sample's expected machine
                  --declarations FILE           Supply host facts, libraries, budgets or skipped passes
                  --allow-declared-calls        Trust call assertions in --declarations; review them first
                  --reviewed-dependencies FILE  Preserve exact matches to independently reviewed DLLs

                --strict also disables permissive interpretation and implicit host assumptions. It
                may recover less; it is not a stronger correctness verdict. For a readable VM
                reconstruction, compare a separate ordinary run.
                See docs/declarations.md for facts, budgets and the risks of call assertions.

                Development: cilantro corpus run [--manifest PATH] [--samples DIR] [--output DIR] [--strict]
                """);
    }
}
