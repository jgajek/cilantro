using System.Text.Json;
using Cilantro.Cli;
using Cilantro.Core;
using Cilantro.Core.Corpus;
using Cilantro.Core.Interpretation;

return CilantroCommand.Run(args);

internal static class CilantroCommand
{
    public static int Run(string[] args)
    {
        if (args.Length >= 2 && args[0] == "corpus" && args[1] == "run")
            return RunCorpus(args[2..]);
        if (args.Any(argument => argument is "--version"))
        {
            Console.WriteLine(CilantroPipeline.Version);
            return 0;
        }

        if (args.Length == 0 || args.Any(argument => argument is "-h" or "--help" or "/?"))
        {
            PrintUsage();
            return args.Length == 0 ? 2 : 0;
        }

        // Read before the loop as well as in it, so that a run asking for JSON still answers in JSON
        // when the thing that went wrong was the command line itself.
        _json = args.Contains("--json");
        var analyzeOnly = false;
        var failOnPartial = false;
        var removeRuntime = true;
        bool? renameSymbols = null;
        var verbose = false;
        string? output = null;
        string? reportDirectory = null;
        string? hostProfile = null;
        string? declarations = null;
        var allowDeclaredCalls = false;
        var strict = false;
        bool? devirtualize = null;
        var status = false;
        string? input = null;
        var libraries = new List<string>();

        for (var index = 0; index < args.Length; index++)
        {
            switch (args[index])
            {
                case "--analyze-only":
                    analyzeOnly = true;
                    break;
                case "--fail-on-partial":
                    failOnPartial = true;
                    break;
                case "--remove-runtime":
                    removeRuntime = true;
                    break;
                case "--keep-runtime":
                    removeRuntime = false;
                    break;
                case "--rename":
                    renameSymbols = true;
                    break;
                case "--keep-names":
                    renameSymbols = false;
                    break;
                case "-v":
                case "--verbose":
                    verbose = true;
                    break;
                case "--json":
                    break;
                case "-o":
                case "--output":
                    if (!TryTakeValue(args, ref index, out output))
                        return Fail($"{args[index]} needs a file path after it.");
                    break;
                case "--report-dir":
                    if (!TryTakeValue(args, ref index, out reportDirectory))
                        return Fail($"{args[index]} needs a folder path after it.");
                    break;
                case "--host-profile":
                    if (!TryTakeValue(args, ref index, out hostProfile))
                        return Fail($"{args[index]} needs a file path after it.");
                    break;
                case "--library":
                    if (!TryTakeValue(args, ref index, out var library))
                        return Fail($"{args[index]} needs a file path after it.");
                    libraries.Add(library!);
                    break;
                case "--declarations":
                    if (!TryTakeValue(args, ref index, out declarations))
                        return Fail($"{args[index]} needs a file path after it.");
                    break;
                case "--allow-declared-calls":
                    allowDeclaredCalls = true;
                    break;
                case "--strict":
                    strict = true;
                    break;
                case "--devirtualize":
                    devirtualize = true;
                    break;
                case "--no-devirtualize":
                    devirtualize = false;
                    break;
                case "--status":
                    status = true;
                    break;
                default:
                    if (args[index].StartsWith('-'))
                        return Fail($"Unknown option: {args[index]}");
                    if (input is not null)
                        return Fail("Give one file at a time.");
                    input = args[index];
                    break;
            }
        }

        if (input is null)
            return Fail("Tell me which file to look at.");
        if (Directory.Exists(input))
            return Fail($"That is a folder, not a file: {input}");
        if (!File.Exists(input))
            return Fail($"No such file: {input}");

        try
        {
            var result = new CilantroPipeline().Run(input, new PipelineOptions(
                AnalyzeOnly: analyzeOnly,
                PreserveTokens: true,
                FailOnPartial: failOnPartial,
                RemoveRuntime: removeRuntime,
                RenameSymbols: renameSymbols,
                OutputPath: output,
                ReportDirectory: reportDirectory,
                HostProfilePath: hostProfile,
                LibraryPaths: libraries,
                DeclarationsPath: declarations,
                AllowDeclaredCalls: allowDeclaredCalls,
                Strict: strict,
                Devirtualize: devirtualize,
                StatusPath: status ? RunStatus.PathFor(input, reportDirectory) : null));

            if (_json)
            {
                // Nothing else goes to standard output in this mode: a caller piping it into a
                // parser should get one object and no prose wrapped around it.
                Console.WriteLine(JsonSerializer.Serialize(
                    RunManifest.Of(result), CilantroPipeline.ReportJsonOptions));
                return result.Success ? 0 : 1;
            }

            if (verbose)
                Explain.PassLog(result.Report);
            Explain.Summarize(result, input);
            if (!result.Report.VerificationPassed)
            {
                foreach (var diagnostic in result.Report.VerificationDiagnostics)
                    Console.Error.WriteLine($"verify: {diagnostic}");
            }

            return result.Success ? 0 : 1;
        }
        catch (BadImageFormatException)
        {
            return Fail(
                $"{Path.GetFileName(input)} is not a .NET assembly. CILantro only reads " +
                ".NET executables and libraries.");
        }
        // These two say what is wrong with what was handed in, so the message is the whole of the
        // answer and prefixing it with the name of a class only gets in the reader's way.
        catch (Exception ex) when (
            ex is HostProfileException or TrustedLibraryException or DeclarationException)
        {
            return Fail(ex.Message);
        }
        catch (Exception ex)
        {
            return Fail($"{ex.GetType().Name}: {ex.Message}");
        }
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

    private static int Fail(string message)
    {
        if (_json)
        {
            Console.WriteLine(JsonSerializer.Serialize(
                new RunFailure(message), CilantroPipeline.ReportJsonOptions));
            return 2;
        }

        Console.Error.WriteLine($"error: {message}");
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

    private static void PrintUsage() =>
        Console.WriteLine(
            $"""
            CILantro {CilantroPipeline.Version} - recover readable code from protected .NET

            Point it at a file protected with .NET Reactor or ConfuserEx. It decrypts what
            the protector encrypted, undoes what it scrambled, and writes a clean copy you
            can open in a decompiler. The protected file is never run.

              cilantro suspicious.exe

            That writes suspicious.cleaned.exe beside the input, plus a cilantro
            folder holding the full report and any files that were hidden inside.

            By default it does everything that makes the result easier to read: it renames
            the protector's generated symbols and, where a method is bytecode for an
            interpreter, builds that method back into code in the clean copy, marked as the
            tool's reading rather than something it proved. --strict turns both off and stops
            wherever a normal run would assume its way past something.

            Options:
              -v, --verbose            Show every step the tool took
                  --json               Print one JSON object instead of the summary, naming
                                       every file written and what to declare to get further
                  --analyze-only       Report what is there without writing a clean copy
              -o, --output PATH        Write the clean copy somewhere else
                  --report-dir DIR     Write the report somewhere else
                  --keep-runtime       Leave the protector's own code in place instead of removing it
                  --rename             Give obfuscated names readable placeholders (default,
                                       and how to ask for it in a strict run)
                  --keep-names         Leave the protector's generated names as they are
                  --devirtualize       Build virtualized methods back into code in the clean copy,
                                       marked as a reading rather than a proof (default, and how
                                       to ask for it in a strict run)
                  --no-devirtualize    Leave virtualized methods as the stubs they shipped as
                  --status             Keep a NAME.status.json beside the reports saying which
                                       pass is running, so a long run can be watched from
                                       elsewhere while it goes
                  --fail-on-partial    Write nothing unless every stage fully succeeded
                  --strict             Assume nothing: stop where a normal run would carry on,
                                       and leave the assembly as it stands
                  --host-profile FILE  State what the Windows machine the sample expects looks like
                  --library FILE       Let the reader follow calls into this assembly (repeatable)
                  --declarations FILE  Everything above in one file, plus budgets and passes to skip
                  --allow-declared-calls
                                       Let that file also say what calls the tool cannot read do
              -h, --help               Show this
                  --version            Print the version

            When a run stops short it writes cilantro/NAME.blockers.json, which names
            each thing that stopped it and the declaration that would get past it. Docs:
            docs/declarations.md

            Driving it from a program or an agent: --json, and docs/agents.md

            Development:
              cilantro corpus run [--manifest PATH] [--samples DIR] [--output DIR] [--strict]

            Docs and issues: https://github.com/jgajek/cilantro
            """);
}
