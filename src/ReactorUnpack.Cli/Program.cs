using ReactorUnpack.Cli;
using ReactorUnpack.Core;
using ReactorUnpack.Core.Corpus;
using ReactorUnpack.Core.Interpretation;

return ReactorCommand.Run(args);

internal static class ReactorCommand
{
    public static int Run(string[] args)
    {
        if (args.Length >= 2 && args[0] == "corpus" && args[1] == "run")
            return RunCorpus(args[2..]);
        if (args.Any(argument => argument is "--version"))
        {
            Console.WriteLine(ReactorPipeline.Version);
            return 0;
        }

        if (args.Length == 0 || args.Any(argument => argument is "-h" or "--help" or "/?"))
        {
            PrintUsage();
            return args.Length == 0 ? 2 : 0;
        }

        var analyzeOnly = false;
        var failOnPartial = false;
        var removeRuntime = true;
        var renameSymbols = false;
        var verbose = false;
        string? output = null;
        string? reportDirectory = null;
        string? hostProfile = null;
        string? declarations = null;
        var allowDeclaredCalls = false;
        var strict = false;
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
                case "-v":
                case "--verbose":
                    verbose = true;
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
            var result = new ReactorPipeline().Run(input, new PipelineOptions(
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
                Strict: strict));

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
                $"{Path.GetFileName(input)} is not a .NET assembly. ReactorUnpack only reads " +
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

    private static int Fail(string message)
    {
        Console.Error.WriteLine($"error: {message}");
        Console.Error.WriteLine("Run ReactorUnpack --help for usage.");
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
            ReactorUnpack {ReactorPipeline.Version} - recover readable code from .NET Reactor

            Point it at a protected .NET file. It decrypts what Reactor encrypted, undoes
            what it scrambled, and writes a clean copy you can open in a decompiler. The
            protected file is never run.

              ReactorUnpack suspicious.exe

            That writes suspicious.cleaned.exe beside the input, plus a reactorunpack
            folder holding the full report and any files that were hidden inside.

            Options:
              -v, --verbose            Show every step the tool took
                  --analyze-only       Report what is there without writing a clean copy
              -o, --output PATH        Write the clean copy somewhere else
                  --report-dir DIR     Write the report somewhere else
                  --keep-runtime       Leave Reactor's own code in place instead of removing it
                  --rename             Give obfuscated names readable placeholders
                  --fail-on-partial    Write nothing unless every stage fully succeeded
                  --strict             Assume nothing: stop where a normal run would carry on
                  --host-profile FILE  State what the Windows machine the sample expects looks like
                  --library FILE       Let the reader follow calls into this assembly (repeatable)
                  --declarations FILE  Everything above in one file, plus budgets and passes to skip
                  --allow-declared-calls
                                       Let that file also say what calls the tool cannot read do
              -h, --help               Show this
                  --version            Print the version

            When a run stops short it writes reactorunpack/NAME.blockers.json, which names
            each thing that stopped it and the declaration that would get past it. Docs:
            docs/declarations.md

            Development:
              ReactorUnpack corpus run [--manifest PATH] [--samples DIR] [--output DIR] [--strict]

            Docs and issues: https://github.com/jgajek/reactor-unpack
            """);
}
