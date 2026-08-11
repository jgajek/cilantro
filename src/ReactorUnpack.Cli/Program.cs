using ReactorUnpack.Core;
using ReactorUnpack.Core.Corpus;

return await ReactorCommand.RunAsync(args);

internal static class ReactorCommand
{
    public static Task<int> RunAsync(string[] args)
    {
        if (args.Length >= 2 && args[0] == "corpus" && args[1] == "run")
        {
            return Task.FromResult(RunCorpus(args[2..]));
        }

        if (args.Length == 0 || args.Any(argument => argument is "-h" or "--help"))
        {
            PrintUsage();
            return Task.FromResult(args.Length == 0 ? 2 : 0);
        }

        var analyzeOnly = false;
        var failOnPartial = false;
        var removeRuntime = false;
        var renameSymbols = false;
        string? output = null;
        string? reportDirectory = null;
        string? input = null;

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
                case "--rename":
                    renameSymbols = true;
                    break;
                case "-o":
                case "--output":
                    output = RequireValue(args, ref index);
                    break;
                case "--report-dir":
                    reportDirectory = RequireValue(args, ref index);
                    break;
                default:
                    if (args[index].Length > 0 && args[index][0] == '-')
                    {
                        return Task.FromResult(Fail($"Unknown option: {args[index]}"));
                    }

                    if (input is not null)
                    {
                        return Task.FromResult(Fail("Only one input assembly can be processed at a time."));
                    }

                    input = args[index];
                    break;
            }
        }

        if (input is null)
        {
            return Task.FromResult(Fail("An input assembly is required."));
        }

        if (!File.Exists(input))
        {
            return Task.FromResult(Fail($"Input does not exist: {input}"));
        }

        try
        {
            var pipeline = new ReactorPipeline();
            var result = pipeline.Run(input, new PipelineOptions(
                AnalyzeOnly: analyzeOnly,
                PreserveTokens: true,
                FailOnPartial: failOnPartial,
                RemoveRuntime: removeRuntime,
                RenameSymbols: renameSymbols,
                OutputPath: output,
                ReportDirectory: reportDirectory));

            Console.WriteLine($"Input:    {result.Report.InputSha256}");
            Console.WriteLine($"Analysis: {result.AnalysisReportPath}");
            Console.WriteLine($"Changes:  {result.ChangesReportPath}");
            Console.WriteLine(result.OutputPath is null
                ? "Output:   not emitted (analysis-only or verification gate)"
                : $"Output:   {result.OutputPath}");
            foreach (var payloadPath in result.ExtractedPayloadPaths)
            {
                Console.WriteLine($"Payload:  {payloadPath}");
            }

            foreach (var pass in result.Report.Passes)
            {
                Console.WriteLine($"[{pass.Status.ToString().ToLowerInvariant(),-11}] {pass.Pass}: {pass.Changes} changes");
                foreach (var diagnostic in pass.Diagnostics)
                {
                    Console.WriteLine($"              {diagnostic}");
                }
            }

            if (!result.Report.VerificationPassed)
            {
                foreach (var diagnostic in result.Report.VerificationDiagnostics)
                {
                    Console.Error.WriteLine($"verify: {diagnostic}");
                }
            }

            return Task.FromResult(result.Success ? 0 : 1);
        }
        catch (Exception ex)
        {
            return Task.FromResult(Fail($"{ex.GetType().Name}: {ex.Message}"));
        }
    }

    private static string RequireValue(string[] args, ref int index)
    {
        if (++index >= args.Length)
        {
            throw new ArgumentException($"Missing value for {args[index - 1]}.");
        }

        return args[index];
    }

    private static int Fail(string message)
    {
        Console.Error.WriteLine($"error: {message}");
        Console.Error.WriteLine("Use --help for usage.");
        return 2;
    }

    private static int RunCorpus(string[] args)
    {
        var manifest = "corpus/reactor-6-nonvirt.manifest.json";
        var samples = "samples";
        var output = "artifacts/corpus";
        try
        {
            for (var index = 0; index < args.Length; index++)
            {
                switch (args[index])
                {
                    case "--manifest":
                        manifest = RequireValue(args, ref index);
                        break;
                    case "--samples":
                        samples = RequireValue(args, ref index);
                        break;
                    case "--output":
                        output = RequireValue(args, ref index);
                        break;
                    default:
                        return Fail($"Unknown corpus option: {args[index]}");
                }
            }

            var report = CorpusRunner.Run(manifest, samples, output);
            Console.WriteLine($"Corpus:  {Path.GetFullPath(manifest)}");
            Console.WriteLine($"Results: {Path.GetFullPath(Path.Combine(output, "corpus.outcomes.json"))}");
            Console.WriteLine($"Passed: {report.Passed}; failed: {report.Failed}; missing: {report.Missing}");
            return report.Failed == 0 && report.Missing == 0 ? 0 : 1;
        }
        catch (Exception ex)
        {
            return Fail($"{ex.GetType().Name}: {ex.Message}");
        }
    }

    private static void PrintUsage()
    {
        Console.WriteLine(
            """
            ReactorUnpack - safe, static-first .NET Reactor analysis and deobfuscation

            Usage:
              ReactorUnpack <assembly> [options]
              ReactorUnpack corpus run [--manifest PATH] [--samples DIR] [--output DIR]

            Options:
              --analyze-only       Produce reports without writing a transformed assembly
              --fail-on-partial    Refuse output when any pass is incomplete
              --remove-runtime     Delete proven-dead Reactor runtime types (opt-in, destructive)
              --rename             Rename proven Reactor-generated non-public symbols (opt-in)
              -o, --output PATH    Select the cleaned assembly path
              --report-dir DIR     Select the JSON report directory
              -h, --help           Show this help

            Corpus options:
              --manifest PATH      Corpus manifest (default: corpus/reactor-6-nonvirt.manifest.json)
              --samples DIR        Hash-verified binary directory (default: samples)
              --output DIR         Normalized report directory (default: artifacts/corpus)
            """);
    }
}
