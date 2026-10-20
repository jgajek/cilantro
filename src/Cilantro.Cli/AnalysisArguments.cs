using Cilantro.Core;

namespace Cilantro.Cli;

/// <summary>The analyst CLI policy; core and MCP callers retain their independent defaults.</summary>
internal sealed class AnalysisArguments
{
    internal string? Input { get; private set; }
    internal bool Help { get; private set; }
    internal bool HelpAll { get; private set; }
    internal bool Version { get; private set; }
    internal bool Verbose { get; private set; }
    internal bool Json { get; private set; }
    internal bool NoColor { get; private set; }
    internal bool AnalyzeOnly { get; private set; }
    internal bool Strict { get; private set; }
    private string? OutputDirectory { get; set; }
    private bool Recurse { get; set; } = true;
    private bool RemoveRuntime { get; set; } = true;
    private bool? Rename { get; set; }
    private bool? Devirtualize { get; set; }
    private bool Generic { get; set; }
    private bool FailOnPartial { get; set; }
    private string? Profile { get; set; }
    private string? Declarations { get; set; }
    private string? References { get; set; }
    private bool AllowDeclaredCalls { get; set; }
    private List<string> Libraries { get; } = [];
    private List<string> SigningKeys { get; } = [];
    private List<string> BabelCodeSources { get; } = [];

    internal static AnalysisArguments Parse(string[] args)
    {
        var parsed = new AnalysisArguments();
        var positional = false;
        for (var index = 0; index < args.Length; index++)
        {
            var argument = args[index];
            if (positional || !argument.StartsWith('-') && argument != "/?")
            {
                if (parsed.Input is not null) throw new ArgumentException("Give one input file at a time.");
                parsed.Input = argument;
                continue;
            }
            if (argument == "--") { positional = true; continue; }
            var equals = argument.IndexOf('=');
            var option = equals >= 0 ? argument[..equals] : argument;
            var inline = equals >= 0 ? argument[(equals + 1)..] : null;
            if (inline is not null && option is not ("-o" or "--output" or "--host-profile" or
                "--library" or "--declarations" or "--reviewed-dependencies" or "--signing-key" or "--babel-code-source"))
                throw new ArgumentException($"{option} does not take a value.");

            switch (option)
            {
                case "-h": case "--help": case "/?": parsed.Help = true; break;
                case "--help-all": parsed.HelpAll = true; break;
                case "--version": parsed.Version = true; break;
                case "-v": case "--verbose": parsed.Verbose = true; break;
                case "--json": parsed.Json = true; break;
                case "--no-color": parsed.NoColor = true; break;
                case "--analyze-only": parsed.AnalyzeOnly = true; break;
                case "--strict": parsed.Strict = true; break;
                case "-o": case "--output": parsed.OutputDirectory = Value(); break;
                case "--no-recursion": parsed.Recurse = false; break;
                case "--keep-runtime": parsed.RemoveRuntime = false; break;
                case "--keep-names": parsed.Rename = false; break;
                case "--no-devirtualize": parsed.Devirtualize = false; break;
                case "--generic-recovery": parsed.Generic = true; break;
                case "--fail-on-partial": parsed.FailOnPartial = true; break;
                case "--host-profile": parsed.Profile = Value(); break;
                case "--library": parsed.Libraries.Add(Value()); break;
                case "--signing-key": parsed.SigningKeys.Add(Value()); break;
                case "--babel-code-source": parsed.BabelCodeSources.Add(Value()); break;
                case "--declarations": parsed.Declarations = Value(); break;
                case "--reviewed-dependencies": parsed.References = Value(); break;
                case "--allow-declared-calls": parsed.AllowDeclaredCalls = true; break;
                default: throw new ArgumentException($"Unknown option: {option}. Use --help-all for specialist controls.");
            }

            string Value()
            {
                if (inline is not null)
                {
                    if (inline.Length > 0) return inline;
                }
                else if (index + 1 < args.Length && !args[index + 1].StartsWith('-'))
                    return args[++index];
                throw new ArgumentException($"{option} needs a path after it.");
            }
        }
        return parsed;
    }

    internal PipelineOptions PreparePipelineOptions()
    {
        if (Input is null) throw new ArgumentException("Give the protected .NET file to analyze: cilantro sample.exe");
        if (Directory.Exists(Input)) throw new ArgumentException($"Input must be a file: {Input}");
        if (!File.Exists(Input)) throw new ArgumentException($"No such file: {Input}");
        if (References is not null && !Recurse)
            throw new ArgumentException("--reviewed-dependencies cannot be combined with --no-recursion.");
        if (AllowDeclaredCalls && Declarations is null)
            throw new ArgumentException("--allow-declared-calls requires --declarations FILE.");
        foreach (var key in SigningKeys)
            if (!File.Exists(key)) throw new ArgumentException($"No such strong-name key file: {key}");
        foreach (var file in BabelCodeSources)
            if (!File.Exists(file)) throw new ArgumentException($"No such Babel code-source file: {file}");
        var input = Path.GetFullPath(Input);
        var stem = Path.GetFileNameWithoutExtension(input);
        var directory = OutputDirectory is null
            ? NextCaseDirectory(Path.Combine(Path.GetDirectoryName(input)!, stem + ".cilantro"))
            : Path.GetFullPath(OutputDirectory);
        if (File.Exists(directory)) throw new ArgumentException($"Output must be a folder, not a file: {directory}");
        if (Directory.Exists(directory) && Directory.EnumerateFileSystemEntries(directory).Any())
            throw new ArgumentException($"Output folder is not empty: {directory}. Choose a fresh folder with -o DIR.");

        return new PipelineOptions(
            AnalyzeOnly: AnalyzeOnly,
            FailOnPartial: FailOnPartial,
            RemoveRuntime: RemoveRuntime,
            RenameSymbols: Rename,
            OutputPath: Path.Combine(directory, stem + ".cleaned" + Path.GetExtension(input)),
            ReportDirectory: directory,
            HostProfilePath: Profile,
            LibraryPaths: Libraries,
            DeclarationsPath: Declarations,
            AllowDeclaredCalls: AllowDeclaredCalls,
            Strict: Strict,
            Devirtualize: Devirtualize,
            StatusPath: RunStatus.PathFor(input, directory),
            GenericRecovery: Generic,
            RecoverEmbeddedAssemblies: Recurse,
            ReviewedDependencyManifest: References)
        { StrongNameKeyFiles = SigningKeys.Select(Path.GetFullPath).ToArray(), BabelCodeSourceFiles = BabelCodeSources.Select(Path.GetFullPath).ToArray() };
    }

    private static string NextCaseDirectory(string path)
    {
        var candidate = path;
        for (var trial = 2; Directory.Exists(candidate) || File.Exists(candidate); trial++)
            candidate = $"{path}-{trial}";
        return candidate;
    }
}
