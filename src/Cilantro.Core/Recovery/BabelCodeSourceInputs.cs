using System.Security.Cryptography;
using Cilantro.Core.Interpretation;

namespace Cilantro.Core.Recovery;

/// <summary>Snapshots explicit method-code inputs before either construction trial begins.</summary>
internal static class BabelCodeSourceInputs
{
    private const string Fact = "babel.methodImages.codeSources";
    internal sealed record Input(string Name, byte[] Bytes, string Sha256);

    internal static void Register(ArtifactContext context, IReadOnlyList<string>? paths)
    {
        if (paths is null || paths.Count == 0) return;
        if (paths.Count > 16) throw new ArgumentException("Supply at most sixteen Babel code-source files.", nameof(paths));
        var files = new List<Input>(); long total = 0;
        foreach (var path in paths)
        {
            var name = Path.GetFileName(path);
            if (!StaticMachineState.ValidCompanionName(name) || files.Any(f => f.Name.Equals(name, StringComparison.OrdinalIgnoreCase)) ||
                name.Equals(Path.GetFileName(context.InputPath), StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Babel code-source file names must be unique safe leaf names distinct from the module.", nameof(paths));
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new ArgumentException("Babel code-source files must be ordinary files, not links.", nameof(paths));
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length is <= 0 or > 16 * 1024 * 1024 || stream.Length > 32 * 1024 * 1024 - total)
                throw new ArgumentException("Babel code sources exceed the per-file or aggregate byte bounds.", nameof(paths));
            var bytes = new byte[(int)stream.Length]; stream.ReadExactly(bytes); total += bytes.Length;
            files.Add(new(name, bytes, Convert.ToHexStringLower(SHA256.HashData(bytes))));
        }
        context.SetFact<IReadOnlyList<Input>>(Fact, files);
        foreach (var file in files)
            context.AddEvidence(new("babel-code-source", $"Explicit data-only companion {file.Name}: {file.Bytes.Length} bytes, SHA-256 {file.Sha256}; mounted beside the analyzed module during Babel method construction."));
    }

    internal static bool Attach(ArtifactContext context, StaticMachineState state)
    {
        if (!context.TryGetFact<IReadOnlyList<Input>>(Fact, out var files) || files is null) return true;
        return files.All(file => state.RegisterCompanionFile(file.Name, file.Bytes));
    }
}
