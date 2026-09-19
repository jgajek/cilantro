using System.Collections.ObjectModel;
using System.Security.Cryptography;
using dnlib.DotNet;
using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;

namespace Cilantro.Core;

/// <summary>Raised when an assembly offered to the interpreter cannot be trusted as given.</summary>
public sealed class TrustedLibraryException : Exception
{
    public TrustedLibraryException()
    {
    }

    public TrustedLibraryException(string message) : base(message)
    {
    }

    public TrustedLibraryException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// An assembly of somebody else's that the interpreter is allowed to run the IL of.
/// </summary>
/// <remarks>
/// Interpreting a library is not the same kind of act as interpreting the sample. The sample is the
/// thing under examination and nothing about it is taken on trust; a library is a known quantity
/// whose behaviour is not in question, supplied because the sample calls into it and the call cannot
/// otherwise be followed. What is recorded here is the identity of the file that was supplied, so
/// that a reader can tell which build of it the result depended on and fetch the same one.
/// </remarks>
public sealed record TrustedLibrary(
    string Path,
    string Name,
    string Version,
    string PublicKeyToken,
    string Sha256,
    bool MatchesReference);

public sealed class ArtifactContext : IDisposable
{
    private readonly List<Evidence> _evidence = [];
    private readonly List<ChangeRecord> _changes = [];
    private readonly List<PassResult> _passResults = [];
    private readonly Dictionary<string, object> _facts = new(StringComparer.Ordinal);
    private readonly List<ModuleDefMD> _trustedModules = [];

    private ArtifactContext(string inputPath, byte[] originalBytes, ModuleDefMD module)
    {
        InputPath = inputPath;
        OriginalBytes = originalBytes;
        OriginalSha256 = Convert.ToHexStringLower(SHA256.HashData(originalBytes));
        Module = module;
        OriginalImage = new PeImageView(originalBytes);
        OriginalIdentity = ArtifactIdentitySnapshot.Capture(module);
        OriginalStructure = ArtifactStructuralSnapshot.Capture(module);
    }

    public string InputPath { get; }
    public byte[] OriginalBytes { get; }
    public string OriginalSha256 { get; }
    public ModuleDefMD Module { get; }
    public PeImageView OriginalImage { get; }
    public ArtifactIdentitySnapshot OriginalIdentity { get; }
    public ArtifactStructuralSnapshot OriginalStructure { get; }
    public IReadOnlyList<Evidence> Evidence => new ReadOnlyCollection<Evidence>(_evidence);
    public IReadOnlyList<ChangeRecord> Changes => new ReadOnlyCollection<ChangeRecord>(_changes);
    public IReadOnlyList<PassResult> PassResults => new ReadOnlyCollection<PassResult>(_passResults);

    /// <summary>The assemblies the interpreter may run the IL of besides the sample itself.</summary>
    public IReadOnlyList<TrustedLibrary> Libraries { get; private set; } = [];

    /// <summary>The metadata of those assemblies, which is what the machine is handed.</summary>
    public IReadOnlyList<ModuleDefMD> TrustedModules =>
        new ReadOnlyCollection<ModuleDefMD>(_trustedModules);

    public static ArtifactContext Load(string path, IReadOnlyList<string>? libraryPaths = null)
    {
        var fullPath = Path.GetFullPath(path);
        var bytes = File.ReadAllBytes(fullPath);
        // One resolution context for the sample and everything supplied alongside it, because a
        // reference from the sample into a library only resolves to a body the machine can run if
        // both of them were read by the same resolver.
        var resolution = ModuleDef.CreateModuleContext();
        var options = new ModuleCreationOptions
        {
            TryToLoadPdbFromDisk = false,
            Context = resolution
        };
        var module = ModuleDefMD.Load(bytes, options);
        var context = new ArtifactContext(fullPath, bytes, module);
        if (libraryPaths is { Count: > 0 })
            context.LoadLibraries(libraryPaths, resolution, options);
        return context;
    }

    private void LoadLibraries(
        IReadOnlyList<string> paths,
        ModuleContext resolution,
        ModuleCreationOptions options)
    {
        if (resolution.AssemblyResolver is not AssemblyResolver resolver)
            throw new TrustedLibraryException(
                "The resolver cannot be told about a library, so none can be trusted.");
        var referenced = Module.GetAssemblyRefs()
            .GroupBy(reference => reference.Name.String, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);
        var loaded = new List<TrustedLibrary>();
        foreach (var path in paths)
        {
            var full = Path.GetFullPath(path);
            if (!File.Exists(full))
                throw new TrustedLibraryException($"No such library: {path}");
            var bytes = File.ReadAllBytes(full);
            ModuleDefMD library;
            try
            {
                library = ModuleDefMD.Load(bytes, options);
            }
            catch (BadImageFormatException ex)
            {
                throw new TrustedLibraryException(
                    $"{Path.GetFileName(full)} is not a .NET assembly, so there is no IL in it " +
                    "to interpret.",
                    ex);
            }

            var assembly = library.Assembly;
            if (assembly is null)
            {
                library.Dispose();
                throw new TrustedLibraryException(
                    $"{Path.GetFileName(full)} is a module rather than an assembly.");
            }

            // A library the sample never mentions cannot be the one it calls into, so accepting it
            // would widen what the machine may run without widening what it can read. Saying so is
            // more useful than silently loading a file that will never be reached.
            if (!referenced.TryGetValue(assembly.Name.String, out var reference))
            {
                // The versions are listed too, because the reader of this message is deciding which
                // file to go and find.
                var names = string.Join(", ", referenced.Values
                    .Select(candidate => $"{candidate.Name} {candidate.Version}")
                    .Order(StringComparer.Ordinal));
                library.Dispose();
                throw new TrustedLibraryException(
                    $"{assembly.Name} is not referenced by {Module.Name}, which references: " +
                    $"{names}.");
            }

            resolver.AddToCache(assembly);
            _trustedModules.Add(library);
            loaded.Add(new TrustedLibrary(
                full,
                assembly.Name,
                assembly.Version.ToString(),
                Convert.ToHexStringLower(assembly.PublicKeyToken?.Data ?? []),
                Convert.ToHexStringLower(SHA256.HashData(bytes)),
                assembly.Version == reference.Version));
        }

        Libraries = loaded;
    }

    public void AddEvidence(Evidence evidence) => _evidence.Add(evidence);
    public void AddChange(ChangeRecord change) => _changes.Add(change);
    internal void AddPassResult(PassResult result) => _passResults.Add(result);
    public void SetFact<T>(string key, T value) where T : notnull => _facts[key] = value;
    public bool TryGetFact<T>(string key, out T? value)
    {
        if (_facts.TryGetValue(key, out var raw) && raw is T typed)
        {
            value = typed;
            return true;
        }

        value = default;
        return false;
    }

    public void Dispose()
    {
        Module.Dispose();
        foreach (var library in _trustedModules)
            library.Dispose();
    }
}
