using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using ILVerify;

namespace Cilantro.Tests;

/// <summary>
/// Reads a .NET assembly with Microsoft's own IL verifier and says what it found, per method.
/// </summary>
/// <remarks>
/// CILantro's own verification stage answers a narrower question than this one: it asks whether the
/// members of the file it wrote are the members that were in memory, and whether branch targets and
/// handler boundaries belong to their methods. A body whose stack contradicts itself survives that,
/// and a short branch that no longer reaches its target survived it too. ECMA-335 is what says those
/// are wrong, and ILVerify is what reads ECMA-335, so it is what the corpus is measured against.
///
/// It is used differentially rather than absolutely. Reactor's own output does not verify — the
/// protected samples carry between 186 and 377 findings before CILantro touches them — so "the
/// cleaned copy verifies" is not a claim any run could make. What a run can be held to is that it
/// does not break a method the protector left verifiable, which is a comparison against the input.
/// </remarks>
internal static class IlVerification
{
    /// <summary>
    /// What the verifier found in one file: the findings of each method it could read, and the
    /// methods it could not read at all.
    /// </summary>
    /// <remarks>
    /// A method the verifier cannot import is not a method that failed. Reactor leaves bodies whose
    /// signatures or tokens the importer refuses before it reaches the IL, and a run that turns one
    /// of those into something readable has improved the file even if what becomes readable has
    /// findings of its own. Those methods are kept apart so that neither reading counts as the other.
    /// </remarks>
    public sealed record Reading(
        IReadOnlyDictionary<string, IReadOnlyList<string>> Findings,
        IReadOnlySet<string> Unreadable)
    {
        public int Count => Findings.Sum(entry => entry.Value.Count);

        public IReadOnlySet<string> Codes =>
            Findings.SelectMany(entry => entry.Value).ToHashSet(StringComparer.Ordinal);
    }

    /// <summary>
    /// How one file's findings compare with another's.
    /// </summary>
    public sealed record Difference(
        Reading Was,
        Reading Is,
        IReadOnlySet<string> Mended,
        IReadOnlySet<string> Broken,
        IReadOnlySet<string> Worsened)
    {
        /// <summary>Of the newly broken, the ones the verifier could not read before.</summary>
        public IReadOnlySet<string> BrokenButUnreadableBefore =>
            Broken.Where(Was.Unreadable.Contains).ToHashSet(StringComparer.Ordinal);

        /// <summary>The finding codes that appear on newly broken or worsened methods.</summary>
        public IReadOnlySet<string> Introduced =>
            Broken.Concat(Worsened)
                .SelectMany(method => Is.Findings[method])
                .ToHashSet(StringComparer.Ordinal);

        public string Describe() =>
            $"was {Was.Count} finding(s) over {Was.Findings.Count} method(s), " +
            $"{Was.Unreadable.Count} unreadable; " +
            $"is {Is.Count} over {Is.Findings.Count}, {Is.Unreadable.Count} unreadable; " +
            $"mended {Mended.Count}, broken {Broken.Count}, worsened {Worsened.Count}" +
            (Broken.Count + Worsened.Count == 0
                ? ""
                : "; " + string.Join(", ", Broken.Concat(Worsened).Order(StringComparer.Ordinal)
                    .Select(method => $"{method} [{string.Join(" ", Is.Findings[method])}]")));
    }

    /// <summary>
    /// The .NET Framework 4.8 reference assemblies, from the package that carries them.
    /// </summary>
    /// <remarks>
    /// Baked in at build time by the test project rather than looked for at run time, because a
    /// path found by searching is a path that differs between machines, and a gate that reads
    /// differently on two machines is not a gate. Restore puts them there or the build fails.
    /// </remarks>
    public static string Net48 { get; } = Assembly.GetExecutingAssembly()
        .GetCustomAttributes<AssemblyMetadataAttribute>()
        .Single(attribute => attribute.Key == "Cilantro.ReferenceAssemblies.net48")
        .Value!;

    /// <summary>
    /// Reads one file, resolving references against the reference assemblies, the file's own
    /// directory, and any directories named.
    /// </summary>
    public static Reading Read(string path, params string[] alongside)
    {
        var resolver = new Beside();
        resolver.AddDirectory(Net48);
        resolver.AddDirectory(Path.Combine(Net48, "Facades"));
        foreach (var directory in alongside)
            resolver.AddDirectory(directory);
        resolver.AddDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        resolver.AddFile(path);

        var verifier = new Verifier(resolver, new VerifierOptions { SanityChecks = true });
        verifier.SetSystemModuleName(new AssemblyNameInfo("mscorlib"));

        using var reader = new PEReader(File.OpenRead(path));
        var metadata = reader.GetMetadataReader();
        var findings = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        var unreadable = new HashSet<string>(StringComparer.Ordinal);
        foreach (var handle in metadata.MethodDefinitions)
        {
            var definition = metadata.GetMethodDefinition(handle);
            var declaring = metadata.GetTypeDefinition(definition.GetDeclaringType());
            var method = $"{metadata.GetString(declaring.Name)}::" +
                metadata.GetString(definition.Name);
            try
            {
                foreach (var finding in verifier.Verify(reader, handle))
                {
                    // VerifierError.None is a reference the resolver could not load, which is a
                    // statement about what is beside the file rather than about its IL. A recovered
                    // body reaches references an encrypted one did not, so counting these would
                    // score recovery as damage.
                    if (finding.Code == VerifierError.None)
                        continue;
                    if (!findings.TryGetValue(method, out var said))
                        findings[method] = said = new List<string>();
                    ((List<string>)said).Add(finding.Code.ToString());
                }
            }
            catch (Exception)
            {
                // The importer refused the method before reaching its IL. Not a finding.
                unreadable.Add(method);
            }
        }

        return new Reading(findings, unreadable);
    }

    /// <summary>
    /// Compares what the verifier found in the protected input with what it found in the cleaned
    /// output.
    /// </summary>
    public static Difference Against(Reading was, Reading @is)
    {
        var mended = was.Findings.Keys.Where(method => !@is.Findings.ContainsKey(method));
        var broken = @is.Findings.Keys.Where(method => !was.Findings.ContainsKey(method));
        var worsened = @is.Findings
            .Where(entry => was.Findings.TryGetValue(entry.Key, out var before) &&
                entry.Value.Count > before.Count)
            .Select(entry => entry.Key);
        return new Difference(
            was,
            @is,
            mended.ToHashSet(StringComparer.Ordinal),
            broken.ToHashSet(StringComparer.Ordinal),
            worsened.ToHashSet(StringComparer.Ordinal));
    }

    /// <summary>
    /// Finds an assembly by simple name in the directories it was given, nearest first.
    /// </summary>
    private sealed class Beside : IResolver
    {
        private readonly Dictionary<string, string> paths = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, PEReader> opened =
            new(StringComparer.OrdinalIgnoreCase);

        public void AddDirectory(string directory)
        {
            if (!Directory.Exists(directory))
                return;
            foreach (var file in Directory.EnumerateFiles(directory, "*.dll"))
                paths.TryAdd(Path.GetFileNameWithoutExtension(file), file);
        }

        public void AddFile(string file) =>
            paths[Path.GetFileNameWithoutExtension(file)] = file;

        public PEReader? ResolveAssembly(AssemblyNameInfo name) => Resolve(name.Name);

        public PEReader? ResolveModule(AssemblyNameInfo referencing, string fileName) =>
            Resolve(Path.GetFileNameWithoutExtension(fileName));

        private PEReader? Resolve(string? simpleName)
        {
            if (simpleName is null)
                return null;
            if (opened.TryGetValue(simpleName, out var already))
                return already;
            if (!paths.TryGetValue(simpleName, out var path))
                return null;
            var reader = new PEReader(File.OpenRead(path));
            opened[simpleName] = reader;
            return reader;
        }
    }
}
