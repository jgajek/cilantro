using dnlib.DotNet;
using Cilantro.Core.Analysis;

namespace Cilantro.Core.Recovery;

/// <summary>
/// Replaces namespace names the protector generated, which renaming used to leave alone.
/// </summary>
/// <remarks>
/// Renaming types and members without touching the namespaces around them produced a cleaned copy
/// that read as recovered inside a file that still looked untouched. A decompiler draws namespaces
/// as the top of its tree, so the first thing an analyst saw on opening the result was a list of
/// names like <c>cyLqt16JuLuQiK9Qfv</c> and <c>JQhawTywsS1NVjM0U2D</c> — the same list the
/// protected file showed. More than one person concluded from that screen alone that the tool had
/// not done anything, and they were reading the only evidence in front of them.
///
/// A namespace is not a member, so the discipline is different from the rest of renaming. Nothing
/// resolves a namespace through an object the way dnlib resolves a call site, and a name that is
/// part of the assembly's contract cannot be moved:
///
/// <list type="bullet">
/// <item>a namespace holding anything externally visible is left alone, its name being a contract
/// with whatever references the assembly;</item>
/// <item>a namespace that an embedded resource is named after is left alone, because resource
/// lookup goes by the declaring type's full name and moving the type breaks it silently;</item>
/// <item>a generated segment appearing anywhere ineligible is left alone everywhere, so a namespace
/// and the namespaces nested inside it never disagree about their shared prefix.</item>
/// </list>
///
/// What is left after those three is the protector's own scaffolding, named per distinct segment so
/// that types sharing a prefix go on sharing it.
/// </remarks>
internal static class NamespaceRenaming
{
    /// <summary>Works out which namespaces can be renamed, and to what.</summary>
    internal static IReadOnlyDictionary<string, string> Collect(ModuleDef module)
    {
        ArgumentNullException.ThrowIfNull(module);
        var byNamespace = module.GetTypes()
            .Where(type => !type.IsGlobalModuleType && type.Namespace.String.Length != 0)
            .GroupBy(type => type.Namespace.String, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.Ordinal);

        var resourceNames = module.Resources
            .Select(resource => resource.Name.String)
            .ToArray();

        var eligible = new List<string>();
        var refused = new List<string>();
        foreach (var (name, types) in byNamespace)
        {
            var segments = name.Split('.');
            if (!segments.Any(ReactorNameHeuristics.IsGeneratedName))
                continue;
            if (types.Any(Exported) || resourceNames.Any(resource =>
                    resource.StartsWith($"{name}.", StringComparison.Ordinal)))
            {
                refused.Add(name);
                continue;
            }

            eligible.Add(name);
        }

        // A segment kept anywhere is kept everywhere. Renaming it in one namespace and not in its
        // neighbour would split a shared prefix into two unrelated ones, which is a worse thing to
        // hand a reader than either name on its own.
        var pinned = refused
            .SelectMany(name => name.Split('.'))
            .Where(ReactorNameHeuristics.IsGeneratedName)
            .ToHashSet(StringComparer.Ordinal);

        var replacements = new Dictionary<string, string>(StringComparer.Ordinal);
        var index = 0;
        foreach (var segment in eligible
                     .SelectMany(name => name.Split('.'))
                     .Where(ReactorNameHeuristics.IsGeneratedName)
                     .Where(segment => !pinned.Contains(segment))
                     .Distinct(StringComparer.Ordinal)
                     .OrderBy(segment => segment, StringComparer.Ordinal))
        {
            replacements[segment] = $"GeneratedNamespace_{index++:D4}";
        }

        var renames = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var name in eligible)
        {
            var renamed = string.Join('.', name.Split('.').Select(segment =>
                replacements.TryGetValue(segment, out var replacement) ? replacement : segment));
            if (!string.Equals(renamed, name, StringComparison.Ordinal))
                renames[name] = renamed;
        }

        return renames;
    }

    /// <summary>
    /// Puts the collected namespace names on the types that carry them, and answers with what it
    /// actually changed.
    /// </summary>
    internal static IReadOnlyList<(string Old, string New)> Apply(
        ModuleDef module,
        IReadOnlyDictionary<string, string> renames)
    {
        ArgumentNullException.ThrowIfNull(module);
        ArgumentNullException.ThrowIfNull(renames);
        if (renames.Count == 0)
            return [];

        var applied = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var type in module.GetTypes())
        {
            if (type.IsGlobalModuleType ||
                !renames.TryGetValue(type.Namespace.String, out var renamed))
            {
                continue;
            }

            applied.Add(type.Namespace.String);
            type.Namespace = renamed;
        }

        return [.. applied.Select(name => (name, renames[name]))];
    }

    /// <summary>
    /// Whether anything outside the assembly could be naming this type, and so its namespace.
    /// </summary>
    private static bool Exported(TypeDef type)
    {
        for (var current = type; current is not null; current = current.DeclaringType)
        {
            if (!current.IsPublic && !current.IsNestedPublic && !current.IsNestedFamily)
                return false;
        }

        return true;
    }
}
