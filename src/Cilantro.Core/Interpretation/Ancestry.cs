using dnlib.DotNet;

namespace Cilantro.Core.Interpretation;

/// <summary>
/// Answers whether one type is a kind of another, from the files in hand and the framework.
/// </summary>
/// <remarks>
/// <para>
/// The machine records what an object is by name, and several questions come down to whether one
/// name is under another: a cast, a catch clause, and a program asking a type about itself. All
/// three are the same walk, so they share one, which is what keeps a cast and the reflective
/// question about the same pair of types from disagreeing.
/// </para>
/// <para>
/// The walk crosses out of the supplied files when it has to. A type in the subject can derive from
/// one in a library, and both can derive from one in the framework, so an ancestor that resolves to
/// no definition is compared by name and then asked of the framework this process is running on.
/// Where even that cannot say, the answer is that it does not know, which is different from no: a
/// cast that would have succeeded reported as failing hands back a null that travels far from where
/// the mistake was made.
/// </para>
/// </remarks>
internal static class Ancestry
{
    /// <summary>
    /// Whether <paramref name="actual"/> is <paramref name="expected"/> or something under it.
    /// </summary>
    /// <returns><see langword="null"/> when the hierarchy cannot be read far enough to tell.</returns>
    public static bool? Reaches(
        IEnumerable<ModuleDef> searched,
        ModuleDef? subject,
        string? actual,
        string? expected)
    {
        if (actual is null || expected is null)
            return null;
        if (string.Equals(actual, expected, StringComparison.Ordinal))
            return true;
        if (expected == "System.Object")
            return true;

        // What sits above a constructed generic is what sits above the type it was constructed
        // from, with the arguments carried along. Those arguments only matter when the question is
        // about another constructed generic, and that one is left unanswered rather than compared
        // by a name that would not match even where it should.
        if (expected.Contains('<', StringComparison.Ordinal))
            return null;
        var named = Unconstructed(actual);
        if (named is null)
            return null;

        const int deepEnoughForAnyHierarchy = 64;
        var modules = searched.ToList();
        var start = modules
            .Select(module => module.Find(named, false))
            .FirstOrDefault(found => found is not null);
        if (start is null)
        {
            return LoaderFrameworkIntrinsic.WellKnown(named, subject) is { } present
                ? Framework(present, expected)
                : null;
        }

        var pending = new Queue<TypeDef>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        pending.Enqueue(start);
        var complete = true;
        while (pending.Count != 0 && seen.Count < deepEnoughForAnyHierarchy)
        {
            var type = pending.Dequeue();
            if (!seen.Add(type.FullName))
                continue;
            if (string.Equals(type.FullName, expected, StringComparison.Ordinal))
                return true;
            ITypeDefOrRef?[] above =
                [type.BaseType, .. type.Interfaces.Select(item => item.Interface)];
            foreach (var ancestor in above)
            {
                if (ancestor is null)
                    continue;
                if (string.Equals(ancestor.FullName, expected, StringComparison.Ordinal))
                    return true;
                if (ancestor.ResolveTypeDef() is { } resolved)
                {
                    pending.Enqueue(resolved);
                    continue;
                }

                if (LoaderFrameworkIntrinsic.WellKnown(ancestor.FullName, subject) is not { } known)
                {
                    complete = false;
                    continue;
                }

                if (Framework(known, expected))
                    return true;
            }
        }

        return complete && seen.Count < deepEnoughForAnyHierarchy ? false : null;
    }

    /// <summary>
    /// The type a name denotes with its generic arguments taken off, or the name unchanged.
    /// </summary>
    /// <returns>
    /// <see langword="null"/> when the arguments cannot be removed without changing which type is
    /// named, which is the case for a type nested inside a constructed one.
    /// </returns>
    private static string? Unconstructed(string name)
    {
        var at = name.IndexOf('<', StringComparison.Ordinal);
        if (at < 0)
            return name;
        return name.IndexOf('/', at) < 0 ? name[..at] : null;
    }

    /// <summary>
    /// Whether a type the framework in hand has sits under a named type.
    /// </summary>
    private static bool Framework(Type present, string expected)
    {
        for (var above = present; above is not null; above = above.BaseType)
        {
            if (string.Equals(above.FullName, expected, StringComparison.Ordinal))
                return true;
        }

        return present.GetInterfaces()
            .Any(contract => string.Equals(contract.FullName, expected, StringComparison.Ordinal));
    }
}
