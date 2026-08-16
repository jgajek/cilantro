using dnlib.DotNet.Emit;
using dnlib.DotNet;

namespace ReactorUnpack.Core.Verification;

public sealed record PlannedMutation(
    string Kind,
    string Location,
    string Description,
    double Confidence);

public sealed record MutationPlan(
    string Pass,
    IReadOnlyList<PlannedMutation> Mutations,
    IReadOnlyList<string> Prerequisites)
{
    public bool MeetsConfidence(double minimum) =>
        Mutations.All(mutation => mutation.Confidence >= minimum);
}

public sealed class InstructionMutationTransaction : IDisposable
{
    private readonly List<(Instruction Instruction, OpCode OpCode, object? Operand)> snapshots = [];
    private bool completed;

    public void Capture(Instruction instruction)
    {
        if (snapshots.Any(snapshot => ReferenceEquals(snapshot.Instruction, instruction)))
            return;
        snapshots.Add((instruction, instruction.OpCode, instruction.Operand));
    }

    public void Commit()
    {
        completed = true;
        snapshots.Clear();
    }

    public void Rollback()
    {
        for (var index = snapshots.Count - 1; index >= 0; index--)
        {
            var snapshot = snapshots[index];
            snapshot.Instruction.OpCode = snapshot.OpCode;
            snapshot.Instruction.Operand = snapshot.Operand;
        }
        snapshots.Clear();
        completed = true;
    }

    public void Dispose()
    {
        if (!completed)
            Rollback();
    }
}

public static class RewritePolicy
{
    public const double MinimumDestructiveConfidence = 0.95;

    public static bool CanRemoveRuntime(
        bool recoveryComplete,
        bool hasRemainingUseSites,
        double confidence) =>
        recoveryComplete &&
        !hasRemainingUseSites &&
        confidence >= MinimumDestructiveConfidence;
}

/// <summary>
/// Declares the identity changes a pass is permitted to make, so the identity gate can stay
/// fail-closed while still allowing proven, opt-in edits.
/// </summary>
/// <remarks>
/// Every set defaults to empty, which reproduces the original strict comparison exactly. A pass
/// that legitimately changes identity (reattaching a decrypted resource, removing a consumed
/// runtime type, renaming an obfuscated symbol) declares precisely what it touched; anything the
/// module changed beyond the declaration still fails verification. Renames are keyed old to new so
/// the gate can confirm the new name is present and the old one is gone.
///
/// Additions are declared the same way as removals and for the same reason. A run that builds a
/// virtualized method back marks it with an attribute of its own, and the type carrying that
/// attribute is a declaration the input did not have; saying so here is what keeps every other
/// unexpected addition a failure.
/// </remarks>
public sealed record RewriteAllowance(
    IReadOnlySet<string>? AddedResources = null,
    IReadOnlySet<string>? RemovedResources = null,
    IReadOnlySet<string>? RemovedPublicApi = null,
    IReadOnlyDictionary<string, string>? RenamedPublicApi = null,
    IReadOnlySet<uint>? RemovedMethodTokens = null,
    int RemovedTypeCount = 0,
    int RemovedFieldCount = 0,
    IReadOnlySet<string>? AddedPublicApi = null,
    IReadOnlySet<uint>? AddedMethodTokens = null,
    int AddedTypeCount = 0)
{
    public static RewriteAllowance None { get; } = new();

    public IReadOnlySet<string> AddedResourceSet =>
        AddedResources ?? System.Collections.Immutable.ImmutableHashSet<string>.Empty;
    public IReadOnlySet<string> RemovedResourceSet =>
        RemovedResources ?? System.Collections.Immutable.ImmutableHashSet<string>.Empty;
    public IReadOnlySet<string> RemovedPublicApiSet =>
        RemovedPublicApi ?? System.Collections.Immutable.ImmutableHashSet<string>.Empty;
    public IReadOnlySet<string> AddedPublicApiSet =>
        AddedPublicApi ?? System.Collections.Immutable.ImmutableHashSet<string>.Empty;
    public IReadOnlyDictionary<string, string> RenamedPublicApiMap =>
        RenamedPublicApi ?? System.Collections.Immutable.ImmutableDictionary<string, string>.Empty;
    public IReadOnlySet<uint> RemovedMethodTokenSet =>
        RemovedMethodTokens ?? System.Collections.Immutable.ImmutableHashSet<uint>.Empty;
    public IReadOnlySet<uint> AddedMethodTokenSet =>
        AddedMethodTokens ?? System.Collections.Immutable.ImmutableHashSet<uint>.Empty;
}

public sealed record ArtifactIdentitySnapshot(
    uint EntryPointToken,
    bool StrongNameSigned,
    IReadOnlyList<string> PublicApi,
    IReadOnlyList<string> ResourceNames)
{
    /// <summary>
    /// The public-API entries a type contributes, including those of its members.
    /// </summary>
    /// <remarks>
    /// Any pass that deletes a declaration has to declare the same entries this snapshot would
    /// have recorded for it, so both come from here rather than from two descriptions that could
    /// drift apart.
    /// </remarks>
    public static IEnumerable<string> PublicApiEntries(TypeDef type)
    {
        if (type.IsPublic || type.IsNestedPublic)
            yield return $"T:{type.FullName}";
        foreach (var method in type.Methods.Where(method => method.IsPublic))
            yield return PublicApiEntry(method);
        foreach (var field in type.Fields.Where(field => field.IsPublic))
            yield return $"F:{field.FullName}";
        foreach (var property in type.Properties.Where(property =>
                     property.GetMethod?.IsPublic == true || property.SetMethod?.IsPublic == true))
        {
            yield return $"P:{property.FullName}";
        }
    }

    public static string PublicApiEntry(MethodDef method) => $"M:{method.FullName}";

    public static ArtifactIdentitySnapshot Capture(ModuleDef module)
    {
        var publicApi = module.GetTypes()
            .SelectMany(PublicApiEntries)
            .Order(StringComparer.Ordinal)
            .ToArray();
        return new ArtifactIdentitySnapshot(
            module.EntryPoint?.MDToken.Raw ?? 0,
            module.IsStrongNameSigned,
            publicApi,
            module.Resources.Select(resource => resource.Name.String)
                .Order(StringComparer.Ordinal)
                .ToArray());
    }
}

/// <summary>
/// A description of a module in terms that survive the metadata writer renumbering rows.
/// </summary>
/// <remarks>
/// Whether the writer produced what was in memory is a different question from whether the
/// transforms changed only what they declared, and it needs a different reference. Metadata tokens
/// answer the second question exactly, since removing one definition does not renumber the others
/// already loaded, but they cannot answer the first: deleting a row forces the writer to renumber
/// everything after it, so tokens legitimately differ between memory and file. Member names and
/// signatures do not, which makes them the durable key for comparing the two.
/// </remarks>
public sealed record ModuleShape(
    string? EntryPoint,
    IReadOnlyList<string> TypeNames,
    IReadOnlyList<string> MethodNames,
    IReadOnlyList<string> ResourceNames,
    int FieldCount)
{
    public static ModuleShape Capture(ModuleDef module)
    {
        var types = module.GetTypes().ToArray();
        return new ModuleShape(
            module.EntryPoint?.FullName,
            types.Select(type => type.FullName).Order(StringComparer.Ordinal).ToArray(),
            types.SelectMany(type => type.Methods)
                .Select(method => method.FullName)
                .Order(StringComparer.Ordinal)
                .ToArray(),
            module.Resources.Select(resource => resource.Name.String)
                .Order(StringComparer.Ordinal)
                .ToArray(),
            types.Sum(type => type.Fields.Count));
    }

    /// <summary>
    /// Describes how <paramref name="actual"/> departs from this shape, naming a few examples of
    /// each difference so a mismatch can be acted on without re-running the comparison by hand.
    /// </summary>
    public IReadOnlyList<string> DifferencesFrom(ModuleShape actual)
    {
        var differences = new List<string>();
        if (!string.Equals(EntryPoint, actual.EntryPoint, StringComparison.Ordinal))
            differences.Add($"Entry point is '{actual.EntryPoint}' but '{EntryPoint}' was expected.");
        if (FieldCount != actual.FieldCount)
            differences.Add($"Field count is {actual.FieldCount} but {FieldCount} was expected.");
        Compare("type", TypeNames, actual.TypeNames);
        Compare("method", MethodNames, actual.MethodNames);
        Compare("resource", ResourceNames, actual.ResourceNames);
        return differences;

        void Compare(string kind, IReadOnlyList<string> expected, IReadOnlyList<string> observed)
        {
            var missing = expected.Except(observed, StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
            var extra = observed.Except(expected, StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
            if (missing.Length != 0)
            {
                differences.Add(
                    $"{missing.Length} {kind}(s) expected but absent, starting with {missing[0]}.");
            }
            if (extra.Length != 0)
                differences.Add($"{extra.Length} unexpected {kind}(s), starting with {extra[0]}.");
            if (missing.Length == 0 && extra.Length == 0 && expected.Count != observed.Count)
                differences.Add($"{kind} count is {observed.Count} but {expected.Count} was expected.");
        }
    }
}

public sealed record ArtifactStructuralSnapshot(
    int TypeCount,
    int MethodCount,
    int FieldCount,
    int ResourceCount,
    IReadOnlyDictionary<uint, uint> MethodRvas,
    IReadOnlyDictionary<uint, int> MethodInstructionCounts)
{
    public static ArtifactStructuralSnapshot Capture(ModuleDef module)
    {
        var types = module.GetTypes().ToArray();
        var methods = types.SelectMany(type => type.Methods).ToArray();
        return new ArtifactStructuralSnapshot(
            types.Length,
            methods.Length,
            types.Sum(type => type.Fields.Count),
            module.Resources.Count,
            methods.ToDictionary(method => method.MDToken.Raw, method => (uint)method.RVA),
            methods.ToDictionary(
                method => method.MDToken.Raw,
                method => method.HasBody ? method.Body.Instructions.Count : -1));
    }
}
