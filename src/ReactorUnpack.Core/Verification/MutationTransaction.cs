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
/// </remarks>
public sealed record RewriteAllowance(
    IReadOnlySet<string>? AddedResources = null,
    IReadOnlySet<string>? RemovedResources = null,
    IReadOnlySet<string>? RemovedPublicApi = null,
    IReadOnlyDictionary<string, string>? RenamedPublicApi = null)
{
    public static RewriteAllowance None { get; } = new();

    public IReadOnlySet<string> AddedResourceSet =>
        AddedResources ?? System.Collections.Immutable.ImmutableHashSet<string>.Empty;
    public IReadOnlySet<string> RemovedResourceSet =>
        RemovedResources ?? System.Collections.Immutable.ImmutableHashSet<string>.Empty;
    public IReadOnlySet<string> RemovedPublicApiSet =>
        RemovedPublicApi ?? System.Collections.Immutable.ImmutableHashSet<string>.Empty;
    public IReadOnlyDictionary<string, string> RenamedPublicApiMap =>
        RenamedPublicApi ?? System.Collections.Immutable.ImmutableDictionary<string, string>.Empty;
}

public sealed record ArtifactIdentitySnapshot(
    uint EntryPointToken,
    bool StrongNameSigned,
    IReadOnlyList<string> PublicApi,
    IReadOnlyList<string> ResourceNames)
{
    public static ArtifactIdentitySnapshot Capture(ModuleDef module)
    {
        var publicApi = module.GetTypes()
            .SelectMany(type =>
            {
                var members = new List<string>();
                if (type.IsPublic || type.IsNestedPublic)
                    members.Add($"T:{type.FullName}");
                members.AddRange(type.Methods.Where(method => method.IsPublic)
                    .Select(method => $"M:{method.FullName}"));
                members.AddRange(type.Fields.Where(field => field.IsPublic)
                    .Select(field => $"F:{field.FullName}"));
                members.AddRange(type.Properties.Where(property =>
                        property.GetMethod?.IsPublic == true || property.SetMethod?.IsPublic == true)
                    .Select(property => $"P:{property.FullName}"));
                return members;
            })
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
