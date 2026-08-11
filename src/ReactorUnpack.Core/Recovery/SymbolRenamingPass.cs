using dnlib.DotNet;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Verification;

namespace ReactorUnpack.Core.Recovery;

/// <summary>
/// Opt-in deterministic renaming of Reactor's machine-generated symbols.
/// </summary>
/// <remarks>
/// Renaming is reference-safe within a module because dnlib resolves call sites, overrides, and
/// interface implementations through the member object rather than its name. The risk is elsewhere:
/// implicit virtual-override and interface-implementation matching is by name and signature, native
/// entry points are keyed by name, and public API is a contract. This pass therefore renames only
/// non-public, non-virtual, non-P/Invoke members whose names it can structurally prove are
/// generated. Renaming a non-public type can still cascade into the full names of public members it
/// declares or that reference it, so the pass measures the public-API set before and after and
/// declares that exact delta to the identity gate, which still fails on anything undeclared. It
/// writes an old-to-new map for auditing and runs solely under <c>--rename</c>.
/// </remarks>
public sealed class SymbolRenamingPass : DeobfuscationPass
{
    public override string Name => "symbol-renaming";
    public override IReadOnlyCollection<string> Dependencies => ["runtime-cleanup"];

    private sealed record RenameTarget(string OldKey, IMemberDef Member, string NewName);

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("options.renameSymbols", out var enabled) || !enabled)
            return (PassStatus.Success, 0, ["Symbol renaming is opt-in; skipped without --rename."]);

        var beforeApi = ArtifactIdentitySnapshot.Capture(context.Module).PublicApi
            .ToHashSet(StringComparer.Ordinal);
        var targets = CollectTargets(context.Module);
        if (targets.Count == 0)
            return (PassStatus.Success, 0, ["No provably generated symbols were found."]);

        var map = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var target in targets)
        {
            target.Member.Name = target.NewName;
            map[target.OldKey] = KeyFor(target.Member);
            context.AddChange(new ChangeRecord(
                Name, "rename-generated-symbol", target.OldKey,
                "Renamed a proven Reactor-generated symbol."));
        }

        var afterApi = ArtifactIdentitySnapshot.Capture(context.Module).PublicApi
            .ToHashSet(StringComparer.Ordinal);
        var removedApi = new HashSet<string>(beforeApi, StringComparer.Ordinal);
        removedApi.ExceptWith(afterApi);
        var addedApi = new HashSet<string>(afterApi, StringComparer.Ordinal);
        addedApi.ExceptWith(beforeApi);

        context.SetFact<IReadOnlyDictionary<string, string>>("rename.map", map);
        if (removedApi.Count != 0)
            context.SetFact<IReadOnlySet<string>>("rename.removedPublicApi", removedApi);
        if (addedApi.Count != 0)
            context.SetFact<IReadOnlySet<string>>("rename.addedPublicApi", addedApi);

        var apiNote = removedApi.Count == 0
            ? "public API unchanged"
            : $"{removedApi.Count} public-API name(s) changed and declared";
        return (PassStatus.Success, map.Count,
            [$"Renamed {map.Count} generated symbols; {apiNote}."]);
    }

    /// <summary>
    /// Gathers every rename to perform, capturing each old key before any name is changed so the map
    /// and change records reflect a consistent pre-rename state.
    /// </summary>
    private static List<RenameTarget> CollectTargets(ModuleDef module)
    {
        var targets = new List<RenameTarget>();
        var types = module.GetTypes()
            .Where(type => type.Name != "<Module>")
            .OrderBy(type => type.MDToken.Raw)
            .ToArray();

        var typeIndex = 0;
        foreach (var type in types)
        {
            if (IsRenamableType(type) && ReactorNameHeuristics.IsGeneratedName(type.Name))
                targets.Add(new RenameTarget(KeyFor(type), type, $"ReactorType_{typeIndex++:D4}"));
        }

        var memberIndex = 0;
        foreach (var type in types)
        {
            var used = new HashSet<string>(
                type.Fields.Select(field => field.Name.String)
                    .Concat(type.Methods.Select(method => method.Name.String)),
                StringComparer.Ordinal);
            foreach (var field in type.Fields.OrderBy(field => field.MDToken.Raw))
            {
                if (IsRenamableField(type, field) && ReactorNameHeuristics.IsGeneratedName(field.Name))
                    targets.Add(new RenameTarget(
                        KeyFor(field), field, UniqueName($"reactorField_{memberIndex++:D4}", used)));
            }
            foreach (var method in type.Methods.OrderBy(method => method.MDToken.Raw))
            {
                if (IsRenamableMethod(method) && ReactorNameHeuristics.IsGeneratedName(method.Name))
                    targets.Add(new RenameTarget(
                        KeyFor(method), method, UniqueName($"reactorMethod_{memberIndex++:D4}", used)));
            }
        }

        return targets;
    }

    private static string KeyFor(IMemberDef member) => member switch
    {
        TypeDef type => $"T:{type.FullName}",
        MethodDef method => $"M:{method.FullName}",
        FieldDef field => $"F:{field.FullName}",
        _ => member.FullName
    };

    private static bool IsRenamableType(TypeDef type) =>
        !type.IsPublic && !type.IsNestedPublic && !type.IsGlobalModuleType;

    private static bool IsRenamableField(TypeDef declaringType, FieldDef field) =>
        !field.IsPublic &&
        !declaringType.IsEnum &&
        !HasSerializableContract(declaringType);

    private static bool IsRenamableMethod(MethodDef method) =>
        !method.IsPublic &&
        !method.IsVirtual &&
        !method.IsPinvokeImpl &&
        !method.IsConstructor &&
        !method.IsStaticConstructor &&
        method.Overrides.Count == 0;

    private static bool HasSerializableContract(TypeDef type) =>
        type.IsSerializable ||
        type.CustomAttributes.Any(attribute =>
            attribute.AttributeType?.Name.String is "DataContractAttribute" or "SerializableAttribute");

    private static string UniqueName(string preferred, HashSet<string> used)
    {
        var name = preferred;
        var suffix = 0;
        while (!used.Add(name))
            name = $"{preferred}_{suffix++}";
        return name;
    }
}
