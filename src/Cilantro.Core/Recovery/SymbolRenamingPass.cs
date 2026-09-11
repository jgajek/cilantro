using dnlib.DotNet;
using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Recovery;

/// <summary>
/// Deterministic renaming of Reactor's machine-generated symbols, done on a triage run.
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
/// writes an old-to-new map for auditing, and a strict run leaves the names alone.
/// </remarks>
public sealed class SymbolRenamingPass : DeobfuscationPass
{
    public override string Name => "symbol-renaming";
    public override IReadOnlyCollection<string> Dependencies => ["runtime-cleanup"];

    private sealed record RenameTarget(
        string OldKey,
        IMemberDef Member,
        string NewName,
        bool FromBehaviour = false);

    protected override (PassStatus Status, int Changes, IReadOnlyList<string> Diagnostics) Execute(
        ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("options.renameSymbols", out var enabled) || !enabled)
            return (PassStatus.Success, 0, ["Names were left as they are, this run not renaming."]);

        var beforeApi = ArtifactIdentitySnapshot.Capture(context.Module).PublicApi
            .ToHashSet(StringComparer.Ordinal);
        // Both are gathered before anything is renamed, so every old key is the name the file
        // shipped with rather than one a rename earlier in the list has already changed.
        var namespaces = NamespaceRenaming.Collect(context.Module);
        var targets = CollectTargets(context.Module, RebuiltMethods.Of(context));
        if (targets.Count == 0 && namespaces.Count == 0)
            return (PassStatus.Success, 0, ["No provably generated symbols were found."]);

        var map = new SortedDictionary<string, string>(StringComparer.Ordinal);
        // Namespaces go first because a member's new key spells out the type that declares it, and
        // that spelling includes the namespace: renaming them afterwards would leave the map
        // pointing at names the cleaned copy does not have.
        foreach (var (old, renamed) in NamespaceRenaming.Apply(context.Module, namespaces))
        {
            map[$"N:{old}"] = $"N:{renamed}";
            context.AddChange(new ChangeRecord(
                Name, "rename-generated-namespace", $"N:{old}",
                "Renamed a namespace whose name the protector generated."));
        }

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
        var named = targets.Count(target => target.FromBehaviour);
        var behaviourNote = named == 0
            ? string.Empty
            : $" {named} of them are named for what they do rather than numbered.";
        return (PassStatus.Success, map.Count,
            [$"Renamed {map.Count} generated symbols; {apiNote}.{behaviourNote}"]);
    }

    /// <summary>
    /// Gathers every rename to perform, capturing each old key before any name is changed so the map
    /// and change records reflect a consistent pre-rename state.
    /// </summary>
    private static List<RenameTarget> CollectTargets(
        ModuleDef module,
        IReadOnlyList<MethodDef> rebuilt)
    {
        var targets = new List<RenameTarget>();
        var fromVirtualization = rebuilt.Select(method => method.MDToken.Raw).ToHashSet();
        var types = module.GetTypes()
            .Where(type => type.Name != "<Module>")
            .OrderBy(type => type.MDToken.Raw)
            .ToArray();

        var typeIndex = 0;
        foreach (var type in types)
        {
            if (IsRenamableType(type) && ReactorNameHeuristics.IsGeneratedName(type.Name))
                targets.Add(new RenameTarget(KeyFor(type), type, $"{Kind(type)}_{typeIndex++:D4}"));
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
                if (!IsRenamableField(type, field) ||
                    !ReactorNameHeuristics.IsGeneratedName(field.Name))
                {
                    continue;
                }

                var held = Held(field);
                targets.Add(new RenameTarget(
                    KeyFor(field),
                    field,
                    UniqueName($"{held ?? "generated"}Field_{memberIndex++:D4}", used),
                    held is not null));
            }
            foreach (var method in type.Methods.OrderBy(method => method.MDToken.Raw))
            {
                if (!IsRenamableMethod(method) ||
                    !ReactorNameHeuristics.IsGeneratedName(method.Name))
                {
                    continue;
                }

                var behaviour = fromVirtualization.Contains(method.MDToken.Raw)
                    ? Rebuilt(method, module)
                    : Does(method, module);
                targets.Add(new RenameTarget(
                    KeyFor(method),
                    method,
                    UniqueName(behaviour ?? $"generatedMethod_{memberIndex++:D4}", used),
                    behaviour is not null));
            }
        }

        return targets;
    }

    /// <summary>
    /// Names a body built back from a virtualized method after the framework it provably reaches.
    /// </summary>
    /// <remarks>
    /// These are the methods a reader most needs to find and the ones a number hides worst. A
    /// rebuilt body is long, it is the only thing in the file that was read rather than recovered,
    /// and what it does is usually the point of the sample — so <c>generatedMethod_0075</c> is the
    /// name on the one method somebody opened the file to read.
    ///
    /// The name says two things and claims nothing beyond them: that the body was rebuilt from a
    /// virtual machine rather than found, and which families of framework API it reaches. Both are
    /// facts already established — the first by the rebuild, the second by the same walk that
    /// writes the account onto the method. The families are deliberately coarse and the name stops
    /// at two of them, because a name is not the place to say what a method is for: the account the
    /// decompiler prints above it lists every member by name, and guessing a purpose in the
    /// identifier would put an interpretation somewhere a reader cannot see it was one.
    /// </remarks>
    private static string? Rebuilt(MethodDef method, ModuleDef module)
    {
        var reaches = MethodBehaviour.Reached(method, module).Reaches;
        if (reaches.Count == 0)
            return "RebuiltFromVirtualMachine";

        var families = Families
            .Where(family => reaches.Any(reached =>
                family.Members.Any(member =>
                    reached.Contains(member, StringComparison.Ordinal))))
            .Take(2)
            .Select(family => family.Name)
            .ToArray();
        return families.Length == 0
            ? "RebuiltFromVirtualMachine"
            : $"RebuiltFromVirtualMachine{string.Concat(families)}";
    }

    /// <summary>
    /// Coarse families of framework API, in the order a reader would want to be told about them.
    /// Matching is on the type name a reached member is spelled with, which is what survives a
    /// protector: it renames what it generates and cannot rename the framework.
    /// </summary>
    private static readonly (string Name, string[] Members)[] Families =
    [
        ("Cryptography", [
            "Aes", "Rijndael", "DES", "RC2", "MD5", "SHA1", "SHA256", "SHA512", "RSA",
            "CryptoStream", "CryptoConfig", "ICryptoTransform", "HashAlgorithm",
            "SymmetricAlgorithm", "AsymmetricAlgorithm"
        ]),
        ("Network", [
            "WebClient", "HttpClient", "WebRequest", "WebResponse", "Socket", "TcpClient",
            "Dns", "HttpWebRequest"
        ]),
        ("Process", ["Process.", "new Process", "ProcessStartInfo"]),
        ("Registry", ["Registry", "RegistryKey"]),
        ("Reflection", [
            "Assembly", "AppDomain", "Activator", "MethodInfo", "MethodBase", "ConstructorInfo",
            "Module.", "Type.GetType", "ObjectHandle"
        ]),
        ("Files", [
            "File.", "Directory", "FileStream", "FileInfo", "Path.", "DriveInfo"
        ]),
        ("Streams", [
            "Stream", "BinaryReader", "BinaryWriter", "StreamReader", "StreamWriter",
            "MemoryStream", "Encoding"
        ])
    ];

    /// <summary>
    /// Names a method after what its body does, where its body does one thing.
    /// </summary>
    /// <remarks>
    /// Two shapes account for most of what a Reactor build generates, and both are worth naming.
    /// The first is the forwarder: one static method per framework member, holding a cast and a
    /// call, left behind wherever a delegate proxy used to dispatch. After proxy restoration those
    /// are what the recovered call sites point at, so a body reading as a hundred calls to
    /// <c>generatedMethod_0101</c> is a hundred calls to <c>CreateDecryptor</c> — and the number
    /// was the only thing hiding it. The second is the opaque predicate: a helper that returns the
    /// same value every time, called where a condition belongs. Saying <c>AlwaysTrue</c> tells a
    /// reader to stop looking at it, which is the entire content of the thing.
    ///
    /// Where the body does more than one thing, no name is offered. A summary of part of a method is
    /// worse than a number, because a number does not claim anything.
    /// </remarks>
    private static string? Does(MethodDef method, ModuleDef module)
    {
        if (MethodBehaviour.AsConstant(method) is { } constant)
        {
            return constant switch
            {
                MethodBehaviour.Constant.True => "AlwaysTrue",
                MethodBehaviour.Constant.False => "AlwaysFalse",
                MethodBehaviour.Constant.Null => "AlwaysNull",
                _ => null
            };
        }

        if (!MethodBehaviour.TryReadForwarder(method, out var called) ||
            called is null ||
            !MethodBehaviour.IsForeign(called, module))
        {
            // A forwarder onto the assembly's own code is left numbered: whatever it reaches is
            // itself generated, so naming this one after it would only move the question.
            return null;
        }

        var declaring = Identifier(called.DeclaringType?.Name);
        var member = Identifier(called.Name);
        if (declaring.Length == 0 || member.Length == 0)
            return null;
        return member == "_ctor" ? $"New_{declaring}" : $"{declaring}_{member}";
    }

    /// <summary>
    /// Names a field after the kind of thing it holds, where that says more than a number.
    /// </summary>
    /// <remarks>
    /// Only where the type's own name survived, which rules out the case that would otherwise
    /// dominate: a field of a generated type would be named after a name this pass is in the middle
    /// of replacing. <see cref="object"/> is ruled out too, being what everything in a lifted body
    /// is declared as and so no help in telling one field from another.
    /// </remarks>
    private static string? Held(FieldDef field)
    {
        var name = field.FieldType?.ToTypeDefOrRef()?.Name;
        if (name is null)
            return null;
        var simple = Identifier(name);
        if (simple.Length == 0 ||
            simple is "Object" or "Void" ||
            ReactorNameHeuristics.IsGeneratedName(simple))
        {
            return null;
        }

        return char.ToLowerInvariant(simple[0]) + simple[1..];
    }

    /// <summary>
    /// What a type is, so that the tree a decompiler draws says something before anything is opened.
    /// </summary>
    private static string Kind(TypeDef type)
    {
        if (type.IsInterface)
            return "GeneratedInterface";
        if (type.IsEnum)
            return "GeneratedEnum";
        var baseName = type.BaseType?.Name.String;
        if (baseName is "MulticastDelegate" or "Delegate")
            return "GeneratedDelegate";
        if (baseName == "Attribute")
            return "GeneratedAttribute";
        return type.IsValueType ? "GeneratedStruct" : "GeneratedType";
    }

    /// <summary>Reduces a metadata name to something that can stand in source.</summary>
    private static string Identifier(UTF8String? name)
    {
        var text = name?.String;
        if (string.IsNullOrEmpty(text))
            return string.Empty;
        var tick = text.IndexOf('`', StringComparison.Ordinal);
        if (tick >= 0)
            text = text[..tick];
        var built = new string([.. text.Select(character =>
            char.IsAsciiLetterOrDigit(character) ? character : '_')]);
        return char.IsAsciiDigit(built.FirstOrDefault()) ? $"_{built}" : built;
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
