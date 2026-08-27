using dnlib.DotNet;

namespace Cilantro.Core;

/// <summary>
/// The field-to-method map Reactor's loader builds, read back out of where the loader left it.
/// </summary>
/// <remarks>
/// The map normally arrives by decoding the resource behind it, which needs the two constants that
/// build's mixer was generated with. A build whose mixer is not the one the structural search knows
/// how to read leaves that route closed, and the map is then only obtainable the way the program
/// itself obtains it: by running the loader, which fills a dictionary keyed by proxy field token.
/// Interpreting the bootstrap already does that, so the table is a by-product of work already done
/// rather than a second decoding.
///
/// Reading it is a validation rather than a decode. A table is accepted only if it names every proxy
/// field and nothing else, and only if every value in it resolves to a method of this module; and if
/// two tables both qualify, neither is, because nothing distinguishes them and picking one would be
/// a guess. That leaves a table that either is the proxy map or is refused.
/// </remarks>
public static class ProxyLoaderTable
{
    /// <summary>Where the bootstrap interpretation leaves the tables it saw being filled.</summary>
    public const string Fact = "bootstrap.tokenMaps";

    /// <summary>The bits of a table entry that are the target's metadata token.</summary>
    private const uint TargetTokenMask = 0x3FFFFFFFu;

    /// <summary>The bit a table entry sets when the call it stands for is virtual.</summary>
    private const uint CallVirtualFlag = 0x40000000u;

    /// <summary>The static fields of every delegate proxy type, by metadata token.</summary>
    public static Dictionary<uint, FieldDef> ProxyFields(ModuleDef module) =>
        module.GetTypes()
            .Where(ReactorDetectionPass.IsDelegateProxy)
            .SelectMany(type => type.Fields)
            .Where(field => field.IsStatic)
            .ToDictionary(field => field.MDToken.Raw);

    /// <summary>
    /// The proxy map the loader built, for a caller that needs the bindings and not the provenance.
    /// </summary>
    /// <remarks>
    /// Nothing is left behind when there is no table or no table qualifies, so a caller that seeds
    /// its proxies from this seeds none, and a call through an unseeded proxy still stops rather than
    /// being sent somewhere plausible.
    /// </remarks>
    public static IReadOnlyList<ProxyBinding> Read(ArtifactContext context) =>
        context.TryGetFact<IReadOnlyDictionary<uint, IReadOnlyDictionary<int, int>>>(
                Fact, out var tables) &&
            TryRead(context.Module, tables, ProxyFields(context.Module), out var bindings, out _)
            ? bindings
            : [];

    /// <summary>Reads the one table that can be the proxy map, saying which field held it.</summary>
    public static bool TryRead(
        ModuleDef module,
        IReadOnlyDictionary<uint, IReadOnlyDictionary<int, int>>? tables,
        IReadOnlyDictionary<uint, FieldDef> proxyFields,
        out IReadOnlyList<ProxyBinding> bindings,
        out string source)
    {
        bindings = [];
        source = string.Empty;
        if (tables is null || proxyFields.Count == 0)
            return false;

        foreach (var (holder, table) in tables)
        {
            if (table.Count != proxyFields.Count)
                continue;
            var read = new List<ProxyBinding>(table.Count);
            foreach (var (field, encoded) in table)
            {
                var fieldToken = unchecked((uint)field);
                var targetToken = unchecked((uint)encoded) & TargetTokenMask;
                if (!proxyFields.ContainsKey(fieldToken) ||
                    module.ResolveToken(targetToken) is not IMethod)
                {
                    read = null!;
                    break;
                }
                read.Add(new ProxyBinding(
                    fieldToken,
                    targetToken,
                    (unchecked((uint)encoded) & CallVirtualFlag) != 0));
            }
            if (read is null)
                continue;
            if (bindings.Count != 0)
            {
                bindings = [];
                source = string.Empty;
                return false;
            }
            bindings = read;
            source = module.ResolveToken(holder) is FieldDef named
                ? $"{named.MDToken} {named.FullName}"
                : $"0x{holder:X8}";
        }

        return bindings.Count != 0;
    }
}
