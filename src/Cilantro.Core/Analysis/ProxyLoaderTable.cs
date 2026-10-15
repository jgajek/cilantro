using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using Cilantro.Core.Analysis;

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
    /// The proxy map, for a caller that needs the bindings and not the provenance. It is the map the
    /// pass recovered and set aside if it did, and otherwise the one the bootstrap left behind.
    /// </summary>
    /// <remarks>
    /// Nothing is left behind when there is no map, so a caller that seeds its proxies from this
    /// seeds none, and a call through an unseeded proxy still stops rather than being sent somewhere
    /// plausible.
    /// </remarks>
    public static IReadOnlyList<ProxyBinding> Read(ArtifactContext context) =>
        context.TryGetFact<IReadOnlyList<ProxyBinding>>("proxy.bindings", out var recovered) &&
            recovered is { Count: > 0 }
            ? recovered
            : context.TryGetFact<IReadOnlyDictionary<uint, IReadOnlyDictionary<int, int>>>(
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

    /// <summary>How far the machine may run to let the resolver decode the whole table once.</summary>
    /// <remarks>
    /// The table is decoded in one pass over a resource a few kilobytes long, with per-word mixing
    /// that is arithmetic rather than iterative, so the cost is the resource's length and not the
    /// number of proxies. The allowance below is the same order the string lookups are given for the
    /// same kind of one-time setup, which is more than the decode is measured to need.
    /// </remarks>
    private const int ResolverSteps = 8_000_000;

    /// <summary>
    /// The proxy map, taken from the fact the bootstrap left if it built one, or by running the
    /// resolver ourselves when it did not.
    /// </summary>
    /// <remarks>
    /// The bootstrap only fills the table when its own startup path reaches the resolver, which a
    /// build that defers proxy setup to first use does not. The resolver is then still the one place
    /// the table exists without reimplementing the build's mixer, so it is run directly: it decodes
    /// the shared table before assigning delegates on the type it was handed. A real proxy type
    /// lets both phases finish; a helper type may decode the table but fail its per-field lookup.
    /// </remarks>
    public static bool TryResolve(
        ArtifactContext context,
        IReadOnlyDictionary<uint, FieldDef> proxyFields,
        out IReadOnlyList<ProxyBinding> bindings,
        out string source)
    {
        context.SetFact<IReadOnlyList<RecoveredResourceOrigin>>("proxy.loaderResources", []);
        if (context.TryGetFact<IReadOnlyDictionary<uint, IReadOnlyDictionary<int, int>>>(
                Fact, out var tables) &&
            TryRead(context.Module, tables, proxyFields, out bindings, out source))
        {
            if (FindResolver(context.Module) is { } resolver &&
                context.TryGetFact<LoaderInterpretationEvidence>("bootstrap.evidence", out var evidence) && evidence is not null)
                RememberResource(context, resolver, source, evidence);
            return true;
        }
        return TryBuildFromResolver(context, proxyFields, out bindings, out source);
    }

    /// <summary>
    /// Runs the resolver that builds the field-to-method table and reads the table it leaves behind.
    /// </summary>
    public static bool TryBuildFromResolver(
        ArtifactContext context,
        IReadOnlyDictionary<uint, FieldDef> proxyFields,
        out IReadOnlyList<ProxyBinding> bindings,
        out string source)
    {
        context.SetFact<IReadOnlyList<RecoveredResourceOrigin>>("proxy.loaderResources", []);
        bindings = [];
        source = string.Empty;
        if (proxyFields.Count == 0 || FindResolver(context.Module) is not { } resolver)
            return false;
        if (!BootstrapMachine.TrySeed(context, ResolverSteps, out var machine, out _) ||
            machine is null)
        {
            return false;
        }

        // Decode the shared table, then let the assignment phase finish on a real proxy type.
        // The resolver's own helper fields need not be keys in that table: using its declaring
        // type can decode successfully but fail on the first subsequent dictionary lookup.
        var proxyType = proxyFields.OrderBy(pair => pair.Key).First().Value.DeclaringType;
        if (!machine.State.Heap.TryAllocateMetadataHandle(proxyType, out var handle))
            return false;
        machine.Execute(resolver, [handle]);
        var built = InitializedFieldCapture.CaptureIntegerMaps(context.Module, machine.State);
        if (!TryRead(context.Module, built, proxyFields, out bindings, out source)) return false;
        RememberResource(context, resolver, source, machine.State.LoaderEvidence);
        return true;
    }

    internal static void RememberResource(ArtifactContext context, MethodDef resolver, string source, LoaderInterpretationEvidence evidence)
    {
        if (!evidence.HasCompleteObservations(LoaderObservationKind.ManagedResourceRead) || !resolver.HasBody || !evidence.EffectsOf(resolver.MDToken.Raw).AllInvocationsCompleted) return;
        var writes = resolver.Body.Instructions.Where(instruction => instruction.OpCode.Code == Code.Stsfld)
            .Select(instruction => (instruction.Operand as IField)?.ResolveFieldDef()).OfType<FieldDef>();
        if (!writes.Any(field => source == $"{field.MDToken} {field.FullName}" &&
                evidence.EffectsOf(resolver.MDToken.Raw).StaticFieldsWritten.Contains(field.FullName))) return;
        var reads = evidence.Observations.Where(observation => observation.Kind == LoaderObservationKind.ManagedResourceRead &&
                observation.CallStack.Contains(resolver.MDToken.Raw)).Select(observation =>
                System.Text.Json.JsonSerializer.Deserialize<ManagedResourceRead>(observation.Detail)).ToArray();
        if (reads.Length == 0 || reads.Any(read => read is null)) return;
        var origins = reads.Select(read => new RecoveredResourceOrigin(read!.Name, read.Sha256)).Distinct().ToArray();
        if (origins.Length != 1 || !context.Module.Resources.OfType<EmbeddedResource>().Any(origins[0].Matches) ||
            !resolver.Body.Instructions.Any(instruction => instruction.OpCode.Code == Code.Ldstr && Equals(instruction.Operand, origins[0].Name))) return;
        context.SetFact<IReadOnlyList<RecoveredResourceOrigin>>("proxy.loaderResources", origins);
    }

    /// <summary>
    /// The method that decodes the proxy table: static, taking one runtime type handle, reading a
    /// manifest resource, resolving tokens against the module, and leaving a number-to-number map in
    /// a static field. Only one method in a Reactor module fits, and if two did neither would, since
    /// running the wrong one would fill nothing and there is no basis for choosing between them.
    /// </summary>
    private static MethodDef? FindResolver(ModuleDef module)
    {
        const string dictionary =
            "System.Collections.Generic.Dictionary`2<System.Int32,System.Int32>";
        MethodDef? found = null;
        foreach (var method in module.GetTypes().SelectMany(type => type.Methods))
        {
            if (!method.HasBody ||
                !method.IsStatic ||
                method.MethodSig?.Params.Count != 1 ||
                method.MethodSig.Params[0].FullName != "System.RuntimeTypeHandle")
            {
                continue;
            }

            var buildsMap = false;
            var readsResource = false;
            var resolvesToken = false;
            foreach (var instruction in method.Body.Instructions)
            {
                if (instruction.OpCode.Code == Code.Stsfld &&
                    instruction.Operand is IField field &&
                    field.FieldSig?.Type.FullName == dictionary)
                {
                    buildsMap = true;
                }
                else if (instruction.Operand is IMethod called)
                {
                    if (called.Name == "GetManifestResourceStream")
                        readsResource = true;
                    else if (called.DeclaringType?.FullName == "System.Reflection.Module" &&
                        called.Name.String.StartsWith("Resolve", StringComparison.Ordinal))
                    {
                        resolvesToken = true;
                    }
                }
            }

            if (!buildsMap || !readsResource || !resolvesToken)
                continue;
            if (found is not null)
                return null;
            found = method;
        }

        return found;
    }
}
