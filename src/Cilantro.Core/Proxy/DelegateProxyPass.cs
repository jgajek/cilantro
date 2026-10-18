using System.Security.Cryptography;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Codec;
using Cilantro.Core.Proxy;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;

namespace Cilantro.Core;

public sealed record ProxyDescriptor(
    uint TypeToken,
    string Type,
    uint? FieldToken,
    uint? WrapperToken,
    uint? InitializerToken);

public sealed record ProxyBinding(uint FieldToken, uint TargetToken, bool CallVirtual);

public sealed class DelegateProxyPass : DeobfuscationPass
{
    public override string Name => "delegate-proxy-analysis";
    public override IReadOnlyCollection<string> Dependencies => ["resource-analysis"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var proxyTypes = context.Module.GetTypes()
            .Where(ReactorDetectionPass.IsDelegateProxy)
            .ToArray();
        var proxies = proxyTypes
            .Select(type => new ProxyDescriptor(
                type.MDToken.Raw,
                type.FullName,
                type.Fields.FirstOrDefault(field => field.IsStatic)?.MDToken.Raw,
                type.Methods.FirstOrDefault(method => method.HasBody && !method.IsStaticConstructor)?.MDToken.Raw,
                type.FindStaticConstructor()?.MDToken.Raw))
            .ToArray();
        context.SetFact("proxy.catalog", proxies);

        var resolverCandidates = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody)
            .Where(method => method.Body.Instructions.Any(instruction =>
                instruction.Operand is IMethod called &&
                called.DeclaringType?.FullName == "System.Reflection.Module" &&
                called.Name.String.StartsWith("Resolve", StringComparison.Ordinal)))
            .ToArray();

        foreach (var candidate in resolverCandidates)
        {
            context.AddEvidence(new Evidence(
                "proxy-resolver",
                $"Token resolver candidate with {candidate.Body.Instructions.Count} IL instructions.",
                $"{candidate.MDToken} {candidate.FullName}",
                0.85));
        }

        if (proxies.Length == 0)
        {
            return (PassStatus.Success, 0, ["No delegate proxies were detected."]);
        }
        if (context.TryGetFact<bool>(BabelProxyRecoveryPass.CompleteFact, out var babelComplete) && babelComplete)
            return (PassStatus.Success, 0, ["The Babel token-based proxy bindings were validated and their adapters recovered by babel-proxies."]);

        var fields = proxyTypes
            .SelectMany(type => type.Fields)
            .Where(field => field.IsStatic)
            .ToDictionary(field => field.MDToken.Raw);
        string mapSource;
        RecoveredResourceOrigin? resourceOrigin = null;
        IReadOnlyList<ProxyBinding> bindings;
        var profileSource = "structural";
        context.TryGetFact<ReactorStructureFacts>("reactor.structure", out var structureFacts);
        if (structureFacts is not null &&
            StructuralStreamDiscovery.TryDiscoverProxyProfile(
                context.Module,
                structureFacts,
                out var discovered) &&
            discovered is not null)
        {
            mapSource = discovered.Resource.Name;
            resourceOrigin = RecoveredResourceOrigin.Capture(discovered.Resource);
            bindings = discovered.Bindings;
            context.AddEvidence(new Evidence(
                "stream-constants",
                $"Derived proxy stream constants A=0x{discovered.A:X8}, D=0x{discovered.D:X8}.",
                discovered.EvidenceMethod,
                1.0));
        }
        else if (ProxyLoaderTable.TryResolve(context, fields, out bindings, out var table))
        {
            profileSource = "loader-table";
            mapSource = table;
            if (context.TryGetFact<IReadOnlyList<RecoveredResourceOrigin>>("proxy.loaderResources", out var origins) && origins is { Count: 1 })
                resourceOrigin = origins[0];
            context.AddEvidence(new Evidence(
                "proxy-table",
                $"Read {bindings.Count} field-to-method bindings out of the table the loader built, " +
                "rather than decoding the resource behind it.",
                table,
                1.0));
        }
        else if (ProxyResourceCodec.TryGetProfile(context.OriginalSha256, out var profile))
        {
            profileSource = "known-regression";
            var resource = context.Module.Resources
                .OfType<EmbeddedResource>()
                .FirstOrDefault(item =>
                    Convert.ToHexStringLower(SHA256.HashData(item.CreateReader().ToArray())) ==
                    profile.ResourceSha256)
                ?? throw new InvalidDataException("The profiled proxy mapping resource was not found.");
            mapSource = resource.Name;
            resourceOrigin = RecoveredResourceOrigin.Capture(resource);
            var decoded = ProxyResourceCodec.Decode(resource.CreateReader().ToArray(), profile);
            if (Convert.ToHexStringLower(SHA256.HashData(decoded)) != profile.DecodedSha256)
                return (PassStatus.Failed, 0, ["Decoded proxy map failed its regression hash."]);
            bindings = ProxyResourceCodec.Parse(decoded);
        }
        else
        {
            return (PassStatus.Unsupported, 0,
            [
                $"Cataloged {proxies.Length} delegate proxies.",
                "No structurally validated proxy stream codec was found, and the loader " +
                "interpretation left no table naming every one of them."
            ]);
        }

        if (bindings.Count != fields.Count ||
            bindings.Any(binding =>
                !fields.ContainsKey(binding.FieldToken) ||
                context.Module.ResolveToken(binding.TargetToken) is not IMethod))
        {
            return (PassStatus.Failed, 0, ["Proxy map failed metadata-token validation."]);
        }

        var bindingByField = bindings.ToDictionary(binding => binding.FieldToken);
        var adapterByField = new Dictionary<uint, MethodDef>();
        foreach (var binding in bindings)
        {
            var field = fields[binding.FieldToken];
            var adapter = field.DeclaringType.Methods.SingleOrDefault(method =>
                method.HasBody &&
                method.IsStatic &&
                !method.IsConstructor &&
                method.Parameters.Count > 0 &&
                method.Parameters[^1].Type.FullName == field.DeclaringType.FullName);
            if (adapter is not null)
            {
                adapterByField[binding.FieldToken] = adapter;
            }
        }

        var changes = 0;
        var widened = 0;
        var declined = 0;
        var narrowings = new List<ProxyNarrowingSite>();
        var bypassedAdapters = new HashSet<MethodDef>();
        foreach (var method in context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody))
        {
            var instructions = method.Body.Instructions;
            for (var index = 0; index + 1 < instructions.Count; index++)
            {
                var fieldLoad = instructions[index];
                var adapterCall = instructions[index + 1];
                if (fieldLoad.OpCode != OpCodes.Ldsfld ||
                    fieldLoad.Operand is not FieldDef field ||
                    !bindingByField.TryGetValue(field.MDToken.Raw, out var binding) ||
                    !adapterByField.TryGetValue(field.MDToken.Raw, out var adapter) ||
                    adapterCall.OpCode != OpCodes.Call ||
                    adapterCall.Operand is not IMethod called ||
                    called.MDToken.Raw != adapter.MDToken.Raw ||
                    context.Module.ResolveToken(binding.TargetToken) is not IMethod target)
                {
                    continue;
                }

                if (ProxyArgumentNarrowing.Plan(adapter, target) is not { } narrowing)
                {
                    declined++;
                    continue;
                }

                fieldLoad.OpCode = OpCodes.Nop;
                fieldLoad.Operand = null;
                adapterCall.OpCode = binding.CallVirtual ? OpCodes.Callvirt : OpCodes.Call;
                adapterCall.Operand = target;

                // The conversion is left for the end of the run. Emitting it here would put a
                // `stloc` between the arguments and the call of two thousand sites, and the passes
                // that read this IL afterwards — the interpreter most of all — read the shape as
                // well as the meaning.
                if (narrowing.Conversions.Count != 0)
                {
                    narrowings.Add(new ProxyNarrowingSite(method, adapterCall, narrowing));
                    widened++;
                }

                context.AddChange(new ChangeRecord(
                    Name,
                    "restore-proxy-call",
                    $"{method.MDToken} IL_{adapterCall.Offset:X4}",
                    $"{field.MDToken} -> 0x{binding.TargetToken:X8} ({adapterCall.OpCode.Name})"));
                changes++;
                bypassedAdapters.Add(adapter);
                index = instructions.IndexOf(adapterCall);
            }
        }

        // The adapters existed to dispatch through the proxy fields these sites no longer load,
        // and the initialization behind them exists only to populate those fields.
        RecoveryOrphans.DeclareSubtree(context, bypassedAdapters);
        context.SetFact("proxy.bindings", bindings);
        if (resourceOrigin is not null)
        {
            context.SetFact("proxy.validatedResource", resourceOrigin);
            if (changes != 0) DecodedResourceOwnership.Remember(context, resourceOrigin, resolverCandidates, proxyTypes);
        }
        context.SetFact("proxy.restoredCallSites", changes);
        context.SetFact("proxy.narrowings", (IReadOnlyList<ProxyNarrowingSite>)narrowings);
        context.AddEvidence(new Evidence(
            "proxy-map",
            $"Decoded and validated {bindings.Count} field-to-method bindings.",
            mapSource,
            1.0));
        var said = new List<string>
        {
            $"Decoded {bindings.Count} proxy bindings.",
            $"Restored {changes} direct call sites.",
            $"Profile source: {profileSource}."
        };
        if (widened != 0)
        {
            said.Add(
                $"{widened} of the sites had an argument the adapter and its target disagreed " +
                "about, and the conversion the adapter was doing is put back in front of the " +
                "direct call at the end of the run.");
        }
        if (declined != 0)
        {
            said.Add(
                $"{declined} site(s) were left dispatching through their adapter, its parameters " +
                "not lining up with the target's in a way a conversion could reconcile.");
        }

        return (PassStatus.Success, changes, said);
    }

    /// <summary>
    /// Takes the field-to-method map out of the table the loader itself built, when it built one.
    /// </summary>
    /// <remarks>
    /// The protector keeps its answers in a table from proxy field to target method, decoded on the
    /// way up from a resource with constants that are chosen per build. Deriving those constants by
    /// search only works while the arithmetic around them is the shape already seen; the loader, by
    /// contrast, has just run and left the finished table behind, and reading it asserts nothing
    /// about how it was made. A table is accepted only when it names every proxy field in the file
    /// and nothing else, and only when exactly one table does — several would mean the pass had
    /// chosen which to believe, and that is a guess.
    /// </remarks>
}
