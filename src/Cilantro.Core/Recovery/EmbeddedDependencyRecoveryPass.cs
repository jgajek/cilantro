using System.Security.Cryptography;
using System.Text.Json;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Payload;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Captures resource-backed dependency resolver responses without loading assemblies into the host.</summary>
public sealed class EmbeddedDependencyRecoveryPass : DeobfuscationPass
{
    internal const string IndexesFact = "dependency.validatedIndexes";
    internal const string DecoderInputsFact = "dependency.validatedDecoderInputs";
    internal sealed record ValidatedIndex(MethodDef Resolver, MethodDef Constructor, DependencyIndexConstruction.Snapshot Index,
        bool SourceClosed, bool ConsumersClosed);
    internal sealed record ValidatedDecoderInput(ValidatedIndex Index, MethodDef Decoder, IReadOnlyList<DependencySliceSource.Slice> Slices);
    public override string Name => "embedded-dependency-recovery";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => ["numeric-runtime-cleanup"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var candidates = context.Module.GetTypes().SelectMany(t => t.Methods).Where(IsResolver).Take(5).ToArray();
        if (candidates.Length == 0) return (PassStatus.Success, 0, ["No resource-backed dependency resolver was found."]);
        if (candidates.Length > 4) return (PassStatus.Partial, 0, ["Dependency resolver candidate limit exceeded (4)."]);
        var requests = context.Module.GetAssemblyRefs().Select(r => r.FullName).Distinct(StringComparer.Ordinal).Take(65).ToArray();
        if (requests.Length > 64) return (PassStatus.Partial, 0, ["Dependency request limit exceeded (64)."]);
        // Shared across candidates, requests and repeat reads. Managed decompression
        // can exceed the startup budget; this stage has its own finite total budget.
        var budget = new StaticWorkBudget(BootstrapMachine.Limits(768_000_000,
            BootstrapMachine.Environment(context).Declarations.Budgets).MaximumSteps);
        var recovered = new List<ExtractedPayload>();
        var diagnostics = new List<string>();
        var declined = false;
        var indexes = new List<ValidatedIndex>();
        var decoderInputs = new List<ValidatedDecoderInput>();
        context.TryGetFact<IReadOnlyList<ExtractedPayload>>("payload.artifacts", out var existing);
        var known = (existing ?? []).Select(p => p.Info.PayloadSha256).ToHashSet(StringComparer.Ordinal);
        foreach (var resolver in candidates)
        {
            var discovered = DiscoverRequests(context, resolver, budget);
            var combined = requests.Concat(discovered).Distinct(StringComparer.Ordinal).Take(65).ToArray();
            if (combined.Length > 64)
            { declined = true; diagnostics.Add($"{resolver.FullName}: combined dependency request limit exceeded (64)."); continue; }
            if (discovered.Length != 0)
                diagnostics.Add($"{resolver.FullName}: discovered {discovered.Length} name(s) in agreeing cold lookup-table snapshots.");
            foreach (var request in combined)
            {
                if (budget.RemainingSteps == 0) break;
                if (!TryRead(context, resolver, request, budget, out var first, out var why))
                { declined = true; diagnostics.Add($"{resolver.FullName}, {request}: {why}"); continue; }
                if (first is null) continue;
                if (!TryRead(context, resolver, request, budget, out var second, out why) || second is null ||
                    first.Source != second.Source || !first.Payload.Bytes.AsSpan().SequenceEqual(second.Payload.Bytes))
                { declined = true; diagnostics.Add($"{request}: independent resolver reads did not agree. {why}"); continue; }
                var payload = first.Payload;
                var hash = Convert.ToHexStringLower(SHA256.HashData(payload.Bytes));
                var resource = context.Module.Resources.OfType<EmbeddedResource>().Single(first.Source.Matches);
                if (!indexes.Any(p => p.Resolver == resolver && p.Index.Source == first.Source))
                    foreach (var constructor in resolver.Body.Instructions.Select(i => i.Operand).OfType<IMethod>()
                        .Select(m => m.ResolveMethodDef()).OfType<MethodDef>().Distinct())
                        if (DependencyIndexConstruction.TryRead(constructor, resource, out var index, out _) && index is not null)
                        {
                            var sourceClosed = DependencyIndexSource.Check(resolver, constructor, index, out var sourceReason);
                            var consumersClosed = DependencyIndexConsumers.Check(resolver, constructor, index, out var consumerReason);
                            var validated = new ValidatedIndex(resolver, constructor, index, sourceClosed, consumersClosed);
                            indexes.Add(validated);
                            diagnostics.Add($"{constructor.FullName}: proved fixed-resource construction of {index.Entries.Count} bundle index entry(s). {sourceReason} {consumerReason}");
                            if (sourceClosed && consumersClosed)
                                foreach (var decoder in resolver.Body.Instructions.Where(i => i.OpCode.Code == Code.Call)
                                    .Select(i => i.Operand).OfType<IMethod>().Select(m => m.ResolveMethodDef()).OfType<MethodDef>()
                                    .Where(m => m.IsStatic && m.HasBody && m.MethodSig.Params.Count == 1 && m.ReturnType.FullName == "System.IO.Stream").Distinct().Take(8))
                                    if (DependencySliceSource.TryRead(validated, decoder, out var slices, out _))
                                    {
                                        decoderInputs.Add(new(validated, decoder, slices));
                                        diagnostics.Add($"{decoder.FullName}: proved {slices.Count} exact resource slice(s) across all direct decoder calls. Decoder effects and replacement remain separate obligations.");
                                    }
                        }
                if (!known.Add(hash)) continue;
                recovered.Add(new(new PayloadInfo(first.Source.Name, first.Source.Sha256, (int)resource.CreateReader().Length,
                    hash, payload.Bytes.Length, hash, payload.AssemblyName, payload.ModuleName, payload.EntryPointToken,
                    payload.Resources, Origin: PayloadOrigin.EmbeddedDependency), payload.Bytes));
                context.AddEvidence(new Evidence(Name,
                    $"Two cold static resolver responses recovered {payload.AssemblyName}, SHA-256 {hash}; request {request}. Resolver code and loading behavior remain unchanged.",
                    first.Source.Name));
            }
        }
        context.SetFact<IReadOnlyList<ExtractedPayload>>("payload.artifacts", [.. existing ?? [], .. recovered]);
        context.SetFact<IReadOnlyList<ValidatedIndex>>(IndexesFact, indexes);
        context.SetFact<IReadOnlyList<ValidatedDecoderInput>>(DecoderInputsFact, decoderInputs);
        diagnostics.Insert(0, $"Recovered {recovered.Count} embedded dependency assembly(s) from assembly references and observed lookup tables; used {budget.ConsumedSteps} interpreted steps.");
        diagnostics.Add("Other possible resolver states are not covered by these requests. Resolver replacement and resource retirement require separate proofs.");
        if (budget.RemainingSteps == 0) diagnostics.Add("The shared dependency-recovery step budget was exhausted.");
        return (budget.RemainingSteps == 0 || declined
            ? PassStatus.Partial : PassStatus.Success, recovered.Count, diagnostics.Take(12).ToArray());
    }

    internal static string[] DiscoverRequests(ArtifactContext context, MethodDef resolver, StaticWorkBudget budget)
    {
        var tables = resolver.DeclaringType.Fields.Where(f => f.IsStatic &&
            f.FieldType.FullName == "System.Collections.Hashtable").ToArray();
        if (tables.Length == 0 || tables.Length > 4) return [];
        string[]? first = null;
        foreach (var probe in new[] { "Cilantro.Missing.Dependency.A", "Cilantro.Missing.Dependency.B" })
        {
            if (budget.RemainingSteps == 0 || !BootstrapMachine.TrySeed(context, budget.MaximumSteps, out var machine, out _) || machine is null ||
                !machine.State.Heap.TryAllocateString(probe, out var name)) return [];
            var result = machine.Execute(resolver, [name], budget);
            if (!result.Succeeded || machine.State.RanOutOfBudget || result.Value.Kind != StaticValueKind.Null ||
                machine.State.CapturedAssemblyLoads.Count != 0) return [];
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var field in tables)
            {
                if (!machine.State.Heap.TryGetModelValue<Dictionary<StaticValue, StaticValue>>(
                    machine.State.ReadStaticField(field), "Entries", out var entries) || entries is null) continue;
                if (entries.Count > 64) return [];
                foreach (var key in entries.Keys)
                {
                    if (!machine.State.Heap.TryGetString(key, out var text) || text.Length == 0 || text.Length > 4096) return [];
                    names.Add(text);
                }
            }
            var ordered = names.Order(StringComparer.Ordinal).ToArray();
            if (first is not null && !first.SequenceEqual(ordered, StringComparer.Ordinal)) return [];
            first = ordered;
        }
        // These are candidate requests, not a proof that every possible invocation
        // uses this table. Each positive response still needs independent validation.
        return first ?? [];
    }

    internal static bool IsResolver(MethodDef method) => method.IsStatic && method.HasBody && !method.HasGenericParameters &&
        !method.DeclaringType.HasGenericParameters && method.MethodSig.Params.Count == 1 &&
        method.MethodSig.Params[0].ElementType is ElementType.String or ElementType.Object &&
        method.ReturnType.FullName == "System.Reflection.Assembly" &&
        method.Body.Instructions.Any(i => FrameworkCall(i, method.Module,
            "System.IO.Stream System.Reflection.Assembly::GetManifestResourceStream(System.String)")) &&
        method.Body.Instructions.Any(i => FrameworkCall(i, method.Module,
            "System.Reflection.Assembly System.Reflection.Assembly::Load(System.Byte[])") ||
            FrameworkCall(i, method.Module, "System.Reflection.Assembly System.Reflection.Assembly::LoadFile(System.String)"));

    private static bool FrameworkCall(Instruction instruction, ModuleDef module, string signature) =>
        instruction.OpCode.Code is Code.Call or Code.Callvirt && instruction.Operand is IMethod method &&
        method.FullName == signature && method.DeclaringType is TypeRef type &&
        type.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName;

    internal sealed record Capture(RecoveredResourceOrigin Source, ValidatedManagedPayload Payload);

    internal static bool TryRead(ArtifactContext context, MethodDef resolver, string request, StaticWorkBudget budget,
        out Capture? capture, out string diagnostic)
    {
        capture = null;
        diagnostic = "";
        if (!BootstrapMachine.TrySeed(context, budget.MaximumSteps, out var machine, out diagnostic) || machine is null ||
            !machine.State.Heap.TryAllocateString(request, out var name)) return false;
        var result = machine.Execute(resolver, [name], budget);
        if (!result.Succeeded || machine.State.RanOutOfBudget)
        { diagnostic = result.Diagnostic ?? result.Status.ToString(); return false; }
        if (result.Value.Kind == StaticValueKind.Null) return true;
        if (!machine.State.Heap.TryGetModelValue<byte[]>(result.Value, "LoadedImage", out var image) || image is null ||
            !machine.State.CapturedAssemblyLoads.Any(bytes => bytes.AsSpan().SequenceEqual(image)) ||
            !PayloadStageValidator.TryValidateManaged(image, out var payload) || payload is null)
        { diagnostic = "The response is not a validated captured managed assembly."; return false; }
        if (!string.Equals(new AssemblyNameInfo(request).Name.String, payload.AssemblyName, StringComparison.OrdinalIgnoreCase))
        { diagnostic = "The returned assembly does not match the requested dependency name."; return false; }
        var evidence = machine.State.LoaderEvidence;
        if (evidence.ObservationsTruncated)
        { diagnostic = "Resource-read evidence was truncated."; return false; }
        var sources = evidence.Observations.Where(o => o.Kind == LoaderObservationKind.ManagedResourceRead)
            .Select(o => JsonSerializer.Deserialize<ManagedResourceRead>(o.Detail))
            .OfType<ManagedResourceRead>().Select(r => new RecoveredResourceOrigin(r.Name, r.Sha256)).Distinct().ToArray();
        if (sources.Length != 1 || context.Module.Resources.Count(r => r.Name == sources[0].Name) != 1 ||
            context.Module.Resources.OfType<EmbeddedResource>().Count(sources[0].Matches) != 1)
        { diagnostic = "The response does not have one exact, unchanged source resource."; return false; }
        capture = new(sources[0], payload);
        return true;
    }
}
