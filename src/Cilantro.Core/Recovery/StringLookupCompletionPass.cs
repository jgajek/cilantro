using System.Security.Cryptography;
using System.Text.Json;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Strings;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Removes recovered string-table calls only when their domain state is exclusively owned.</summary>
public class StringLookupCompletionPass : DeobfuscationPass
{
    internal const string TypesFact = "cleanup.orphanedStringLookupTypes";
    private const string CandidatesFact = "strings.retainedLookups";
    internal sealed record Candidate(MethodDef Resolver, IReadOnlyCollection<MethodDef> Aliases, IReadOnlyDictionary<int, string> Answers);
    internal static void Remember(ArtifactContext context, MethodDef resolver, IReadOnlyCollection<MethodDef> aliases,
        IReadOnlyDictionary<int, string> answers)
    {
        if (!context.TryGetFact<List<Candidate>>(CandidatesFact, out var candidates) || candidates is null)
            context.SetFact(CandidatesFact, candidates = []);
        candidates.Add(new(resolver, aliases, new Dictionary<int, string>(answers)));
    }

    public override string Name => "string-lookup-completion";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => ["memory-integrity-completion", "emitted-method-reconstruction"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("options.removeRuntime", out var enabled) || !enabled ||
            !context.TryGetFact<List<Candidate>>(CandidatesFact, out var candidates) || candidates is null)
            return (PassStatus.Success, 0, ["No retained recovered string lookup requires completion."]);
        var notes = new List<string>();
        var changes = 0;
        var removedTypes = new HashSet<uint>();
        if (context.TryGetFact<IReadOnlySet<uint>>(TypesFact, out var previouslyOwned) && previouslyOwned is not null)
            removedTypes.UnionWith(previouslyOwned);
        var existingIslands = ProtectorIslands.Find(context);
        var reachability = existingIslands.Count == 0 ? ModuleReachability.Compute(context.Module) : ProtectorIslands.Without(context, existingIslands);
        if (context.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody && reachability.IsReachable(m)).Any(m =>
            m.Body.Instructions.Any(i => i.Operand is IMethod called && NumericTokenUses.IsResolution(called) &&
                !NumericTokenUses.MemberRoundTrips(m).Contains(i))))
            return (PassStatus.Partial, 0, ["Unresolved reachable metadata-token access prevents establishing exclusive string-state ownership."]);
        foreach (var candidate in candidates)
        {
            var owner = candidate.Resolver.DeclaringType;
            if (owner.Module != context.Module) continue;
            var owned = ProtectorIslands.Nest(owner).ToHashSet();
            var methods = context.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody).ToArray();
            if (owner.IsGlobalModuleType || !owner.IsSealed || owned.Any(MemberVisibility.IsExternallyVisible) ||
                candidate.Aliases.Any(a => !owned.Contains(a.DeclaringType))) continue;
            var keys = candidate.Resolver.Body.Instructions.Where(i => i.OpCode.Code == Code.Ldsfld)
                .Select(i => (i.Operand as IField)?.ResolveFieldDef()).OfType<FieldDef>()
                .Where(f => owned.Contains(f.DeclaringType) && f.FieldType.ElementType == ElementType.String).Distinct().ToArray();
            if (keys.Length != 1) continue;
            var domainUses = methods.SelectMany(m => m.Body.Instructions.Select(i => (Method: m, Instruction: i)))
                .Where(p => p.Instruction.Operand is IMethod call && call.DeclaringType.FullName == "System.AppDomain" &&
                    call.Name.String is "GetData" or "SetData").ToArray();
            if (domainUses.Length != 2 || domainUses.Any(p => !owned.Contains(p.Method.DeclaringType)) ||
                domainUses.Count(p => ((IMethod)p.Instruction.Operand).Name == "GetData") != 1 ||
                domainUses.Any(p => p.Instruction.OpCode.Code is not (Code.Call or Code.Callvirt))) continue;
            if (!TrySites(candidate, owned, methods, out var sites) || sites.Count == 0) continue;

            // Follow dependencies from the proven string holder, then keep only the group
            // which no surviving declaration references after the calls are replaced.
            // This admits private decompression tables without claiming shared caches.
            var privateTypes = context.Module.GetTypes().Where(t => !t.IsGlobalModuleType &&
                !MemberVisibility.IsExternallyVisible(t)).ToHashSet();
            var dependencies = new HashSet<TypeDef>(owned);
            while (true)
            {
                var count = dependencies.Count;
                dependencies.UnionWith(RuntimeCleanupPass.CollectReferencedCandidates(context.Module, dependencies.ToArray(), privateTypes));
                dependencies.UnionWith(dependencies.ToArray().SelectMany(ProtectorIslands.Nest).Where(privateTypes.Contains));
                if (dependencies.Count == count) break;
            }
            using (var probe = new BodyMutationBatch(sites.Select(s => s.Method)))
            {
                Rewrite(sites);
                owned = RuntimeCleanupPass.ComputeUnreferenced(context.Module, dependencies);
            }
            if (!owned.Contains(owner)) continue;

            IReadOnlyList<RecoveredResourceOrigin>? observedResources = null;
            var resourceReadsAgree = true;
            var budget = LoaderCallElisionPass.ColdInitializerStepBudget(context);
            var metadata = new Dictionary<object, int>(ReferenceEqualityComparer.Instance);
            MethodDef[]? sharedInitializers = null;
            var preserveSharedInitialization = false;
            if (!Read(true, null, out var left, out var slot, out var why) ||
                !Read(true, slot, out var repeated, out _, out why) || left != repeated)
            { notes.Add(owner.FullName + ": initial state proof refused: " +
                (why.Length != 0 ? why : "independent initialization states disagree")); continue; }
            var names = owned.Select(t => t.FullName).Concat(owned.Select(t => t.Name.String))
                .Concat(owned.SelectMany(t => t.Fields).Select(f => f.Name.String))
                .Concat(candidate.Aliases.Select(m => m.Name.String)).ToHashSet(StringComparer.Ordinal);
            if (methods.Where(m => !owned.Contains(m.DeclaringType)).Any(m => m.Body.Instructions.Any(i =>
                i.Operand is string text && (text == slot || text is "GetData" or "SetData" || names.Contains(text)))))
            { notes.Add(owner.FullName + ": an external literal names the domain slot or access API."); continue; }

            using var transaction = new BodyMutationBatch(sites.Select(s => s.Method));
            Rewrite(sites);
            if (!RuntimeCleanupPass.ComputeUnreferenced(context.Module, owned).Contains(owner))
            { notes.Add(owner.FullName + ": another declaration still references the string machinery."); continue; }
            var agrees = Read(false, slot, out var right, out _, out why) && left == right &&
                Read(false, slot, out var repeatedRight, out _, out why) && right == repeatedRight;
            if (!agrees && sharedInitializers is { Length: > 0 } &&
                sharedInitializers.All(m => !m.HasGenericParameters && !m.DeclaringType.HasGenericParameters))
            {
                // Shared decoder tables can still serve an assembly resolver. Retain
                // precisely their observed initialization, rather than exempting
                // their state from the equivalence comparison or keeping string calls.
                preserveSharedInitialization = true;
                PreserveInitialization(context.Module, sites, sharedInitializers);
                agrees = Read(false, slot, out right, out _, out why) && left == right &&
                    Read(false, slot, out var repeatedWithInitialization, out _, out why) && right == repeatedWithInitialization;
            }
            if (!agrees)
            { notes.Add(owner.FullName + ": application state did not agree after removing the lookup: " +
                (why.Length != 0 ? why : Difference(left, right))); continue; }
            if (!AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
                CilantroPipeline.BuildRewriteAllowance(context)).Passed)
            { notes.Add(owner.FullName + ": structural verification refused the rewrite."); continue; }
            transaction.Commit();
            if (resourceReadsAgree)
                foreach (var resource in observedResources ?? [])
                    DecodedResourceOwnership.Remember(context, resource, owned.SelectMany(t => t.Methods));
            RecoveryOrphans.DeclareSubtree(context, owned.SelectMany(t => t.Methods));
            removedTypes.UnionWith(owned.Select(t => t.MDToken.Raw));
            changes += sites.Count;
            context.AddChange(new(Name, "remove-owned-string-lookup", owner.FullName,
                $"Removed {sites.Count} already-literalized calls. The domain table has one owned reader and writer and no named external consumer; " +
                "two independent startups on each side preserve other static, domain, network, native and captured-payload state. " +
                (preserveSharedInitialization ? $"Retained {sharedInitializers!.Length} shared type-initialization trigger(s) at each former call site. " : "") +
                $"Owned domain-slot SHA-256: {Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(slot!)))}."));

            bool Read(bool invoke, string? expectedSlot, out string? state, out string? actualSlot, out string reason)
            {
                state = null; actualSlot = expectedSlot; reason = "";
                if (!BootstrapMachine.TrySeed(context, budget, out var machine, out reason) || machine is null) return false;
                var work = new StaticWorkBudget(budget);
                if (context.Module.GlobalType.FindStaticConstructor() is { HasBody: true } cctor)
                {
                    var initialized = machine.Execute(cctor, [], work);
                    if (!initialized.Succeeded) { reason = "module initialization did not complete: " + initialized.Diagnostic; return false; }
                }
                if (invoke)
                {
                    var entered = new List<MethodDef>();
                    machine.FrameEntered = (method, _) =>
                    {
                        if (method.IsStaticConstructor && dependencies.Contains(method.DeclaringType) &&
                            !owned.Contains(method.DeclaringType) && !entered.Contains(method)) entered.Add(method);
                    };
                    if (!machine.Execute(candidate.Resolver, [StaticValue.FromInt32(candidate.Answers.Keys.First())], work).Succeeded ||
                        !machine.State.Heap.TryGetString(machine.State.ReadStaticField(keys[0]), out actualSlot) || string.IsNullOrEmpty(actualSlot) ||
                        expectedSlot is not null && actualSlot != expectedSlot)
                    { reason = "lookup initialization or domain key is not stable"; return false; }
                    var reads = DecodedResourceOwnership.ObservedOwnedReads(context, machine.State.LoaderEvidence, owned);
                    if (observedResources is null) observedResources = reads;
                    else resourceReadsAgree &= observedResources.SequenceEqual(reads);
                    if (sharedInitializers is null) sharedInitializers = entered.ToArray();
                    else if (!sharedInitializers.SequenceEqual(entered))
                    { reason = "shared initialization order differs between independent startups"; return false; }
                }
                else if (preserveSharedInitialization)
                {
                    foreach (var initializer in sharedInitializers!)
                    {
                        var status = machine.State.GetTypeInitializationStatus(initializer.DeclaringType);
                        if (status == TypeInitializationStatus.Initialized) continue;
                        if (status != TypeInitializationStatus.Uninitialized || !machine.Execute(initializer, [], work).Succeeded)
                        { reason = "preserved shared initialization did not complete"; return false; }
                    }
                }
                if (actualSlot is null) return false;
                var snapshot = new RebuiltMethodTrial.Snapshot(machine.State.Heap, metadata, new HashSet<string>(StringComparer.Ordinal) { actualSlot });
                var values = context.Module.GetTypes().Where(t => !owned.Contains(t)).SelectMany(t => t.Fields).Where(f => f.IsStatic)
                    .OrderBy(f => f.FullName, StringComparer.Ordinal).ToDictionary(f => f.FullName, f => snapshot.Read(machine.State.ReadStaticField(f)));
                values.Add("$domain", snapshot.ReadDomainState(machine.State));
                values.Add("$network", snapshot.ReadNetworkSettings(machine.State));
                values.Add("$native", snapshot.ReadNativeState(machine.State));
                if (values.Values.Any(v => v is null)) { reason = snapshot.Failure ?? "incomplete state snapshot"; return false; }
                if (!machine.State.TryGetOrAllocateRuntimeSingleton("System.AppDomain", out var domain)) return false;
                if (machine.State.Heap.TryGetModelValue(domain, "Data:" + actualSlot, out StaticValue table) && snapshot.Captures(table))
                { reason = "the string table escapes into application state"; return false; }
                if (snapshot.MetadataHandles.Any(handle => handle switch
                    {
                        TypeDef type => owned.Contains(type),
                        MethodDef method => owned.Contains(method.DeclaringType),
                        FieldDef field => owned.Contains(field.DeclaringType),
                        _ => false
                    }))
                { reason = "string machinery metadata escapes into application state"; return false; }
                var registrations = machine.State.LoaderEvidence.Effects.Values.SelectMany(e => e.Registrations)
                    .Where(r => r != "AppDomain.SetData").Order(StringComparer.Ordinal).ToArray();
                state = JsonSerializer.Serialize(new { Values = values, Registrations = registrations,
                    Payloads = machine.State.CapturedAssemblyLoads.Select(bytes => Convert.ToHexStringLower(SHA256.HashData(bytes))).ToArray() });
                return true;
            }
        }
        if (removedTypes.Count != 0) context.SetFact<IReadOnlySet<uint>>(TypesFact, removedTypes);
        return (notes.Count == 0 ? PassStatus.Success : PassStatus.Partial, changes,
            [ $"Removed {changes} retained string-lookup call(s); attributed {removedTypes.Count} exclusively owned string type(s) for cleanup.", .. notes ]);
    }

    private static void Rewrite(IEnumerable<(MethodDef Method, Instruction Call, Instruction Discard)> sites)
    {
        foreach (var site in sites)
        {
            site.Call.OpCode = OpCodes.Pop; site.Call.Operand = null;
            site.Discard.OpCode = OpCodes.Nop; site.Discard.Operand = null;
        }
    }

    private static void PreserveInitialization(ModuleDef module,
        IEnumerable<(MethodDef Method, Instruction Call, Instruction Discard)> sites, IEnumerable<MethodDef> initializers)
    {
        var run = new MemberRefUser(module, "RunClassConstructor",
            MethodSig.CreateStatic(module.CorLibTypes.Void, VirtualLift.Handle(module, "RuntimeTypeHandle")),
            module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "RuntimeHelpers"));
        foreach (var site in sites)
        {
            var at = site.Method.Body.Instructions.IndexOf(site.Call) + 1;
            foreach (var initializer in initializers)
            {
                site.Method.Body.Instructions.Insert(at++, OpCodes.Ldtoken.ToInstruction(initializer.DeclaringType));
                site.Method.Body.Instructions.Insert(at++, OpCodes.Call.ToInstruction(run));
            }
            site.Method.Body.KeepOldMaxStack = false;
            site.Method.Body.SimplifyBranches();
        }
    }

    private static string Difference(string? left, string? right)
    {
        if (left is null || right is null) return "a state snapshot is unavailable";
        using var before = JsonDocument.Parse(left);
        using var after = JsonDocument.Parse(right);
        foreach (var section in before.RootElement.EnumerateObject())
        {
            var other = after.RootElement.GetProperty(section.Name);
            if (section.Value.GetRawText() == other.GetRawText()) continue;
            if (section.Value.ValueKind == JsonValueKind.Object)
                foreach (var value in section.Value.EnumerateObject())
                    if (value.Value.GetRawText() != other.GetProperty(value.Name).GetRawText())
                        return section.Name + "/" + value.Name + " differs";
            return section.Name + " differs";
        }
        return "repeated startup differs";
    }

    private static bool TrySites(Candidate candidate, HashSet<TypeDef> owned, MethodDef[] methods,
        out List<(MethodDef Method, Instruction Call, Instruction Discard)> sites)
    {
        sites = [];
        foreach (var method in methods.Where(m => !owned.Contains(m.DeclaringType)))
        {
            var il = method.Body.Instructions;
            var entries = il.SelectMany(i => i.Operand is Instruction one ? [one] : i.Operand as IList<Instruction> ?? []).ToHashSet();
            foreach (var eh in method.Body.ExceptionHandlers)
                foreach (var edge in new[] { eh.TryStart, eh.TryEnd, eh.HandlerStart, eh.HandlerEnd, eh.FilterStart })
                    if (edge is not null) entries.Add(edge);
            for (var at = 0; at < il.Count; at++)
            {
                var call = il[at];
                if (call.Operand is not IMethod reference || reference.ResolveMethodDef() is not { } target || !candidate.Aliases.Contains(target)) continue;
                if (call.OpCode.Code != Code.Call || at > 0 && il[at - 1].OpCode.OpCodeType == OpCodeType.Prefix ||
                    !StringOffsetSlicer.TryEvaluate(method, at, new Dictionary<uint, int>(), out var key, out _) || !candidate.Answers.TryGetValue(key, out var answer)) return false;
                var next = at + 1;
                while (next < il.Count && il[next].OpCode.Code == Code.Nop && !entries.Contains(il[next])) next++;
                if (next >= il.Count || entries.Contains(il[next]) || il[next].OpCode.Code != Code.Pop) return false;
                var discard = il[next++];
                while (next < il.Count && il[next].OpCode.Code == Code.Nop && !entries.Contains(il[next])) next++;
                if (next >= il.Count || entries.Contains(il[next]) || il[next].OpCode.Code != Code.Ldstr || (string)il[next].Operand != answer) return false;
                sites.Add((method, call, discard));
            }
        }
        return true;
    }
}

/// <summary>Rechecks string ownership after numeric and runtime consumers have been removed.</summary>
public sealed class StringLookupFinalizationPass : StringLookupCompletionPass
{
    internal const string ChangedFact = "strings.finalizationChanged";
    public override string Name => "string-lookup-finalization";
    public override IReadOnlyCollection<string> Dependencies => ["loader-runtime-cleanup"];
    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var result = base.Execute(context);
        context.SetFact(ChangedFact, result.Item2 != 0);
        return result;
    }
}
