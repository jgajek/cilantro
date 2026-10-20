using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Recovery;

/// <summary>Reads closed, initializer-owned numeric tables without executing sample code.</summary>
public class NumericTableRecoveryPass : DeobfuscationPass
{
    public override string Name => "numeric-tables";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => ["constant-strings"];
    protected virtual bool RevisitModuleInitialization => false;
    protected virtual bool ProveConstructedValues => false;
    internal const string AddedInitializationMethodsFact = "numeric.addedInitializationMethodCount";
    internal const string InitializationBridgesFact = "numeric.initializationBridges";
    internal sealed record InitializationBridge(MethodDef Method, FieldDef Holder);

    private sealed record Getter(MethodDef Method, FieldDef Holder, FieldDef Table);

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var methods = context.Module.GetTypes().SelectMany(t => t.Methods).ToArray();
        var getters = methods.Select(ReadGetter).OfType<Getter>().ToArray();
        var rejected = new List<string>();
        var graphInputs = new Dictionary<FieldDef, SharedGraphReadOnly.Result>();
        getters = getters.Where(g =>
        {
            var accepted = Closed(g, getters, methods, out var reason);
            if (accepted) accepted = ReadOnlyConstructionInputs(g, graphInputs, out reason);
            if (!accepted) rejected.Add($"{g.Method.MDToken}: {reason}");
            return accepted;
        }).ToArray();
        if (getters.Length == 0) return (PassStatus.Success, 0, ["No closed numeric-table getter was found.", .. rejected.Take(8)]);
        var byMethod = getters.ToDictionary(g => g.Method);
        var sites = new List<(MethodDef Caller, Instruction Key, Instruction Call, Getter Getter, int Index)>();
        foreach (var method in methods.Where(m => m.HasBody))
        {
            var targeted = new HashSet<Instruction>();
            foreach (var instruction in method.Body.Instructions)
            {
                if (instruction.Operand is Instruction target) targeted.Add(target);
                if (instruction.Operand is IList<Instruction> targets) targeted.UnionWith(targets);
            }
            foreach (var handler in method.Body.ExceptionHandlers)
                foreach (var boundary in new[] { handler.TryStart, handler.TryEnd, handler.HandlerStart, handler.HandlerEnd, handler.FilterStart })
                    if (boundary is not null) targeted.Add(boundary);
            var instructions = method.Body.Instructions;
            for (var i = 1; i < instructions.Count; i++)
                if (instructions[i].OpCode.Code == Code.Call && instructions[i].Operand is IMethod called &&
                    called.ResolveMethodDef() is { } definition && byMethod.TryGetValue(definition, out var getter) &&
                    LiteralCallArgument.Int32(instructions, i, targeted) is { } key)
                    sites.Add((method, key, instructions[i], getter, key.GetLdcI4Value()));
        }
        var asks = sites.Select(s => (s.Getter, s.Index)).Distinct().Take(2048).ToArray();
        if (asks.Length == 0) return (PassStatus.Success, 0, ["Numeric table calls did not supply literal indexes."]);
        // Reconstructed initializers can expose an integrity check that early bootstrap
        // could not reach. Revisit the existing file-refusal policy, but discard this
        // machine: constants still require two fresh, host-independent executions below.
        if (RevisitModuleInitialization)
            BootstrapMachine.TryRunInitializers(context, 4_000_000, out _, out _);
        if (!BootstrapMachine.TrySeed(context, 4_000_000, out var first, out var why) || first is null ||
            !BootstrapMachine.TrySeed(context, 4_000_000, out var second, out why) || second is null)
            return (PassStatus.Partial, 0, [why]);
        // Constant rewrites must not bake the run's assumed or declared host into
        // the assembly. Only module bytes and deterministic interpreted operations
        // may supply these values; executed ambient reads stop either machine.
        first.State.RegisterRunEnvironment(new RunEnvironment(new HostEnvironment(HostProfile.Empty)));
        second.State.RegisterRunEnvironment(new RunEnvironment(new HostEnvironment(HostProfile.Empty)));
        var refusals = new HashSet<string>();
        var initializationFields = InitializationFields(context.Module, methods);
        var preserve = new HashSet<Getter>();
        var preservable = new HashSet<Getter>();
        // Give loader cleanup the first opportunity to make initialization inert.
        // Preserving its effects too early can strand otherwise removable dispatchers.
        var constructedValues = ProveConstructedValues ? new Dictionary<TypeDef, ClosedInitializerValues.Result>() : null;
        foreach (var getter in getters)
        {
            if (CanPreserveInitialization(getter, initializationFields) ||
                IndependentConstruction(getter, initializationFields, constructedValues, out var dependency)) preservable.Add(getter);
            else refusals.Add($"{getter.Method.MDToken}: initialization dependency proof refused: {dependency}");
        }
        var forward = Read(first, asks, refusals, initializationFields, preservable, preserve);
        var reverse = Read(second, asks.Reverse(), refusals, initializationFields, preservable, preserve);
        foreach (var getter in getters)
        {
            var missing = asks.Where(a => a.Getter == getter &&
                (forward.GetValueOrDefault(a) is null || reverse.GetValueOrDefault(a) is null)).Select(a => a.Index).ToArray();
            if (missing.Length == 0 || getter.Method.ReturnType.ElementType != ElementType.I4 || FinalConstruction(getter) is not { } constructor) continue;
            var initializer = getter.Holder.DeclaringType.FindStaticConstructor();
            var isolatedForward = ClosedTableConstruction.Read(context, initializer, constructor, getter.Holder, getter.Method, missing);
            var isolatedReverse = ClosedTableConstruction.Read(context, initializer, constructor, getter.Holder, getter.Method, missing.Reverse());
            foreach (var index in missing)
                if (isolatedForward.TryGetValue(index, out var value) && isolatedReverse.TryGetValue(index, out var other) && value == other)
                {
                    forward[(getter, index)] = StaticValue.FromInt32(value);
                    reverse[(getter, index)] = StaticValue.FromInt32(other);
                    preserve.Add(getter);
                }
        }
        using var transaction = new BodyMutationBatch();
        var bridges = new Dictionary<Getter, MethodDef>();
        var folded = new HashSet<MethodDef>();
        var changes = 0;
        foreach (var site in sites)
        {
            var key = (site.Getter, site.Index);
            if (!forward.TryGetValue(key, out var value) || value is null ||
                !reverse.TryGetValue(key, out var other) || other != value) continue;
            if (preserve.Contains(site.Getter) && (site.Caller.DeclaringType == site.Getter.Holder.DeclaringType || site.Caller.IsStaticConstructor)) continue;
            var bridgeRequired = preserve.Contains(site.Getter) && NeedsInitializationBridge(site.Getter.Holder);
            if (bridgeRequired && site.Getter.Method.DeclaringType.HasGenericParameters) continue;
            transaction.Capture(site.Caller);
            site.Key.OpCode = OpCodes.Nop; site.Key.Operand = null;
            if (bridgeRequired)
            {
                if (!bridges.TryGetValue(site.Getter, out var bridge))
                {
                    var owner = site.Getter.Method.DeclaringType;
                    var name = "InitializeNumericTable";
                    while (owner.Methods.Any(m => m.Name == name) || bridges.Values.Any(m => m.Name == name)) name += "_";
                    bridge = new MethodDefUser(name, MethodSig.CreateStatic(context.Module.CorLibTypes.Void),
                        MethodAttributes.Assembly | MethodAttributes.Static) { Body = new CilBody() };
                    bridge.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(site.Getter.Holder));
                    bridge.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
                    bridge.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                    bridges.Add(site.Getter, bridge);
                }
                // Keep the read in the getter's original access context. Calling a
                // sibling method preserves both owners' initialization triggers.
                site.Key.OpCode = OpCodes.Call; site.Key.Operand = bridge;
            }
            else if (preserve.Contains(site.Getter))
            {
                // Keep the actual field access that triggered initialization. This also
                // preserves beforefieldinit timing instead of forcing its initializer.
                var il = site.Caller.Body.Instructions;
                var insert = il.IndexOf(site.Key) + 1;
                var getterOwner = site.Getter.Method.DeclaringType;
                if (getterOwner != site.Getter.Holder.DeclaringType && !getterOwner.IsBeforeFieldInit &&
                    getterOwner.FindStaticConstructor() is not null)
                {
                    site.Key.OpCode = OpCodes.Ldtoken; site.Key.Operand = getterOwner;
                    var helper = new MemberRefUser(context.Module, "RunClassConstructor",
                        MethodSig.CreateStatic(context.Module.CorLibTypes.Void, VirtualLift.Handle(context.Module, "RuntimeTypeHandle")),
                        context.Module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "RuntimeHelpers"));
                    il.Insert(insert++, OpCodes.Call.ToInstruction(helper));
                    il.Insert(insert++, OpCodes.Ldsfld.ToInstruction(site.Getter.Holder));
                }
                else { site.Key.OpCode = OpCodes.Ldsfld; site.Key.Operand = site.Getter.Holder; }
                il.Insert(insert, OpCodes.Pop.ToInstruction());
                site.Caller.Body.KeepOldMaxStack = false;
                site.Caller.Body.SimplifyBranches();
            }
            (site.Call.OpCode, site.Call.Operand) = value.Value.Kind switch
            {
                StaticValueKind.Int32 => (OpCodes.Ldc_I4, (object)value.Value.AsInt32()),
                StaticValueKind.Int64 => (OpCodes.Ldc_I8, (object)value.Value.AsInt64()),
                StaticValueKind.Float32 => (OpCodes.Ldc_R4, (object)value.Value.AsFloat32()),
                StaticValueKind.Float64 => (OpCodes.Ldc_R8, (object)value.Value.AsFloat64()),
                _ => throw new InvalidOperationException("Non-numeric table result escaped validation.")
            };
            transaction.RecordChange(context, new ChangeRecord(Name, "restore-numeric-constant",
                $"{site.Caller.MDToken} IL_{site.Call.Offset:X4}", $"Recovered {value.Value.Kind} constant, bits 0x{value.Value.Bits:X16}."));
            folded.Add(site.Getter.Method);
            changes++;
        }
        var committed = false;
        try
        {
            foreach (var (getter, bridge) in bridges)
            {
                getter.Method.DeclaringType.Methods.Add(bridge);
            }
            if (!AssemblyVerifier.Verify(context.Module).Passed)
                return (PassStatus.Partial, 0, ["Numeric rewrites failed verification and were rolled back."]);
            transaction.Commit();
            committed = true;
        }
        finally
        {
            if (!committed)
                foreach (var (getter, bridge) in bridges) getter.Method.DeclaringType.Methods.Remove(bridge);
        }
        context.TryGetFact<int>(AddedInitializationMethodsFact, out var previousBridges);
        context.SetFact(AddedInitializationMethodsFact, previousBridges + bridges.Count);
        if (bridges.Count != 0)
        {
            context.TryGetFact<List<InitializationBridge>>(InitializationBridgesFact, out var recorded);
            recorded ??= [];
            recorded.AddRange(bridges.Select(p => new InitializationBridge(p.Value, p.Key.Holder)));
            context.SetFact(InitializationBridgesFact, recorded);
        }
        // Recovery identifies the closed numeric table, not only the element kinds
        // that happened to have call sites. Unused sibling accessors are equally
        // attributable. Reachability still protects siblings with surviving callers.
        var recoveredHolders = getters.Where(g => folded.Contains(g.Method)).Select(g => g.Holder).ToHashSet();
        RecoveryOrphans.DeclareSubtree(context, getters.Where(g => recoveredHolders.Contains(g.Holder)).Select(g => g.Method));
        foreach (var getter in getters.Where(g => recoveredHolders.Contains(g.Holder)))
            RecoveryOrphans.Declare(context, getter.Method.DeclaringType.Methods
                .Where(m => IsNumericArrayWrapper(m, getter.Holder.DeclaringType)));
        RecordResourceOwners(context, first.State.LoaderEvidence, second.State.LoaderEvidence,
            getters.Where(getter => folded.Contains(getter.Method)).SelectMany(getter => new[]
                { getter.Method.DeclaringType, getter.Holder.DeclaringType, getter.Table.DeclaringType }).ToHashSet());
        context.AddEvidence(new Evidence(Name, $"Replaced {changes} numeric-table reads; independent static interpretations agreed bit-for-bit."));
        return (PassStatus.Success, changes, [$"Recovered {changes} numeric constants from {getters.Length} closed table getter(s).", .. refusals.Take(8)]);
    }

    private static void RecordResourceOwners(ArtifactContext context, LoaderInterpretationEvidence first,
        LoaderInterpretationEvidence second, HashSet<TypeDef> owners)
    {
        if (owners.Count == 0) return;
        var sources = DecodedResourceOwnership.ObservedOwnedReads(context, first, owners)
            .Intersect(DecodedResourceOwnership.ObservedOwnedReads(context, second, owners)).ToArray();
        var methods = owners.SelectMany(owner => owner.Methods).Where(method => method.Rid != 0).ToDictionary(method => method.MDToken.Raw);
        foreach (var source in sources)
        {
            var readers = first.Observations.Concat(second.Observations).Where(observation => observation.Kind == LoaderObservationKind.ManagedResourceRead &&
                    observation.CallStack.Count != 0 && methods.ContainsKey(observation.CallStack[^1]))
                .Where(observation => System.Text.Json.JsonSerializer.Deserialize<ManagedResourceRead>(observation.Detail) is { } read &&
                    read.Name == source.Name && read.Sha256 == source.Sha256)
                .Select(observation => methods[observation.CallStack[^1]]).Distinct().ToArray();
            if (readers.Length == 0) continue;
            DecodedResourceOwnership.Remember(context, source, readers, numericConstruction: true);
            RecoveryOrphans.Declare(context, readers);
            context.AddEvidence(new("numeric-resource-ownership",
                $"Both closed numeric construction trials read {source.Name} (SHA-256 {source.Sha256}); cleanup still requires physical removal of every observed reader.",
                string.Join(", ", readers.Select(reader => reader.FullName))));
        }
    }

    internal static bool IsNumericArrayWrapper(MethodDef method, TypeDef holder)
    {
        // A sibling packed-array entry point uses the very same recovered numeric
        // reader. This is provenance only: ordinary reachability and reference
        // checks must still establish that nobody uses it before deletion.
        if (!method.IsStatic || !method.HasBody || method.HasGenericParameters ||
            method.MethodSig.Params.Count != 1 || method.MethodSig.Params[0].ElementType != ElementType.Object ||
            method.ReturnType.FullName != "System.Array") return false;
        var calls = method.Body.Instructions.Where(i => i.OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj)
            .Select(i => i.Operand).OfType<IMethod>().ToArray();
        return calls.Any(c => c.FullName == "System.Void System.IO.MemoryStream::.ctor(System.Byte[])" &&
                c.DeclaringType.DefinitionAssembly?.FullName == method.Module.CorLibTypes.AssemblyRef.FullName) &&
            calls.Any(c => c.ResolveMethodDef() is { IsStatic: true } reader && reader.DeclaringType == holder &&
                reader.ReturnType.FullName == "System.Array" && reader.MethodSig.Params.Count == 1 &&
                reader.MethodSig.Params[0].ElementType == ElementType.Object);
    }

    private static Getter? ReadGetter(MethodDef method)
    {
        if (!method.IsStatic || !method.HasBody || method.HasGenericParameters ||
            method.MethodSig.Params.Count != 1 || method.MethodSig.Params[0].ElementType != ElementType.I4 ||
            method.ReturnType.ElementType is not (ElementType.I4 or ElementType.I8 or ElementType.R4 or ElementType.R8) || method.Body.ExceptionHandlers.Count != 0) return null;
        var element = method.ReturnType.ElementType;
        var il = method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        var cast = il.Length == 6 && IsArrayCast(il[2], element);
        if (cast) il = [il[0], il[1], .. il[3..]];
        return il.Length == 5 && il[0].OpCode.Code == Code.Ldsfld && il[1].OpCode.Code == Code.Ldfld &&
            il[2].OpCode.Code == Code.Ldarg_0 && il[3].OpCode.Code == LoadElement(element) && il[4].OpCode.Code == Code.Ret &&
            il[0].Operand is IField holderRef && holderRef.ResolveFieldDef() is { IsInitOnly: true } holder &&
            il[1].Operand is IField tableRef && tableRef.ResolveFieldDef() is { } table &&
            (table.FieldType is SZArraySig array && array.Next.ElementType == element || table.FieldType.ElementType == ElementType.Object) &&
            holder.DeclaringType == table.DeclaringType && holder.Module == method.Module
                ? new(method, holder, table) : null;
    }

    private static bool Closed(Getter getter, Getter[] getters, MethodDef[] methods, out string reason)
    {
        reason = "storage is externally accessible or can be modified outside initialization";
        var owner = getter.Table.DeclaringType;
        if (MemberVisibility.IsExternallyVisible(owner) || owner.FindStaticConstructor() is not { } initializer) return false;
        var initialization = new HashSet<MethodDef>();
        var pending = new Stack<MethodDef>(); pending.Push(initializer);
        while (pending.TryPop(out var method))
        {
            if (!initialization.Add(method) || !method.HasBody) continue;
            foreach (var instruction in method.Body.Instructions)
                if (instruction.Operand is IMethod called && called.ResolveMethodDef() is { } target && target.DeclaringType == owner)
                    pending.Push(target);
        }
        var readers = getters.Where(g => g.Table == getter.Table).Select(g => g.Method).ToHashSet();
        foreach (var method in initialization.Where(m => m.HasBody))
            if (!ArrayStaysPrivate(method, getter.Table, element: getter.Method.ReturnType.ElementType)) { reason = $"array privacy could not be established in {method.FullName}"; return false; }
        var holderReaders = methods.Where(m => m.HasBody &&
            (ReadsHolder(m, getter.Holder) || DiscardsHolder(m, getter.Holder))).ToHashSet();
        foreach (var method in methods.Where(m => m.HasBody))
            foreach (var instruction in method.Body.Instructions)
            {
                if (instruction.Operand is IField fieldRef && fieldRef.ResolveFieldDef() is { } field &&
                    (field == getter.Table || field == getter.Holder && !holderReaders.Contains(method)) &&
                    !initialization.Contains(method) && !readers.Contains(method)) return false;
                if (instruction.Operand is IMethod call && call.ResolveMethodDef() is { } target &&
                    initialization.Contains(target) && !initialization.Contains(method)) return false;
                // A runtime type handle can expose private storage to reflection.
                if (instruction.OpCode.Code == Code.Ldtoken && instruction.Operand is ITypeDefOrRef type &&
                    type.ResolveTypeDef() == owner) return false;
            }
        return true;
    }

    private static Code LoadElement(ElementType element) => element switch
    {
        ElementType.I4 => Code.Ldelem_I4, ElementType.I8 => Code.Ldelem_I8,
        ElementType.R4 => Code.Ldelem_R4, ElementType.R8 => Code.Ldelem_R8,
        _ => Code.UNKNOWN1
    };

    private static Code StoreElement(ElementType element) => element switch
    {
        ElementType.I4 => Code.Stelem_I4, ElementType.I8 => Code.Stelem_I8,
        ElementType.R4 => Code.Stelem_R4, ElementType.R8 => Code.Stelem_R8,
        _ => Code.UNKNOWN1
    };

    private static bool ArrayStaysPrivate(MethodDef method, FieldDef table, bool readOnly = false, ElementType element = ElementType.I4)
    {
        var il = method.Body.Instructions.ToArray();
        var targets = method.Body.Instructions.SelectMany(i => i.Operand switch
        {
            Instruction target => new[] { target },
            IList<Instruction> many => many,
            _ => Array.Empty<Instruction>()
        }).ToHashSet();
        for (var at = 0; at < il.Length; at++)
        {
            if (il[at].Operand is not IField reference || reference.ResolveFieldDef() != table) continue;
            if (il[at].OpCode.Code is Code.Stfld or Code.Stsfld)
            {
                if (readOnly) return false;
                // A fresh array goes straight into the field; no duplicated reference can
                // have been published elsewhere before that store.
                var previous = at - 1;
                if (targets.Contains(il[at])) return false;
                while (previous >= 0 && il[previous].OpCode.Code == Code.Nop)
                {
                    if (targets.Contains(il[previous])) return false;
                    previous--;
                }
                if (previous < 0 || il[previous].OpCode.Code != Code.Newarr) return false;
                if (table.FieldType.ElementType == ElementType.Object &&
                    (il[previous].Operand is not ITypeDefOrRef arrayElement || arrayElement.ToTypeSig().ElementType != element)) return false;
                continue;
            }
            if (il[at].OpCode.Code != (table.IsStatic ? Code.Ldsfld : Code.Ldfld)) return false;
            var stack = new Stack<bool>(); stack.Push(true);
            var consumed = false;
            for (var scan = at + 1; scan < il.Length && scan <= at + 64; scan++)
            {
                var instruction = il[scan];
                if (targets.Contains(instruction) || instruction.OpCode.FlowControl is
                    FlowControl.Branch or FlowControl.Cond_Branch or FlowControl.Return or FlowControl.Throw) return false;
                instruction.CalculateStackUsage(out var pushes, out var pops);
                if (pops < 0 || pushes < 0) return false;
                var usedArray = false;
                for (var count = 0; count < pops; count++)
                    if (stack.TryPop(out var array) && array)
                    {
                        if (count != pops - 1) return false;
                        usedArray = true;
                    }
                if (usedArray)
                {
                    // A cast preserves the array identity. Keep following it until an
                    // element operation consumes it; a cast must not hide an escape.
                    if (IsArrayCast(instruction, element))
                    { stack.Push(true); continue; }
                    if (readOnly ? instruction.OpCode.Code is not (Code.Ldelem_I1 or Code.Ldelem_U1 or Code.Ldelem_I2 or Code.Ldelem_U2 or Code.Ldelem_I4 or Code.Ldelem_U4 or Code.Ldelem_I8 or Code.Ldelem_R4 or Code.Ldelem_R8 or Code.Ldlen)
                        : instruction.OpCode.Code != StoreElement(element) && instruction.OpCode.Code != LoadElement(element) && instruction.OpCode.Code != Code.Ldlen) return false;
                    consumed = true;
                    break;
                }
                for (var count = 0; count < pushes; count++) stack.Push(false);
            }
            if (!consumed) return false;
        }
        return true;
    }

    // A lazily initialized decompressor may set up its own immutable lookup tables.
    // Dropping that trigger is harmless only when every static write is confined to
    // the declaring type's initializer: any later field access triggers it itself.
    private static HashSet<string> InitializationFields(ModuleDef module, MethodDef[] methods)
    {
        var allowed = module.GetTypes().SelectMany(t => t.Fields).Where(f => f.IsStatic).ToHashSet();
        foreach (var method in methods.Where(m => m.HasBody))
            foreach (var instruction in method.Body.Instructions)
                if (instruction.Operand is IField fieldRef && fieldRef.ResolveFieldDef() is { } field &&
                    (instruction.OpCode.Code == Code.Ldsflda || instruction.OpCode.Code == Code.Stsfld &&
                     (!method.IsStaticConstructor || method.DeclaringType != field.DeclaringType)))
                    allowed.Remove(field);
        return allowed.Select(f => f.FullName).ToHashSet(StringComparer.Ordinal);
    }

    private static bool NeedsInitializationBridge(FieldDef field)
    {
        if (!(field.IsPublic || field.IsAssembly || field.IsFamilyOrAssembly)) return true;
        for (var type = field.DeclaringType; type.IsNested; type = type.DeclaringType)
            if (!(type.IsNestedPublic || type.IsNestedAssembly || type.IsNestedFamilyOrAssembly)) return true;
        return false;
    }

    private static bool ReadOnlyConstructionInputs(Getter getter, Dictionary<FieldDef, SharedGraphReadOnly.Result> graphs, out string reason)
    {
        reason = "shared construction input closure exceeded its bound";
        var owner = getter.Holder.DeclaringType;
        var pending = new Stack<MethodDef>(owner.Methods.Where(m => m.IsInstanceConstructor));
        var seen = new HashSet<MethodDef>();
        while (pending.TryPop(out var method))
        {
            if (!seen.Add(method)) continue;
            if (seen.Count > 512) return false;
            if (!method.HasBody) continue;
            foreach (var instruction in method.Body.Instructions)
            {
                if (instruction.OpCode.Code == Code.Ldsfld && instruction.Operand is IField reference &&
                    reference.ResolveFieldDef() is { } field && field != getter.Holder &&
                    field.FieldType.ToTypeDefOrRef()?.ResolveTypeDef() is { IsValueType: false } type && type.Module == owner.Module)
                {
                    if (type.BaseType?.FullName == "System.MulticastDelegate")
                    {
                        if (ReadonlyDelegateBinding.Target(field) is { } target) pending.Push(target);
                        continue;
                    }
                    if (!graphs.TryGetValue(field, out var graph)) graphs[field] = graph = SharedGraphReadOnly.Check(field);
                    if (!graph.Passed)
                    {
                        reason = $"shared reference consumers are not closed for {field.FullName}: {graph.Detail}";
                        return false;
                    }
                }
                if (instruction.OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj && instruction.Operand is IMethod called &&
                    called.ResolveMethodDef() is { } callee && callee.Module == owner.Module) pending.Push(callee);
            }
        }
        return true;
    }

    // Preserve effects only when the values cannot depend on mutable external static
    // inputs. Follow local calls and triggered type initializers; unknown reads refuse.
    private static bool CanPreserveInitialization(Getter getter, HashSet<string> immutable)
    {
        var owner = getter.Holder.DeclaringType;
        if (getter.Method.DeclaringType != owner) return false;
        for (var type = owner; type is not null; type = type.DeclaringType)
            if (type.HasGenericParameters) return false;
        var pending = new Stack<MethodDef>(); pending.Push(owner.FindStaticConstructor());
        var seen = new HashSet<MethodDef>();
        while (pending.TryPop(out var method))
        {
            if (!seen.Add(method)) continue;
            if (!method.HasBody || seen.Count > 512) return false;
            foreach (var instruction in method.Body.Instructions)
            {
                if (instruction.Operand is IField reference)
                {
                    var field = reference.ResolveFieldDef();
                    if (instruction.OpCode.Code == Code.Ldsflda) return false;
                    if (instruction.OpCode.Code == Code.Ldsfld &&
                        (field is null || !immutable.Contains(field.FullName))) return false;
                    if (field?.DeclaringType.FindStaticConstructor() is { } init) pending.Push(init);
                }
                if (instruction.Operand is IMethod call && call.ResolveMethodDef() is { } target && target.Module == owner.Module)
                {
                    pending.Push(target);
                    if (target.DeclaringType.FindStaticConstructor() is { } init) pending.Push(init);
                }
                if (instruction.OpCode.Code == Code.Calli) return false;
            }
        }
        return true;
    }

    // Slice the holder assignment away from earlier initializer side effects. The
    // initializer is still invoked at each rewritten site; only the newly constructed
    // table's inputs must be closed. Branching initialization and later mutations refuse.
    private static bool IndependentConstruction(Getter getter, HashSet<string> immutable,
        Dictionary<TypeDef, ClosedInitializerValues.Result>? constructedValues, out string reason)
    {
        reason = "initializer timing, generic context or exception regions are not closed";
        var owner = getter.Holder.DeclaringType;
        if (owner.HasGenericParameters ||
            getter.Method.DeclaringType.HasGenericParameters ||
            owner.FindStaticConstructor() is not { HasBody: true } initializer ||
            initializer.Body.ExceptionHandlers.Count != 0) return false;
        reason = "holder is not the final straight-line, unique parameterless construction";
        var il = StraightLine(initializer);
        if (il is null || il.Length < 3 ||
            il[^1].OpCode.Code != Code.Ret || il[^2].OpCode.Code != Code.Stsfld ||
            il[^2].Operand is not IField holder || holder.ResolveFieldDef() != getter.Holder ||
            il[^3].OpCode.Code != Code.Newobj || il[^3].Operand is not IMethod constructed ||
            constructed.ResolveMethodDef() is not { HasBody: true } constructor ||
            constructor.DeclaringType != owner || constructor.MethodSig.Params.Count != 0 ||
            il.Count(i => i.Operand is IField f && f.ResolveFieldDef() == getter.Holder) != 1) return false;
        var pending = new Stack<(MethodDef Method, string Path)>(); pending.Push((constructor, constructor.FullName));
        var seen = new HashSet<MethodDef>();
        var literalFields = new Dictionary<FieldDef, bool>();
        var delegates = new Dictionary<FieldDef, MethodDef?>();
        while (pending.TryPop(out var item))
        {
            var (method, path) = item;
            if (!seen.Add(method)) continue;
            reason = $"unreadable or over-budget dependency {method.FullName}";
            if (!method.HasBody || seen.Count > 256 || method.HasGenericParameters) return false;
            foreach (var instruction in method.Body.Instructions)
            {
                reason = $"indirect dependency {method.FullName} IL_{instruction.Offset:X4}";
                if (instruction.OpCode.Code is Code.Calli or Code.Ldsflda or Code.Ldftn or Code.Ldvirtftn) return false;
                if (instruction.OpCode.Code == Code.Ldsfld && instruction.Operand is IField reference)
                {
                    reason = $"unresolved mutable static read {reference.FullName}; conservative dependency path: {path} (not proof the table value depends on this read)";
                    if (reference.ResolveFieldDef() is not { } field || !immutable.Contains(field.FullName)) return false;
                    if (!delegates.TryGetValue(field, out var bound))
                        delegates[field] = bound = ReadonlyDelegateBinding.Target(field);
                    if (bound is not null)
                    {
                        pending.Push((bound, Extend(path, "readonly delegate target", bound)));
                        continue;
                    }
                    // A literal lookup table can have unrelated loader work before its
                    // assignment. Prove its complete value expression instead of following
                    // that unrelated work as a dependency of every array element.
                    if (!literalFields.TryGetValue(field, out var literal))
                        literalFields[field] = literal = LiteralInitializerField(field);
                    if (literal) continue;
                    if (constructedValues is not null)
                    {
                        if (!constructedValues.TryGetValue(field.DeclaringType, out var values))
                            constructedValues[field.DeclaringType] = values = ClosedInitializerValues.Check(field.DeclaringType);
                        if (values.Passed && values.Fields.Contains(field)) continue;
                    }
                    if (field.DeclaringType.FindStaticConstructor() is { } init) pending.Push((init, Extend(path, "field initializer", init)));
                }
                if (instruction.OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj && instruction.Operand is IMethod called)
                {
                    if (called.ResolveMethodDef() is { } target && target.Module == owner.Module)
                    {
                        reason = $"virtual dispatch {target.FullName}";
                        // Unknown dispatch could introduce dependencies outside this slice.
                        if (instruction.OpCode.Code == Code.Callvirt && target.IsVirtual)
                        {
                            var receiver = ReadonlyDelegateBinding.Receiver(method, instruction);
                            if (receiver is null) return false;
                            if (!delegates.TryGetValue(receiver, out var bound))
                                delegates[receiver] = bound = ReadonlyDelegateBinding.Target(receiver);
                            if (bound is null) return false;
                            pending.Push((bound, Extend(path, "readonly delegate invocation", bound)));
                            continue;
                        }
                        pending.Push((target, Extend(path, "call", target)));
                    }
                    else if (called.DeclaringType?.ResolveTypeDef()?.Module == owner.Module) return false;
                }
            }
        }
        return true;
    }

    private static MethodDef? FinalConstruction(Getter getter)
    {
        var owner = getter.Holder.DeclaringType;
        for (var type = owner; type is not null; type = type.DeclaringType)
            if (type.HasGenericParameters) return null;
        for (var type = getter.Method.DeclaringType; type is not null; type = type.DeclaringType)
            if (type.HasGenericParameters) return null;
        if (owner.FindStaticConstructor() is not { HasBody: true } initializer ||
            initializer.Body.ExceptionHandlers.Count != 0 || StraightLine(initializer) is not { Length: >= 3 } il ||
            il[^1].OpCode.Code != Code.Ret || il[^2].OpCode.Code != Code.Stsfld ||
            il[^2].Operand is not IField holder || holder.ResolveFieldDef() != getter.Holder ||
            il[^3].OpCode.Code != Code.Newobj || il[^3].Operand is not IMethod reference ||
            reference.ResolveMethodDef() is not { HasBody: true } constructor ||
            constructor.DeclaringType != owner || constructor.MethodSig.Params.Count != 0 ||
            il.Count(i => i.Operand is IField field && field.ResolveFieldDef() == getter.Holder) != 1) return null;
        if (!ClosedTableConstruction.SafePrefix(initializer, il[..^3])) return null;
        return constructor;
    }

    private static string Extend(string path, string edge, MethodDef method) =>
        (path.Length > 1600 ? "..." + path[^1600..] : path) + $" -> {edge} {method.FullName}";

    internal static bool LiteralInitializerField(FieldDef field)
    {
        if (!field.IsInitOnly || MemberVisibility.IsExternallyVisible(field.DeclaringType) ||
            field.DeclaringType.FindStaticConstructor() is not { HasBody: true } initializer ||
            initializer.Body.ExceptionHandlers.Count != 0 || StraightLine(initializer) is not { } il) return false;
        var stores = il.Select((instruction, index) => (instruction, index)).Where(x =>
            x.instruction.OpCode.Code == Code.Stsfld && x.instruction.Operand is IField f && f.ResolveFieldDef() == field).ToArray();
        if (stores.Length != 1) return false;
        var end = stores[0].index;
        var needed = 1;
        var start = end;
        while (start > 0 && needed > 0 && end - start < 4096)
        {
            var instruction = il[--start];
            instruction.CalculateStackUsage(out var pushes, out var pops);
            if (pops < 0 || pushes < 0 || !Literal(instruction)) return false;
            needed = Math.Max(0, needed - pushes) + pops;
        }
        if (needed != 0) return false;
        var depth = 0;
        foreach (var instruction in il[start..end])
        {
            instruction.CalculateStackUsage(out var pushes, out var pops);
            if (depth < pops) return false;
            depth += pushes - pops;
        }
        // No alias remains on the stack after publishing the array.
        if (depth != 1) return false;
        foreach (var method in field.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
        {
            if (method.Body.Instructions.Any(i => i.OpCode.Code == Code.Ldtoken &&
                (i.Operand is IField f && f.ResolveFieldDef() == field ||
                 i.Operand is ITypeDefOrRef t && t.ResolveTypeDef() == field.DeclaringType))) return false;
            if (method == initializer) continue;
            if (field.FieldType is SZArraySig)
            { if (!ArrayStaysPrivate(method, field, readOnly: true)) return false; }
            else if (method.Body.Instructions.Any(i => i.Operand is IField f && f.ResolveFieldDef() == field && i.OpCode.Code != Code.Ldsfld)) return false;
        }
        if (il.Count(i => i.Operand is IField f && f.ResolveFieldDef() == field) == 1) return true;
        // Some compilers publish a fresh array and then fill it through the field.
        // Admit only literal element stores, with no calls or foreign initialization
        // after publication that could observe or mutate the partially filled array.
        if (field.FieldType is not SZArraySig) return false;
        for (var at = end + 1; at < il.Length; at++)
        {
            var instruction = il[at];
            if (instruction.OpCode.Code is Code.Call or Code.Callvirt or Code.Calli or Code.Newobj or Code.Ldtoken ||
                instruction.Operand is IField other && other.DeclaringType.ResolveTypeDef() != field.DeclaringType) return false;
        }
        for (var at = 0; at < il.Length; at++)
        {
            if (il[at].Operand is not IField reference || reference.ResolveFieldDef() != field || at == end) continue;
            if (at <= end || at + 3 >= il.Length || il[at].OpCode.Code != Code.Ldsfld ||
                !il[at + 1].IsLdcI4() || il[at + 1].GetLdcI4Value() < 0 ||
                !(il[at + 2].IsLdcI4() || il[at + 2].OpCode.Code is Code.Ldc_I8 or Code.Ldc_R4 or Code.Ldc_R8) ||
                il[at + 3].OpCode.Code is not (Code.Stelem_I1 or Code.Stelem_I2 or Code.Stelem_I4 or Code.Stelem_I8 or Code.Stelem_R4 or Code.Stelem_R8)) return false;
        }
        return true;

        bool Literal(Instruction i) => i.IsLdcI4() || i.OpCode.Code is
            Code.Ldc_I8 or Code.Ldc_R4 or Code.Ldc_R8 or Code.Ldnull or Code.Ldstr or Code.Dup or Code.Pop or
            Code.Stelem_I1 or Code.Stelem_I2 or Code.Stelem_I4 or Code.Stelem_I8 or Code.Stelem_R4 or Code.Stelem_R8 ||
            i.OpCode.Code == Code.Newarr && i.Operand is ITypeDefOrRef type && type.FullName is
                "System.Byte" or "System.SByte" or "System.Int16" or "System.UInt16" or "System.Int32" or "System.UInt32" or "System.Int64" or "System.UInt64" or "System.Single" or "System.Double" ||
            i.OpCode.Code == Code.Ldtoken && i.Operand is IField source && source.ResolveFieldDef() is { HasFieldRVA: true } ||
            i.OpCode.Code == Code.Call && i.Operand is IMethod { DeclaringType.FullName: "System.Runtime.CompilerServices.RuntimeHelpers", Name.String: "InitializeArray" } helper &&
            helper.ResolveMethodDef()?.Module != field.Module;
    }

    private static Instruction[]? StraightLine(MethodDef method)
    {
        var body = method.Body.Instructions;
        var positions = body.Select((instruction, index) => (instruction, index)).ToDictionary(x => x.instruction, x => x.index);
        var seen = new HashSet<Instruction>();
        var path = new List<Instruction>();
        for (var at = 0; at < body.Count; at++)
        {
            var instruction = body[at];
            if (!seen.Add(instruction)) return null;
            if (instruction.OpCode.Code is Code.Br or Code.Br_S)
            {
                if (instruction.Operand is not Instruction target || !positions.TryGetValue(target, out var next)) return null;
                at = next - 1;
                continue;
            }
            if (instruction.OpCode.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch or FlowControl.Throw) return null;
            if (instruction.OpCode.Code != Code.Nop) path.Add(instruction);
            if (instruction.OpCode.Code == Code.Ret) return [.. path];
        }
        return null;
    }

    private static bool ReadsHolder(MethodDef method, FieldDef holder)
    {
        var il = method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        if (il.Length == 6 && IsArrayCast(il[2], il[4].OpCode.Code switch
        {
            Code.Ldelem_I4 => ElementType.I4,
            Code.Ldelem_I8 => ElementType.I8,
            Code.Ldelem_R4 => ElementType.R4,
            Code.Ldelem_R8 => ElementType.R8,
            _ => ElementType.End
        }))
            il = [il[0], il[1], .. il[3..]];
        return il.Length == 5 && il[0].OpCode.Code == Code.Ldsfld && il[0].Operand is IField reference &&
            reference.ResolveFieldDef() == holder && il[1].OpCode.Code == Code.Ldfld &&
            il[2].OpCode.Code == Code.Ldarg_0 && il[3].OpCode.Code is Code.Ldelem_I4 or Code.Ldelem_I8 or Code.Ldelem_R4 or Code.Ldelem_R8 &&
            il[4].OpCode.Code == Code.Ret;
    }

    // Earlier constant recovery can retain a field read solely for its type
    // initialization trigger. The reference is immediately discarded, so it
    // cannot expose the table to a writer. This check does not remove that read.
    private static bool DiscardsHolder(MethodDef method, FieldDef holder)
    {
        var il = method.Body.Instructions;
        var targets = il.SelectMany(i => i.Operand is Instruction one ? [one] : i.Operand as IList<Instruction> ?? []).ToHashSet();
        foreach (var eh in method.Body.ExceptionHandlers)
            foreach (var edge in new[] { eh.TryStart, eh.TryEnd, eh.HandlerStart, eh.HandlerEnd, eh.FilterStart })
                if (edge is not null) targets.Add(edge);
        for (var at = 0; at < il.Count; at++)
            if (il[at].Operand is IField reference && reference.ResolveFieldDef() == holder &&
                (il[at].OpCode.Code != Code.Ldsfld || at + 1 >= il.Count || il[at + 1].OpCode.Code != Code.Pop ||
                 targets.Contains(il[at + 1]) || at > 0 && il[at - 1].OpCode.OpCodeType == OpCodeType.Prefix)) return false;
        return true;
    }

    private static bool IsArrayCast(Instruction instruction, ElementType element) =>
        instruction.OpCode.Code == Code.Castclass && instruction.Operand is TypeSpec { TypeSig: SZArraySig array } &&
        array.Next.ElementType == element;

    private static Dictionary<(Getter, int), StaticValue?> Read(StaticMachine machine, IEnumerable<(Getter Getter, int Index)> asks, HashSet<string> refusals, HashSet<string> initializationFields, HashSet<Getter> preservable, HashSet<Getter> preserve)
    {
        var results = new Dictionary<(Getter, int), StaticValue?>();
        var initialized = new Dictionary<Getter, bool>();
        foreach (var (getter, index) in asks)
        {
            if (!initialized.TryGetValue(getter, out var ready))
            {
                var warm = machine.Execute(getter.Method, [StaticValue.FromInt32(index)]);
                var effects = machine.State.LoaderEvidence.EffectsOf(getter.Method.MDToken.Raw);
                var inert = effects.StaticFieldsWritten.All(initializationFields.Contains);
                ready = warm.Succeeded && !effects.WroteMappedImage && !effects.WroteScratchRegion &&
                    effects.Registrations.Count == 0 && (inert || preservable.Contains(getter));
                if (ready && !inert) preserve.Add(getter);
                initialized[getter] = ready;
                if (!ready) refusals.Add($"{getter.Method.MDToken}: {warm.Diagnostic ?? $"initializer effects prevent folding: fields={string.Join(",", effects.StaticFieldsWritten)}, mapped={effects.WroteMappedImage}, scratch={effects.WroteScratchRegion}, registrations={string.Join(",", effects.Registrations)}"}");
            }
            if (!ready) { results[(getter, index)] = null; continue; }
            using var scope = machine.State.Evidence.SetAside(getter.Method.MDToken.Raw);
            var answer = machine.Execute(getter.Method, [StaticValue.FromInt32(index)]);
            var mark = machine.State.LoaderEvidence.EffectsOf(getter.Method.MDToken.Raw);
            var expectedKind = getter.Method.ReturnType.ElementType switch
            {
                ElementType.I4 => StaticValueKind.Int32, ElementType.I8 => StaticValueKind.Int64,
                ElementType.R4 => StaticValueKind.Float32, ElementType.R8 => StaticValueKind.Float64,
                _ => StaticValueKind.Unknown
            };
            results[(getter, index)] = answer.Succeeded && answer.Value.Kind == expectedKind &&
                !mark.WroteStaticField && !mark.WroteMappedImage && !mark.WroteScratchRegion && mark.Registrations.Count == 0
                ? answer.Value : null;
        }
        return results;
    }
}


/// <summary>Retries numeric recovery after proven loader initialization has been removed.</summary>
public sealed class NumericTableRecheckPass : NumericTableRecoveryPass
{
    public override string Name => "numeric-tables-recheck";
    public override IReadOnlyCollection<string> Dependencies => ["method-inlining-recheck"];
}

/// <summary>Revisits tables whose getter and initializer shapes emerge during late cleanup.</summary>
public sealed class NumericTableCompletionPass : NumericTableRecoveryPass
{
    protected override bool ProveConstructedValues => true;
    protected override bool RevisitModuleInitialization => true;
    public override string Name => "numeric-tables-completion";
    public override IReadOnlyCollection<string> Dependencies => ["loader-call-recheck"];
}

/// <summary>Consumes construction shapes exposed by reachability and unwritten-guard cleanup.</summary>
public sealed class NumericTableFinalizationPass : NumericTableRecoveryPass
{
    protected override bool ProveConstructedValues => true;
    protected override bool RevisitModuleInitialization => true;
    public override string Name => "numeric-tables-finalization";
    public override IReadOnlyCollection<string> Dependencies => ["unwritten-guards-completion"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var result = base.Execute(context);
        context.SetFact("numeric-tables.finalized", result.Item2 > 0);
        return result;
    }
}
