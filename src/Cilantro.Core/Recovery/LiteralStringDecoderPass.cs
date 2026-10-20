using Cilantro.Core.Interpretation;
using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Text.Json;

namespace Cilantro.Core.Recovery;

/// <summary>Recovers closed literal string/key decoder chains.</summary>
public sealed class LiteralStringDecoderPass(bool babelOnly = false, bool dotfuscatorOnly = false) : DeobfuscationPass
{
    internal const string InitializersFact = "literalStrings.retainedInitializers";
    public override string Name => dotfuscatorOnly ? "dotfuscator-literal-strings" : babelOnly ? "babel-literal-strings" : "literal-string-decoders";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => dotfuscatorOnly
        ? ["dotfuscator-detection", "constant-strings"] : babelOnly
            ? ["babel-detection", "constant-strings"] : ["control-flow-finalization"];

    private sealed record Site(MethodDef Caller, Instruction Text, Instruction Key, Instruction? Extra,
        Instruction Call, MethodDef Decoder, bool Interned);

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (dotfuscatorOnly && (!context.TryGetFact<DotfuscatorStructureFacts>("dotfuscator.structure", out var dotfuscator) || dotfuscator?.IsDotfuscator != true))
            return (PassStatus.Success, 0, ["No Dotfuscator literal string recovery required."]);
        if (babelOnly && (!context.TryGetFact<BabelStructureFacts>("babel.structure", out var babel) || babel?.IsBabel != true))
            return (PassStatus.Success, 0, ["No Babel literal string recovery required."]);
        var count = 0;
        var literals = new HashSet<Instruction>();
        var retainedInitializers = new HashSet<TypeDef>();
        using var batch = new BodyMutationBatch();
        for (var round = 0; round < 8; round++)
        {
            var sites = Sites(context.Module, dotfuscatorOnly).Take(2048).ToArray();
            if (sites.Length == 0) break;
            var changed = 0;
            foreach (var site in sites)
            {
                // Every site can be the first application call to this decoder.
                // Prove it from fresh startups rather than borrowing warmed state
                // from a different call site visited earlier during the scan.
                if (!WithInitialization(context, site, out var text, out var initializers)) continue;
                batch.Capture(site.Caller);
                site.Text.OpCode = OpCodes.Nop; site.Text.Operand = null;
                site.Key.OpCode = OpCodes.Nop; site.Key.Operand = null;
                if (site.Extra is { } extra) { extra.OpCode = OpCodes.Nop; extra.Operand = null; }
                site.Call.OpCode = OpCodes.Ldstr; site.Call.Operand = text;
                if (!site.Interned) literals.Add(site.Call);
                if (initializers.Length != 0)
                {
                    var runtimeHelpers = new TypeRefUser(context.Module, "System.Runtime.CompilerServices", "RuntimeHelpers", context.Module.CorLibTypes.AssemblyRef);
                    var handle = new TypeRefUser(context.Module, "System", "RuntimeTypeHandle", context.Module.CorLibTypes.AssemblyRef);
                    var initialize = new MemberRefUser(context.Module, "RunClassConstructor",
                        MethodSig.CreateStatic(context.Module.CorLibTypes.Void, new ValueTypeSig(handle)), runtimeHelpers);
                    var at = site.Caller.Body.Instructions.IndexOf(site.Call);
                    foreach (var initializer in initializers)
                    {
                        if (babelOnly) retainedInitializers.Add(initializer.DeclaringType);
                        site.Caller.Body.Instructions.Insert(at++, OpCodes.Ldtoken.ToInstruction(initializer.DeclaringType));
                        site.Caller.Body.Instructions.Insert(at++, OpCodes.Call.ToInstruction(initialize));
                    }
                }
                batch.RecordChange(context, new(Name, "decode-literal-string", site.Caller.FullName,
                    $"Decoded a literal string/key call to {site.Decoder.FullName}: {text}"));
                changed++;
            }
            count += changed;
            if (changed == 0) break;
        }
        // Resolve nested layers before restoring fresh allocations. Returning an
        // interned literal would change ReferenceEquals behavior of these decoders.
        var toChars = new MemberRefUser(context.Module, "ToCharArray",
            MethodSig.CreateInstance(new SZArraySig(context.Module.CorLibTypes.Char)), context.Module.CorLibTypes.String.TypeDefOrRef);
        var constructor = new MemberRefUser(context.Module, ".ctor",
            MethodSig.CreateInstance(context.Module.CorLibTypes.Void, new SZArraySig(context.Module.CorLibTypes.Char)), context.Module.CorLibTypes.String.TypeDefOrRef);
        foreach (var method in context.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
            for (var at = 0; at < method.Body.Instructions.Count; at++)
                if (method.Body.Instructions[at].OpCode.Code == Code.Ldstr && literals.Contains(method.Body.Instructions[at]))
                {
                    method.Body.Instructions.Insert(++at, OpCodes.Callvirt.ToInstruction(toChars));
                    method.Body.Instructions.Insert(++at, OpCodes.Newobj.ToInstruction(constructor));
                }
        if (!AssemblyVerifier.Verify(context.Module).Passed)
            return (PassStatus.Partial, 0, ["Literal decoder completion failed verification and was rolled back."]);
        batch.Commit();
        if (retainedInitializers.Count != 0)
        {
            context.TryGetFact<IReadOnlySet<TypeDef>>(InitializersFact, out var earlierInitializers);
            retainedInitializers.UnionWith(earlierInitializers ?? new HashSet<TypeDef>());
            context.SetFact<IReadOnlySet<TypeDef>>(InitializersFact, retainedInitializers);
        }
        context.TryGetFact<int>("strings.constantSites", out var earlierSites);
        context.SetFact("strings.constantSites", earlierSites + count);
        return (PassStatus.Success, count, [$"Decoded {count} literal string/key call(s) with agreeing independent interpreter trials and no recorded call effects."]);
    }

    private static string? Read(ArtifactContext context, StaticMachine machine, Site site)
    {
        var before = State(context, machine);
        if (before is null) return null;
        if (!machine.State.Heap.TryAllocateString((string)site.Text.Operand, out var argument)) return null;
        using var alone = machine.State.Evidence.SetAside(site.Decoder.MDToken.Raw);
        var result = machine.Execute(site.Decoder, Arguments(site, argument));
        if (!result.Succeeded || !machine.State.Heap.TryGetString(result.Value, out var text) || result.Value.HeapId <= argument.HeapId) return null;
        var effects = machine.State.LoaderEvidence.EffectsOf(site.Decoder.MDToken.Raw);
        return effects.WroteStaticField || effects.WroteMappedImage || effects.WroteScratchRegion || effects.Registrations.Count != 0 ||
            State(context, machine) != before ? null : text;
    }

    private static bool WithInitialization(ArtifactContext context, Site site, out string? text, out MethodDef[] initializers)
    {
        text = null; initializers = [];
        if (!BootstrapMachine.TryRunInitializers(context, 4_000_000, out var original, out _) || original is null ||
            !BootstrapMachine.TryRunInitializers(context, 4_000_000, out var replaced, out _) || replaced is null) return false;
        var entered = new List<MethodDef>();
        original.FrameEntered = (method, _) => { if (method.IsStaticConstructor && !entered.Contains(method)) entered.Add(method); };
        if (!original.State.Heap.TryAllocateString((string)site.Text.Operand, out var argument)) return false;
        var result = original.Execute(site.Decoder, Arguments(site, argument));
        if (!result.Succeeded || !original.State.Heap.TryGetString(result.Value, out text)) return false;
        foreach (var initializer in entered)
            if (replaced.State.GetTypeInitializationStatus(initializer.DeclaringType) != TypeInitializationStatus.Initialized &&
                !replaced.Execute(initializer).Succeeded) return false;
        // Removing the decoder body must leave precisely the state produced by its
        // retained initialization triggers, including reachable objects and payloads.
        var expected = State(context, original);
        if (expected is null || State(context, replaced) != expected || Read(context, replaced, site) != text) return false;
        initializers = entered.ToArray();
        return true;
    }

    private static string? State(ArtifactContext context, StaticMachine machine)
    {
        if (!context.TryGetFact<Dictionary<object, int>>("literalStrings.metadata", out var metadata) || metadata is null)
        {
            metadata = new(ReferenceEqualityComparer.Instance);
            context.SetFact("literalStrings.metadata", metadata);
        }
        var snapshot = new RebuiltMethodTrial.Snapshot(machine.State.Heap, metadata);
        var fields = context.Module.GetTypes().SelectMany(t => t.Fields).Where(f => f.IsStatic)
            .Select(f => snapshot.Read(machine.State.ReadStaticField(f))).ToArray();
        var domain = snapshot.ReadDomainState(machine.State);
        var network = snapshot.ReadNetworkSettings(machine.State);
        var native = snapshot.ReadNativeState(machine.State);
        if (snapshot.Failure is not null || fields.Any(f => f is null) || domain is null || network is null || native is null) return null;
        return JsonSerializer.Serialize(new { fields, domain, network, native,
            Registrations = machine.State.LoaderEvidence.Effects.Values.SelectMany(e => e.Registrations).Order().ToArray(),
            Payloads = machine.State.CapturedAssemblyLoads.Select(b => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(b))).ToArray() });
    }

    private static StaticValue[] Arguments(Site site, StaticValue text) => site.Extra is null
        ? [text, StaticValue.FromInt32(site.Key.GetLdcI4Value())]
        : [text, StaticValue.FromInt32(site.Key.GetLdcI4Value()), StaticValue.Null];

    private static IEnumerable<Site> Sites(ModuleDef module, bool dotfuscator)
    {
        var closed = new Dictionary<MethodDef, bool>();
        foreach (var caller in module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
        {
            var targeted = new HashSet<Instruction>();
            foreach (var i in caller.Body.Instructions)
                if (i.Operand is Instruction target) targeted.Add(target);
                else if (i.Operand is IList<Instruction> targets) targeted.UnionWith(targets);
            foreach (var h in caller.Body.ExceptionHandlers)
                foreach (var boundary in new[] { h.TryStart, h.TryEnd, h.HandlerStart, h.HandlerEnd, h.FilterStart })
                    if (boundary is not null) targeted.Add(boundary);
            var il = caller.Body.Instructions;
            for (var at = 2; at < il.Count; at++)
            {
                var call = il[at];
                if (call.OpCode.Code != Code.Call || call.Operand is not IMethod target || target is MethodSpec ||
                    target.ResolveMethodDef() is not { HasBody: true, IsStatic: true, HasGenericParameters: false } decoder ||
                    decoder.Module != module || decoder.DeclaringType.HasGenericParameters ||
                    (decoder.MethodSig.Params.Count != 2 && !(dotfuscator && decoder.MethodSig.Params.Count == 3 &&
                        decoder.MethodSig.Params[2].ElementType == ElementType.String &&
                        !decoder.Body.Instructions.Any(i => i.GetParameterIndex() == 2))) ||
                    decoder.MethodSig.Params[0].ElementType != ElementType.String ||
                    decoder.MethodSig.Params[1].ElementType != ElementType.I4 || decoder.ReturnType.ElementType != ElementType.String ||
                    decoder.Body.Instructions.Count > 512) continue;
                if (!closed.TryGetValue(decoder, out var eligible)) closed[decoder] = eligible = Closed(decoder, dotfuscator);
                if (!eligible) continue;
                var key = at - 1;
                while (key >= 0 && il[key].OpCode.Code == Code.Nop) key--;
                Instruction? extra = null;
                if (decoder.MethodSig.Params.Count == 3)
                {
                    if (key < 0 || !(il[key].OpCode.Code is Code.Ldstr or Code.Ldnull ||
                        il[key].IsLdloc() && il[key].GetLocal(caller.Body.Variables)?.Type.ElementType == ElementType.String)) continue;
                    extra = il[key--];
                    while (key >= 0 && il[key].OpCode.Code == Code.Nop) key--;
                }
                var text = key - 1;
                while (text >= 0 && il[text].OpCode.Code == Code.Nop) text--;
                if (text < 0 || !il[key].IsLdcI4() || il[text].OpCode.Code != Code.Ldstr ||
                    Enumerable.Range(text + 1, at - text).Any(i => targeted.Contains(il[i]))) continue;
                var interned = decoder.Body.Instructions.Any(i => i.OpCode.Code == Code.Call &&
                    i.Operand is IMethod called && IsIntern(called));
                yield return new(caller, il[text], il[key], extra, call, decoder, interned);
            }
        }
    }

    private static bool IsIntern(IMethod called) => called.FullName == "System.String System.String::Intern(System.String)";

    private static bool Closed(MethodDef decoder, bool allowIntern)
    {
        var methods = new HashSet<MethodDef>();
        var fields = new HashSet<FieldDef>();
        var pending = new Stack<MethodDef>(); pending.Push(decoder);
        var transform = false;
        while (pending.TryPop(out var method))
        {
            if (!methods.Add(method)) continue;
            if (methods.Count > 32 || !method.HasBody || method.HasGenericParameters || method.Body.Instructions.Count > 512 ||
                method.IsVirtual && !method.IsFinal && !method.DeclaringType.IsSealed) return false;
            foreach (var i in method.Body.Instructions)
            {
                transform |= i.OpCode.Code == Code.Xor;
                if (i.OpCode.Code is Code.Ldfld or Code.Ldsfld)
                {
                    if (i.Operand is not IField reference || reference.ResolveFieldDef() is not { } field || field.Module != decoder.Module) return false;
                    fields.Add(field);
                }
                else if (i.OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj)
                {
                    if (i.Operand is not IMethod called || called is MethodSpec) return false;
                    if (called.ResolveMethodDef() is { } body && body.Module == decoder.Module) pending.Push(body);
                    else if (called.DeclaringType is not TypeRef type || type.FullName != "System.String" ||
                        type.DefinitionAssembly?.FullName != decoder.Module.CorLibTypes.AssemblyRef.FullName ||
                        called.FullName is not ("System.Int32 System.String::get_Length()" or "System.Char[] System.String::ToCharArray()" or
                            "System.Void System.String::.ctor(System.Char[])" ) && !(allowIntern && IsIntern(called))) return false;
                }
                else if (i.OpCode.Code is Code.Stfld or Code.Stsfld or Code.Ldflda or Code.Ldsflda or Code.Calli or Code.Jmp or
                    Code.Ldftn or Code.Ldvirtftn or Code.Stobj or Code.Cpobj or Code.Cpblk or Code.Initblk) return false;
            }
        }
        if (!transform) return false;
        foreach (var method in methods)
        {
            var body = method.Body.Instructions;
            for (var at = 0; at < body.Count; at++)
                if (body[at].OpCode.Code == Code.Call && body[at].Operand is IMethod intern && IsIntern(intern) &&
                    (method != decoder || at + 1 >= body.Count || body[at + 1].OpCode.Code != Code.Ret)) return false;
            var targets = body.SelectMany(i => i.Operand is Instruction one ? new[] { one } :
                i.Operand is IList<Instruction> many ? many : []).ToHashSet();
            for (var at = 0; at < body.Count; at++)
            {
                if (body[at].OpCode.Code != Code.Ret) continue;
                var previous = at - 1;
                if (targets.Contains(body[at])) return false;
                while (previous >= 0 && body[previous].OpCode.Code == Code.Nop)
                { if (targets.Contains(body[previous--])) return false; }
                if (previous < 0 || body[previous].Operand is not IMethod called) return false;
                var interns = method == decoder && method.Body.Instructions.Any(i => i.OpCode.Code == Code.Call && i.Operand is IMethod m && IsIntern(m));
                if (allowIntern && interns && body[previous].OpCode.Code == Code.Call && IsIntern(called) && previous > 0 &&
                    !targets.Contains(body[previous]) && body[previous - 1].OpCode.Code == Code.Newobj &&
                    body[previous - 1].Operand is IMethod created && created.FullName == "System.Void System.String::.ctor(System.Char[])") continue;
                if (interns) return false;
                if (body[previous].OpCode.Code == Code.Newobj && called.FullName == "System.Void System.String::.ctor(System.Char[])") continue;
                if (body[previous].OpCode.Code is not (Code.Call or Code.Callvirt) ||
                    called.ResolveMethodDef() is not { } returned || !methods.Contains(returned)) return false;
            }
        }
        // Mutable key material must not escape to application code. Constructor writes
        // are retained by initialization replay; later writers and address aliases refuse.
        foreach (var method in decoder.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
            foreach (var i in method.Body.Instructions)
                if (i.Operand is IField reference && reference.ResolveFieldDef() is { } field && fields.Contains(field))
                {
                    if (i.OpCode.Code is Code.Ldflda or Code.Ldsflda) return false;
                    if (i.OpCode.Code is Code.Stfld or Code.Stsfld && !method.IsConstructor) return false;
                    if (i.OpCode.Code is Code.Ldfld or Code.Ldsfld && !methods.Contains(method) && !method.IsConstructor) return false;
                }
        return true;
    }
}
