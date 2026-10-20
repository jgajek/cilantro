using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Proxy;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Recovery;

/// <summary>Resolves ConfuserEx strong delegate fields through their own token decoder.</summary>
public sealed class ConfuserExStrongProxyPass : DeobfuscationPass
{
    public override string Name => "confuserex-strong-proxy";
    public override IReadOnlyCollection<string> Dependencies => ["confuserex-constants"];
    public override bool GatesEmission => true;

    private sealed record Binding(FieldDef Field, IMethod Target, Code Opcode);
    private sealed record Site(MethodDef Method, Instruction Load, Instruction Invoke,
        Binding Binding);

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<ConfuserExStructureFacts>("confuserex.structure", out var facts) ||
            facts?.IsConfuserExProtected != true)
            return (PassStatus.Success, 0, ["Not ConfuserEx-protected."]);

        var fields = context.Module.GetTypes()
            .Where(type => type.BaseType?.FullName == "System.MulticastDelegate")
            .SelectMany(type => type.Fields)
            .Where(FieldShape)
            .ToArray();
        if (fields.Length == 0)
            return (PassStatus.Success, 0, ["No strong reference-proxy fields."]);

        var bindings = new Dictionary<FieldDef, Binding>();
        var refused = new List<string>();
        foreach (var field in fields)
        {
            if (!TryInitializer(field, out var initializer, out var key) || initializer is null)
            {
                refused.Add($"{field.MDToken}: field initializer was not proven.");
                continue;
            }
            if (!TryResolve(context, field, initializer, key, out var target, out var reason) || target is null)
            {
                refused.Add($"{field.MDToken}: {reason}");
                continue;
            }
            if (!TryOpcode(field, key, target, out var opcode))
            {
                refused.Add($"{field.MDToken}: decoded opcode was not proven for {target.FullName}; key {key}, name bytes {string.Join(',', field.Name.String.Select(character => (int)character))}.");
                continue;
            }
            bindings.Add(field, new Binding(field, target, opcode));
        }
        if (bindings.Count == 0)
            return (PassStatus.Partial, 0,
                [$"None of {fields.Length} strong proxy field(s) could be resolved.", .. refused.Take(8)]);

        var sites = new List<Site>();
        var unresolvedSites = new List<string>();
        var strongTypes = fields.Select(field => field.DeclaringType).ToHashSet();
        var invokeCount = 0;
        foreach (var method in context.Module.GetTypes().SelectMany(type => type.Methods)
                     .Where(method => method.HasBody && !method.IsStaticConstructor))
        {
            var il = method.Body.Instructions;
            EvaluationStackOrigins.Result? origins = null;
            for (var index = 0; index < il.Count; index++)
            {
                if (il[index].OpCode.Code is not (Code.Call or Code.Callvirt) ||
                    il[index].Operand is not IMethod { Name.String: "Invoke" } invoke ||
                    invoke.DeclaringType?.ResolveTypeDef() is not { } invokeType ||
                    !strongTypes.Contains(invokeType))
                    continue;
                invokeCount++;
                if (!TryReceiver(method, index, out var load) || load is null)
                {
                    origins ??= EvaluationStackOrigins.Analyze(method);
                    if (!TryReceiverAcrossBlocks(origins, il[index], out load) || load is null)
                    {
                        unresolvedSites.Add($"{method.MDToken} IL_{il[index].Offset:X4}: receiver was not traced.");
                        continue;
                    }
                }
                if (load.OpCode.Code != Code.Ldsfld ||
                    (load.Operand as IField)?.ResolveFieldDef() is not { } field ||
                    !bindings.TryGetValue(field, out var binding) ||
                    invoke.DeclaringType?.ResolveTypeDef() != field.DeclaringType)
                {
                    unresolvedSites.Add($"{method.MDToken} IL_{il[index].Offset:X4}: receiver field was not bound.");
                    continue;
                }
                if (!SignatureMatches(invoke, binding.Target, binding.Opcode) ||
                    !BabelProxyRecoveryPass.CallableFrom(method, binding.Target, binding.Opcode))
                {
                    unresolvedSites.Add($"{method.MDToken} IL_{il[index].Offset:X4}: decoded target signature or access was not proven.");
                    continue;
                }
                sites.Add(new Site(method, load, il[index], binding));
            }
        }
        if (sites.Count == 0)
            return (PassStatus.Partial, 0,
                [$"Resolved {bindings.Count} strong proxy field(s), but no invoke site could be safely rewritten."]);
        if (sites.GroupBy(site => site.Load).Any(group => group.Count() != 1))
            return (PassStatus.Unsupported, 0, ["A proxy field load feeds more than one invoke site."]);

        using var batch = new BodyMutationBatch();
        foreach (var site in sites)
        {
            batch.Capture(site.Method);
            site.Load.OpCode = OpCodes.Nop;
            site.Load.Operand = null;
            site.Invoke.OpCode = site.Binding.Opcode switch
            {
                Code.Call => OpCodes.Call,
                Code.Callvirt => OpCodes.Callvirt,
                _ => OpCodes.Newobj
            };
            site.Invoke.Operand = site.Binding.Target;
        }
        if (!AssemblyVerifier.Verify(context.Module, context.OriginalIdentity,
                context.OriginalStructure, CilantroPipeline.BuildRewriteAllowance(context)).Passed)
            return (PassStatus.Unsupported, 0, ["Strong proxy rewrite failed verification."]);
        batch.Commit();
        context.TryGetFact<int>("proxy.restoredCallSites", out var previous);
        context.SetFact("proxy.restoredCallSites", previous + sites.Count);
        foreach (var site in sites)
            context.AddChange(new ChangeRecord(Name, "restore-strong-proxy-call",
                site.Method.FullName,
                $"Replaced field {site.Binding.Field.MDToken} delegate invoke with {site.Binding.Target.FullName}."));
        return (refused.Count == 0 && sites.Count == invokeCount
                ? PassStatus.Success : PassStatus.Partial, sites.Count,
            [$"Resolved {bindings.Count} of {fields.Length} strong proxy field(s) and restored {sites.Count} invoke site(s).",
             .. (sites.Count == invokeCount ? Array.Empty<string>() :
                 [$"Left {invokeCount - sites.Count} strong proxy invoke site(s) unresolved; cleaned emission is withheld."]),
             .. unresolvedSites.Take(8),
             .. refused.Take(8)]);
    }

    private static bool FieldShape(FieldDef field) =>
        field.IsStatic && field.DeclaringType.BaseType?.FullName == "System.MulticastDelegate" &&
        field.FieldSig?.Type is CModOptSig &&
        field.FieldSig.ExtraData is { Length: 8 } extra && extra[0] == 0xc0 && extra[4] == 0xc0 &&
        field.Name.String.Length == 5 && field.CustomAttributes.Count == 1;

    private static bool TryInitializer(FieldDef field, out MethodDef? initializer, out byte key)
    {
        initializer = null;
        key = 0;
        var cctor = field.DeclaringType.FindStaticConstructor();
        if (cctor?.HasBody != true) return false;
        var il = cctor.Body.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop).ToArray();
        for (var index = 0; index + 2 < il.Length; index++)
        {
            if (il[index].OpCode.Code != Code.Ldtoken ||
                (il[index].Operand as IField)?.ResolveFieldDef() != field ||
                !il[index + 1].IsLdcI4() ||
                il[index + 2].OpCode.Code != Code.Call ||
                (il[index + 2].Operand as IMethod)?.ResolveMethodDef() is not { } candidate ||
                candidate.DeclaringType != field.Module.GlobalType ||
                candidate.MethodSig is not { Params.Count: 2, RetType.ElementType: ElementType.Void })
                continue;
            var number = il[index + 1].GetLdcI4Value();
            if (number is < 0 or > 255) return false;
            initializer = candidate;
            key = (byte)number;
            return true;
        }
        return false;
    }

    private static bool TryResolve(ArtifactContext context, FieldDef field,
        MethodDef initializer, byte key, out IMethod? target, out string reason)
    {
        target = null;
        reason = "initializer interpretation was not proven";
        if (!ResolveOnce(context, field, initializer, key, out var first, out reason) ||
            !ResolveOnce(context, field, initializer, key, out var second, out reason) ||
            first is null || second is null || first.MDToken.Raw != second.MDToken.Raw ||
            first.FullName != second.FullName)
            return false;
        target = first;
        reason = string.Empty;
        return true;
    }

    private static bool ResolveOnce(ArtifactContext context, FieldDef field,
        MethodDef initializer, byte key, out IMethod? target, out string reason)
    {
        target = null;
        reason = "static machine could not be seeded";
        if (!BootstrapMachine.TrySeed(context, 2_000_000, out var machine, out _,
                modelTypeInitialization: false) || machine is null ||
            !machine.State.Heap.TryAllocateMetadataHandle(field, out var handle)) return false;
        var result = machine.Execute(initializer, [handle, StaticValue.FromInt32(key)]);
        reason = result.Diagnostic ?? $"initializer stopped with {result.Status}";
        if (machine.State.Blockers.Continuations.Count != 0 ||
            machine.State.ResolvedMethodObservations is not [var only] ||
            only.MethodSig is null ||
            !result.Succeeded && result.Diagnostic?.Contains("GetDynamicILInfo", StringComparison.Ordinal) != true)
            return false;
        target = only;
        return true;
    }

    private static bool TryOpcode(FieldDef field, byte key, IMethod target, out Code opcode)
    {
        opcode = default;
        var candidates = target.Name == ".ctor" ? new[] { Code.Newobj } :
            target.MethodSig?.HasThis == true ? new[] { Code.Call, Code.Callvirt } :
            new[] { Code.Call };
        var matches = candidates.SelectMany(candidate => field.Name.String
            .Where(character => character <= byte.MaxValue &&
                ((byte)character ^ key) == (byte)candidate)
            .Select(_ => candidate)).Distinct().ToArray();
        if (matches.Length != 1) return false;
        opcode = matches[0];
        return true;
    }

    private static bool SignatureMatches(IMethod invoke, IMethod target, Code opcode)
    {
        if (invoke.MethodSig is not { } outer || target.MethodSig is not { } inner) return false;
        var comparer = new SigComparer();
        var extraReceiver = opcode != Code.Newobj && inner.HasThis ? 1 : 0;
        if (outer.Params.Count != inner.Params.Count + extraReceiver) return false;
        for (var index = 0; index < inner.Params.Count; index++)
            if (!comparer.Equals(outer.Params[index + extraReceiver], inner.Params[index])) return false;
        if (extraReceiver == 1 &&
            !comparer.Equals(outer.Params[0], target.DeclaringType.ToTypeSig())) return false;
        return comparer.Equals(outer.RetType, opcode == Code.Newobj
            ? target.DeclaringType.ToTypeSig() : inner.RetType);
    }

    private static bool TryReceiver(MethodDef method, int invokeIndex, out Instruction? load)
    {
        load = null;
        var il = method.Body.Instructions;
        il[invokeIndex].CalculateStackUsage(out _, out var needed);
        if (needed < 1 || needed > 32) return false;
        var branchTargets = il.SelectMany(instruction => instruction.Operand switch
            {
                Instruction target => [target],
                Instruction[] targets => targets,
                _ => Array.Empty<Instruction>()
            }).ToHashSet();
        for (var index = invokeIndex - 1; index >= 0 && invokeIndex - index < 128; index--)
        {
            var instruction = il[index];
            if (instruction.OpCode.FlowControl is not (FlowControl.Call or FlowControl.Next or FlowControl.Meta) ||
                instruction.OpCode.Code is Code.Dup or Code.Pop)
                return false;
            instruction.CalculateStackUsage(out var pushed, out var popped);
            if (pushed < 0 || popped < 0) return false;
            needed += popped - pushed;
            if (needed < 0) return false;
            if (needed != 0)
            {
                if (branchTargets.Contains(instruction)) return false;
                continue;
            }
            load = instruction;
            return !branchTargets.Contains(il[invokeIndex]);
        }
        return false;
    }

    private static bool TryReceiverAcrossBlocks(EvaluationStackOrigins.Result origins,
        Instruction invoke, out Instruction? load)
    {
        load = null;
        if (!origins.Valid || !origins.Inputs.TryGetValue(invoke, out var inputs) ||
            inputs.Length == 0 || inputs[0].Count != 1 ||
            inputs[0].Single() is not { OpCode.Code: Code.Ldsfld } candidate)
            return false;
        if (origins.Inputs.Any(pair => pair.Key != invoke &&
            pair.Value.Any(slot => slot.Contains(candidate))))
            return false;
        load = candidate;
        return true;
    }
}
