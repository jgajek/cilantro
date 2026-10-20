using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Proxy;

/// <summary>Reconstructs Babel's metadata-token delegate adapters without loading sample code.</summary>
public sealed class BabelProxyRecoveryPass : DeobfuscationPass
{
    /// <summary>Every matched binding was either rewritten or deliberately retained for its access context.</summary>
    public const string CompleteFact = "babel.proxies.complete";
    public const string RetainedFact = "babel.proxies.retained";
    public const string ContractsFact = "babel.proxies.erasedContracts";
    internal const string BindingsFact = "babel.proxies.bindingFingerprints";
    public override string Name => "babel-proxies";
    public override IReadOnlyCollection<string> Dependencies => ["babel-detection", "resource-analysis"];
    public override bool GatesEmission => false;
    internal sealed record Candidate(TypeDef Type, FieldDef Field, MethodDef Initializer, MethodDef Binder, MethodDef Wrapper);

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<BabelStructureFacts>("babel.structure", out var facts) || facts?.IsBabel != true)
            return (PassStatus.Success, 0, ["No Babel delegate adapters require recovery."]);
        var types = context.Module.GetTypes().Where(ReactorStructureDetector.IsDelegateProxy).ToArray();
        if (types.Length == 0) return (PassStatus.Success, 0, ["No Babel delegate proxy types were found."]);
        var candidates = types.Select(Catalog).OfType<Candidate>().ToArray();
        if (candidates.Length != types.Length || candidates.Length > 8192)
            return (PassStatus.Partial, 0, [$"Matched {candidates.Length}/{types.Length} proxy types to the Babel token-binder shape.",
                .. types.Where(type => Catalog(type) is null).Take(8).Select(type => $"Unmatched proxy {type.MDToken} {type.FullName}.")]);
        if (!Closed(context.Module, candidates))
            return (PassStatus.Partial, 0, ["Proxy fields or token binders have uses outside their closed initialization paths."]);
        context.SetFact<IReadOnlySet<MethodDef>>(ContractsFact, candidates.Select(candidate => candidate.Wrapper).ToHashSet());
        var forward = Read(context, candidates, out var firstWhy);
        var reverse = Read(context, candidates.Reverse().ToArray(), out var secondWhy);
        var agreed = candidates.Where(candidate => forward.TryGetValue(candidate.Field, out var first) &&
            reverse.TryGetValue(candidate.Field, out var second) && first.Fingerprint == second.Fingerprint).ToArray();
        var rewritten = 0;
        var retained = 0;
        var retainedMethods = new HashSet<MethodDef>();
        var recoveredCallerSites = 0;
        var notes = new List<string>();
        var callerSites = candidates.ToDictionary(candidate => candidate.Wrapper,
            _ => new List<(MethodDef Caller, Instruction Site)>());
        foreach (var caller in context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody))
            foreach (var instruction in caller.Body.Instructions)
                if (instruction.OpCode.Code == Code.Call && instruction.Operand is IMethod called &&
                    called.ResolveMethodDef() is { } wrapper && callerSites.TryGetValue(wrapper, out var sites)) sites.Add((caller, instruction));
        foreach (var candidate in agreed)
        {
            var body = forward[candidate.Field].Body;
            var call = body.Instructions.Single(instruction => instruction.OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj);
            var target = (IMethod)call.Operand;
            // DynamicMethod can skip access checks and issue nonvirtual calls that ordinary CIL
            // cannot express from this declaring type. Keep that runtime adapter intact.
            if (!CallableFrom(candidate.Wrapper, target, call.OpCode.Code))
            {
                // The original caller may have the private access that the shared
                // delegate type lacks. Recover those sites in their own context.
                recoveredCallerSites += RecoverCallers(context, candidate, target, call.OpCode, callerSites[candidate.Wrapper]);
                retained++;
                retainedMethods.Add(candidate.Wrapper);
                context.AddEvidence(new("babel-proxy-retained", $"Resolved {call.OpCode.Name} {target.FullName}; retained the original adapter because its access/dispatch context cannot be expressed as a direct call here.", candidate.Wrapper.MDToken.ToString()));
                continue;
            }
            var reconciliation = ProxyArgumentNarrowing.PlanDirect(candidate.Wrapper, target, call.OpCode.Code == Code.Newobj);
            if (reconciliation is null) { notes.Add($"{candidate.Wrapper.MDToken}: target arguments cannot be reconciled."); continue; }
            using var transaction = new BodyMutationTransaction(candidate.Wrapper);
            candidate.Wrapper.Body = body;
            ProxyArgumentNarrowing.Apply(candidate.Wrapper, call, reconciliation);
            PreserveInitialization(context.Module, candidate.Wrapper, candidate.Type);
            if (!EvaluationStackAnalyzer.Analyze(candidate.Wrapper).Valid)
            { notes.Add($"{candidate.Wrapper.MDToken}: reconstructed adapter did not verify."); continue; }
            transaction.Commit();
            rewritten++;
            context.AddChange(new(Name, "restore-babel-proxy", candidate.Wrapper.MDToken.ToString(),
                $"Reconstructed {call.OpCode.Name} {target.FullName}; original type initialization retained."));
        }
        context.TryGetFact<int>("proxy.restoredCallSites", out var previous);
        context.SetFact(CompleteFact, rewritten + retained == candidates.Length);
        context.SetFact<IReadOnlySet<MethodDef>>(RetainedFact, retainedMethods);
        context.SetFact("proxy.restoredCallSites", previous + rewritten);
        context.SetFact("babel.proxies.directCallerSites", recoveredCallerSites);
        context.SetFact<IReadOnlyDictionary<uint, string>>(BindingsFact,
            agreed.ToDictionary(candidate => candidate.Initializer.MDToken.Raw, candidate => forward[candidate.Field].Fingerprint));
        context.AddEvidence(new("babel-proxy-bindings", $"Independent initializer trials in opposite orders agreed on {agreed.Length}/{candidates.Length} bindings; reconstructed {rewritten} adapters."));
        return (rewritten == candidates.Length ? PassStatus.Success : PassStatus.Partial, rewritten,
            [$"Recovered {agreed.Length}/{candidates.Length} Babel proxy bindings and reconstructed {rewritten} adapters; retained {retained} adapters requiring their original access/dispatch context. Recovered {recoveredCallerSites} direct calls in accessible caller contexts.",
                .. new[] { firstWhy, secondWhy }.Where(note => note.Length != 0), .. notes.Take(8)]);
    }

    private static int RecoverCallers(ArtifactContext context, Candidate candidate, IMethod target, OpCode opcode,
        IReadOnlyList<(MethodDef Caller, Instruction Site)> sites)
    {
        var narrowing = ProxyArgumentNarrowing.PlanDirect(candidate.Wrapper, target, opcode.Code == Code.Newobj);
        if (narrowing is null) return 0;
        var recovered = 0;
        foreach (var (caller, site) in sites)
        {
            if (!CallableFrom(caller, target, opcode.Code)) continue;
            var index = caller.Body.Instructions.IndexOf(site);
            if (index > 0 && caller.Body.Instructions[index - 1].OpCode.OpCodeType == OpCodeType.Prefix) continue;
            using var transaction = new BodyMutationTransaction(caller);
            // Keep the original instruction as the entry to the replacement,
            // including branches and exception-handler boundaries targeting it.
            site.OpCode = OpCodes.Ldtoken;
            site.Operand = candidate.Type;
            var direct = new Instruction(opcode, target);
            caller.Body.Instructions.Insert(index + 1, OpCodes.Call.ToInstruction(InitializationTrigger(context.Module)));
            caller.Body.Instructions.Insert(index + 2, direct);
            ProxyArgumentNarrowing.Apply(caller, direct, narrowing);
            caller.Body.SimplifyBranches();
            if (!EvaluationStackAnalyzer.Analyze(caller).Valid) continue;
            transaction.Commit();
            recovered++;
            context.AddChange(new("babel-proxies", "restore-babel-proxy-caller", caller.MDToken.ToString(),
                $"Recovered {opcode.Name} {target.FullName} in its accessible caller context; proxy initialization retained."));
        }
        return recovered;
    }

    internal static bool CallableFrom(MethodDef wrapper, IMethod target, Code opcode)
    {
        if (!AccessibleType(target.DeclaringType?.ToTypeSig(), wrapper) ||
            target.MethodSig is not { } signature || !AccessibleType(signature.RetType, wrapper) ||
            signature.Params.Any(parameter => !AccessibleType(parameter, wrapper)) ||
            target is MethodSpec specification && specification.GenericInstMethodSig.GenericArguments.Any(argument => !AccessibleType(argument, wrapper))) return false;
        var definition = target.ResolveMethodDef();
        if (definition is null && target.DeclaringType?.ResolveTypeDef()?.Module == wrapper.Module) return false;
        if (definition is not null)
        {
            if (definition.Module == wrapper.Module)
            {
                if (!(definition.IsPublic || definition.IsAssembly || definition.IsFamilyOrAssembly ||
                      definition.DeclaringType == wrapper.DeclaringType)) return false;
                for (var type = definition.DeclaringType; type.IsNested; type = type.DeclaringType)
                    if (!(type.IsNestedPublic || type.IsNestedAssembly || type.IsNestedFamilyOrAssembly ||
                          type.DeclaringType == wrapper.DeclaringType)) return false;
            }
            else if (!definition.IsPublic || !MemberVisibility.IsExternallyVisible(definition.DeclaringType)) return false;
        }
        // Calling a virtual base implementation nonvirtually requires a compatible this context.
        // An unresolved external instance method also supplies no proof that it is nonvirtual.
        return opcode != Code.Call || target.MethodSig?.HasThis != true ||
               definition is { IsVirtual: false } || target.DeclaringType?.ToTypeSig()?.IsValueType == true ||
               definition?.DeclaringType.IsValueType == true;
    }

    internal static bool AccessibleType(TypeSig? signature, MethodDef caller)
    {
        if (signature is null) return false;
        if (signature is GenericInstSig generic &&
            (!AccessibleType(generic.GenericType, caller) || generic.GenericArguments.Any(argument => !AccessibleType(argument, caller)))) return false;
        if (signature.Next is { } element && !AccessibleType(element, caller)) return false;
        if (signature is not TypeDefOrRefSig named || named.TypeDefOrRef.ResolveTypeDef() is not { } definition) return true;
        if (definition.Module != caller.Module) return MemberVisibility.IsExternallyVisible(definition);
        for (var type = definition; type.IsNested; type = type.DeclaringType)
            if (!(type.IsNestedPublic || type.IsNestedAssembly || type.IsNestedFamilyOrAssembly || type.DeclaringType == caller.DeclaringType)) return false;
        return true;
    }

    private sealed record Bound(CilBody Body, string Fingerprint);
    private static Dictionary<FieldDef, Bound> Read(ArtifactContext context, Candidate[] candidates, out string why)
    {
        why = "";
        var result = new Dictionary<FieldDef, Bound>();
        if (!BootstrapMachine.TrySeed(context, 32_000_000, out var machine, out why) || machine is null) return result;
        machine.State.RegisterRunEnvironment(new RunEnvironment(new HostEnvironment(HostProfile.Empty)));
        var budget = new StaticWorkBudget(64_000_000);
        foreach (var candidate in candidates)
        {
            var initialized = machine.Execute(candidate.Initializer, [], budget);
            if (!initialized.Succeeded) { if (why.Length == 0) why = initialized.Diagnostic ?? initialized.Status.ToString(); continue; }
            var value = machine.State.ReadStaticField(candidate.Field);
            if (!machine.State.Heap.TryGetModelValue<IMethod>(value, StaticMachine.DelegateMethodKey, out var target) || target is null ||
                !machine.State.Heap.TryGetModelValue<StaticValue>(value, StaticMachine.DelegateTargetKey, out var receiver) || receiver.Kind != StaticValueKind.Null)
                continue;
            var body = Reconstruct(candidate.Wrapper, target);
            if (body is null)
            {
                if (why.Length == 0) why = $"{candidate.Wrapper.MDToken} {candidate.Wrapper.FullName}: adapter body/signature not reconstructed for {target.FullName}. " +
                    (target is MethodDef { HasBody: true } generated ? string.Join("; ", generated.Body.Instructions.Take(12)) : "No emitted body.");
                continue;
            }
            var fingerprint = BindingFingerprint(body);
            result[candidate.Field] = new(body, fingerprint);
        }
        return result;
    }

    internal static CilBody? Reconstruct(MethodDef wrapper, IMethod target)
    {
        var body = new CilBody();
        if (target is MethodDef generated && generated.Module != wrapper.Module && generated.HasBody)
        {
            if (generated.Body.Variables.Count != 0 || generated.Body.ExceptionHandlers.Count != 0 ||
                !CompatibleSignature(wrapper.MethodSig, generated.MethodSig)) return null;
            var il = generated.Body.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop).ToArray();
            var calls = il.Where(instruction => instruction.OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj).ToArray();
            if (calls.Length != 1 || il.Length != wrapper.MethodSig.Params.Count + 2 || il[^1].OpCode.Code != Code.Ret ||
                il[^2] != calls[0] || !il.Take(il.Length - 2).Select((instruction, index) => instruction.IsLdarg() && instruction.GetParameterIndex() == index).All(match => match))
                return null;
            for (var index = 0; index < wrapper.Parameters.Count; index++) body.Instructions.Add(OpCodes.Ldarg.ToInstruction(wrapper.Parameters[index]));
            body.Instructions.Add(new Instruction(calls[0].OpCode, calls[0].Operand));
        }
        else
        {
            if (target.MethodSig?.HasThis != false || !CompatibleSignature(wrapper.MethodSig, target.MethodSig, GenericScope.For(target, null))) return null;
            foreach (var parameter in wrapper.Parameters) body.Instructions.Add(OpCodes.Ldarg.ToInstruction(parameter));
            body.Instructions.Add(OpCodes.Call.ToInstruction(target));
        }
        body.Instructions.Add(OpCodes.Ret.ToInstruction());
        return body;
    }

    internal static string BindingFingerprint(CilBody body)
    {
        var scopes = body.Instructions.Select(instruction => instruction.Operand).OfType<IMethod>()
            .Select(method => method.DeclaringType.DefinitionAssembly?.FullName ?? "<unresolved assembly>");
        var identity = MethodBodySnapshot.Capture(body).Fingerprint + "|" + string.Join("|", scopes);
        return Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(identity)));
    }

    private static bool CompatibleSignature(MethodSig wrapper, MethodSig target, GenericScope? scope = null)
    {
        if (target.HasThis || target.GenParamCount != 0 || wrapper.Params.Count != target.Params.Count ||
            !wrapper.Params.Zip(target.Params).All(pair => new SigComparer().Equals(pair.First, scope?.Bind(pair.Second) ?? pair.Second))) return false;
        var returned = scope?.Bind(target.RetType) ?? target.RetType;
        return new SigComparer().Equals(wrapper.RetType, returned) || wrapper.RetType.ElementType == ElementType.Object &&
            !returned.IsValueType && returned.ElementType is ElementType.Class or ElementType.String or ElementType.Object or ElementType.SZArray or ElementType.Array or ElementType.GenericInst;
    }

    internal static Candidate? Catalog(TypeDef type)
    {
        if (MemberVisibility.IsExternallyVisible(type) || type.FindStaticConstructor() is not { HasBody: true } initializer) return null;
        var fields = type.Fields.Where(field => field.IsStatic && field.FieldType.FullName == type.FullName).ToArray();
        var wrappers = type.Methods.Where(method => method.IsStatic && method.HasBody && !method.IsConstructor).ToArray();
        if (fields.Length != 1 || fields[0].HasCustomAttributes || wrappers.Length != 1) return null;
        var init = initializer.Body.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop).ToArray();
        if (init.Length is not (5 or 6) || !init.Take(init.Length - 2).All(instruction => instruction.IsLdcI4()) || init[^2].OpCode.Code != Code.Call ||
            init[^2].Operand is not IMethod reference || reference.ResolveMethodDef() is not { IsStatic: true, HasBody: true } binder ||
            binder.MethodSig.Params.Count != init.Length - 2 || binder.MethodSig.Params.Any(parameter => parameter.ElementType != ElementType.I4) ||
            binder.ReturnType.ElementType != ElementType.Void || init[^1].OpCode.Code != Code.Ret) return null;
        var wrapper = wrappers[0];
        var il = wrapper.Body.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop).ToArray();
        if (il.Length != wrapper.Parameters.Count + 3 || il[0].OpCode.Code != Code.Ldsfld ||
            (il[0].Operand as IField)?.ResolveFieldDef() != fields[0] || il[^1].OpCode.Code != Code.Ret ||
            il[^2].OpCode.Code is not (Code.Call or Code.Callvirt) || il[^2].Operand is not IMethod { Name.String: "Invoke" } invoke ||
            invoke.DeclaringType.ResolveTypeDef() != type || !il.Skip(1).Take(wrapper.Parameters.Count)
                .Select((instruction, index) => instruction.IsLdarg() && instruction.GetParameterIndex() == index).All(match => match)) return null;
        return new(type, fields[0], initializer, binder, wrapper);
    }

    private static bool Closed(ModuleDef module, Candidate[] candidates)
    {
        var fields = candidates.Select(candidate => candidate.Field).ToHashSet();
        var binders = candidates.Select(candidate => candidate.Binder).ToHashSet();
        var initializers = candidates.Select(candidate => candidate.Initializer).ToHashSet();
        return !module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody).Any(method =>
            method.Body.Instructions.Any(instruction =>
                instruction.Operand is IField field && field.ResolveFieldDef() is { } definition && fields.Contains(definition) && instruction.OpCode.Code != Code.Ldsfld ||
                instruction.Operand is IMethod called && called.ResolveMethodDef() is { } binder && binders.Contains(binder) && !initializers.Contains(method)));
    }

    private static void PreserveInitialization(ModuleDef module, MethodDef wrapper, TypeDef type)
    {
        wrapper.Body.Instructions.Insert(0, OpCodes.Ldtoken.ToInstruction(type));
        wrapper.Body.Instructions.Insert(1, OpCodes.Call.ToInstruction(InitializationTrigger(module)));
    }

    private static MemberRefUser InitializationTrigger(ModuleDef module)
    {
        var runtime = new TypeRefUser(module, "System.Runtime.CompilerServices", "RuntimeHelpers", module.CorLibTypes.AssemblyRef);
        var handle = new TypeRefUser(module, "System", "RuntimeTypeHandle", module.CorLibTypes.AssemblyRef);
        return new MemberRefUser(module, "RunClassConstructor", MethodSig.CreateStatic(module.CorLibTypes.Void, new ValueTypeSig(handle)), runtime);
    }
}
