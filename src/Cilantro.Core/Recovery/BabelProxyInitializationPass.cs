using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Proxy;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Retires closed delegate construction after every live use has been recovered.</summary>
public sealed class BabelProxyInitializationPass : DeobfuscationPass
{
    public override string Name => "babel-proxy-initialization";
    public override IReadOnlyCollection<string> Dependencies => ["babel-proxies", "babel-hash-strings"];
    internal const string RetiredFact = "babel.proxies.retiredInitializers";
    internal const string RetiredWrappersFact = "babel.proxies.retiredWrappers";

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("options.removeRuntime", out var enabled) || !enabled ||
            !context.TryGetFact<bool>(BabelProxyRecoveryPass.CompleteFact, out var complete) || !complete ||
            !context.TryGetFact<IReadOnlyDictionary<uint, string>>(BabelProxyRecoveryPass.BindingsFact, out var bindings) || bindings is null)
            return (PassStatus.Success, 0, ["Complete Babel proxy recovery/runtime removal is not enabled."]);
        using var original = ModuleDefMD.Load(context.OriginalBytes);
        var candidates = original.GetTypes().Where(ReactorStructureDetector.IsDelegateProxy)
            .Select(BabelProxyRecoveryPass.Catalog).OfType<BabelProxyRecoveryPass.Candidate>().ToArray();
        if (candidates.Length is 0 or > 8192) return (PassStatus.Success, 0, ["No bounded closed proxy initialization family found."]);
        var work = new StaticWorkBudget(64_000_000);
        var forward = Read(context, candidates, bindings, 0, work);
        var reverse = Read(context, candidates.Reverse().ToArray(), bindings, 7919, work);
        var current = candidates.Select(candidate => new BabelProxyRecoveryPass.Candidate(
            (TypeDef)context.Module.ResolveToken(candidate.Type.MDToken), (FieldDef)context.Module.ResolveToken(candidate.Field.MDToken),
            (MethodDef)context.Module.ResolveToken(candidate.Initializer.MDToken), (MethodDef)context.Module.ResolveToken(candidate.Binder.MDToken),
            (MethodDef)context.Module.ResolveToken(candidate.Wrapper.MDToken))).ToArray();
        var currentForward = Read(context, current, bindings, 0, work);
        var currentReverse = Read(context, current.Reverse().ToArray(), bindings, 7919, work);
        var reachability = ModuleReachability.ComputeWithInstances(context.Module, false, RebuiltMethods.CleanupRoots(context));
        var eligible = new List<(BabelProxyRecoveryPass.Candidate Original, TypeDef Type, MethodDef Initializer)>();
        var methods = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody).ToArray();
        foreach (var candidate in candidates.Where(candidate => forward.Contains(candidate.Initializer.MDToken.Raw) && reverse.Contains(candidate.Initializer.MDToken.Raw) &&
                     currentForward.Contains(candidate.Initializer.MDToken.Raw) && currentReverse.Contains(candidate.Initializer.MDToken.Raw)))
        {
            if (context.Module.ResolveToken(candidate.Type.MDToken) is not TypeDef type ||
                context.Module.ResolveToken(candidate.Initializer.MDToken) is not MethodDef initializer || !type.Methods.Contains(initializer) ||
                context.Module.ResolveToken(candidate.Field.MDToken) is not FieldDef field || !type.Fields.Contains(field) ||
                MemberVisibility.IsExternallyVisible(type) || reachability.IsReflectivelyExposed(type) || !SameInitializer(candidate.Initializer, initializer)) continue;
            var readers = methods.Where(method => method.Body.Instructions.Any(instruction => instruction.Operand is IField reference && reference.ResolveFieldDef() == field)).ToArray();
            // Unrecovered live calls still need the original delegate. An unused private
            // wrapper may disappear only through the ordinary attributed cleanup checks.
            if (readers.Any(method => method != initializer && (reachability.IsReachable(method) ||
                    reachability.IsReflectivelyExposed(method.DeclaringType) || MemberVisibility.IsExternallyVisible(method)))) continue;
            eligible.Add((candidate, type, initializer));
        }
        if (eligible.Count == 0) return (PassStatus.Success, 0, ["Proxy initialization retained: live delegate consumers or unverified construction effects remain."]);
        using var batch = new BodyMutationBatch();
        var attributed = new List<MethodDef>();
        var triggers = 0;
        foreach (var item in eligible)
        {
            // Capture attribution while the old initializer still reaches its binder.
            attributed.AddRange(item.Type.Methods);
            batch.Capture(item.Initializer);
            item.Initializer.Body = new CilBody(); item.Initializer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            foreach (var method in methods)
            {
                var graph = ControlFlowGraph.Build(method);
                var il = method.Body.Instructions;
                for (var index = 1; index < il.Count; index++)
                {
                    var token = il[index - 1]; var call = il[index];
                    if (token.OpCode.Code != Code.Ldtoken || token.Operand is not ITypeDefOrRef reference || reference.ResolveTypeDef() != item.Type ||
                        !IsInitializationTrigger(call, context.Module) || graph.BlockOf(token) != graph.BlockOf(call) || !graph.HaveIdenticalExceptionRegions(token, call)) continue;
                    batch.Capture(method); token.OpCode = OpCodes.Nop; token.Operand = null;
                    call.OpCode = OpCodes.Nop; call.Operand = null; triggers++;
                }
            }
        }
        if (!AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure, CilantroPipeline.BuildRewriteAllowance(context)).Passed)
            return (PassStatus.Unsupported, 0, ["Proxy initialization retirement failed verification; original bodies restored."]);
        batch.Commit();
        RecoveryOrphans.Declare(context, attributed);
        RecoveryOrphans.DeclareOwningTypes(context, eligible.Select(item => (MethodDef)context.Module.ResolveToken(item.Original.Binder.MDToken)));
        context.SetFact(RetiredFact, eligible.Count);
        context.TryGetFact<IReadOnlySet<MethodDef>>(RetiredWrappersFact, out var previousWrappers);
        context.SetFact<IReadOnlySet<MethodDef>>(RetiredWrappersFact, (previousWrappers ?? new HashSet<MethodDef>())
            .Concat(eligible.Select(item => context.Module.ResolveToken(item.Original.Wrapper.MDToken)).OfType<MethodDef>()).ToHashSet());
        foreach (var item in eligible)
            context.AddChange(new(Name, "retire-babel-proxy-initializer", item.Initializer.FullName,
                "Original-byte and current-code construction trials in both orders agreed with the recovered binding and wrote only the private delegate/module-handle cache; no live delegate field consumer remains."));
        return (PassStatus.Success, eligible.Count, [$"Retired {eligible.Count} Babel proxy initializers and {triggers} initialization triggers; unrecovered live delegate consumers remain intact."]);
    }

    private static HashSet<uint> Read(ArtifactContext context, BabelProxyRecoveryPass.Candidate[] candidates,
        IReadOnlyDictionary<uint, string> bindings, int seed, StaticWorkBudget work)
    {
        var machine = new StaticMachine(BootstrapMachine.Limits(64_000_000), modelTypeInitialization: true);
        var module = candidates[0].Type.Module;
        machine.State.RegisterModuleMetadata(module);
        machine.State.RegisterPointerSize(context.OriginalImage.IsPe32Plus ? 8 : module.Is32BitRequired || seed == 0 ? 4 : 8);
        machine.State.RegisterModuleFile(context.InputPath, context.OriginalBytes);
        machine.State.RegisterAssemblyIdentity(module.Assembly?.Name ?? module.Name, module.Assembly?.PublicKeyToken?.Data ?? []);
        machine.State.RegisterRunEnvironment(new(new(HostProfile.Parse($"{{\"facts\":{{\"guid:Seed\":{seed}}}}}", "Babel proxy construction"))));
        var allowed = new Dictionary<TypeDef, FieldDef?>();
        foreach (var group in candidates.GroupBy(candidate => candidate.Binder.DeclaringType))
        {
            var owner = group.Key;
            // The only shared state permitted is the generated manifest-module handle.
            // All outside binder calls must belong to the catalogued initializers.
            var initializers = group.Select(candidate => candidate.Initializer).ToHashSet();
            var binders = group.Select(candidate => candidate.Binder).ToHashSet();
            var construction = ConstructionMethods(owner, binders);
            if (!ClosedWork(owner, construction)) continue;
            if (module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody && method.DeclaringType != owner).Any(method =>
                    method.Body.Instructions.Any(instruction => instruction.Operand is IField field && field.ResolveFieldDef()?.DeclaringType == owner ||
                        instruction.Operand is IMethod call && call.ResolveMethodDef() is { } target && target.DeclaringType == owner &&
                        construction.Contains(target) &&
                        (!initializers.Contains(method) || !binders.Contains(target))))) continue;
            var fields = owner.Fields.ToArray();
            if (fields.Length == 0) { allowed[owner] = null; continue; }
            if (fields.Length != 1 || fields[0].HasCustomAttributes || !fields[0].IsPrivate || !fields[0].IsStatic || fields[0].FieldType.FullName != "System.ModuleHandle" ||
                owner.FindStaticConstructor() is not { HasBody: true } cctor) continue;
            if (owner.Methods.Where(method => method.HasBody && !construction.Contains(method)).Any(method => method.Body.Instructions.Any(instruction =>
                    instruction.OpCode.Code is Code.Stsfld or Code.Ldsflda && (instruction.Operand as IField)?.ResolveFieldDef() == fields[0]))) continue;
            using var proof = ModuleDefMD.Load(context.OriginalBytes);
            var copy = (MethodDef)proof.ResolveToken(cctor.MDToken);
            if (!GeneratedRuntimeBodyNormalization.TryNormalize(copy, false, out _)) continue;
            var il = copy.Body.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop).ToArray();
            string[] calls = ["System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)",
                "System.Reflection.Assembly System.Type::get_Assembly()", "System.Reflection.Module System.Reflection.Assembly::get_ManifestModule()",
                "System.ModuleHandle System.Reflection.Module::get_ModuleHandle()"];
            if (il.Length != 7 || il[0].OpCode.Code != Code.Ldtoken || (il[0].Operand as ITypeDefOrRef)?.ResolveTypeDef()?.MDToken != owner.MDToken ||
                !calls.Select((name, index) => il[index + 1].Operand is IMethod call && call.FullName == name && call.DeclaringType.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName).All(match => match) ||
                il[5].OpCode.Code != Code.Stsfld || (il[5].Operand as IField)?.ResolveFieldDef()?.MDToken != fields[0].MDToken || il[6].OpCode.Code != Code.Ret) continue;
            allowed[owner] = fields[0];
        }
        var result = new HashSet<uint>();
        foreach (var candidate in candidates)
        {
            if (!bindings.TryGetValue(candidate.Initializer.MDToken.Raw, out var expected) || !allowed.TryGetValue(candidate.Binder.DeclaringType, out var handle)) continue;
            var execution = machine.Execute(candidate.Initializer, [], work);
            if (!execution.Succeeded || !machine.State.Heap.TryGetModelValue<IMethod>(machine.State.ReadStaticField(candidate.Field), StaticMachine.DelegateMethodKey, out var target) || target is null ||
                !machine.State.Heap.TryGetModelValue<StaticValue>(machine.State.ReadStaticField(candidate.Field), StaticMachine.DelegateTargetKey, out var receiver) || receiver.Kind != StaticValueKind.Null ||
                BabelProxyRecoveryPass.Reconstruct(candidate.Wrapper, target) is not { } body || BabelProxyRecoveryPass.BindingFingerprint(body) != expected) continue;
            var evidence = machine.State.LoaderEvidence;
            var effects = evidence.EffectsOf(candidate.Initializer.MDToken.Raw);
            if (evidence.ObservationsTruncated || evidence.Observations.Count != 0 || machine.State.CapturedAssemblyLoads.Count != 0 ||
                !effects.AllInvocationsCompleted || effects.WroteMappedImage || effects.WroteScratchRegion || effects.Registrations.Count != 0 ||
                effects.StaticFieldsWritten.Any(field => field != candidate.Field.FullName && field != handle?.FullName)) continue;
            result.Add(candidate.Initializer.MDToken.Raw);
        }
        return result;
    }

    private static bool IsInitializationTrigger(Instruction instruction, ModuleDef module) => instruction.OpCode.Code == Code.Call &&
        instruction.Operand is IMethod call && call.FullName == "System.Void System.Runtime.CompilerServices.RuntimeHelpers::RunClassConstructor(System.RuntimeTypeHandle)" &&
        call.DeclaringType.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName;

    private static bool SameInitializer(MethodDef original, MethodDef current)
    {
        if (!current.HasBody || current.Body.ExceptionHandlers.Count != 0) return false;
        var first = original.Body.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop).ToArray();
        var second = current.Body.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop).ToArray();
        return first.Length == second.Length && first.Select((instruction, index) => instruction.IsLdcI4()
            ? second[index].IsLdcI4() && instruction.GetLdcI4Value() == second[index].GetLdcI4Value()
            : instruction.OpCode.Code == second[index].OpCode.Code && (instruction.OpCode.Code == Code.Ret ||
                instruction.Operand is IMethod call && second[index].Operand is IMethod other && call.ResolveMethodDef()?.MDToken == other.ResolveMethodDef()?.MDToken)).All(match => match);
    }

    private static HashSet<MethodDef> ConstructionMethods(TypeDef owner, IEnumerable<MethodDef> binders)
    {
        var found = binders.ToHashSet();
        if (owner.FindStaticConstructor() is { } initializer) found.Add(initializer);
        var pending = new Queue<MethodDef>(found);
        while (pending.TryDequeue(out var method))
            if (method.HasBody)
                foreach (var instruction in method.Body.Instructions)
                    if (instruction.OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj && instruction.Operand is IMethod call &&
                        call.ResolveMethodDef() is { } target && target.DeclaringType == owner && found.Add(target)) pending.Enqueue(target);
        return found;
    }

    private static bool ClosedWork(TypeDef owner, IEnumerable<MethodDef> methods)
    {
        foreach (var instruction in methods.Where(method => method.HasBody).SelectMany(method => method.Body.Instructions))
        {
            // A cold trial must not stand in for mutable application inputs, including
            // reflected field reads or indirectly invoked application initializers.
            if (instruction.Operand is IField field && instruction.OpCode.Code is Code.Ldsfld or Code.Ldsflda &&
                field.ResolveFieldDef() is { } definition && definition.Module == owner.Module && definition.DeclaringType != owner) return false;
            if (instruction.Operand is not IMethod call) continue;
            if (instruction.OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj && call.ResolveMethodDef() is { } target &&
                target.Module == owner.Module && target.DeclaringType != owner &&
                !(instruction.OpCode.Code == Code.Newobj && target.IsRuntime && target.IsInstanceConstructor &&
                    target.DeclaringType.BaseType?.FullName is "System.MulticastDelegate" or "System.Delegate")) return false;
            if (call.Name.String is "DynamicInvoke" or "RunClassConstructor" or "GetCallingAssembly" or "GetEntryAssembly" ||
                call.DeclaringType.FullName.StartsWith("System.Reflection.", StringComparison.Ordinal) && call.Name.String is "GetValue" or "Invoke") return false;
        }
        return true;
    }
}
