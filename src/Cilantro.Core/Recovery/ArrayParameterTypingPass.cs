using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Restores array stack types where every closed caller already supplies that array.</summary>
public class ArrayParameterTypingPass : DeobfuscationPass
{
    internal sealed record CallerValue(TypeSig? Type, Parameter? Source = null, bool IsNull = false,
        FieldDef? Field = null, MethodDef? LocalMethod = null, Local? Local = null);
    private sealed record Plan(MethodDef Method, Parameter Parameter, TypeSig Array, TypeSig Concrete, bool AfterCasts);
    private sealed record CallSite(MethodDef Caller, Instruction Instruction, IMethod Call);
    private sealed record TypingAnalysis(Dictionary<Parameter, CallerValue[]> Inputs, List<Plan> Plans,
        HashSet<MethodDef> UncalledForwarders, HashSet<MethodDef> ClosedUncalled);

    internal static IReadOnlyDictionary<Parameter, CallerValue[]> ClosedInputs(ArtifactContext context) =>
        new ReferenceParameterTypingPass().Analyze(context).Inputs;

    private static CallerValue ProducedValue(MethodDef method, Instruction instruction, TypeSig? type) =>
        new(type, instruction.IsLdarg() ? instruction.GetParameter(method.Parameters) : null,
            instruction.OpCode.Code == Code.Ldnull,
            instruction.OpCode.Code is Code.Ldfld or Code.Ldsfld ? instruction.Operand as FieldDef : null,
            instruction.IsLdloc() ? method : null,
            instruction.IsLdloc() ? instruction.GetLocal(method.Body.Variables) : null);
    public override string Name => "array-parameter-typing";
    public override IReadOnlyCollection<string> Dependencies => ["unused-private-helper-cleanup"];

    private TypingAnalysis Analyze(ArtifactContext context)
    {
        var methods = context.Module.GetTypes().SelectMany(t => t.Methods).ToArray();
        var exposed = ModuleReachability.Compute(context.Module).ReflectivelyExposedTypes.ToHashSet();
        var names = RecoveryMethodNames.Collect(context.Module, methods, exposed);
        var scopedNames = new ScopedMethodNameUses(context.Module, exposed);
        var namedHandles = new NamedMethodHandleUses(context.Module);
        var propertyHandles = new PropertyOnlyTypeHandles(context.Module);
        var uncalledForwarders = UncalledResourceForwarders(context.Module, methods, exposed, names);
        var referenceContracts = ReferenceParameterContracts.Find(context.Module);
        var hasFriends = context.Module.Assembly?.CustomAttributes.Any(a =>
            a.TypeFullName == "System.Runtime.CompilerServices.InternalsVisibleToAttribute") == true;
        var candidates = methods.Where(m => m.HasBody && m.IsStatic && !m.IsConstructor && !m.IsVirtual &&
            !m.DeclaringType.HasGenericParameters && HasClosedCallerBoundary(m, hasFriends) &&
            !m.IsUnmanagedExport && m.ExportInfo is null && !m.IsPinvokeImpl &&
            !m.CustomAttributes.Any(a => a.TypeFullName == "System.Runtime.InteropServices.UnmanagedCallersOnlyAttribute") &&
            (referenceContracts.Contains(m) || !exposed.Contains(m.DeclaringType) || namedHandles.IsClosed(m) || propertyHandles.IsClosed(m)) &&
            (referenceContracts.Contains(m) || (!names.Contains(m.Name.String) && !names.Contains(m.FullName)) || scopedNames.ExcludesAll(m)) &&
            m.MethodSig.Params.Any(p => p.ElementType == ElementType.Object)).ToHashSet();
        // Babel adapters already carry their required conversions, or retain their access-skipping
        // runtime. Caller-derived refinements can name private subtypes inaccessible at this site.
        if (context.TryGetFact<IReadOnlySet<MethodDef>>(Cilantro.Core.Proxy.BabelProxyRecoveryPass.ContractsFact, out var adapters) && adapters is not null)
            candidates.ExceptWith(adapters);
        var arrayConsumers = candidates.Where(ConsumesRecoveredType).ToHashSet();
        foreach (var reference in context.Module.GetMemberRefs().Where(r => r.IsMethodRef))
            if (reference.ResolveMethodDef() is { } definition) candidates.Remove(definition);
        var referencedMethods = methods.Where(m => m.HasBody).SelectMany(m => m.Body.Instructions)
            .Select(i => i.Operand).OfType<IMethod>().Select(m => m.ResolveMethodDef())
            .Concat(context.Module.GetMemberRefs().Where(r => r.IsMethodRef).Select(r => r.ResolveMethodDef())).ToHashSet();
        // A closed static method with no references has no invocation that can
        // contribute values to a callee. Preserve its body, but do not treat its
        // unbound arguments as evidence against actual callers. Handles, names,
        // exports, attributes, accessors and friend assemblies veto this proof.
        var closedUncalled = candidates.Where(m => !hasFriends && m.IsAssembly && !uncalledForwarders.Contains(m) &&
            !m.IsSpecialName && !m.HasCustomAttributes && m.Overrides.Count == 0 &&
            !names.Contains(m.Name.String) && !names.Contains(m.FullName) &&
            !exposed.Contains(m.DeclaringType) && !referencedMethods.Contains(m) && m != context.Module.EntryPoint &&
            !m.DeclaringType.Properties.Any(p => p.GetMethods.Contains(m) || p.SetMethods.Contains(m) || p.OtherMethods.Contains(m)) &&
            !m.DeclaringType.Events.Any(e => e.AddMethod == m || e.RemoveMethod == m || e.InvokeMethod == m || e.OtherMethods.Contains(m))).ToHashSet();
        uncalledForwarders.UnionWith(closedUncalled);
        var delegateInputs = ClosedDelegateParameterTypes.Find(context.Module, candidates, exposed);
        var inferred = new Dictionary<Parameter, TypeSig>();
        var plans = new List<Plan>();
        var instantiations = methods.Where(m => m.HasBody).SelectMany(m => m.Body.Instructions
                .Where(i => i.OpCode.Code == Code.Call && i.Operand is IMethod)
                .Select(i => new CallSite(m, i, (IMethod)i.Operand)))
            .ToLookup(site => site.Call.ResolveMethodDef());
        var graphs = methods.Where(m => m.HasBody).ToDictionary(m => m, ControlFlowGraph.Build);
        var blocks = graphs.SelectMany(pair => pair.Value.Blocks.Select(block => (method: pair.Key, block))).ToArray();
        var flowMethods = methods.Where(m => m.HasBody && (candidates.Contains(m) || m.Body.Instructions.Any(i =>
            i.Operand is IMethod call && call.ResolveMethodDef() is { } target && candidates.Contains(target)))).ToHashSet();
        // Propagate only already-proven caller parameters. Each round adds a parameter
        // or stops, so chains converge without treating a recursive cycle as evidence.
        Dictionary<Parameter, CallerValue[]> inputs = [];
        while (true)
        {
            var previousCount = inferred.Count;
            var calls = candidates.ToDictionary(m => m, _ => new List<CallerValue[]>());
            var assignments = new Dictionary<Parameter, List<CallerValue>>();
            var entries = new Dictionary<MethodDef, Dictionary<BasicBlock, CallerValue[]>>();
            foreach (var (method, block) in blocks)
            {
                if (flowMethods.Contains(method) && !entries.ContainsKey(method))
                    entries[method] = AcyclicEntries(method, graphs[method], inferred);
                var initial = entries.GetValueOrDefault(method)?.GetValueOrDefault(block);
                var stack = initial is null ? new List<CallerValue>() : new List<CallerValue>(initial);
                foreach (var instruction in block.Instructions)
                {
                    if (instruction.OpCode.Code == Code.Nop) continue;
                    if (instruction.OpCode.Code == Code.Dup)
                    { stack.Add(stack.Count == 0 ? new CallerValue(null) : stack[^1]); continue; }
                    instruction.CalculateStackUsage(out var pushes, out var pops);
                    if (instruction.OpCode.Code is Code.Starg or Code.Starg_S && instruction.Operand is Parameter assigned)
                    {
                        if (!assignments.TryGetValue(assigned, out var values)) assignments[assigned] = values = [];
                        values.Add(stack.Count == 0 ? new CallerValue(null) : stack[^1]);
                    }
                    if (instruction.Operand is IMethod invoked && invoked.ResolveMethodDef() is { } target && candidates.Contains(target) &&
                        !uncalledForwarders.Contains(method))
                    {
                        if (instruction.OpCode.Code == Code.Ldftn && delegateInputs.TryGetValue(target, out var supplied))
                            calls[target].Add(supplied.Select(type => new CallerValue(type)).ToArray());
                        else if (instruction.OpCode.Code == Code.Call && IsDirectDefinitionCall(invoked, target) && pops > stack.Count &&
                            BackwardInputs(method, graphs[method], instruction, pops, inferred) is { } recovered)
                            calls[target].Add(recovered);
                        else if (instruction.OpCode.Code != Code.Call || !IsDirectDefinitionCall(invoked, target) || pops > stack.Count || pops < 0)
                            candidates.Remove(target);
                        else calls[target].Add(stack.Skip(stack.Count - pops).ToArray());
                    }
                    if (pops < 0) { stack.Clear(); continue; }
                    var inputsKnown = pops <= stack.Count;
                    // Legacy proxy rewrites can box an array. Boxing a reference preserves its
                    // identity; retain its type only when the input and operand agree exactly.
                    var boxedArray = inputsKnown && instruction.OpCode.Code == Code.Box && pops == 1 &&
                        instruction.Operand is ITypeDefOrRef boxed && boxed.ToTypeSig() is SZArraySig or ArraySig &&
                        new SigComparer().Equals(stack[^1].Type, boxed.ToTypeSig()) ? stack[^1].Type : null;
                    var indirectReference = inputsKnown && instruction.OpCode.Code == Code.Ldind_Ref && pops == 1 &&
                        stack[^1].Type is ByRefSig address && AcceptsType(address.Next) ? address.Next : null;
                    var arrayElement = inputsKnown && instruction.OpCode.Code == Code.Ldelem_Ref && pops == 2 &&
                        stack[^2].Type is SZArraySig array ? array.Next : null;
                    if (inputsKnown) stack.RemoveRange(stack.Count - pops, pops);
                    else stack.Clear();
                    // Unknown incoming operands cannot certify a callee's inputs,
                    // but a completed typed instruction still establishes its
                    // result type (for example a string-returning instance call).
                    TypeSig? type = instruction.IsLdloc() ? instruction.GetLocal(method.Body.Variables)?.Type :
                        instruction.IsLdarg() && instruction.GetParameter(method.Parameters) is { } argument ? inferred.GetValueOrDefault(argument, argument.Type) :
                        instruction.OpCode.Code == Code.Ldstr ? method.Module.CorLibTypes.String :
                        instruction.OpCode.Code == Code.Newobj && instruction.Operand is IMethod constructor ? constructor.DeclaringType.ToTypeSig() :
                        instruction.OpCode.Code == Code.Newarr && instruction.Operand is ITypeDefOrRef element ? new SZArraySig(element.ToTypeSig()) :
                        instruction.OpCode.Code is Code.Castclass or Code.Isinst && instruction.Operand is ITypeDefOrRef cast ? cast.ToTypeSig() :
                        instruction.OpCode.Code is Code.Call or Code.Callvirt && instruction.Operand is IMethod call ? ReturnedType(call) :
                        instruction.OpCode.Code is Code.Ldfld or Code.Ldsfld && instruction.Operand is IField field ? field.FieldSig?.Type : boxedArray ?? indirectReference ?? arrayElement;
                    for (var index = 0; index < pushes; index++) stack.Add(ProducedValue(method, instruction, type));
                }
            }
            inputs = [];
            foreach (var method in candidates.Where(m => calls[m].Count != 0))
            foreach (var parameter in method.Parameters.Where(p => p.Type.ElementType == ElementType.Object))
            {
                if (method.Body.Instructions.Any(i => i.OpCode.Code is Code.Ldarga or Code.Ldarga_S && i.Operand == parameter)) continue;
                inputs[parameter] = calls[method].Select(c => parameter.Index < c.Length ? c[parameter.Index] : new CallerValue(null))
                    .Concat(assignments.GetValueOrDefault(parameter) ?? []).ToArray();
            }
            foreach (var parameter in inputs.Keys.Where(p => !inferred.ContainsKey(p)))
            {
                // A cycle is evidence of forwarding, not a concrete type. Walk every
                // incoming parameter edge and require at least one concrete seed and
                // agreement from every source outside the cycle, including every
                // reassignment. Unknown writers poison the proof; a self-assignment
                // cannot serve as its own concrete seed.
                TypeSig? common = null;
                var concreteInputs = new List<TypeSig>();
                var pending = new Stack<Parameter>(); pending.Push(parameter);
                var visited = new HashSet<Parameter>();
                var valid = true;
                while (valid && pending.TryPop(out var source))
                {
                    if (!visited.Add(source)) continue;
                    if (!inputs.TryGetValue(source, out var supplied)) { valid = false; break; }
                    foreach (var value in supplied)
                    {
                        if (value.IsNull) continue;
                        if (value.Type is { } concrete && AcceptsType(concrete) && !concrete.ContainsGenericParameter)
                        {
                            concreteInputs.Add(concrete);
                            if (common is null) common = concrete;
                            else if (MergeTypes(common, concrete) is { } merged) common = merged;
                            else { valid = false; break; }
                        }
                        else if (value.Type?.ElementType == ElementType.Object && value.Source is { } forwarded)
                            pending.Push(forwarded);
                        else { valid = false; break; }
                    }
                }
                if (!valid || common is null) continue;
                var preferred = PreferConsumerType(parameter, common, concreteInputs);
                var afterCasts = !new SigComparer().Equals(preferred, common);
                common = preferred;
                inferred.Add(parameter, common);
                var method = parameter.Method;
                var bodyType = GenericBodyType(method, parameter, common, instantiations[method], graphs);
                if (arrayConsumers.Contains(method) && method.Body.Instructions.Any(i => i.IsLdarg() && i.GetParameter(method.Parameters) == parameter &&
                    !AlreadyTyped(method, i, bodyType, afterCasts))) plans.Add(new(method, parameter, bodyType, common, afterCasts));
            }
            if (inferred.Count == previousCount) break;
        }
        // An open forwarding call cannot establish a closed type. It can still
        // prove a generic template when its actual value already has exactly the
        // bound template type. Require a separate closed seed and inspect every
        // call without using inferred parameter types, avoiding circular proofs.
        foreach (var method in candidates.Where(m => m.HasGenericParameters && arrayConsumers.Contains(m)))
        foreach (var parameter in method.Parameters.Where(p => p.Type.ElementType == ElementType.Object && !inferred.ContainsKey(p)))
        {
            if (method.Body.Instructions.Any(i => i.OpCode.Code is Code.Starg or Code.Starg_S or Code.Ldarga or Code.Ldarga_S && i.Operand == parameter)) continue;
            TypeSig? concrete = null;
            var valid = true;
            foreach (var site in instantiations[method].Where(s => IsClosedDirectCall(s.Call, method)))
            {
                var actual = BackwardInputs(site.Caller, graphs[site.Caller], site.Instruction, method.Parameters.Count,
                    new Dictionary<Parameter, TypeSig>())?[parameter.Index];
                if (actual?.IsNull == true) continue;
                if (actual?.Type is not { ContainsGenericParameter: false } type || !AcceptsType(type) ||
                    concrete is not null && !new SigComparer().Equals(concrete, type)) { valid = false; break; }
                concrete = type;
            }
            if (!valid || concrete is null) continue;
            var template = GenericBodyType(method, parameter, concrete, instantiations[method], graphs);
            if (template.ContainsGenericParameter && method.Body.Instructions.Any(i => i.IsLdarg() &&
                i.GetParameter(method.Parameters) == parameter && !AlreadyTyped(method, i, template)))
                plans.Add(new(method, parameter, template, concrete, false));
        }
        return new(inputs, plans, uncalledForwarders, closedUncalled);
    }

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var analysis = Analyze(context);
        var plans = analysis.Plans;
        var uncalledForwarders = analysis.UncalledForwarders;
        if (plans.Count == 0) return (PassStatus.Success, 0, [$"No erased {TypeLabel} parameter had unanimous concrete caller types."]);
        using var transaction = new BodyMutationBatch(plans.Select(p => p.Method).Distinct().ToArray());
        var importer = new Importer(context.Module);
        foreach (var plan in plans)
        foreach (var read in plan.Method.Body.Instructions.Where(i => i.IsLdarg() && i.GetParameter(plan.Method.Parameters) == plan.Parameter &&
            !AlreadyTyped(plan.Method, i, plan.Array, plan.AfterCasts)).ToArray())
        {
            var il = plan.Method.Body.Instructions;
            var next = il.IndexOf(read) + 1;
            while (next < il.Count && il[next].OpCode.Code == Code.Nop) next++;
            if (plan.AfterCasts)
            {
                while (next < il.Count && il[next].OpCode.Code is Code.Nop or Code.Castclass) next++;
                il.Insert(next, OpCodes.Castclass.ToInstruction(importer.Import(plan.Array).ToTypeDefOrRef()));
                continue;
            }
            // A previous recovery may have inserted the closed caller type. Its
            // replacement is equivalent at every proved instantiation, while
            // retaining the open body's generic stack type.
            if (plan.Array.ContainsGenericParameter && next < il.Count &&
                il[next] is { OpCode.Code: Code.Castclass, Operand: ITypeDefOrRef existing } &&
                new SigComparer().Equals(existing.ToTypeSig(), plan.Concrete))
                il[next].Operand = importer.Import(plan.Array).ToTypeDefOrRef();
            else il.Insert(il.IndexOf(read) + 1, OpCodes.Castclass.ToInstruction(importer.Import(plan.Array).ToTypeDefOrRef()));
        }
        foreach (var method in plans.Select(p => p.Method).Distinct()) method.Body.SimplifyBranches();
        var verification = AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
            CilantroPipeline.BuildRewriteAllowance(context));
        if (!verification.Passed) return (PassStatus.Partial, 0, [$"{TypeLabel} parameter typing rolled back after structural verification."]);
        transaction.Commit();
        foreach (var method in uncalledForwarders.Where(m => m.Body.Instructions.Any(i =>
                     i.Operand is IMethod call && plans.Any(p => p.Method == call.ResolveMethodDef()))))
            context.AddEvidence(new(analysis.ClosedUncalled.Contains(method) ? "typing-uncalled-internal-method" : "typing-uncalled-resource-forwarder",
                analysis.ClosedUncalled.Contains(method)
                    ? "Excluded an unreferenced internal static method from caller inputs: no friend assembly, reflective exposure, name, handle, export, attribute or accessor can supply a caller. Body retained unchanged."
                    : "Excluded an unreferenced forwarding helper from caller inputs: its resource lookup does not expose methods, its non-public static boundary has no friend assemblies, and no IL or metadata alias names it. Body retained unchanged.", method.FullName));
        foreach (var plan in plans) context.AddChange(new(Name, ChangeKind, plan.Method.FullName,
            $"Restored {plan.Array.FullName} at reads of parameter {plan.Parameter.Index}; every potentially callable direct caller supplies a value compatible with this proven {TypeLabel} type. Signature unchanged."));
        return (PassStatus.Success, plans.Count, [$"Restored {TypeLabel} stack types for {plans.Count} parameter(s) from closed caller evidence."]);
    }

    private static bool HasClosedCallerBoundary(MethodDef method, bool hasFriends)
    {
        if (MemberVisibility.IsExternallyVisible(method)) return false;
        if (!hasFriends || method.IsPrivate) return true;
        for (var owner = method.DeclaringType; owner is not null; owner = owner.DeclaringType)
            if (owner.IsNestedPrivate) return true;
        return false;
    }

    // Recover only the stack slots consumed by this call. Loops elsewhere in the
    // method and unrelated exception clauses do not invalidate a local proof.
    // Never carry a value across an exception-region boundary or handler edge.
    private static HashSet<MethodDef> UncalledResourceForwarders(ModuleDef module, MethodDef[] methods,
        HashSet<TypeDef> exposed, HashSet<string> names)
    {
        if (module.Assembly is not { } assembly || assembly.CustomAttributes.Any(a =>
                a.TypeFullName == "System.Runtime.CompilerServices.InternalsVisibleToAttribute")) return [];
        var resourceOwners = methods.Where(m => m.HasBody).SelectMany(m => m.Body.Instructions.Select((i, n) => (m, i, n)))
            .Where(p => p.i.OpCode.Code == Code.Ldtoken && p.i.Operand is ITypeDefOrRef &&
                ResourceLookupTypeHandleUse.IsClosed(p.m, p.n))
            .Select(p => ((ITypeDefOrRef)p.i.Operand).ResolveTypeDef()).Where(t => t?.Module == module).ToHashSet();
        var referenced = methods.Where(m => m.HasBody).SelectMany(m => m.Body.Instructions)
            .Select(i => i.Operand).OfType<IMethod>().Select(m => m.ResolveMethodDef())
            .Concat(module.GetMemberRefs().Where(r => r.IsMethodRef).Select(r => r.ResolveMethodDef())).ToHashSet();
        var result = new HashSet<MethodDef>();
        foreach (var method in methods.Where(m => m.HasBody && m.IsStatic && (m.IsPrivate || m.IsAssembly) &&
                     !m.IsSpecialName && !m.IsConstructor && !m.IsVirtual && !m.IsUnmanagedExport && m.ExportInfo is null &&
                     !m.IsPinvokeImpl && !m.HasCustomAttributes &&
                     !m.HasGenericParameters && !m.DeclaringType.HasGenericParameters && m.Overrides.Count == 0 &&
                     resourceOwners.Contains(m.DeclaringType) && !exposed.Contains(m.DeclaringType) &&
                     !referenced.Contains(m) && m != module.EntryPoint && !names.Contains(m.Name.String) && !names.Contains(m.FullName)))
        {
            if (method.Body.HasExceptionHandlers) continue;
            var code = method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
            if (code.Length != method.Parameters.Count + 2 || code[^1].OpCode.Code != Code.Ret ||
                code[^2].OpCode.Code is not (Code.Call or Code.Callvirt) || code[^2].Operand is not IMethod call ||
                call.ResolveMethodDef() is not { IsVirtual: false, IsConstructor: false } target || target.Module != module || target == method ||
                call.MethodSig is not { ExplicitThis: false, GenParamCount: 0, ParamsAfterSentinel: null } signature ||
                signature.Params.Count + (signature.HasThis ? 1 : 0) != method.Parameters.Count ||
                (signature.RetType.ElementType == ElementType.Void) != (method.ReturnType.ElementType == ElementType.Void) ||
                method.ReturnType.ElementType != ElementType.Object && !new SigComparer().Equals(method.ReturnType, signature.RetType) ||
                code.Take(code.Length - 2).Where((i, n) => !i.IsLdarg() || i.GetParameter(method.Parameters) != method.Parameters[n]).Any() ||
                method.DeclaringType.Properties.Any(p => p.GetMethods.Contains(method) || p.SetMethods.Contains(method) || p.OtherMethods.Contains(method)) ||
                method.DeclaringType.Events.Any(e => e.AddMethod == method || e.RemoveMethod == method || e.InvokeMethod == method || e.OtherMethods.Contains(method))) continue;
            result.Add(method);
        }
        return result;
    }

    private CallerValue[]? BackwardInputs(MethodDef method, ControlFlowGraph graph, Instruction call, int count,
        IReadOnlyDictionary<Parameter, TypeSig> inferred)
    {
        if (count > 128) return null;
        var positions = method.Body.Instructions.Select((i, n) => (i, n)).ToDictionary(p => p.i, p => p.n);
        var active = new HashSet<(int, int)>();
        var memo = new Dictionary<(int, int), CallerValue?>();
        var steps = 0;
        CallerValue? Read(int before, int slot)
        {
            var key = (before, slot);
            if (memo.TryGetValue(key, out var saved)) return saved;
            if (++steps > 4096 || active.Count >= 256 || !active.Add(key)) return null;
            try
            {
                var block = graph.BlockOf(method.Body.Instructions[before]);
                if (block.First == method.Body.Instructions[before])
                {
                    CallerValue? combined = null;
                    foreach (var edge in block.Predecessors)
                    {
                        if (edge.Kind == ControlFlowEdgeKind.Exception ||
                            !graph.HaveIdenticalExceptionRegions(edge.Source.Last, block.First)) return null;
                        var value = After(positions[edge.Source.Last], slot);
                        if (value is null) return null;
                        if (combined is null || combined.IsNull) combined = value;
                        else if (!value.IsNull)
                        {
                            if (combined.Type is null || value.Type is null) return null;
                            if (combined.Type.ElementType == ElementType.Object || value.Type.ElementType == ElementType.Object)
                            {
                                if (combined.Source is null || combined.Source != value.Source ||
                                    !new SigComparer().Equals(combined.Type, value.Type)) return null;
                            }
                            else
                            {
                                var merged = MergeTypes(combined.Type, value.Type);
                                if (merged is null) return null;
                                combined = new(merged);
                            }
                        }
                    }
                    return memo[key] = combined;
                }
                return memo[key] = After(before - 1, slot);
            }
            finally { active.Remove(key); }
        }
        CallerValue? After(int at, int slot)
        {
            var i = method.Body.Instructions[at];
            i.CalculateStackUsage(out var pushes, out var pops);
            if (pops < 0 || i.OpCode.Code is Code.Leave or Code.Leave_S or Code.Jmp) return null;
            if (slot >= pushes) return Read(at, slot - pushes + pops);
            if (i.OpCode.Code == Code.Dup) return Read(at, 0);
            if (i.OpCode.Code == Code.Ldnull) return new(null, IsNull: true);
            var source = i.IsLdarg() ? i.GetParameter(method.Parameters) : null;
            TypeSig? type = source is not null ? inferred.GetValueOrDefault(source, source.Type) :
                i.IsLdloc() ? i.GetLocal(method.Body.Variables)?.Type :
                i.OpCode.Code == Code.Ldstr ? method.Module.CorLibTypes.String :
                i.OpCode.Code == Code.Newobj && i.Operand is IMethod constructor ? constructor.DeclaringType.ToTypeSig() :
                i.OpCode.Code == Code.Newarr && i.Operand is ITypeDefOrRef element ? new SZArraySig(element.ToTypeSig()) :
                i.OpCode.Code is Code.Castclass or Code.Isinst && i.Operand is ITypeDefOrRef cast ? cast.ToTypeSig() :
                i.OpCode.Code is Code.Call or Code.Callvirt && i.Operand is IMethod invoked ? ReturnedType(invoked) :
                i.OpCode.Code is Code.Ldfld or Code.Ldsfld && i.Operand is IField field ? field.FieldSig?.Type : null;
            return type is null ? null : ProducedValue(method, i, type);
        }
        var result = new CallerValue[count];
        for (var n = 0; n < count; n++)
        {
            var value = Read(positions[call], count - 1 - n);
            // Unknown evidence poisons this parameter, not independent argument slots.
            result[n] = value ?? new CallerValue(null);
        }
        return result;
    }
    private Dictionary<BasicBlock, CallerValue[]> AcyclicEntries(MethodDef method, ControlFlowGraph graph,
        IReadOnlyDictionary<Parameter, TypeSig> inferred)
    {
        var entries = new Dictionary<BasicBlock, CallerValue[]>();
        if (method.Body.HasExceptionHandlers || graph.Blocks.Count > 2048) return entries;
        var outputs = new Dictionary<BasicBlock, CallerValue[]?>();
        var active = new HashSet<BasicBlock>();
        CallerValue Merge(CallerValue first, CallerValue second)
        {
            if (first.IsNull) return second;
            if (second.IsNull) return first;
            if (first.Type is null || second.Type is null) return new(null);
            if (first.Type.ElementType == ElementType.Object || second.Type.ElementType == ElementType.Object)
                return first.Source is not null && first.Source == second.Source && new SigComparer().Equals(first.Type, second.Type) ? first : new(null);
            var common = MergeTypes(first.Type, second.Type);
            return new(common);
        }
        CallerValue[]? Exit(BasicBlock block)
        {
            if (outputs.TryGetValue(block, out var saved)) return saved;
            if (active.Count >= 256 || !active.Add(block)) return null;
            try
            {
                CallerValue[]? incoming = null;
                if (block == graph.Entry)
                {
                    if (block.Predecessors.Count != 0) return outputs[block] = null;
                    incoming = [];
                }
                else
                {
                    foreach (var edge in block.Predecessors)
                    {
                        if (edge.Kind == ControlFlowEdgeKind.Exception || Exit(edge.Source) is not { } previous) return outputs[block] = null;
                        if (incoming is null) incoming = previous.ToArray();
                        else
                        {
                            if (incoming.Length != previous.Length) return outputs[block] = null;
                            for (var n = 0; n < incoming.Length; n++) incoming[n] = Merge(incoming[n], previous[n]);
                        }
                    }
                    if (incoming is null) return outputs[block] = null;
                }
                entries[block] = incoming;
                var stack = incoming.ToList();
                foreach (var instruction in block.Instructions)
                {
                    if (instruction.OpCode.Code == Code.Nop) continue;
                    if (instruction.OpCode.Code == Code.Dup)
                    {
                        if (stack.Count == 0) return outputs[block] = null;
                        stack.Add(stack[^1]); continue;
                    }
                    instruction.CalculateStackUsage(out var pushes, out var pops);
                    if (pops < 0 || instruction.OpCode.Code is Code.Leave or Code.Leave_S or Code.Jmp)
                    { stack.Clear(); continue; }
                    if (pops > stack.Count) return outputs[block] = null;
                    var code = instruction.OpCode.Code;
                    var boxedArray = code == Code.Box && pops == 1 && instruction.Operand is ITypeDefOrRef boxed &&
                        boxed.ToTypeSig() is SZArraySig or ArraySig && new SigComparer().Equals(stack[^1].Type, boxed.ToTypeSig()) ? stack[^1].Type : null;
                    var indirect = code == Code.Ldind_Ref && pops == 1 && stack[^1].Type is ByRefSig address && AcceptsType(address.Next) ? address.Next : null;
                    var elementType = code == Code.Ldelem_Ref && pops == 2 && stack[^2].Type is SZArraySig array ? array.Next : null;
                    TypeSig? type = instruction.IsLdloc() ? instruction.GetLocal(method.Body.Variables)?.Type :
                        instruction.IsLdarg() && instruction.GetParameter(method.Parameters) is { } argument ? inferred.GetValueOrDefault(argument, argument.Type) :
                        code == Code.Ldstr ? method.Module.CorLibTypes.String :
                        code == Code.Newobj && instruction.Operand is IMethod constructor ? constructor.DeclaringType.ToTypeSig() :
                        code == Code.Newarr && instruction.Operand is ITypeDefOrRef item ? new SZArraySig(item.ToTypeSig()) :
                        code is Code.Castclass or Code.Isinst && instruction.Operand is ITypeDefOrRef cast ? cast.ToTypeSig() :
                        code is Code.Call or Code.Callvirt && instruction.Operand is IMethod call ? ReturnedType(call) :
                        code is Code.Ldfld or Code.Ldsfld && instruction.Operand is IField field ? field.FieldSig?.Type : boxedArray ?? indirect ?? elementType;
                    var value = ProducedValue(method, instruction, type);
                    stack.RemoveRange(stack.Count - pops, pops);
                    for (var n = 0; n < pushes; n++) stack.Add(value);
                }
                return outputs[block] = stack.ToArray();
            }
            finally { active.Remove(block); }
        }
        foreach (var block in graph.Blocks) Exit(block);
        return entries;
    }
    // Erased arguments also reach array APIs through typed spills, constructors and
    // ordinary calls. These shapes select consumers; unanimous caller evidence above
    // remains the authority for the cast, never the callee's desired parameter type.
    protected virtual string TypeLabel => "array";
    protected virtual TypeSig PreferConsumerType(Parameter parameter, TypeSig common, IReadOnlyList<TypeSig> inputs) => common;
    private TypeSig GenericBodyType(MethodDef method, Parameter parameter, TypeSig concrete, IEnumerable<CallSite> calls,
        Dictionary<MethodDef, ControlFlowGraph> graphs)
    {
        if (!method.HasGenericParameters) return concrete;
        var invocations = calls.ToArray();
        if (invocations.Length == 0) return concrete;
        var il = method.Body.Instructions;
        TypeSig? template = null;
        for (var index = 0; index < il.Count; index++)
        {
            if (!il[index].IsLdarg() || il[index].GetParameter(method.Parameters) != parameter) continue;
            var next = index + 1;
            while (next < il.Count && il[next].OpCode.Code == Code.Nop) next++;
            if (next < il.Count && il[next] is { OpCode.Code: Code.Castclass, Operand: ITypeDefOrRef cast } &&
                (new SigComparer().Equals(cast.ToTypeSig(), concrete) || cast.ToTypeSig().ContainsGenericParameter)) next++;
            while (next < il.Count && il[next].OpCode.Code == Code.Nop) next++;
            if (next >= il.Count || !il[next].IsStloc() ||
                il[next].GetLocal(method.Body.Variables)?.Type is not { ContainsGenericParameter: true } local) continue;
            // The local proposes a template, never evidence for the value's type.
            // Closed instantiations must agree with the concrete seed; an open
            // caller must already supply the exact bound template independently.
            if (invocations.Any(site => !ProvesTemplate(site, local))) continue;
            if (template is not null && !new SigComparer().Equals(template, local)) return concrete;
            template = local;
        }
        return template ?? concrete;

        bool ProvesTemplate(CallSite site, TypeSig proposed)
        {
            if (!IsDirectDefinitionCall(site.Call, method)) return false;
            var bound = Interpretation.GenericScope.For(site.Call, null)?.Bind(proposed);
            if (bound is null) return false;
            if (IsClosedDirectCall(site.Call, method)) return new SigComparer().Equals(bound, concrete);
            var actual = BackwardInputs(site.Caller, graphs[site.Caller], site.Instruction, method.Parameters.Count,
                new Dictionary<Parameter, TypeSig>())?[parameter.Index];
            return actual?.IsNull == true || actual?.Type is { } type && new SigComparer().Equals(type, bound);
        }
    }
    internal static TypeSig? ReturnedType(IMethod method)
    {
        var signature = method.MethodSig;
        if (signature is null) return null;
        if (method is MethodSpec specification &&
            (specification.GenericInstMethodSig?.GenericArguments is not { } arguments || arguments.Count != signature.GenParamCount))
            return null;
        // Both declaring-type and method parameters belong to the call-site scope.
        // For example, List<int>.ToArray returns int[], not an unresolved !0[].
        // Any unbound variable remains open and cannot certify a concrete caller.
        return Interpretation.GenericScope.For(method, null)?.Bind(signature.RetType) ?? signature.RetType;
    }
    protected virtual string ChangeKind => "restore-array-parameter-stack-type";
    protected virtual bool AcceptsType(TypeSig type) => type is SZArraySig or ArraySig;
    protected virtual TypeSig? MergeTypes(TypeSig first, TypeSig second) =>
        new SigComparer().Equals(first, second) ? first : null;
    protected virtual bool ConsumesRecoveredType(MethodDef method) =>
        method.Body.Variables.Any(v => IsArrayConsumerType(v.Type)) ||
        IsArrayConsumerType(method.ReturnType) ||
        method.Body.Instructions.Any(i => IsArrayOperation(i.OpCode.Code) ||
            i.OpCode.Code is Code.Stfld or Code.Stsfld && i.Operand is IField field &&
            field.FieldSig is { } fieldSignature && IsArrayConsumerType(fieldSignature.Type) ||
            i.OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj && i.Operand is IMethod call &&
            call.MethodSig is { } signature && signature.Params.Any(IsArrayConsumerType));

    // This only selects consumers; caller evidence must still prove a concrete array.
    private static bool IsArrayConsumerType(TypeSig type) =>
        type is SZArraySig or ArraySig || type is ClassSig { FullName: "System.Array" };

    private static bool IsArrayOperation(Code code) => code is
        Code.Ldlen or Code.Ldelema or Code.Ldelem or Code.Ldelem_I or
        Code.Ldelem_I1 or Code.Ldelem_U1 or Code.Ldelem_I2 or Code.Ldelem_U2 or
        Code.Ldelem_I4 or Code.Ldelem_U4 or Code.Ldelem_I8 or Code.Ldelem_R4 or
        Code.Ldelem_R8 or Code.Ldelem_Ref or Code.Stelem or Code.Stelem_I or
        Code.Stelem_I1 or Code.Stelem_I2 or Code.Stelem_I4 or Code.Stelem_I8 or
        Code.Stelem_R4 or Code.Stelem_R8 or Code.Stelem_Ref;

    // An open method argument does not invalidate a different, independently
    // concrete value slot. Generic-dependent inputs still fail type inference;
    // recovering an open body template below continues to require closed calls.
    private static bool IsDirectDefinitionCall(IMethod invoked, MethodDef target) => target.HasGenericParameters
        ? invoked is MethodSpec { Method: MethodDef definition, GenericInstMethodSig: { } arguments } &&
            ReferenceEquals(definition, target) && arguments.GenericArguments.Count == target.GenericParameters.Count
        : ReferenceEquals(invoked, target);
    private static bool IsClosedDirectCall(IMethod invoked, MethodDef target) => target.HasGenericParameters
        ? invoked is MethodSpec { Method: MethodDef definition, GenericInstMethodSig: { } arguments } &&
            ReferenceEquals(definition, target) && arguments.GenericArguments.Count == target.GenericParameters.Count &&
            arguments.GenericArguments.All(t => !t.ContainsGenericParameter)
        : ReferenceEquals(invoked, target);

    private static bool AlreadyTyped(MethodDef method, Instruction read, TypeSig array, bool afterCasts = false)
    {
        var index = method.Body.Instructions.IndexOf(read) + 1;
        while (index < method.Body.Instructions.Count && method.Body.Instructions[index].OpCode.Code == Code.Nop) index++;
        if (afterCasts)
        {
            TypeSig? last = null;
            while (index < method.Body.Instructions.Count)
            {
                var instruction = method.Body.Instructions[index++];
                if (instruction.OpCode.Code == Code.Nop) continue;
                if (instruction is not { OpCode.Code: Code.Castclass, Operand: ITypeDefOrRef cast }) break;
                last = cast.ToTypeSig();
            }
            return last is not null && new SigComparer().Equals(last, array);
        }
        return index < method.Body.Instructions.Count && method.Body.Instructions[index] is { OpCode.Code: Code.Castclass, Operand: ITypeDefOrRef type } &&
            new SigComparer().Equals(type.ToTypeSig(), array);
    }
}
