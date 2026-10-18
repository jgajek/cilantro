using Cilantro.Core.Analysis;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Restores array stack types where every closed caller already supplies that array.</summary>
public class ArrayParameterTypingPass : DeobfuscationPass
{
    private sealed record CallerValue(TypeSig? Type, Parameter? Source = null, bool IsNull = false);
    public override string Name => "array-parameter-typing";
    public override IReadOnlyCollection<string> Dependencies => ["unused-private-helper-cleanup"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var methods = context.Module.GetTypes().SelectMany(t => t.Methods).ToArray();
        var exposed = ModuleReachability.Compute(context.Module).ReflectivelyExposedTypes.ToHashSet();
        var names = RecoveryMethodNames.Collect(context.Module, methods, exposed);
        var scopedNames = new ScopedMethodNameUses(context.Module, exposed);
        var namedHandles = new NamedMethodHandleUses(context.Module);
        var propertyHandles = new PropertyOnlyTypeHandles(context.Module);
        var referenceContracts = ReferenceParameterContracts.Find(context.Module);
        var candidates = methods.Where(m => m.HasBody && m.IsStatic && !m.IsConstructor && !m.IsVirtual &&
            !m.DeclaringType.HasGenericParameters && !MemberVisibility.IsExternallyVisible(m) &&
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
        var delegateInputs = ClosedDelegateParameterTypes.Find(context.Module, candidates, exposed);
        var inferred = new Dictionary<Parameter, TypeSig>();
        var plans = new List<(MethodDef Method, Parameter Parameter, TypeSig Array, TypeSig Concrete, bool AfterCasts)>();
        var instantiations = methods.Where(m => m.HasBody).SelectMany(m => m.Body.Instructions)
            .Where(i => i.OpCode.Code == Code.Call).Select(i => i.Operand).OfType<IMethod>()
            .ToLookup(m => m.ResolveMethodDef());
        var graphs = methods.Where(m => m.HasBody).ToDictionary(m => m, ControlFlowGraph.Build);
        var blocks = graphs.SelectMany(pair => pair.Value.Blocks.Select(block => (method: pair.Key, block))).ToArray();
        var flowMethods = methods.Where(m => m.HasBody && (candidates.Contains(m) || m.Body.Instructions.Any(i =>
            i.Operand is IMethod call && call.ResolveMethodDef() is { } target && candidates.Contains(target)))).ToHashSet();
        // Propagate only already-proven caller parameters. Each round adds a parameter
        // or stops, so chains converge without treating a recursive cycle as evidence.
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
                    if (instruction.Operand is IMethod invoked && invoked.ResolveMethodDef() is { } target && candidates.Contains(target))
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
                    var source = instruction.IsLdarg() ? instruction.GetParameter(method.Parameters) : null;
                    for (var index = 0; index < pushes; index++) stack.Add(new CallerValue(type, source, instruction.OpCode.Code == Code.Ldnull));
                }
            }
            var inputs = new Dictionary<Parameter, CallerValue[]>();
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
                var bodyType = GenericBodyType(method, parameter, common, instantiations[method]);
                if (arrayConsumers.Contains(method) && method.Body.Instructions.Any(i => i.IsLdarg() && i.GetParameter(method.Parameters) == parameter &&
                    !AlreadyTyped(method, i, bodyType, afterCasts))) plans.Add((method, parameter, bodyType, common, afterCasts));
            }
            if (inferred.Count == previousCount) break;
        }
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
        foreach (var plan in plans) context.AddChange(new(Name, ChangeKind, plan.Method.FullName,
            $"Restored {plan.Array.FullName} at reads of parameter {plan.Parameter.Index}; every direct caller supplies a value compatible with this proven {TypeLabel} type. Signature unchanged."));
        return (PassStatus.Success, plans.Count, [$"Restored {TypeLabel} stack types for {plans.Count} parameter(s) from closed caller evidence."]);
    }

    // Recover only the stack slots consumed by this call. Loops elsewhere in the
    // method and unrelated exception clauses do not invalidate a local proof.
    // Never carry a value across an exception-region boundary or handler edge.
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
            return type is null ? null : new(type, source);
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
                    var value = new CallerValue(type, instruction.IsLdarg() ? instruction.GetParameter(method.Parameters) : null, code == Code.Ldnull);
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
    private static TypeSig GenericBodyType(MethodDef method, Parameter parameter, TypeSig concrete, IEnumerable<IMethod> calls)
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
            // Every closed call must instantiate it to the independently proven
            // common caller type before it can be used in the generic body.
            if (invocations.Any(call => !IsClosedDirectCall(call, method) ||
                !new SigComparer().Equals(Interpretation.GenericScope.For(call, null)?.Bind(local), concrete))) continue;
            if (template is not null && !new SigComparer().Equals(template, local)) return concrete;
            template = local;
        }
        return template ?? concrete;
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
