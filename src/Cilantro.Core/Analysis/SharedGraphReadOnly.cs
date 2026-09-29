using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Checks direct CIL consumers of a published reference, not its construction or reflective access.</summary>
internal static class SharedGraphReadOnly
{
    internal sealed record Result(bool Passed, int AliasFields, int Methods, string Detail);

    internal static Result Check(FieldDef root)
    {
        if (MemberVisibility.IsExternallyVisible(root.DeclaringType))
            return new(false, 1, 0, "The root owner is externally visible.");
        if (root.DeclaringType.FindStaticConstructor() is { HasBody: true } initializer &&
            initializer.Body.Instructions.Any(i => i.OpCode.Code != Code.Stsfld && i.Operand is IField f && f.ResolveFieldDef() == root))
            return new(false, 1, 0, "The initializer reads or exposes the published field; its construction boundary needs a separate proof.");
        return CheckPublishedTogether([root], root.DeclaringType.FindStaticConstructor());
    }

    // Only a caller that has separately proved closed construction may exclude
    // initializer uses. Seed every publication, including construction-time aliases.
    internal static Result CheckPublishedTogether(IReadOnlyCollection<FieldDef> roots, MethodDef? initializer)
    {
        if (roots.Count == 0) return new(false, 0, 0, "No published roots.");
        var root = roots.First();
        if (roots.Any(f => f.DeclaringType != root.DeclaringType || MemberVisibility.IsExternallyVisible(f.DeclaringType)))
            return new(false, roots.Count, 0, "Publication owners are not private and shared.");
        var publications = roots.ToHashSet();
        var aliases = new HashSet<FieldDef>(roots);
        var arguments = new Dictionary<MethodDef, HashSet<int>>();
        var returns = new HashSet<MethodDef>();
        var visited = new HashSet<MethodDef>();
        var methods = root.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody).ToArray();
        var changed = false;
        var budget = 500_000;
        string reason = "reference flow exceeded its bound";
        for (var round = 0; round < 32; round++)
        {
            changed = false;
            foreach (var method in methods)
            {
                // Construction is checked separately. This proof covers consumers
                // after publication, and must never be used to justify the initializer.
                if (method == initializer) continue;
                if (!arguments.ContainsKey(method) && !method.Body.Instructions.Any(i =>
                    i.Operand is IField f && f.ResolveFieldDef() is { } field && aliases.Contains(field) ||
                    i.Operand is IMethod called && called.ResolveMethodDef() is { } target && returns.Contains(target))) continue;
                visited.Add(method);
                if (visited.Count > 256 || !Analyze(method))
                    return new(false, aliases.Count, visited.Count, reason);
            }
            if (!changed)
            {
                if (methods.Any(m => m.Body.Instructions.Any(i => i.OpCode.Code is Code.Ldftn or Code.Ldvirtftn &&
                    i.Operand is IMethod target && target.ResolveMethodDef() is { } method && returns.Contains(method))))
                    return new(false, aliases.Count, visited.Count, "A borrowed return is exposed through a function pointer.");
                return new(true, aliases.Count, visited.Count, "Direct CIL consumers only read the published graph.");
            }
        }
        return new(false, aliases.Count, visited.Count, "Reference flow did not converge within 32 rounds.");

        bool Analyze(MethodDef method)
        {
            reason = $"unsupported consumer {method.FullName}";
            if (method.Body.Instructions.Count == 0 || method.Body.ExceptionHandlers.Count != 0 || method.HasGenericParameters) return false;
            var cfg = ControlFlowGraph.Build(method);
            var states = new Dictionary<BasicBlock, Flow>();
            var entry = new Flow([], new bool[method.Body.Variables.Count], new bool[method.Parameters.Count]);
            if (arguments.TryGetValue(method, out var inputs))
                foreach (var index in inputs) { if (index >= entry.Args.Length) return false; entry.Args[index] = true; }
            states[cfg.Entry] = entry;
            var queue = new Queue<BasicBlock>(); queue.Enqueue(cfg.Entry);
            while (queue.TryDequeue(out var block))
            {
                var state = states[block].Copy();
                foreach (var instruction in block.Instructions)
                {
                    reason = $"reference mutation or escape at {method.FullName} IL_{instruction.Offset:X4} ({instruction.OpCode})";
                    if (--budget < 0) { reason = "Reference-flow instruction budget exceeded."; return false; }
                    var code = instruction.OpCode.Code;
                    if (code is Code.Calli or Code.Jmp) return false;
                    if (instruction.IsLdarg()) { state.Stack.Add(state.Args[instruction.GetParameterIndex()]); continue; }
                    if (code is Code.Starg or Code.Starg_S)
                    { if (!state.Pop(out var value)) return false; state.Args[((Parameter)instruction.Operand).Index] = value; continue; }
                    if (instruction.IsLdloc()) { state.Stack.Add(state.Locals[instruction.GetLocal(method.Body.Variables).Index]); continue; }
                    if (instruction.IsStloc())
                    { if (!state.Pop(out var value)) return false; state.Locals[instruction.GetLocal(method.Body.Variables).Index] = value; continue; }
                    if (code == Code.Dup)
                    { if (!state.Pop(out var value)) return false; state.Stack.Add(value); state.Stack.Add(value); continue; }
                    if (code is Code.Ldloca or Code.Ldloca_S)
                    { if (state.Locals[instruction.GetLocal(method.Body.Variables).Index]) return false; state.Stack.Add(false); continue; }
                    if (code is Code.Ldarga or Code.Ldarga_S)
                    { if (state.Args[((Parameter)instruction.Operand).Index]) return false; state.Stack.Add(false); continue; }
                    if (instruction.Operand is IField fieldReference && fieldReference.ResolveFieldDef() is { } field)
                    {
                        if (code is Code.Ldsfld or Code.Ldfld)
                        {
                            var receiver = false;
                            if (code == Code.Ldfld && !state.Pop(out receiver)) return false;
                            state.Stack.Add(aliases.Contains(field) || receiver && ReferenceLike(field.FieldType));
                            continue;
                        }
                        if (code is Code.Stsfld or Code.Stfld)
                        {
                            if (!state.Pop(out var value)) return false;
                            if (code == Code.Stfld && (!state.Pop(out var receiver) || receiver)) return false;
                            if (publications.Contains(field)) return false;
                            if (value)
                            {
                                if (field.Module != root.Module || MemberVisibility.IsExternallyVisible(field.DeclaringType)) return false;
                                changed |= aliases.Add(field);
                            }
                            continue;
                        }
                        if (aliases.Contains(field)) return false;
                    }
                    if (code is Code.Call or Code.Callvirt or Code.Newobj && instruction.Operand is IMethod called)
                    {
                        instruction.CalculateStackUsage(out var pushes, out var pops);
                        if (pops < 0 || pops > state.Stack.Count) return false;
                        var supplied = state.Stack.TakeLast(pops).ToArray(); state.Stack.RemoveRange(state.Stack.Count - pops, pops);
                        var target = called.ResolveMethodDef();
                        var borrowed = supplied.Any(v => v);
                        if (borrowed)
                        {
                            if (ReadOnlyArrayCall(called, root.Module))
                            {
                                for (var push = 0; push < pushes; push++) state.Stack.Add(false);
                                continue;
                            }
                            if (called is MethodSpec || target?.Module != root.Module || !target.HasBody ||
                                code == Code.Newobj || code == Code.Callvirt && target.IsVirtual) return false;
                            if (!arguments.TryGetValue(target, out var known)) arguments[target] = known = [];
                            for (var index = 0; index < supplied.Length; index++) if (supplied[index]) changed |= known.Add(index);
                        }
                        for (var push = 0; push < pushes; push++) state.Stack.Add(target is not null && returns.Contains(target));
                        continue;
                    }
                    if (code == Code.Ret)
                    {
                        if (method.ReturnType.ElementType != ElementType.Void)
                        {
                            if (!state.Pop(out var result)) return false;
                            if (result)
                            {
                                if (method.IsPublic || method.IsFamily || method.IsFamilyOrAssembly || method.IsVirtual) return false;
                                changed |= returns.Add(method);
                            }
                        }
                        if (state.Stack.Count != 0) return false;
                        continue;
                    }
                    instruction.CalculateStackUsage(out var count, out var consumed);
                    if (consumed < 0 || consumed > state.Stack.Count) return false;
                    var values = state.Stack.TakeLast(consumed).ToArray(); state.Stack.RemoveRange(state.Stack.Count - consumed, consumed);
                    var tainted = values.Any(v => v);
                    var propagated = false;
                    if (tainted)
                    {
                        if (code == Code.Ldobj && instruction.Operand is ITypeDefOrRef copied && ScalarValueType(copied)) { }
                        else if (code is Code.Castclass or Code.Isinst or Code.Ldelema or Code.Ldelem_Ref) propagated = true;
                        else if (code == Code.Box && instruction.Operand is ITypeDefOrRef type && !type.IsValueType) propagated = true;
                        else if (code is not (Code.Pop or Code.Ldlen or Code.Ldelem_I1 or Code.Ldelem_U1 or Code.Ldelem_I2 or Code.Ldelem_U2 or
                            Code.Ldelem_I4 or Code.Ldelem_U4 or Code.Ldelem_I8 or Code.Ldelem_R4 or Code.Ldelem_R8 or
                            Code.Ceq or Code.Cgt_Un or Code.Brtrue or Code.Brtrue_S or Code.Brfalse or Code.Brfalse_S or Code.Beq or Code.Beq_S or Code.Bne_Un or Code.Bne_Un_S)) return false;
                    }
                    for (var push = 0; push < count; push++) state.Stack.Add(propagated);
                }
                foreach (var edge in block.Successors)
                {
                    if (!states.TryGetValue(edge.Target, out var old)) { states[edge.Target] = state.Copy(); queue.Enqueue(edge.Target); }
                    else
                    {
                        if (old.Stack.Count != state.Stack.Count) return false;
                        if (old.Merge(state)) queue.Enqueue(edge.Target);
                    }
                }
            }
            return true;
        }
    }

    private static bool ReadOnlyArrayCall(IMethod method, ModuleDef module)
    {
        if (method.DeclaringType.FullName != "System.Array" || method.ResolveMethodDef()?.Module == module) return false;
        if (method.Name == "get_Length" && method.MethodSig is { HasThis: true, Params.Count: 0, RetType.ElementType: ElementType.I4 }) return true;
        return method is MethodSpec { GenericInstMethodSig.GenericArguments.Count: 1 } spec &&
            method.Name == "BinarySearch" && method.MethodSig is { HasThis: false, Params.Count: 2, RetType.ElementType: ElementType.I4 } &&
            !ReferenceLike(spec.GenericInstMethodSig.GenericArguments[0]);
    }

    private static bool ScalarValueType(ITypeDefOrRef type)
    {
        var seen = new HashSet<TypeDef>();
        return Check(type);
        bool Check(ITypeDefOrRef reference)
        {
            if (reference.ResolveTypeDef() is not { IsValueType: true } definition || definition.HasGenericParameters ||
                !seen.Add(definition) || seen.Count > 32) return false;
            var result = definition.Fields.Where(f => !f.IsStatic).All(f => !ReferenceLike(f.FieldType) ||
                f.FieldType.ElementType == ElementType.ValueType && Check(f.FieldType.ToTypeDefOrRef()));
            seen.Remove(definition);
            return result;
        }
    }

    private static bool ReferenceLike(TypeSig type) => type.ElementType is not
        (ElementType.Boolean or ElementType.Char or ElementType.I1 or ElementType.U1 or ElementType.I2 or ElementType.U2 or
        ElementType.I4 or ElementType.U4 or ElementType.I8 or ElementType.U8 or ElementType.R4 or ElementType.R8);

    private sealed record Flow(List<bool> Stack, bool[] Locals, bool[] Args)
    {
        internal Flow Copy() => new([.. Stack], [.. Locals], [.. Args]);
        internal bool Pop(out bool value)
        { value = false; if (Stack.Count == 0) return false; value = Stack[^1]; Stack.RemoveAt(Stack.Count - 1); return true; }
        internal bool Merge(Flow other)
        {
            var changed = false;
            for (var i = 0; i < Stack.Count; i++) if (other.Stack[i] && !Stack[i]) { Stack[i] = true; changed = true; }
            for (var i = 0; i < Locals.Length; i++) if (other.Locals[i] && !Locals[i]) { Locals[i] = true; changed = true; }
            for (var i = 0; i < Args.Length; i++) if (other.Args[i] && !Args[i]) { Args[i] = true; changed = true; }
            return changed;
        }
    }
}
