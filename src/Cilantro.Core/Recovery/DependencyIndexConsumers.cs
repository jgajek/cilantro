using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Closes direct CIL mutations and escapes of a dependency index after construction.</summary>
internal static class DependencyIndexConsumers
{
    [Flags]
    private enum Kind { None = 0, Null = 1, Table = 2, Entry = 4, Keys = 8, Enumerator = 16, EntryAddress = 32 }

    internal static bool Check(MethodDef resolver, MethodDef constructor, DependencyIndexConstruction.Snapshot index, out string reason)
    {
        var table = index.Table;
        var records = index.Entries.Select(e => e.Type).ToHashSet();
        var data = index.Entries.SelectMany(e => e.Values.Keys).ToHashSet();
        var methods = resolver.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody).ToArray();
        var recordConstructors = records.SelectMany(t => t.Methods).Where(m => m.IsInstanceConstructor).ToHashSet();
        reason = "The index publication or record types are externally visible.";
        if (MemberVisibility.IsExternallyVisible(table.DeclaringType) || records.Any(MemberVisibility.IsExternallyVisible)) return false;
        var consumers = new HashSet<MethodDef>();
        foreach (var method in methods)
        {
            foreach (var instruction in method.Body.Instructions)
            {
                reason = $"Unowned index mutation or exposure in {method.FullName} IL_{instruction.Offset:X4}.";
                if (instruction.Operand is IMethod called && called.ResolveMethodDef() is { } target && recordConstructors.Contains(target) &&
                    (method != constructor || instruction.OpCode.Code != Code.Newobj)) return false;
                if (instruction.Operand is ITypeDefOrRef type && records.Contains(type.ResolveTypeDef()) && instruction.OpCode.Code == Code.Ldtoken) return false;
                if (instruction.Operand is not IField fieldReference || fieldReference.ResolveFieldDef() is not { } field) continue;
                if (field == table)
                {
                    if (method == constructor && instruction.OpCode.Code == Code.Stsfld) continue;
                    if (instruction.OpCode.Code != Code.Ldsfld) return false;
                    if (method != constructor) consumers.Add(method);
                }
                if (data.Contains(field))
                {
                    if (instruction.OpCode.Code == Code.Stfld && (method == constructor || recordConstructors.Contains(method))) continue;
                    if (instruction.OpCode.Code != Code.Ldfld) return false;
                }
                if (records.Contains(field.DeclaringType) && method != constructor && !recordConstructors.Contains(method)) consumers.Add(method);
            }
            if (method != constructor && !recordConstructors.Contains(method) &&
                (method.Parameters.Any(p => Typed(p.Type) != Kind.None) || method.Body.Variables.Any(v => Typed(v.Type) != Kind.None))) consumers.Add(method);
        }
        var budget = 500_000;
        foreach (var method in consumers)
        {
            if (!Analyze(method, out reason)) return false;
        }
        reason = "Index consumers only read the table and construction-owned integer fields; resolver assembly/path caches remain writable.";
        return true;

        Kind Typed(TypeSig type)
        {
            if (type is ByRefSig reference && reference.Next.ToTypeDefOrRef()?.ResolveTypeDef() is { } element && records.Contains(element)) return Kind.EntryAddress;
            return type.ToTypeDefOrRef()?.ResolveTypeDef() is { } definition && records.Contains(definition) ? Kind.Entry : Kind.None;
        }

        bool Analyze(MethodDef method, out string failure)
        {
            failure = "Unsupported index consumer " + method.FullName;
            if (consumers.Count > 64 || method.HasGenericParameters || method.DeclaringType.HasGenericParameters ||
                method.Body.Instructions.Count == 0 || method.Parameters.Any(p => Typed(p.Type) != Kind.None) && !method.IsPrivate) return false;
            var cfg = ControlFlowGraph.Build(method);
            var states = new Dictionary<BasicBlock, Flow>();
            states[cfg.Entry] = new([], new Kind[method.Body.Variables.Count], method.Parameters.Select(p => Typed(p.Type)).ToArray());
            var queue = new Queue<BasicBlock>(); queue.Enqueue(cfg.Entry);
            while (queue.TryDequeue(out var block))
            {
                var state = states[block].Copy();
                var exceptional = state.Copy();
                foreach (var instruction in block.Instructions)
                {
                    failure = $"Index reference mutation or escape at {method.FullName} IL_{instruction.Offset:X4} ({instruction.OpCode}).";
                    if (--budget < 0) return false;
                    if (!Step(instruction)) return false;
                    for (var n = 0; n < exceptional.Locals.Length; n++) exceptional.Locals[n] |= state.Locals[n];
                    for (var n = 0; n < exceptional.Args.Length; n++) exceptional.Args[n] |= state.Args[n];
                }
                foreach (var edge in block.Successors)
                {
                    var outgoing = state.Copy();
                    if (edge.Kind == ControlFlowEdgeKind.Exception)
                    {
                        outgoing = exceptional.Copy(); outgoing.Stack.Clear();
                        if (method.Body.ExceptionHandlers.Any(h => h.FilterStart == edge.Target.First ||
                            h.HandlerStart == edge.Target.First && h.HandlerType is ExceptionHandlerType.Catch or ExceptionHandlerType.Filter))
                            outgoing.Stack.Add(Kind.None);
                    }
                    if (!states.TryGetValue(edge.Target, out var old)) { states[edge.Target] = outgoing; queue.Enqueue(edge.Target); }
                    else
                    {
                        if (old.Stack.Count != outgoing.Stack.Count) return false;
                        if (old.Merge(outgoing)) queue.Enqueue(edge.Target);
                    }
                }

                bool Step(Instruction i)
                {
                    var code = i.OpCode.Code;
                    if (code is Code.Calli or Code.Jmp or Code.Localloc or Code.Cpblk or Code.Initblk) return false;
                    if (i.IsLdarg()) { state.Stack.Add(state.Args[i.GetParameterIndex()]); return true; }
                    if (i.IsLdloc())
                    { var local = i.GetLocal(method.Body.Variables); state.Stack.Add(state.Locals[local.Index] | Typed(local.Type)); return true; }
                    if (i.IsStloc())
                    { if (!state.Pop(out var value)) return false; state.Locals[i.GetLocal(method.Body.Variables).Index] = value; return true; }
                    if (code is Code.Starg or Code.Starg_S)
                    { if (!state.Pop(out var value)) return false; state.Args[((Parameter)i.Operand).Index] = value; return true; }
                    if (code == Code.Ldnull) { state.Stack.Add(Kind.Null); return true; }
                    if (code == Code.Dup)
                    { if (!state.Pop(out var value)) return false; state.Stack.Add(value); state.Stack.Add(value); return true; }
                    if (code is Code.Ldloca or Code.Ldloca_S)
                    {
                        var local = i.GetLocal(method.Body.Variables);
                        if (Typed(local.Type) == Kind.Entry) { state.Stack.Add(Kind.EntryAddress); return true; }
                        if (Sensitive(state.Locals[local.Index])) return false;
                        state.Stack.Add(Kind.None); return true;
                    }
                    if (code is Code.Ldarga or Code.Ldarga_S)
                    {
                        if (Sensitive(state.Args[((Parameter)i.Operand).Index])) return false;
                        state.Stack.Add(Kind.None); return true;
                    }
                    if (code is Code.Castclass or Code.Isinst)
                    {
                        if (!state.Pop(out var value)) return false;
                        var typed = i.Operand is ITypeDefOrRef cast ? Typed(cast.ToTypeSig()) : Kind.None;
                        state.Stack.Add(value | typed); return true;
                    }
                    if (code == Code.Stind_Ref)
                    {
                        if (!state.Pop(out var value) || !state.Pop(out var address)) return false;
                        if (address == Kind.EntryAddress) return value != Kind.None && (value & ~(Kind.Entry | Kind.Null)) == 0;
                        return !Sensitive(address) && !Sensitive(value);
                    }
                    if (i.Operand is IField reference && reference.ResolveFieldDef() is { } field)
                    {
                        if (code is Code.Ldfld or Code.Ldsfld)
                        {
                            var receiver = Kind.None;
                            if (code == Code.Ldfld && !state.Pop(out receiver)) return false;
                            if (Sensitive(receiver) && ((receiver & ~(Kind.Entry | Kind.Null)) != 0 || !records.Contains(field.DeclaringType))) return false;
                            state.Stack.Add(field == table ? Kind.Table : Typed(field.FieldType)); return true;
                        }
                        if (code is Code.Stfld or Code.Stsfld)
                        {
                            if (!state.Pop(out var value) || Sensitive(value)) return false;
                            if (code == Code.Stfld)
                            {
                                if (!state.Pop(out var receiver)) return false;
                                if (Sensitive(receiver) && ((receiver & ~(Kind.Entry | Kind.Null)) != 0 || !records.Contains(field.DeclaringType) ||
                                    data.Contains(field) || method != resolver)) return false;
                            }
                            return field != table;
                        }
                    }
                    if (code is Code.Call or Code.Callvirt or Code.Newobj && i.Operand is IMethod called)
                    {
                        i.CalculateStackUsage(out var pushes, out var pops);
                        if (pops < 0 || pops > state.Stack.Count) return false;
                        var arguments = state.Stack.TakeLast(pops).ToArray(); state.Stack.RemoveRange(state.Stack.Count - pops, pops);
                        var result = Kind.None;
                        var definition = called.ResolveMethodDef();
                        if (definition?.Module == method.Module && definition.Parameters.Count == arguments.Length)
                            for (var n = 0; n < arguments.Length; n++)
                            {
                                var expected = Typed(definition.Parameters[n].Type);
                                // Do not lose an out-entry through an object-typed
                                // local address in malformed or type-erased CIL.
                                if (expected != Kind.None && (arguments[n] & ~Kind.Null) != expected &&
                                    !(expected == Kind.Entry && arguments[n] == Kind.Null)) return false;
                            }
                        if (arguments.Any(Sensitive))
                        {
                            if (!ReadOnlyCall(called, arguments, method.Module, out result))
                            {
                                var target = called.ResolveMethodDef();
                                if (code != Code.Call || target is null || !consumers.Contains(target) || !target.IsPrivate || !target.IsStatic ||
                                    called is MethodSpec || target.Parameters.Count != arguments.Length) return false;
                                for (var n = 0; n < arguments.Length; n++)
                                    if (Sensitive(arguments[n]) && ((arguments[n] & ~Kind.Null) != Typed(target.Parameters[n].Type))) return false;
                                result = Typed(target.ReturnType);
                            }
                        }
                        else result = Typed(called.MethodSig.RetType);
                        for (var n = 0; n < pushes; n++) state.Stack.Add(result);
                        return true;
                    }
                    if (code is Code.Leave or Code.Leave_S) { state.Stack.Clear(); return true; }
                    if (code == Code.Endfinally) return state.Stack.Count == 0;
                    if (code == Code.Ret)
                    {
                        if (method.ReturnType.ElementType != ElementType.Void && (!state.Pop(out var value) || Sensitive(value))) return false;
                        return state.Stack.Count == 0;
                    }
                    i.CalculateStackUsage(out var count, out var consumed);
                    if (consumed < 0 || consumed > state.Stack.Count) return false;
                    var supplied = state.Stack.TakeLast(consumed).ToArray(); state.Stack.RemoveRange(state.Stack.Count - consumed, consumed);
                    if (supplied.Any(Sensitive) && code is not (Code.Pop or Code.Ceq or Code.Cgt_Un or Code.Brtrue or Code.Brtrue_S or
                        Code.Brfalse or Code.Brfalse_S or Code.Beq or Code.Beq_S or Code.Bne_Un or Code.Bne_Un_S)) return false;
                    for (var n = 0; n < count; n++) state.Stack.Add(Kind.None);
                    return true;
                }
            }
            return true;
        }
    }

    private static bool Sensitive(Kind value) => (value & ~Kind.Null) != 0;

    private static bool ReadOnlyCall(IMethod called, Kind[] arguments, ModuleDef module, out Kind result)
    {
        result = Kind.None;
        if (called.MethodSig is not { HasThis: true } || called.MethodSig.ParamsAfterSentinel?.Count is > 0 ||
            called.DeclaringType is not TypeRef type || type.DefinitionAssembly?.FullName != module.CorLibTypes.AssemblyRef.FullName ||
            arguments.Length == 0 || arguments.Skip(1).Any(Sensitive)) return false;
        var receiver = arguments[0] & ~Kind.Null;
        switch (called.FullName)
        {
            case "System.Boolean System.Collections.Hashtable::ContainsKey(System.Object)": return receiver == Kind.Table;
            case "System.Object System.Collections.Hashtable::get_Item(System.Object)": result = Kind.Entry; return receiver == Kind.Table;
            case "System.Collections.ICollection System.Collections.Hashtable::get_Keys()": result = Kind.Keys; return receiver == Kind.Table;
            case "System.Collections.IEnumerator System.Collections.IEnumerable::GetEnumerator()": result = Kind.Enumerator; return receiver == Kind.Keys;
            case "System.Boolean System.Collections.IEnumerator::MoveNext()": return receiver == Kind.Enumerator;
            case "System.Object System.Collections.IEnumerator::get_Current()": return receiver == Kind.Enumerator;
            case "System.Void System.IDisposable::Dispose()": return receiver == Kind.Enumerator;
            default: return false;
        }
    }

    private sealed record Flow(List<Kind> Stack, Kind[] Locals, Kind[] Args)
    {
        internal Flow Copy() => new([.. Stack], [.. Locals], [.. Args]);
        internal bool Pop(out Kind value)
        { value = Kind.None; if (Stack.Count == 0) return false; value = Stack[^1]; Stack.RemoveAt(Stack.Count - 1); return true; }
        internal bool Merge(Flow other)
        {
            var changed = false;
            for (var i = 0; i < Stack.Count; i++) { var next = Stack[i] | other.Stack[i]; changed |= next != Stack[i]; Stack[i] = next; }
            for (var i = 0; i < Locals.Length; i++) { var next = Locals[i] | other.Locals[i]; changed |= next != Locals[i]; Locals[i] = next; }
            for (var i = 0; i < Args.Length; i++) { var next = Args[i] | other.Args[i]; changed |= next != Args[i]; Args[i] = next; }
            return changed;
        }
    }
}
