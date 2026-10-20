using System.Buffers.Binary;
using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Tracks the exact resource slice reaching each call of a dependency decoder.</summary>
internal static class DependencySliceSource
{
    internal sealed record Slice(Instruction Call, int Offset, byte[] Bytes);
    internal sealed record FixedRead(Instruction Call, int Pops, long Value, bool Wide, bool Native = false);
    internal sealed record DiscardPlan(Instruction Open, IReadOnlyList<FixedRead> Reads, IReadOnlyList<Instruction> UnobservedAllocations,
        IReadOnlyList<Instruction> RedundantCasts);
    private enum Kind { Unknown, Integer, Resource, Reader, Buffer, Input, Poison }
    private sealed record Value(Kind Kind, long Number = 0, bool Wide = false, Instruction? Identity = null)
    {
        internal static readonly Value Unknown = new(Kind.Unknown);
        internal static readonly Value Poison = new(Kind.Poison);
        internal bool Protected => Kind is Kind.Resource or Kind.Reader or Kind.Buffer or Kind.Input or Kind.Poison;
    }
    private sealed record Buffer(int Length, int? Offset);

    internal static bool TryRead(EmbeddedDependencyRecoveryPass.ValidatedIndex proof, MethodDef decoder,
        out IReadOnlyList<Slice> slices, out string reason) => TryAnalyze(proof, decoder, false, out slices, out _, out reason);

    internal static bool TryDiscard(EmbeddedDependencyRecoveryPass.ValidatedIndex proof, MethodDef decoder,
        out DiscardPlan? plan, out string reason) => TryAnalyze(proof, decoder, true, out _, out plan, out reason);

    private static bool TryAnalyze(EmbeddedDependencyRecoveryPass.ValidatedIndex proof, MethodDef decoder, bool discard,
        out IReadOnlyList<Slice> slices, out DiscardPlan? plan, out string reason)
    {
        slices = [];
        plan = null;
        reason = "Index ownership or decoder call shape is not closed.";
        var method = proof.Resolver;
        var module = method.Module;
        if (!proof.SourceClosed || !proof.ConsumersClosed || !decoder.IsStatic || !decoder.HasBody || decoder.HasGenericParameters ||
            decoder.DeclaringType.HasGenericParameters || MemberVisibility.IsExternallyVisible(decoder.DeclaringType) ||
            decoder.MethodSig.Params.Count != 1 || decoder.MethodSig.Params[0].ElementType != ElementType.Object ||
            decoder.ReturnType.FullName != "System.IO.Stream" || method.Body.Instructions.Count > 4096 ||
            module.Resources.Count(r => r.Name == proof.Index.Source.Name) != 1) return false;
        var resource = module.Resources.OfType<EmbeddedResource>().SingleOrDefault(proof.Index.Source.Matches);
        if (resource is null) return false;
        var bytes = resource.CreateReader().ToArray();
        var sites = new HashSet<Instruction>();
        foreach (var caller in module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
            foreach (var instruction in caller.Body.Instructions)
                if (instruction.Operand is IMethod reference && reference.ResolveMethodDef() == decoder)
                {
                    if (caller != method || instruction.OpCode.Code != Code.Call || reference is MethodSpec) return false;
                    sites.Add(instruction);
                }
        if (sites.Count is 0 or > 8) return false;
        if (discard && decoder.Body.Instructions.Any(i => i.IsLdarg() || i.OpCode.Code is Code.Ldarga or Code.Ldarga_S or Code.Starg or Code.Starg_S)) return false;
        Instruction? openedAt = null;
        var fixedReads = new Dictionary<Instruction, FixedRead>();
        var scaffolding = new HashSet<Instruction>();
        var inputStreams = new HashSet<Instruction>();
        var identitiesObserved = false;
        var redundantCasts = new HashSet<Instruction>();
        var fields = proof.Index.Entries.SelectMany(e => e.Values).GroupBy(v => v.Key)
            .Where(g => g.Select(v => v.Value).Distinct().Count() == 1).ToDictionary(g => g.Key, g => g.First().Value);
        var cfg = ControlFlowGraph.Build(method);
        var addressedLocals = method.Body.Instructions.Where(i => i.OpCode.Code is Code.Ldloca or Code.Ldloca_S)
            .Select(i => i.GetLocal(method.Body.Variables)).ToHashSet();
        var states = new Dictionary<BasicBlock, Flow> { [cfg.Entry] = new([], new Value[method.Body.Variables.Count], [], null, false) };
        Array.Fill(states[cfg.Entry].Locals, Value.Unknown);
        var queue = new Queue<BasicBlock>(); queue.Enqueue(cfg.Entry);
        var found = new Dictionary<Instruction, (int Offset, int Length)>();
        var budget = 500_000;
        while (queue.TryDequeue(out var block))
        {
            var state = states[block].Copy();
            var exceptional = state.Copy();
            foreach (var instruction in block.Instructions)
            {
                reason = $"Decoder slice is not established at {method.FullName} IL_{instruction.Offset:X4} ({instruction.OpCode}).";
                if (--budget < 0 || !Step(instruction)) return false;
                exceptional.Allocated.UnionWith(state.Allocated);
                exceptional.Opened |= state.Opened;
                for (var n = 0; n < exceptional.Locals.Length; n++)
                    if (state.Locals[n].Protected || exceptional.Locals[n].Protected) exceptional.Locals[n] = Value.Poison;
                    else exceptional.Locals[n] = Value.Unknown;
            }
            foreach (var edge in block.Successors)
            {
                var outgoing = state.Copy();
                if (edge.Kind == ControlFlowEdgeKind.Exception)
                {
                    outgoing = exceptional.Copy(); outgoing.Stack.Clear(); outgoing.Position = null; outgoing.Buffers.Clear();
                    if (method.Body.ExceptionHandlers.Any(h => h.FilterStart == edge.Target.First ||
                        h.HandlerStart == edge.Target.First && h.HandlerType is ExceptionHandlerType.Catch or ExceptionHandlerType.Filter)) outgoing.Stack.Add(Value.Unknown);
                }
                if (!states.TryGetValue(edge.Target, out var prior)) { states[edge.Target] = outgoing; queue.Enqueue(edge.Target); }
                else
                {
                    if (prior.Stack.Count != outgoing.Stack.Count) return false;
                    if (prior.Merge(outgoing)) queue.Enqueue(edge.Target);
                }
            }

            bool Step(Instruction i)
            {
                var code = i.OpCode.Code;
                if (code is Code.Calli or Code.Jmp or Code.Localloc or Code.Cpblk or Code.Initblk or Code.Starg or Code.Starg_S) return false;
                if (i.IsLdcI4()) { state.Stack.Add(new(Kind.Integer, i.GetLdcI4Value())); return true; }
                if (code == Code.Ldc_I8) { state.Stack.Add(new(Kind.Integer, (long)i.Operand, true)); return true; }
                if (i.IsLdloc()) { state.Stack.Add(state.Locals[i.GetLocal(method.Body.Variables).Index]); return true; }
                if (i.IsStloc())
                {
                    if (!state.Pop(out var value)) return false;
                    var local = i.GetLocal(method.Body.Variables);
                    if (value.Protected && addressedLocals.Contains(local)) return false;
                    state.Locals[local.Index] = value; return true;
                }
                if (i.IsLdarg()) { state.Stack.Add(Value.Unknown); return true; }
                if (code is Code.Ldloca or Code.Ldloca_S)
                { if (state.Locals[i.GetLocal(method.Body.Variables).Index].Protected) return false; state.Stack.Add(Value.Unknown); return true; }
                if (code == Code.Dup)
                { if (!state.Pop(out var value)) return false; state.Stack.Add(value); state.Stack.Add(value); return true; }
                if (code is Code.Castclass or Code.Isinst)
                {
                    if (state.Stack.Count == 0) return false;
                    if (discard && state.Stack[^1].Protected)
                    {
                        if (code == Code.Isinst || i.Operand is not ITypeDefOrRef cast ||
                            !DependencyFrameworkScope.Matches(cast, module)) return false;
                        var allowed = state.Stack[^1].Kind switch
                        {
                            Kind.Resource => cast.FullName is "System.Object" or "System.IO.Stream",
                            Kind.Reader => cast.FullName is "System.Object" or "System.IO.BinaryReader",
                            Kind.Buffer => cast.FullName is "System.Object" or "System.Array" or "System.Byte[]",
                            Kind.Input => cast.FullName is "System.Object" or "System.IO.Stream" or "System.IO.MemoryStream",
                            _ => false
                        };
                        if (!allowed) return false;
                        redundantCasts.Add(i);
                    }
                    return true;
                }
                if (code is Code.Conv_I4 or Code.Conv_I8)
                {
                    if (!state.Pop(out var value) || value.Protected) return false;
                    state.Stack.Add(value.Kind == Kind.Integer ? new(Kind.Integer, code == Code.Conv_I4 ? unchecked((int)value.Number) : value.Number,
                        code == Code.Conv_I8) : Value.Unknown); return true;
                }
                if (code is Code.Add or Code.Sub or Code.Xor or Code.And or Code.Or)
                {
                    if (!state.Pop(out var right) || !state.Pop(out var left) || left.Protected || right.Protected) return false;
                    if (left.Kind != Kind.Integer || right.Kind != Kind.Integer || left.Wide != right.Wide) { state.Stack.Add(Value.Unknown); return true; }
                    var number = code switch { Code.Add => unchecked(left.Number + right.Number), Code.Sub => unchecked(left.Number - right.Number),
                        Code.Xor => left.Number ^ right.Number, Code.And => left.Number & right.Number, _ => left.Number | right.Number };
                    state.Stack.Add(new(Kind.Integer, left.Wide ? number : unchecked((int)number), left.Wide)); return true;
                }
                if (code == Code.Newarr)
                {
                    if (!state.Pop(out var length) || length.Protected) return false;
                    if (i.Operand is ITypeDefOrRef type && type.FullName == "System.Byte" && type.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName &&
                        length.Kind == Kind.Integer && length.Number is >= 0 and <= 16 * 1024 * 1024)
                    {
                        if (!state.Allocated.Add(i)) return false; // repeated allocation could hide an older alias
                        state.Buffers.Add(i, new((int)length.Number, null)); state.Stack.Add(new(Kind.Buffer, Identity: i));
                        scaffolding.Add(i);
                    }
                    else state.Stack.Add(Value.Unknown);
                    return true;
                }
                if (code == Code.Ldlen)
                {
                    if (!state.Pop(out var value)) return false;
                    if (value.Kind == Kind.Buffer && value.Identity is { } id && state.Buffers.TryGetValue(id, out var buffer))
                    {
                        state.Stack.Add(new(Kind.Integer, buffer.Length));
                        if (!Record(i, 1, buffer.Length, false, true)) return false;
                    }
                    else { if (value.Protected) return false; state.Stack.Add(Value.Unknown); }
                    return true;
                }
                if (code is Code.Ldfld or Code.Ldsfld && i.Operand is IField reference)
                {
                    if (code == Code.Ldfld && (!state.Pop(out var receiver) || receiver.Protected)) return false;
                    if (reference.ResolveFieldDef() is { } field && fields.TryGetValue(field, out var number))
                        state.Stack.Add(new(Kind.Integer, number, field.FieldType.ElementType == ElementType.I8));
                    else state.Stack.Add(Value.Unknown);
                    return true;
                }
                if (code is Code.Call or Code.Callvirt or Code.Newobj && i.Operand is IMethod called)
                {
                    i.CalculateStackUsage(out var pushes, out var pops);
                    if (pops < 0 || pops > state.Stack.Count) return false;
                    var args = state.Stack.TakeLast(pops).ToArray(); state.Stack.RemoveRange(state.Stack.Count - pops, pops);
                    var result = Value.Unknown;
                    if (sites.Contains(i))
                    {
                        if (args.Length != 1 || args[0].Kind != Kind.Input || args[0].Identity is not { } input ||
                            !state.Buffers.TryGetValue(input, out var buffer) || buffer.Offset is not { } offset) return false;
                        var slice = (offset, buffer.Length);
                        if (found.TryGetValue(i, out var previous) && previous != slice) return false;
                        found[i] = slice;
                        // Until its effects are separately proved, a decoder may
                        // mutate or retain its input. It cannot seed another proof.
                        state.Buffers[input] = buffer with { Offset = null };
                    }
                    else if (called.ResolveMethodDef() == proof.Constructor)
                    {
                        if (args.Length != 1 || args[0].Kind != Kind.Resource) return false;
                        state.Position = proof.Index.Position;
                    }
                    else if (Framework(called, "System.IO.Stream System.Reflection.Assembly::GetManifestResourceStream(System.String)"))
                    {
                        if (state.Opened) return false;
                        if (openedAt is not null && openedAt != i) return false;
                        openedAt = i;
                        state.Opened = true; state.Position = 0; result = new(Kind.Resource);
                    }
                    else if (Framework(called, "System.Int64 System.IO.Stream::Seek(System.Int64,System.IO.SeekOrigin)") && args.Length == 3 && args[0].Kind == Kind.Resource)
                    {
                        if (args[1].Kind != Kind.Integer || args[2].Kind != Kind.Integer || args[2].Number != 0 || args[1].Number < 0 || args[1].Number > bytes.Length) return false;
                        state.Position = args[1].Number; result = new(Kind.Integer, args[1].Number, true);
                        if (!Record(i, 3, args[1].Number, true)) return false;
                    }
                    else if (code == Code.Newobj && Framework(called, "System.Void System.IO.BinaryReader::.ctor(System.IO.Stream)") && args.Length == 1 && args[0].Kind == Kind.Resource)
                    { result = new(Kind.Reader); scaffolding.Add(i); }
                    else if (Framework(called, "System.Int32 System.IO.BinaryReader::ReadInt32()") && args.Length == 1 && args[0].Kind == Kind.Reader)
                    {
                        if (state.Position is not { } position || position < 0 || position > bytes.Length - 4) return false;
                        result = new(Kind.Integer, BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan((int)position, 4)));
                        state.Position = position + 4;
                        if (!Record(i, 1, result.Number, false)) return false;
                    }
                    else if (Framework(called, "System.Int32 System.IO.BinaryReader::Read(System.Byte[],System.Int32,System.Int32)") && args.Length == 4 && args[0].Kind == Kind.Reader)
                    {
                        if (args[1].Kind != Kind.Buffer || args[1].Identity is not { } id || !state.Buffers.TryGetValue(id, out var buffer) ||
                            args[2].Kind != Kind.Integer || args[2].Number != 0 || args[3].Kind != Kind.Integer || args[3].Number != buffer.Length ||
                            state.Position is not { } position || position < 0 || position > bytes.Length - buffer.Length) return false;
                        state.Buffers[id] = buffer with { Offset = (int)position };
                        state.Position = position + buffer.Length; result = new(Kind.Integer, buffer.Length);
                        if (!Record(i, 4, buffer.Length, false)) return false;
                    }
                    else if (code == Code.Newobj && Framework(called, "System.Void System.IO.MemoryStream::.ctor(System.Byte[])") && args.Length == 1 && args[0].Kind == Kind.Buffer)
                    {
                        // Only an inline, fresh stream qualifies. A stored stream
                        // could retain a position changed by a prior decoder call,
                        // even if its underlying byte array was subsequently filled.
                        var next = block.Instructions.SkipWhile(p => p != i).Skip(1).FirstOrDefault(p => p.OpCode.Code != Code.Nop);
                        if (next is null || !sites.Contains(next)) return false;
                        inputStreams.Add(i);
                        result = new(Kind.Input, Identity: args[0].Identity);
                    }
                    else if (args.Any(a => a.Protected)) return false;
                    for (var n = 0; n < pushes; n++) state.Stack.Add(result);
                    return true;
                }
                if (code is Code.Leave or Code.Leave_S) { state.Stack.Clear(); return true; }
                if (code == Code.Endfinally) return state.Stack.Count == 0;
                if (code == Code.Ret)
                {
                    if (method.ReturnType.ElementType != ElementType.Void && (!state.Pop(out var value) || value.Protected)) return false;
                    return state.Stack.Count == 0;
                }
                i.CalculateStackUsage(out var count, out var consumed);
                if (consumed < 0 || consumed > state.Stack.Count) return false;
                var supplied = state.Stack.TakeLast(consumed).ToArray(); state.Stack.RemoveRange(state.Stack.Count - consumed, consumed);
                if (code != Code.Pop && supplied.Any(v => v.Kind is Kind.Reader or Kind.Buffer or Kind.Poison))
                    identitiesObserved = true;
                if (supplied.Any(v => v.Protected) && code is not (Code.Pop or Code.Ceq or Code.Cgt_Un or Code.Brtrue or Code.Brtrue_S or
                    Code.Brfalse or Code.Brfalse_S or Code.Beq or Code.Beq_S or Code.Bne_Un or Code.Bne_Un_S)) return false;
                for (var n = 0; n < count; n++) state.Stack.Add(Value.Unknown);
                return true;
            }
        }
        if (found.Count != sites.Count) { reason = "Not every decoder call has an established slice."; return false; }
        slices = found.Select(p => new Slice(p.Key, p.Value.Offset, bytes.AsSpan(p.Value.Offset, p.Value.Length).ToArray())).ToArray();
        if (discard)
        {
            if (openedAt is null || fixedReads.Count == 0) return false;
            // Input streams go directly to the helper whose argument is unused.
            // Readers/buffers may become null only when identity/null comparisons
            // cannot observe them; lengths and reads are replaced with fixed values.
            plan = new(openedAt, fixedReads.Values.ToArray(), inputStreams.Concat(identitiesObserved ? [] : scaffolding).ToArray(), redundantCasts.ToArray());
        }
        reason = "Every direct decoder call receives a complete byte slice of the owned resource.";
        return true;

        bool Framework(IMethod called, string signature) => called.FullName == signature && called.DeclaringType is TypeRef type &&
            DependencyFrameworkScope.Matches(type, module);

        bool Record(Instruction call, int pops, long value, bool wide, bool native = false)
        {
            if (!discard) return true;
            var next = new FixedRead(call, pops, value, wide, native);
            if (fixedReads.TryGetValue(call, out var prior) && prior != next) return false;
            fixedReads[call] = next; return true;
        }
    }

    private sealed record Flow(List<Value> Stack, Value[] Locals, Dictionary<Instruction, Buffer> Buffers, long? InitialPosition, bool InitialOpened)
    {
        internal long? Position { get; set; } = InitialPosition;
        internal bool Opened { get; set; } = InitialOpened;
        internal HashSet<Instruction> Allocated { get; init; } = [];
        internal Flow Copy() => new([.. Stack], [.. Locals], new(Buffers), Position, Opened) { Allocated = new(Allocated) };
        internal bool Pop(out Value value)
        { value = Value.Unknown; if (Stack.Count == 0) return false; value = Stack[^1]; Stack.RemoveAt(Stack.Count - 1); return true; }
        internal bool Merge(Flow other)
        {
            var changed = false;
            for (var i = 0; i < Stack.Count; i++) { var next = MergeValue(Stack[i], other.Stack[i]); changed |= next != Stack[i]; Stack[i] = next; }
            for (var i = 0; i < Locals.Length; i++) { var next = MergeValue(Locals[i], other.Locals[i]); changed |= next != Locals[i]; Locals[i] = next; }
            if (Position != other.Position && Position is not null) { Position = null; changed = true; }
            if (other.Opened && !Opened) { Opened = true; changed = true; }
            var allocated = Allocated.Count; Allocated.UnionWith(other.Allocated); changed |= Allocated.Count != allocated;
            foreach (var key in Buffers.Keys.ToArray())
                if (!other.Buffers.TryGetValue(key, out var value) || value != Buffers[key])
                { Buffers.Remove(key); changed = true; }
            return changed;
        }
        private static Value MergeValue(Value left, Value right) => left == right ? left : left.Protected || right.Protected ? Value.Poison : Value.Unknown;
    }
}
