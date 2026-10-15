using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Retires closed byte-array writers to an independently decoded, retired string cache.</summary>
internal static class ReactorStringCacheWriters
{
    private const string Fact = "cleanup.decodedStringCaches";
    private sealed record Cache(MethodDef Reader, TypeDef Owner, FieldDef Field, RecoveredResourceOrigin Resource);

    internal static void Remember(ArtifactContext context, MethodDef reader, CapturedStringTable table)
    {
        if (table.Resource is not { } resource || table.TableFields is not { Count: > 0 } || !reader.HasBody ||
            reader.Module != context.Module || !context.Module.Resources.OfType<EmbeddedResource>().Any(resource.Matches)) return;
        var captured = table.TableFields.ToHashSet(StringComparer.Ordinal);
        var fields = reader.Body.Instructions.Where(i => i.OpCode.Code == Code.Ldsfld).Select(i => i.Operand).OfType<IField>()
            .Select(f => f.ResolveFieldDef()).Where(f => f is not null && f.DeclaringType == reader.DeclaringType &&
                f.IsStatic && Bytes(f.FieldType) && captured.Contains(f.FullName)).Distinct().ToArray();
        context.TryGetFact<IReadOnlyList<Cache>>(Fact, out var prior);
        context.SetFact<IReadOnlyList<Cache>>(Fact, [.. prior ?? [], .. fields.Select(f => new Cache(reader, reader.DeclaringType, f, resource))]);
    }

    internal static IReadOnlyList<MethodDef> Find(ArtifactContext context)
    {
        if (!context.TryGetFact<IReadOnlyList<Cache>>(Fact, out var caches) || caches is null) return [];
        var owners = ReactorIntegrityHelpers.Owners(context).ToHashSet();
        var methods = context.Module.GetTypes().SelectMany(t => t.Methods).ToHashSet();
        return caches.GroupBy(c => c.Field).Where(g => g.Select(c => c.Resource).Distinct().Count() == 1 &&
                g.All(c => owners.Contains(c.Owner) && !methods.Contains(c.Reader)) && g.Key.DeclaringType is not null)
            .SelectMany(g => g.Key.DeclaringType.Methods.Where(m => IsClosedWriter(m, g.Key))).Distinct().ToArray();
    }

    internal static bool IsClosedWriter(MethodDef method, FieldDef field)
    {
        if (!method.HasBody || method.IsConstructor || method.IsVirtual || method.HasGenericParameters || method.DeclaringType.HasGenericParameters ||
            method.DeclaringType != field.DeclaringType || method.ReturnType.ElementType != ElementType.Void || method.HasCustomAttributes ||
            method.MethodSig.Params.Count != 3 || method.MethodSig.Params.Any(p => !Bytes(p)) || method.Body.HasExceptionHandlers ||
            method.Body.Variables.Count > 256 || !field.IsStatic || !Bytes(field.FieldType)) return false;
        var il = method.Body.Instructions;
        if (il.Count is 0 or > 8192 || il.Count(i => i.OpCode.Code == Code.Newarr) != 1 || il.Count(i => i.OpCode.Code == Code.Stsfld) != 1 ||
            il.Any(i => !Allowed(i, field))) return false;
        foreach (var instruction in il)
        {
            if (instruction.IsLdarg() && instruction.GetParameter(method.Parameters) is null) return false;
            if (instruction.IsLdloc() || instruction.IsStloc())
            {
                var local = instruction.GetLocal(method.Body.Variables);
                if (local is null || local.Index < 0 || local.Index >= method.Body.Variables.Count || method.Body.Variables[local.Index] != local) return false;
            }
        }
        var indices = il.Select((instruction, index) => (instruction, index)).ToDictionary(p => p.instruction, p => p.index);
        var states = new Frame?[il.Count];
        states[0] = new(Enumerable.Repeat(Other, method.Body.Variables.Count).ToArray(), []);
        var pending = new Queue<int>(); pending.Enqueue(0);
        var iterations = 0;
        while (pending.TryDequeue(out var at))
        {
            if (++iterations > 100_000) return false;
            var state = states[at]!.Copy();
            var instruction = il[at];
            var code = instruction.OpCode.Code;
            if (instruction.IsLdarg()) state.Stack.Add(Other);
            else if (instruction.IsLdloc()) state.Stack.Add(state.Locals[instruction.GetLocal(method.Body.Variables).Index]);
            else if (instruction.IsStloc())
            {
                if (!Pop(state, out var value)) return false;
                state.Locals[instruction.GetLocal(method.Body.Variables).Index] = value;
            }
            else if (code == Code.Dup)
            {
                if (state.Stack.Count == 0) return false;
                state.Stack.Add(state.Stack[^1]);
            }
            else if (code == Code.Newarr)
            {
                if (!Pop(state, out var length) || length != Other) return false;
                state.Stack.Add(Fresh);
            }
            else if (code == Code.Stelem_I1)
            {
                if (!Pop(state, out var value) || value != Other || !Pop(state, out var index) || index != Other ||
                    !Pop(state, out var array) || array != Fresh) return false;
            }
            else if (code == Code.Stsfld)
            {
                if (!Pop(state, out var array) || array != Fresh) return false;
            }
            else if (code is Code.Ldlen or Code.Ldelem_U1)
            {
                if (code == Code.Ldelem_U1 && (!Pop(state, out var index) || index != Other)) return false;
                if (!Pop(state, out _)) return false;
                state.Stack.Add(Other);
            }
            else
            {
                instruction.CalculateStackUsage(out var pushes, out var pops);
                if (pops < 0 || pushes < 0) return false;
                for (var p = 0; p < pops; p++) if (!Pop(state, out var value) || value != Other) return false;
                for (var p = 0; p < pushes; p++) state.Stack.Add(Other);
            }
            if (code == Code.Ret)
            {
                if (state.Stack.Count != 0) return false;
                continue;
            }
            var successors = new List<int>();
            if (instruction.Operand is Instruction target)
            {
                if (!indices.TryGetValue(target, out var destination)) return false;
                successors.Add(destination);
            }
            else if (instruction.Operand is IList<Instruction> targets)
                foreach (var targetItem in targets)
                {
                    if (!indices.TryGetValue(targetItem, out var destination)) return false;
                    successors.Add(destination);
                }
            if (instruction.OpCode.FlowControl != FlowControl.Branch)
            {
                if (at + 1 == il.Count) return false;
                successors.Add(at + 1);
            }
            foreach (var next in successors)
            {
                if (states[next] is not { } previous) { states[next] = state.Copy(); pending.Enqueue(next); continue; }
                if (previous.Stack.Count != state.Stack.Count) return false;
                var changed = false;
                for (var i = 0; i < previous.Locals.Length; i++)
                {
                    var value = (byte)(previous.Locals[i] | state.Locals[i]);
                    if (value != previous.Locals[i]) { previous.Locals[i] = value; changed = true; }
                }
                for (var i = 0; i < previous.Stack.Count; i++)
                {
                    var value = (byte)(previous.Stack[i] | state.Stack[i]);
                    if (value != previous.Stack[i]) { previous.Stack[i] = value; changed = true; }
                }
                if (changed) pending.Enqueue(next);
            }
        }
        return states.All(s => s is not null);
    }

    private const byte Fresh = 1, Other = 2;
    private sealed record Frame(byte[] Locals, List<byte> Stack)
    {
        internal Frame Copy() => new((byte[])Locals.Clone(), [.. Stack]);
    }
    private static bool Pop(Frame frame, out byte value)
    {
        value = 0;
        if (frame.Stack.Count == 0) return false;
        value = frame.Stack[^1]; frame.Stack.RemoveAt(frame.Stack.Count - 1); return true;
    }
    private static bool Bytes(TypeSig type) => type is SZArraySig { Next.ElementType: ElementType.U1 };
    private static bool Allowed(Instruction instruction, FieldDef field)
    {
        if (instruction.IsLdarg() || instruction.IsLdloc() || instruction.IsStloc() || instruction.IsLdcI4()) return true;
        if (instruction.OpCode.Code == Code.Stsfld) return instruction.Operand is IField written && written.ResolveFieldDef() == field;
        if (instruction.OpCode.Code == Code.Newarr) return instruction.Operand is ITypeDefOrRef type && type.FullName == "System.Byte" &&
            type.DefinitionAssembly?.Name.String is "mscorlib" or "System.Private.CoreLib";
        if (instruction.OpCode.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch)
            return instruction.OpCode.Code is not (Code.Leave or Code.Leave_S) &&
                instruction.Operand is Instruction or IList<Instruction>;
        return instruction.OpCode.Code is Code.Nop or Code.Ret or Code.Dup or Code.Pop or Code.Ldlen or Code.Ldelem_U1 or Code.Stelem_I1 or
            Code.Add or Code.Sub or Code.Mul or Code.Div or Code.Div_Un or Code.Rem or Code.Rem_Un or Code.And or Code.Or or Code.Xor or
            Code.Shl or Code.Shr or Code.Shr_Un or Code.Neg or Code.Not or Code.Ceq or Code.Clt or Code.Clt_Un or Code.Cgt or Code.Cgt_Un or
            Code.Conv_I1 or Code.Conv_I2 or Code.Conv_I4 or Code.Conv_I8 or Code.Conv_U1 or Code.Conv_U2 or Code.Conv_U4 or Code.Conv_U8 or
            Code.Conv_R4 or Code.Conv_R8 or Code.Conv_R_Un or Code.Ldc_I8 or Code.Ldc_R4 or Code.Ldc_R8;
    }
}
