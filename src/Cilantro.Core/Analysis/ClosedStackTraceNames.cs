using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Recognizes nonescaping framework stack-frame name reads, including a null guard.</summary>
internal static class ClosedStackTraceNames
{
    internal static IReadOnlySet<Instruction> Find(MethodDef method)
    {
        var known = new HashSet<Instruction>();
        if (!method.HasBody || !method.Body.InitLocals) return known;
        var il = method.Body.Instructions;
        var incoming = new Dictionary<Instruction, HashSet<Instruction>>();
        foreach (var instruction in il)
            foreach (var target in instruction.Operand switch
            {
                Instruction one => new[] { one },
                IList<Instruction> many => many,
                _ => (IEnumerable<Instruction>)[]
            })
            {
                if (!incoming.TryGetValue(target, out var sources)) incoming[target] = sources = [];
                sources.Add(instruction);
            }
        var boundaries = method.Body.ExceptionHandlers.SelectMany(h =>
            new[] { h.TryStart, h.TryEnd, h.HandlerStart, h.HandlerEnd, h.FilterStart }).OfType<Instruction>().ToHashSet();
        bool Closed(int first, int last) => Enumerable.Range(first + 1, last - first)
            .All(i => !incoming.ContainsKey(il[i]) && !boundaries.Contains(il[i]));
        bool Call(int i, string name) => i >= 0 && i < il.Count && il[i].OpCode.Code is Code.Call or Code.Callvirt && Framework(il[i], name);
        bool Framework(Instruction instruction, string name) => instruction.Operand is IMethod called && called.FullName == name &&
            called.DeclaringType is TypeRef type && type.DefinitionAssembly?.FullName == method.Module.CorLibTypes.AssemblyRef.FullName;
        Local? Loaded(int i) => i >= 0 && il[i].IsLdloc() ? il[i].GetLocal(method.Body.Variables) : null;
        bool LocalIs(Local local, bool trace)
        {
            var stores = il.Select((instruction, index) => (instruction, index))
                .Where(p => p.instruction.IsStloc() && p.instruction.GetLocal(method.Body.Variables) == local).ToArray();
            if (stores.Length == 0 || il.Any(i => i.OpCode.Code is Code.Ldloca or Code.Ldloca_S && i.GetLocal(method.Body.Variables) == local)) return false;
            foreach (var (_, i) in stores)
            {
                if (trace)
                {
                    if (i < 1 || il[i - 1].OpCode.Code != Code.Newobj ||
                        !Framework(il[i - 1], "System.Void System.Diagnostics.StackTrace::.ctor(System.Exception,System.Boolean)") || !Closed(i - 1, i)) return false;
                }
                else if (i < 3 || Loaded(i - 3) is not { } source || !il[i - 2].IsLdcI4() ||
                    !Call(i - 1, "System.Diagnostics.StackFrame System.Diagnostics.StackTrace::GetFrame(System.Int32)") ||
                    !Closed(i - 3, i) || !LocalIs(source, true)) return false;
            }
            // No alias can hand either framework object to an unknown implementation.
            foreach (var i in Enumerable.Range(0, il.Count).Where(i => Loaded(i) == local))
            {
                var end = trace && i + 2 < il.Count && il[i + 1].IsLdcI4() &&
                    Call(i + 2, "System.Diagnostics.StackFrame System.Diagnostics.StackTrace::GetFrame(System.Int32)") ? i + 2 : i + 1;
                var allowed = trace
                    ? end == i + 2 || Call(end, "System.Int32 System.Diagnostics.StackTrace::get_FrameCount()")
                    : Call(end, "System.Reflection.MethodBase System.Diagnostics.StackFrame::GetMethod()") ||
                      Call(end, "System.String System.Diagnostics.StackFrame::GetFileName()") ||
                      Call(end, "System.Int32 System.Diagnostics.StackFrame::GetFileLineNumber()");
                if (!allowed || !Closed(i, end)) return false;
            }
            return true;
        }
        for (var i = 1; i < il.Count; i++)
        {
            if (!Call(i, "System.Reflection.MethodBase System.Diagnostics.StackFrame::GetMethod()") ||
                Loaded(i - 1) is not { } frame || !Closed(i - 1, i) || !LocalIs(frame, false)) continue;
            const string getter = "System.String System.Reflection.MemberInfo::get_Name()";
            if (Call(i + 1, getter) && Closed(i, i + 1)) { known.Add(il[i + 1]); continue; }
            if (i + 8 >= il.Count || il[i + 1].OpCode.Code != Code.Dup ||
                il[i + 2].OpCode.Code is not (Code.Brfalse or Code.Brfalse_S) || il[i + 2].Operand != il[i + 4] ||
                il[i + 3].OpCode.Code is not (Code.Br or Code.Br_S) || il[i + 3].Operand != il[i + 7] ||
                il[i + 4].OpCode.Code != Code.Pop || il[i + 5].OpCode.Code != Code.Ldnull ||
                il[i + 6].OpCode.Code is not (Code.Br or Code.Br_S) || il[i + 6].Operand != il[i + 8] || !Call(i + 7, getter)) continue;
            if (Enumerable.Range(i + 1, 7).Any(j => boundaries.Contains(il[j]) ||
                incoming.TryGetValue(il[j], out var sources) &&
                !(j == i + 4 && sources.SetEquals([il[i + 2]]) || j == i + 7 && sources.SetEquals([il[i + 3]])))) continue;
            known.Add(il[i + 7]);
        }
        return known;
    }
}
