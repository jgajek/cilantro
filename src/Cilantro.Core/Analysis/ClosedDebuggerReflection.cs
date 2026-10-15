using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Recognizes a literal framework debugger-property query without changing its result.</summary>
internal static class ClosedDebuggerReflection
{
    internal static IReadOnlySet<Instruction> Find(ModuleDef module)
    {
        const string debugger = "System.Diagnostics.Debugger";
        var result = new HashSet<Instruction>();
        // Unqualified Type.GetType checks the caller assembly as well as the core
        // library. Never assume the framework type when the input shadows/forwards it.
        if (module.GetTypes().Any(t => t.FullName == debugger) || module.ExportedTypes.Any(t => t.FullName == debugger)) return result;
        foreach (var method in module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody && m.Body.InitLocals))
        {
            var il = method.Body.Instructions;
            if (!il.Any(i => i.OpCode.Code == Code.Ldstr && i.Operand is string name && name == debugger)) continue;
            var graph = ControlFlowGraph.Build(method);
            var locals = new HashSet<Local>();
            foreach (var block in graph.Blocks)
            {
                var code = block.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
                for (var at = 1; at + 1 < code.Length; at++)
                {
                    if (code[at - 1].OpCode.Code != Code.Ldstr || code[at - 1].Operand is not string name || name != debugger ||
                        !Framework(code[at], "System.Type System.Type::GetType(System.String)")) continue;
                    result.Add(code[at]);
                    if (!code[at + 1].IsStloc() || code[at + 1].GetLocal(method.Body.Variables) is not { } local ||
                        il.Any(i => i.OpCode.Code is Code.Ldloca or Code.Ldloca_S && i.GetLocal(method.Body.Variables) == local) ||
                        il.Count(i => i.IsStloc() && i.GetLocal(method.Body.Variables) == local) != 1) continue;
                    locals.Add(local);
                }
            }
            foreach (var block in graph.Blocks)
            {
                var code = block.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
                for (var at = 0; at < code.Length; at++)
                {
                    if (!code[at].IsLdloc() || code[at].GetLocal(method.Body.Variables) is not { } local || !locals.Contains(local)) continue;
                    var next = at + 1;
                    if (next < code.Length && code[next].OpCode.Code == Code.Castclass && code[next].Operand is TypeRef cast &&
                        cast.FullName == "System.Type" && cast.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName) next++;
                    if (next + 5 >= code.Length || code[next].OpCode.Code != Code.Ldstr || code[next].Operand is not string property || property != "IsAttached" ||
                        !code[next + 1].IsLdcI4() || code[next + 1].GetLdcI4Value() != 4096 ||
                        code[next + 2].OpCode.Code != Code.Ldnull || code[next + 3].OpCode.Code != Code.Ldnull || code[next + 4].OpCode.Code != Code.Ldnull ||
                        !Framework(code[next + 5], "System.Object System.Type::InvokeMember(System.String,System.Reflection.BindingFlags,System.Reflection.Binder,System.Object,System.Object[])")) continue;
                    result.Add(code[next + 5]);
                }
            }
        }
        return result;

        bool Framework(Instruction instruction, string signature) => instruction.OpCode.Code is Code.Call or Code.Callvirt &&
            instruction.Operand is IMethod call && call.FullName == signature && call.DeclaringType is TypeRef type &&
            type.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName;
    }
}
