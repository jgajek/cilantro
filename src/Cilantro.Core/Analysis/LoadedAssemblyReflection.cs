using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Tracks reflection along closed control-flow chains rooted in Assembly.Load(byte[]).</summary>
internal static class LoadedAssemblyReflection
{
    private enum Value { Unknown, Assembly, Type, Method }

    internal static IReadOnlySet<Instruction> Find(ModuleDef module)
    {
        var result = new HashSet<Instruction>();
        foreach (var method in module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody &&
                     m.Body.Instructions.Any(i => Is(i, Code.Call, "System.Reflection.Assembly System.Reflection.Assembly::Load(System.Byte[])"))))
        {
            var addressed = method.Body.Instructions.Where(i => i.OpCode.Code is Code.Ldloca or Code.Ldloca_S)
                .Select(i => i.GetLocal(method.Body.Variables)).ToHashSet();
            foreach (var chain in Chains(ControlFlowGraph.Build(method)))
            {
                var stack = new List<Value>(); var locals = new Dictionary<Local, Value>();
                foreach (var instruction in chain.SelectMany(block => block.Instructions))
                {
                    if (instruction.OpCode.Code == Code.Nop) continue;
                    if (instruction.IsLdloc())
                    {
                        var local = instruction.GetLocal(method.Body.Variables);
                        stack.Add(local is not null && !addressed.Contains(local) ? locals.GetValueOrDefault(local) : Value.Unknown); continue;
                    }
                    if (instruction.OpCode.Code == Code.Dup)
                    { if (stack.Count != 0) stack.Add(stack[^1]); continue; }
                    instruction.CalculateStackUsage(out var pushes, out var pops);
                    if (pops < 0 || pops > stack.Count) { stack.Clear(); locals.Clear(); continue; }
                    var receiver = pops == 0 ? Value.Unknown : stack[stack.Count - pops];
                    var top = pops == 0 ? Value.Unknown : stack[^1];
                    stack.RemoveRange(stack.Count - pops, pops);
                    if (instruction.IsStloc() && instruction.GetLocal(method.Body.Variables) is { } localStore)
                    { locals[localStore] = addressed.Contains(localStore) ? Value.Unknown : top; continue; }
                    var value = Value.Unknown;
                    if (Is(instruction, Code.Call, "System.Reflection.Assembly System.Reflection.Assembly::Load(System.Byte[])")) value = Value.Assembly;
                    if (receiver == Value.Assembly &&
                        (Is(instruction, Code.Callvirt, "System.Type System.Reflection.Assembly::GetType(System.String)") ||
                         Is(instruction, Code.Callvirt, "System.Type System.Reflection.Assembly::GetType(System.String,System.Boolean)") ||
                         Is(instruction, Code.Callvirt, "System.Type System.Reflection.Assembly::GetType(System.String,System.Boolean,System.Boolean)")))
                    { value = Value.Type; result.Add(instruction); }
                    if (receiver == Value.Type &&
                        (Is(instruction, Code.Callvirt, "System.Reflection.MethodInfo System.Type::GetMethod(System.String)") ||
                         Is(instruction, Code.Callvirt, "System.Reflection.MethodInfo System.Type::GetMethod(System.String,System.Type[])") ||
                         Is(instruction, Code.Callvirt, "System.Reflection.MethodInfo System.Type::GetMethod(System.String,System.Reflection.BindingFlags)")))
                    { value = Value.Method; result.Add(instruction); }
                    if (receiver == Value.Method && Is(instruction, Code.Callvirt, "System.Object System.Reflection.MethodBase::Invoke(System.Object,System.Object[])"))
                        result.Add(instruction);
                    if (instruction.OpCode.Code == Code.Castclass && instruction.Operand is TypeRef cast &&
                        cast.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName &&
                        (cast.FullName == "System.Object" || top == Value.Assembly && cast.FullName == "System.Reflection.Assembly" ||
                         top == Value.Type && cast.FullName == "System.Type" || top == Value.Method && cast.FullName is "System.Reflection.MethodInfo" or "System.Reflection.MethodBase")) value = top;
                    for (var n = 0; n < pushes; n++) stack.Add(value);
                }
            }
        }
        result.UnionWith(LoadedAssemblyFlow.Find(module));
        return result;

        bool Is(Instruction instruction, Code code, string signature) => instruction.OpCode.Code == code &&
            instruction.Operand is IMethod call && call.FullName == signature && call.DeclaringType is TypeRef type &&
            type.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName;
    }

    private static IEnumerable<IReadOnlyList<BasicBlock>> Chains(ControlFlowGraph graph)
    {
        // Carry provenance only over a unique normal edge with no join, exception entry,
        // or protected-region transition. Cycles start with unknown state and are visited
        // once; no value is inferred from a back edge or an unexamined predecessor.
        var next = new Dictionary<BasicBlock, BasicBlock>();
        foreach (var block in graph.Blocks)
            if (block.Successors.Count == 1 && block.Successors[0] is { Kind: not ControlFlowEdgeKind.Exception } edge &&
                edge.Target != graph.Entry && edge.Target.Predecessors.Count == 1 &&
                block.Last.OpCode.Code is not (Code.Leave or Code.Leave_S) &&
                graph.HaveIdenticalExceptionRegions(block.Last, edge.Target.First))
                next[block] = edge.Target;
        var continuations = next.Values.ToHashSet();
        var visited = new HashSet<BasicBlock>();
        foreach (var start in graph.Blocks.Where(block => !continuations.Contains(block)).Concat(graph.Blocks))
        {
            if (!visited.Add(start)) continue;
            var chain = new List<BasicBlock> { start };
            var current = start;
            while (next.TryGetValue(current, out var successor) && visited.Add(successor))
            { chain.Add(successor); current = successor; }
            yield return chain;
        }
    }
}
