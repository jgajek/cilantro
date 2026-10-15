using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Proves strings are used solely to name newly created dynamic methods.</summary>
internal sealed class DynamicMethodNameUses(ModuleDef module)
{
    private readonly Dictionary<MethodDef, ControlFlowGraph> graphs = [];
    private readonly Dictionary<Parameter, bool> parameters = [];
    private ControlFlowGraph Graph(MethodDef method)
    {
        if (!graphs.TryGetValue(method, out var graph)) graphs[method] = graph = ControlFlowGraph.Build(method);
        return graph;
    }
    internal bool IsCreationName(MethodDef method, Instruction producer) => Trace(method, producer, 0);

    private bool ParameterOnlyNames(Parameter parameter, int depth)
    {
        if (depth > 8) return false;
        if (parameters.TryGetValue(parameter, out var known)) return known;
        parameters[parameter] = false;
        var method = parameter.Method;
        if (method.Module != module || !method.HasBody || !method.IsStatic || method.IsVirtual ||
            method.HasGenericParameters || method.DeclaringType.HasGenericParameters) return false;
        var reads = method.Body.Instructions.Where(i => i.GetParameter(method.Parameters) == parameter).ToArray();
        if (reads.Length == 0 || reads.Any(i => !i.IsLdarg())) return false;
        return parameters[parameter] = reads.All(i => Trace(method, i, depth + 1));
    }

    private bool Trace(MethodDef method, Instruction producer, int depth)
    {
        var instructions = Graph(method).BlockOf(producer).Instructions;
        var start = 0; while (start < instructions.Count && instructions[start] != producer) start++;
        var stack = new List<bool> { true };
        for (var n = start + 1; n < instructions.Count; n++)
        {
            var instruction = instructions[n];
            if (instruction.OpCode.Code == Code.Nop) continue;
            if (instruction.OpCode.Code == Code.Dup)
            {
                if (stack.Count == 0) return false;
                stack.Add(stack[^1]); continue;
            }
            instruction.CalculateStackUsage(out var pushes, out var pops);
            if (pops < 0 || pushes < 0) return false;
            // Earlier stack slots are not derived from this producer.
            while (stack.Count < pops) stack.Insert(0, false);
            var consumed = stack.Skip(stack.Count - pops).ToArray();
            stack.RemoveRange(stack.Count - pops, pops);
            var tainted = consumed.Any(value => value);
            var result = false;
            if (tainted)
            {
                if (instruction.OpCode.Code == Code.Castclass && instruction.Operand is ITypeDefOrRef cast &&
                    (new SigComparer().Equals(cast.ToTypeSig(), module.CorLibTypes.String) ||
                     new SigComparer().Equals(cast.ToTypeSig(), module.CorLibTypes.Object))) result = true;
                else if (instruction.OpCode.Code == Code.Call && instruction.Operand is IMethod concat &&
                    Framework(concat, "System.String") && concat.Name == "Concat" &&
                    concat.MethodSig is { HasThis: false, Params.Count: 2 } signature &&
                    signature.Params.All(p => new SigComparer().Equals(p, module.CorLibTypes.String)) &&
                    new SigComparer().Equals(signature.RetType, module.CorLibTypes.String)) result = true;
                else if (instruction.OpCode.Code == Code.Newobj && instruction.Operand is IMethod constructor &&
                    Framework(constructor, "System.Reflection.Emit.DynamicMethod") && constructor.Name == ".ctor" &&
                    constructor.MethodSig is { HasThis: true, Params.Count: 5 } ctor &&
                    ctor.Params.Select(p => p.FullName).SequenceEqual(new[] { "System.String", "System.Type", "System.Type[]",
                        ctor.Params[3].FullName == "System.Type" ? "System.Type" : "System.Reflection.Module", "System.Boolean" }) &&
                    consumed.Length == 5 && consumed[0] && !consumed.Skip(1).Any(value => value)) { }
                else if (instruction.OpCode.Code == Code.Call && instruction.Operand is MethodDef called &&
                    called.Module == module && called.IsStatic && consumed.Length == called.MethodSig.Params.Count &&
                    consumed.Select((value, index) => !value || ParameterOnlyNames(called.Parameters[index], depth)).All(value => value)) { }
                else return false;
            }
            for (var p = 0; p < pushes; p++) stack.Add(result);
            if (!stack.Any(value => value)) return tainted;
        }
        return false;
    }
    private bool Framework(IMethod method, string owner) => method is not MethodSpec &&
        method.DeclaringType is TypeRef type && type.FullName == owner &&
        type.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName &&
        method.MethodSig is { GenParamCount: 0, ParamsAfterSentinel: null };
}
