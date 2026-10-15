using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Checks that direct callers pass a fresh stream of the proved bundle to its index constructor.</summary>
internal static class DependencyIndexSource
{
    private sealed record Value(string Kind, object? Data = null);

    internal static bool Check(MethodDef resolver, MethodDef constructor, DependencyIndexConstruction.Snapshot index, out string reason)
    {
        reason = "Index callers or resource-stream provenance are not closed.";
        if (!constructor.IsPrivate || !constructor.IsStatic || !resolver.HasBody || resolver.HasGenericParameters ||
            resolver.DeclaringType.HasGenericParameters || resolver.Module.Resources.Count(r => r.Name == index.Source.Name) != 1 ||
            resolver.Module.Resources.OfType<EmbeddedResource>().Count(index.Source.Matches) != 1) return false;
        var calls = new List<Instruction>();
        foreach (var method in resolver.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
            foreach (var instruction in method.Body.Instructions)
                if (instruction.Operand is IMethod reference && reference.ResolveMethodDef() == constructor)
                {
                    if (method != resolver || instruction.OpCode.Code != Code.Call || reference is MethodSpec) return false;
                    calls.Add(instruction);
                }
        if (calls.Count == 0) return false;
        var cfg = ControlFlowGraph.Build(resolver);
        var opens = resolver.Body.Instructions.Where(i => FrameworkCall(i, resolver.Module,
            "System.IO.Stream System.Reflection.Assembly::GetManifestResourceStream(System.String)")).ToArray();
        if (opens.Length != 1) return false;
        var open = opens[0];
        if (!FixedName(cfg.BlockOf(open).Instructions.TakeWhile(i => i != open), resolver, index.Source.Name))
        { reason = "The resource receiver or name is not a closed expression."; return false; }
        var following = cfg.BlockOf(open).Instructions.SkipWhile(i => i != open).Skip(1).FirstOrDefault(i => i.OpCode.Code != Code.Nop);
        if (following is null || !following.IsStloc()) return false;
        var stream = following.GetLocal(resolver.Body.Variables);
        if (stream is null || resolver.Body.Instructions.Any(i => i.IsStloc() && i.GetLocal(resolver.Body.Variables) == stream && i != following ||
            i.OpCode.Code is Code.Ldloca or Code.Ldloca_S && i.GetLocal(resolver.Body.Variables) == stream)) return false;
        var argumentLoads = new HashSet<Instruction>();
        foreach (var call in calls)
        {
            var previous = cfg.BlockOf(call).Instructions.TakeWhile(i => i != call).LastOrDefault(i => i.OpCode.Code != Code.Nop);
            if (previous is null || !previous.IsLdloc() || previous.GetLocal(resolver.Body.Variables) != stream) return false;
            argumentLoads.Add(previous);
        }
        // A stream may be consumed after index initialization, but every path to
        // each initialization must still carry the newly opened stream at zero.
        var queue = new Queue<(BasicBlock Block, bool Fresh)>(); queue.Enqueue((cfg.Entry, false));
        var seen = new HashSet<(BasicBlock, bool)>();
        while (queue.TryDequeue(out var item))
        {
            if (!seen.Add(item)) continue;
            var fresh = item.Fresh;
            foreach (var instruction in item.Block.Instructions)
            {
                if (instruction == following) { fresh = true; continue; }
                if (calls.Contains(instruction))
                {
                    if (!fresh) { reason = "An index call can receive an uninitialized, consumed or escaped stream."; return false; }
                    fresh = false; continue;
                }
                if (!instruction.IsLdloc() || instruction.GetLocal(resolver.Body.Variables) != stream || argumentLoads.Contains(instruction)) continue;
                var next = item.Block.Instructions.SkipWhile(i => i != instruction).Skip(1).FirstOrDefault(i => i.OpCode.Code != Code.Nop);
                // A null test neither exposes the reference nor moves the stream.
                if (next?.OpCode.Code is not (Code.Brtrue or Code.Brtrue_S or Code.Brfalse or Code.Brfalse_S)) fresh = false;
            }
            foreach (var edge in item.Block.Successors)
                queue.Enqueue((edge.Target, edge.Kind == ControlFlowEdgeKind.Exception ? false : fresh));
        }
        reason = "Every direct index call receives the exact fresh resource stream; later table/record mutation is a separate obligation.";
        return true;
    }

    private static bool FixedName(IEnumerable<Instruction> prefix, MethodDef method, string expected)
    {
        var module = method.Module;
        var stack = new List<Value>();
        var locals = new Dictionary<Local, Value>();
        foreach (var instruction in prefix)
        {
            var code = instruction.OpCode.Code;
            if (code == Code.Nop) continue;
            if (code == Code.Ldtoken && instruction.Operand is ITypeDefOrRef type && type.ResolveTypeDef()?.Module == module)
            { stack.Add(new("handle")); continue; }
            if (code == Code.Ldstr) { stack.Add(new("string", instruction.Operand)); continue; }
            if (instruction.IsLdcI4()) { stack.Add(new("int", instruction.GetLdcI4Value())); continue; }
            if (code == Code.Ldsfld && instruction.Operand is IField reference && reference.ResolveFieldDef() is { } field &&
                ReadonlyDelegateBinding.UniqueInitializerTarget(field) is { } target)
            { stack.Add(new("binding", (field, target))); continue; }
            if (instruction.IsStloc())
            {
                if (!Pop(out var value) || instruction.GetLocal(method.Body.Variables) is not { } local) return false;
                locals[local] = value; continue;
            }
            if (instruction.IsLdloc())
            {
                if (instruction.GetLocal(method.Body.Variables) is not { } local || !locals.TryGetValue(local, out var value)) return false;
                stack.Add(value); continue;
            }
            if (code == Code.Castclass && instruction.Operand is TypeRef cast &&
                cast.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName && stack.Count != 0 &&
                (stack[^1].Kind, cast.FullName) is ("type", "System.Type") or ("assembly", "System.Reflection.Assembly") or ("string", "System.String")) continue;
            if (FrameworkCall(instruction, module, "System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)"))
            { if (!Pop(out var value) || value.Kind != "handle") return false; stack.Add(new("type")); continue; }
            if (FrameworkCall(instruction, module, "System.Reflection.Assembly System.Type::get_Assembly()"))
            { if (!Pop(out var value) || value.Kind != "type") return false; stack.Add(new("assembly")); continue; }
            if (code == Code.Callvirt && instruction.Operand is IMethod { Name.String: "Invoke", MethodSig.Params.Count: 1 } invoke)
            {
                if (!Pop(out var argument) || argument.Kind != "int" || !Pop(out var binding) ||
                    binding.Data is not ValueTuple<FieldDef, MethodDef> pair ||
                    pair.Item1.FieldType.ToTypeDefOrRef()?.ResolveTypeDef() != invoke.DeclaringType.ResolveTypeDef() ||
                    invoke.ResolveMethodDef() is not { IsRuntime: true, IsVirtual: true } ||
                    invoke.MethodSig.Params[0].ElementType != ElementType.I4 || invoke.MethodSig.RetType.ElementType != ElementType.String) return false;
                var text = DelegateStringCompletionPass.ReadClosedIntegerDecoder(pair.Item2, (int)argument.Data!);
                if (text is null) return false;
                stack.Add(new("string", text)); continue;
            }
            return false;
        }
        return stack.Count == 2 && stack[0].Kind == "assembly" && stack[1].Kind == "string" && (string?)stack[1].Data == expected;

        bool Pop(out Value value)
        {
            value = new("unknown");
            if (stack.Count == 0) return false;
            value = stack[^1]; stack.RemoveAt(stack.Count - 1); return true;
        }
    }

    private static bool FrameworkCall(Instruction instruction, ModuleDef module, string signature) =>
        instruction.OpCode.Code is Code.Call or Code.Callvirt && instruction.Operand is IMethod called && called.FullName == signature &&
        called.DeclaringType is TypeRef type && type.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName;
}
