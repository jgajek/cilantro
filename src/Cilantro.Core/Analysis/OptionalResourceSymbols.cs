using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Uses only exact containing-assembly resource-count branches to prove an optional local stays null.</summary>
internal static class OptionalResourceSymbols
{
    internal static bool IsNull(MethodDef method, Local local)
    {
        if (!method.HasBody || !method.Body.InitLocals || local.Type is not SZArraySig { Next.ElementType: ElementType.U1 } ||
            method.Body.Instructions.Any(i => i.OpCode.Code is Code.Ldloca or Code.Ldloca_S && i.GetLocal(method.Body.Variables) == local)) return false;
        var graph = ControlFlowGraph.Build(method);
        var pending = new Queue<BasicBlock>(); pending.Enqueue(graph.Entry);
        // Treat every handler/filter as reachable even if its try block looks unreachable.
        foreach (var h in method.Body.ExceptionHandlers)
        {
            if (h.HandlerStart is { } handler) pending.Enqueue(graph.BlockOf(handler));
            if (h.FilterStart is { } filter) pending.Enqueue(graph.BlockOf(filter));
        }
        var seen = new HashSet<BasicBlock>();
        var flow = EvaluationStackOrigins.Analyze(method);
        if (!flow.Valid) return false;
        while (pending.TryDequeue(out var block))
        {
            if (!seen.Add(block)) continue;
            foreach (var instruction in block.Instructions.Where(i => i.IsStloc() && i.GetLocal(method.Body.Variables) == local))
                if (!flow.Inputs.TryGetValue(instruction, out var inputs) || inputs.Length != 1 || inputs[0].Count == 0 ||
                    inputs[0].Any(i => i is null || i.OpCode.Code != Code.Ldnull)) return false;
            var decision = CountBranch(method, block.Last);
            foreach (var edge in block.Successors)
            {
                if (decision is { } taken && edge.Kind != ControlFlowEdgeKind.Exception &&
                    (edge.Kind == ControlFlowEdgeKind.Branch) != taken) continue;
                pending.Enqueue(edge.Target);
            }
        }
        return true;
    }

    private static bool? CountBranch(MethodDef method, Instruction branch)
    {
        var code = method.Body.Instructions; var at = code.IndexOf(branch);
        if (at < 7 || branch.OpCode.Code is not (Code.Ble or Code.Ble_S or Code.Bgt or Code.Bgt_S)) return null;
        var start = at - 7;
        if (code[start].OpCode.Code != Code.Ldtoken || code[start].Operand is not TypeDef owner || owner.Module != method.Module ||
            !Call(start+1, Code.Call, "System.Type", "System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)") ||
            !Call(start+2, Code.Callvirt, "System.Type", "System.Reflection.Assembly System.Type::get_Assembly()") ||
            !Call(start+3, Code.Callvirt, "System.Reflection.Assembly", "System.String[] System.Reflection.Assembly::GetManifestResourceNames()") ||
            code[start+4].OpCode.Code != Code.Ldlen || code[start+5].OpCode.Code != Code.Conv_I4 || !code[start+6].IsLdcI4()) return null;
        var interior = code.Skip(start+1).Take(7).ToHashSet();
        if (code.Any(i => i.Operand is Instruction target && interior.Contains(target) || i.Operand is IList<Instruction> targets && targets.Any(interior.Contains)) ||
            method.Body.ExceptionHandlers.Any(h => new[] {h.TryStart,h.TryEnd,h.HandlerStart,h.HandlerEnd,h.FilterStart}.Any(i => i is not null && interior.Contains(i)))) return null;
        var lessOrEqual = method.Module.Resources.Count <= code[start+6].GetLdcI4Value();
        return branch.OpCode.Code is Code.Ble or Code.Ble_S ? lessOrEqual : !lessOrEqual;
        bool Call(int index, Code op, string type, string signature) => code[index].OpCode.Code == op &&
            code[index].Operand is IMethod called && called.FullName == signature && CoreLibraryIdentity.Matches(method.Module,called.DeclaringType,type) &&
            called.MethodSig is { ExplicitThis:false, GenParamCount:0, ParamsAfterSentinel:null } sig &&
            (sig.GetCallingConvention() & CallingConvention.Mask) == CallingConvention.Default && sig.HasThis == (op == Code.Callvirt);
    }
}
