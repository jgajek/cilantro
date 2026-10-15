using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Type relationship queries on runtime Types do not expose their members.
/// Arbitrary Type parameters, custom subclasses, and escaping aliases are refused.</summary>
internal static class RuntimeTypeRelationshipUse
{
    internal static bool IsClosed(MethodDef method, Instruction token)
    {
        if (!method.HasBody || token.OpCode.Code != Code.Ldtoken || token.Operand is not ITypeDefOrRef) return false;
        var flow = EvaluationStackOrigins.Analyze(method);
        if (!flow.Valid) return false;
        var il = method.Body.Instructions;
        bool Core(IMethod m, string signature) => m.FullName == signature && CoreLibraryIdentity.Matches(method.Module,m.DeclaringType,m.DeclaringType.FullName);
        bool Conversion(Instruction i) => i.OpCode.Code == Code.Call && i.Operand is IMethod m &&
            Core(m,"System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)");
        bool Cast(Instruction i) => i.OpCode.Code == Code.Castclass && i.Operand is ITypeDefOrRef t &&
            (CoreLibraryIdentity.Matches(method.Module,t,"System.Type") || CoreLibraryIdentity.Matches(method.Module,t,"System.Object"));
        var seeds = flow.Inputs.Where(p => Conversion(p.Key) && p.Value.Length == 1 && p.Value[0].Contains(token)).Select(p => p.Key).ToArray();
        if (seeds.Length != 1 || flow.Inputs.Any(p => p.Key != seeds[0] && p.Value.Any(s => s.Contains(token)))) return false;
        var tainted = new HashSet<Instruction>(seeds);
        var locals = new HashSet<Local>();
        bool changed;
        do {
            changed = false;
            foreach (var i in il) {
                if (i.IsLdloc() && locals.Contains(i.GetLocal(method.Body.Variables)!)) changed |= tainted.Add(i);
                if (!flow.Inputs.TryGetValue(i,out var input) || !input.Any(s => s.Any(p => p is not null && tainted.Contains(p)))) continue;
                if (i.IsStloc()) changed |= locals.Add(i.GetLocal(method.Body.Variables)!);
                else if (Cast(i)) changed |= tainted.Add(i);
            }
        } while (changed);
        if (il.Any(i => i.OpCode.Code is Code.Ldloca or Code.Ldloca_S && locals.Contains(i.GetLocal(method.Body.Variables)!))) return false;
        var active = new HashSet<Instruction>(); var budget = 4096;
        bool Runtime(IReadOnlySet<Instruction?> origins) => origins.Count > 0 && origins.All(i => i is not null && Producer(i));
        bool Producer(Instruction i) {
            if (--budget < 0 || !active.Add(i)) return false;
            try {
                if (i.OpCode.Code == Code.Ldnull) return true;
                if (i.IsLdloc()) {
                    var local = i.GetLocal(method.Body.Variables);
                    if (!method.Body.InitLocals || il.Any(p => p.OpCode.Code is Code.Ldloca or Code.Ldloca_S && p.GetLocal(method.Body.Variables) == local)) return false;
                    var writes = il.Where(p => p.IsStloc() && p.GetLocal(method.Body.Variables) == local).ToArray();
                    return writes.Length > 0 && writes.All(p => flow.Inputs.TryGetValue(p,out var inputs) && inputs.Length == 1 && Runtime(inputs[0]));
                }
                if (!flow.Inputs.TryGetValue(i,out var args)) return false;
                if (Cast(i)) return args.Length == 1 && Runtime(args[0]);
                if (Conversion(i)) return args.Length == 1 && args[0].Count > 0 && args[0].All(p => p?.OpCode.Code == Code.Ldtoken && p.Operand is ITypeDefOrRef);
                return i.OpCode.Code is Code.Call or Code.Callvirt && i.Operand is IMethod call && args.Length == 1 &&
                    Core(call,"System.Type System.Object::GetType()");
            } finally { active.Remove(i); }
        }
        var queries = 0;
        foreach (var (consumer, args) in flow.Inputs) {
            if (!args.Any(s => s.Any(p => p is not null && tainted.Contains(p)))) continue;
            if (consumer.IsStloc() || Cast(consumer) || consumer.OpCode.Code is Code.Dup or Code.Pop) continue;
            if (consumer.OpCode.Code is not (Code.Call or Code.Callvirt) || consumer.Operand is not IMethod call || args.Length != 2 ||
                !(Core(call,"System.Boolean System.Type::IsSubclassOf(System.Type)") || Core(call,"System.Boolean System.Type::IsAssignableFrom(System.Type)")) ||
                !args.All(Runtime)) return false;
            queries++;
        }
        return queries > 0;
    }
}
