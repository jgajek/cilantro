using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Candidate-specific proof for a type handle used only to invoke other named methods.</summary>
internal sealed class NamedMethodHandleUses(ModuleDef module)
{
    private enum Kind { Handle, Type, Method }
    private readonly ILookup<TypeDef, (MethodDef Method, Instruction Token, TypeDef Owner)> handles = module.GetTypes()
        .SelectMany(t => t.Methods).Where(m => m.HasBody).SelectMany(m => m.Body.Instructions
            .Where(i => i.OpCode.Code == Code.Ldtoken && i.Operand is ITypeDefOrRef)
            .Select(i => (Method: m, Token: i, Owner: ((ITypeDefOrRef)i.Operand).ScopeType.ResolveTypeDef())))
        .Where(use => use.Owner?.Module == module).ToLookup(use => use.Owner);
    private readonly Dictionary<MethodDef, bool> cache = [];
    internal static bool Excludes(ModuleDef module, MethodDef candidate) => new NamedMethodHandleUses(module).IsClosed(candidate);
    internal bool IsClosed(MethodDef candidate)
    {
        if (cache.TryGetValue(candidate, out var known)) return known;
        var uses = handles[candidate.DeclaringType].ToArray();
        return cache[candidate] = uses.Length != 0 && uses.All(use =>
            TypeIdentityHandleUse.IsClosed(use.Method, use.Method.Body.Instructions.IndexOf(use.Token)) || Closed(use.Method, use.Token, candidate));
    }
    private static bool Closed(MethodDef method, Instruction token, MethodDef candidate)
    {
        var flow = EvaluationStackOrigins.Analyze(method);
        if (!flow.Valid) return false;
        var pending = new Queue<(Instruction Source, Kind Kind)>();
        var seen = new HashSet<(Instruction, Kind)>();
        pending.Enqueue((token, Kind.Handle));
        bool Core(ITypeDefOrRef type, string name) => type is TypeRef && type.FullName == name &&
            type.DefinitionAssembly?.FullName == method.Module.CorLibTypes.AssemblyRef.FullName;
        bool Signature(IMethod call, string owner, string name, string result, bool instance, params string[] parameters) =>
            Core(call.DeclaringType, owner) && call.Name == name && call.MethodSig is { } sig &&
            sig.HasThis == instance && !sig.ExplicitThis && sig.GenParamCount == 0 && sig.ParamsAfterSentinel is null &&
            (sig.GetCallingConvention() & CallingConvention.Mask) == CallingConvention.Default && sig.RetType.FullName == result &&
            sig.Params.Select(p => p.FullName).SequenceEqual(parameters);
        string? Literal(IReadOnlySet<Instruction?> origins, HashSet<Instruction> active)
        {
            string? value = null;
            foreach (var origin in origins)
            {
                if (origin is null || active.Count > 64 || !active.Add(origin)) return null;
                string? next = origin.OpCode.Code == Code.Ldstr ? (string)origin.Operand : null;
                if (origin.IsLdloc())
                {
                    var local = origin.GetLocal(method.Body.Variables);
                    var stores = method.Body.Instructions.Where(i => i.GetLocal(method.Body.Variables) == local && i.IsStloc()).ToArray();
                    if (method.Body.Instructions.Any(i => i.GetLocal(method.Body.Variables) == local && i.OpCode.Code is Code.Ldloca or Code.Ldloca_S)) return null;
                    if (stores.Length == 1 && flow.Inputs.TryGetValue(stores[0], out var stored) && stored.Length == 1)
                        next = Literal(stored[0], active);
                }
                active.Remove(origin);
                if (next is null || value is not null && value != next) return null;
                value = next;
            }
            return value;
        }
        while (pending.TryDequeue(out var work))
        {
            if (!seen.Add(work)) continue;
            if (seen.Count > 256) return false;
            foreach (var (instruction, args) in flow.Inputs)
            {
                var slots = Enumerable.Range(0, args.Length).Where(n => args[n].Contains(work.Source)).ToArray();
                if (slots.Length == 0) continue;
                if (instruction.OpCode.Code == Code.Dup) continue;
                if (instruction.IsStloc())
                {
                    var local = instruction.GetLocal(method.Body.Variables);
                    foreach (var use in method.Body.Instructions.Where(i => i.GetLocal(method.Body.Variables) == local))
                    {
                        if (use.IsLdloc()) pending.Enqueue((use, work.Kind));
                        else if (!use.IsStloc()) return false;
                    }
                    continue;
                }
                if (slots.Length != 1 || slots[0] != 0) return false;
                if (instruction.OpCode.Code == Code.Castclass && instruction.Operand is ITypeDefOrRef cast &&
                    (work.Kind == Kind.Type && Core(cast, "System.Type") || work.Kind == Kind.Method &&
                     (Core(cast, "System.Reflection.MethodInfo") || Core(cast, "System.Reflection.MethodBase"))))
                { pending.Enqueue((instruction, work.Kind)); continue; }
                if (instruction.OpCode.Code is not (Code.Call or Code.Callvirt) || instruction.Operand is not IMethod call) return false;
                if (work.Kind == Kind.Handle && Signature(call, "System.Type", "GetTypeFromHandle", "System.Type", false, "System.RuntimeTypeHandle"))
                { pending.Enqueue((instruction, Kind.Type)); continue; }
                if (work.Kind == Kind.Type && Signature(call, "System.Type", "GetMethod", "System.Reflection.MethodInfo", true, "System.String") &&
                    args.Length == 2 && Literal(args[1], []) is { } name && name != candidate.Name.String)
                { pending.Enqueue((instruction, Kind.Method)); continue; }
                if (work.Kind == Kind.Method && Signature(call, "System.Reflection.MethodInfo", "MakeGenericMethod", "System.Reflection.MethodInfo", true, "System.Type[]"))
                { pending.Enqueue((instruction, Kind.Method)); continue; }
                if (work.Kind == Kind.Method && Signature(call, "System.Reflection.MethodBase", "Invoke", "System.Object", true, "System.Object", "System.Object[]")) continue;
                return false;
            }
        }
        return true;
    }
}
