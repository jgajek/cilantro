using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Closes dictionary aliases over ordinary collection operations.
/// Returned keys/values are outside this proof; their metadata uses need a separate check.</summary>
internal static class ClosedDictionaryAliases
{
    private enum Kind { Dictionary, Keys, Enumerator }
    internal sealed record Result(bool Closed, string Reason);
    internal static Result Analyze(MethodDef method, Instruction lookup)
    {
        var construction = DefaultDictionaryConstruction.Analyze(method, lookup);
        if (!construction.Proven) return new(false, "Unknown construction");
        var module = method.Module;
        var methods = module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody).ToArray();
        var exposed = ModuleReachability.Compute(module).ReflectivelyExposedTypes.ToHashSet();
        var literals = methods.SelectMany(m => m.Body.Instructions).Where(i => i.OpCode.Code == Code.Ldstr)
            .Select(i => (string)i.Operand).ToHashSet();
        var pending = new Queue<(MethodDef Method, Instruction Source, Kind Kind)>();
        var seen = new HashSet<(MethodDef, Instruction, Kind)>();
        var flows = new Dictionary<MethodDef, EvaluationStackOrigins.Result>();
        foreach (var origin in construction.Origins) pending.Enqueue((origin.Method, origin.Instruction, Kind.Dictionary));
        while (pending.TryDequeue(out var work))
        {
            if (!seen.Add(work)) continue;
            if (seen.Count > 2048) return new(false, "Alias budget exhausted");
            if (!flows.TryGetValue(work.Method, out var flow)) flows[work.Method] = flow = EvaluationStackOrigins.Analyze(work.Method);
            if (!flow.Valid) return new(false, "Unknown evaluation stack");
            foreach (var (instruction, arguments) in flow.Inputs)
            {
                var slots = Enumerable.Range(0, arguments.Length).Where(n => arguments[n].Contains(work.Source)).ToArray();
                if (slots.Length == 0) continue;
                if (instruction.OpCode.Code == Code.Dup) continue;
                if (instruction.IsStloc())
                {
                    var local = instruction.GetLocal(work.Method.Body.Variables);
                    if (local is null) return new(false, "Unknown local");
                    foreach (var use in work.Method.Body.Instructions.Where(i => i.GetLocal(work.Method.Body.Variables) == local))
                    {
                        if (use.IsLdloc() || work.Kind == Kind.Enumerator && use.OpCode.Code is Code.Ldloca or Code.Ldloca_S)
                            pending.Enqueue((work.Method, use, work.Kind));
                        else if (!use.IsStloc()) return new(false, "Local address escape");
                    }
                    continue;
                }
                if (work.Kind == Kind.Dictionary && instruction.OpCode.Code is Code.Stfld or Code.Stsfld &&
                    slots.Length == 1 && slots[0] == arguments.Length - 1 && instruction.Operand is IField reference &&
                    reference.ResolveFieldDef() is { IsPrivate: true } field && field.Module == module &&
                    !literals.Contains(field.Name.String) && !literals.Contains(field.FullName) && !exposed.Contains(field.DeclaringType))
                {
                    foreach (var owner in methods)
                    foreach (var use in owner.Body.Instructions.Where(i => i.Operand is IField f && f.ResolveFieldDef() == field))
                    {
                        if (use.OpCode.Code is Code.Ldfld or Code.Ldsfld) pending.Enqueue((owner, use, Kind.Dictionary));
                        else if (use.OpCode.Code is not (Code.Stfld or Code.Stsfld)) return new(false, "Field address or token escape");
                    }
                    continue;
                }
                if (instruction.OpCode.Code == Code.Ret && work.Kind == Kind.Dictionary &&
                    !work.Method.IsVirtual && !exposed.Contains(work.Method.DeclaringType) && !literals.Contains(work.Method.Name.String) && !literals.Contains(work.Method.FullName) &&
                    work.Method.DeclaringType.Properties.Any(p => p.GetMethods.Contains(work.Method) && !literals.Contains(p.Name.String)))
                {
                    var calls = 0;
                    foreach (var owner in methods)
                    foreach (var use in owner.Body.Instructions.Where(i => i.Operand is IMethod m && m.ResolveMethodDef() == work.Method))
                    {
                        if (use.OpCode.Code is not (Code.Call or Code.Callvirt)) return new(false, "Getter handle escape");
                        calls++; pending.Enqueue((owner, use, Kind.Dictionary));
                    }
                    if (calls == 0) return new(false, "Unconsumed getter");
                    continue;
                }
                if (slots.Length != 1 || slots[0] != 0) return new(false, "Alias passed as argument: " + instruction);
                if (instruction.OpCode.Code is Code.Brtrue or Code.Brtrue_S or Code.Brfalse or Code.Brfalse_S) continue;
                if (instruction.OpCode.Code == Code.Castclass && instruction.Operand is ITypeDefOrRef cast &&
                    work.Kind == Kind.Enumerator && (CoreLibraryIdentity.Matches(module, cast, "System.IDisposable") ||
                    CoreLibraryIdentity.Matches(module, cast, "System.Collections.IEnumerator")))
                { pending.Enqueue((work.Method, instruction, work.Kind)); continue; }
                if (instruction.OpCode.Code is not (Code.Call or Code.Callvirt) || instruction.Operand is not IMethod call ||
                    call.MethodSig is not { HasThis: true, ExplicitThis: false, GenParamCount: 0, ParamsAfterSentinel: null } sig ||
                    (sig.GetCallingConvention() & CallingConvention.Mask) != CallingConvention.Default) return new(false, instruction.ToString());
                var declaring = call.DeclaringType.ToTypeSig() as GenericInstSig;
                var definition = declaring?.GenericType.TypeDefOrRef ?? call.DeclaringType;
                var name = definition.FullName;
                if (!CoreLibraryIdentity.Matches(module, definition, name)) return new(false, "Foreign collection operation");
                var scope = new Interpretation.GenericScope(declaring?.GenericArguments, null);
                var result = scope.Bind(sig.RetType);
                if (result is null) return new(false, "Unresolved collection signature");
                if (work.Kind == Kind.Dictionary && name == "System.Collections.Generic.Dictionary`2" && declaring?.GenericArguments.Count == 2)
                {
                    var key = declaring.GenericArguments[0]; var value = declaring.GenericArguments[1];
                    bool Same(TypeSig? a, TypeSig b) => a is not null && new SigComparer().Equals(a, b);
                    if (call.Name == "get_Item" && sig.Params.Count == 1 && Same(scope.Bind(sig.Params[0]), key) && Same(result, value)) continue;
                    if (call.Name == "Add" && sig.Params.Count == 2 && Same(scope.Bind(sig.Params[0]), key) && Same(scope.Bind(sig.Params[1]), value) && result.ElementType == ElementType.Void) continue;
                    if (call.Name == "get_Count" && sig.Params.Count == 0 && result.ElementType == ElementType.I4) continue;
                    if (call.Name == "Clear" && sig.Params.Count == 0 && result.ElementType == ElementType.Void) continue;
                    if (call.Name == "get_Keys" && sig.Params.Count == 0 && result is GenericInstSig keys && CoreLibraryIdentity.Matches(module, keys.GenericType.TypeDefOrRef, "System.Collections.Generic.Dictionary`2/KeyCollection") && keys.GenericArguments.Count == 2 && keys.GenericArguments.Zip(declaring.GenericArguments).All(p => Same(p.First, p.Second)))
                    { pending.Enqueue((work.Method, instruction, Kind.Keys)); continue; }
                }
                if (work.Kind == Kind.Keys && name == "System.Collections.Generic.Dictionary`2/KeyCollection" && call.Name == "GetEnumerator" && sig.Params.Count == 0 &&
                    result is GenericInstSig enumerator && CoreLibraryIdentity.Matches(module, enumerator.GenericType.TypeDefOrRef, "System.Collections.Generic.Dictionary`2/KeyCollection/Enumerator") && declaring is not null && enumerator.GenericArguments.Count == declaring.GenericArguments.Count && enumerator.GenericArguments.Zip(declaring.GenericArguments).All(p => new SigComparer().Equals(p.First, p.Second)))
                { pending.Enqueue((work.Method, instruction, Kind.Enumerator)); continue; }
                if (work.Kind == Kind.Enumerator && sig.Params.Count == 0)
                {
                    if (name == "System.Collections.Generic.Dictionary`2/KeyCollection/Enumerator" &&
                        (call.Name == "get_Current" && declaring?.GenericArguments.Count == 2 && new SigComparer().Equals(result, declaring.GenericArguments[0]) || call.Name == "MoveNext" && result.ElementType == ElementType.Boolean)) continue;
                    if (name == "System.IDisposable" && call.Name == "Dispose" && result.ElementType == ElementType.Void) continue;
                }
                return new(false, "Unknown collection consumer: " + instruction);
            }
        }
        return new(true, "Dictionary aliases closed; key/value use remains separate");
    }
}
