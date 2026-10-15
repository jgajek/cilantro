using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Tracks a runtime property array through observed local collection uses.
/// This is corpus-scoped: callers must separately exclude other type-handle exposure.</summary>
internal static class ClosedPropertyContainers
{
    private enum Kind { Array, Property, List, Values, KeyDictionary, PropertySequence, PropertyEnumerator, StringKeys, StringEnumerator }
    internal sealed record Result(bool Closed, string Reason, int Tracked);
    internal static Result Analyze(MethodDef method, Instruction source)
    {
        var module = method.Module;
        var methods = module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody).ToArray();
        var literals = methods.SelectMany(m => m.Body.Instructions).Where(i => i.OpCode.Code == Code.Ldstr).Select(i => (string)i.Operand).ToHashSet();
        var pending = new Queue<(MethodDef Method, Instruction Source, Kind Kind)>();
        var seen = new HashSet<(MethodDef, Instruction, Kind)>();
        var fields = new HashSet<(FieldDef, Kind)>();
        var flows = new Dictionary<MethodDef, EvaluationStackOrigins.Result>();
        var seedBudget = 512;
        EvaluationStackOrigins.Result Flow(MethodDef owner)
        {
            if (!flows.TryGetValue(owner, out var result)) flows[owner] = result = EvaluationStackOrigins.Analyze(owner);
            return result;
        }
        bool Core(ITypeDefOrRef type, string name) => CoreLibraryIdentity.Matches(module, type, name);
        bool Property(TypeSig type) => Core(type.ToTypeDefOrRef(), "System.Reflection.PropertyInfo");
        bool Text(TypeSig type) => type.ElementType == ElementType.String;
        bool Field(FieldDef field, Kind kind)
        {
            if (field.Module != module || literals.Contains(field.Name.String) || literals.Contains(field.FullName)) return false;
            if (!fields.Add((field, kind))) return true;
            foreach (var owner in methods)
            foreach (var use in owner.Body.Instructions.Where(i => i.Operand is IField f && f.ResolveFieldDef() == field))
            {
                if (use.OpCode.Code is Code.Ldfld or Code.Ldsfld) pending.Enqueue((owner, use, kind));
                else if (use.OpCode.Code is not (Code.Stfld or Code.Stsfld)) return false;
            }
            return true;
        }
        bool Seeds(MethodDef owner, IReadOnlySet<Instruction?> origins, Kind kind)
        {
            if (origins.Count == 0 || --seedBudget < 0) return false;
            foreach (var origin in origins)
            {
                if (origin is null) return false;
                if (origin.OpCode.Code is Code.Ldfld or Code.Ldsfld && origin.Operand is IField f && f.ResolveFieldDef() is { } field)
                { if (!Field(field, kind)) return false; continue; }
                if (origin.IsLdloc())
                {
                    var local = origin.GetLocal(owner.Body.Variables);
                    var uses = owner.Body.Instructions.Where(i => i.GetLocal(owner.Body.Variables) == local).ToArray();
                    if (local is null || uses.Any(i => i.OpCode.Code is Code.Ldloca or Code.Ldloca_S)) return false;
                    var stores = uses.Where(i => i.IsStloc()).ToArray();
                    var flow = Flow(owner);
                    if (!flow.Valid || stores.Length == 0) return false;
                    foreach (var store in stores)
                        if (!flow.Inputs.TryGetValue(store, out var input) || input.Length != 1 || !Seeds(owner, input[0], kind)) return false;
                    continue;
                }
                if (origin.OpCode.Code is Code.Call or Code.Callvirt && origin.Operand is IMethod call &&
                    call.ResolveMethodDef() is { HasBody: true, IsVirtual: false, HasGenericParameters: false } getter && getter.Module == module &&
                    getter.MethodSig.Params.Count == 0 && getter.DeclaringType.Properties.Any(p => p.GetMethods.Contains(getter)))
                {
                    var il = getter.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
                    if (il.Length == 3 && il[0].IsLdarg() && il[0].GetParameter(getter.Parameters)?.IsHiddenThisParameter == true &&
                        il[1].OpCode.Code == Code.Ldfld && il[1].Operand is IField member && member.ResolveFieldDef() is { } value && il[2].OpCode.Code == Code.Ret &&
                        Field(value, kind)) continue;
                }
                return false;
            }
            return true;
        }
        pending.Enqueue((method, source, Kind.Array));
        while (pending.TryDequeue(out var work))
        {
            if (!seen.Add(work)) continue;
            if (seen.Count > 4096) return new(false, "Property-flow budget exhausted", seen.Count);
            if (work.Kind == Kind.Property && ClosedPropertyMetadataUses.IsClosed(work.Method, work.Source)) continue;
            var flow = Flow(work.Method);
            if (!flow.Valid) return new(false, "Unknown stack: " + work.Method.FullName, seen.Count);
            foreach (var (instruction, args) in flow.Inputs)
            {
                var slots = Enumerable.Range(0, args.Length).Where(n => args[n].Contains(work.Source)).ToArray();
                if (slots.Length == 0) continue;
                Result Fail() => new(false, work.Method.FullName + ": " + instruction, seen.Count);
                if (instruction.OpCode.Code == Code.Dup) continue;
                if (instruction.IsStloc())
                {
                    var local = instruction.GetLocal(work.Method.Body.Variables);
                    if (local is null) return Fail();
                    foreach (var use in work.Method.Body.Instructions.Where(i => i.GetLocal(work.Method.Body.Variables) == local))
                    {
                        if (use.IsLdloc() || work.Kind is Kind.PropertyEnumerator or Kind.StringEnumerator && use.OpCode.Code is Code.Ldloca or Code.Ldloca_S)
                            pending.Enqueue((work.Method, use, work.Kind));
                        else if (!use.IsStloc()) return Fail();
                    }
                    continue;
                }
                if (instruction.OpCode.Code == Code.Ret && work.Kind == Kind.KeyDictionary && !work.Method.IsVirtual &&
                    !literals.Contains(work.Method.Name.String) && work.Method.DeclaringType.Properties.Any(p => p.GetMethods.Contains(work.Method) && !literals.Contains(p.Name.String)))
                {
                    var count = 0;
                    foreach (var owner in methods)
                    foreach (var use in owner.Body.Instructions.Where(i => i.Operand is IMethod m && m.ResolveMethodDef() == work.Method))
                    {
                        if (use.OpCode.Code is not (Code.Call or Code.Callvirt)) return Fail();
                        count++; pending.Enqueue((owner, use, work.Kind));
                    }
                    if (count == 0) return Fail();
                    continue;
                }
                if (slots.Length != 1) return Fail();
                var slot = slots[0];
                if (slot == 0 && instruction.OpCode.Code is Code.Brtrue or Code.Brtrue_S or Code.Brfalse or Code.Brfalse_S) continue;
                if (work.Kind == Kind.Array && slot == 0 && instruction.OpCode.Code == Code.Ldlen) continue;
                if (work.Kind == Kind.Array && slot == 0 && instruction.OpCode.Code == Code.Ldelem_Ref)
                { pending.Enqueue((work.Method, instruction, Kind.Property)); continue; }
                if (slot == 0 && instruction.OpCode.Code == Code.Castclass && instruction.Operand is ITypeDefOrRef cast &&
                    work.Kind is Kind.PropertyEnumerator or Kind.StringEnumerator &&
                    (Core(cast, "System.Collections.IEnumerator") || Core(cast, "System.IDisposable")))
                { pending.Enqueue((work.Method, instruction, work.Kind)); continue; }
                if (instruction.OpCode.Code is not (Code.Call or Code.Callvirt) || instruction.Operand is not IMethod invoked ||
                    invoked.MethodSig is not { HasThis: true, ExplicitThis: false, GenParamCount: 0, ParamsAfterSentinel: null } sig ||
                    (sig.GetCallingConvention() & CallingConvention.Mask) != CallingConvention.Default) return Fail();
                var generic = invoked.DeclaringType.ToTypeSig() as GenericInstSig;
                var definition = generic?.GenericType.TypeDefOrRef ?? invoked.DeclaringType;
                if (!Core(definition, definition.FullName)) return Fail();
                var scope = new Interpretation.GenericScope(generic?.GenericArguments, null);
                var result = scope.Bind(sig.RetType);
                var parameters = sig.Params.Select(scope.Bind).ToArray();
                if (result is null || parameters.Any(p => p is null)) return Fail();
                bool List() => definition.FullName == "System.Collections.Generic.List`1" && generic?.GenericArguments.Count == 1 && Property(generic.GenericArguments[0]);
                bool Values() => definition.FullName == "System.Collections.Generic.Dictionary`2" && generic?.GenericArguments.Count == 2 && Text(generic.GenericArguments[0]) && Property(generic.GenericArguments[1]);
                bool Keys() => definition.FullName == "System.Collections.Generic.Dictionary`2" && generic?.GenericArguments.Count == 2 && Property(generic.GenericArguments[0]) && Text(generic.GenericArguments[1]);
                if (work.Kind == Kind.Property && invoked.Name == "Add" && result.ElementType == ElementType.Void &&
                    (slot == 1 && List() && parameters.Length == 1 && Property(parameters[0]!) ||
                     slot == 2 && Values() && parameters.Length == 2 && Text(parameters[0]!) && Property(parameters[1]!) ||
                     slot == 1 && Keys() && parameters.Length == 2 && Property(parameters[0]!) && Text(parameters[1]!) && ClosedDictionaryAliases.Analyze(work.Method, instruction).Closed))
                {
                    if (!Seeds(work.Method, args[0], List() ? Kind.List : Values() ? Kind.Values : Kind.KeyDictionary)) return Fail();
                    continue;
                }
                if (slot != 0) return Fail();
                if (work.Kind == Kind.List && List() && invoked.Name == "Add" && parameters.Length == 1 && Property(parameters[0]!) && result.ElementType == ElementType.Void) continue;
                if (work.Kind is Kind.Values or Kind.KeyDictionary && (Values() || Keys()))
                {
                    if (invoked.Name == "Add" && parameters.Length == 2 && result.ElementType == ElementType.Void) continue;
                    if (invoked.Name == "Clear" && parameters.Length == 0 && result.ElementType == ElementType.Void) continue;
                    if (invoked.Name == "ContainsKey" && parameters.Length == 1 && result.ElementType == ElementType.Boolean) continue;
                    if (invoked.Name == "get_Item" && parameters.Length == 1)
                    {
                        if (Values() && Property(result)) { pending.Enqueue((work.Method, instruction, Kind.Property)); continue; }
                        if (Keys() && Text(result)) continue;
                    }
                    if (invoked.Name == "get_Keys" && parameters.Length == 0 && result is GenericInstSig keys && Core(keys.GenericType.TypeDefOrRef, "System.Collections.Generic.Dictionary`2/KeyCollection"))
                    { pending.Enqueue((work.Method, instruction, Values() ? Kind.StringKeys : Kind.PropertySequence)); continue; }
                }
                if (work.Kind is Kind.List or Kind.PropertySequence or Kind.StringKeys && invoked.Name == "GetEnumerator" && parameters.Length == 0 && generic is not null &&
                    definition.FullName is "System.Collections.Generic.IEnumerable`1" or "System.Collections.Generic.Dictionary`2/KeyCollection")
                { pending.Enqueue((work.Method, instruction, work.Kind == Kind.StringKeys ? Kind.StringEnumerator : Kind.PropertyEnumerator)); continue; }
                if (work.Kind is Kind.PropertyEnumerator or Kind.StringEnumerator && parameters.Length == 0)
                {
                    if (invoked.Name == "get_Current" && (definition.FullName == "System.Collections.Generic.IEnumerator`1" || definition.FullName == "System.Collections.Generic.Dictionary`2/KeyCollection/Enumerator"))
                    {
                        if (work.Kind == Kind.PropertyEnumerator && Property(result)) { pending.Enqueue((work.Method, instruction, Kind.Property)); continue; }
                        if (work.Kind == Kind.StringEnumerator && Text(result)) continue;
                    }
                    if (invoked.Name == "MoveNext" && result.ElementType == ElementType.Boolean && definition.FullName is "System.Collections.IEnumerator" or "System.Collections.Generic.Dictionary`2/KeyCollection/Enumerator") continue;
                    if (invoked.Name == "Dispose" && result.ElementType == ElementType.Void && Core(definition, "System.IDisposable")) continue;
                }
                return Fail();
            }
        }
        return new(true, "Observed property array and container uses closed", seen.Count);
    }
}
