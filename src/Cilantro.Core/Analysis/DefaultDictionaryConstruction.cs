using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Proves dictionary construction provenance only. This does not close
/// subsequent aliases, reflection, serialization callbacks or comparer mutation.</summary>
internal static class DefaultDictionaryConstruction
{
    internal sealed record Origin(MethodDef Method, Instruction Instruction);
    internal sealed record Result(bool Proven, IReadOnlyList<Origin> Origins);
    internal static bool Receiver(MethodDef method, Instruction call) => Analyze(method, call).Proven;
    internal static Result Analyze(MethodDef method, Instruction call)
    {
        var module = method.Module;
        var origins = new List<Origin>();
        var flows = new Dictionary<MethodDef, EvaluationStackOrigins.Result>();
        var active = new HashSet<(MethodDef, Instruction)>();
        var fields = new HashSet<FieldDef>();
        var budget = 512;
        EvaluationStackOrigins.Result Flow(MethodDef owner)
        {
            if (!flows.TryGetValue(owner, out var result)) flows[owner] = result = EvaluationStackOrigins.Analyze(owner);
            return result;
        }
        bool Sources(MethodDef owner, IReadOnlySet<Instruction?> sources) => sources.Count != 0 &&
            sources.All(source => source is not null && Value(owner, source));
        bool Stored(MethodDef owner, Instruction store)
        {
            var flow = Flow(owner);
            return flow.Valid && flow.Inputs.TryGetValue(store, out var args) && args.Length != 0 && Sources(owner, args[^1]);
        }
        bool Value(MethodDef owner, Instruction source)
        {
            if (--budget < 0 || !active.Add((owner, source))) return false;
            try
            {
                if (source.OpCode.Code == Code.Newobj && source.Operand is IMethod ctor &&
                    ctor.Name == ".ctor" && ctor.DeclaringType.ToTypeSig() is GenericInstSig { GenericArguments.Count: 2 } generic &&
                    generic.GenericType.TypeDefOrRef is TypeRef { FullName: "System.Collections.Generic.Dictionary`2" } definition &&
                    CoreLibraryIdentity.Matches(module, definition, "System.Collections.Generic.Dictionary`2") &&
                    ctor.MethodSig is { HasThis: true, ExplicitThis: false, GenParamCount: 0, Params.Count: 0, ParamsAfterSentinel: null } sig &&
                    (sig.GetCallingConvention() & CallingConvention.Mask) == CallingConvention.Default &&
                    sig.RetType.ElementType == ElementType.Void) { origins.Add(new(owner, source)); return true; }
                if (source.IsLdloc())
                {
                    var local = source.GetLocal(owner.Body.Variables);
                    if (local is null || owner.Body.Instructions.Any(i => i.GetLocal(owner.Body.Variables) == local &&
                        i.OpCode.Code is Code.Ldloca or Code.Ldloca_S)) return false;
                    var stores = owner.Body.Instructions.Where(i => i.IsStloc() && i.GetLocal(owner.Body.Variables) == local).ToArray();
                    return stores.Length != 0 && stores.All(store => Stored(owner, store));
                }
                if (source.OpCode.Code is Code.Ldfld or Code.Ldsfld && source.Operand is IField reference &&
                    reference.ResolveFieldDef() is { } field && field.Module == module && field.IsPrivate && fields.Add(field))
                {
                    try
                    {
                        var stores = 0;
                        foreach (var body in module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
                        foreach (var use in body.Body.Instructions.Where(i => i.Operand is IField f && f.ResolveFieldDef() == field))
                        {
                            if (use.OpCode.Code is Code.Ldflda or Code.Ldsflda or Code.Ldtoken) return false;
                            if (use.OpCode.Code is not (Code.Stfld or Code.Stsfld)) continue;
                            stores++;
                            if (!Stored(body, use)) return false;
                        }
                        return stores != 0;
                    }
                    finally { fields.Remove(field); }
                }
                if (source.OpCode.Code is Code.Call or Code.Callvirt && source.Operand is IMethod invoked &&
                    invoked.ResolveMethodDef() is { } getter && getter.Module == module && getter.HasBody &&
                    !getter.IsVirtual && !getter.HasGenericParameters && getter.MethodSig.Params.Count == 0 &&
                    !getter.Body.HasExceptionHandlers && new SigComparer().Equals(invoked.MethodSig, getter.MethodSig) &&
                    getter.DeclaringType.Properties.Any(p => p.GetMethods.Contains(getter)))
                {
                    var il = getter.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
                    if (il.Length == 2 && il[0].OpCode.Code == Code.Ldsfld && il[1].OpCode.Code == Code.Ret)
                        return Value(getter, il[0]);
                    if (il.Length == 3 && !getter.IsStatic && il[0].IsLdarg() &&
                        il[0].GetParameter(getter.Parameters)?.IsHiddenThisParameter == true &&
                        il[1].OpCode.Code == Code.Ldfld && il[2].OpCode.Code == Code.Ret)
                        return Value(getter, il[1]);
                }
                return false;
            }
            finally { active.Remove((owner, source)); }
        }
        var input = Flow(method);
        var proven = input.Valid && input.Inputs.TryGetValue(call, out var arguments) && arguments.Length != 0 && Sources(method, arguments[0]);
        return new(proven, proven ? origins : []);
    }
}
