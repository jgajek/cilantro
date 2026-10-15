using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Proves that a literal's observed consumers cannot name one candidate method.
/// Propagates through local arguments/storage; unknown consumers refuse the proof.</summary>
internal sealed class ScopedMethodNameUses(ModuleDef module, IReadOnlySet<TypeDef> exposed)
{
    private readonly MethodDef[] bodies = module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody).ToArray();
    private ILookup<string, (MethodDef Method, Instruction Literal)>? literalUses;
    internal bool ExcludesAll(MethodDef candidate)
    {
        // One instance belongs to the read-only planning phase of a recovery pass.
        // Index literals once, retaining every site for both short and full names.
        literalUses ??= bodies.SelectMany(m => m.Body.Instructions
            .Where(i => i.OpCode.Code == Code.Ldstr && i.Operand is string)
            .Select(i => (Method: m, Literal: i)))
            .ToLookup(use => (string)use.Literal.Operand, StringComparer.Ordinal);
        var uses = literalUses[candidate.Name.String].Union(literalUses[candidate.FullName]).ToArray();
        return uses.Length != 0 && uses.All(use => Excludes(candidate, use.Method, use.Literal, out _));
    }
    internal bool Excludes(MethodDef candidate, MethodDef source, Instruction literal, out string reason)
    {
        var pending = new Queue<(MethodDef Method, Instruction Seed)>();
        var processed = new HashSet<(MethodDef, Instruction)>();
        var fields = new HashSet<FieldDef>();
        var remaining = 100_000;
        pending.Enqueue((source, literal));
        bool Core(ITypeDefOrRef type, string name) => type is TypeRef && type.FullName == name &&
            type.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName;
        bool OtherLookup(MethodDef method, Instruction instruction, IMethod call)
        {
            if (!Core(call.DeclaringType, "System.Type") || call.Name != "GetMethod" ||
                call.MethodSig is not { HasThis: true, Params.Count: 1 } signature ||
                !Core(signature.RetType.ToTypeDefOrRef(), "System.Reflection.MethodInfo") ||
                signature.Params[0].ElementType != ElementType.String) return false;
            var target = ExactReflectionTypes.Receiver(method, instruction)?.ScopeType.ResolveTypeDef();
            var seen = new HashSet<TypeDef>();
            while (target is not null && seen.Add(target))
            {
                if (target == candidate.DeclaringType) return false;
                if (target.BaseType is null || Core(target.BaseType, "System.Object")) return true;
                target = target.BaseType.ResolveTypeDef();
            }
            return false;
        }
        while (pending.TryDequeue(out var work))
        {
            if (!processed.Add(work)) continue;
            if (processed.Count > 256 || (remaining -= work.Method.Body.Instructions.Count) < 0)
            { reason = "Name-use proof budget exhausted."; return false; }
            var method = work.Method;
            var flow = EvaluationStackOrigins.Analyze(method);
            if (!flow.Valid) { reason = "Unresolved stack: " + method.FullName; return false; }
            var tainted = new HashSet<Instruction> { work.Seed };
            var locals = new HashSet<Local>();
            bool changed;
            do
            {
                changed = false;
                foreach (var instruction in method.Body.Instructions)
                {
                    if (instruction.IsLdloc() && locals.Contains(instruction.GetLocal(method.Body.Variables)!))
                        changed |= tainted.Add(instruction);
                    if (instruction.IsStloc() && flow.Inputs.TryGetValue(instruction, out var inputs) && inputs.Any(origins => origins.Any(i => i is not null && tainted.Contains(i))))
                        changed |= locals.Add(instruction.GetLocal(method.Body.Variables)!);
                }
            } while (changed);
            foreach (var instruction in method.Body.Instructions)
            {
                if (instruction.OpCode.Code is Code.Ldloca or Code.Ldloca_S && locals.Contains(instruction.GetLocal(method.Body.Variables)!))
                { reason = "Name local address: " + method.FullName; return false; }
                if (!flow.Inputs.TryGetValue(instruction, out var args)) continue;
                var slots = Enumerable.Range(0, args.Length).Where(n => args[n].Any(i => i is not null && tainted.Contains(i))).ToArray();
                if (slots.Length == 0) continue;
                if (instruction.IsStloc() || instruction.OpCode.Code == Code.Dup) continue;
                if (instruction.OpCode.Code is Code.Stfld or Code.Stsfld && slots.Length == 1 && slots[0] == args.Length - 1 &&
                    instruction.Operand is IField fieldRef && ResolveField(fieldRef) is { } field && field.Module == module &&
                    field.FieldSig.Type.ElementType == ElementType.String && !exposed.Contains(field.DeclaringType) &&
                    (!MemberVisibility.IsExternallyVisible(field.DeclaringType) || field.IsPrivate))
                {
                    if (fields.Add(field))
                    foreach (var reader in bodies)
                    foreach (var use in reader.Body.Instructions)
                    {
                        if (use.OpCode.Code == Code.Ldstr && use.Operand is string name && (name == field.Name.String || name == field.FullName))
                        { reason = "Named storage: " + field.FullName; return false; }
                        if (use.Operand is not IField reference || ResolveField(reference) != field) continue;
                        if (use.OpCode.Code is Code.Ldfld or Code.Ldsfld) pending.Enqueue((reader, use));
                        else if (use.OpCode.Code is not (Code.Stfld or Code.Stsfld))
                        { reason = "Storage escape: " + field.FullName; return false; }
                    }
                    continue;
                }
                if (instruction.OpCode.Code is Code.Call or Code.Callvirt && instruction.Operand is IMethod call)
                {
                    if (Core(call.DeclaringType, "System.String") && call.Name == "op_Equality" &&
                        call.MethodSig is { HasThis: false, Params.Count: 2 } equality && equality.RetType.ElementType == ElementType.Boolean &&
                        equality.Params.All(p => p.ElementType == ElementType.String)) continue;
                    if (slots.SequenceEqual(new[] { 1 }) && OtherLookup(method, instruction, call)) continue;
                    var target = ResolveMethod(call);
                    if (target?.Module == module && target.HasBody && !target.IsVirtual && !target.IsConstructor &&
                        call.MethodSig is { } signature && args.Length == signature.Params.Count + (signature.HasThis ? 1 : 0))
                    {
                        foreach (var slot in slots)
                        {
                            if (slot >= target.Parameters.Count || target.Parameters[slot].Type.ElementType != ElementType.String)
                            { reason = "Non-string forwarding: " + target.FullName; return false; }
                            foreach (var use in target.Body.Instructions.Where(i => i.GetParameter(target.Parameters) == target.Parameters[slot]))
                            {
                                if (!use.IsLdarg()) { reason = "Parameter mutation/address: " + target.FullName; return false; }
                                pending.Enqueue((target, use));
                            }
                        }
                        continue;
                    }
                }
                reason = method.FullName + ": " + instruction + (instruction.Operand is IMethod rejected ? $" [resolved={rejected.ResolveMethodDef()?.FullName ?? "null"}; stack={args.Length}; parameters={rejected.MethodSig?.Params.Count}; instance={rejected.MethodSig?.HasThis}]" : "");
                return false;
            }
        }
        reason = "All observed name uses are comparisons or lookups on unrelated exact types.";
        return true;
    }
    private static MethodDef? ResolveMethod(IMethod reference)
    {
        if (reference.ResolveMethodDef() is { } direct) return direct;
        var owner = reference.DeclaringType?.ScopeType.ResolveTypeDef();
        var matches = owner?.Methods.Where(m => m.Name == reference.Name && new SigComparer().Equals(m.MethodSig, reference.MethodSig)).Take(2).ToArray();
        return matches?.Length == 1 ? matches[0] : null;
    }
    private static FieldDef? ResolveField(IField reference)
    {
        if (reference.ResolveFieldDef() is { } direct) return direct;
        var owner = reference.DeclaringType?.ScopeType.ResolveTypeDef();
        var matches = owner?.Fields.Where(f => f.Name == reference.Name && new SigComparer().Equals(f.FieldSig, reference.FieldSig)).Take(2).ToArray();
        return matches?.Length == 1 ? matches[0] : null;
    }}
