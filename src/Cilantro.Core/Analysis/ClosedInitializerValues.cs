using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Proves a closed construction region and all its direct CIL publications.</summary>
internal static class ClosedInitializerValues
{
    internal sealed record Result(bool Passed, string Detail)
    {
        internal IReadOnlySet<FieldDef> Fields { get; init; } = new HashSet<FieldDef>();
    }

    internal static Result Check(TypeDef owner)
    {
        if (owner.HasGenericParameters || MemberVisibility.IsExternallyVisible(owner) ||
            owner.FindStaticConstructor() is not { HasBody: true } initializer ||
            initializer.Body.ExceptionHandlers.Count != 0 || initializer.Body.Instructions.Count == 0)
            return new(false, "No private, nongeneric initializer region.");
        var il = initializer.Body.Instructions;
        var positions = il.Select((instruction, index) => (instruction, index)).ToDictionary(p => p.instruction, p => p.index);
        var prefix = new HashSet<Instruction>();
        var at = 0;
        while (at < il.Count)
        {
            var i = il[at];
            if (i.OpCode.Code is Code.Br or Code.Br_S)
            {
                if (!prefix.Add(i) || i.Operand is not Instruction target || !positions.TryGetValue(target, out at))
                    return new(false, "Cyclic initializer prefix.");
                continue;
            }
            if (i.OpCode.Code != Code.Nop && !(i.OpCode.Code == Code.Call && i.Operand is IMethod
                { MethodSig: { HasThis: false, Params.Count: 0, RetType.ElementType: ElementType.Void } })) break;
            if (!prefix.Add(i)) return new(false, "Cyclic initializer prefix.");
            at++;
        }
        if (at == il.Count) return new(false, "No construction follows the prefix.");
        var fields = new HashSet<FieldDef>();
        var methods = new HashSet<MethodDef>();
        var budget = 250_000;
        var reason = "Construction region exceeds its bound.";
        var entries = new Dictionary<Instruction, HashSet<FieldDef>> { [il[at]] = [] };
        var pending = new Queue<Instruction>(); pending.Enqueue(il[at]);
        var returns = new List<HashSet<FieldDef>>();
        while (pending.TryDequeue(out var instruction))
        {
            if (--budget < 0 || prefix.Contains(instruction)) return new(false, "Construction returns to the prefix or exceeds its bound.");
            var assigned = new HashSet<FieldDef>(entries[instruction]);
            if (!CheckInstruction(initializer, instruction, assigned)) return new(false, reason);
            if (instruction.OpCode.Code == Code.Ret) { returns.Add(assigned); continue; }
            var index = positions[instruction];
            var successors = new List<Instruction>();
            if (instruction.Operand is Instruction target) successors.Add(target);
            if (instruction.Operand is IList<Instruction> targets) successors.AddRange(targets);
            if (instruction.OpCode.FlowControl != FlowControl.Branch)
            {
                if (index + 1 == il.Count) return new(false, "Construction falls off its body.");
                successors.Add(il[index + 1]);
            }
            foreach (var next in successors)
            {
                if (!positions.ContainsKey(next)) return new(false, "Foreign branch target.");
                if (!entries.TryGetValue(next, out var prior)) { entries[next] = new(assigned); pending.Enqueue(next); }
                else
                {
                    var count = prior.Count;
                    prior.IntersectWith(assigned);
                    if (prior.Count != count) pending.Enqueue(next);
                }
            }
        }
        if (fields.Count == 0 || returns.Count == 0 || returns.Any(r => !fields.IsSubsetOf(r)))
            return new(false, "A publication is not definitely assigned on every return.");
        // Reflection over these declarations would invalidate direct-CIL ownership.
        foreach (var method in owner.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
            for (var index = 0; index < method.Body.Instructions.Count; index++)
            {
                var instruction = method.Body.Instructions[index];
                if (instruction.OpCode.Code != Code.Ldtoken) continue;
                if (instruction.Operand is IField f && f.ResolveFieldDef() is { } field && fields.Contains(field) ||
                    instruction.Operand is ITypeDefOrRef t && t.ResolveTypeDef() == owner &&
                    !IsInitializationOnly(method, index))
                    return new(false, "A publication is exposed through a metadata token.");
            }
        var consumers = SharedGraphReadOnly.CheckPublishedTogether(fields, initializer);
        return new(consumers.Passed, consumers.Detail) { Fields = fields };

        bool CheckMethod(MethodDef method)
        {
            if (!methods.Add(method)) return true;
            if (methods.Count > 128 || !method.HasBody || method.HasGenericParameters || method.DeclaringType.HasGenericParameters ||
                method.Body.ExceptionHandlers.Count != 0 || method.Body.Variables.Count != 0 && !method.Body.InitLocals) return false;
            // Helpers receive only construction-owned values; no static access may
            // introduce an alias, ambient input or publication outside the root region.
            foreach (var instruction in method.Body.Instructions)
                if (--budget < 0 || !CheckInstruction(method, instruction, null)) return false;
            return true;
        }

        bool CheckInstruction(MethodDef method, Instruction instruction, HashSet<FieldDef>? assigned)
        {
            reason = $"Open construction input at {method.FullName} IL_{instruction.Offset:X4} ({instruction.OpCode}).";
            if (method.Body.Variables.Count != 0 && !method.Body.InitLocals) return false;
            var code = instruction.OpCode.Code;
            if (code is Code.Ldsfld or Code.Stsfld)
            {
                if (assigned is null || instruction.Operand is not IField reference ||
                    reference.ResolveFieldDef() is not { IsStatic: true } field || field.DeclaringType != owner) return false;
                if (code == Code.Ldsfld) return assigned.Contains(field);
                fields.Add(field); assigned.Add(field); return true;
            }
            if (code is Code.Ldfld or Code.Stfld or Code.Ldflda)
                return instruction.Operand is IField reference && reference.ResolveFieldDef() is { IsStatic: false } field && field.Module == owner.Module;
            if (code is Code.Call or Code.Callvirt or Code.Newobj)
            {
                if (instruction.Operand is not IMethod called || called is MethodSpec) return false;
                if (called.ResolveMethodDef() is { } target && target.Module == owner.Module)
                    return !(code == Code.Callvirt && target.IsVirtual) && !target.IsStaticConstructor && CheckMethod(target);
                return code == Code.Call && called.DeclaringType.FullName == "System.Object" && called.Name == ".ctor" &&
                    called.MethodSig is { HasThis: true, Params.Count: 0, RetType.ElementType: ElementType.Void } ||
                    code == Code.Callvirt && called.DeclaringType.FullName == "System.Array" && called.Name == "get_Length" &&
                    called.MethodSig is { HasThis: true, Params.Count: 0, RetType.ElementType: ElementType.I4 };
            }
            return PureInstruction(code);
        }
    }

    // A handle consumed immediately by the framework initialization intrinsic never
    // becomes a Type/FieldInfo and cannot expose the published graph to reflection.
    // This only classifies the handle use; the initialization call remains in place.
    private static bool IsInitializationOnly(MethodDef method, int index)
    {
        var il = method.Body.Instructions;
        return index + 1 < il.Count && il[index + 1].OpCode.Code == Code.Call &&
            il[index + 1].Operand is IMethod called && called.DeclaringType is TypeRef declaring &&
            declaring.DefinitionAssembly?.FullName == method.Module.CorLibTypes.AssemblyRef.FullName &&
            called.FullName == "System.Void System.Runtime.CompilerServices.RuntimeHelpers::RunClassConstructor(System.RuntimeTypeHandle)";
    }

    private static bool PureInstruction(Code code) => code is
        Code.Nop or Code.Ret or Code.Ldnull or Code.Dup or Code.Pop or
        Code.Ldarg or Code.Ldarg_S or Code.Ldarg_0 or Code.Ldarg_1 or Code.Ldarg_2 or Code.Ldarg_3 or
        Code.Ldloc or Code.Ldloc_S or Code.Ldloc_0 or Code.Ldloc_1 or Code.Ldloc_2 or Code.Ldloc_3 or
        Code.Stloc or Code.Stloc_S or Code.Stloc_0 or Code.Stloc_1 or Code.Stloc_2 or Code.Stloc_3 or
        Code.Ldloca or Code.Ldloca_S or Code.Ldelema or Code.Ldobj or Code.Stobj or Code.Initobj or
        Code.Ldc_I4 or Code.Ldc_I4_S or Code.Ldc_I4_M1 or Code.Ldc_I4_0 or Code.Ldc_I4_1 or Code.Ldc_I4_2 or
        Code.Ldc_I4_3 or Code.Ldc_I4_4 or Code.Ldc_I4_5 or Code.Ldc_I4_6 or Code.Ldc_I4_7 or Code.Ldc_I4_8 or
        Code.Ldc_I8 or Code.Ldc_R4 or Code.Ldc_R8 or
        Code.Add or Code.Sub or Code.Mul or Code.Div or Code.Div_Un or Code.Rem or Code.Rem_Un or
        Code.And or Code.Or or Code.Xor or Code.Not or Code.Neg or Code.Shl or Code.Shr or Code.Shr_Un or
        Code.Ceq or Code.Cgt or Code.Cgt_Un or Code.Clt or Code.Clt_Un or
        Code.Conv_I1 or Code.Conv_U1 or Code.Conv_I2 or Code.Conv_U2 or Code.Conv_I4 or Code.Conv_U4 or
        Code.Conv_I8 or Code.Conv_U8 or Code.Conv_R4 or Code.Conv_R8 or Code.Conv_R_Un or
        Code.Br or Code.Br_S or Code.Brtrue or Code.Brtrue_S or Code.Brfalse or Code.Brfalse_S or
        Code.Beq or Code.Beq_S or Code.Bne_Un or Code.Bne_Un_S or Code.Bge or Code.Bge_S or Code.Bge_Un or Code.Bge_Un_S or
        Code.Bgt or Code.Bgt_S or Code.Bgt_Un or Code.Bgt_Un_S or Code.Ble or Code.Ble_S or Code.Ble_Un or Code.Ble_Un_S or
        Code.Blt or Code.Blt_S or Code.Blt_Un or Code.Blt_Un_S or Code.Switch or
        Code.Newarr or Code.Ldlen or Code.Castclass or Code.Box or Code.Ldelem or Code.Stelem or
        Code.Ldelem_I1 or Code.Ldelem_U1 or Code.Ldelem_I2 or Code.Ldelem_U2 or Code.Ldelem_I4 or Code.Ldelem_U4 or
        Code.Ldelem_I8 or Code.Ldelem_R4 or Code.Ldelem_R8 or Code.Ldelem_Ref or
        Code.Stelem_I1 or Code.Stelem_I2 or Code.Stelem_I4 or Code.Stelem_I8 or Code.Stelem_R4 or Code.Stelem_R8 or Code.Stelem_Ref;
}
