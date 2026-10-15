using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Recovers closed reference field stack types without changing field signatures.</summary>
public sealed class ReferenceFieldTypingPass : ArrayFieldTypingPass
{
    public override string Name => "reference-field-typing";
    public override IReadOnlyCollection<string> Dependencies => ["array-field-typing"];
    protected override string TypeLabel => "reference";
    protected override string ChangeKind => "restore-reference-field-stack-type";

    protected override bool TryStoredType(MethodDef method, int store, ControlFlowGraph graph, out TypeSig type)
    {
        type = null!;
        if (TryNullCoalescedValue(method, store, graph, out type)) return true;
        var il = method.Body.Instructions;
        var block = graph.BlockOf(il[store]);
        var slot = 0;
        for (var index = store - 1; index >= 0 && graph.BlockOf(il[index]) == block; index--)
        {
            var instruction = il[index];
            instruction.CalculateStackUsage(out var pushes, out var pops);
            if (pops < 0) return false;
            if (slot < pushes)
            {
                // Both dup outputs denote the same incoming value. Property setters
                // can consume one copy while the other remains for the field store.
                if (instruction.OpCode.Code == Code.Dup) { slot = 0; continue; }
                TypeSig? produced = instruction.OpCode.Code switch
                {
                    Code.Newobj when instruction.Operand is IMethod constructor => constructor.DeclaringType.ToTypeSig(),
                    Code.Castclass or Code.Isinst when instruction.Operand is ITypeDefOrRef cast => cast.ToTypeSig(),
                    Code.Ldstr => method.Module.CorLibTypes.String,
                    Code.Call or Code.Callvirt when instruction.Operand is IMethod call => ArrayParameterTypingPass.ReturnedType(call),
                    Code.Ldelem_Ref => ArrayElementType(method, index, graph),
                    _ => instruction.IsLdloc() ? instruction.GetLocal(method.Body.Variables)?.Type :
                        instruction.IsLdarg() ? instruction.GetParameter(method.Parameters)?.Type : null
                };
                if (produced is null || produced.ContainsGenericParameter ||
                    !(produced is ClassSig || produced.ElementType == ElementType.String ||
                      produced is GenericInstSig { GenericType: ClassSig })) return false;
                type = produced;
                return true;
            }
            slot = slot - pushes + pops;
        }
        return false;
    }

    private static bool TryNullCoalescedValue(MethodDef method, int store, ControlFlowGraph graph, out TypeSig type)
    {
        type = null!;
        var il = method.Body.Instructions;
        if (store < 5 || il[store - 2].OpCode.Code != Code.Pop || il[store - 1].OpCode.Code != Code.Newobj ||
            il[store - 1].Operand is not IMethod constructor || constructor.MethodSig is not { Params.Count: 0 }) return false;
        var direct = il[store - 4].OpCode.Code == Code.Dup &&
            il[store - 3].OpCode.Code is (Code.Brtrue or Code.Brtrue_S) && il[store - 3].Operand == il[store];
        var inverted = store >= 6 && il[store - 5].OpCode.Code == Code.Dup &&
            il[store - 4].OpCode.Code is (Code.Brfalse or Code.Brfalse_S) && il[store - 4].Operand == il[store - 2] &&
            il[store - 3].OpCode.Code is (Code.Br or Code.Br_S) && il[store - 3].Operand == il[store];
        if (!direct && !inverted) return false;
        var start = store - (inverted ? 6 : 5);
        var source = il[start];
        var supplied = source.IsLdarg() ? source.GetParameter(method.Parameters)?.Type :
            source.IsLdloc() ? source.GetLocal(method.Body.Variables)?.Type : null;
        if (supplied is not ClassSig || supplied.ContainsGenericParameter || supplied.FullName == "System.Object" ||
            !ReferenceParameterTypingPass.Ancestors(constructor.DeclaringType.ToTypeSig())
                .Any(candidate => new SigComparer().Equals(candidate, supplied))) return false;
        var interior = il.Skip(start + 1).Take(store - start).ToHashSet();
        if (il.Any(i => i != il[store - 3] && (!inverted || i != il[store - 4]) &&
            (i.Operand is Instruction target && interior.Contains(target) ||
             i.Operand is IList<Instruction> targets && targets.Any(interior.Contains)))) return false;
        if (!interior.All(i => graph.HaveIdenticalExceptionRegions(source, i))) return false;
        // Exception/filter entries can supply a different stack even when their
        // surrounding region memberships happen to compare equal.
        if (method.Body.ExceptionHandlers.Any(h =>
            new[] { h.TryStart, h.TryEnd, h.HandlerStart, h.HandlerEnd, h.FilterStart }
                .OfType<Instruction>().Any(interior.Contains))) return false;
        type = supplied;
        return true;
    }

    private static TypeSig? ArrayElementType(MethodDef method, int read, ControlFlowGraph graph)
    {
        // The array is below the index. Trace that stack slot within this block;
        // no type is inferred from the consumer's desired type or across joins.
        var il = method.Body.Instructions;
        var block = graph.BlockOf(il[read]);
        var slot = 1;
        for (var index = read - 1; index >= 0 && graph.BlockOf(il[index]) == block; index--)
        {
            var instruction = il[index];
            instruction.CalculateStackUsage(out var pushes, out var pops);
            if (pops < 0) return null;
            if (slot < pushes)
            {
                if (instruction.OpCode.Code == Code.Dup) { slot = 0; continue; }
                TypeSig? array = instruction.IsLdloc() ? instruction.GetLocal(method.Body.Variables)?.Type :
                    instruction.IsLdarg() ? instruction.GetParameter(method.Parameters)?.Type :
                    instruction.OpCode.Code is Code.Ldfld or Code.Ldsfld && instruction.Operand is IField field ? field.FieldSig?.Type :
                    instruction.OpCode.Code is Code.Call or Code.Callvirt && instruction.Operand is IMethod call ? ArrayParameterTypingPass.ReturnedType(call) :
                    instruction.OpCode.Code is Code.Castclass or Code.Isinst && instruction.Operand is ITypeDefOrRef cast ? cast.ToTypeSig() :
                    instruction.OpCode.Code == Code.Newarr && instruction.Operand is ITypeDefOrRef element ? new SZArraySig(element.ToTypeSig()) : null;
                return array is SZArraySig vector ? vector.Next : null;
            }
            slot = slot - pushes + pops;
        }
        return null;
    }
}
