using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Verification;

namespace Cilantro.Core.Recovery;

/// <summary>Evaluates literal calls to bounded, integer-only helper bodies with no effects.</summary>
public class IntegerHelperRecoveryPass : DeobfuscationPass
{
    public override string Name => "integer-helpers";
    public override IReadOnlyCollection<string> Dependencies => ["numeric-tables"];
    public override bool GatesEmission => false;

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var methods = context.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody).ToArray();
        var helpers = methods.Where(IsPure).ToHashSet();
        if (helpers.Count == 0) return (PassStatus.Success, 0, ["No pure integer helper was found."]);
        var machine = new StaticMachine(BootstrapMachine.Limits(10_000));
        var answers = new Dictionary<(MethodDef, int), int?>();
        using var transaction = new InstructionMutationTransaction();
        var folded = new HashSet<MethodDef>();
        var changes = 0;
        foreach (var method in methods)
        {
            var il = method.Body.Instructions;
            var targeted = new HashSet<Instruction>();
            foreach (var instruction in il)
            {
                if (instruction.Operand is Instruction target) targeted.Add(target);
                if (instruction.Operand is IList<Instruction> targets) targeted.UnionWith(targets);
            }
            foreach (var h in method.Body.ExceptionHandlers)
                foreach (var boundary in new[] { h.TryStart, h.TryEnd, h.HandlerStart, h.HandlerEnd, h.FilterStart })
                    if (boundary is not null) targeted.Add(boundary);
            for (var at = 1; at < il.Count; at++)
            {
                var call = il[at]; var key = il[at - 1];
                if (call.OpCode.Code != Code.Call || call.Operand is not IMethod reference ||
                    reference.ResolveMethodDef() is not { } helper || !helpers.Contains(helper) ||
                    !key.IsLdcI4() || targeted.Contains(call)) continue;
                var query = (helper, key.GetLdcI4Value());
                if (!answers.TryGetValue(query, out var value))
                {
                    if (answers.Count >= 2048) continue;
                    var result = machine.Execute(helper, [StaticValue.FromInt32(query.Item2)]);
                    value = result.Succeeded && result.Value.Kind == StaticValueKind.Int32 ? result.Value.AsInt32() : null;
                    answers[query] = value;
                }
                if (value is null) continue;
                transaction.Capture(key); transaction.Capture(call);
                key.OpCode = OpCodes.Nop; key.Operand = null;
                call.OpCode = OpCodes.Ldc_I4; call.Operand = value.Value;
                transaction.RecordChange(context, new ChangeRecord(Name, "restore-integer-helper", method.FullName,
                    $"Replaced a pure helper call with Int32 constant {value.Value}."));
                folded.Add(helper); changes++;
            }
        }
        if (!AssemblyVerifier.Verify(context.Module).Passed)
            return (PassStatus.Partial, 0, ["Integer helper rewrites failed verification and were rolled back."]);
        transaction.Commit();
        RecoveryOrphans.Declare(context, folded);
        return (PassStatus.Success, changes, [$"Replaced {changes} calls to pure integer helpers."]);
    }

    private static bool IsPure(MethodDef method) => method.IsStatic && !method.HasGenericParameters &&
        (method.DeclaringType.FindStaticConstructor() is not { } initializer ||
         initializer.HasBody && initializer.Body.Instructions.All(i => i.OpCode.Code is Code.Nop or Code.Ret)) &&
        method.MethodSig.Params.Count == 1 &&
        method.MethodSig.Params[0].ElementType == ElementType.I4 && method.ReturnType.ElementType == ElementType.I4 &&
        method.Body.InitLocals && method.Body.ExceptionHandlers.Count == 0 && method.Body.Instructions.Count <= 512 &&
        method.Body.Variables.All(v => v.Type.ElementType is ElementType.I4 or ElementType.U4) &&
        method.Body.Instructions.All(i => i.IsLdcI4() || i.IsLdloc() || i.IsStloc() || i.OpCode.Code is
            Code.Nop or Code.Ldarg_0 or Code.Ret or Code.Dup or Code.Pop or
            Code.Add or Code.Sub or Code.Mul or Code.Xor or Code.And or Code.Or or Code.Neg or Code.Not or
            Code.Shl or Code.Shr or Code.Shr_Un or Code.Ceq or Code.Cgt or Code.Cgt_Un or Code.Clt or Code.Clt_Un or
            Code.Br or Code.Br_S or Code.Brtrue or Code.Brtrue_S or Code.Brfalse or Code.Brfalse_S or Code.Switch or
            Code.Beq or Code.Beq_S or Code.Bne_Un or Code.Bne_Un_S or Code.Bgt or Code.Bgt_S or Code.Blt or Code.Blt_S or
            Code.Bge or Code.Bge_S or Code.Ble or Code.Ble_S);
}

/// <summary>Retries numeric recovery after proven loader initialization has been removed.</summary>
public sealed class IntegerHelperRecheckPass : IntegerHelperRecoveryPass
{
    public override string Name => "integer-helpers-recheck";
    public override IReadOnlyCollection<string> Dependencies => ["numeric-tables-recheck"];
}
