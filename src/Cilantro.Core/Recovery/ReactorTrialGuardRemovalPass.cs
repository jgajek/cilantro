using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;

namespace Cilantro.Core.Recovery;

/// <summary>Removes the identified Reactor trial gate after protected bodies have been recovered.</summary>
public sealed class ReactorTrialGuardRemovalPass : DeobfuscationPass
{
    internal const string Message = "This assembly is protected by an unregistered version of Eziriz's \".NET Reactor\"! This assembly won't further work.";
    public override string Name => "reactor-trial-guard-removal";
    public override IReadOnlyCollection<string> Dependencies => ["method-body-recovery", "delegate-proxy-analysis"];

    private static readonly HashSet<string> Calls = new(StringComparer.Ordinal)
    {
        "System.DateTime System.DateTime::get_Now()",
        "System.Void System.DateTime::.ctor(System.Int32,System.Int32,System.Int32)",
        "System.TimeSpan System.DateTime::op_Subtraction(System.DateTime,System.DateTime)",
        "System.Int32 System.TimeSpan::get_Days()",
        "System.Void System.Exception::.ctor(System.String)"
    };

    internal static bool IsGeneratedGate(MethodDef method)
    {
        if (!method.DeclaringType.IsGlobalModuleType || !method.IsStatic || !method.HasBody ||
            method.MethodSig.Params.Count != 0 || method.ReturnType.ElementType != ElementType.Void ||
            method.Body.HasExceptionHandlers || !method.Body.Instructions.Any(instruction => instruction.OpCode.Code == Code.Ldstr &&
                instruction.Operand is string text && text == Message)) return false;
        if (!TrialGuardAnalysis.Find(method.Module, []).Contains(method.MDToken.Raw)) return false;
        foreach (var instruction in method.Body.Instructions)
        {
            if (instruction.Operand is IMethod called)
            {
                if (instruction.OpCode.Code is not (Code.Call or Code.Newobj) || !Calls.Contains(called.FullName)) return false;
                continue;
            }
            if (instruction.OpCode.Code == Code.Ldstr && instruction.Operand is string literal && literal != Message) return false;
            if (instruction.OpCode.Code is not (Code.Nop or Code.Ldstr or Code.Ldc_I4 or Code.Ldc_I4_S or
                Code.Ldc_I4_M1 or Code.Ldc_I4_0 or Code.Ldc_I4_1 or Code.Ldc_I4_2 or Code.Ldc_I4_3 or
                Code.Ldc_I4_4 or Code.Ldc_I4_5 or Code.Ldc_I4_6 or Code.Ldc_I4_7 or Code.Ldc_I4_8 or
                Code.Ldloc or Code.Ldloc_S or Code.Ldloc_0 or Code.Ldloc_1 or Code.Ldloc_2 or Code.Ldloc_3 or
                Code.Ldloca or Code.Ldloca_S or Code.Stloc or Code.Stloc_S or Code.Stloc_0 or Code.Stloc_1 or Code.Stloc_2 or Code.Stloc_3 or
                Code.Add or Code.Sub or Code.Cgt or Code.Cgt_Un or Code.Clt or Code.Clt_Un or Code.Ceq or Code.Dup or Code.Pop or
                Code.Br or Code.Br_S or Code.Brtrue or Code.Brtrue_S or Code.Brfalse or Code.Brfalse_S or
                Code.Beq or Code.Beq_S or Code.Bne_Un or Code.Bne_Un_S or Code.Bge or Code.Bge_S or Code.Bgt or Code.Bgt_S or
                Code.Ble or Code.Ble_S or Code.Blt or Code.Blt_S or Code.Ret or Code.Throw)) return false;
        }
        return true;
    }

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        if (!context.TryGetFact<bool>("options.removeRuntime", out var enabled) || !enabled ||
            !context.TryGetFact<bool>("method-protection.complete", out var complete) || !complete)
            return (PassStatus.Success, 0, ["Trial-gate removal requires enabled runtime cleanup and completed method recovery."]);
        var gates = context.Module.GlobalType.Methods.Where(IsGeneratedGate).ToArray();
        foreach (var gate in gates)
        {
            gate.Body = new CilBody();
            gate.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            context.AddChange(new ChangeRecord(Name, "remove-reactor-trial-gate", gate.MDToken.ToString(),
                "Removed the exact generated Reactor expiry gate after method recovery; its only calls were clock arithmetic and exception construction."));
        }
        return (PassStatus.Success, gates.Length, [$"Removed {gates.Length} identified Reactor trial expiry gate(s); ordinary application date checks were retained."]);
    }
}
