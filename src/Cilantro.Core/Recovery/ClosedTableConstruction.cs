using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Evaluates a fresh object graph whose construction cannot observe initialization state.</summary>
internal static class ClosedTableConstruction
{
    internal static bool IsClosed(MethodDef constructor) => Check(constructor, false, null);

    internal static bool SafePrefix(MethodDef initializer, IReadOnlyList<Instruction> instructions) => Check(initializer, true, instructions);

    private static bool Check(MethodDef constructor, bool prefix, IReadOnlyList<Instruction>? root)
    {
        var pending = new Stack<MethodDef>();
        var seen = new HashSet<MethodDef>();
        pending.Push(constructor);
        while (pending.TryPop(out var method))
        {
            if (!seen.Add(method)) continue;
            if (seen.Count > 128 || !method.HasBody || method.HasGenericParameters ||
                method.DeclaringType.HasGenericParameters || method.Body.ExceptionHandlers.Count != 0) return false;
            foreach (var instruction in method == constructor && root is not null ? root : method.Body.Instructions.ToArray())
            {
                if (instruction.OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj)
                {
                    if (instruction.Operand is not IMethod called || called is MethodSpec) return false;
                    var target = called.ResolveMethodDef();
                    if (target?.Module == constructor.Module)
                    {
                        if (instruction.OpCode.Code == Code.Callvirt && target.IsVirtual) return false;
                        pending.Push(target);
                        if (prefix && target.DeclaringType.FindStaticConstructor() is { } initializer) pending.Push(initializer);
                        if (!prefix && target.DeclaringType != constructor.DeclaringType &&
                            target.DeclaringType.FindStaticConstructor() is { } dependencyInitializer &&
                            !Check(dependencyInitializer, true, null)) return false;
                    }
                    else if (prefix && instruction.OpCode.Code == Code.Call && AmbientRead(called)) { }
                    else if (instruction.OpCode.Code != Code.Call || called.DeclaringType.FullName != "System.Object" ||
                        called.Name != ".ctor" || called.MethodSig is not { HasThis: true, Params.Count: 0, RetType.ElementType: ElementType.Void }) return false;
                    continue;
                }
                // The skipped prefix must not be able to patch code, publish aliases,
                // register callbacks or alter module resources. Scalar writes and a
                // few read-only ambient queries are retained at the real call site.
                if (prefix && instruction.OpCode.Code == Code.Throw) continue;
                if (prefix && instruction.OpCode.Code is Code.Ldsfld or Code.Stsfld)
                {
                    if (instruction.Operand is not IField reference || reference.ResolveFieldDef() is not { IsStatic: true } field ||
                        field.Module != constructor.Module || field.FieldType.ElementType is not
                        (ElementType.Boolean or ElementType.Char or ElementType.I1 or ElementType.U1 or ElementType.I2 or ElementType.U2 or
                        ElementType.I4 or ElementType.U4 or ElementType.I8 or ElementType.U8 or ElementType.R4 or ElementType.R8)) return false;
                    if (field.DeclaringType.FindStaticConstructor() is { } initializer) pending.Push(initializer);
                    continue;
                }
                if (instruction.OpCode.Code is Code.Ldfld or Code.Stfld)
                {
                    if (instruction.Operand is not IField reference || reference.ResolveFieldDef() is not { IsStatic: false } field ||
                        field.Module != constructor.Module) return false;
                    continue;
                }
                // No static reads/writes, addresses, reflection, indirect calls or external
                // operations. All references originate in this fresh construction graph.
                if (instruction.OpCode.Code is not (
                    Code.Nop or Code.Ret or Code.Ldnull or Code.Ldstr or Code.Dup or Code.Pop or
                    Code.Ldarg or Code.Ldarg_S or Code.Ldarg_0 or Code.Ldarg_1 or Code.Ldarg_2 or Code.Ldarg_3 or
                    Code.Ldloc or Code.Ldloc_S or Code.Ldloc_0 or Code.Ldloc_1 or Code.Ldloc_2 or Code.Ldloc_3 or
                    Code.Stloc or Code.Stloc_S or Code.Stloc_0 or Code.Stloc_1 or Code.Stloc_2 or Code.Stloc_3 or
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
                    Code.Newarr or Code.Ldlen or Code.Castclass or
                    Code.Ldelem_I1 or Code.Ldelem_U1 or Code.Ldelem_I2 or Code.Ldelem_U2 or Code.Ldelem_I4 or Code.Ldelem_U4 or
                    Code.Ldelem_I8 or Code.Ldelem_R4 or Code.Ldelem_R8 or Code.Ldelem_Ref or
                    Code.Stelem_I1 or Code.Stelem_I2 or Code.Stelem_I4 or Code.Stelem_I8 or Code.Stelem_R4 or Code.Stelem_R8 or Code.Stelem_Ref)) return false;
            }
        }
        return true;
    }

    private static bool AmbientRead(IMethod method) => method.MethodSig is { HasThis: false, Params.Count: 0 } &&
        (method.DeclaringType.FullName, method.Name.String, method.MethodSig.RetType.ElementType) is
        ("System.Environment", "get_TickCount", ElementType.I4) or
        ("System.Environment", "get_TickCount64", ElementType.I8) or
        ("System.Diagnostics.Debugger", "get_IsAttached", ElementType.Boolean) or
        ("System.Security.Cryptography.CryptoConfig", "get_AllowOnlyFipsAlgorithms", ElementType.Boolean);

    internal static Dictionary<int, int> Read(ArtifactContext context, MethodDef initializer, MethodDef constructor,
        FieldDef holder, MethodDef getter, IEnumerable<int> indexes)
    {
        var answers = new Dictionary<int, int>();
        if (!IsClosed(constructor)) return answers;
        // Only the proved self-contained construction runs without automatic type
        // initialization. The original initializer is retained in emitted code.
        var limits = BootstrapMachine.Environment(context).Declarations.Budgets.Over(new StaticMachineLimits(MaximumSteps: 4_000_000));
        var machine = new StaticMachine(limits);
        if (!BootstrapMachine.TryTell(context, machine, out _)) return answers;
        machine.State.RegisterRunEnvironment(new RunEnvironment(new HostEnvironment(HostProfile.Empty)));
        var original = initializer.Body;
        var construction = new CilBody();
        construction.Instructions.Add(OpCodes.Newobj.ToInstruction(constructor));
        construction.Instructions.Add(OpCodes.Stsfld.ToInstruction(holder));
        construction.Instructions.Add(OpCodes.Ret.ToInstruction());
        try
        {
            initializer.Body = construction;
            if (!machine.Execute(initializer).Succeeded) return answers;
        }
        finally { initializer.Body = original; }
        foreach (var index in indexes)
        {
            var result = machine.Execute(getter, [StaticValue.FromInt32(index)]);
            if (result.Succeeded && result.Value.Kind == StaticValueKind.Int32) answers[index] = result.Value.AsInt32();
        }
        return answers;
    }
}
