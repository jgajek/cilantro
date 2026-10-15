using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Replaces closed character decoders behind readonly delegates with decoded text.</summary>
public sealed class DelegateStringCompletionPass : DeobfuscationPass
{
    public override string Name => "delegate-string-completion";
    public override bool GatesEmission => false;
    public override IReadOnlyCollection<string> Dependencies => ["string-runtime-cleanup"];

    protected override (PassStatus, int, IReadOnlyList<string>) Execute(ArtifactContext context)
    {
        var candidates = context.Module.GetTypes().SelectMany(t => t.Fields)
            .Select(ReadonlyDelegateBinding.Target).OfType<MethodDef>().Distinct().Where(Closed).Take(512).ToArray();
        using var batch = new BodyMutationBatch();
        var count = 0;
        foreach (var method in candidates)
        {
            var text = Read(method);
            if (text is null || text != Read(method)) continue;
            batch.Capture(method);
            // Keep the method and its invocation: its declaring type still initializes,
            // and invoking a null delegate still throws. Preserve a fresh string result.
            var toChars = new MemberRefUser(context.Module, "ToCharArray",
                MethodSig.CreateInstance(new SZArraySig(context.Module.CorLibTypes.Char)),
                context.Module.CorLibTypes.String.TypeDefOrRef);
            var constructor = new MemberRefUser(context.Module, ".ctor",
                MethodSig.CreateInstance(context.Module.CorLibTypes.Void, new SZArraySig(context.Module.CorLibTypes.Char)),
                context.Module.CorLibTypes.String.TypeDefOrRef);
            method.Body = new CilBody();
            foreach (var instruction in new[] { OpCodes.Ldstr.ToInstruction(text), OpCodes.Callvirt.ToInstruction(toChars),
                OpCodes.Newobj.ToInstruction(constructor), OpCodes.Ret.ToInstruction() }) method.Body.Instructions.Add(instruction);
            count++;
            batch.RecordChange(context, new ChangeRecord(Name, "decode-delegate-string-body", method.FullName,
                "Decoded the closed character transform; retained the callable method, initialization triggers and fresh string construction."));
        }
        if (!AssemblyVerifier.Verify(context.Module).Passed)
            return (PassStatus.Partial, 0, ["Delegate decoder completion failed verification and was rolled back."]);
        batch.Commit();
        return (PassStatus.Success, count, [$"Replaced {count} closed delegate decoder body(s), retaining calls and fresh string results."]);
    }

    private static string? Read(MethodDef method)
    {
        // Only the body is interpreted. Closed() excludes all ambient/static inputs;
        // its declaring-type initializer remains on the actual invocation path.
        var machine = new StaticMachine(new StaticMachineLimits(MaximumSteps: 500_000));
        var result = machine.Execute(method);
        return result.Succeeded && machine.State.Heap.TryGetString(result.Value, out var text) ? text : null;
    }

    internal static string? ReadClosedIntegerDecoder(MethodDef method, int argument)
    {
        if (!Closed(method, true)) return null;
        string? first = null;
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var machine = new StaticMachine(new StaticMachineLimits(MaximumSteps: 500_000));
            var result = machine.Execute(method, [StaticValue.FromInt32(argument)]);
            if (!result.Succeeded || !machine.State.Heap.TryGetString(result.Value, out var value) ||
                attempt != 0 && first != value) return null;
            first = value;
        }
        return first;
    }

    private static bool Closed(MethodDef method) => Closed(method, false);

    private static bool Closed(MethodDef method, bool integerParameter)
    {
        if (!method.IsStatic || !method.HasBody || method.HasGenericParameters || method.DeclaringType.HasGenericParameters ||
            method.MethodSig.Params.Count != (integerParameter ? 1 : 0) ||
            integerParameter && method.MethodSig.Params[0].ElementType != ElementType.I4 || method.ReturnType.ElementType != ElementType.String ||
            method.Body.HasExceptionHandlers || !method.Body.InitLocals && method.Body.Variables.Count != 0 ||
            method.Body.Instructions.Count > 512 || !method.Body.Instructions.Any(i => i.OpCode.Code == Code.Xor)) return false;
        var il = method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        if (!il.Any(i => i.OpCode.Code == Code.Ldstr)) return false;
        for (var index = 0; index < il.Length; index++)
        {
            var i = il[index];
            if (integerParameter && i.IsLdarg() && i.GetParameterIndex() == 0) continue;
            if (i.OpCode.Code == Code.Ret)
            {
                if (index == 0 || il[index - 1].OpCode.Code != Code.Newobj ||
                    !StringCall(method.Module, il[index - 1], "System.Void System.String::.ctor(System.Char[])")) return false;
            }
            else if (i.OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj)
            {
                if (!(i.OpCode.Code is Code.Call or Code.Callvirt &&
                    StringCall(method.Module, i, "System.Char[] System.String::ToCharArray()")) &&
                    !(i.OpCode.Code == Code.Newobj && StringCall(method.Module, i, "System.Void System.String::.ctor(System.Char[])"))) return false;
            }
            else if (i.OpCode.Code == Code.Castclass)
            {
                if (i.Operand is not TypeRef type || type.FullName != "System.String" ||
                    type.DefinitionAssembly?.FullName != method.Module.CorLibTypes.AssemblyRef.FullName) return false;
            }
            else if (i.OpCode.Code is not (Code.Ldstr or Code.Ldnull or Code.Dup or Code.Pop or
                Code.Ldloc or Code.Ldloc_S or Code.Ldloc_0 or Code.Ldloc_1 or Code.Ldloc_2 or Code.Ldloc_3 or
                Code.Stloc or Code.Stloc_S or Code.Stloc_0 or Code.Stloc_1 or Code.Stloc_2 or Code.Stloc_3 or
                Code.Ldc_I4 or Code.Ldc_I4_S or Code.Ldc_I4_M1 or Code.Ldc_I4_0 or Code.Ldc_I4_1 or Code.Ldc_I4_2 or
                Code.Ldc_I4_3 or Code.Ldc_I4_4 or Code.Ldc_I4_5 or Code.Ldc_I4_6 or Code.Ldc_I4_7 or Code.Ldc_I4_8 or
                Code.Add or Code.Sub or Code.Mul or Code.Xor or Code.And or Code.Or or Code.Not or Code.Neg or
                Code.Conv_I4 or Code.Conv_U2 or Code.Ldlen or Code.Ldelem_U2 or Code.Stelem_I2 or
                Code.Br or Code.Br_S or Code.Brtrue or Code.Brtrue_S or Code.Brfalse or Code.Brfalse_S or
                Code.Blt or Code.Blt_S or Code.Bge or Code.Bge_S or Code.Beq or Code.Beq_S or Code.Bne_Un or Code.Bne_Un_S)) return false;
        }
        // A return entered directly could bypass the allocation inspected above.
        var returns = il.Where(i => i.OpCode.Code == Code.Ret).ToHashSet();
        var allocationBypasses = new HashSet<Instruction>(returns);
        foreach (var ret in returns)
            for (var at = method.Body.Instructions.IndexOf(ret) - 1;
                 at >= 0 && method.Body.Instructions[at].OpCode.Code == Code.Nop; at--)
                allocationBypasses.Add(method.Body.Instructions[at]);
        return returns.Count != 0 && !il.Any(i => i.Operand is Instruction target && allocationBypasses.Contains(target));
    }

    private static bool StringCall(ModuleDef module, Instruction instruction, string fullName) =>
        instruction.Operand is IMethod called && called.FullName == fullName && called.DeclaringType is TypeRef type &&
        type.DefinitionAssembly?.FullName == module.CorLibTypes.AssemblyRef.FullName;
}
