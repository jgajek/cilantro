using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Replaces the invocation inside a retained stub, preserving its packing and copyback.</summary>
internal static class BabelByRefAdapter
{
    internal static bool Supported(MethodDef method, Func<IMethod, bool> dispatcher)
    {
        if (method.HasGenericParameters || method.DeclaringType.HasGenericParameters ||
            !method.IsStatic && method.DeclaringType.IsValueType || method.Body.ExceptionHandlers.Count != 0 ||
            method.Body.Instructions.Count > 512 || method.ReturnType.IsByRef ||
            method.Body.Variables.Count != 0 && !method.Body.InitLocals ||
            method.ReturnType.ElementType != ElementType.Void && !Element(method.ReturnType) ||
            !method.Parameters.Any(parameter => parameter.Type.IsByRef) ||
            method.Parameters.Any(parameter => !Element(parameter.Type.IsByRef ? parameter.Type.Next : parameter.Type))) return false;
        var il = method.Body.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop).ToArray();
        var calls = il.Select((instruction, index) => (instruction, index)).Where(item => item.instruction.OpCode.Code == Code.Call &&
            item.instruction.Operand is IMethod called && dispatcher(called)).ToArray();
        if (calls.Length != 1 || calls[0].index < 4) return false;
        var stack = EvaluationStackAnalyzer.Analyze(method);
        if (!stack.Valid || !stack.Depths.TryGetValue(calls[0].instruction, out var depth) || depth != 4) return false;
        var at = calls[0].index;
        if (!il[at - 4].IsLdcI4() || il[at - 3].OpCode.Code != Code.Ldnull || !il[at - 1].IsLdloc() ||
            (method.IsStatic ? il[at - 2].OpCode.Code != Code.Ldnull : il[at - 2].OpCode.Code != Code.Ldarg_0)) return false;
        return il.All(instruction => instruction == calls[0].instruction || instruction.IsLdcI4() || instruction.IsLdarg() || instruction.IsLdloc() || instruction.IsStloc() ||
            instruction.OpCode.Code is Code.Ldnull or Code.Ldc_I8 or Code.Ldc_R4 or Code.Ldc_R8 or Code.Newarr or Code.Dup or Code.Box or Code.Stelem_Ref or
                Code.Ldelem_Ref or Code.Unbox_Any or Code.Castclass or Code.Ret or Code.Pop or Code.Ldind_I1 or Code.Ldind_U1 or Code.Ldind_I2 or Code.Ldind_U2 or
                Code.Ldind_I4 or Code.Ldind_U4 or Code.Ldind_I8 or Code.Ldind_R4 or Code.Ldind_R8 or Code.Ldind_Ref or Code.Stind_I1 or Code.Stind_I2 or Code.Stind_I4 or
                Code.Stind_I8 or Code.Stind_R4 or Code.Stind_R8 or Code.Stind_Ref);
    }

    private static bool Element(TypeSig type) => !type.ContainsGenericParameter && type.ElementType is
        ElementType.Boolean or ElementType.Char or ElementType.I1 or ElementType.U1 or ElementType.I2 or ElementType.U2 or ElementType.I4 or ElementType.U4 or
        ElementType.I8 or ElementType.U8 or ElementType.R4 or ElementType.R8 or ElementType.String or ElementType.Object or ElementType.Class or ElementType.Array or ElementType.SZArray ||
        !type.ContainsGenericParameter && type.ElementType == ElementType.GenericInst && !type.IsValueType;

    internal static CilBody? Build(MethodDef stub, MethodDef generated, MethodDef target, Func<IMethod, bool> dispatcher)
    {
        if (generated.Body.Instructions.Any(instruction => instruction.OpCode.Code is Code.Tailcall or Code.Jmp) ||
            generated.Body.Variables.Count != 0 && !generated.Body.InitLocals) return null;
        var body = BabelMethodImagePass.Lower(stub, target);
        var application = BabelMethodImagePass.Lower(generated, target);
        var call = body.Instructions.Single(instruction => instruction.OpCode.Code == Code.Call && instruction.Operand is IMethod called && dispatcher(called));
        var module = target.Module;
        var importer = new Importer(module);
        Local Slot(TypeSig type) { var local = new Local(importer.Import(type)); body.Variables.Add(local); return local; }
        var packed = Slot(new SZArraySig(module.CorLibTypes.Object));
        var receiver = Slot(module.CorLibTypes.Object);
        var arguments = target.Parameters.Select(parameter => Slot(parameter.Type)).ToArray();
        var cells = target.Parameters.Select(parameter => parameter.Type.IsByRef ? Slot(parameter.Type.Next) : null).ToArray();
        Local? returned = target.ReturnType.ElementType == ElementType.Void ? null : Slot(target.ReturnType);
        foreach (var local in application.Variables) body.Variables.Add(local);
        var replacement = new List<Instruction>
        {
            OpCodes.Stloc.ToInstruction(packed), OpCodes.Stloc.ToInstruction(receiver), OpCodes.Pop.ToInstruction(), OpCodes.Pop.ToInstruction()
        };
        for (var index = 0; index < arguments.Length; index++)
        {
            var parameter = target.Parameters[index];
            var element = parameter.Type.IsByRef ? parameter.Type.Next : parameter.Type;
            if (parameter.IsHiddenThisParameter) replacement.Add(OpCodes.Ldloc.ToInstruction(receiver));
            else
            {
                replacement.Add(OpCodes.Ldloc.ToInstruction(packed));
                replacement.Add(OpCodes.Ldc_I4.ToInstruction(parameter.MethodSigIndex));
                replacement.Add(OpCodes.Ldelem_Ref.ToInstruction());
            }
            replacement.Add((element.IsValueType ? OpCodes.Unbox_Any : OpCodes.Castclass).ToInstruction(importer.Import(element.ToTypeDefOrRef())));
            replacement.Add(OpCodes.Stloc.ToInstruction(cells[index] ?? arguments[index]));
            if (cells[index] is { } cell)
            {
                replacement.Add(OpCodes.Ldloca.ToInstruction(cell)); replacement.Add(OpCodes.Stloc.ToInstruction(arguments[index]));
            }
        }
        var end = OpCodes.Nop.ToInstruction();
        var epilogue = OpCodes.Nop.ToInstruction();
        foreach (var instruction in application.Instructions)
        {
            var code = instruction.OpCode.Code;
            if (instruction.IsLdarg() || code is Code.Ldarga or Code.Ldarga_S or Code.Starg or Code.Starg_S)
            {
                var index = code switch { Code.Ldarg_0 => 0, Code.Ldarg_1 => 1, Code.Ldarg_2 => 2, Code.Ldarg_3 => 3, _ => ((Parameter)instruction.Operand).Index };
                instruction.OpCode = code is Code.Ldarga or Code.Ldarga_S ? OpCodes.Ldloca : code is Code.Starg or Code.Starg_S ? OpCodes.Stloc : OpCodes.Ldloc;
                instruction.Operand = arguments[index];
            }
            if (code == Code.Ret)
            {
                instruction.OpCode = returned is null ? OpCodes.Br : OpCodes.Stloc;
                instruction.Operand = returned is null ? epilogue : returned;
                replacement.Add(instruction);
                if (returned is not null) replacement.Add(OpCodes.Br.ToInstruction(epilogue));
            }
            else replacement.Add(instruction);
        }
        replacement.Add(end); replacement.Add(epilogue);
        foreach (var parameter in target.Parameters.Where(parameter => parameter.Type.IsByRef))
        {
            replacement.Add(OpCodes.Ldloc.ToInstruction(packed)); replacement.Add(OpCodes.Ldc_I4.ToInstruction(parameter.MethodSigIndex));
            replacement.Add(OpCodes.Ldloc.ToInstruction(cells[parameter.Index]!));
            if (parameter.Type.Next.IsValueType) replacement.Add(OpCodes.Box.ToInstruction(importer.Import(parameter.Type.Next.ToTypeDefOrRef())));
            replacement.Add(OpCodes.Stelem_Ref.ToInstruction());
        }
        replacement.Add(returned is null ? OpCodes.Ldnull.ToInstruction() : OpCodes.Ldloc.ToInstruction(returned));
        if (returned is not null && target.ReturnType.IsValueType) replacement.Add(OpCodes.Box.ToInstruction(importer.Import(target.ReturnType.ToTypeDefOrRef())));
        foreach (var handler in application.ExceptionHandlers)
        {
            handler.TryEnd ??= end; handler.HandlerEnd ??= end; body.ExceptionHandlers.Add(handler);
        }
        var at = body.Instructions.IndexOf(call); body.Instructions.RemoveAt(at);
        foreach (var instruction in replacement) body.Instructions.Insert(at++, instruction);
        body.InitLocals = true;
        body.MaxStack = Math.Max(body.MaxStack, application.MaxStack);
        body.SimplifyBranches();
        return body;
    }
}
