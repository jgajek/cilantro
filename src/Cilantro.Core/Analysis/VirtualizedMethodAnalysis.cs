using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>
/// A method whose body was replaced by a call into an interpreter, and the identity it is called by.
/// </summary>
public sealed record VirtualizedMethod(
    MethodDef Stub,
    IMethod Entry,
    int ProgramId,
    int ArgumentCount);

/// <summary>
/// Finds methods a code virtualizer emptied, by the shape of what it left behind.
/// </summary>
/// <remarks>
/// A virtualizer cannot hide the seam between compiled code and its interpreter: something has to
/// take the arguments the runtime passes on the stack and hand them to an interpreter that knows
/// nothing about this method's signature. Every such tool solves that the same way, by packing the
/// arguments into an object array and passing it with a number identifying which program to run.
/// That shape — pack every argument in order, pass a constant, call once, return — is what this
/// looks for, and it holds whatever the interpreter is called or however its bytecode is encoded.
///
/// Matching on shape rather than on a known engine is what makes the answer survive the protector
/// renaming everything, changing its opcode numbering, or being replaced by a different product.
/// The cost is that the shape must be recognized exactly: a stub that does any work of its own is
/// not reported, because then the interpreter is not the whole of the method and saying it was
/// would overstate what was found.
/// </remarks>
public static class VirtualizedMethodDetector
{
    public static IReadOnlyList<VirtualizedMethod> Detect(ModuleDef module)
    {
        ArgumentNullException.ThrowIfNull(module);
        var found = new List<VirtualizedMethod>();
        foreach (var method in module.GetTypes().SelectMany(type => type.Methods))
        {
            if (TryMatch(method) is { } virtualized)
                found.Add(virtualized);
        }

        // One interpreter serves every method it swallowed, and it tells them apart by the number
        // the stub passes. Two stubs reaching the same entry with the same number would mean that
        // number does not identify a program, so the reading is wrong and the group is dropped.
        return found
            .GroupBy(item => item.Entry.MDToken.Raw)
            .Where(group => group.Select(item => item.ProgramId).Distinct().Count() == group.Count())
            .SelectMany(group => group)
            .OrderBy(item => item.ProgramId)
            .ToArray();
    }

    private static VirtualizedMethod? TryMatch(MethodDef method)
    {
        if (!method.HasBody || method.Body.ExceptionHandlers.Count > 0)
            return null;
        var instructions = method.Body.Instructions
            .Where(instruction => instruction.OpCode.Code != Code.Nop)
            .ToArray();
        var parameters = method.Parameters.Count;
        if (parameters == 0 || instructions.Length < 3)
            return null;

        // The array has to hold every argument, this included, or the interpreter could not run a
        // body that reads them.
        var at = 0;
        if (!TryReadInt32(instructions, ref at, out var length) || length != parameters)
            return null;
        if (!Consume(instructions, ref at, Code.Newarr))
            return null;

        var stored = new bool[parameters];
        var array = -1;
        if (Consume(instructions, ref at, Code.Stloc, Code.Stloc_0, Code.Stloc_1, Code.Stloc_2,
                Code.Stloc_3, Code.Stloc_S))
        {
            array = LocalIndex(instructions[at - 1]);
        }

        while (at < instructions.Length)
        {
            var restart = at;
            if (!LoadsArray(instructions, ref at, array))
            {
                at = restart;
                break;
            }
            if (!TryReadInt32(instructions, ref at, out var slot) ||
                slot < 0 || slot >= parameters ||
                !Consume(instructions, ref at, Code.Ldarg, Code.Ldarg_0, Code.Ldarg_1, Code.Ldarg_2,
                    Code.Ldarg_3, Code.Ldarg_S))
            {
                return null;
            }
            if (ArgumentIndex(instructions[at - 1]) != slot)
                return null;
            Consume(instructions, ref at, Code.Box);
            if (!Consume(instructions, ref at, Code.Stelem_Ref, Code.Stelem))
                return null;
            stored[slot] = true;
        }

        if (!stored.All(item => item))
            return null;

        // The call carries which program to run. Everything between here and the return may only
        // move the result, never compute with it.
        var identifier = -1;
        IMethod? entry = null;
        while (at < instructions.Length)
        {
            var instruction = instructions[at];
            if (instruction.OpCode.Code == Code.Call || instruction.OpCode.Code == Code.Callvirt)
            {
                if (entry is not null || instruction.Operand is not IMethod called)
                    return null;
                entry = called;
                at++;
                continue;
            }
            if (entry is null)
            {
                if (TryReadInt32(instructions, ref at, out var constant))
                {
                    if (identifier >= 0)
                        return null;
                    identifier = constant;
                    continue;
                }
                if (LoadsArray(instructions, ref at, array) ||
                    Consume(instructions, ref at, Code.Ldnull, Code.Ldarg_0, Code.Ldloca,
                        Code.Ldloca_S, Code.Ldloc, Code.Ldloc_0, Code.Ldloc_1, Code.Ldloc_2,
                        Code.Ldloc_3, Code.Ldloc_S))
                {
                    continue;
                }
                return null;
            }
            if (Consume(instructions, ref at, Code.Pop, Code.Ret, Code.Castclass, Code.Unbox_Any,
                    Code.Ldelem_Ref, Code.Ldc_I4_0, Code.Ldc_I4, Code.Ldc_I4_S, Code.Stloc,
                    Code.Stloc_0, Code.Stloc_1, Code.Stloc_2, Code.Stloc_3, Code.Stloc_S,
                    Code.Ldloc, Code.Ldloc_0, Code.Ldloc_1, Code.Ldloc_2, Code.Ldloc_3,
                    Code.Ldloc_S))
            {
                continue;
            }
            return null;
        }

        return entry is not null && identifier >= 0
            ? new VirtualizedMethod(method, entry, identifier, parameters)
            : null;
    }

    private static bool LoadsArray(Instruction[] instructions, ref int at, int array)
    {
        if (at >= instructions.Length)
            return false;
        var instruction = instructions[at];
        if (array < 0)
        {
            if (instruction.OpCode.Code != Code.Dup)
                return false;
            at++;
            return true;
        }
        if (instruction.OpCode.Code is not (Code.Ldloc or Code.Ldloc_0 or Code.Ldloc_1 or
            Code.Ldloc_2 or Code.Ldloc_3 or Code.Ldloc_S))
        {
            return false;
        }
        if (LocalIndex(instruction) != array)
            return false;
        at++;
        return true;
    }

    private static bool Consume(Instruction[] instructions, ref int at, params Code[] allowed)
    {
        if (at >= instructions.Length || !allowed.Contains(instructions[at].OpCode.Code))
            return false;
        at++;
        return true;
    }

    private static bool TryReadInt32(Instruction[] instructions, ref int at, out int value)
    {
        value = 0;
        if (at >= instructions.Length)
            return false;
        var instruction = instructions[at];
        switch (instruction.OpCode.Code)
        {
            case Code.Ldc_I4:
                value = (int)instruction.Operand;
                break;
            case Code.Ldc_I4_S:
                value = (sbyte)instruction.Operand;
                break;
            case >= Code.Ldc_I4_0 and <= Code.Ldc_I4_8:
                value = instruction.OpCode.Code - Code.Ldc_I4_0;
                break;
            case Code.Ldc_I4_M1:
                value = -1;
                break;
            default:
                return false;
        }
        at++;
        return true;
    }

    private static int LocalIndex(Instruction instruction) => instruction.OpCode.Code switch
    {
        Code.Ldloc_0 or Code.Stloc_0 => 0,
        Code.Ldloc_1 or Code.Stloc_1 => 1,
        Code.Ldloc_2 or Code.Stloc_2 => 2,
        Code.Ldloc_3 or Code.Stloc_3 => 3,
        _ => instruction.Operand is Local local ? local.Index : -1
    };

    private static int ArgumentIndex(Instruction instruction) => instruction.OpCode.Code switch
    {
        Code.Ldarg_0 => 0,
        Code.Ldarg_1 => 1,
        Code.Ldarg_2 => 2,
        Code.Ldarg_3 => 3,
        _ => instruction.Operand is Parameter parameter ? parameter.Index : -1
    };
}
