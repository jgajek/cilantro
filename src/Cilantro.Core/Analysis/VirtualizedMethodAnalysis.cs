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
/// Somewhere the interpreter is asked to run one of its programs, and which program that is.
/// </summary>
/// <param name="Replaced">
/// Whether the whole of the calling method is this call, which is what makes it a stub whose body
/// can be built back. Where it is false the program is run as part of a method that does other
/// work, so the program is still there to be read but the method is not the program.
/// </param>
public sealed record VirtualInvocation(
    MethodDef Caller,
    Instruction Call,
    IMethod Entry,
    int ProgramId,
    bool Replaced);

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

    /// <summary>
    /// Every place the interpreter is asked to run a program, once one stub has shown which method
    /// the interpreter is entered by.
    /// </summary>
    /// <remarks>
    /// Matching the stub shape answers which methods are nothing but a program, and that is the
    /// question worth asking first, because only those methods can have a body built back into
    /// them. It is not the same question as which programs the file contains, and taking it for
    /// that under-reports: a protector is free to run a program from the middle of a method that
    /// does other work, and Reactor does, initializing the state its opaque predicates read from a
    /// program run by a static constructor. That call is wrapped in the same flattened control flow
    /// as everything else, so no shape match will ever find it.
    ///
    /// Once a single stub has been matched, the interpreter's entry is known, and then the calls to
    /// it can simply be counted. That needs nothing of the calling method's shape, which is the
    /// point: it finds the programs run from methods no shape describes. The entry has to be
    /// learned from a stub first, since what makes a method an interpreter is that something enters
    /// it that way.
    /// </remarks>
    public static IReadOnlyList<VirtualInvocation> Invocations(
        ModuleDef module,
        IReadOnlyList<VirtualizedMethod> stubs)
    {
        ArgumentNullException.ThrowIfNull(module);
        ArgumentNullException.ThrowIfNull(stubs);
        var entries = stubs
            .GroupBy(stub => stub.Entry.MDToken.Raw)
            .ToDictionary(group => group.Key, group => group.First().Entry);
        if (entries.Count == 0)
            return [];

        var replaced = stubs.Select(stub => stub.Stub).ToHashSet();
        var found = new List<VirtualInvocation>();
        foreach (var method in module.GetTypes().SelectMany(type => type.Methods))
        {
            if (!method.HasBody)
                continue;
            var instructions = method.Body.Instructions;
            for (var at = 0; at < instructions.Count; at++)
            {
                var call = instructions[at];
                if (call.OpCode.Code is not (Code.Call or Code.Callvirt) ||
                    call.Operand is not IMethod called ||
                    !entries.TryGetValue(called.MDToken.Raw, out var entry) ||
                    Identifier(instructions, at, called) is not { } program)
                {
                    continue;
                }
                found.Add(new VirtualInvocation(
                    method, call, entry, program, replaced.Contains(method)));
            }
        }
        return found
            .OrderBy(item => item.ProgramId)
            .ThenBy(item => item.Caller.MDToken.Raw)
            .ToArray();
    }

    /// <summary>
    /// Which program a call asks for, or <see langword="null"/> where the call site does not say so
    /// plainly that counting can tell.
    /// </summary>
    /// <remarks>
    /// Arguments are pushed in order, so the push belonging to the parameter that names the program
    /// can be found by counting back from the call. Only pushes that take nothing from the stack
    /// and leave one value on it are counted, because anything else breaks the correspondence
    /// between pushes counted and parameters passed, and a program number arrived at by guessing
    /// would be worse than admitting the call site was not read.
    /// </remarks>
    private static int? Identifier(IList<Instruction> instructions, int at, IMethod called)
    {
        if (called.MethodSig is not { } signature)
            return null;
        var offset = signature.HasThis ? 1 : 0;
        var slots = signature.Params.Count + offset;
        var naming = -1;
        for (var index = 0; index < signature.Params.Count; index++)
        {
            if (signature.Params[index].RemovePinnedAndModifiers()?.ElementType != ElementType.I4)
                continue;
            if (naming >= 0)
                return null;
            naming = index + offset;
        }
        if (naming < 0 || at < slots)
            return null;

        for (var slot = 0; slot < slots; slot++)
        {
            if (!Leaves(instructions[at - slots + slot]))
                return null;
        }
        var read = 0;
        return TryReadInt32([instructions[at - slots + naming]], ref read, out var value)
            ? value
            : null;
    }

    /// <summary>Whether this instruction takes nothing from the stack and leaves one thing on it.</summary>
    private static bool Leaves(Instruction instruction) =>
        instruction.IsLdcI4() ||
        instruction.OpCode.Code is Code.Ldnull or Code.Ldstr or Code.Ldc_I8 or Code.Ldc_R4 or
            Code.Ldc_R8 or Code.Ldtoken or Code.Ldftn or Code.Ldsfld or Code.Ldsflda or
            Code.Ldloc or Code.Ldloc_0 or Code.Ldloc_1 or Code.Ldloc_2 or Code.Ldloc_3 or
            Code.Ldloc_S or Code.Ldloca or Code.Ldloca_S or Code.Ldarg or Code.Ldarg_0 or
            Code.Ldarg_1 or Code.Ldarg_2 or Code.Ldarg_3 or Code.Ldarg_S or Code.Ldarga or
            Code.Ldarga_S;

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
