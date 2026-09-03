using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>What a method demonstrably does, read off its body rather than off its name.</summary>
/// <remarks>
/// A protector renames everything it generates, but it cannot rename the framework. Every obfuscated
/// assembly therefore still says <c>SymmetricAlgorithm.CreateDecryptor</c> and
/// <c>AssemblyName.GetPublicKeyToken</c> in full, because those names belong to references it does
/// not own. Those calls are the fixed points an analyst navigates by, and they are what this class
/// recovers: the framework members a body reaches, and the shape of the small forwarders Reactor
/// puts between the code and the framework so that neither the call nor the name is visible at the
/// site.
///
/// The forwarders matter more than their size suggests. Reactor's delegate proxies leave behind one
/// static method per framework member, each one a cast and a call, and after proxy restoration those
/// are what the recovered call sites point at. A body that reads as a hundred calls to
/// <c>generatedMethod_0101</c> is a body making a hundred calls to <c>CreateDecryptor</c>, and the
/// only thing standing between the reader and that fact is a name nobody chose.
/// </remarks>
internal static class MethodBehaviour
{
    /// <summary>How far to follow forwarders when collecting what a body reaches.</summary>
    private const int MaximumDepth = 4;

    /// <summary>A method whose body is one value, whatever it is asked.</summary>
    internal enum Constant
    {
        False,
        True,
        Null
    }

    /// <summary>What a body reaches, in the terms the assembly itself still spells out.</summary>
    internal sealed record Footprint(
        IReadOnlyList<string> Reaches,
        IReadOnlyList<string> Writes);

    /// <summary>
    /// Reads a method that answers the same thing every time, which is how Reactor writes an opaque
    /// predicate: a helper returning a constant, called where a condition belongs.
    /// </summary>
    internal static Constant? AsConstant(MethodDef method)
    {
        ArgumentNullException.ThrowIfNull(method);
        if (!method.HasBody || method.HasGenericParameters || method.Parameters.Count != 0)
            return null;

        var instructions = Significant(method);
        if (instructions.Length == 4 &&
            instructions[0].OpCode == OpCodes.Ldnull &&
            instructions[1].OpCode == OpCodes.Ldnull &&
            instructions[2].OpCode == OpCodes.Ceq &&
            instructions[3].OpCode == OpCodes.Ret)
        {
            return Constant.True;
        }

        if (instructions.Length == 2 && instructions[1].OpCode == OpCodes.Ret)
        {
            if (instructions[0].OpCode == OpCodes.Ldnull) return Constant.Null;
            if (instructions[0].OpCode == OpCodes.Ldc_I4_0) return Constant.False;
            if (instructions[0].OpCode == OpCodes.Ldc_I4_1) return Constant.True;
        }

        return null;
    }

    /// <summary>
    /// Reads a method that exists only to make one call on its arguments' behalf, and answers with
    /// the member it calls.
    /// </summary>
    /// <remarks>
    /// The accepted shape is deliberately narrow: loads of the arguments, whatever casting the
    /// signature's use of <see cref="object"/> forces, one call, and a return. Anything that
    /// computes, branches or touches state is not a forwarder and is not reported as one, because
    /// the whole value of the answer is that it is the method's entire behaviour and not a summary
    /// of part of it.
    /// </remarks>
    internal static bool TryReadForwarder(MethodDef method, out IMethod? called)
    {
        ArgumentNullException.ThrowIfNull(method);
        called = null;
        if (!method.HasBody)
            return false;

        var instructions = Significant(method);
        if (instructions.Length < 2 || instructions[^1].OpCode != OpCodes.Ret)
            return false;

        var call = instructions[^2];
        if (call.OpCode.Code is not (Code.Call or Code.Callvirt or Code.Newobj) ||
            call.Operand is not IMethod target)
        {
            return false;
        }

        for (var index = 0; index < instructions.Length - 2; index++)
        {
            if (!IsPrelude(instructions[index]))
                return false;
        }

        called = target;
        return true;
    }

    /// <summary>
    /// Collects the members a body reaches and the fields it writes, following the forwarders
    /// between it and the framework so that what it reaches is named rather than hidden.
    /// </summary>
    internal static Footprint Reached(MethodDef method, ModuleDef module)
    {
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(module);
        var reaches = new SortedSet<string>(StringComparer.Ordinal);
        var writes = new SortedSet<string>(StringComparer.Ordinal);
        var visited = new HashSet<uint>();
        Walk(method, module, reaches, writes, visited, MaximumDepth);
        return new Footprint([.. reaches], [.. writes]);
    }

    /// <summary>
    /// Names a member the way an analyst says it aloud: the declaring type and the member, without
    /// the namespace that only repeats what the type already implies.
    /// </summary>
    internal static string Describe(IMethod called)
    {
        ArgumentNullException.ThrowIfNull(called);
        var declaring = Simplify(called.DeclaringType?.Name ?? "?");
        var name = called.Name.String;
        return name == ".ctor" ? $"new {declaring}" : $"{declaring}.{name}";
    }

    /// <summary>Whether a member belongs to something other than the assembly being read.</summary>
    internal static bool IsForeign(IMemberRef member, ModuleDef module) =>
        member switch
        {
            MethodDef method => method.Module != module,
            FieldDef field => field.Module != module,
            _ => member.DeclaringType?.ResolveTypeDef()?.Module != module
        };

    private static void Walk(
        MethodDef method,
        ModuleDef module,
        SortedSet<string> reaches,
        SortedSet<string> writes,
        HashSet<uint> visited,
        int budget)
    {
        if (budget <= 0 || !method.HasBody || !visited.Add(method.MDToken.Raw))
            return;

        foreach (var instruction in method.Body.Instructions)
        {
            switch (instruction.Operand)
            {
                case IMethod called when instruction.OpCode.Code is
                    Code.Call or Code.Callvirt or Code.Newobj or Code.Ldftn or Code.Ldvirtftn:
                    Reach(called);
                    break;
                case IField written when instruction.OpCode.Code is Code.Stsfld or Code.Stfld:
                    writes.Add(Field(written));
                    break;
            }
        }

        void Reach(IMethod called)
        {
            // A call into the assembly itself names nothing a reader does not already have, so it is
            // followed rather than recorded: what is wanted is the framework member at the end of it.
            if (called is MethodDef local && local.Module == module)
            {
                Walk(local, module, reaches, writes, visited, budget - 1);
                return;
            }

            reaches.Add(Describe(called));
        }

        // A field of the assembly's own is named plainly: the reader is already looking at the type
        // that declares it, and repeating the type would say nothing. A foreign one needs both.
        string Field(IField field) => IsForeign(field, module)
            ? $"{Simplify(field.DeclaringType?.Name ?? "?")}.{field.Name.String}"
            : field.Name.String;
    }

    /// <summary>
    /// Whether an instruction only arranges what the call about to happen will consume.
    /// </summary>
    private static bool IsPrelude(Instruction instruction) =>
        instruction.OpCode.Code switch
        {
            Code.Ldarg or Code.Ldarg_S or Code.Ldarg_0 or Code.Ldarg_1 or Code.Ldarg_2 or
                Code.Ldarg_3 or Code.Ldarga or Code.Ldarga_S => true,
            Code.Castclass or Code.Unbox_Any or Code.Unbox or Code.Box or Code.Isinst => true,
            Code.Ldnull => true,
            _ => false
        };

    private static Instruction[] Significant(MethodDef method) =>
        [.. method.Body.Instructions.Where(instruction => instruction.OpCode != OpCodes.Nop)];

    /// <summary>Drops the arity marker generics leave on a type name.</summary>
    private static string Simplify(UTF8String? name)
    {
        var text = name?.String ?? "?";
        var tick = text.IndexOf('`', StringComparison.Ordinal);
        return tick < 0 ? text : text[..tick];
    }
}
