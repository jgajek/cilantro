using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>
/// Finds the static fields no instruction in the module writes, which therefore still hold the zero
/// or null the runtime put in them.
/// </summary>
/// <remarks>
/// This is a different question from the one <see cref="FieldWriteSafety"/> answers, and the
/// difference is the point of asking it. Interpreting the loader and finding no write is absence of
/// evidence: the interpretation may simply not have reached one, and reading a zero out of that
/// would be inventing a value, which is exactly why the capture refuses to. Searching the whole
/// module for an instruction that writes the field and finding that none exists is evidence of
/// absence. The runtime zeroes a static field before anything can observe it, so if nothing ever
/// changes it, every read of it answers that zero, and that holds for the whole run rather than for
/// a window.
///
/// A protector is why it is worth proving. Reactor declares a singleton it never assigns and then
/// guards flattened control flow on fields reached through it, so each guard either compares a
/// reference against the null it certainly holds, or dereferences that null and throws. Both are
/// decidable once the field is, and until then the state machine wrapped around them is not: the
/// jumps can be made direct one at a time, but no whole-method proof closes, and the method stays a
/// switch in a loop.
///
/// What could write a field without naming it decides the shape of the proof, and searching for
/// <c>stfld</c> is only worth anything once every such route is closed. Three are closed per field,
/// by refusing the fields they could reach: a field whose address is taken can be written through
/// that address, a field anything outside the assembly can see can be written by code that is not
/// here to be examined, and a field of a type whose handle reachable code takes can be named by
/// reflection. Fields holding initial data in the image, and literals, were written by the compiler
/// and are not unwritten at all.
///
/// Two routes cannot be closed per field and so refuse the whole question, which on a protected
/// module is the usual answer. A reflective write names no field, and code the program generates
/// while it runs is not in the module to be searched — a module that reaches
/// <c>System.Reflection.Emit</c> can build a setter for anything. Reactor does exactly this, and
/// not incidentally: its interpreter writes fields through generated code, so the state its opaque
/// predicates read is assigned by a virtualized method rather than by any instruction here. That is
/// worth saying plainly in the report, because it is also the reason those predicates cannot be
/// folded until the virtualized method that assigns them has been read back.
///
/// What is left is still a reading rather than a proof: the module is searched as it stands, and a
/// pass that has not run yet may still put a write into it. A strict run does not draw it.
/// </remarks>
public sealed class UnwrittenFields
{
    private readonly HashSet<uint> _unwritten;

    private UnwrittenFields(HashSet<uint> unwritten, string? refusal)
    {
        _unwritten = unwritten;
        Refusal = refusal;
    }

    /// <summary>How many static fields hold what the runtime left in them.</summary>
    public int Count => _unwritten.Count;

    /// <summary>
    /// Why no field could be read as unwritten, or <see langword="null"/> if the search ran. A
    /// module that can write a field without naming it refuses the question rather than answering
    /// it narrowly, there being no field the unnamed write could not have been to.
    /// </summary>
    public string? Refusal { get; }

    /// <summary>Whether this field still holds the value the runtime gave it.</summary>
    public bool Holds(IField? field) =>
        field is not null && _unwritten.Contains(TokenOf(field));

    public static UnwrittenFields Prove(ModuleDef module)
    {
        ArgumentNullException.ThrowIfNull(module);

        var written = new HashSet<uint>();
        var addressTaken = new HashSet<uint>();
        var reachability = ModuleReachability.Compute(module);
        string? unnamed = null;

        foreach (var method in module.GetTypes().SelectMany(type => type.Methods))
        {
            if (!method.HasBody)
                continue;
            foreach (var instruction in method.Body.Instructions)
            {
                switch (instruction.OpCode.Code)
                {
                    case Code.Stfld or Code.Stsfld when instruction.Operand is IField stored:
                        written.Add(TokenOf(stored));
                        break;
                    case Code.Ldflda or Code.Ldsflda when instruction.Operand is IField addressed:
                        addressTaken.Add(TokenOf(addressed));
                        break;
                    default:
                        if (unnamed is null &&
                            WritesWithoutNaming(instruction.Operand) is { } how &&
                            reachability.IsReachable(method))
                        {
                            unnamed = $"{how}, reached from {method.FullName}";
                        }
                        break;
                }
            }
        }

        if (unnamed is not null)
        {
            return new UnwrittenFields(
                [],
                $"This module can write a field without naming one: {unnamed}. No field it " +
                "declares can be read as holding what the runtime left in it, whatever the " +
                "search for writes to it finds.");
        }

        var unwritten = module.GetTypes()
            .Where(type => !MemberVisibility.IsExternallyVisible(type) &&
                !reachability.IsReflectivelyExposed(type))
            .SelectMany(type => type.Fields)
            .Where(field => field.IsStatic &&
                !field.HasFieldRVA &&
                !field.IsLiteral &&
                !field.HasConstant &&
                !written.Contains(field.MDToken.Raw) &&
                !addressTaken.Contains(field.MDToken.Raw))
            .Select(field => field.MDToken.Raw)
            .ToHashSet();

        return new UnwrittenFields(unwritten, null);
    }

    /// <summary>
    /// How this operand lets the program write a field the module never names, or
    /// <see langword="null"/> if it does not.
    /// </summary>
    /// <remarks>
    /// A reflective write names its field at run time, out of a string or a token the search cannot
    /// follow. Emitting code is worse than that and subsumes it: a method built while the program
    /// runs is not in the module at all, so it can carry any store to any field, and a module that
    /// builds one has put every field it declares beyond this kind of reading. Reactor's
    /// interpreter is built this way, which is why the answer here is usually that there is none.
    /// </remarks>
    private static string? WritesWithoutNaming(object? operand)
    {
        if (operand is not IMethod method)
            return null;
        var declaring = method.DeclaringType?.FullName;
        if ((method.Name == "SetValue" || method.Name == "SetValueDirect") &&
            declaring is "System.Reflection.FieldInfo" or "System.Reflection.RtFieldInfo")
        {
            return $"it writes fields reflectively, through {declaring}::{method.Name}";
        }
        if (declaring is not null && declaring.StartsWith("System.Reflection.Emit.", StringComparison.Ordinal))
        {
            return $"it builds code while it runs, through {declaring}::{method.Name}";
        }
        return null;
    }

    private static uint TokenOf(IField field) =>
        field.ResolveFieldDef()?.MDToken.Raw ?? field.MDToken.Raw;
}
