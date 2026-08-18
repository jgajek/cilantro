using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>
/// Decides which fields hold, for the whole life of the program, whatever value initialization left
/// in them.
/// </summary>
/// <remarks>
/// A value observed at the end of loader initialization is only a constant if nothing can overwrite
/// it later. That is a whole-module question, not a local one, so it is answered from the call graph
/// rather than from any single method. A writer is harmless in one of two ways: it can never run at
/// all, or it can only run inside the one-shot initialization window. The second case needs both
/// halves of the test, since a method called during initialization is only confined to it if nothing
/// outside can call it again.
///
/// Two escapes need separate handling. Taking a field's address hands out a location that can be
/// written through without any <c>stfld</c> naming the field, so an address-taken field is never
/// eligible. A reflective write names no field at all, so it is treated as a writer of every field
/// and judged by the same timing test: reflective writes confined to the one-shot initialization
/// window leave the conclusion intact, while one that can run afterwards could overwrite anything
/// and so refuses the whole analysis.
/// </remarks>
public sealed class FieldWriteSafety
{
    private readonly HashSet<uint> _writeOnce;

    private FieldWriteSafety(HashSet<uint> writeOnce, string? refusal)
    {
        _writeOnce = writeOnce;
        Refusal = refusal;
    }

    /// <summary>Why no field could be judged safe, or <see langword="null"/> if the analysis ran.</summary>
    public string? Refusal { get; }

    public bool IsWriteOnceDuringInitialization(uint fieldToken) => _writeOnce.Contains(fieldToken);

    public static FieldWriteSafety Analyze(ModuleDef module)
    {
        var methods = module.GetTypes().SelectMany(type => type.Methods).ToArray();
        var callees = new Dictionary<MethodDef, HashSet<MethodDef>>();
        var writers = new Dictionary<uint, HashSet<MethodDef>>();
        var addressTaken = new HashSet<uint>();
        var written = new HashSet<uint>();
        var reflectiveWriters = new HashSet<MethodDef>();

        foreach (var method in methods)
        {
            var reached = new HashSet<MethodDef>();
            callees[method] = reached;
            if (!method.HasBody)
                continue;
            foreach (var instruction in method.Body.Instructions)
            {
                if (IsReflectiveFieldWrite(instruction.Operand))
                    reflectiveWriters.Add(method);

                switch (instruction.OpCode.Code)
                {
                    case Code.Call or Code.Callvirt or Code.Newobj or Code.Ldftn or Code.Ldvirtftn
                        when instruction.Operand is IMethod called &&
                            called.ResolveMethodDef() is { } target:
                        reached.Add(target);
                        break;
                    case Code.Stfld or Code.Stsfld when instruction.Operand is IField stored:
                    {
                        var token = TokenOf(stored);
                        written.Add(token);
                        if (!writers.TryGetValue(token, out var bucket))
                            writers[token] = bucket = [];
                        bucket.Add(method);
                        break;
                    }
                    case Code.Ldflda or Code.Ldsflda when instruction.Operand is IField addressed:
                        addressTaken.Add(TokenOf(addressed));
                        break;
                }
            }
        }

        var closure = InitializationClosure(module, callees);
        var callableFromOutside = methods
            .Where(method => !closure.Contains(method))
            .SelectMany(method => callees[method])
            .ToHashSet();
        var reachability = ModuleReachability.Compute(module);

        var unbounded = reflectiveWriters
            .Where(writer => !CannotWriteAfterInitialization(writer))
            .Select(writer => writer.FullName)
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (unbounded.Length != 0)
        {
            return new FieldWriteSafety(
                [],
                $"{unbounded.Length} method(s) can write fields reflectively after initialization, " +
                $"so no field can be proven write-once, starting with {unbounded[0]}.");
        }

        // Restricting to fields no code outside the assembly can name keeps the conclusion narrow:
        // reflection is the one writer the call graph cannot see, and an externally invisible field
        // is out of reach of everything but this module's own reflection, which is bounded above.
        var invisible = module.GetTypes()
            .Where(type => !MemberVisibility.IsExternallyVisible(type))
            .SelectMany(type => type.Fields)
            .Select(field => field.MDToken.Raw)
            .ToHashSet();
        var safe = written
            .Where(token => invisible.Contains(token) &&
                !addressTaken.Contains(token) &&
                writers[token].All(CannotWriteAfterInitialization))
            .ToHashSet();
        return new FieldWriteSafety(safe, null);

        bool CannotWriteAfterInitialization(MethodDef writer) =>
            !reachability.IsReachable(writer) ||
            (closure.Contains(writer) && !callableFromOutside.Contains(writer));
    }

    /// <summary>
    /// Every method the runtime can run as part of type initialization.
    /// </summary>
    /// <remarks>
    /// Static constructors are the roots because the runtime runs each exactly once before its type
    /// is first used. Anything they reach transitively runs within that same one-shot window, which
    /// is what makes a write inside the closure a write that cannot repeat.
    /// </remarks>
    private static HashSet<MethodDef> InitializationClosure(
        ModuleDef module,
        Dictionary<MethodDef, HashSet<MethodDef>> callees)
    {
        var closure = new HashSet<MethodDef>();
        var pending = new Queue<MethodDef>();
        foreach (var type in module.GetTypes())
        {
            if (type.FindStaticConstructor() is { } initializer && closure.Add(initializer))
                pending.Enqueue(initializer);
        }

        while (pending.Count != 0)
        {
            foreach (var callee in callees.GetValueOrDefault(pending.Dequeue(), []))
            {
                if (closure.Add(callee))
                    pending.Enqueue(callee);
            }
        }
        return closure;
    }

    private static bool IsReflectiveFieldWrite(object? operand) =>
        operand is IMethod method &&
        (method.Name == "SetValue" || method.Name == "SetValueDirect") &&
        method.DeclaringType?.FullName is
            "System.Reflection.FieldInfo" or "System.Reflection.RtFieldInfo";

    private static uint TokenOf(IField field) =>
        field.ResolveFieldDef()?.MDToken.Raw ?? field.MDToken.Raw;
}
