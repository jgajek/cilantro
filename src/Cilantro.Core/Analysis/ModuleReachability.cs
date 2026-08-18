using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>
/// The set of methods the runtime can actually reach, computed conservatively from every way
/// execution can enter the module.
/// </summary>
/// <remarks>
/// Two later conclusions depend on knowing what cannot run. A field is only constant if no reachable
/// method writes it, and Reactor scaffolding is only removable if nothing reaches it. Both are
/// whole-module questions that a per-method walk cannot answer.
///
/// Every approximation here errs toward calling something reachable. Entry points, type
/// initializers, finalizers, and the assembly's externally visible surface are roots, because
/// callers outside the module are not in evidence. A virtual call marks every method in the module
/// that could satisfy it, matched by name and signature rather than by resolving the hierarchy, so
/// an unresolvable or unusual dispatch keeps candidates alive rather than dropping them. The cost of
/// each approximation is a smaller cleanup; the cost of the opposite choice would be deleting live
/// code.
///
/// Reachability here means the runtime can transfer control to the method without reflection.
/// Reflective invocation is reported separately as <see cref="ReflectivelyExposedTypes"/> rather
/// than folded in, because the two answer different questions. Whether a method can overwrite a
/// field depends on whether control reaches it, and merely handing a type to reflection does not
/// run anything; whether a method is safe to delete additionally depends on whether reflection can
/// name it, and that is what the exposed set is for.
/// </remarks>
public sealed class ModuleReachability
{
    private readonly HashSet<MethodDef> _reachable;
    private readonly HashSet<TypeDef> _reflectivelyExposed;

    private ModuleReachability(HashSet<MethodDef> reachable, HashSet<TypeDef> reflectivelyExposed)
    {
        _reachable = reachable;
        _reflectivelyExposed = reflectivelyExposed;
    }

    public IReadOnlyCollection<MethodDef> ReachableMethods => _reachable;

    /// <summary>
    /// Types whose handle reachable code takes, so reflection could name any of their members.
    /// </summary>
    public IReadOnlyCollection<TypeDef> ReflectivelyExposedTypes => _reflectivelyExposed;

    public bool IsReachable(MethodDef method) => _reachable.Contains(method);

    public bool IsReflectivelyExposed(TypeDef type) => _reflectivelyExposed.Contains(type);

    public static ModuleReachability Compute(ModuleDef module) =>
        Compute(module, typeInitializersAlwaysRun: true);

    /// <param name="typeInitializersAlwaysRun">
    /// Whether every type initializer counts as a root regardless of whether its type is used.
    /// </param>
    /// <param name="alsoRoots">
    /// Methods the caller knows to be entered for reasons the module does not show, which are
    /// treated as roots along with the ones it does.
    /// </param>
    /// <remarks>
    /// The runtime runs a type initializer before the first use of its type, so a type nothing
    /// touches never runs one. Modelling that turns a self-contained island of code into what it
    /// is, which is the difference between recognizing abandoned scaffolding and being unable to
    /// say anything about it. It is the less conservative reading, so callers ask for it
    /// explicitly, and only where the consequence of being wrong is bounded by other evidence.
    ///
    /// Roots the caller adds go the other way, toward keeping more. A method the tool put a body
    /// into is one the run means to be read, and nothing in the module has to call it for that to
    /// be true; naming it a root keeps it and everything its body reaches.
    /// </remarks>
    public static ModuleReachability Compute(
        ModuleDef module,
        bool typeInitializersAlwaysRun,
        IEnumerable<MethodDef>? alsoRoots = null)
    {
        var methods = module.GetTypes().SelectMany(type => type.Methods).ToArray();
        var candidatesBySignature = methods
            .Where(method => method.IsVirtual)
            .GroupBy(SignatureKey, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.Ordinal);

        var reachable = new HashSet<MethodDef>();
        var reflectivelyExposed = new HashSet<TypeDef>();
        var activated = new HashSet<TypeDef>();
        var pending = new Queue<MethodDef>();
        foreach (var root in Roots(module, methods, typeInitializersAlwaysRun)
                     .Concat(alsoRoots ?? []))
        {
            if (reachable.Add(root))
                pending.Enqueue(root);
        }

        while (pending.Count != 0)
        {
            var method = pending.Dequeue();
            if (!method.HasBody)
                continue;
            foreach (var instruction in method.Body.Instructions)
            {
                switch (instruction.Operand)
                {
                    case IMethod called when IsMethodReference(instruction):
                        Mark(called.ResolveMethodDef());
                        MarkVirtualCandidates(called);
                        break;
                    case IField field when IsStaticFieldAccess(instruction):
                        Activate(field.DeclaringType?.ScopeType?.ResolveTypeDef());
                        break;
                    case ITypeDefOrRef referenced when instruction.OpCode.Code == Code.Ldtoken:
                        if (referenced.ResolveTypeDef() is { } exposed)
                        {
                            reflectivelyExposed.Add(exposed);
                            Activate(exposed);
                        }
                        break;
                }
            }
        }
        return new ModuleReachability(reachable, reflectivelyExposed);

        void Mark(MethodDef? method)
        {
            if (method is null || !reachable.Add(method))
                return;
            pending.Enqueue(method);
            Activate(method.DeclaringType);
        }

        // Using a type is what makes the runtime run its initializer, so the initializer joins the
        // reachable set at that point rather than beforehand.
        void Activate(TypeDef? type)
        {
            while (type is not null && activated.Add(type))
            {
                Mark(type.FindStaticConstructor());
                type = type.DeclaringType;
            }
        }

        void MarkVirtualCandidates(IMethod called)
        {
            var resolved = called.ResolveMethodDef();
            if (resolved is not null && !resolved.IsVirtual)
                return;
            foreach (var candidate in
                     candidatesBySignature.GetValueOrDefault(SignatureKey(called), []))
            {
                Mark(candidate);
            }
        }
    }

    /// <summary>
    /// Everything execution can enter through without a call from inside the module.
    /// </summary>
    /// <remarks>
    /// The externally visible surface is a root unconditionally. For a library that is the whole
    /// point, and for an executable it costs only cleanup, since anything referencing the
    /// executable can call it.
    /// </remarks>
    private static IEnumerable<MethodDef> Roots(
        ModuleDef module, IReadOnlyList<MethodDef> methods, bool typeInitializersAlwaysRun)
    {
        if (module.EntryPoint is not null)
            yield return module.EntryPoint;
        // The module initializer is the one the runtime runs unconditionally, before anything else.
        if (module.GlobalType?.FindStaticConstructor() is { } moduleInitializer)
            yield return moduleInitializer;
        foreach (var method in methods)
        {
            // Finalizers are invoked by the runtime, and an explicit interface implementation is
            // invoked through the interface rather than by name.
            if ((typeInitializersAlwaysRun && method.IsStaticConstructor) ||
                (method.Name == "Finalize" && method.MethodSig?.Params.Count == 0) ||
                method.HasOverrides ||
                MemberVisibility.IsExternallyVisible(method))
            {
                yield return method;
            }
        }
    }

    private static bool IsStaticFieldAccess(Instruction instruction) =>
        instruction.OpCode.Code is Code.Ldsfld or Code.Stsfld or Code.Ldsflda;

    private static bool IsMethodReference(Instruction instruction) =>
        instruction.OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj or
            Code.Ldftn or Code.Ldvirtftn or Code.Ldtoken or Code.Jmp;

    private static string SignatureKey(IMethod method) =>
        $"{method.Name}|{method.MethodSig?.Params.Count ?? -1}|{method.MethodSig?.RetType?.FullName}";
}
