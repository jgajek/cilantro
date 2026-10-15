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
/// The walk reads only this module's bodies, and a reference leaving it counts as unresolvable even
/// on a machine that could resolve it. A reference into another assembly finds a body, or finds
/// nothing, according to what happens to be installed where the reading is done; following it would
/// let the framework on that machine decide what this module keeps, and the same file would clean up
/// differently on two desks. Reading past the edge is no more informative than stopping at it,
/// because a framework body that calls something of a shape this module also declares says nothing
/// about this module — so the boundary costs only the pretence of knowing.
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

    private ModuleReachability(
        HashSet<MethodDef> reachable,
        HashSet<TypeDef> reflectivelyExposed,
        string? refusal = null)
    {
        _reachable = reachable;
        _reflectivelyExposed = reflectivelyExposed;
        InstanceRefusal = refusal;
    }

    /// <summary>
    /// Why a virtual method was kept without an instance of its type to call it on, or
    /// <see langword="null"/> where none was asked for or the question was answered.
    /// </summary>
    /// <remarks>
    /// Only set where a caller asked for the narrower reading and the module would not support it.
    /// A caller that did not ask gets <see langword="null"/> and the wider reading, which is what
    /// it wanted.
    /// </remarks>
    public string? InstanceRefusal { get; }

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
        IEnumerable<MethodDef>? alsoRoots = null) =>
        Walk(module, typeInitializersAlwaysRun, alsoRoots, virtualsNeedAnInstance: false);

    /// <summary>
    /// The same, but keeping a virtual method only where an instance of its type can exist.
    /// </summary>
    /// <remarks>
    /// A virtual call is matched to candidates by name and signature, which keeps alive every
    /// method in the module that could satisfy a call of that shape. For ordinary code that costs
    /// little. For a protector's interpreter it costs everything: its types are only ever
    /// constructed by its own code, so once nothing reaches that code nothing constructs them — and
    /// yet their virtual methods go on matching signatures that surviving code calls, and the whole
    /// interpreter is held alive by calls that could never arrive at it.
    ///
    /// So a candidate is kept only once something reachable can make an instance of the type
    /// declaring it, which is what a virtual call needs to arrive. Making one is reaching a
    /// <c>newobj</c> of it, or of anything derived from it, or taking its handle, or its being
    /// visible outside the assembly; and this is a fixed point, since constructing a type reaches
    /// its methods and those may construct more.
    ///
    /// The reading is only taken where the module cannot get behind it, and the reachable reading
    /// decides that: where anything it reaches can make an instance without naming its type, there
    /// is no type the unnamed instance could not be of, and the narrower reading is refused whole.
    /// <see cref="InstanceRefusal"/> says why.
    /// </remarks>
    public static ModuleReachability ComputeWithInstances(
        ModuleDef module,
        bool typeInitializersAlwaysRun,
        IEnumerable<MethodDef>? alsoRoots = null)
    {
        ArgumentNullException.ThrowIfNull(module);
        var roots = alsoRoots?.ToArray() ?? [];
        var narrower = Walk(module, typeInitializersAlwaysRun, roots, virtualsNeedAnInstance: true);
        // A reflective constructor inside an uninstantiated type cannot bootstrap its
        // own receiver. Inspect the reachable fixed point, then fall back if something
        // in that graph can actually introduce instances without naming their types.
        if (UnnamedReach(module, narrower) is not { } refusal) return narrower;
        var wider = Walk(module, typeInitializersAlwaysRun, roots, virtualsNeedAnInstance: false);
        return new ModuleReachability(wider._reachable, wider._reflectivelyExposed, refusal);
    }

    /// <summary>
    /// How the module could make an instance of a type its own code does not name, or
    /// <see langword="null"/> where every instance it can make is of a type it names.
    /// </summary>
    /// <remarks>
    /// Only what the instance-aware fixed point reaches is asked about. A module may carry a reflective
    /// constructor the protector abandoned — these files do — and an abandoned one makes nothing.
    ///
    /// Invoking a method reflectively is deliberately not a reason to refuse, though it does run a
    /// body this reading cannot follow. The body is either this module's, in which case deleting it
    /// on the strength of being unreachable is a risk this pass already takes wherever it deletes
    /// anything at all, or another assembly's, in which case what it can reach of this one is
    /// governed by what is visible outside it and what has been handed to reflection — both of
    /// which are already asked. Refusing here on a ground the surrounding deletion does not apply
    /// would be stricter about which methods a type keeps than about whether the type survives.
    ///
    /// Building code while it runs is a reason, but only once that code can be entered. The
    /// protector generates thunks to fill the delegate fields of its proxies, and a thunk could
    /// hold a construction this module never names. Once the proxies are resolved to direct calls
    /// nothing reachable invokes those delegates, so no thunk can run; where one still could, both
    /// halves of the second clause hold and the reading is refused.
    /// </remarks>
    private static string? UnnamedReach(ModuleDef module, ModuleReachability wider)
    {
        var delegates = module.GetTypes()
            .Where(type => type.BaseType?.FullName is
                "System.MulticastDelegate" or "System.Delegate")
            .Select(type => type.FullName)
            .ToHashSet(StringComparer.Ordinal);

        string? builds = null;
        string? enters = null;
        foreach (var method in wider._reachable.Where(method => method.HasBody))
        {
            var body = method.Body.Instructions;
            for (var at = 0; at < body.Count; at++)
            {
                if (body[at].Operand is not IMethod called ||
                    called.DeclaringType?.FullName is not { } owner)
                {
                    continue;
                }
                var name = called.Name.String;
                if (Constructs(owner, name) && !NamesWhatItMakes(module, method, at))
                {
                    return "it can make an instance without naming its type, through " +
                        $"{owner}::{name} reached from {method.FullName}";
                }
                if (owner.StartsWith("System.Reflection.Emit.", StringComparison.Ordinal))
                    builds ??= $"{owner}::{name} reached from {method.FullName}";
                if (name == "Invoke" && delegates.Contains(owner))
                    enters ??= $"{owner}::{name} called from {method.FullName}";
            }
        }

        return builds is not null && enters is not null
            ? $"it builds code while it runs, at {builds}, and can enter such code, at {enters}, " +
                "so what it builds could make an instance of anything"
            : null;

        static bool Constructs(string owner, string name) => (owner, name) switch
        {
            ("System.Activator", "CreateInstance" or "CreateInstanceFrom") => true,
            ("System.AppDomain", "CreateInstance" or "CreateInstanceAndUnwrap" or
                "CreateInstanceFrom" or "CreateInstanceFromAndUnwrap") => true,
            ("System.Reflection.Assembly", "CreateInstance") => true,
            ("System.Reflection.ConstructorInfo" or "System.Reflection.RtCtorInfo", "Invoke") => true,
            ("System.Runtime.Serialization.FormatterServices", "GetUninitializedObject") => true,
            ("System.Runtime.CompilerServices.RuntimeHelpers", "GetUninitializedObject") => true,
            _ => false
        };
    }

    /// <summary>
    /// Whether a reflective construction says at the call site what it makes, so it makes nothing
    /// this reading has not already allowed for.
    /// </summary>
    /// <remarks>
    /// A type token, including a finite set carried through local assignments, names the type.
    /// Taking that token has already
    /// put the type among those an instance can exist of, so the construction adds nothing. One
    /// handed an assembly name and a type name as literals names both, and where the assembly is
    /// not this one it makes nothing declared here at all — these files reach for a cipher out of
    /// the framework that way, naming it in full, and that is no reason to give up the reading.
    ///
    /// Anything else is a construction whose type is decided by a value, and a value could be any
    /// type. There is no middle answer to give about it.
    /// </remarks>
    private static bool NamesWhatItMakes(ModuleDef module, MethodDef method, int at)
    {
        var body = method.Body.Instructions;
        var entries = body.SelectMany(i => i.Operand switch
        {
            Instruction target => new[] { target },
            IList<Instruction> many => many,
            _ => Array.Empty<Instruction>()
        }).ToHashSet();
        foreach (var handler in method.Body.ExceptionHandlers)
            foreach (var boundary in new[] { handler.TryStart, handler.TryEnd, handler.HandlerStart, handler.HandlerEnd, handler.FilterStart })
                if (boundary is not null) entries.Add(boundary);
        if (entries.Contains(body[at])) return false;
        if (body[at].Operand is not IMethod called || called.MethodSig?.Params is not { } parameters)
            return false;
        if (parameters is [{ FullName: "System.Type" }])
        {
            return NamedType(at - 1, new HashSet<Local>(), 0);
        }
        if (parameters is [{ FullName: "System.String" }, { FullName: "System.String" }] &&
            at >= 2 &&
            body[at - 2].Operand is string assembly &&
            body[at - 1].Operand is string)
        {
            var ours = module.Assembly?.Name.String;
            return ours is not null &&
                !assembly.StartsWith(ours, StringComparison.OrdinalIgnoreCase);
        }
        return false;

        bool FixedType(MethodDef? helper, HashSet<MethodDef> seen)
        {
            if (helper is not { IsStatic: true, HasBody: true } || helper.Module != module ||
                helper.HasGenericParameters || helper.DeclaringType.HasGenericParameters ||
                helper.MethodSig.Params.Count != 0 || helper.ReturnType.FullName != "System.Type" ||
                helper.Body.ExceptionHandlers.Count != 0 || seen.Count >= 8 || !seen.Add(helper)) return false;
            var il = helper.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
            if (il.Length == 3 && il[0].OpCode.Code == Code.Ldtoken && il[0].Operand is ITypeDefOrRef &&
                il[1].OpCode.Code == Code.Call && il[1].Operand is IMethod
                { DeclaringType.FullName: "System.Type", Name.String: "GetTypeFromHandle" } &&
                il[2].OpCode.Code == Code.Ret) return true;
            return il.Length == 2 && il[0].OpCode.Code == Code.Call && il[0].Operand is IMethod next &&
                il[1].OpCode.Code == Code.Ret && FixedType(next.ResolveMethodDef(), seen);
        }

        bool NamedType(int index, HashSet<Local> visited, int depth)
        {
            if (index < 0 || depth > 8) return false;
            while (index >= 0 && body[index].OpCode.Code == Code.Nop)
            { if (entries.Contains(body[index])) return false; index--; }
            if (index < 0) return false;
            if (body[index].OpCode.Code == Code.Ldnull) return true;
            if (index >= 1 && !entries.Contains(body[index]) && body[index].OpCode.Code == Code.Call &&
                body[index].Operand is IMethod { DeclaringType.FullName: "System.Type", Name.String: "GetTypeFromHandle" } &&
                body[index - 1].OpCode.Code == Code.Ldtoken && body[index - 1].Operand is ITypeDefOrRef) return true;
            if (body[index].OpCode.Code == Code.Call && body[index].Operand is IMethod helper &&
                FixedType(helper.ResolveMethodDef(), new HashSet<MethodDef>())) return true;
            if (!body[index].IsLdloc() || body[index].GetLocal(method.Body.Variables) is not { } local || !visited.Add(local)) return false;
            if (body.Any(i => i.OpCode.Code is Code.Ldloca or Code.Ldloca_S && i.GetLocal(method.Body.Variables) == local)) return false;
            var stores = body.Select((i, n) => (i, n)).Where(x => x.i.IsStloc() && x.i.GetLocal(method.Body.Variables) == local).ToArray();
            // A local assigned only known tokens can hold one of those or its initial null value;
            // neither permits constructing a different type. The token itself already
            // makes that exact type reflectively exposed in the ordinary reachability walk.
            return stores.Length is > 0 and <= 8 && stores.All(store => !entries.Contains(store.i) &&
                NamedType(store.n - 1, new HashSet<Local>(visited), depth + 1));
        }
    }

    private static ModuleReachability Walk(
        ModuleDef module,
        bool typeInitializersAlwaysRun,
        IEnumerable<MethodDef>? alsoRoots,
        bool virtualsNeedAnInstance)
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

        // Types an instance of which can exist, and the candidates waiting on one. A type visible
        // outside the assembly starts constructed: code that references this one can make it.
        var constructed = new HashSet<TypeDef>();
        var waiting = new Dictionary<TypeDef, List<MethodDef>>();
        if (virtualsNeedAnInstance)
        {
            foreach (var type in module.GetTypes().Where(MemberVisibility.IsExternallyVisible))
                Construct(type);
        }

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
            for (var index = 0; index < method.Body.Instructions.Count; index++)
            {
                var instruction = method.Body.Instructions[index];
                switch (instruction.Operand)
                {
                    case IMethod called when IsMethodReference(instruction):
                        Mark(Own(called));
                        MarkVirtualCandidates(called);
                        break;
                    case IField field when IsStaticFieldAccess(instruction):
                        Activate(OwnType(field.DeclaringType?.ScopeType));
                        break;
                    case ITypeDefOrRef referenced when instruction.OpCode.Code == Code.Ldtoken:
                        if (OwnType(referenced) is { } exposed)
                        {
                            // typeof(T).Assembly consumes the type without exposing its
                            // members or permitting construction of T. Keep T's ordinary
                            // metadata reference, but do not invent a reflective caller.
                            if (IsAssemblyOnlyHandle(method, index) || IsBinderContextHandle(method, index) ||
                                TypeIdentityHandleUse.IsClosed(method, index)) break;
                            // RunClassConstructor consumes this handle and activates only
                            // the static initializer. It neither returns the type nor makes
                            // an instance or a reflective caller of its ordinary methods.
                            if (IsInitializerOnlyHandle(method, index))
                            {
                                Activate(exposed);
                                break;
                            }
                            reflectivelyExposed.Add(exposed);
                            Activate(exposed);
                            // Reflection given a type can construct it, so a handle taken is an
                            // instance that can exist.
                            Construct(exposed);
                        }
                        break;
                }

                if (virtualsNeedAnInstance)
                    Construct(Made(instruction));
            }
        }
        return new ModuleReachability(reachable, reflectivelyExposed);

        // A type is constructed along with every type it inherits from, an inherited virtual being
        // entered on an instance of the derived type without the base one ever being made.
        void Construct(TypeDef? type)
        {
            while (type is not null && constructed.Add(type))
            {
                if (waiting.Remove(type, out var held))
                {
                    foreach (var candidate in held)
                        Mark(candidate);
                }
                type = OwnType(type.BaseType);
            }
        }

        // The type an instruction can leave an instance of, where it leaves one. A new array is not
        // one: it holds references to its element type and creates none.
        TypeDef? Made(Instruction instruction) => instruction.OpCode.Code switch
        {
            Code.Newobj when instruction.Operand is IMethod constructor =>
                OwnType(constructor.DeclaringType),
            Code.Initobj or Code.Box when instruction.Operand is ITypeDefOrRef made =>
                OwnType(made),
            _ => null
        };

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
                type = OwnType(type.DeclaringType);
            }
        }

        void MarkVirtualCandidates(IMethod called)
        {
            var resolved = Own(called);
            if (resolved is not null && !resolved.IsVirtual)
                return;
            foreach (var candidate in
                     candidatesBySignature.GetValueOrDefault(SignatureKey(called), []))
            {
                // Runtime delegate invocation slots belong to their exact sealed
                // delegate type. An unrelated delegate with the same signature
                // cannot implement that slot, even when instance creation is unknown.
                if (DistinctRuntimeDelegateSlot(called, candidate)) continue;
                // A call of this shape could arrive here, but only on an instance of the type
                // declaring it. Where none can exist yet the candidate waits for one, and is
                // marked if one ever can.
                if (!virtualsNeedAnInstance ||
                    candidate.DeclaringType is not { } declaring ||
                    constructed.Contains(declaring))
                {
                    Mark(candidate);
                    continue;
                }
                var held = waiting.TryGetValue(declaring, out var known) ? known : waiting[declaring] = [];
                held.Add(candidate);
            }
        }

        MethodDef? Own(IMethod reference) =>
            reference.ResolveMethodDef() is { } definition && definition.Module == module
                ? definition
                : null;

        TypeDef? OwnType(ITypeDefOrRef? reference) =>
            reference?.ResolveTypeDef() is { } definition && definition.Module == module
                ? definition
                : null;
    }

    private static bool DistinctRuntimeDelegateSlot(IMethod called, MethodDef candidate)
    {
        var owner = candidate.DeclaringType;
        if (!candidate.IsRuntime || !candidate.IsVirtual || !candidate.IsNewSlot || candidate.IsStatic ||
            candidate.HasGenericParameters || candidate.Overrides.Count != 0 ||
            candidate.Name.String is not ("Invoke" or "BeginInvoke" or "EndInvoke") ||
            !owner.IsSealed || owner.HasGenericParameters || owner.Interfaces.Count != 0 ||
            owner.BaseType is not TypeRef baseType || baseType.FullName != "System.MulticastDelegate" ||
            baseType.DefinitionAssembly?.Name.String is not ("mscorlib" or "System.Private.CoreLib")) return false;
        var calledOwner = called.DeclaringType;
        if (calledOwner is TypeSpec specification)
        {
            if (specification.TypeSig is not GenericInstSig instance) return false;
            calledOwner = instance.GenericType.TypeDefOrRef;
        }
        return calledOwner is not null && !new SigComparer().Equals(owner, calledOwner);
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

    private static bool IsInitializerOnlyHandle(MethodDef method, int index)
    {
        var body = method.Body.Instructions;
        return index + 1 < body.Count && body[index + 1] is { OpCode.Code: Code.Call, Operand: IMethod called } &&
            called.Name == "RunClassConstructor" && called.DeclaringType is TypeRef reference &&
            reference.FullName == "System.Runtime.CompilerServices.RuntimeHelpers" &&
            reference.DefinitionAssembly?.Name.String is "mscorlib" or "System.Private.CoreLib" or "System.Runtime" &&
            called.MethodSig is { HasThis: false, GenParamCount: 0 } signature &&
            signature.RetType.ElementType == ElementType.Void && signature.Params.Count == 1 &&
            signature.Params[0].FullName == "System.RuntimeTypeHandle";
    }

    private static bool IsBinderContextHandle(MethodDef method, int index)
    {
        var il = method.Body.Instructions;
        var at = index + 1;
        while (at < il.Count && il[at].OpCode.Code == Code.Nop) at++;
        if (at >= il.Count || il[at].OpCode.Code != Code.Call || il[at].Operand is not IMethod
            { FullName: "System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)", DeclaringType: TypeRef type } ||
            type.DefinitionAssembly?.Name.String is not ("mscorlib" or "System.Private.CoreLib" or "System.Runtime")) return false;
        var depth = 0;
        for (at++; at < il.Count && at <= index + 128; at++)
        {
            var instruction = il[at];
            if (instruction.OpCode.Code == Code.Nop) continue;
            if (instruction.OpCode.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch or FlowControl.Return or FlowControl.Throw) return false;
            if (instruction.OpCode.Code == Code.Dup && depth == 0) return false;
            if (depth == 0 && instruction.OpCode.Code == Code.Castclass &&
                instruction.Operand is TypeRef { FullName: "System.Type" } cast &&
                cast.DefinitionAssembly?.Name.String is "mscorlib" or "System.Private.CoreLib" or "System.Runtime") continue;
            instruction.CalculateStackUsage(out var pushes, out var pops);
            if (pops < 0) return false;
            if (pops <= depth) { depth += pushes - pops; continue; }
            if (instruction.OpCode.Code != Code.Call || instruction.Operand is not IMethod called ||
                called.DeclaringType is not TypeRef { FullName: "Microsoft.CSharp.RuntimeBinder.Binder" } binder ||
                binder.DefinitionAssembly?.Name.String != "Microsoft.CSharp" ||
                called.MethodSig is not { HasThis: false, GenParamCount: 0 } signature ||
                signature.GetCallingConvention() != CallingConvention.Default ||
                signature.RetType.FullName != "System.Runtime.CompilerServices.CallSiteBinder") return false;
            string[] parameters = called.Name.String switch
            {
                "Convert" => ["Microsoft.CSharp.RuntimeBinder.CSharpBinderFlags", "System.Type", "System.Type"],
                "UnaryOperation" or "BinaryOperation" => ["Microsoft.CSharp.RuntimeBinder.CSharpBinderFlags", "System.Linq.Expressions.ExpressionType", "System.Type", "System.Collections.Generic.IEnumerable`1<Microsoft.CSharp.RuntimeBinder.CSharpArgumentInfo>"],
                "GetIndex" => ["Microsoft.CSharp.RuntimeBinder.CSharpBinderFlags", "System.Type", "System.Collections.Generic.IEnumerable`1<Microsoft.CSharp.RuntimeBinder.CSharpArgumentInfo>"],
                _ => []
            };
            var contextParameter = called.Name == "GetIndex" ? 1 : 2;
            if (!signature.Params.Select(p => p.FullName).SequenceEqual(parameters) ||
                signature.Params.Count - 1 - depth != contextParameter) return false;
            // The handle reaches only the binder's lexical access context, not
            // its conversion target or a dynamic receiver. Reject alternate
            // entries that could invalidate the linear stack provenance.
            var interior = il.Skip(index + 1).Take(at - index).ToHashSet();
            return !il.Any(i => i.Operand is Instruction target && interior.Contains(target) ||
                    i.Operand is IList<Instruction> targets && targets.Any(interior.Contains)) &&
                !method.Body.ExceptionHandlers.Any(h => new[] { h.TryStart, h.TryEnd, h.HandlerStart, h.HandlerEnd, h.FilterStart }
                    .OfType<Instruction>().Any(interior.Contains));
        }
        return false;
    }

    private static bool IsAssemblyOnlyHandle(MethodDef method, int index)
    {
        var il = method.Body.Instructions;
        var next = index + 1;
        void SkipNops() { while (next < il.Count && il[next].OpCode.Code == Code.Nop) next++; }
        SkipNops();
        if (next >= il.Count || il[next].OpCode.Code != Code.Call || il[next].Operand is not IMethod
            { FullName: "System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)" }) return false;
        next++;
        SkipNops();
        if (AssemblyEnd(next) is var end && end >= 0) return Linear(index + 1, end);
        // Rebuilt stack slots can spill the Type to a local. Accept only a local
        // whose every read consumes it solely as an assembly lookup, with no address
        // escape. This is deliberately independent of reaching-definition guesses.
        if (next >= il.Count || !il[next].IsStloc() ||
            il[next].GetLocal(method.Body.Variables) is not { } local || !Linear(index + 1, next)) return false;
        var reads = 0;
        for (var at = 0; at < il.Count; at++)
        {
            if (il[at].GetLocal(method.Body.Variables) != local) continue;
            if (il[at].OpCode.Code is Code.Ldloca or Code.Ldloca_S) return false;
            if (!il[at].IsLdloc()) continue;
            reads++;
            var consumed = AssemblyEnd(at + 1);
            if (consumed < 0 || !Linear(at + 1, consumed)) return false;
        }
        return reads != 0;

        int AssemblyEnd(int at)
        {
            while (at < il.Count && il[at].OpCode.Code == Code.Nop) at++;
            // Proxy argument narrowing can leave a redundant cast on the known Type result.
            if (at < il.Count && il[at].OpCode.Code == Code.Castclass &&
                il[at].Operand is ITypeDefOrRef { FullName: "System.Type" }) at++;
            while (at < il.Count && il[at].OpCode.Code == Code.Nop) at++;
            if (at < il.Count && il[at] is { OpCode.Code: Code.Call, Operand: MethodDef wrapper } &&
                IsAssemblyOnlyWrapper(wrapper, method.Module)) return at;
            return at < il.Count && il[at].OpCode.Code is Code.Call or Code.Callvirt &&
                il[at].Operand is IMethod
                { FullName: "System.Reflection.Assembly System.Type::get_Assembly()" } ? at : -1;
        }

        bool Linear(int first, int last)
        {
            var interior = il.Skip(first).Take(last - first + 1).ToHashSet();
            bool Interior(Instruction? instruction) => instruction is not null && interior.Contains(instruction);
            return !il.Any(i => i.Operand is Instruction target && Interior(target) ||
                    i.Operand is IList<Instruction> targets && targets.Any(Interior)) &&
                !method.Body.ExceptionHandlers.Any(h => Interior(h.TryStart) || Interior(h.TryEnd) ||
                    Interior(h.HandlerStart) || Interior(h.HandlerEnd) || Interior(h.FilterStart));
        }
    }

    // A local compatibility wrapper may route typeof(T).Assembly through TypeInfo.
    // Inspect its entire body: names alone cannot establish non-exposure.
    private static bool IsAssemblyOnlyWrapper(MethodDef wrapper, ModuleDef module)
    {
        if (wrapper.Module != module || !wrapper.IsStatic || wrapper.IsConstructor || wrapper.IsVirtual ||
            wrapper.HasGenericParameters || wrapper.DeclaringType.HasGenericParameters || !wrapper.HasBody ||
            wrapper.Body.HasExceptionHandlers || wrapper.MethodSig is not { HasThis: false, GenParamCount: 0 } sig ||
            sig.Params.Count != 1 || sig.Params[0].FullName != "System.Type" ||
            sig.RetType.FullName != "System.Reflection.Assembly") return false;
        var body = wrapper.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        if (body.Length < 3 || !body[0].IsLdarg() || body[0].GetParameter(wrapper.Parameters)?.Index != 0 ||
            body[^1].OpCode.Code != Code.Ret) return false;
        var at = 1;
        var typeInfo = body[at].OpCode.Code == Code.Call && FrameworkCall(body[at],
            "System.Reflection.TypeInfo System.Reflection.IntrospectionExtensions::GetTypeInfo(System.Type)");
        if (typeInfo) at++;
        if (at < body.Length && body[at].OpCode.Code == Code.Castclass && body[at].Operand is TypeRef cast &&
            cast.FullName == (typeInfo ? "System.Reflection.TypeInfo" : "System.Type") && Framework(cast)) at++;
        return at == body.Length - 2 && body[at].OpCode.Code is Code.Call or Code.Callvirt &&
            FrameworkCall(body[at], typeInfo
                ? "System.Reflection.Assembly System.Reflection.TypeInfo::get_Assembly()"
                : "System.Reflection.Assembly System.Type::get_Assembly()");

        static bool Framework(TypeRef type) => type.DefinitionAssembly?.Name.String is
            "mscorlib" or "System.Private.CoreLib" or "System.Runtime" or "System.Reflection";
        static bool FrameworkCall(Instruction instruction, string fullName) =>
            instruction.Operand is IMethod { DeclaringType: TypeRef type } call &&
            call.FullName == fullName && Framework(type);
    }

    private static bool IsMethodReference(Instruction instruction) =>
        instruction.OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj or
            Code.Ldftn or Code.Ldvirtftn or Code.Ldtoken or Code.Jmp;

    private static string SignatureKey(IMethod method) =>
        $"{method.Name}|{method.MethodSig?.Params.Count ?? -1}|{method.MethodSig?.RetType?.FullName}";
}
