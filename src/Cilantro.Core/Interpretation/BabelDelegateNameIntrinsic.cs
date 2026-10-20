using Cilantro.Core.Analysis;
using dnlib.DotNet;

namespace Cilantro.Core.Interpretation;

/// <summary>Abstracts only a proved, fresh private delegate cache's otherwise unobservable name.</summary>
internal sealed class BabelDelegateNameIntrinsic(BabelDelegateNameContract contract, IStaticIntrinsicRegistry inner, string label)
    : IStaticIntrinsicRegistry, IStaticIntrinsic
{
    private readonly List<(MethodDef Method, StaticValue[] Arguments)> frames = [];
    private readonly HashSet<int> declaredModules = [];
    private readonly HashSet<int> namedModules = [];
    private readonly HashSet<string> symbolicNames = [];
    private readonly HashSet<int> defaultCaches = [];
    private readonly Dictionary<int, StaticValue> symbolicCaches = [];
    private StaticMachineState? state;
    internal int Summaries { get; private set; }

    // Constructing the machine here ensures every type declaration is observed from the start.
    internal StaticMachine CreateMachine(StaticMachineLimits limits)
    {
        if (state is not null) throw new InvalidOperationException("A delegate-name registry belongs to one construction trial.");
        var machine = new StaticMachine(limits, this, modelTypeInitialization: true);
        state = machine.State;
        machine.FrameEntered = (method, arguments) => frames.Add((method, arguments.ToArray()));
        machine.FrameExited = method =>
        {
            if (frames.Count == 0 || frames[^1].Method != method) throw new InvalidOperationException("Delegate-name frame tracking disagreed.");
            frames.RemoveAt(frames.Count - 1);
        };
        machine.MethodSummary = (context, method, arguments) => method == contract.Formatter ? Invoke(context, method, arguments) : null;
        return machine;
    }

    public bool Matches(IMethod method) => method.ResolveMethodDef() == contract.Formatter ||
        method.DeclaringType.FullName == "System.Reflection.Emit.ModuleBuilder" && method.Name == "DefineType";

    public bool TryResolve(IMethod method, out IStaticIntrinsic intrinsic)
    {
        if (Matches(method) || inner.TryResolve(method, out _)) { intrinsic = this; return true; }
        intrinsic = null!; return false;
    }

    public IntrinsicResult Invoke(IntrinsicContext context, IMethod method, IReadOnlyList<StaticValue> arguments)
    {
        if (!ReferenceEquals(state, context.State)) return Refuse("Delegate-name observation belongs to another machine.");
        var heap = context.State.Heap;
        if (method.ResolveMethodDef() != contract.Formatter)
        {

            bool PrivateNameField(StaticValue value)
            {
                object? metadata = null;
                if (!heap.TryGetModelValue(value, "Metadata", out metadata)) heap.TryGetMetadataHandle(value, out metadata);
                return metadata is IField field && field.ResolveFieldDef() is { } definition && (definition == contract.Name || definition == contract.Cache);
            }
            if (arguments.Any(PrivateNameField)) return Refuse("Private symbolic-name fields cannot escape their proved consumers.");
            var table = method.DeclaringType.FullName == "System.Collections.Hashtable";
            if (table && arguments.Count > 0 && arguments[0].Kind == StaticValueKind.HeapReference && symbolicCaches.TryGetValue(arguments[0].HeapId, out var cacheKey))
            {
                if (context.Frames is not { Count: > 0 } cacheFrames || cacheFrames[^1] != contract.Caller || arguments.Count < 2 || arguments[1] != cacheKey ||
                    !heap.TryGetModelValue<Dictionary<StaticValue, StaticValue>>(arguments[0], "Entries", out var storedEntries) || storedEntries is not { Count: 0 })
                    return Refuse("A symbolic-name cache was observed outside its proved fresh use.");
                if (method.Name == "get_Item" && arguments.Count == 2) return IntrinsicResult.Completed(StaticValue.Null);
                if (method.Name == "set_Item" && arguments.Count == 3) { storedEntries[cacheKey] = arguments[2]; return IntrinsicResult.Completed(); }
                return Refuse("Unsupported symbolic-name cache operation.");
            }
            if (method.DeclaringType.FullName == "System.Reflection.Emit.ModuleBuilder" && method.Name == "DefineType" &&
                arguments.Count > 0 && arguments[0].Kind == StaticValueKind.HeapReference) declaredModules.Add(arguments[0].HeapId);
            var declared = inner.TryResolve(method, out var ordinary) ? ordinary.Invoke(context, method, arguments) : Refuse("Unmodeled type declaration.");
            if (table && method.Name == ".ctor" && declared.Status == StaticExecutionStatus.Completed && arguments.Count > 0 &&
                (method.MethodSig.Params.Count == 0 || method.MethodSig.Params.Count == 1 && method.MethodSig.Params[0].ElementType == ElementType.I4))
                defaultCaches.Add(arguments[0].HeapId);
            if (declared.Status == StaticExecutionStatus.Completed && PrivateNameField(declared.Value)) return Refuse("Private symbolic-name field metadata escaped.");
            if (inner is ParametricTypeIntrinsic types && declared.Status == StaticExecutionStatus.Completed && arguments.Count > 1 &&
                context.State.Heap.TryGetString(arguments[1], out var name) && symbolicNames.Contains(name) &&
                context.State.Heap.TryGetModelValue<TypeDef>(declared.Value, "EmittedType", out var definition) && definition is not null)
                types.MarkSymbolicName(definition);
            return declared;
        }

        if (frames.Count < 2 || frames[^1].Method != contract.Formatter || frames[^2].Method != contract.Caller || context.Frames is not { } active ||
            active.Count != frames.Count || active[^1] != contract.Formatter || active[^2] != contract.Caller || frames[^2].Arguments is not { Length: 3 } caller ||
            arguments.Count != 2 || !heap.TryGetLength(arguments[1], out var count) || count > 256 ||
            (arguments[0].Kind == StaticValueKind.Null ? count != 0 : !TypeModel(heap, arguments[0])))
            return Refuse("Delegate-name formatter was not reached with a proved caller and type signature.");
        for (var index = 0; index < count; index++)
            if (!heap.TryReadArray(arguments[1], index, out var item) || !TypeModel(heap, item))
                return Refuse("Delegate-name parameter type is unavailable.");
        if (!heap.TryReadField(caller[1], contract.Name, out var oldName) || oldName.Kind != StaticValueKind.Null ||
            !heap.TryReadField(caller[0], contract.Cache, out var cache) ||
            !heap.TryGetRuntimeTypeName(cache, out var cacheType) || cacheType != "System.Collections.Hashtable" ||
            !defaultCaches.Contains(cache.HeapId) ||
            !heap.TryGetModelValue<Dictionary<StaticValue, StaticValue>>(cache, "Entries", out var entries) || entries is not { Count: 0 } ||
            !heap.TryReadField(caller[0], contract.Module, out var module) || module.Kind != StaticValueKind.HeapReference ||
            !heap.TryGetRuntimeTypeName(module, out var moduleType) || moduleType != "System.Reflection.Emit.ModuleBuilder" ||
            declaredModules.Contains(module.HeapId) || !namedModules.Add(module.HeapId))
            return Refuse("Delegate-name abstraction requires an empty cache, null descriptor name and unused module builder.");
        // Every consumer is proved: a first cache key and a first delegate type name. The value
        // cannot choose application CIL, an existing delegate or an existing emitted type.
        var spelling = "Cilantro.ParametricDelegate." + label + "." + (++Summaries);
        if (!heap.TryAllocateString(spelling, out var key))
            return Refuse("Cannot allocate a symbolic delegate name.");
        symbolicNames.Add(spelling);
        symbolicCaches.Add(cache.HeapId, key);
        return IntrinsicResult.Completed(key);
    }

    private static bool TypeModel(StaticHeap heap, StaticValue value) =>
        heap.TryGetModelValue<object>(value, "Metadata", out var metadata) && metadata is TypeSig or ITypeDefOrRef;
    private static IntrinsicResult Refuse(string message) => IntrinsicResult.Invalid(message);
}
