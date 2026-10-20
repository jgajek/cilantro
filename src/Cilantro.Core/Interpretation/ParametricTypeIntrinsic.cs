using dnlib.DotNet;

namespace Cilantro.Core.Interpretation;

/// <summary>Structural metadata for unknown closed runtime types, distinct from open metadata parameters.</summary>
internal sealed class ParametricTypeIntrinsic : IStaticIntrinsicRegistry, IStaticIntrinsic
{
    private readonly IStaticIntrinsicRegistry inner;
    private readonly Dictionary<TypeSig, StaticValue> types = new(ReferenceEqualityComparer.Instance);
    private readonly HashSet<int> defaultTypeMaps = [];
    private readonly HashSet<TypeDef> symbolicNames = [];
    internal void MarkSymbolicName(TypeDef type) => symbolicNames.Add(type);
    private StaticMachineState? state;
    private StaticValue receiver;
    private MethodDef? certifiedStub;
    private StaticValue subtypeType;
    private StaticValue subtypeHandle;
    private readonly HashSet<int> receiverContexts = [];
    internal IReadOnlyList<GenericVar> Variables { get; }
    internal GenericInstSig Owner { get; }

    internal ParametricTypeIntrinsic(TypeDef owner, IStaticIntrinsicRegistry inner)
    {
        if (owner.GenericParameters.Count is 0 or > 8 || owner.GenericParameters.Any(parameter =>
            (parameter.Flags & ~GenericParamAttributes.SpecialConstraintMask) != GenericParamAttributes.NonVariant))
            throw new ArgumentException("Parametric construction requires bounded invariant owner parameters.", nameof(owner));
        this.inner = inner;
        Variables = owner.GenericParameters.Select(parameter => new GenericVar(parameter.Number, owner)).ToArray();
        Owner = new GenericInstSig((ClassOrValueTypeSig)owner.ToTypeSig(), Variables.Cast<TypeSig>().ToArray());
    }

    internal void Attach(StaticMachine machine)
    {
        if (state is not null) throw new InvalidOperationException("Parametric types belong to one construction trial.");
        state = machine.State;
        machine.UnknownIdentity = value => DependentMetadata(machine.State.Heap, value) || RawDynamicMethodIntrinsic.IsOpaqueSignature(machine.State.Heap, value) ||
            ReceiverContext(value) || machine.State.Heap.HasUnknownRuntimeType(value);
        machine.ProvedSubtypeCast = (value, expected) => value == receiver && expected is GenericInstSig instance &&
            instance.GenericType is ClassSig && instance.GenericType.TypeDefOrRef.ResolveTypeDef() == Owner.GenericType.TypeDefOrRef.ResolveTypeDef() &&
            instance.GenericArguments.Count == Variables.Count && instance.GenericArguments.Zip(Variables).All(pair => ReferenceEquals(pair.First, pair.Second));
    }

    internal void BindReceiver(StaticValue value) => receiver = value;
    internal void CertifyStub(MethodDef method) => certifiedStub = method;
    private bool ReceiverContext(StaticValue value) => value.Kind == StaticValueKind.HeapReference && receiverContexts.Contains(value.HeapId);

    internal bool CertifiesRuntimeType(TypeSig signature, StaticValue value) => signature.ContainsGenericParameter &&
        Contains(signature) && ClosedRuntimeExpression(signature) && types.TryGetValue(signature, out var registered) && registered == value;

    internal bool Contains(TypeSig? signature, int depth = 0)
    {
        if (signature is null) return false;
        if (depth > 32) return true;
        if (Variables.Any(variable => ReferenceEquals(variable, signature))) return true;
        if (signature is ClassOrValueTypeSig named && named.TypeDefOrRef.ResolveTypeDef() is { } definition && symbolicNames.Contains(definition)) return true;
        return signature is GenericInstSig instance ? instance.GenericArguments.Any(argument => Contains(argument, depth + 1)) :
            signature.Next is { } next && Contains(next, depth + 1);
    }

    private bool MetadataContains(object? metadata) => metadata switch
    {
        TypeSig signature => Contains(signature), ITypeDefOrRef type => Contains(type.ToTypeSig()),
        MethodSpec specification => specification.GenericInstMethodSig.GenericArguments.Any(argument => Contains(argument)) || MetadataContains(specification.Method),
        IMethod method => Contains(method.DeclaringType?.ToTypeSig()) ||
            method.MethodSig is { } signature && (Contains(signature.RetType) || signature.Params.Any(parameter => Contains(parameter))),
        IField field => Contains(field.DeclaringType?.ToTypeSig()) || Contains(field.FieldSig?.Type),
        _ => false
    };

    private bool DependentMetadata(StaticHeap heap, StaticValue value) =>
        heap.TryGetModelValue<object>(value, "Metadata", out var metadata) && MetadataContains(metadata) ||
        heap.TryGetMetadataHandle(value, out var handle) && MetadataContains(handle);

    internal StaticValue RuntimeType(TypeSig signature)
    {
        if (state is null) throw new InvalidOperationException("Parametric types have no construction machine.");
        if (types.TryGetValue(signature, out var cached)) return cached;
        var heap = state.Heap;
        // Never use the name cache: an open T and an unknown runtime T can have the same spelling.
        if (!heap.TryAllocateObject("System.Type", out var value)) throw new InvalidOperationException("Cannot allocate a parametric type.");
        heap.TrySetModelValue(value, "Metadata", signature); heap.TrySetModelValue(value, "TypeName", signature.FullName);
        types.Add(signature, value); return value;
    }

    public bool Matches(IMethod method) => inner.TryResolve(method, out _);
    public bool TryResolve(IMethod method, out IStaticIntrinsic intrinsic)
    {
        if (inner.TryResolve(method, out _)) { intrinsic = this; return true; }
        intrinsic = null!; return false;
    }

    public IntrinsicResult Invoke(IntrinsicContext context, IMethod method, IReadOnlyList<StaticValue> arguments)
    {
        if (!ReferenceEquals(state, context.State)) return Unknown("Parametric metadata belongs to another machine.");
        var heap = context.State.Heap; var name = method.Name.String; var api = method.DeclaringType.FullName;
        if (arguments.Any(argument => heap.TryGetMetadataHandle(argument, out var handle) && handle is IField field && context.State.IsPreservedStaticField(field)) &&
            !(api == "System.Reflection.Emit.DynamicILInfo" && name == "GetTokenFor" || api == "System.Reflection.FieldInfo" && name == "GetFieldFromHandle"))
            return Unknown("Application static field handles are available only as metadata during construction.");
        var inStub = certifiedStub is not null && context.Frames is { Count: > 0 } active && active[^1] == certifiedStub;
        if (arguments.Any(ReceiverContext))
        {
            if (inStub && method.FullName == "System.RuntimeTypeHandle System.Type::get_TypeHandle()" && arguments.Count == 1 && arguments[0] == subtypeType)
            {
                if (!subtypeHandle.IsKnown)
                { heap.TryAllocateMetadataHandle(new object(), out subtypeHandle); receiverContexts.Add(subtypeHandle.HeapId); }
                return IntrinsicResult.Completed(subtypeHandle);
            }
            if (inStub && method.FullName == "System.Reflection.MethodBase System.Reflection.MethodBase::GetMethodFromHandle(System.RuntimeMethodHandle,System.RuntimeTypeHandle)" &&
                arguments.Count == 2 && arguments[1] == subtypeHandle && heap.TryGetMetadataHandle(arguments[0], out var source) &&
                ReferenceEquals(source, certifiedStub) && heap.TryAllocateMetadataHandle(Owner, out var ownerHandle))
                return Fallback(context, method, [arguments[0], ownerHandle]);
            return Unknown("An arbitrary receiver subtype can only bind the certified declaring method.");
        }
        if (receiver.IsKnown && heap.HasUnknownRuntimeType(receiver) && arguments.Contains(receiver))
        {
            if (inStub && method.FullName == "System.Type System.Object::GetType()" && arguments.Count == 1)
            {
                if (!subtypeType.IsKnown)
                { heap.TryAllocateObject("System.Type", out subtypeType); receiverContexts.Add(subtypeType.HeapId); }
                return IntrinsicResult.Completed(subtypeType);
            }
            if (method.FullName == "System.Delegate System.Reflection.Emit.DynamicMethod::CreateDelegate(System.Type,System.Object)" && arguments.Count == 3 && arguments[2] == receiver)
                return Fallback(context, method, arguments);
            return Unknown("A framework observation depends on the receiver's arbitrary subtype.");
        }
        if (inStub && certifiedStub!.IsStatic && method.FullName == "System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)" && arguments.Count == 1 &&
            heap.TryGetMetadataHandle(arguments[0], out var rawOwner) &&
            (rawOwner is TypeSpec spec ? spec.TypeSig : rawOwner as TypeSig) is GenericInstSig rootOwner &&
            rootOwner.GenericType.TypeDefOrRef.ResolveTypeDef() == certifiedStub.DeclaringType && rootOwner.GenericArguments.Count == Variables.Count &&
            rootOwner.GenericArguments.Select((argument, index) => argument is GenericVar variable && variable.Number == index).All(valid => valid))
            return IntrinsicResult.Completed(RuntimeType(Owner));
        if (arguments.Any(argument => RawDynamicMethodIntrinsic.IsOpaqueSignature(heap, argument)))
            return method.FullName == "System.Void System.Reflection.Emit.DynamicILInfo::SetLocalSignature(System.Byte[])"
                ? Fallback(context, method, arguments) : Unknown("Opaque local signatures can only reach their original emit sink.");
        var dictionaryApi = method.DeclaringType is TypeSpec { TypeSig: GenericInstSig { GenericArguments.Count: 2 } map } &&
            map.GenericType.FullName == "System.Collections.Generic.Dictionary`2";
        var typeMap = dictionaryApi && ((GenericInstSig)((TypeSpec)method.DeclaringType).TypeSig).GenericArguments[0].FullName == "System.Type";
        if (dictionaryApi && name == ".ctor")
        {
            if (method.MethodSig.Params.Count != 0 && !(method.MethodSig.Params.Count == 1 && method.MethodSig.Params[0].ElementType == ElementType.I4))
                return Unknown("Parametric type caches require the default comparer and a fresh dictionary.");
            var created = Fallback(context, method, arguments);
            if (created.Status == StaticExecutionStatus.Completed && created.Value.Kind == StaticValueKind.HeapReference) defaultTypeMaps.Add(created.Value.HeapId);
            return created;
        }
        if (typeMap && name is "Add" or "set_Item" && arguments.Count == 3 && DependentMetadata(heap, arguments[1]))
        {
            if (arguments[0].Kind != StaticValueKind.HeapReference || !defaultTypeMaps.Contains(arguments[0].HeapId) ||
                !heap.TryGetModelValue<List<KeyValuePair<StaticValue, StaticValue>>>(arguments[0], "Pairs", out var pairs) || pairs is not { Count: 0 })
                return Unknown("Inserting an unknown type key would require an equality decision.");
            pairs.Add(new(arguments[1], arguments[2])); return IntrinsicResult.Completed();
        }
        if (dictionaryApi && name is "Add" or "set_Item" && arguments.Count == 3 && DependentMetadata(heap, arguments[2]) && !DependentMetadata(heap, arguments[1]))
        {
            bool ScalarKey(StaticValue value) => value.IsInteger || heap.TryGetString(value, out _);
            if (arguments[0].Kind != StaticValueKind.HeapReference || !defaultTypeMaps.Contains(arguments[0].HeapId) ||
                !heap.TryGetModelValue<List<KeyValuePair<StaticValue, StaticValue>>>(arguments[0], "Pairs", out var pairs) || pairs is null ||
                !(ScalarKey(arguments[1]) && pairs.All(pair => ScalarKey(pair.Key))))
                return Unknown("Transporting a parametric value requires default scalar-key equality.");
            return Fallback(context, method, arguments);
        }
        if (name == "ContainsValue" && arguments.Count == 2 &&
            heap.TryGetModelValue<List<KeyValuePair<StaticValue, StaticValue>>>(arguments[0], "Pairs", out var held) && held is not null &&
            held.Any(pair => DependentMetadata(heap, pair.Value))) return Unknown("Dictionary value equality depends on unknown runtime types.");
        if (method.FullName == "System.Type System.Object::GetType()" && arguments.Count == 1 && receiver.IsKnown && arguments[0] == receiver)
            return IntrinsicResult.Completed(RuntimeType(Owner));
        object? metadata = null;
        if (arguments.Count > 0) heap.TryGetModelValue(arguments[0], "Metadata", out metadata);
        if (metadata is IField applicationField && context.State.IsPreservedStaticField(applicationField) && name is "GetValue" or "SetValue")
            return Unknown("Application static field values are opaque during construction.");
        var described = metadata switch { TypeSig signature => signature, ITypeDefOrRef type => type.ToTypeSig(), _ => null };
        if (method.FullName == "System.Boolean System.Type::Equals(System.Type)" && arguments.Count == 2 && arguments[0] == arguments[1] &&
            (types.ContainsValue(arguments[0]) || heap.TryGetObjectType(arguments[0], out var runtimeTypeName) && runtimeTypeName == "System.Type" &&
                ReflectionEmitIntrinsic.Signatures(heap, arguments[0]) is not null) && context.State.ModuleMetadata is { } typeModule &&
            new SigComparer().Equals(method.DeclaringType, typeModule.CorLibTypes.GetTypeRef("System", "Type")))
            return IntrinsicResult.Completed(StaticValue.FromInt32(1));
        if (method.FullName == "System.Boolean System.Type::Equals(System.Type)" && arguments.Count == 2 &&
            ReflectionEmitIntrinsic.Signatures(heap, arguments[0]) is CorLibTypeSig leftPrimitive &&
            ReflectionEmitIntrinsic.Signatures(heap, arguments[1]) is CorLibTypeSig rightPrimitive &&
            context.State.ModuleMetadata is { } primitiveModule && new SigComparer().Equals(method.DeclaringType, primitiveModule.CorLibTypes.GetTypeRef("System", "Type")))
            return IntrinsicResult.Completed(StaticValue.FromInt32(leftPrimitive.ElementType == rightPrimitive.ElementType ? 1 : 0));
        if (api == "System.Reflection.MethodInfo" && name == "MakeGenericMethod" && arguments.Count == 2 &&
            ReadTypes(heap, arguments[1]) is { } methodArguments)
            return BindMethod(context, metadata, methodArguments);
        if (name is "op_Equality" or "op_Inequality" or "Equals" or "ReferenceEquals" && arguments.Count == 2 &&
            arguments.Any(argument => argument.Kind == StaticValueKind.Null) && arguments.Any(argument => DependentMetadata(heap, argument)))
            return Fallback(context, method, arguments);

        if (api == "System.Type" && name == "GetTypeFromHandle" && arguments.Count == 1 &&
            heap.TryGetMetadataHandle(arguments[0], out var handled) && MetadataContains(handled))
            return handled is TypeSig signature ? IntrinsicResult.Completed(RuntimeType(signature)) :
                handled is ITypeDefOrRef type ? IntrinsicResult.Completed(RuntimeType(type.ToTypeSig())) : Unknown("Not a type handle.");

        if (api == "System.Type" && name == "MakeGenericType" && arguments.Count == 2 && ReadTypes(heap, arguments[1]) is { } supplied &&
            (Contains(described) || supplied.Any(type => Contains(type))))
        {
            if (Contains(described) || supplied.Any(type => !ClosedRuntimeExpression(type)))
                return Unknown("Parametric construction requires a definition and closed runtime arguments.");
            // These are the actual arguments of an existing closed receiver, so its
            // own constraints are already satisfied. This proves only the identity
            // reconstruction Owner<T...>; it says nothing about other definitions,
            // permutations, or the observable traits of any unknown argument.
            if (described?.ToTypeDefOrRef()?.ResolveTypeDef() == Owner.GenericType.TypeDefOrRef.ResolveTypeDef() &&
                supplied.Count == Variables.Count && supplied.Zip(Variables).All(pair => ReferenceEquals(pair.First, pair.Second)))
                return IntrinsicResult.Completed(RuntimeType(Owner));
            if (ExistingHierarchyConstruction(described, supplied) is { } inherited)
                return IntrinsicResult.Completed(RuntimeType(inherited));
            return LoaderFrameworkIntrinsic.TryConstructGenericType(described, supplied, false, out var constructed, out var why)
                ? IntrinsicResult.Completed(RuntimeType(constructed!)) : Unknown(why);
        }

        if (api.StartsWith("System.Reflection.", StringComparison.Ordinal) && arguments.Count == 1)
        {
            if (name == "get_DeclaringType" && metadata is IMemberRef member && Contains(member.DeclaringType?.ToTypeSig()))
                return IntrinsicResult.Completed(RuntimeType(member.DeclaringType.ToTypeSig()));
            if (metadata is IMethod { MethodSig: { } signature } callable)
            {
                var scope = GenericScope.For(callable, null);
                TypeSig Bind(TypeSig type) => scope?.Bind(type) ?? type;
                if (name == "get_ReturnType")
                    return IntrinsicResult.Completed(RuntimeType(Bind(signature.RetType)));
                if (name == "GetParameters")
                {
                    if (!heap.TryAllocateArray(null, signature.Params.Count, out var parameters)) return Unknown("Parameter array exceeds its bound.");
                    for (var index = 0; index < signature.Params.Count; index++)
                    {
                        if (!heap.TryAllocateObject("System.Reflection.ParameterInfo", out var parameter)) return Unknown("Cannot allocate parameter metadata.");
                        heap.TrySetModelValue(parameter, "Metadata", Bind(signature.Params[index])); heap.TryWriteArray(parameters, index, parameter);
                    }
                    return IntrinsicResult.Completed(parameters);
                }
            }
            if (name == "get_ParameterType" && described is not null && Contains(described))
                return IntrinsicResult.Completed(RuntimeType(described));
            if (name == "get_FieldType" && metadata is IField { FieldSig: { } fieldSignature,
                DeclaringType: TypeSpec { TypeSig: GenericInstSig owner } } &&
                new GenericScope(owner.GenericArguments, null).Bind(fieldSignature.Type) is { } fieldType)
                return IntrinsicResult.Completed(RuntimeType(fieldType));
        }

        if (api == "System.Type" && Contains(described))
        {
            if (described is GenericInstSig list && context.State.ModuleMetadata is { } module &&
                ((name == "GetMethod" && arguments.Count == 6 && heap.TryGetString(arguments[1], out _) && arguments[2].Kind == StaticValueKind.Int32 && arguments[5].Kind == StaticValueKind.Null) ||
                 (name == "GetConstructor" && arguments.Count == 5 && arguments[1].Kind == StaticValueKind.Int32 && arguments[4].Kind == StaticValueKind.Null)))
            {
                var constructor = name == "GetConstructor";
                var requested = constructor ? ".ctor" : heap.TryGetString(arguments[1], out var spelling) ? spelling : "";
                var parameters = ReadTypes(heap, arguments[constructor ? 3 : 4]);
                var member = parameters is null ? null : ParametricListMembers.Bind(module, list, requested, arguments[constructor ? 1 : 2].AsInt32(), parameters);
                if (member is not null)
                {
                    if (!heap.TryAllocateObject(constructor ? "System.Reflection.ConstructorInfo" : "System.Reflection.MethodInfo", out var result)) return Unknown("Parametric method allocation failed.");
                    heap.TrySetModelValue(result, "Metadata", member);
                    var binder = arguments[constructor ? 2 : 3];
                    if (binder.Kind != StaticValueKind.Null)
                    {
                        if (context.Call is null || !heap.TryGetObjectType(binder, out var binderName)) return Unknown("Unreviewed parametric binder.");
                        var binderDefinition = module.GetTypes().SingleOrDefault(type => type.FullName == binderName && type.BaseType?.FullName == "System.Reflection.Binder");
                        var selection = binderDefinition?.Methods.Where(method => method.Name == "SelectMethod" && method.HasBody && method.MethodSig.Params.Count == 4).ToArray();
                        if (selection is not { Length: 1 } || !heap.TryAllocateArray(module.CorLibTypes.GetTypeRef("System.Reflection", "MethodBase").ToTypeSig(), 1, out var candidates))
                            return Unknown("Parametric binder has no supported selection body.");
                        heap.TryWriteArray(candidates, 0, result);
                        var selected = context.Call(selection[0], [binder, arguments[constructor ? 1 : 2], candidates, arguments[constructor ? 3 : 4], StaticValue.Null]);
                        if (selected.Status != StaticExecutionStatus.Completed) return selected;
                        if (selected.Value.Kind == StaticValueKind.Null) return selected;
                        if (selected.Value != result) return Unknown("Binder selected a method outside its candidate set.");
                    }
                    return IntrinsicResult.Completed(result);
                }
            }
            if (described?.ToTypeDefOrRef()?.ResolveTypeDef() is { } emitted && symbolicNames.Contains(emitted) && name == "GetMethod" &&
                arguments.Count is 2 or 3 && heap.TryGetString(arguments[1], out var memberName) &&
                (arguments.Count == 2 || arguments[2].IsInteger) && emitted.Methods.Count(candidate => candidate.Name == memberName) == 1)
                return Fallback(context, method, arguments);
            if (name == "get_TypeHandle" && arguments.Count == 1 && heap.TryAllocateMetadataHandle(described!, out var handle))
                return IntrinsicResult.Completed(handle);
            if (name == "GetGenericArguments" && arguments.Count == 1 && described is GenericInstSig owner)
            {
                if (!heap.TryAllocateArray(null, owner.GenericArguments.Count, out var array)) return Unknown("Generic argument array exceeds its bound.");
                for (var index = 0; index < owner.GenericArguments.Count; index++) heap.TryWriteArray(array, index, RuntimeType(owner.GenericArguments[index]));
                return IntrinsicResult.Completed(array);
            }
            if (arguments.Count == 1 && name is "MakeByRefType" or "MakePointerType" or "MakeArrayType")
                return IntrinsicResult.Completed(RuntimeType(name switch
                { "MakeByRefType" => new ByRefSig(described!), "MakePointerType" => new PtrSig(described!), _ => new SZArraySig(described!) }));
            if (name == "GetField" && described is GenericInstSig fieldOwner && fieldOwner.GenericType.TypeDefOrRef.ResolveTypeDef() is { } definition &&
                definition.Module == context.State.ModuleMetadata)
            {
                var result = Fallback(context, method, arguments);
                if (result.Status != StaticExecutionStatus.Completed || result.Value.Kind == StaticValueKind.Null) return result;
                if (!heap.TryGetModelValue<IField>(result.Value, "Metadata", out var field) || field?.DeclaringType.ResolveTypeDef() != definition)
                    return Unknown("Parametric field lookup requires a declared field on the known owner.");
                heap.TrySetModelValue(result.Value, "Metadata", (IField)new MemberRefUser(definition.Module, field.Name, field.FieldSig, fieldOwner.ToTypeDefOrRef()));
                return result;
            }
            return Unknown("Runtime type query depends on an unknown type argument: " + name);
        }

        if (arguments.Any(argument => DependentMetadata(heap, argument)))
        {
            if (api.StartsWith("System.Reflection.Emit.", StringComparison.Ordinal) ||
                api == "System.Reflection.MethodBase" && name == "GetMethodFromHandle" ||
                api == "System.Reflection.FieldInfo" && name == "GetFieldFromHandle" ||
                api.StartsWith("System.Reflection.", StringComparison.Ordinal) && metadata is IMethod or IField &&
                    name is "get_Name" or "get_MethodHandle" or "get_FieldHandle" or "get_IsStatic" or "get_IsPublic" or "get_IsPrivate" or "CreateDelegate" or "get_IsGenericMethod" or "get_IsGenericMethodDefinition" ||
                Collection(api) && name is "Add" or "set_Item") return Fallback(context, method, arguments);
            return Unknown("Operation observes parametric type identity: " + method.FullName);
        }
        if (arguments.Count > 0 && ContainerDepends(heap, arguments[0]) &&
            !(Collection(api) && name is "Add" or "set_Item" or "get_Item" or "get_Count" or "ToArray" ||
              api == "System.Array" && name is "Copy" or "get_Length" or "GetLength" || typeMap && name is "get_Count" or "Clear"))
            return Unknown("Operation compares a container with unknown runtime type identities: " + method.FullName);
        return Fallback(context, method, arguments);
    }

    private bool ContainerDepends(StaticHeap heap, StaticValue value)
    {
        if (heap.TryGetModelValue<List<StaticValue>>(value, "Items", out var items) && items is not null)
            return items.Count > 256 || items.Any(item => DependentMetadata(heap, item));
        if (heap.TryGetModelValue<Dictionary<StaticValue, StaticValue>>(value, "Entries", out var entries) && entries is not null)
            return entries.Keys.Any(key => DependentMetadata(heap, key));
        if (heap.TryGetModelValue<List<KeyValuePair<StaticValue, StaticValue>>>(value, "Pairs", out var pairs) && pairs is not null)
            return pairs.Any(pair => DependentMetadata(heap, pair.Key));
        if (heap.HasPrimitiveArrayElement(value) || !heap.TryGetLength(value, out var length)) return false;
        if (length > 256) return true;
        for (var index = 0; index < length; index++)
            if (heap.TryReadArray(value, index, out var item) && DependentMetadata(heap, item)) return true;
        return false;
    }

    private bool ClosedRuntimeExpression(TypeSig signature, int depth = 0)
    {
        if (depth > 32) return false;
        if (Variables.Any(variable => ReferenceEquals(variable, signature))) return true;
        if (signature is GenericSig) return false;
        if (signature is GenericInstSig instance) return instance.GenericArguments.All(argument => ClosedRuntimeExpression(argument, depth + 1));
        if (signature.Next is { } next) return ClosedRuntimeExpression(next, depth + 1);
        return signature is not ClassOrValueTypeSig named || named.TypeDefOrRef.ResolveTypeDef()?.HasGenericParameters != true;
    }

    private TypeSig? ExistingHierarchyConstruction(TypeSig? template, List<TypeSig> arguments)
    {
        if (template is not ClassOrValueTypeSig named || arguments.Any(argument => !LoaderFrameworkIntrinsic.GenericArgument(argument, 0)) ||
            !GenericOwnerHierarchy.TryRead(Owner, out var hierarchy, out var externalBase)) return null;
        bool Named(ClassOrValueTypeSig left, ClassOrValueTypeSig right) => left.ElementType == right.ElementType &&
            left.FullName == right.FullName && left.TypeDefOrRef.DefinitionAssembly?.FullName == right.TypeDefOrRef.DefinitionAssembly?.FullName;
        bool Same(TypeSig left, TypeSig right)
        {
            if (ReferenceEquals(left, right)) return true;
            if (left is GenericSig || right is GenericSig) return false;
            if (left is GenericInstSig a && right is GenericInstSig b)
                return Named(a.GenericType, b.GenericType) && a.GenericArguments.Count == b.GenericArguments.Count && a.GenericArguments.Zip(b.GenericArguments).All(pair => Same(pair.First, pair.Second));
            if (left is SZArraySig x && right is SZArraySig y) return Same(x.Next, y.Next);
            return left is ClassOrValueTypeSig c && right is ClassOrValueTypeSig d ? Named(c, d) :
                left is CorLibTypeSig && right is CorLibTypeSig && left.ElementType == right.ElementType;
        }
        TypeSig? Find(TypeSig type)
        {
            if (type is GenericInstSig instance)
            {
                if (Named(named, instance.GenericType) && arguments.Count == instance.GenericArguments.Count && arguments.Zip(instance.GenericArguments).All(pair => Same(pair.First, pair.Second))) return instance;
                foreach (var argument in instance.GenericArguments) if (Find(argument) is { } found) return found;
            }
            return type.Next is { } next ? Find(next) : null;
        }
        // An existing valid closed receiver already contains these exact base
        // expressions, so their constraints hold. This does not certify other
        // constructions of the same definition or invent traits of its arguments.
        return hierarchy.Select(layer => Find(layer.Type)).FirstOrDefault(type => type is not null) ??
            (externalBase is null ? null : Find(externalBase));
    }

    private IntrinsicResult BindMethod(IntrinsicContext context, object? metadata, List<TypeSig> supplied)
    {
        if (supplied.Count is 0 or > 256 || supplied.Any(type => !ClosedRuntimeExpression(type) || !LoaderFrameworkIntrinsic.GenericArgument(type, 0)))
            return Unknown("Generic method arguments must be supported closed runtime expressions.");
        IMethodDefOrRef? definition;
        List<(GenericParamAttributes Flags, bool OtherConstraints)> requirements;
        if (metadata is System.Reflection.MethodInfo host && host.IsGenericMethodDefinition &&
            host.DeclaringType?.Assembly == typeof(object).Assembly && !host.DeclaringType.IsGenericType && context.State.ModuleMetadata is { } module)
        {
            requirements = host.GetGenericArguments().Select(parameter => ((GenericParamAttributes)(int)parameter.GenericParameterAttributes,
                parameter.GetGenericParameterConstraints().Any(constraint => constraint != typeof(ValueType) || (parameter.GenericParameterAttributes & System.Reflection.GenericParameterAttributes.NotNullableValueTypeConstraint) == 0))).ToList();
            var imported = new Importer(module).Import(host);
            // Map core-library metadata to the input's own core-library identity.
            // No foreign assembly is loaded and the method itself is never invoked.
            TypeSig? Map(TypeSig type) => type switch
            {
                CorLibTypeSig or GenericMVar => type,
                SZArraySig array when Map(array.Next) is { } element => new SZArraySig(element),
                ByRefSig reference when Map(reference.Next) is { } element => new ByRefSig(element),
                PtrSig pointer when Map(pointer.Next) is { } element => new PtrSig(element),
                ClassOrValueTypeSig named when named.TypeDefOrRef.DeclaringType is null &&
                    named.TypeDefOrRef.DefinitionAssembly?.Name == typeof(object).Assembly.GetName().Name => named.IsValueType
                        ? new ValueTypeSig(module.CorLibTypes.GetTypeRef(named.TypeDefOrRef.Namespace, named.TypeDefOrRef.Name))
                        : new ClassSig(module.CorLibTypes.GetTypeRef(named.TypeDefOrRef.Namespace, named.TypeDefOrRef.Name)),
                _ => null
            };
            var signature = imported.MethodSig.Clone();
            if (signature.ParamsAfterSentinel is { Count: > 0 } || Map(signature.RetType) is not { } returns)
                return Unknown("Framework generic method signature cannot be mapped to the input core library.");
            var parameters = signature.Params.Select(Map).ToArray();
            if (parameters.Any(parameter => parameter is null)) return Unknown("Framework generic parameter signature cannot be mapped.");
            signature.RetType = returns; signature.Params.Clear(); foreach (var parameter in parameters) signature.Params.Add(parameter!);
            definition = new MemberRefUser(module, host.Name, signature, module.CorLibTypes.GetTypeRef(host.DeclaringType.Namespace!, host.DeclaringType.Name));
        }
        else if (metadata is IMethodDefOrRef candidate && candidate.ResolveMethodDef() is { HasGenericParameters: true } declared)
        {
            definition = candidate;
            requirements = declared.GenericParameters.Select(parameter => (parameter.Flags,
                parameter.GenericParamConstraints.Any(constraint => constraint.Constraint.FullName != "System.ValueType" || !parameter.HasNotNullableValueTypeConstraint))).ToList();
        }
        else return Unknown("Generic method construction requires a proved definition and its constraints.");
        if (requirements.Count != supplied.Count) return Unknown("Generic method argument count differs from its definition.");
        for (var index = 0; index < supplied.Count; index++)
        {
            var (flags, other) = requirements[index];
            if (other || (flags & ~GenericParamAttributes.SpecialConstraintMask) != 0)
                return Unknown("Generic method constraints have not been proved.");
            if (flags == 0) continue;
            var variable = Variables.FirstOrDefault(variable => ReferenceEquals(variable, supplied[index]));
            if (variable is null) return Unknown("Special method constraints require the original receiver type argument.");
            var actual = Owner.GenericType.TypeDefOrRef.ResolveTypeDef()!.GenericParameters[(int)variable.Number].Flags;
            if ((flags & GenericParamAttributes.ReferenceTypeConstraint) != 0 && (actual & GenericParamAttributes.ReferenceTypeConstraint) == 0 ||
                (flags & GenericParamAttributes.NotNullableValueTypeConstraint) != 0 && (actual & GenericParamAttributes.NotNullableValueTypeConstraint) == 0 ||
                (flags & GenericParamAttributes.DefaultConstructorConstraint) != 0 &&
                (actual & (GenericParamAttributes.DefaultConstructorConstraint | GenericParamAttributes.NotNullableValueTypeConstraint)) == 0)
                return Unknown("Receiver constraints do not imply the generic method constraints.");
        }
        if (!context.State.Heap.TryAllocateObject("System.Reflection.MethodInfo", out var result)) return Unknown("Generic method allocation failed.");
        context.State.Heap.TrySetModelValue(result, "Metadata", (IMethod)new MethodSpecUser(definition, new GenericInstMethodSig(supplied)));
        return IntrinsicResult.Completed(result);
    }

    private static bool Collection(string api) => api.StartsWith("System.Collections.Generic.List`1", StringComparison.Ordinal) ||
        api.StartsWith("System.Collections.Generic.ICollection`1", StringComparison.Ordinal) || api.StartsWith("System.Collections.Generic.IList`1", StringComparison.Ordinal);

    private static List<TypeSig>? ReadTypes(StaticHeap heap, StaticValue value)
    {
        if (!heap.TryGetLength(value, out var count) || count > 256) return null;
        var result = new List<TypeSig>();
        for (var index = 0; index < count; index++)
        {
            if (!heap.TryReadArray(value, index, out var item) || ReflectionEmitIntrinsic.Signatures(heap, item) is not { } type) return null;
            result.Add(type);
        }
        return result;
    }
    private IntrinsicResult Fallback(IntrinsicContext context, IMethod method, IReadOnlyList<StaticValue> arguments) =>
        inner.TryResolve(method, out var intrinsic) ? intrinsic.Invoke(context, method, arguments) : Unknown("No parametric fallback.");
    private static IntrinsicResult Unknown(string message) => IntrinsicResult.Unknown(message);
}
