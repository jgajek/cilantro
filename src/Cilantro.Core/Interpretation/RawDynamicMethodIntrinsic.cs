using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;

namespace Cilantro.Core.Interpretation;

/// <summary>Captures DynamicILInfo output as data; never creates or invokes executable methods.</summary>
internal sealed class RawDynamicMethodIntrinsic : IStaticIntrinsicRegistry, IStaticIntrinsic
{
    private const string CaptureKey = "Cilantro.RawMethod";
    private const string SignatureKey = "Cilantro.LocalSignature";
    private const string OpaqueSignatureKey = "Cilantro.OpaqueLocalSignature";
    private const string BoundKey = "Cilantro.RawBoundFirstArgument";
    private const string EmittedInstanceKey = "Cilantro.EmittedInstanceType";
    private const string EmittedRuntimeTypeKey = "Cilantro.EmittedRuntimeType";
    private readonly StaticIntrinsicRegistry fallback = StaticIntrinsicRegistry.CreateDefault();
    private uint nextToken = 1;
    private readonly Dictionary<int, Signature> signatures = [];
    internal Dictionary<MethodDef, Capture> Methods { get; } = [];
    internal Action<Capture, IReadOnlyList<StaticValue>>? Invoking { get; set; }
    internal Func<TypeSig, StaticValue, bool>? UnknownBoxInput { get; set; }
    internal Func<TypeSig, StaticValue, bool>? OpaqueLocalInput { get; set; }

    internal sealed class Capture
    {
        internal required TypeSig Returns { get; init; }
        internal required IReadOnlyList<TypeSig> Parameters { get; init; }
        internal string Name { get; init; } = "Captured";
        internal MethodDef? Assembled { get; set; }
        internal StaticValue Reference { get; init; }
        internal bool InitLocals { get; set; } = true;
        internal List<TypeSig>? Locals { get; set; }
        internal byte[]? Code { get; set; }
        internal byte[]? Exceptions { get; set; }
        internal ushort MaxStack { get; set; }
        internal Dictionary<uint, object> Tokens { get; } = [];
    }

    private sealed class Signature
    {
        internal List<TypeSig> Locals { get; } = [];
        internal System.Reflection.Emit.SignatureHelper Writer { get; } = System.Reflection.Emit.SignatureHelper.GetLocalVarSigHelper();
        internal byte[]? Bytes { get; set; }
        internal bool Opaque { get; set; }
        internal bool Frozen { get; set; }
    }

    public bool TryResolve(IMethod method, out IStaticIntrinsic intrinsic)
    {
        if (Matches(method)) { intrinsic = this; return true; }
        return fallback.TryResolve(method, out intrinsic);
    }

    public bool Matches(IMethod method) => method.DeclaringType?.FullName is
        "System.Reflection.Emit.DynamicMethod" or "System.Reflection.Emit.DynamicILInfo" or "System.Reflection.Emit.SignatureHelper" or "System.IO.BinaryWriter" or "System.Threading.ReaderWriterLock" ||
        method.Name.String is "get_MethodHandle" or "get_FieldHandle" && method.DeclaringType?.FullName is
            "System.Reflection.MethodBase" or "System.Reflection.MethodInfo" or "System.Reflection.ConstructorInfo" or "System.Reflection.FieldInfo" ||
        method.Name == "CreateDelegate" && method.DeclaringType?.FullName == "System.Reflection.MethodInfo" ||
        method.FullName is "System.Void System.GC::SuppressFinalize(System.Object)" or "System.Void System.Reflection.Binder::.ctor()" or
            "System.Object System.Delegate::DynamicInvoke(System.Object[])" or
            "System.Object System.Activator::CreateInstance(System.Type,System.Object[])" or
            "System.Type System.Object::GetType()" or
            "System.Object System.Type::InvokeMember(System.String,System.Reflection.BindingFlags,System.Reflection.Binder,System.Object,System.Object[])";

    internal static Capture? Read(StaticHeap heap, StaticValue reference) =>
        heap.TryGetModelValue<Capture>(reference, CaptureKey, out var capture) ? capture : null;

    internal static bool IsOpaqueSignature(StaticHeap heap, StaticValue reference) =>
        heap.TryGetModelValue<bool>(reference, OpaqueSignatureKey, out var opaque) && opaque;

    public IntrinsicResult Invoke(IntrinsicContext context, IMethod method, IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        var name = method.Name.String;
        if (method.FullName == "System.Type System.Object::GetType()" && arguments.Count == 1)
        {
            if (heap.TryGetModelValue<TypeDef>(arguments[0], EmittedInstanceKey, out var instanceType) && instanceType is not null && context.State.IsAssembled(instanceType.Module))
            {
                return heap.TryGetModelValue<StaticValue>(arguments[0], EmittedRuntimeTypeKey, out var runtimeType) &&
                    heap.TryGetModelValue<TypeDef>(runtimeType, "Metadata", out var described) && described == instanceType
                    ? IntrinsicResult.Completed(runtimeType) : Refuse("Emitted runtime type identity is unavailable.");
            }
            return fallback.TryResolve(method, out var ordinaryType) ? ordinaryType.Invoke(context, method, arguments) : Refuse("Runtime type is unavailable.");
        }
        if (method.FullName == "System.Object System.Activator::CreateInstance(System.Type,System.Object[])")
            return ConstructEmitted(context, arguments);
        if (method.FullName == "System.Object System.Type::InvokeMember(System.String,System.Reflection.BindingFlags,System.Reflection.Binder,System.Object,System.Object[])")
            return InvokeEmitted(context, arguments);
        if (method.FullName == "System.Object System.Delegate::DynamicInvoke(System.Object[])" && arguments.Count == 2 &&
            heap.TryGetModelValue<IMethod>(arguments[0], StaticMachine.DelegateMethodKey, out var boundMethod) && boundMethod is MethodDef target &&
            context.State.IsAssembled(target.Module) && target.HasBody)
        {
            var argumentCount = 0;
            if (arguments[1].Kind != StaticValueKind.Null && !heap.TryGetLength(arguments[1], out argumentCount))
                return Refuse("Dynamic invocation argument array is unavailable.");
            var invoked = Methods.GetValueOrDefault(target) ?? new Capture { Returns = target.ReturnType, Parameters = target.MethodSig.Params.ToArray(), Assembled = target };
            var supplied = new List<StaticValue>();
            var bound = heap.TryGetModelValue<bool>(arguments[0], BoundKey, out var closed) && closed;
            if (argumentCount + (bound ? 1 : 0) != invoked.Parameters.Count) return Refuse("Dynamic invocation argument count differs from the bound signature.");
            if (bound)
            {
                if (!heap.TryGetModelValue<StaticValue>(arguments[0], StaticMachine.DelegateTargetKey, out var receiver)) return Refuse("Bound dynamic receiver is unavailable.");
                supplied.Add(receiver);
            }
            for (var index = 0; index < argumentCount; index++)
            {
                if (!heap.TryReadArray(arguments[1], index, out var value)) return Refuse("Dynamic invocation argument is unavailable.");
                var parameter = invoked.Parameters[index + (bound ? 1 : 0)];
                if (parameter.IsByRef) parameter = parameter.Next;
                if (parameter.IsValueType)
                {
                    if (value.Kind == StaticValueKind.Unknown && UnknownBoxInput?.Invoke(parameter, value) == true)
                    { supplied.Add(value); continue; }
                    if (!heap.TryGetRuntimeTypeName(value, out var boxedType) || boxedType != parameter.FullName || !heap.TryUnbox(value, out value))
                        return Refuse("Dynamic invocation argument cannot be unboxed exactly.");
                }
                supplied.Add(value);
            }
            Invoking?.Invoke(invoked, supplied);
            return Refuse("Captured application bodies are not executed by the construction model.");
        }
        if (method.DeclaringType.FullName == "System.Threading.ReaderWriterLock") return Lock(context, method, arguments);
        if (name is "get_MethodHandle" or "get_FieldHandle" && arguments.Count == 1)
        {
            if (name == "get_FieldHandle" && heap.TryGetModelValue<IField>(arguments[0], "Metadata", out var field) && field is not null &&
                heap.TryAllocateMetadataHandle(field, out var fieldHandle)) return IntrinsicResult.Completed(fieldHandle);
            if (heap.TryGetModelValue<bool>(arguments[0], ReflectionEmitIntrinsic.Confirmed, out var confirmed) && confirmed &&
                heap.TryGetModelValue<IMemberRef>(arguments[0], ReflectionEmitIntrinsic.Emitted, out var reference) && reference is not null &&
                heap.TryAllocateMetadataHandle(reference, out var handle)) return IntrinsicResult.Completed(handle);
            return fallback.TryResolve(method, out var intrinsic) ? intrinsic.Invoke(context, method, arguments) : Refuse("Unknown member handle.");
        }
        if (method.FullName == "System.Void System.Reflection.Binder::.ctor()" && arguments.Count == 1)
            return IntrinsicResult.Completed();
        if (method.DeclaringType.FullName == "System.IO.BinaryWriter") return Write(context, method, arguments);
        if (method.FullName == "System.Void System.GC::SuppressFinalize(System.Object)" && arguments.Count == 1)
        {
            if (!heap.TryGetObjectType(arguments[0], out _)) return Refuse("Finalization receiver is unavailable.");
            heap.TrySetModelValue(arguments[0], "FinalizationSuppressed", true);
            return IntrinsicResult.Completed();
        }
        if (method.DeclaringType.FullName == "System.Reflection.Emit.SignatureHelper")
            return LocalSignature(context, method, arguments);
        if (arguments.Count == 0) return Refuse("Raw emit operation has no receiver.");
        if (name == ".ctor" && method.DeclaringType.FullName == "System.Reflection.Emit.DynamicMethod")
        {
            // Constructors with attributes also carry CallingConventions before the return type.
            var at = method.MethodSig.Params.Count > 1 && method.MethodSig.Params[1].ElementType == ElementType.ValueType ? 4 : 2;
            if (arguments.Count <= at + 1 || Type(heap, arguments[at]) is not { } returns ||
                !heap.TryGetLength(arguments[at + 1], out var count) || count > 256) return Refuse("Dynamic method signature is not concrete.");
            var parameters = new List<TypeSig>();
            for (var index = 0; index < count; index++)
            {
                if (!heap.TryReadArray(arguments[at + 1], index, out var item) || Type(heap, item) is not { } type)
                    return Refuse("Dynamic method parameter is not concrete.");
                parameters.Add(type);
            }
            heap.TrySetModelValue(arguments[0], CaptureKey, new Capture { Returns = returns, Parameters = parameters,
                Name = heap.TryGetString(arguments[1], out var spelled) ? spelled : "Captured", Reference = arguments[0] });
            // ILGenerator-built helper methods continue through the existing model.
            return fallback.TryResolve(method, out var constructor) ? constructor.Invoke(context, method, arguments) : IntrinsicResult.Completed();
        }
        var capture = Read(heap, arguments[0]);
        if (capture is null) return fallback.TryResolve(method, out var ordinary) ? ordinary.Invoke(context, method, arguments) : Refuse("Unknown emit receiver.");
        if (name is "GetILGenerator" or "CreateDelegate" && capture.Code is null)
            return fallback.TryResolve(method, out var builder) ? builder.Invoke(context, method, arguments) : Refuse("Unknown generated helper.");
        if (name == "CreateDelegate" && capture.Code is not null && arguments.Count is 2 or 3 && context.State.ModuleMetadata is { } source)
        {
            var assembled = capture.Assembled ??= Assemble(source, capture);
            context.State.RegisterAssembledModule(assembled.Module);
            if (!heap.TryGetModelValue<string>(arguments[1], "TypeName", out var delegateName) || delegateName is null ||
                !heap.TryAllocateObject(delegateName, out var bound)) return Refuse("Unknown dynamic delegate type.");
            if (arguments.Count == 3 && (capture.Parameters.Count == 0 || capture.Parameters[0].IsValueType || capture.Parameters[0].IsByRef))
                return Refuse("Bound dynamic receivers must be reference types.");
            heap.TrySetModelValue(bound, BoundKey, arguments.Count == 3);
            heap.TrySetModelValue(bound, StaticMachine.DelegateTargetKey, arguments.Count == 3 ? arguments[2] : StaticValue.Null);
            heap.TrySetModelValue(bound, StaticMachine.DelegateMethodKey, (IMethod)assembled);
            return IntrinsicResult.Completed(bound);
        }
        if (name == "set_InitLocals" && arguments.Count == 2 && arguments[1].IsInteger)
        {
            if (capture.Assembled is not null) return Refuse("Local initialization changed after raw body assembly.");
            capture.InitLocals = arguments[1].AsInt32() != 0;
            return IntrinsicResult.Completed();
        }
        if (name == "GetDynamicILInfo" && arguments.Count == 1)
        {
            if (!heap.TryAllocateObject("System.Reflection.Emit.DynamicILInfo", out var info)) return Refuse("Raw emit allocation failed.");
            heap.TrySetModelValue(info, CaptureKey, capture);
            return IntrinsicResult.Completed(info);
        }
        if (name == "GetTokenFor" && arguments.Count is 2 or 3)
        {
            object? metadata;
            if (method.MethodSig.Params[0].ElementType == ElementType.String)
            {
                if (!heap.TryGetString(arguments[1], out var literal) || literal is null) return Refuse("Dynamic string is unknown.");
                metadata = literal;
            }
            else if (!heap.TryGetMetadataHandle(arguments[1], out metadata)) return Refuse("Dynamic token handle is unknown.");
            if (arguments.Count == 3)
            {
                if (!heap.TryGetMetadataHandle(arguments[2], out var owner)) return Refuse("Dynamic token context is unknown.");
                var ownerType = owner is TypeSig signature ? signature.ToTypeDefOrRef() : owner as ITypeDefOrRef;
                if (ownerType is null) return Refuse("Dynamic token context is not a type.");
                metadata = metadata switch
                {
                    IMethod { MethodSig: not null } called when called is not MethodSpec => new MemberRefUser(context.State.ModuleMetadata, called.Name, called.MethodSig, ownerType),
                    IField { FieldSig: not null } field => new MemberRefUser(context.State.ModuleMetadata, field.Name, field.FieldSig, ownerType),
                    _ => null
                };
            }
            var table = metadata switch
            {
                IMethod { MethodSig: not null } => 0x06000000U,
                IField { FieldSig: not null } => 0x04000000U,
                ITypeDefOrRef or TypeSig => 0x02000000U,
                string => 0x70000000U,
                _ => 0U
            };
            if (table == 0 || nextToken > 65536) return Refuse("Dynamic token kind or count exceeds capture bounds.");
            var token = table | nextToken++;
            capture.Tokens.Add(token, metadata is TypeSig type ? type.ToTypeDefOrRef() : metadata!);
            return IntrinsicResult.Completed(StaticValue.FromInt32(unchecked((int)token)));
        }
        if (name == "SetLocalSignature" && arguments.Count == 2 &&
            arguments[1].Kind == StaticValueKind.HeapReference && signatures.TryGetValue(arguments[1].HeapId, out var locals))
        {
            var unchanged = locals.Opaque
                ? heap.TryGetObjectType(arguments[1], out var opaqueType) && opaqueType == "System.Byte[]" && !heap.TryGetLength(arguments[1], out _)
                : heap.GetBytesSnapshot(arguments[1]) is { } signatureBytes && locals.Bytes is { } original && signatureBytes.AsSpan().SequenceEqual(original);
            if (!unchanged) return Refuse("Local signature transport was altered.");
            if (capture.Locals is not null || capture.Assembled is not null) return Refuse("Repeated or late local signatures are not supported.");
            capture.Locals = [.. locals.Locals];
            return IntrinsicResult.Completed();
        }
        if (name is "SetCode" or "SetExceptions" && arguments.Count == (name == "SetCode" ? 3 : 2) &&
            heap.GetBytesSnapshot(arguments[1]) is { Length: <= 1048576 } bytes)
        {
            if (name == "SetExceptions")
            {
                if (capture.Exceptions is not null || capture.Assembled is not null) return Refuse("Repeated or late exception sections are not supported.");
                capture.Exceptions = bytes;
            }
            else
            {
                if (capture.Code is not null || !arguments[2].IsInteger || arguments[2].AsInt32() is < 0 or > 65535)
                    return Refuse("Invalid or repeated raw method body.");
                capture.Code = bytes;
                capture.MaxStack = (ushort)arguments[2].AsInt32();
                if (context.State.ModuleMetadata is { } origin)
                {
                    capture.Assembled = Assemble(origin, capture);
                    Methods.Add(capture.Assembled, capture);
                    context.State.RegisterAssembledModule(capture.Assembled.Module);
                    // Reflection.Emit helpers can name this method while building their adapters.
                    heap.TrySetModelValue(capture.Reference, "Metadata", capture.Assembled);
                }
            }
            return IntrinsicResult.Completed();
        }
        return Refuse($"Raw emit operation {method.FullName} is unsupported.");
    }

    private static IntrinsicResult ConstructEmitted(IntrinsicContext context, IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (arguments.Count != 2 || context.Call is null ||
            !heap.TryGetModelValue<TypeDef>(arguments[0], "Metadata", out var type) || type is null || !context.State.IsAssembled(type.Module) ||
            type.IsValueType || type.IsAbstract || type.IsInterface || type.HasGenericParameters || !heap.TryGetLength(arguments[1], out var count) || count > 256)
            return Refuse("Activator construction requires a concrete interpreter-emitted reference type and argument array.");
        var supplied = new List<StaticValue>();
        for (var index = 0; index < count; index++)
        {
            if (!heap.TryReadArray(arguments[1], index, out var value)) return Refuse("Emitted constructor argument is unavailable.");
            supplied.Add(value);
        }
        var constructors = type.Methods.Where(candidate => candidate.IsInstanceConstructor && candidate.IsPublic && candidate.HasBody &&
            candidate.MethodSig.Params.Count == count && candidate.MethodSig.Params.Select((parameter, index) =>
                ReferenceArgument(heap, parameter, supplied[index])).All(match => match)).ToArray();
        if (constructors.Length != 1 || !heap.TryAllocateObject(type.FullName, out var instance))
            return Refuse("Emitted constructor binding is unavailable or ambiguous.");
        heap.TrySetModelValue(instance, EmittedInstanceKey, type);
        heap.TrySetModelValue(instance, EmittedRuntimeTypeKey, arguments[0]);
        var result = context.Call(constructors[0], [instance, .. supplied]);
        return result.Status == StaticExecutionStatus.Completed ? IntrinsicResult.Completed(instance) : result;
    }

    private static IntrinsicResult InvokeEmitted(IntrinsicContext context, IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (arguments.Count != 6 || context.Call is null || !arguments[2].IsInteger || arguments[2].AsInt32() != 256 || arguments[3].Kind != StaticValueKind.Null ||
            !heap.TryGetModelValue<TypeDef>(arguments[0], "Metadata", out var type) || type is null || !context.State.IsAssembled(type.Module) ||
            !heap.TryGetString(arguments[1], out var name) || !heap.TryGetRuntimeTypeName(arguments[4], out var actual) || actual != type.FullName ||
            !heap.TryGetLength(arguments[5], out var count) || count > 256)
            return Refuse("InvokeMember requires an exact public instance method on an interpreter-emitted receiver, with no custom binder.");
        var methods = type.Methods.Where(candidate => candidate.Name == name && candidate.IsPublic && !candidate.IsStatic && candidate.HasBody &&
            !candidate.HasGenericParameters && candidate.MethodSig.Params.Count == count && ReferenceType(candidate.ReturnType) &&
            candidate.MethodSig.Params.All(ReferenceType)).ToArray();
        if (methods.Length != 1) return Refuse("Emitted InvokeMember binding is unavailable or ambiguous.");
        var supplied = new List<StaticValue> { arguments[4] };
        for (var index = 0; index < count; index++)
        {
            if (!heap.TryReadArray(arguments[5], index, out var value)) return Refuse("Emitted InvokeMember argument is unavailable.");
            if (!ReferenceArgument(heap, methods[0].MethodSig.Params[index], value)) return Refuse("Emitted InvokeMember argument type is not an exact reference binding.");
            supplied.Add(value);
        }
        return context.Call(methods[0], supplied);
    }

    private static bool ReferenceArgument(StaticHeap heap, TypeSig parameter, StaticValue value) =>
        ReferenceType(parameter) && (value.Kind == StaticValueKind.Null || parameter.ElementType == ElementType.Object ||
            heap.TryGetRuntimeTypeName(value, out var name) && parameter.FullName == name);

    private static bool ReferenceType(TypeSig type) => !type.IsValueType && !type.ContainsGenericParameter &&
        type.ElementType is ElementType.Class or ElementType.Object or ElementType.String or ElementType.Array or ElementType.SZArray or ElementType.GenericInst;

    private IntrinsicResult LocalSignature(IntrinsicContext context, IMethod method, IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (method.Name == "GetLocalVarSigHelper" && arguments.Count == 0)
        {
            if (!heap.TryAllocateObject("System.Reflection.Emit.SignatureHelper", out var helper)) return Refuse("Signature allocation failed.");
            heap.TrySetModelValue(helper, SignatureKey, new Signature());
            return IntrinsicResult.Completed(helper);
        }
        if (arguments.Count == 0 || !heap.TryGetModelValue<Signature>(arguments[0], SignatureKey, out var signature) || signature is null)
            return Refuse("Unknown signature helper.");
        if (method.Name == "AddArgument" && arguments.Count is 2 or 3 && Type(heap, arguments[1]) is { } type && signature.Locals.Count < 256 && !signature.Frozen)
        {
            // Only framework primitives can be described by a host Type without loading sample types.
            var host = type.ElementType switch
            {
                ElementType.Boolean => typeof(bool), ElementType.Char => typeof(char), ElementType.I1 => typeof(sbyte), ElementType.U1 => typeof(byte),
                ElementType.I2 => typeof(short), ElementType.U2 => typeof(ushort), ElementType.I4 => typeof(int), ElementType.U4 => typeof(uint),
                ElementType.I8 => typeof(long), ElementType.U8 => typeof(ulong), ElementType.R4 => typeof(float), ElementType.R8 => typeof(double),
                ElementType.I => typeof(nint), ElementType.U => typeof(nuint), ElementType.Object => typeof(object), ElementType.String => typeof(string),
                _ => null
            };
            if (arguments.Count == 3 && !arguments[2].IsInteger || host is null && OpaqueLocalInput?.Invoke(type, arguments[1]) != true)
                return Refuse("Unsupported local signature type.");
            var pinned = arguments.Count == 3 && arguments[2].AsInt32() != 0;
            if (host is null) signature.Opaque = true;
            else signature.Writer.AddArgument(host, pinned);
            signature.Locals.Add(pinned ? new PinnedSig(type) : type);
            return IntrinsicResult.Completed();
        }
        if (method.Name == "GetSignature" && arguments.Count == 1)
        {
            // A runtime-dependent signature can contain internal type handles and
            // have a type-dependent length. Give it no invented bytes or length.
            // Only the original immutable transport identity reaches the sink.
            var allocated = signature.Opaque
                ? heap.TryAllocateObject("System.Byte[]", out var bytes)
                : heap.TryAllocateByteArray(signature.Bytes ??= signature.Writer.GetSignature(), out bytes);
            if (!allocated) return Refuse("Local signature allocation failed.");
            if (signature.Opaque) heap.TrySetModelValue(bytes, OpaqueSignatureKey, true);
            signature.Frozen = true;
            signatures.Add(bytes.HeapId, signature);
            return IntrinsicResult.Completed(bytes);
        }
        return Refuse("Unsupported signature helper operation.");
    }

    private static TypeSig? Type(StaticHeap heap, StaticValue reference)
    {
        if (!heap.TryGetModelValue<object>(reference, "Metadata", out var metadata)) return null;
        return metadata switch { TypeSig type => type, ITypeDefOrRef type => type.ToTypeSig(), _ => null };
    }

    private static IntrinsicResult Write(IntrinsicContext context, IMethod method, IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (method.Name == ".ctor" && arguments.Count == 2 && heap.TryGetRuntimeTypeName(arguments[1], out var type) && type == "System.IO.MemoryStream")
        {
            heap.TrySetModelValue(arguments[0], "BaseStream", arguments[1]);
            return IntrinsicResult.Completed();
        }
        if (arguments.Count == 0 || !heap.TryGetModelValue<StaticValue>(arguments[0], "BaseStream", out var stream)) return Refuse("Unknown binary writer.");
        if (method.Name == "get_BaseStream" && arguments.Count == 1) return IntrinsicResult.Completed(stream);
        if (method.Name == "Flush" && arguments.Count == 1) return IntrinsicResult.Completed();
        if (method.Name != "Write" || arguments.Count != 2 || context.Call is null || context.State.ModuleMetadata is not { } module)
            return Refuse("Unsupported binary writer operation.");
        byte[] data;
        var value = arguments[1];
        if (method.MethodSig.Params[0] is SZArraySig { Next.ElementType: ElementType.U1 })
        {
            if (heap.GetBytesSnapshot(value) is not { } bytes) return Refuse("Binary writer input is unknown.");
            data = bytes;
        }
        else
        {
            using var memory = new MemoryStream();
            using var writer = new BinaryWriter(memory);
            var element = method.MethodSig.Params[0].ElementType;
            if (value.IsInteger)
                switch (element)
                {
                    case ElementType.U1: writer.Write(unchecked((byte)value.AsInt32())); break;
                    case ElementType.I1: writer.Write(unchecked((sbyte)value.AsInt32())); break;
                    case ElementType.I2: writer.Write(unchecked((short)value.AsInt32())); break;
                    case ElementType.U2: writer.Write(unchecked((ushort)value.AsInt32())); break;
                    case ElementType.I4: writer.Write(value.AsInt32()); break;
                    case ElementType.U4: writer.Write(unchecked((uint)value.AsInt32())); break;
                    case ElementType.I8: writer.Write(value.AsInt64()); break;
                    case ElementType.U8: writer.Write(unchecked((ulong)value.AsInt64())); break;
                    default: return Refuse("Unsupported binary writer value type.");
                }
            else if (value.Kind == StaticValueKind.Float64 && element == ElementType.R4) writer.Write((float)value.AsFloat64());
            else if (value.Kind == StaticValueKind.Float64 && element == ElementType.R8) writer.Write(value.AsFloat64());
            else return Refuse("Binary writer value is unknown.");
            data = memory.ToArray();
        }
        if (!heap.TryAllocateByteArray(data, out var buffer)) return Refuse("Binary writer allocation failed.");
        var write = new MemberRefUser(module, "Write", MethodSig.CreateInstance(module.CorLibTypes.Void,
            new SZArraySig(module.CorLibTypes.Byte), module.CorLibTypes.Int32, module.CorLibTypes.Int32),
            new TypeRefUser(module, "System.IO", "Stream", module.CorLibTypes.AssemblyRef));
        return context.Call(write, [stream, buffer, StaticValue.FromInt32(0), StaticValue.FromInt32(data.Length)]);
    }

    private static IntrinsicResult Refuse(string reason) => IntrinsicResult.Invalid(reason);

    private static IntrinsicResult Lock(IntrinsicContext context, IMethod method, IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (arguments.Count == 0) return Refuse("Lock receiver unavailable.");
        var receiver = arguments[0];
        if (method.Name == ".ctor" && arguments.Count == 1)
        {
            heap.TrySetModelValue(receiver, "ReadDepth", 0);
            heap.TrySetModelValue(receiver, "WriteDepth", 0);
            return IntrinsicResult.Completed();
        }
        if (!heap.TryGetModelValue<int>(receiver, "ReadDepth", out var reads) || !heap.TryGetModelValue<int>(receiver, "WriteDepth", out var writes))
            return Refuse("Unknown reader/writer lock.");
        switch (method.Name.String)
        {
            case "AcquireReaderLock" when arguments.Count == 2 && arguments[1].IsInteger && reads < 1024:
                heap.TrySetModelValue(receiver, "ReadDepth", reads + 1);
                return IntrinsicResult.Completed();
            case "ReleaseReaderLock" when arguments.Count == 1 && reads > 0:
                heap.TrySetModelValue(receiver, "ReadDepth", reads - 1);
                return IntrinsicResult.Completed();
            case "AcquireWriterLock" when arguments.Count == 2 && arguments[1].IsInteger && reads == 0 && writes < 1024:
                heap.TrySetModelValue(receiver, "WriteDepth", writes + 1);
                return IntrinsicResult.Completed();
            case "ReleaseWriterLock" when arguments.Count == 1 && writes > 0:
                heap.TrySetModelValue(receiver, "WriteDepth", writes - 1);
                return IntrinsicResult.Completed();
            case "UpgradeToWriterLock" when arguments.Count == 2 && arguments[1].IsInteger && writes < 1024:
                if (!heap.TryAllocateObject("System.Threading.LockCookie", out var cookie)) return Refuse("Lock cookie allocation failed.");
                heap.TrySetModelValue(cookie, "ReadDepth", reads);
                heap.TrySetModelValue(cookie, "WriteDepth", writes);
                heap.TrySetModelValue(cookie, "Owner", receiver);
                heap.TrySetModelValue(receiver, "ReadDepth", 0);
                heap.TrySetModelValue(receiver, "WriteDepth", writes + 1);
                return IntrinsicResult.Completed(cookie);
            case "DowngradeFromWriterLock" when arguments.Count == 2 && writes > 0:
                var saved = arguments[1];
                if (saved.Kind == StaticValueKind.ManagedReference && !heap.TryReadManaged(saved, out saved)) return Refuse("Unknown lock cookie.");
                if (!heap.TryGetModelValue<StaticValue>(saved, "Owner", out var owner) || owner.HeapId != receiver.HeapId ||
                    !heap.TryGetModelValue<int>(saved, "ReadDepth", out var previousReads) || !heap.TryGetModelValue<int>(saved, "WriteDepth", out var previousWrites))
                    return Refuse("Mismatched lock cookie.");
                heap.TrySetModelValue(receiver, "ReadDepth", previousReads);
                heap.TrySetModelValue(receiver, "WriteDepth", previousWrites);
                return IntrinsicResult.Completed();
            default: return Refuse("Unsupported reader/writer lock operation.");
        }
    }

    internal static MethodDef Assemble(ModuleDef source, Capture capture)
    {
        if (capture.Code is not { Length: > 0 } code || capture.Locals is null) throw new InvalidOperationException("Incomplete dynamic method capture.");
        var module = new ModuleDefUser("Cilantro.CapturedMethod") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser("Cilantro.CapturedMethod", new Version(1, 0));
        assembly.Modules.Add(module);
        var type = new TypeDefUser("Cilantro.Analysis", "Captured", source.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(type);
        var method = new MethodDefUser(capture.Name, MethodSig.CreateStatic(capture.Returns, [.. capture.Parameters]), MethodAttributes.Static | MethodAttributes.Public);
        type.Methods.Add(method);
        var resolver = new OperandResolver(capture);
        method.Body = MethodBodyReader.CreateCilBody(resolver, code, capture.Exceptions, method.Parameters,
            (ushort)((capture.InitLocals ? 0x10 : 0) | (capture.Exceptions is { Length: > 0 } ? 8 : 0)), capture.MaxStack,
            (uint)code.Length, 0x11000001);
        if (method.Body.Instructions.Count == 0 || !EvaluationStackAnalyzer.Analyze(method).Valid ||
            method.Body.Instructions.Any(instruction => instruction.OpCode.OperandType is OperandType.InlineField or OperandType.InlineMethod or
                OperandType.InlineType or OperandType.InlineTok or OperandType.InlineString or OperandType.InlineSig or OperandType.InlineBrTarget or
                OperandType.ShortInlineBrTarget && instruction.Operand is null))
            throw new InvalidOperationException("Captured method bytes or operands did not verify.");
        return method;
    }

    private sealed class OperandResolver(Capture capture) : IInstructionOperandResolver
    {
        public IMDTokenProvider? ResolveToken(uint token, GenericParamContext gpContext) => token == 0x11000001
            ? new StandAloneSigUser(new LocalSig(capture.Locals!)) : capture.Tokens.GetValueOrDefault(token) as IMDTokenProvider;
        public string ReadUserString(uint token) => capture.Tokens.GetValueOrDefault(token) as string ?? throw new InvalidOperationException("Unresolved dynamic string token.");
    }
}
