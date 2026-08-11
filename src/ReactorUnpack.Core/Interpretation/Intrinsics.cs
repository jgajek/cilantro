using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using dnlib.DotNet;

namespace ReactorUnpack.Core.Interpretation;

public sealed record IntrinsicResult(
    StaticExecutionStatus Status,
    StaticValue Value,
    string? Diagnostic = null)
{
    public static IntrinsicResult Completed(StaticValue value = default) =>
        new(StaticExecutionStatus.Completed, value);
    public static IntrinsicResult Unknown(string diagnostic) =>
        new(StaticExecutionStatus.Unknown, StaticValue.Unknown, diagnostic);
    public static IntrinsicResult Invalid(string diagnostic) =>
        new(StaticExecutionStatus.InvalidProgram, StaticValue.Unknown, diagnostic);
}

public sealed record IntrinsicContext(StaticMachineState State);

public interface IStaticIntrinsic
{
    bool Matches(IMethod method);
    IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments);
}

public interface IStaticIntrinsicRegistry
{
    bool TryResolve(IMethod method, out IStaticIntrinsic intrinsic);
}

public sealed class StaticIntrinsicRegistry : IStaticIntrinsicRegistry
{
    private readonly List<IStaticIntrinsic> _intrinsics;

    public StaticIntrinsicRegistry(IEnumerable<IStaticIntrinsic>? intrinsics = null) =>
        _intrinsics = intrinsics?.ToList() ?? [];

    public static StaticIntrinsicRegistry CreateDefault() => new(
    [
        new BitConverterIntrinsic(),
        new ArrayIntrinsic(),
        new GenericListIntrinsic(),
        new MonitorIntrinsic(),
        new NativeDelegateIntrinsic(),
        new LoaderFrameworkIntrinsic(),
        new VirtualRegionIntrinsic()
    ]);

    public void Register(IStaticIntrinsic intrinsic)
    {
        ArgumentNullException.ThrowIfNull(intrinsic);
        _intrinsics.Add(intrinsic);
    }

    public bool TryResolve(IMethod method, out IStaticIntrinsic intrinsic)
    {
        intrinsic = _intrinsics.FirstOrDefault(candidate => candidate.Matches(method))!;
        return intrinsic is not null;
    }
}

public sealed class NativeDelegateIntrinsic : IStaticIntrinsic
{
    public bool Matches(IMethod method) =>
        method.Name == "Invoke" &&
        method.DeclaringType.ResolveTypeDef()?.BaseType?.FullName is
            "System.MulticastDelegate" or "System.Delegate";

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        if (arguments.Count == 0 ||
            !context.State.Heap.TryGetModelValue(
                arguments[0], "NativeName", out string? nativeName) ||
            string.IsNullOrEmpty(nativeName))
            return IntrinsicResult.Invalid("Native delegate target is not modeled.");
        if (nativeName is "VirtualProtect" or "VirtualProtectEx")
        {
            if (arguments.Count >= 5 &&
                arguments[^1].Kind == StaticValueKind.ManagedReference)
                context.State.Heap.TryWriteManaged(arguments[^1], StaticValue.FromInt32(4));
            return IntrinsicResult.Completed(StaticValue.FromInt32(1));
        }
        if (nativeName == "OpenProcess" && arguments.Count == 4)
        {
            const int modeledProcessId = 1;
            if (arguments[3].AsInt32() != modeledProcessId)
                return IntrinsicResult.Invalid(
                    "OpenProcess may only target the modeled current process.");
            if (!context.State.Heap.TryAllocateObject(
                    "SyntheticProcessHandle",
                    out var handle))
            {
                return new IntrinsicResult(
                    StaticExecutionStatus.AllocationLimitExceeded,
                    StaticValue.Unknown,
                    "Synthetic process handle exceeded the allocation budget.");
            }
            context.State.Heap.TrySetModelValue(handle, "ProcessId", modeledProcessId);
            return IntrinsicResult.Completed(handle);
        }
        if (nativeName == "CloseHandle" &&
            arguments.Count == 2 &&
            context.State.Heap.TryGetModelValue(arguments[1], "ProcessId", out int _))
        {
            return IntrinsicResult.Completed(StaticValue.FromInt32(1));
        }
        if (nativeName == "WriteProcessMemory" && arguments.Count == 6)
        {
            var heap = context.State.Heap;
            if (!heap.TryGetModelValue(arguments[1], "ProcessId", out int processId) ||
                processId != 1)
            {
                return IntrinsicResult.Invalid(
                    "WriteProcessMemory requires the modeled current-process handle.");
            }
            var destination = arguments[2];
            if (destination.IsInteger &&
                heap.TryResolveNativeAddress(destination.AsInt64(), out var resolved))
            {
                destination = resolved;
            }
            var count = arguments[4].AsInt32();
            var bytes = new byte[count < 0 ? 0 : count];
            if (count < 0 ||
                !heap.TryReadBytes(arguments[3], 0, bytes) ||
                !heap.TryWriteBytes(destination, 0, bytes))
            {
                return IntrinsicResult.Invalid(
                    $"WriteProcessMemory range is invalid (destination={destination.Kind}:" +
                    $"{destination.Bits}, count={count}).");
            }
            if (arguments[5].Kind == StaticValueKind.ManagedReference)
                heap.TryWriteManaged(arguments[5], StaticValue.FromInt32(count));
            return IntrinsicResult.Completed(StaticValue.FromInt32(1));
        }
        return IntrinsicResult.Invalid(
            $"Native delegate operation {nativeName} is unsupported.");
    }
}

public sealed class GenericListIntrinsic : IStaticIntrinsic
{
    public bool Matches(IMethod method) =>
        method.DeclaringType.FullName.StartsWith(
            "System.Collections.Generic.List`1<",
            StringComparison.Ordinal);

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        var name = method.Name.String;
        if (name == ".ctor")
        {
            if (!heap.TryAllocateObject(method.DeclaringType.FullName, out var list) ||
                !heap.TrySetModelValue(list, "Items", new List<StaticValue>()))
                return IntrinsicResult.Invalid("Could not allocate modeled List<T>.");
            return IntrinsicResult.Completed(list);
        }
        if (arguments.Count == 0 ||
            !heap.TryGetModelValue<List<StaticValue>>(arguments[0], "Items", out var items) ||
            items is null)
            return IntrinsicResult.Invalid($"List<T>.{name} target is not modeled.");
        if (name == "Add" && arguments.Count == 2)
        {
            items.Add(arguments[1]);
            return IntrinsicResult.Completed();
        }
        if (name == "get_Count" && arguments.Count == 1)
            return IntrinsicResult.Completed(StaticValue.FromInt32(items.Count));
        if (name == "get_Item" && arguments.Count == 2)
        {
            var index = arguments[1].AsInt32();
            return (uint)index < (uint)items.Count
                ? IntrinsicResult.Completed(items[index])
                : IntrinsicResult.Invalid("List<T> index is out of range.");
        }
        if (name == "set_Item" && arguments.Count == 3)
        {
            var index = arguments[1].AsInt32();
            if ((uint)index >= (uint)items.Count)
                return IntrinsicResult.Invalid("List<T> index is out of range.");
            items[index] = arguments[2];
            return IntrinsicResult.Completed();
        }
        if (name == "ToArray" && arguments.Count == 1)
        {
            if (!heap.TryAllocateArray(null, items.Count, out var array))
                return IntrinsicResult.Invalid("Could not allocate List<T> array.");
            for (var index = 0; index < items.Count; index++)
            {
                if (!heap.TryGetArrayElementReference(array, index, out var element) ||
                    !heap.TryWriteManaged(element, items[index]))
                    return IntrinsicResult.Invalid("Could not populate List<T> array.");
            }
            return IntrinsicResult.Completed(array);
        }
        if (name == "Clear" && arguments.Count == 1)
        {
            items.Clear();
            return IntrinsicResult.Completed();
        }
        return IntrinsicResult.Invalid($"Unsupported List<T> operation {name}.");
    }
}

public sealed class MonitorIntrinsic : IStaticIntrinsic
{
    public bool Matches(IMethod method) =>
        method.DeclaringType.FullName == "System.Threading.Monitor" &&
        method.Name.String is "Enter" or "Exit" or "TryEnter";

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        var name = method.Name.String;
        if (name == "Exit" && arguments.Count == 1)
            return IntrinsicResult.Completed();
        if (name == "Enter" && arguments.Count == 1)
            return IntrinsicResult.Completed();
        if (name == "Enter" && arguments.Count == 2 &&
            context.State.Heap.TryWriteManaged(arguments[1], StaticValue.FromInt32(1)))
            return IntrinsicResult.Completed();
        if (name == "TryEnter" && arguments.Count is 1 or 2)
        {
            if (arguments.Count == 2 &&
                !context.State.Heap.TryWriteManaged(arguments[1], StaticValue.FromInt32(1)))
                return IntrinsicResult.Invalid("Monitor.TryEnter lockTaken is not writable.");
            return IntrinsicResult.Completed(StaticValue.FromInt32(1));
        }
        return IntrinsicResult.Invalid($"Unsupported Monitor operation {name}.");
    }
}

public sealed class BitConverterIntrinsic : IStaticIntrinsic
{
    public bool Matches(IMethod method) =>
        method.DeclaringType.FullName == "System.BitConverter" &&
        method.Name.String is "GetBytes" or "ToInt16" or "ToUInt16" or
            "ToInt32" or "ToUInt32" or "ToInt64" or "ToUInt64" or
            "ToSingle" or "ToDouble";

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        if (arguments.Any(value => !value.IsKnown))
            return IntrinsicResult.Unknown($"{method.FullName} received an unknown value.");

        if (method.Name == "GetBytes" && arguments.Count == 1)
        {
            var type = method.MethodSig?.Params[0].ElementType;
            byte[] bytes = type switch
            {
                ElementType.Boolean => [arguments[0].AsInt64() == 0 ? (byte)0 : (byte)1],
                ElementType.Char or ElementType.I2 or ElementType.U2 =>
                    LittleEndian(unchecked((ushort)arguments[0].AsInt64())),
                ElementType.I4 or ElementType.U4 =>
                    LittleEndian(unchecked((uint)arguments[0].AsInt64())),
                ElementType.I8 or ElementType.U8 =>
                    LittleEndian(unchecked((ulong)arguments[0].AsInt64())),
                ElementType.R4 =>
                    LittleEndian(unchecked((uint)BitConverter.SingleToInt32Bits(
                        (float)arguments[0].AsFloat64()))),
                ElementType.R8 =>
                    LittleEndian(unchecked((ulong)BitConverter.DoubleToInt64Bits(
                        arguments[0].AsFloat64()))),
                _ => []
            };
            if (bytes.Length == 0)
                return IntrinsicResult.Invalid($"Unsupported BitConverter overload {method.FullName}.");
            return context.State.Heap.TryAllocateByteArray(bytes, out var reference)
                ? IntrinsicResult.Completed(reference)
                : new IntrinsicResult(
                    StaticExecutionStatus.AllocationLimitExceeded,
                    StaticValue.Unknown,
                    "BitConverter result exceeded the allocation budget.");
        }

        if (arguments.Count != 2 ||
            !arguments[1].IsInteger ||
            !context.State.Heap.TryGetLength(arguments[0], out _) ||
            !context.State.Heap.TryGetArrayElementType(
                arguments[0],
                out var elementType) ||
            elementType != "System.Byte")
            return IntrinsicResult.Invalid($"Invalid arguments for {method.FullName}.");
        var offset = arguments[1].AsInt32();
        var name = method.Name.String;
        var width = name is "ToInt16" or "ToUInt16" ? 2 :
            name is "ToInt32" or "ToUInt32" or "ToSingle" ? 4 : 8;
        var bytesToRead = new byte[width];
        if (!context.State.Heap.TryReadBytes(arguments[0], offset, bytesToRead))
            return IntrinsicResult.Invalid($"{method.FullName} read outside the array.");

        return name switch
        {
            "ToInt16" or "ToUInt16" =>
                IntrinsicResult.Completed(StaticValue.FromInt32(
                    BinaryPrimitives.ReadUInt16LittleEndian(bytesToRead))),
            "ToInt32" or "ToUInt32" =>
                IntrinsicResult.Completed(StaticValue.FromInt32(
                    BinaryPrimitives.ReadInt32LittleEndian(bytesToRead))),
            "ToInt64" or "ToUInt64" =>
                IntrinsicResult.Completed(StaticValue.FromInt64(
                    BinaryPrimitives.ReadInt64LittleEndian(bytesToRead))),
            "ToSingle" =>
                IntrinsicResult.Completed(StaticValue.FromFloat32(
                    BitConverter.Int32BitsToSingle(
                        BinaryPrimitives.ReadInt32LittleEndian(bytesToRead)))),
            "ToDouble" =>
                IntrinsicResult.Completed(StaticValue.FromFloat64(
                    BitConverter.Int64BitsToDouble(
                        BinaryPrimitives.ReadInt64LittleEndian(bytesToRead)))),
            _ => IntrinsicResult.Invalid($"Unsupported BitConverter method {method.FullName}.")
        };
    }

    private static byte[] LittleEndian(ushort value)
    {
        var result = new byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(result, value);
        return result;
    }

    private static byte[] LittleEndian(uint value)
    {
        var result = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(result, value);
        return result;
    }

    private static byte[] LittleEndian(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(result, value);
        return result;
    }
}

public sealed class ArrayIntrinsic : IStaticIntrinsic
{
    public bool Matches(IMethod method) =>
        method.DeclaringType.FullName == "System.Array" &&
        method.Name.String is "Copy" or "Clear" or "Reverse";

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        if (arguments.Any(value => !value.IsKnown))
            return IntrinsicResult.Unknown($"{method.FullName} received an unknown value.");

        var heap = context.State.Heap;
        if (method.Name == "Clear" && arguments.Count == 3)
        {
            var start = arguments[1].AsInt32();
            var count = arguments[2].AsInt32();
            return heap.TryClearArray(arguments[0], start, count)
                ? IntrinsicResult.Completed()
                : IntrinsicResult.Invalid("Array.Clear range is invalid.");
        }

        if (method.Name == "Reverse" && arguments.Count is 1 or 3)
        {
            var start = arguments.Count == 1 ? 0 : arguments[1].AsInt32();
            if (!heap.TryGetLength(arguments[0], out var total))
                return IntrinsicResult.Invalid("Array.Reverse target is not an array.");
            var count = arguments.Count == 1 ? total : arguments[2].AsInt32();
            if (start < 0 || count < 0 || start > total - count)
                return IntrinsicResult.Invalid("Array.Reverse range is invalid.");
            for (var i = 0; i < count / 2; i++)
            {
                if (!heap.TryReadArray(arguments[0], start + i, out var left) ||
                    !heap.TryReadArray(arguments[0], start + count - i - 1, out var right) ||
                    !heap.TryWriteArray(arguments[0], start + i, right) ||
                    !heap.TryWriteArray(arguments[0], start + count - i - 1, left))
                    return IntrinsicResult.Invalid("Array.Reverse range is invalid.");
            }
            return IntrinsicResult.Completed();
        }

        if (method.Name == "Copy" && arguments.Count is 3 or 5)
        {
            var source = arguments[0];
            var sourceIndex = arguments.Count == 3 ? 0 : arguments[1].AsInt32();
            var destination = arguments.Count == 3 ? arguments[1] : arguments[2];
            var destinationIndex = arguments.Count == 3 ? 0 : arguments[3].AsInt32();
            var count = arguments[^1].AsInt32();
            var temporary = new StaticValue[count < 0 ? 0 : count];
            for (var i = 0; i < count; i++)
                if (!heap.TryReadArray(source, sourceIndex + i, out temporary[i]))
                    return IntrinsicResult.Invalid("Array.Copy source range is invalid.");
            for (var i = 0; i < count; i++)
                if (!heap.TryWriteArray(destination, destinationIndex + i, temporary[i]))
                    return IntrinsicResult.Invalid("Array.Copy destination range is invalid.");
            return count < 0
                ? IntrinsicResult.Invalid("Array.Copy count is negative.")
                : IntrinsicResult.Completed();
        }

        return IntrinsicResult.Invalid($"Unsupported Array overload {method.FullName}.");
    }
}

public sealed class LoaderFrameworkIntrinsic : IStaticIntrinsic
{
    private static readonly HashSet<string> AllowedTypes = new(StringComparer.Ordinal)
    {
        "System.Object",
        "System.String",
        "System.Version",
        "System.Runtime.CompilerServices.RuntimeHelpers",
        "System.IntPtr",
        "System.UIntPtr",
        "System.ModuleHandle",
        "System.Type",
        "System.Reflection.MethodBase",
        "System.Reflection.MethodInfo",
        "System.Reflection.FieldInfo",
        "System.Text.Encoding",
        "System.Text.UTF8Encoding",
        "System.Text.UnicodeEncoding",
        "System.IO.Stream",
        "System.IO.MemoryStream",
        "System.IO.BinaryReader",
        "System.IO.Compression.DeflateStream",
        "System.IO.Compression.GZipStream",
        "System.Security.Cryptography.SHA1",
        "System.Security.Cryptography.SHA256",
        "System.Security.Cryptography.MD5",
        "System.Security.Cryptography.Aes",
        "System.Security.Cryptography.Rijndael",
        "System.Security.Cryptography.RijndaelManaged",
        "System.Security.Cryptography.ICryptoTransform",
        "System.Security.Cryptography.RSACryptoServiceProvider",
        "System.IO.File",
        "System.Security.Cryptography.CryptoStream",
        "System.IO.FileStream",
        "System.Math",
        "System.Security.Cryptography.AsymmetricAlgorithm",
        "System.Security.Cryptography.HashAlgorithm",
        "System.Security.Cryptography.CryptoConfig",
        "System.Reflection.Assembly",
        "System.Reflection.AssemblyName",
        "System.Reflection.Module",
        "System.AppDomain",
        "System.ResolveEventHandler"
        ,"System.Collections.Hashtable"
        ,"System.Collections.SortedList"
        ,"System.Diagnostics.Process"
        ,"System.Diagnostics.ProcessModuleCollection"
        ,"System.Diagnostics.ProcessModule"
        ,"System.Diagnostics.FileVersionInfo"
        ,"System.Collections.ReadOnlyCollectionBase"
        ,"System.Collections.IEnumerator"
        ,"System.IDisposable"
    };

    public bool Matches(IMethod method) =>
        AllowedTypes.Contains(Canonicalize(method.DeclaringType.FullName));

    /// <summary>Folds the concrete cryptography provider classes onto the algorithm they
    /// implement so a single model serves every spelling Reactor emits.</summary>
    private static string Canonicalize(string type) => type switch
    {
        "System.Security.Cryptography.MD5CryptoServiceProvider" =>
            "System.Security.Cryptography.MD5",
        "System.Security.Cryptography.SHA1CryptoServiceProvider" or
        "System.Security.Cryptography.SHA1Managed" =>
            "System.Security.Cryptography.SHA1",
        "System.Security.Cryptography.SHA256CryptoServiceProvider" or
        "System.Security.Cryptography.SHA256Managed" =>
            "System.Security.Cryptography.SHA256",
        "System.Security.Cryptography.AesCryptoServiceProvider" or
        "System.Security.Cryptography.AesManaged" =>
            "System.Security.Cryptography.Aes",
        "System.Security.Cryptography.SymmetricAlgorithm" =>
            "System.Security.Cryptography.Rijndael",
        "System.Security.Cryptography.RSA" =>
            "System.Security.Cryptography.RSACryptoServiceProvider",
        _ => type
    };

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        if (arguments.Any(value => !value.IsKnown))
            return IntrinsicResult.Unknown($"{method.FullName} received an unknown value.");

        var type = Canonicalize(method.DeclaringType.FullName);
        var name = method.Name.String;
        if (type == "System.Object" && name == ".ctor")
            return IntrinsicResult.Completed();
        if (type == "System.Object" && name == "GetType" && arguments.Count == 1 &&
            context.State.Heap.TryGetRuntimeTypeName(arguments[0], out var runtimeTypeName))
        {
            if (!context.State.Heap.TryAllocateObject("System.Type", out var runtimeType))
                return AllocationFailure("runtime type");
            context.State.Heap.TrySetModelValue(runtimeType, "TypeName", runtimeTypeName);
            return IntrinsicResult.Completed(runtimeType);
        }
        if (type is "System.Type" or "System.Reflection.MethodBase" or
            "System.Reflection.MethodInfo" or
            "System.Reflection.FieldInfo")
            return InvokeMetadata(context, type, name, arguments);
        if (type == "System.String")
            return InvokeString(context, name, arguments);
        if (type == "System.Version")
            return InvokeVersion(context, name, arguments);
        if (type == "System.Runtime.CompilerServices.RuntimeHelpers")
            return InvokeRuntimeHelpers(context, name, arguments);
        if (type is "System.IntPtr" or "System.UIntPtr")
            return InvokePointer(context, name, arguments);
        if (type == "System.ModuleHandle" &&
            name == "GetRuntimeTypeHandleFromMetadataToken" &&
            arguments.Count == 2)
        {
            return context.State.Heap.TryAllocateMetadataHandle(
                arguments[1].AsInt32(), out var handle)
                ? IntrinsicResult.Completed(handle)
                : AllocationFailure("runtime type handle");
        }
        if (type is "System.Text.Encoding" or "System.Text.UTF8Encoding" or
            "System.Text.UnicodeEncoding")
            return InvokeEncoding(context, type, name, arguments);
        if (type == "System.Math")
            return InvokeMath(name, arguments);
        if (type == "System.Security.Cryptography.CryptoStream")
            return InvokeCryptoStream(context, name, arguments);
        if (type == "System.IO.FileStream")
            return name == ".ctor"
                ? OpenModuleFileStream(context, arguments)
                : InvokeMemoryStream(context, name, arguments);
        if (type is "System.IO.Stream" or "System.IO.MemoryStream")
            return arguments.Count != 0 &&
                context.State.Heap.TryGetRuntimeTypeName(arguments[0], out var streamType) &&
                streamType == "System.Security.Cryptography.CryptoStream"
                ? InvokeCryptoStream(context, name, arguments)
                : InvokeMemoryStream(context, name, arguments);
        if (type == "System.IO.BinaryReader")
            return InvokeBinaryReader(context, name, arguments);
        if (type is "System.IO.Compression.DeflateStream" or
            "System.IO.Compression.GZipStream")
            return InvokeCompression(context, type, name, arguments);
        if (type is "System.Security.Cryptography.SHA1" or
            "System.Security.Cryptography.SHA256" or "System.Security.Cryptography.MD5")
            return InvokeHash(context, type, name, arguments);
        if (type is "System.Security.Cryptography.Aes" or
            "System.Security.Cryptography.Rijndael" or
            "System.Security.Cryptography.RijndaelManaged" or
            "System.Security.Cryptography.ICryptoTransform")
            return InvokeCrypto(context, type, name, arguments);
        if (type is "System.Security.Cryptography.RSACryptoServiceProvider" or
            "System.Security.Cryptography.AsymmetricAlgorithm" or
            "System.Security.Cryptography.CryptoConfig")
        {
            return InvokeAsymmetric(context, type, name, arguments);
        }
        if (type == "System.Security.Cryptography.HashAlgorithm")
            return InvokeHashAlgorithm(context, name, arguments);
        if (type == "System.IO.File")
            return InvokeFile(context, name, arguments);
        if (type == "System.Reflection.Assembly")
            return InvokeAssembly(context, name, arguments);
        if (type == "System.Reflection.AssemblyName")
            return InvokeAssemblyName(context, name, arguments);
        if (type == "System.Reflection.Module")
            return InvokeModule(context, name, arguments);
        if (type == "System.AppDomain")
            return InvokeAppDomain(context, name, arguments);
        if (type == "System.ResolveEventHandler" &&
            name == ".ctor" &&
            arguments.Count == 3)
        {
            context.State.Heap.TrySetModelValue(arguments[0], "Target", arguments[1]);
            context.State.Heap.TrySetModelValue(arguments[0], "Method", arguments[2]);
            return IntrinsicResult.Completed();
        }
        if (type is "System.Collections.Hashtable" or "System.Collections.SortedList")
            return InvokeHashtable(context, name, arguments);
        if (type == "System.Diagnostics.Process")
            return InvokeProcess(context, name, arguments);
        if (type is "System.Diagnostics.ProcessModuleCollection" or
            "System.Diagnostics.ProcessModule" or "System.Diagnostics.FileVersionInfo")
        {
            return InvokeProcessModule(context, type, name, arguments);
        }
        if (type is "System.Collections.ReadOnlyCollectionBase" or
            "System.Collections.IEnumerator" or "System.IDisposable")
        {
            return InvokeEnumerator(context, type, name, arguments);
        }
        return IntrinsicResult.Invalid($"Unsupported modeled call {method.FullName}.");
    }

    private static IntrinsicResult InvokeAppDomain(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        if (name == "get_CurrentDomain" && arguments.Count == 0)
        {
            return context.State.TryGetOrAllocateRuntimeSingleton(
                "System.AppDomain",
                out var domain)
                ? IntrinsicResult.Completed(domain)
                : AllocationFailure("current application domain");
        }
        if ((name.StartsWith("add_", StringComparison.Ordinal) ||
             name.StartsWith("remove_", StringComparison.Ordinal)) &&
            arguments.Count == 2)
        {
            return context.State.Heap.TrySetModelValue(
                arguments[0],
                $"Event:{name[(name.IndexOf('_') + 1)..]}",
                arguments[1])
                ? IntrinsicResult.Completed()
                : IntrinsicResult.Invalid("Application-domain event receiver is not modeled.");
        }
        return IntrinsicResult.Invalid($"Unsupported AppDomain operation {name}.");
    }

    private static IntrinsicResult InvokePointer(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        if (name == "get_Size" && arguments.Count == 0)
            return IntrinsicResult.Completed(StaticValue.FromInt32(context.State.PointerSize));
        if (name is "op_Equality" or "op_Inequality" && arguments.Count == 2)
        {
            var left = NormalizePointerValue(context.State.Heap, arguments[0]);
            var right = NormalizePointerValue(context.State.Heap, arguments[1]);
            var equal = left.Kind == right.Kind && left.Bits == right.Bits;
            return IntrinsicResult.Completed(StaticValue.FromInt32(
                (name == "op_Equality" ? equal : !equal) ? 1 : 0));
        }
        if (name == ".ctor" && arguments.Count == 2)
        {
            if (arguments[0].Kind == StaticValueKind.ManagedReference)
            {
                return context.State.Heap.TryWriteManaged(arguments[0], arguments[1])
                    ? IntrinsicResult.Completed()
                    : IntrinsicResult.Invalid("Managed pointer destination is not writable.");
            }
            return context.State.Heap.TrySetModelValue(arguments[0], "Pointer", arguments[1])
                ? IntrinsicResult.Completed()
                : IntrinsicResult.Invalid("Pointer receiver is not modeled.");
        }
        if (name is "ToInt32" or "ToInt64" &&
            arguments.Count == 1)
        {
            var pointer = arguments[0];
            if (context.State.Heap.TryGetModelValue(
                    pointer,
                    "Pointer",
                    out StaticValue modeled))
            {
                pointer = modeled;
            }
            if (context.State.Heap.TryReadManaged(pointer, out var managed))
                pointer = managed;
            if (pointer.Kind == StaticValueKind.NativePointer &&
                context.State.Heap.TryGetNativeAddress(pointer, out var nativeAddress))
            {
                return IntrinsicResult.Completed(name == "ToInt32"
                    ? StaticValue.FromInt32(unchecked((int)nativeAddress))
                    : StaticValue.FromInt64(nativeAddress));
            }
            return pointer.IsInteger
                ? IntrinsicResult.Completed(name == "ToInt32"
                    ? StaticValue.FromInt32(unchecked((int)pointer.AsInt64()))
                    : StaticValue.FromInt64(pointer.AsInt64()))
                : IntrinsicResult.Unknown("Managed pointer has no synthetic integer address.");
        }
        return IntrinsicResult.Invalid($"Unsupported pointer operation {name}.");
    }

    private static StaticValue NormalizePointerValue(StaticHeap heap, StaticValue value)
    {
        if (heap.TryGetModelValue(value, "Pointer", out StaticValue modeled))
            value = modeled;
        if (heap.TryReadManaged(value, out var managed))
            value = managed;
        return value;
    }

    private static IntrinsicResult InvokeMetadata(
        IntrinsicContext context,
        string type,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (type == "System.Type" &&
            name is "op_Equality" or "op_Inequality" &&
            arguments.Count == 2)
        {
            var equal = arguments[0].Equals(arguments[1]);
            return IntrinsicResult.Completed(StaticValue.FromInt32(
                (name == "op_Equality" ? equal : !equal) ? 1 : 0));
        }
        if (type == "System.Type" &&
            name is "get_Module" or "get_Assembly" &&
            arguments.Count == 1)
        {
            var modelType = name == "get_Module"
                ? "System.Reflection.Module"
                : "System.Reflection.Assembly";
            return heap.TryAllocateObject(modelType, out var owner)
                ? IntrinsicResult.Completed(owner)
                : AllocationFailure(modelType);
        }
        if (type == "System.Type" &&
            name == "GetType" &&
            arguments.Count is 1 or 2 &&
            heap.TryGetString(arguments[0], out var typeName))
        {
            if (!heap.TryAllocateObject("System.Type", out var runtimeType))
                return AllocationFailure("runtime type");
            heap.TrySetModelValue(runtimeType, "TypeName", typeName);
            return IntrinsicResult.Completed(runtimeType);
        }
        if (type == "System.Type" &&
            name is "GetField" or "GetMethod" &&
            arguments.Count >= 2 &&
            heap.TryGetString(arguments[1], out var memberName))
        {
            var memberType = name == "GetField"
                ? "System.Reflection.FieldInfo"
                : "System.Reflection.MethodInfo";
            if (!heap.TryAllocateObject(memberType, out var member))
                return AllocationFailure("runtime member");
            heap.TrySetModelValue(member, "MemberName", memberName);
            heap.TrySetModelValue(member, "DeclaringType", arguments[0]);
            return IntrinsicResult.Completed(member);
        }
        var expected = type switch
        {
            "System.Type" => "GetTypeFromHandle",
            "System.Reflection.MethodBase" => "GetMethodFromHandle",
            _ => "GetFieldFromHandle"
        };
        if (name != expected || arguments.Count is < 1 or > 2 ||
            !context.State.Heap.TryGetMetadataHandle(arguments[0], out var metadata))
            return IntrinsicResult.Invalid($"Unsupported metadata operation {type}::{name}.");
        if (!heap.TryAllocateObject(type, out var result))
            return AllocationFailure("metadata object");
        heap.TrySetModelValue(result, "Metadata", metadata);
        return IntrinsicResult.Completed(result);
    }

    private static IntrinsicResult InvokeString(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        if (name is "op_Equality" or "op_Inequality" && arguments.Count == 2)
        {
            var leftIsNull = arguments[0].Kind == StaticValueKind.Null;
            var rightIsNull = arguments[1].Kind == StaticValueKind.Null;
            var equal = leftIsNull || rightIsNull
                ? leftIsNull == rightIsNull
                : context.State.Heap.TryGetString(arguments[0], out var left) &&
                  context.State.Heap.TryGetString(arguments[1], out var right) &&
                  string.Equals(left, right, StringComparison.Ordinal);
            return IntrinsicResult.Completed(StaticValue.FromInt32(
                (name == "op_Equality" ? equal : !equal) ? 1 : 0));
        }
        if (name == "Concat" && arguments.Count is >= 2 and <= 4)
        {
            var parts = new string[arguments.Count];
            for (var index = 0; index < arguments.Count; index++)
            {
                if (arguments[index].Kind == StaticValueKind.Null)
                    parts[index] = string.Empty;
                else if (!context.State.Heap.TryGetString(arguments[index], out parts[index]!))
                    return IntrinsicResult.Invalid("String.Concat requires concrete strings.");
            }
            return context.State.Heap.TryAllocateString(string.Concat(parts), out var concatenated)
                ? IntrinsicResult.Completed(concatenated)
                : AllocationFailure("String.Concat");
        }
        if (name == "get_Length" && arguments.Count == 1 &&
            context.State.Heap.TryGetString(arguments[0], out var text))
            return IntrinsicResult.Completed(StaticValue.FromInt32(text.Length));
        if (name == "ToCharArray" && arguments.Count == 1 &&
            context.State.Heap.TryGetString(arguments[0], out text))
        {
            if (!context.State.Heap.TryAllocateArray(null, text.Length, out var array))
                return AllocationFailure("String.ToCharArray");
            for (var i = 0; i < text.Length; i++)
                context.State.Heap.TryWriteArray(array, i, StaticValue.FromInt32(text[i]));
            return IntrinsicResult.Completed(array);
        }
        if (name is "ToLower" or "ToLowerInvariant" or "ToUpper" or "ToUpperInvariant" &&
            arguments.Count == 1 &&
            context.State.Heap.TryGetString(arguments[0], out text))
        {
            var transformed = name.StartsWith("ToLower", StringComparison.Ordinal)
                ? text.ToLowerInvariant()
                : text.ToUpperInvariant();
            return context.State.Heap.TryAllocateString(transformed, out var result)
                ? IntrinsicResult.Completed(result)
                : AllocationFailure(name);
        }
        if (name is "Trim" or "TrimStart" or "TrimEnd" &&
            arguments.Count == 1 &&
            context.State.Heap.TryGetString(arguments[0], out text))
        {
            var transformed = name switch
            {
                "TrimStart" => text.TrimStart(),
                "TrimEnd" => text.TrimEnd(),
                _ => text.Trim()
            };
            return context.State.Heap.TryAllocateString(transformed, out var result)
                ? IntrinsicResult.Completed(result)
                : AllocationFailure(name);
        }
        if (name is "Contains" or "StartsWith" or "EndsWith" &&
            arguments.Count >= 2 &&
            context.State.Heap.TryGetString(arguments[0], out text) &&
            context.State.Heap.TryGetString(arguments[1], out var searched))
        {
            var matched = name switch
            {
                "Contains" => text.Contains(searched, StringComparison.Ordinal),
                "StartsWith" => text.StartsWith(searched, StringComparison.Ordinal),
                _ => text.EndsWith(searched, StringComparison.Ordinal)
            };
            return IntrinsicResult.Completed(StaticValue.FromInt32(matched ? 1 : 0));
        }
        return IntrinsicResult.Invalid($"Unsupported String operation {name}.");
    }

    private static IntrinsicResult InvokeVersion(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (name == ".ctor" && arguments.Count is >= 3 and <= 5)
        {
            var components = new int[4];
            for (var index = 1; index < arguments.Count; index++)
                components[index - 1] = arguments[index].AsInt32();
            heap.TrySetModelValue(arguments[0], "Components", components);
            return IntrinsicResult.Completed();
        }
        if (arguments.Count == 1 &&
            heap.TryGetModelValue(arguments[0], "Components", out int[]? own) &&
            own is not null)
        {
            var component = name switch
            {
                "get_Major" => 0,
                "get_Minor" => 1,
                "get_Build" => 2,
                "get_Revision" => 3,
                _ => -1
            };
            if (component >= 0)
                return IntrinsicResult.Completed(StaticValue.FromInt32(own[component]));
        }
        if (arguments.Count == 2 &&
            heap.TryGetModelValue(arguments[0], "Components", out int[]? left) &&
            heap.TryGetModelValue(arguments[1], "Components", out int[]? right) &&
            left is not null && right is not null)
        {
            var comparison = CompareVersions(left, right);
            return name switch
            {
                "CompareTo" => IntrinsicResult.Completed(StaticValue.FromInt32(comparison)),
                "op_Equality" => IntrinsicResult.Completed(
                    StaticValue.FromInt32(comparison == 0 ? 1 : 0)),
                "op_Inequality" => IntrinsicResult.Completed(
                    StaticValue.FromInt32(comparison != 0 ? 1 : 0)),
                "op_LessThan" => IntrinsicResult.Completed(
                    StaticValue.FromInt32(comparison < 0 ? 1 : 0)),
                "op_LessThanOrEqual" => IntrinsicResult.Completed(
                    StaticValue.FromInt32(comparison <= 0 ? 1 : 0)),
                "op_GreaterThan" => IntrinsicResult.Completed(
                    StaticValue.FromInt32(comparison > 0 ? 1 : 0)),
                "op_GreaterThanOrEqual" => IntrinsicResult.Completed(
                    StaticValue.FromInt32(comparison >= 0 ? 1 : 0)),
                _ => IntrinsicResult.Invalid($"Version operation {name} is denied.")
            };
        }
        return IntrinsicResult.Invalid($"Version operation {name} is denied.");
    }

    private static int CompareVersions(int[] left, int[] right)
    {
        for (var index = 0; index < 4; index++)
        {
            var comparison = left[index].CompareTo(right[index]);
            if (comparison != 0)
                return comparison;
        }
        return 0;
    }

    private static IntrinsicResult InvokeRuntimeHelpers(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        if (name != "InitializeArray" ||
            arguments.Count != 2 ||
            !context.State.Heap.TryGetMetadataHandle(arguments[1], out var metadata) ||
            metadata is not FieldDef field ||
            field.InitialValue is not { Length: > 0 } bytes)
        {
            return IntrinsicResult.Invalid($"RuntimeHelpers operation {name} is denied.");
        }
        var provenance = context.State.Provenance.Operation(
            StaticValue.FromInt32(bytes.Length),
            ProvenanceKind.Metadata,
            "RuntimeHelpers.InitializeArray",
            field.FullName,
            arguments[1]);
        return (context.State.Heap.TryWriteBytes(arguments[0], 0, bytes) ||
                context.State.Heap.TryInitializePrimitiveArray(
                    arguments[0],
                    bytes,
                    provenance.ProvenanceId))
            ? IntrinsicResult.Completed()
            : IntrinsicResult.Invalid("Initialized-array data does not fit its destination.");
    }

    private static IntrinsicResult InvokeEncoding(
        IntrinsicContext context,
        string type,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (name is ".ctor")
        {
            heap.TrySetModelValue(arguments[0], "Encoding",
                type.Contains("Unicode", StringComparison.Ordinal) ? "Unicode" : "UTF8");
            return IntrinsicResult.Completed();
        }
        if (name is "get_UTF8" or "get_Unicode")
        {
            if (!heap.TryAllocateObject("System.Text.Encoding", out var encodingReference))
                return AllocationFailure(name);
            heap.TrySetModelValue(
                encodingReference,
                "Encoding",
                name == "get_Unicode" ? "Unicode" : "UTF8");
            return IntrinsicResult.Completed(encodingReference);
        }
        if (arguments.Count < 2 ||
            !heap.TryGetModelValue(arguments[0], "Encoding", out string? encodingName))
            return IntrinsicResult.Invalid($"Invalid Encoding receiver for {name}.");
        var encoding = encodingName == "Unicode" ? Encoding.Unicode : Encoding.UTF8;
        if (name == "GetBytes" && arguments.Count == 2 &&
            heap.TryGetString(arguments[1], out var text))
            return heap.TryAllocateByteArray(encoding.GetBytes(text), out var bytes)
                ? IntrinsicResult.Completed(bytes)
                : AllocationFailure("Encoding.GetBytes");
        if (name == "GetString" && arguments.Count is 2 or 4)
        {
            var offset = arguments.Count == 2 ? 0 : arguments[2].AsInt32();
            if (!heap.TryGetLength(arguments[1], out var total))
                return IntrinsicResult.Invalid("Encoding.GetString target is not a byte array.");
            var count = arguments.Count == 2 ? total : arguments[3].AsInt32();
            var bytes = new byte[count < 0 ? 0 : count];
            if (count < 0 || !heap.TryReadBytes(arguments[1], offset, bytes))
                return IntrinsicResult.Invalid("Encoding.GetString range is invalid.");
            return heap.TryAllocateString(encoding.GetString(bytes), out var result)
                ? IntrinsicResult.Completed(result)
                : AllocationFailure("Encoding.GetString");
        }
        return IntrinsicResult.Invalid($"Unsupported Encoding operation {name}.");
    }

    private static IntrinsicResult InvokeMemoryStream(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        var stream = arguments[0];
        if (name == ".ctor")
        {
            StaticValue buffer;
            var origin = 0;
            var length = 0;
            var capacity = 0;
            var writable = true;
            var expandable = true;
            var publiclyVisible = true;
            if (arguments.Count >= 2 &&
                arguments[1].Kind == StaticValueKind.HeapReference)
            {
                buffer = arguments[1];
                if (!heap.TryGetLength(buffer, out var bufferLength) ||
                    !heap.TryGetArrayElementType(buffer, out var elementType) ||
                    elementType != "System.Byte")
                    return IntrinsicResult.Invalid("MemoryStream segment is invalid.");
                origin = arguments.Count >= 4 ? arguments[2].AsInt32() : 0;
                length = arguments.Count >= 4 ? arguments[3].AsInt32() : bufferLength;
                if (origin < 0 || length < 0 || origin > bufferLength - length)
                    return IntrinsicResult.Invalid("MemoryStream segment is invalid.");
                capacity = length;
                writable = arguments.Count switch
                {
                    >= 5 => arguments[4].AsInt32() != 0,
                    3 => arguments[2].AsInt32() != 0,
                    _ => true
                };
                publiclyVisible = arguments.Count >= 6 && arguments[5].AsInt32() != 0;
                expandable = false;
            }
            else
            {
                capacity = arguments.Count == 2 && arguments[1].IsInteger
                    ? arguments[1].AsInt32()
                    : 0;
                if (capacity < 0 ||
                    !heap.TryAllocateByteArray(new byte[capacity], out buffer))
                {
                    return capacity < 0
                        ? IntrinsicResult.Invalid("MemoryStream capacity is negative.")
                        : AllocationFailure("MemoryStream");
                }
            }
            heap.TrySetModelValue(stream, "Buffer", buffer);
            heap.TrySetModelValue(stream, "Position", 0L);
            heap.TrySetModelValue(stream, "Origin", origin);
            heap.TrySetModelValue(stream, "Length", length);
            heap.TrySetModelValue(stream, "Capacity", capacity);
            heap.TrySetModelValue(stream, "Writable", writable);
            heap.TrySetModelValue(stream, "Expandable", expandable);
            heap.TrySetModelValue(stream, "PubliclyVisible", publiclyVisible);
            heap.TrySetModelValue(stream, "Open", true);
            return IntrinsicResult.Completed();
        }
        if (!heap.TryGetModelValue(stream, "Buffer", out StaticValue bufferValue) ||
            !heap.TryGetModelValue(stream, "Position", out long position) ||
            !heap.TryGetModelValue(stream, "Origin", out int originValue) ||
            !heap.TryGetModelValue(stream, "Length", out int lengthValue) ||
            !heap.TryGetModelValue(stream, "Capacity", out int capacityValue) ||
            !heap.TryGetModelValue(stream, "Writable", out bool isWritable) ||
            !heap.TryGetModelValue(stream, "Expandable", out bool isExpandable) ||
            !heap.TryGetModelValue(stream, "Open", out bool isOpen))
            return IntrinsicResult.Invalid("Stream is not initialized.");
        if (name is "Dispose" or "Close")
        {
            heap.TrySetModelValue(stream, "Open", false);
            return IntrinsicResult.Completed();
        }
        if (!isOpen)
            return IntrinsicResult.Invalid("Stream is closed.");
        if (name == "get_Length")
            return IntrinsicResult.Completed(StaticValue.FromInt64(lengthValue));
        if (name == "get_Position")
            return IntrinsicResult.Completed(StaticValue.FromInt64(position));
        if (name == "get_CanRead" || name == "get_CanSeek")
            return IntrinsicResult.Completed(StaticValue.FromInt32(1));
        if (name == "get_CanWrite")
            return IntrinsicResult.Completed(StaticValue.FromInt32(isWritable ? 1 : 0));
        if (name == "set_Position" && arguments.Count == 2)
        {
            var requested = arguments[1].AsInt64();
            if (requested < 0 || requested > int.MaxValue - originValue)
                return IntrinsicResult.Invalid("Stream position is out of range.");
            heap.TrySetModelValue(stream, "Position", requested);
            return IntrinsicResult.Completed();
        }
        if (name == "Seek" && arguments.Count == 3)
        {
            var offset = arguments[1].AsInt64();
            var basis = arguments[2].AsInt32() switch
            {
                0 => 0L,
                1 => position,
                2 => lengthValue,
                _ => -1L
            };
            if (basis < 0 || offset < -basis ||
                offset > int.MaxValue - originValue - basis)
                return IntrinsicResult.Invalid("Stream seek is out of range.");
            var requested = basis + offset;
            heap.TrySetModelValue(stream, "Position", requested);
            return IntrinsicResult.Completed(StaticValue.FromInt64(requested));
        }
        if (name == "ToArray")
        {
            var bytes = new byte[lengthValue];
            return heap.TryReadBytes(bufferValue, originValue, bytes) &&
                heap.TryAllocateByteArray(bytes, out var copy)
                    ? IntrinsicResult.Completed(copy)
                    : AllocationFailure("MemoryStream.ToArray");
        }
        if (name == "ReadByte")
        {
            if (position >= lengthValue)
                return IntrinsicResult.Completed(StaticValue.FromInt32(-1));
            Span<byte> one = stackalloc byte[1];
            heap.TryReadBytes(bufferValue, checked(originValue + (int)position), one);
            heap.TrySetModelValue(stream, "Position", position + 1);
            return IntrinsicResult.Completed(StaticValue.FromInt32(one[0]));
        }
        if (name == "Read" && arguments.Count == 4)
        {
            var offset = arguments[2].AsInt32();
            var requested = arguments[3].AsInt32();
            var available = position >= lengthValue ? 0 : checked(lengthValue - (int)position);
            var count = Math.Min(Math.Max(requested, 0), available);
            var bytes = new byte[count];
            if (requested < 0 ||
                !heap.TryReadBytes(
                    bufferValue,
                    checked(originValue + (int)position),
                    bytes) ||
                !heap.TryWriteBytes(arguments[1], offset, bytes))
                return IntrinsicResult.Invalid("Stream.Read range is invalid.");
            heap.TrySetModelValue(stream, "Position", position + count);
            return IntrinsicResult.Completed(StaticValue.FromInt32(count));
        }
        if (name == "Write" && arguments.Count == 4)
        {
            var sourceOffset = arguments[2].AsInt32();
            var count = arguments[3].AsInt32();
            if (count < 0)
                return IntrinsicResult.Invalid("Stream.Write source range is invalid.");
            var sourceBytes = new byte[count];
            if (!heap.TryReadBytes(arguments[1], sourceOffset, sourceBytes))
                return IntrinsicResult.Invalid("Stream.Write source range is invalid.");
            return WriteMemoryStream(
                heap, stream, bufferValue, originValue, lengthValue, capacityValue,
                position, isWritable, isExpandable, sourceBytes);
        }
        if (name == "WriteByte" && arguments.Count == 2)
        {
            return WriteMemoryStream(
                heap, stream, bufferValue, originValue, lengthValue, capacityValue,
                position, isWritable, isExpandable,
                [unchecked((byte)arguments[1].AsInt32())]);
        }
        if (name == "CopyTo" && arguments.Count >= 2)
        {
            var available = position >= lengthValue ? 0 : checked(lengthValue - (int)position);
            var bytes = new byte[available];
            if (!heap.TryReadBytes(bufferValue, checked(originValue + (int)position), bytes))
                return IntrinsicResult.Invalid("Stream.CopyTo source range is invalid.");
            heap.TrySetModelValue(stream, "Position", position + available);
            return CopyInto(context, arguments[1], bytes);
        }
        if (name is "Flush" or "FlushFinalBlock")
            return IntrinsicResult.Completed();
        return IntrinsicResult.Invalid($"Unsupported MemoryStream operation {name}.");
    }

    /// <summary>
    /// Writes the drained bytes of a <c>CopyTo</c> into whichever stream the destination models.
    /// </summary>
    private static IntrinsicResult CopyInto(
        IntrinsicContext context,
        StaticValue destination,
        byte[] bytes)
    {
        var heap = context.State.Heap;
        if (!heap.TryAllocateByteArray(bytes, out var source))
            return AllocationFailure("Stream.CopyTo");
        StaticValue[] write =
        [
            destination, source, StaticValue.FromInt32(0), StaticValue.FromInt32(bytes.Length)
        ];
        return heap.TryGetRuntimeTypeName(destination, out var destinationType) &&
            destinationType == "System.Security.Cryptography.CryptoStream"
                ? InvokeCryptoStream(context, "Write", write)
                : InvokeMemoryStream(context, "Write", write);
    }

    private static IntrinsicResult WriteMemoryStream(
        StaticHeap heap,
        StaticValue stream,
        StaticValue buffer,
        int origin,
        int length,
        int capacity,
        long position,
        bool writable,
        bool expandable,
        ReadOnlySpan<byte> bytes)
    {
        if (!writable || position > int.MaxValue - origin - bytes.Length)
            return IntrinsicResult.Invalid("Stream is not writable at the requested position.");
        var required = checked((int)position + bytes.Length);
        if (required > capacity)
        {
            if (!expandable)
                return IntrinsicResult.Invalid("MemoryStream capacity is fixed.");
            var expandedBytes = new byte[required];
            if (!heap.TryReadBytes(buffer, origin, expandedBytes.AsSpan(0, length)) ||
                !heap.TryAllocateByteArray(expandedBytes, out buffer))
                return AllocationFailure("MemoryStream expansion");
            origin = 0;
            capacity = required;
            heap.TrySetModelValue(stream, "Buffer", buffer);
            heap.TrySetModelValue(stream, "Origin", origin);
            heap.TrySetModelValue(stream, "Capacity", capacity);
        }
        if (!heap.TryWriteBytes(buffer, checked(origin + (int)position), bytes))
            return IntrinsicResult.Invalid("MemoryStream backing buffer write failed.");
        heap.TrySetModelValue(stream, "Length", Math.Max(length, required));
        heap.TrySetModelValue(stream, "Position", position + bytes.Length);
        return IntrinsicResult.Completed();
    }

    private static IntrinsicResult InvokeBinaryReader(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (name == ".ctor" && arguments.Count >= 2)
        {
            if (!heap.TryGetModelValue(arguments[1], "Buffer", out StaticValue _))
                return IntrinsicResult.Invalid("BinaryReader requires a modeled stream.");
            heap.TrySetModelValue(arguments[0], "Stream", arguments[1]);
            heap.TrySetModelValue(
                arguments[0],
                "LeaveOpen",
                arguments.Count >= 4 && arguments[^1].AsInt32() != 0);
            return IntrinsicResult.Completed();
        }
        if (name is "Dispose" or "Close")
        {
            if (heap.TryGetModelValue(arguments[0], "Stream", out StaticValue ownedStream) &&
                (!heap.TryGetModelValue(arguments[0], "LeaveOpen", out bool leaveOpen) ||
                 !leaveOpen))
            {
                heap.TrySetModelValue(ownedStream, "Open", false);
            }
            return IntrinsicResult.Completed();
        }
        if (name == "get_BaseStream" &&
            arguments.Count == 1 &&
            heap.TryGetModelValue(arguments[0], "Stream", out StaticValue baseStream))
        {
            return IntrinsicResult.Completed(baseStream);
        }
        if (!heap.TryGetModelValue(arguments[0], "Stream", out StaticValue stream) ||
            !heap.TryGetModelValue(stream, "Buffer", out StaticValue buffer) ||
            !heap.TryGetModelValue(stream, "Position", out long position) ||
            !heap.TryGetModelValue(stream, "Origin", out int bufferOrigin) ||
            !heap.TryGetModelValue(stream, "Length", out int length) ||
            !heap.TryGetModelValue(stream, "Open", out bool open) ||
            !open)
            return IntrinsicResult.Invalid("BinaryReader is not initialized.");
        var width = name switch
        {
            "ReadByte" or "ReadSByte" => 1,
            "ReadInt16" or "ReadUInt16" => 2,
            "ReadInt32" or "ReadUInt32" or "ReadSingle" => 4,
            "ReadInt64" or "ReadUInt64" or "ReadDouble" => 8,
            "ReadBytes" when arguments.Count == 2 => arguments[1].AsInt32(),
            _ => -1
        };
        if (width < 0)
            return IntrinsicResult.Invalid(
                $"Unsupported or out-of-range BinaryReader operation {name} " +
                $"(position={position}, length={length}, width={width}).");
        if (name == "ReadBytes")
            width = Math.Min(width, position >= length ? 0 : checked(length - (int)position));
        else if (position > length - width)
            return IntrinsicResult.Invalid(
                $"Unsupported or out-of-range BinaryReader operation {name} " +
                $"(position={position}, length={length}, width={width}).");
        var bytes = new byte[width];
        if (!heap.TryReadBytes(buffer, checked(bufferOrigin + (int)position), bytes))
            return IntrinsicResult.Invalid("BinaryReader backing range is invalid.");
        heap.TrySetModelValue(stream, "Position", position + width);
        if (MachineTrace.Enabled)
            MachineTrace.Line(
                $"read {name}@{position} len={length} = {Convert.ToHexString(bytes.AsSpan(0, Math.Min(width, 8)))}");
        if (name == "ReadBytes")
        {
            var origin = context.State.Provenance.Operation(
                StaticValue.FromInt32(width),
                ProvenanceKind.Intrinsic,
                "BinaryReader",
                $"{name}@{position}",
                buffer,
                arguments[0],
                arguments[1]);
            return heap.TryAllocateByteArray(bytes, out var result, origin.ProvenanceId)
                ? IntrinsicResult.Completed(result.WithProvenance(origin.ProvenanceId))
                : AllocationFailure("BinaryReader.ReadBytes");
        }
        var scalar = name switch
        {
            "ReadByte" => IntrinsicResult.Completed(StaticValue.FromInt32(bytes[0])),
            "ReadSByte" => IntrinsicResult.Completed(StaticValue.FromInt32(unchecked((sbyte)bytes[0]))),
            "ReadInt16" => IntrinsicResult.Completed(StaticValue.FromInt32(
                BinaryPrimitives.ReadInt16LittleEndian(bytes))),
            "ReadUInt16" => IntrinsicResult.Completed(StaticValue.FromInt32(
                BinaryPrimitives.ReadUInt16LittleEndian(bytes))),
            "ReadInt32" or "ReadUInt32" => IntrinsicResult.Completed(StaticValue.FromInt32(
                BinaryPrimitives.ReadInt32LittleEndian(bytes))),
            "ReadInt64" or "ReadUInt64" => IntrinsicResult.Completed(StaticValue.FromInt64(
                BinaryPrimitives.ReadInt64LittleEndian(bytes))),
            "ReadSingle" => IntrinsicResult.Completed(StaticValue.FromFloat32(
                BitConverter.Int32BitsToSingle(BinaryPrimitives.ReadInt32LittleEndian(bytes)))),
            "ReadDouble" => IntrinsicResult.Completed(StaticValue.FromFloat64(
                BitConverter.Int64BitsToDouble(BinaryPrimitives.ReadInt64LittleEndian(bytes)))),
            _ => IntrinsicResult.Invalid($"Unsupported BinaryReader operation {name}.")
        };
        if (scalar.Status != StaticExecutionStatus.Completed)
            return scalar;
        var byteInputs = new List<StaticValue>(width + 1) { arguments[0] };
        for (var index = 0; index < width; index++)
        {
            if (heap.TryReadArray(
                    buffer,
                    checked(bufferOrigin + (int)position) + index,
                    out var byteValue))
                byteInputs.Add(byteValue);
        }
        return IntrinsicResult.Completed(context.State.Provenance.Operation(
            scalar.Value,
            ProvenanceKind.Intrinsic,
            "BinaryReader",
            $"{name}@{position}",
            [.. byteInputs]));
    }

    private static IntrinsicResult InvokeCompression(
        IntrinsicContext context,
        string type,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        // The constructor inflates eagerly and leaves the result modeled as a readable memory
        // stream, so every later operation is the memory-stream one over those bytes.
        if (name != ".ctor")
            return InvokeMemoryStream(context, name, arguments);
        if (arguments.Count < 3)
            return IntrinsicResult.Invalid($"Unsupported compression operation {name}.");
        var heap = context.State.Heap;
        if (!heap.TryGetModelValue(arguments[1], "Buffer", out StaticValue source) ||
            !heap.TryGetModelValue(arguments[1], "Position", out long sourcePosition) ||
            !heap.TryGetModelValue(arguments[1], "Origin", out int sourceOrigin) ||
            !heap.TryGetModelValue(arguments[1], "Length", out int length))
            return IntrinsicResult.Invalid("Compression stream source is not modeled.");
        if (sourcePosition < 0 || sourcePosition > length)
            return IntrinsicResult.Invalid("Compression stream position is invalid.");
        var compressed = new byte[length - checked((int)sourcePosition)];
        if (!heap.TryReadBytes(
                source,
                checked(sourceOrigin + (int)sourcePosition),
                compressed))
            return IntrinsicResult.Invalid("Compression source is invalid.");
        try
        {
            using var input = new MemoryStream(compressed, writable: false);
            using Stream inflater = type.EndsWith("GZipStream", StringComparison.Ordinal)
                ? new GZipStream(input, CompressionMode.Decompress)
                : new DeflateStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();
            var chunk = new byte[8192];
            while (true)
            {
                var read = inflater.Read(chunk, 0, chunk.Length);
                if (read == 0)
                    break;
                if (output.Length > heap.MaximumObjectLength - read)
                    return AllocationFailure(type);
                output.Write(chunk, 0, read);
            }
            var outputBytes = output.ToArray();
            if (!heap.TryAllocateByteArray(outputBytes, out var buffer))
                return AllocationFailure(type);
            heap.TrySetModelValue(arguments[0], "Buffer", buffer);
            heap.TrySetModelValue(arguments[0], "Position", 0L);
            heap.TrySetModelValue(arguments[0], "Origin", 0);
            heap.TrySetModelValue(arguments[0], "Length", outputBytes.Length);
            heap.TrySetModelValue(arguments[0], "Capacity", outputBytes.Length);
            heap.TrySetModelValue(arguments[0], "Writable", false);
            heap.TrySetModelValue(arguments[0], "Expandable", false);
            heap.TrySetModelValue(arguments[0], "PubliclyVisible", false);
            heap.TrySetModelValue(arguments[0], "Open", true);
            return IntrinsicResult.Completed();
        }
        catch (InvalidDataException)
        {
            return IntrinsicResult.Invalid("Compressed data is invalid.");
        }
    }

#pragma warning disable CA5350, CA5351
    private static IntrinsicResult InvokeHash(
        IntrinsicContext context,
        string type,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (name == "Create")
        {
            if (!heap.TryAllocateObject(type, out var hash))
                return AllocationFailure(type);
            return IntrinsicResult.Completed(hash);
        }
        if (name is ".ctor" or "Initialize" or "Clear" or "Dispose")
            return IntrinsicResult.Completed();
        if (name is "get_Hash" or "TransformBlock" or "TransformFinalBlock")
            return InvokeHashAlgorithm(context, name, arguments);
        if (name != "ComputeHash" || arguments.Count != 2 ||
            !heap.TryGetLength(arguments[1], out var length) ||
            !heap.TryGetArrayElementType(arguments[1], out var elementType) ||
            elementType != "System.Byte")
            return IntrinsicResult.Invalid($"Unsupported hash operation {name}.");
        var bytes = new byte[length];
        if (!heap.TryReadBytes(arguments[1], 0, bytes))
            return IntrinsicResult.Invalid("Hash input bytes are unavailable.");
        var digest = type switch
        {
            "System.Security.Cryptography.SHA1" => SHA1.HashData(bytes),
            "System.Security.Cryptography.MD5" => MD5.HashData(bytes),
            _ => SHA256.HashData(bytes)
        };
        if (!heap.TryAllocateByteArray(digest, out var result))
            return AllocationFailure("hash result");
        heap.TrySetModelValue(arguments[0], "Hash", result);
        return IntrinsicResult.Completed(result);
    }
#pragma warning restore CA5350, CA5351

    /// <summary>Models a filesystem holding exactly the analysed assembly. Reactor probes its
    /// own location before reading the protected image; any other path is reported absent.</summary>
    private static IntrinsicResult InvokeFile(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var state = context.State;
        if (arguments.Count != 1 || !state.Heap.TryGetString(arguments[0], out var path))
            return IntrinsicResult.Invalid($"Unsupported file operation {name}.");
        var isModule = state.ModulePath.Length != 0 &&
            string.Equals(path, state.ModulePath, StringComparison.OrdinalIgnoreCase);
        if (name == "Exists")
        {
            if (isModule)
                state.Observe(LoaderObservationKind.ModuleFileRead, "File.Exists on the module path");
            return IntrinsicResult.Completed(StaticValue.FromInt32(isModule ? 1 : 0));
        }
        if (name == "ReadAllBytes")
        {
            if (!isModule)
                return IntrinsicResult.Invalid($"File '{path}' is outside the analysed image.");
            state.Observe(
                LoaderObservationKind.ModuleFileRead,
                $"File.ReadAllBytes of {state.ModuleFileBytes.Length} module byte(s)");
            return state.Heap.TryAllocateByteArray(state.ModuleFileBytes, out var bytes)
                ? IntrinsicResult.Completed(bytes)
                : AllocationFailure("module file bytes");
        }
        return IntrinsicResult.Invalid($"Unsupported file operation {name}.");
    }

    /// <summary>Models the Reactor tamper check. The signature is verified for real against
    /// the concrete key and digest so the outcome is proven rather than assumed.</summary>
    private static IntrinsicResult InvokeAsymmetric(
        IntrinsicContext context,
        string type,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (type == "System.Security.Cryptography.CryptoConfig")
        {
            // Reactor picks its algorithm providers from the FIPS policy of the host. The
            // machine models a default host, where the policy is not enforced.
            if (name == "get_AllowOnlyFipsAlgorithms")
                return IntrinsicResult.Completed(StaticValue.FromInt32(0));
            if (name != "MapNameToOID" || arguments.Count != 1 ||
                !heap.TryGetString(arguments[0], out var algorithmName))
                return IntrinsicResult.Invalid($"Unsupported CryptoConfig operation {name}.");
            var oid = MapNameToOid(algorithmName);
            return oid is null
                ? IntrinsicResult.Invalid($"Unmapped hash algorithm '{algorithmName}'.")
                : heap.TryAllocateString(oid, out var mapped)
                    ? IntrinsicResult.Completed(mapped)
                    : AllocationFailure("algorithm oid");
        }
        if (name == ".ctor")
            return IntrinsicResult.Completed();
        if (name is "set_UseMachineKeyStore" or "set_PersistKeyInCsp" or "Clear" or "Dispose")
            return IntrinsicResult.Completed();
        if (name == "FromXmlString" && arguments.Count == 2)
        {
            if (!heap.TryGetString(arguments[1], out var keyXml))
                return IntrinsicResult.Invalid("RSA key material is not concrete.");
            heap.TrySetModelValue(arguments[0], "KeyXml", keyXml);
            return IntrinsicResult.Completed();
        }
        if (name is "VerifyHash" or "VerifyData" && arguments.Count == 4)
        {
            if (!heap.TryGetModelValue(arguments[0], "KeyXml", out string? keyXml) ||
                string.IsNullOrEmpty(keyXml))
                return IntrinsicResult.Invalid("RSA key material was never imported.");
            if (!TryReadByteArray(heap, arguments[1], out var digest) ||
                !TryReadByteArray(heap, arguments[3], out var signature) ||
                !heap.TryGetString(arguments[2], out var algorithm))
                return IntrinsicResult.Invalid("RSA verification inputs are not concrete.");
            if (ResolveHashAlgorithmName(algorithm) is not { } hashName)
                return IntrinsicResult.Invalid($"Unmapped signature algorithm '{algorithm}'.");
            bool verified;
            try
            {
                using var rsa = System.Security.Cryptography.RSA.Create();
                rsa.FromXmlString(keyXml);
                verified = name == "VerifyHash"
                    ? rsa.VerifyHash(digest, signature, hashName, RSASignaturePadding.Pkcs1)
                    : rsa.VerifyData(digest, signature, hashName, RSASignaturePadding.Pkcs1);
            }
            catch (CryptographicException exception)
            {
                return IntrinsicResult.Invalid($"RSA verification failed: {exception.Message}");
            }
            context.State.Observe(
                LoaderObservationKind.SignatureVerification,
                $"{type}::{name} over a {digest.Length}-byte digest with a " +
                $"{signature.Length}-byte signature",
                verified);
            return IntrinsicResult.Completed(StaticValue.FromInt32(verified ? 1 : 0));
        }
        return IntrinsicResult.Invalid($"Unsupported asymmetric operation {type}::{name}.");
    }

    private static string? MapNameToOid(string algorithmName) => algorithmName switch
    {
        "SHA1" or "System.Security.Cryptography.SHA1" => "1.3.14.3.2.26",
        "SHA256" or "System.Security.Cryptography.SHA256" => "2.16.840.1.101.3.4.2.1",
        "SHA384" => "2.16.840.1.101.3.4.2.2",
        "SHA512" => "2.16.840.1.101.3.4.2.3",
        "MD5" or "System.Security.Cryptography.MD5" => "1.2.840.113549.2.5",
        _ => null
    };

#pragma warning disable CA5350, CA5351
    private static HashAlgorithmName? ResolveHashAlgorithmName(string algorithm) => algorithm switch
    {
        "1.3.14.3.2.26" or "SHA1" => HashAlgorithmName.SHA1,
        "2.16.840.1.101.3.4.2.1" or "SHA256" => HashAlgorithmName.SHA256,
        "2.16.840.1.101.3.4.2.2" or "SHA384" => HashAlgorithmName.SHA384,
        "2.16.840.1.101.3.4.2.3" or "SHA512" => HashAlgorithmName.SHA512,
        "1.2.840.113549.2.5" or "MD5" => HashAlgorithmName.MD5,
        _ => null
    };
#pragma warning restore CA5350, CA5351

    private static IntrinsicResult InvokeHashAlgorithm(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (arguments.Count == 0)
            return IntrinsicResult.Invalid($"Unsupported hash algorithm operation {name}.");
        var receiver = arguments[0];
        switch (name)
        {
            case "get_Hash"
                when heap.TryGetModelValue(receiver, "Hash", out StaticValue digest):
                return IntrinsicResult.Completed(digest);
            case "TransformBlock" when arguments.Count == 6:
            {
                if (!TryReadHashSegment(heap, arguments, out var chunk, out var failure))
                    return failure;
                PendingHashBytes(heap, receiver).AddRange(chunk);
                if (arguments[4].Kind == StaticValueKind.HeapReference &&
                    !heap.TryWriteBytes(arguments[4], arguments[5].AsInt32(), chunk))
                    return IntrinsicResult.Invalid("Hash block destination is unavailable.");
                return IntrinsicResult.Completed(StaticValue.FromInt32(chunk.Length));
            }
            case "TransformFinalBlock" when arguments.Count == 4:
            {
                if (!TryReadHashSegment(heap, arguments, out var chunk, out var failure))
                    return failure;
                var pending = PendingHashBytes(heap, receiver);
                pending.AddRange(chunk);
                if (ComputeDigest(heap, receiver, [.. pending]) is not { } digestBytes)
                    return IntrinsicResult.Invalid("Hash algorithm is unknown.");
                pending.Clear();
                if (!heap.TryAllocateByteArray(digestBytes, out var digestValue))
                    return AllocationFailure("hash result");
                heap.TrySetModelValue(receiver, "Hash", digestValue);
                return heap.TryAllocateByteArray(chunk, out var tail)
                    ? IntrinsicResult.Completed(tail)
                    : AllocationFailure("hash tail");
            }
            default:
                return IntrinsicResult.Invalid($"Unsupported hash algorithm operation {name}.");
        }
    }

    private static bool TryReadHashSegment(
        StaticHeap heap,
        IReadOnlyList<StaticValue> arguments,
        out byte[] chunk,
        out IntrinsicResult failure)
    {
        chunk = [];
        var offset = arguments[2].AsInt32();
        var count = arguments[3].AsInt32();
        if (offset < 0 || count < 0)
        {
            failure = IntrinsicResult.Invalid("Hash block range is invalid.");
            return false;
        }
        var buffer = new byte[count];
        if (!heap.TryReadBytes(arguments[1], offset, buffer))
        {
            failure = IntrinsicResult.Invalid("Hash block source is unavailable.");
            return false;
        }
        chunk = buffer;
        failure = IntrinsicResult.Completed();
        return true;
    }

    private static List<byte> PendingHashBytes(StaticHeap heap, StaticValue receiver)
    {
        if (heap.TryGetModelValue(receiver, "Pending", out List<byte>? pending) &&
            pending is not null)
            return pending;
        var created = new List<byte>();
        heap.TrySetModelValue(receiver, "Pending", created);
        return created;
    }

#pragma warning disable CA5350, CA5351
    private static byte[]? ComputeDigest(StaticHeap heap, StaticValue receiver, byte[] data) =>
        heap.TryGetRuntimeTypeName(receiver, out var typeName)
            ? Canonicalize(typeName) switch
            {
                "System.Security.Cryptography.SHA1" => SHA1.HashData(data),
                "System.Security.Cryptography.MD5" => MD5.HashData(data),
                "System.Security.Cryptography.SHA256" => SHA256.HashData(data),
                _ => null
            }
            : null;
#pragma warning restore CA5350, CA5351

    private static bool TryReadByteArray(StaticHeap heap, StaticValue reference, out byte[] bytes)
    {
        bytes = [];
        if (!heap.TryGetLength(reference, out var length) ||
            !heap.TryGetArrayElementType(reference, out var elementType) ||
            elementType != "System.Byte")
            return false;
        var buffer = new byte[length];
        if (!heap.TryReadBytes(reference, 0, buffer))
            return false;
        bytes = buffer;
        return true;
    }

    private static IntrinsicResult InvokeCrypto(
        IntrinsicContext context,
        string type,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (name is "Create" or ".ctor")
        {
            if (name == ".ctor")
                return IntrinsicResult.Completed();
            if (!heap.TryAllocateObject(type, out var algorithm))
                return AllocationFailure(type);
            return IntrinsicResult.Completed(algorithm);
        }
        if (name is "set_Key" or "set_IV" && arguments.Count == 2)
        {
            heap.TrySetModelValue(arguments[0], name[4..], arguments[1]);
            return IntrinsicResult.Completed();
        }
        if (name is "set_Mode" or "set_Padding" && arguments.Count == 2)
        {
            heap.TrySetModelValue(arguments[0], name[4..], arguments[1].AsInt32());
            return IntrinsicResult.Completed();
        }
        if (name is "CreateDecryptor" or "CreateEncryptor")
        {
            var owner = arguments[0];
            if (arguments.Count == 3)
            {
                heap.TrySetModelValue(owner, "Key", arguments[1]);
                heap.TrySetModelValue(owner, "IV", arguments[2]);
            }
            if (!heap.TryAllocateObject("System.Security.Cryptography.ICryptoTransform", out var transform))
                return AllocationFailure("crypto transform");
            heap.TrySetModelValue(transform, "Algorithm", owner);
            heap.TrySetModelValue(transform, "Decrypt", name == "CreateDecryptor");
            return IntrinsicResult.Completed(transform);
        }
        if (name == "TransformFinalBlock" && arguments.Count == 4)
            return TransformFinalBlock(context, arguments);
        if (name is "Dispose" or "Clear")
            return IntrinsicResult.Completed();
        return IntrinsicResult.Invalid($"Unsupported cryptography operation {name}.");
    }

    private static IntrinsicResult TransformFinalBlock(
        IntrinsicContext context,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        var offset = arguments[2].AsInt32();
        var count = arguments[3].AsInt32();
        var input = new byte[count < 0 ? 0 : count];
        if (count < 0 || !heap.TryReadBytes(arguments[1], offset, input))
            return IntrinsicResult.Invalid("Crypto transform range is invalid.");
        if (!TryTransformBytes(heap, arguments[0], input, out var output, out var error))
            return IntrinsicResult.Invalid(error);
        return heap.TryAllocateByteArray(output, out var result)
            ? IntrinsicResult.Completed(result)
            : AllocationFailure("crypto output");
    }

    private static bool TryTransformBytes(
        StaticHeap heap,
        StaticValue transform,
        byte[] input,
        out byte[] output,
        out string error)
    {
        output = [];
        if (!heap.TryGetModelValue(transform, "Algorithm", out StaticValue algorithm) ||
            !heap.TryGetModelValue(transform, "Decrypt", out bool decrypt) ||
            !heap.TryGetModelValue(algorithm, "Key", out StaticValue keyReference) ||
            !heap.TryGetModelValue(algorithm, "IV", out StaticValue ivReference) ||
            !heap.TryGetLength(keyReference, out var keyLength) ||
            !heap.TryGetLength(ivReference, out var ivLength))
        {
            error = "Crypto transform is not fully configured.";
            return false;
        }
        var key = new byte[keyLength];
        var iv = new byte[ivLength];
        if (!heap.TryReadBytes(keyReference, 0, key) || !heap.TryReadBytes(ivReference, 0, iv))
        {
            error = "Crypto transform key material is unavailable.";
            return false;
        }
        try
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            if (heap.TryGetModelValue(algorithm, "Mode", out int mode))
                aes.Mode = (CipherMode)mode;
            if (heap.TryGetModelValue(algorithm, "Padding", out int padding))
                aes.Padding = (PaddingMode)padding;
            using var cryptoTransform = decrypt ? aes.CreateDecryptor() : aes.CreateEncryptor();
            output = cryptoTransform.TransformFinalBlock(input, 0, input.Length);
            error = string.Empty;
            return true;
        }
        catch (CryptographicException exception)
        {
            error = $"Crypto parameters or input are invalid: {exception.Message}";
            return false;
        }
    }

    private static IntrinsicResult InvokeMath(string name, IReadOnlyList<StaticValue> arguments)
    {
        if (arguments.Count == 2 && arguments.All(value => value.IsInteger))
        {
            var wide = arguments.Any(value => value.Kind == StaticValueKind.Int64);
            var left = arguments[0].AsInt64();
            var right = arguments[1].AsInt64();
            long? value = name switch
            {
                "Min" => Math.Min(left, right),
                "Max" => Math.Max(left, right),
                _ => null
            };
            if (value is { } result)
            {
                return IntrinsicResult.Completed(wide
                    ? StaticValue.FromInt64(result)
                    : StaticValue.FromInt32(unchecked((int)result)));
            }
        }
        if (arguments.Count == 2 && arguments.All(value => value.IsFloatingPoint))
        {
            double? value = name switch
            {
                "Min" => Math.Min(arguments[0].AsFloat64(), arguments[1].AsFloat64()),
                "Max" => Math.Max(arguments[0].AsFloat64(), arguments[1].AsFloat64()),
                "Pow" => Math.Pow(arguments[0].AsFloat64(), arguments[1].AsFloat64()),
                _ => null
            };
            if (value is { } result)
                return IntrinsicResult.Completed(StaticValue.FromFloat64(result));
        }
        if (arguments.Count == 1 && name == "Abs")
        {
            if (arguments[0].Kind == StaticValueKind.Int64)
                return IntrinsicResult.Completed(
                    StaticValue.FromInt64(Math.Abs(arguments[0].AsInt64())));
            if (arguments[0].IsInteger)
                return IntrinsicResult.Completed(
                    StaticValue.FromInt32(Math.Abs(arguments[0].AsInt32())));
            if (arguments[0].IsFloatingPoint)
                return IntrinsicResult.Completed(
                    StaticValue.FromFloat64(Math.Abs(arguments[0].AsFloat64())));
        }
        return IntrinsicResult.Invalid($"Unsupported math operation {name}.");
    }

    /// <summary>Opens the analysed assembly as a read-only stream. Reactor reads its own image
    /// back from disk to hash it, so the stream is backed by the original file bytes.</summary>
    private static IntrinsicResult OpenModuleFileStream(
        IntrinsicContext context,
        IReadOnlyList<StaticValue> arguments)
    {
        var state = context.State;
        var heap = state.Heap;
        if (arguments.Count < 2 || !heap.TryGetString(arguments[1], out var path))
            return IntrinsicResult.Invalid("FileStream path is not concrete.");
        if (state.ModulePath.Length == 0 ||
            !string.Equals(path, state.ModulePath, StringComparison.OrdinalIgnoreCase))
            return IntrinsicResult.Invalid($"File '{path}' is outside the analysed image.");
        if (!heap.TryAllocateByteArray(state.ModuleFileBytes, out var buffer))
            return AllocationFailure("module file stream");
        state.Observe(
            LoaderObservationKind.ModuleFileRead,
            $"FileStream over {state.ModuleFileBytes.Length} module byte(s)");
        var stream = arguments[0];
        heap.TrySetModelValue(stream, "Buffer", buffer);
        heap.TrySetModelValue(stream, "Position", 0L);
        heap.TrySetModelValue(stream, "Origin", 0);
        heap.TrySetModelValue(stream, "Length", state.ModuleFileBytes.Length);
        heap.TrySetModelValue(stream, "Capacity", state.ModuleFileBytes.Length);
        heap.TrySetModelValue(stream, "Writable", false);
        heap.TrySetModelValue(stream, "Expandable", false);
        heap.TrySetModelValue(stream, "PubliclyVisible", true);
        heap.TrySetModelValue(stream, "Open", true);
        return IntrinsicResult.Completed();
    }

    /// <summary>Models a write-mode <c>CryptoStream</c>. Reactor pipes its encrypted key
    /// material through one, so the buffered plaintext must reach the backing stream.</summary>
    private static IntrinsicResult InvokeCryptoStream(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (name == ".ctor")
        {
            if (arguments.Count is not (4 or 5))
                return IntrinsicResult.Invalid("Unsupported CryptoStream constructor.");
            heap.TrySetModelValue(arguments[0], "Target", arguments[1]);
            heap.TrySetModelValue(arguments[0], "Transform", arguments[2]);
            heap.TrySetModelValue(arguments[0], "Pending", new List<byte>());
            heap.TrySetModelValue(arguments[0], "Flushed", false);
            return IntrinsicResult.Completed();
        }
        if (arguments.Count == 0 ||
            !heap.TryGetModelValue(arguments[0], "Pending", out List<byte>? pending) ||
            pending is null)
            return IntrinsicResult.Invalid("CryptoStream is not initialized.");
        switch (name)
        {
            case "get_CanWrite":
                return IntrinsicResult.Completed(StaticValue.FromInt32(1));
            case "get_CanRead":
            case "get_CanSeek":
                return IntrinsicResult.Completed(StaticValue.FromInt32(0));
            case "Flush":
                return IntrinsicResult.Completed();
            case "WriteByte" when arguments.Count == 2:
                pending.Add(unchecked((byte)arguments[1].AsInt32()));
                return IntrinsicResult.Completed();
            case "Write" when arguments.Count == 4:
            {
                var offset = arguments[2].AsInt32();
                var count = arguments[3].AsInt32();
                if (offset < 0 || count < 0)
                    return IntrinsicResult.Invalid("CryptoStream write range is invalid.");
                var chunk = new byte[count];
                if (!heap.TryReadBytes(arguments[1], offset, chunk))
                    return IntrinsicResult.Invalid("CryptoStream write source is unavailable.");
                pending.AddRange(chunk);
                return IntrinsicResult.Completed();
            }
            case "FlushFinalBlock":
            case "Close":
            case "Dispose":
                return FlushCryptoStream(
                    context,
                    arguments[0],
                    pending,
                    name == "FlushFinalBlock");
            default:
                return IntrinsicResult.Invalid($"Unsupported CryptoStream operation {name}.");
        }
    }

    private static IntrinsicResult FlushCryptoStream(
        IntrinsicContext context,
        StaticValue stream,
        List<byte> pending,
        bool required)
    {
        var heap = context.State.Heap;
        if (heap.TryGetModelValue(stream, "Flushed", out bool flushed) && flushed)
            return IntrinsicResult.Completed();
        if (!heap.TryGetModelValue(stream, "Transform", out StaticValue transform) ||
            !heap.TryGetModelValue(stream, "Target", out StaticValue target))
            return IntrinsicResult.Invalid("CryptoStream is not initialized.");
        if (!TryTransformBytes(heap, transform, [.. pending], out var output, out var error))
            return required ? IntrinsicResult.Invalid(error) : IntrinsicResult.Completed();
        heap.TrySetModelValue(stream, "Flushed", true);
        if (output.Length == 0)
            return IntrinsicResult.Completed();
        if (!heap.TryAllocateByteArray(output, out var buffer))
            return AllocationFailure("crypto stream output");
        return InvokeMemoryStream(
            context,
            "Write",
            [target, buffer, StaticValue.FromInt32(0), StaticValue.FromInt32(output.Length)]);
    }

    private static IntrinsicResult InvokeAssembly(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        if (name is "GetExecutingAssembly" or "GetCallingAssembly")
            return context.State.Heap.TryAllocateObject("System.Reflection.Assembly", out var assembly)
                ? IntrinsicResult.Completed(assembly)
                : AllocationFailure("assembly model");
        if (name == "get_Location" && arguments.Count == 1)
            return context.State.Heap.TryAllocateString(
                context.State.ModulePath.Length != 0
                    ? context.State.ModulePath
                    : context.State.AssemblyName + ".dll",
                out var location)
                ? IntrinsicResult.Completed(location)
                : AllocationFailure("assembly location");
        if (name == "GetManifestResourceStream" && arguments.Count == 2 &&
            context.State.Heap.TryGetString(arguments[1], out var resourceName))
            return context.State.TryOpenResource(resourceName, out var stream)
                ? IntrinsicResult.Completed(stream)
                : IntrinsicResult.Invalid($"Resource '{resourceName}' is not registered.");
        if (name == "GetName" && arguments.Count is 1 or 2)
            return context.State.Heap.TryAllocateObject(
                "System.Reflection.AssemblyName",
                out var assemblyName)
                ? IntrinsicResult.Completed(assemblyName)
                : AllocationFailure("assembly name model");
        if (name == "GetModules" && arguments.Count is 1 or 2)
        {
            var heap = context.State.Heap;
            if (!heap.TryAllocateObject("System.Reflection.Module", out var assemblyModule) ||
                !heap.TryAllocateArray(null, 1, out var modules) ||
                !heap.TryWriteArray(modules, 0, assemblyModule))
            {
                return AllocationFailure("module model");
            }
            return IntrinsicResult.Completed(modules);
        }
        return IntrinsicResult.Invalid($"Assembly operation {name} is denied.");
    }

    private static IntrinsicResult InvokeAssemblyName(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        if (arguments.Count != 1)
            return IntrinsicResult.Invalid($"AssemblyName operation {name} is denied.");
        if (name == "GetPublicKeyToken")
        {
            context.State.Observe(
                LoaderObservationKind.StrongNameProbe,
                $"AssemblyName.GetPublicKeyToken of {context.State.PublicKeyToken.Length} byte(s)");
            return context.State.Heap.TryAllocateByteArray(
                context.State.PublicKeyToken,
                out var token)
                ? IntrinsicResult.Completed(token)
                : AllocationFailure("public key token");
        }
        if (name == "get_Name")
            return context.State.Heap.TryAllocateString(context.State.AssemblyName, out var value)
                ? IntrinsicResult.Completed(value)
                : AllocationFailure("assembly name");
        return IntrinsicResult.Invalid($"AssemblyName operation {name} is denied.");
    }

    private static IntrinsicResult InvokeModule(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        if (arguments.Count == 1 && name == "get_ModuleHandle")
            return IntrinsicResult.Completed(arguments[0]);
        if (arguments.Count == 1 && name is "get_Name" or "get_FullyQualifiedName")
        {
            var value = string.IsNullOrEmpty(context.State.AssemblyName)
                ? "module"
                : context.State.AssemblyName + ".dll";
            return context.State.Heap.TryAllocateString(value, out var result)
                ? IntrinsicResult.Completed(result)
                : AllocationFailure("module name");
        }
        return IntrinsicResult.Invalid($"Module operation {name} is denied.");
    }

    private static IntrinsicResult InvokeHashtable(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (name == ".ctor" && arguments.Count is 1 or 2)
        {
            heap.TrySetModelValue(
                arguments[0],
                "Entries",
                new Dictionary<StaticValue, StaticValue>());
            return IntrinsicResult.Completed();
        }
        if (arguments.Count == 0 ||
            !heap.TryGetModelValue(
                arguments[0],
                "Entries",
                out Dictionary<StaticValue, StaticValue>? entries) ||
            entries is null)
        {
            return IntrinsicResult.Invalid("Hashtable is not initialized.");
        }
        if (name == "get_Count" && arguments.Count == 1)
            return IntrinsicResult.Completed(StaticValue.FromInt32(entries.Count));
        if (name is "Add" or "set_Item" && arguments.Count == 3)
        {
            var key = UnboxKey(heap, arguments[1]);
            if (name == "Add" && entries.ContainsKey(key))
                return IntrinsicResult.Invalid("Hashtable duplicate key.");
            entries[key] = arguments[2];
            return IntrinsicResult.Completed();
        }
        if (name == "get_Item" && arguments.Count == 2)
            return IntrinsicResult.Completed(
                entries.GetValueOrDefault(UnboxKey(heap, arguments[1]), StaticValue.Null));
        if (name is "Contains" or "ContainsKey" && arguments.Count == 2)
            return IntrinsicResult.Completed(StaticValue.FromInt32(
                entries.ContainsKey(UnboxKey(heap, arguments[1])) ? 1 : 0));
        return IntrinsicResult.Invalid($"Hashtable operation {name} is denied.");
    }

    private static StaticValue UnboxKey(StaticHeap heap, StaticValue key) =>
        heap.TryUnbox(key, out var value) ? value : key;

    private static IntrinsicResult InvokeProcess(
        IntrinsicContext context,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        if (name == "GetCurrentProcess" && arguments.Count == 0)
            return context.State.Heap.TryAllocateObject(
                "System.Diagnostics.Process",
                out var process)
                ? IntrinsicResult.Completed(process)
                : AllocationFailure("process model");
        if (name == "get_Id" && arguments.Count == 1)
            return IntrinsicResult.Completed(StaticValue.FromInt32(1));
        if (name == "get_Handle" && arguments.Count == 1)
            return IntrinsicResult.Completed(StaticValue.FromInt64(0));
        if (name == "get_Modules" && arguments.Count == 1)
        {
            var heap = context.State.Heap;
            if (!heap.TryAllocateObject(
                    "System.Diagnostics.ProcessModule",
                    out var runtimeModule) ||
                !heap.TryAllocateObject(
                    "System.Diagnostics.ProcessModuleCollection",
                    out var modules))
            {
                return AllocationFailure("process modules");
            }
            if (!heap.TryAllocateRegion(64 * 1024, "RuntimeModule", out var runtimeBase))
                return AllocationFailure("runtime module image");
            heap.TrySetModelValue(runtimeModule, "BaseAddress", runtimeBase);
            heap.TrySetModelValue(runtimeModule, "ModuleName", "clrjit.dll");
            heap.TrySetModelValue(runtimeModule, "MemorySize", 64 * 1024);

            // The loader locates its own module by scanning for the one whose
            // [BaseAddress, BaseAddress + ModuleMemorySize) range covers a mapped-image
            // address, so the protected assembly must appear as a real process module.
            var count = 0;
            if (TryCreateMappedImageModule(context, out var imageModule))
                heap.TrySetModelValue(modules, $"Module{count++}", imageModule);
            heap.TrySetModelValue(modules, $"Module{count++}", runtimeModule);
            heap.TrySetModelValue(modules, "Count", count);
            heap.TrySetModelValue(modules, "RuntimeModule", runtimeModule);
            return IntrinsicResult.Completed(modules);
        }
        if (name is "Dispose" or "Close" && arguments.Count == 1)
            return IntrinsicResult.Completed();
        return IntrinsicResult.Invalid($"Process operation {name} is denied.");
    }

    private static bool TryCreateMappedImageModule(
        IntrinsicContext context,
        out StaticValue module)
    {
        module = StaticValue.Unknown;
        var heap = context.State.Heap;
        if (!context.State.ImageRegion.IsKnown ||
            !heap.TryGetNativePointer(context.State.ImageRegion, 0, out var imageBase) ||
            !heap.TryGetLength(context.State.ImageRegion, out var imageLength) ||
            imageLength <= 0 ||
            !heap.TryAllocateObject("System.Diagnostics.ProcessModule", out module))
        {
            return false;
        }
        heap.TrySetModelValue(module, "BaseAddress", imageBase);
        heap.TrySetModelValue(module, "MemorySize", imageLength);
        heap.TrySetModelValue(
            module,
            "ModuleName",
            string.IsNullOrEmpty(context.State.AssemblyName)
                ? "module.dll"
                : context.State.AssemblyName + ".dll");
        return true;
    }

    private static IntrinsicResult InvokeProcessModule(
        IntrinsicContext context,
        string type,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (type == "System.Diagnostics.ProcessModuleCollection" &&
            arguments.Count == 1 &&
            name == "get_Count")
        {
            return IntrinsicResult.Completed(StaticValue.FromInt32(
                heap.TryGetModelValue(arguments[0], "Count", out int moduleCount)
                    ? moduleCount
                    : 1));
        }
        if (type == "System.Diagnostics.ProcessModuleCollection" &&
            arguments.Count == 2 &&
            name == "get_Item")
        {
            return heap.TryGetModelValue(
                    arguments[0],
                    $"Module{arguments[1].AsInt32()}",
                    out StaticValue indexedModule)
                ? IntrinsicResult.Completed(indexedModule)
                : IntrinsicResult.Invalid("Process module index is out of range.");
        }
        if (type == "System.Diagnostics.ProcessModule" &&
            arguments.Count == 1 &&
            name is "get_ModuleName" or "get_FileName")
        {
            var value = heap.TryGetModelValue(arguments[0], "ModuleName", out string? stored) &&
                !string.IsNullOrEmpty(stored)
                    ? stored
                    : "clrjit.dll";
            return heap.TryAllocateString(value, out var moduleName)
                ? IntrinsicResult.Completed(moduleName)
                : AllocationFailure("runtime module name");
        }
        if (type == "System.Diagnostics.ProcessModule" &&
            arguments.Count == 1 &&
            name == "get_ModuleMemorySize")
        {
            return heap.TryGetModelValue(arguments[0], "MemorySize", out int memorySize)
                ? IntrinsicResult.Completed(StaticValue.FromInt32(memorySize))
                : IntrinsicResult.Invalid("Process module memory size is not modeled.");
        }
        if (type == "System.Diagnostics.ProcessModule" &&
            arguments.Count == 1 &&
            name == "get_BaseAddress")
        {
            if (heap.TryGetModelValue(arguments[0], "BaseAddress", out StaticValue existing))
                return IntrinsicResult.Completed(existing);
            if (!heap.TryAllocateRegion(64 * 1024, "RuntimeModule", out var moduleBase))
                return AllocationFailure("runtime module image");
            heap.TrySetModelValue(arguments[0], "BaseAddress", moduleBase);
            return IntrinsicResult.Completed(moduleBase);
        }
        if (type == "System.Diagnostics.ProcessModule" &&
            arguments.Count == 1 &&
            name == "get_FileVersionInfo")
        {
            return heap.TryAllocateObject(
                "System.Diagnostics.FileVersionInfo",
                out var version)
                ? IntrinsicResult.Completed(version)
                : AllocationFailure("runtime version");
        }
        if (type == "System.Diagnostics.FileVersionInfo" && arguments.Count == 1)
        {
            if (name is "get_FileMajorPart" or "get_ProductMajorPart")
                return IntrinsicResult.Completed(StaticValue.FromInt32(4));
            if (name is "get_FileMinorPart" or "get_ProductMinorPart")
                return IntrinsicResult.Completed(StaticValue.FromInt32(8));
            if (name is "get_FileBuildPart" or "get_ProductBuildPart")
                return IntrinsicResult.Completed(StaticValue.FromInt32(9037));
            if (name is "get_FilePrivatePart" or "get_ProductPrivatePart")
                return IntrinsicResult.Completed(StaticValue.FromInt32(0));
            if (name is "get_FileVersion" or "get_ProductVersion")
                return heap.TryAllocateString("4.8.9037.0", out var versionText)
                    ? IntrinsicResult.Completed(versionText)
                    : AllocationFailure("runtime version string");
        }
        return IntrinsicResult.Invalid($"Process module operation {name} is denied.");
    }

    private static IntrinsicResult InvokeEnumerator(
        IntrinsicContext context,
        string type,
        string name,
        IReadOnlyList<StaticValue> arguments)
    {
        var heap = context.State.Heap;
        if (type == "System.Collections.ReadOnlyCollectionBase" &&
            name == "GetEnumerator" &&
            arguments.Count == 1 &&
            heap.TryGetModelValue(arguments[0], "Count", out int _))
        {
            if (!heap.TryAllocateObject("System.Collections.IEnumerator", out var enumerator))
                return AllocationFailure("module enumerator");
            heap.TrySetModelValue(enumerator, "Collection", arguments[0]);
            heap.TrySetModelValue(enumerator, "Index", -1);
            return IntrinsicResult.Completed(enumerator);
        }
        if (type == "System.Collections.IEnumerator" &&
            name == "MoveNext" &&
            arguments.Count == 1 &&
            heap.TryGetModelValue(arguments[0], "Index", out int index) &&
            heap.TryGetModelValue(arguments[0], "Collection", out StaticValue source) &&
            heap.TryGetModelValue(source, "Count", out int sourceCount))
        {
            var next = index + 1;
            heap.TrySetModelValue(arguments[0], "Index", next);
            return IntrinsicResult.Completed(StaticValue.FromInt32(next < sourceCount ? 1 : 0));
        }
        if (type == "System.Collections.IEnumerator" &&
            name == "get_Current" &&
            arguments.Count == 1 &&
            heap.TryGetModelValue(arguments[0], "Index", out int current) &&
            heap.TryGetModelValue(arguments[0], "Collection", out StaticValue collection) &&
            heap.TryGetModelValue(collection, $"Module{current}", out StaticValue item))
        {
            return IntrinsicResult.Completed(item);
        }
        if (type == "System.IDisposable" && name == "Dispose")
            return IntrinsicResult.Completed();
        return IntrinsicResult.Invalid($"Enumerator operation {name} is denied.");
    }

    private static IntrinsicResult AllocationFailure(string operation) => new(
        StaticExecutionStatus.AllocationLimitExceeded,
        StaticValue.Unknown,
        $"{operation} exceeded the allocation budget.");
}

public sealed class VirtualRegionIntrinsic : IStaticIntrinsic
{
    public bool Matches(IMethod method) =>
        (method.DeclaringType.FullName == "System.Runtime.InteropServices.Marshal" &&
        method.Name.String is "AllocHGlobal" or "FreeHGlobal" or
            "AllocCoTaskMem" or "FreeCoTaskMem" or "Copy" or
            "GetHINSTANCE" or "GetDelegateForFunctionPointer" or
            "ReadByte" or "ReadInt16" or "ReadInt32" or "ReadInt64" or "ReadIntPtr" or
            "WriteByte" or "WriteInt16" or "WriteInt32" or "WriteInt64" or "WriteIntPtr") ||
        (NativeName(method) ?? method.Name.String) is
            "VirtualAlloc" or "VirtualAllocEx" or "VirtualProtect" or
            "WriteProcessMemory" or "LoadLibrary" or "LoadLibraryA" or "LoadLibraryW" or
            "GetModuleHandle" or "GetModuleHandleA" or "GetModuleHandleW" or "GetProcAddress";

    public IntrinsicResult Invoke(
        IntrinsicContext context,
        IMethod method,
        IReadOnlyList<StaticValue> arguments)
    {
        if (arguments.Any(value => !value.IsKnown))
            return IntrinsicResult.Unknown($"{method.FullName} received an unknown value.");
        var heap = context.State.Heap;
        var name = NativeName(method) ?? method.Name.String;
        if (name is "LoadLibrary" or "LoadLibraryA" or "LoadLibraryW" or
            "GetModuleHandle" or "GetModuleHandleA" or "GetModuleHandleW")
        {
            return heap.TryAllocateRegion(64 * 1024, "RuntimeModule", out var module)
                ? IntrinsicResult.Completed(module)
                : new IntrinsicResult(
                    StaticExecutionStatus.AllocationLimitExceeded,
                    StaticValue.Unknown,
                    "Runtime module exceeded the allocation budget.");
        }
        if (name == "GetProcAddress" && arguments.Count == 2 &&
            heap.TryGetString(arguments[1], out var procedureName) &&
            heap.TryGetNativePointer(arguments[0], 0, out var procedure))
        {
            if (!heap.TryAllocateObject("System.IntPtr", out var pointer))
                return IntrinsicResult.Invalid("Could not allocate procedure pointer.");
            heap.TrySetModelValue(pointer, "Pointer", procedure);
            heap.TrySetModelValue(pointer, "NativeName", procedureName);
            return IntrinsicResult.Completed(pointer);
        }
        if (name == "GetDelegateForFunctionPointer" && arguments.Count == 2 &&
            heap.TryGetModelValue(arguments[0], "NativeName", out string? nativeName) &&
            !string.IsNullOrEmpty(nativeName))
        {
            if (!heap.TryAllocateObject("System.Delegate", out var nativeDelegate))
                return IntrinsicResult.Invalid("Could not allocate native delegate.");
            heap.TrySetModelValue(nativeDelegate, "NativeName", nativeName);
            return IntrinsicResult.Completed(nativeDelegate);
        }
        if (name == "GetHINSTANCE" && arguments.Count == 1)
            return heap.TryGetNativePointer(context.State.ImageRegion, 0, out var moduleBase)
                ? IntrinsicResult.Completed(moduleBase)
                : IntrinsicResult.Invalid("Synthetic module image is unavailable.");
        if (name is "AllocHGlobal" or "AllocCoTaskMem" &&
            arguments.Count == 1)
            return heap.TryAllocateRegion(arguments[0].AsInt32(), out var region)
                ? IntrinsicResult.Completed(region)
                : new IntrinsicResult(
                    StaticExecutionStatus.AllocationLimitExceeded,
                    StaticValue.Unknown,
                    "Virtual region exceeded the allocation budget.");
        if (name is "FreeHGlobal" or "FreeCoTaskMem" &&
            arguments.Count == 1)
            return IntrinsicResult.Completed();
        if (name is "VirtualAlloc" or "VirtualAllocEx" && arguments.Count >= 2)
        {
            var sizeIndex = name == "VirtualAllocEx" ? 2 : 1;
            return heap.TryAllocateRegion(
                    arguments[sizeIndex].AsInt32(),
                    "VirtualAlloc",
                    out var region)
                ? IntrinsicResult.Completed(region)
                : new IntrinsicResult(
                    StaticExecutionStatus.AllocationLimitExceeded,
                    StaticValue.Unknown,
                    "VirtualAlloc region exceeded the allocation budget.");
        }
        if (name == "VirtualProtect" && arguments.Count >= 3)
            return IntrinsicResult.Completed(StaticValue.FromInt32(1));
        if (name == "WriteProcessMemory" && arguments.Count >= 4)
        {
            var destination = arguments[1];
            var source = arguments[2];
            var count = arguments[3].AsInt32();
            if (count < 0)
                return IntrinsicResult.Invalid("WriteProcessMemory length is negative.");
            var copied = new byte[count];
            return heap.TryReadBytes(source, 0, copied) &&
                heap.TryWriteBytes(destination, 0, copied)
                    ? IntrinsicResult.Completed(StaticValue.FromInt32(1))
                    : IntrinsicResult.Invalid("WriteProcessMemory range is invalid.");
        }
        if (name == "ReadIntPtr" && arguments.Count is 1 or 2)
        {
            var readOffset = arguments.Count == 2 ? arguments[1].AsInt32() : 0;
            var address = NormalizeAddress(context, arguments[0]);
            Span<byte> pointerBytes = stackalloc byte[8];
            if (!heap.TryReadBytes(
                    address,
                    readOffset,
                    pointerBytes[..context.State.PointerSize]))
                return IntrinsicResult.Invalid("Native IntPtr source is out of bounds.");
            var nativeAddress = context.State.PointerSize == 4
                ? BinaryPrimitives.ReadUInt32LittleEndian(pointerBytes)
                : BinaryPrimitives.ReadInt64LittleEndian(pointerBytes);
            if (heap.TryResolveNativeAddress(nativeAddress, out var concrete))
                return IntrinsicResult.Completed(concrete);
            return IntrinsicResult.Completed(context.State.PointerSize == 4
                ? StaticValue.FromInt32(unchecked((int)nativeAddress))
                : StaticValue.FromInt64(nativeAddress));
        }
        if (name == "WriteIntPtr" && arguments.Count is 2 or 3)
        {
            var destination = arguments[0];
            var writeOffset = arguments.Count == 3 ? arguments[1].AsInt32() : 0;
            var source = arguments[^1];
            if (heap.TryGetModelValue(destination, "Pointer", out StaticValue modeled) &&
                modeled.Kind == StaticValueKind.ManagedReference &&
                writeOffset == 0)
            {
                return heap.TryWriteManaged(modeled, source)
                    ? IntrinsicResult.Completed()
                    : IntrinsicResult.Invalid("Managed IntPtr destination is invalid.");
            }
            destination = NormalizeAddress(context, destination);
            var syntheticAddress =
                source.Kind == StaticValueKind.NativePointer &&
                heap.TryGetNativeAddress(source, out var nativeAddress)
                    ? nativeAddress
                    : source.IsInteger ? source.AsInt64() : 0;
            Span<byte> addressBytes = stackalloc byte[8];
            if (context.State.PointerSize == 4)
                BinaryPrimitives.WriteInt32LittleEndian(
                    addressBytes,
                    unchecked((int)syntheticAddress));
            else
                BinaryPrimitives.WriteInt64LittleEndian(addressBytes, syntheticAddress);
            return heap.TryWriteBytes(
                destination,
                writeOffset,
                addressBytes[..context.State.PointerSize])
                ? IntrinsicResult.Completed()
                : IntrinsicResult.Invalid("Native IntPtr destination is out of bounds.");
        }
        if (name == "Copy" && arguments.Count == 4)
        {
            var count = arguments[3].AsInt32();
            if (count < 0)
                return IntrinsicResult.Invalid("Marshal.Copy length is negative.");
            var sourceIsArray = method.MethodSig?.Params[0].ElementType is
                ElementType.SZArray or ElementType.Array;
            var arrayParameter = sourceIsArray
                ? method.MethodSig?.Params[0]
                : method.MethodSig?.Params[2];
            var elementWidth = MarshalArrayElementWidth(arrayParameter);
            if (elementWidth == 0 ||
                count > heap.MaximumObjectLength / elementWidth)
            {
                return IntrinsicResult.Invalid(
                    "Marshal.Copy array element type or length is invalid.");
            }
            var byteCount = checked(count * elementWidth);
            var arrayByteOffset = arguments[1].AsInt32();
            if (arrayByteOffset < 0 ||
                arrayByteOffset > int.MaxValue / elementWidth)
            {
                return IntrinsicResult.Invalid("Marshal.Copy array index is invalid.");
            }
            arrayByteOffset *= elementWidth;
            var temporary = new byte[byteCount];
            if (sourceIsArray)
                return heap.TryReadBytes(arguments[0], arrayByteOffset, temporary) &&
                    heap.TryWriteBytes(
                        NormalizeAddress(context, arguments[2]),
                        0,
                        temporary)
                    ? IntrinsicResult.Completed()
                    : IntrinsicResult.Invalid("Marshal.Copy array-to-native range is invalid.");
            return heap.TryReadBytes(
                    NormalizeAddress(context, arguments[0]),
                    0,
                    temporary) &&
                heap.TryWriteBytes(arguments[2], arrayByteOffset, temporary)
                    ? IntrinsicResult.Completed()
                    : IntrinsicResult.Invalid("Marshal.Copy native-to-array range is invalid.");
        }

        var width = name switch
        {
            "WriteByte" or "ReadByte" => 1,
            "WriteInt16" or "ReadInt16" => 2,
            "WriteInt32" or "ReadInt32" => 4,
            "WriteInt64" or "ReadInt64" => 8,
            _ => 0
        };
        if (name.StartsWith("Read", StringComparison.Ordinal))
        {
            var readOffset = arguments.Count == 1 ? 0 : arguments[1].AsInt32();
            var address = NormalizeAddress(context, arguments[0]);
            Span<byte> readBytes = stackalloc byte[8];
            if (!heap.TryReadBytes(address, readOffset, readBytes[..width]))
                return IntrinsicResult.Invalid(
                    $"Virtual region read is out of bounds (kind={address.Kind}, " +
                    $"value={address.Bits}, offset={readOffset}, width={width}).");
            return width switch
            {
                1 => IntrinsicResult.Completed(StaticValue.FromInt32(readBytes[0])),
                2 => IntrinsicResult.Completed(StaticValue.FromInt32(
                    BinaryPrimitives.ReadInt16LittleEndian(readBytes))),
                4 => IntrinsicResult.Completed(StaticValue.FromInt32(
                    BinaryPrimitives.ReadInt32LittleEndian(readBytes))),
                8 => IntrinsicResult.Completed(StaticValue.FromInt64(
                    BinaryPrimitives.ReadInt64LittleEndian(readBytes))),
                _ => IntrinsicResult.Invalid($"Unsupported region read {method.FullName}.")
            };
        }
        var offset = arguments.Count == 2 ? 0 : arguments[1].AsInt32();
        var value = arguments[^1].AsInt64();
        Span<byte> bytes = stackalloc byte[8];
        switch (width)
        {
            case 1: bytes[0] = unchecked((byte)value); break;
            case 2: BinaryPrimitives.WriteInt16LittleEndian(bytes, unchecked((short)value)); break;
            case 4: BinaryPrimitives.WriteInt32LittleEndian(bytes, unchecked((int)value)); break;
            case 8: BinaryPrimitives.WriteInt64LittleEndian(bytes, value); break;
            default: return IntrinsicResult.Invalid($"Unsupported region write {method.FullName}.");
        }
        var writeAddress = NormalizeAddress(context, arguments[0]);
        return heap.TryWriteBytes(
            writeAddress,
            offset,
            bytes[..width])
            ? IntrinsicResult.Completed()
            : IntrinsicResult.Invalid(
                $"Virtual region write is out of bounds (kind={writeAddress.Kind}, " +
                $"value={writeAddress.Bits}, offset={offset}, width={width}).");
    }

    private static int MarshalArrayElementWidth(TypeSig? arrayType) =>
        arrayType?.Next?.ElementType switch
        {
            ElementType.I1 or ElementType.U1 => 1,
            ElementType.I2 or ElementType.U2 or ElementType.Char => 2,
            ElementType.I4 or ElementType.U4 or ElementType.R4 => 4,
            ElementType.I8 or ElementType.U8 or ElementType.R8 => 8,
            _ => 0
        };

    private static StaticValue NormalizeAddress(IntrinsicContext context, StaticValue value)
    {
        var heap = context.State.Heap;
        for (var depth = 0; depth < 4; depth++)
        {
            if (heap.TryGetModelValue(value, "Pointer", out StaticValue modeled))
            {
                value = modeled;
                continue;
            }
            if (value.Kind == StaticValueKind.ManagedReference)
                break;
            if (heap.TryReadManaged(value, out var managed))
            {
                value = managed;
                continue;
            }
            break;
        }
        if (value.IsInteger &&
            heap.TryResolveNativeAddress(value.AsInt64(), out var nativeAddress))
        {
            return nativeAddress;
        }
        return value;
    }

    private static string? NativeName(IMethod method) =>
        method.ResolveMethodDef()?.ImplMap?.Name.String;
}
