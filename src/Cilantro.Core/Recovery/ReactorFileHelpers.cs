using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Complete file utilities observed in the benign protected Reactor runtime.</summary>
internal static class ReactorFileHelpers
{
    private static readonly string[] ReaderLocals = ["System.Byte[]", "System.IO.FileStream", "System.Int32", "System.Int32", "System.Int32"];
    internal static IReadOnlyList<MethodDef> Find(ArtifactContext context) =>
        ReactorIntegrityHelpers.Owners(context).SelectMany(t => t.Methods).Where(Recognize).ToArray();

    internal static bool Recognize(MethodDef method)
    {
        if (!method.IsStatic || method.IsConstructor || method.IsVirtual || method.HasGenericParameters ||
            method.DeclaringType.HasGenericParameters || method.HasCustomAttributes || !method.HasBody ||
            method.Parameters.Count != 1 || method.Parameters[0].Type.ElementType != ElementType.Object) return false;
        var il = method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        if (il.Length is not (41 or 65)) return false;
        var tokens = ReactorCryptoHelpers.Tokens(method, []);
        if (tokens is null) return false;
        if (method.ReturnType.FullName == "System.Byte[]" &&
            method.Body.Variables.Select(v => v.Type.FullName).SequenceEqual(ReaderLocals) &&
            tokens.SequenceEqual(Reader) && method.Body.ExceptionHandlers.Count == 1)
        {
            var handler = method.Body.ExceptionHandlers[0];
            return handler.HandlerType == ExceptionHandlerType.Finally && handler.CatchType is null &&
                Region(handler, 6, 34, 34, 39);
        }
        if (method.ReturnType.ElementType != ElementType.Object || method.Body.Variables.Count != 1 ||
            method.Body.Variables[0].Type.ElementType != ElementType.Object || !tokens.SequenceEqual(Location) ||
            method.Body.ExceptionHandlers.Count != 3) return false;
        return Catch(0, 11, 11, 13) && Catch(13, 34, 34, 36) && Catch(36, 59, 59, 61);

        bool Catch(int start, int end, int handler, int finish) => method.Body.ExceptionHandlers.Any(h =>
            h.HandlerType == ExceptionHandlerType.Catch && h.CatchType is TypeRef type &&
            type.FullName == "System.Object" && type.DefinitionAssembly?.Name.String is "mscorlib" or "System.Private.CoreLib" &&
            Region(h, start, end, handler, finish));
        bool Region(ExceptionHandler h, int start, int end, int handler, int finish) => h.FilterStart is null &&
            Next(h.TryStart) == il[start] && Next(h.TryEnd) == il[end] &&
            Next(h.HandlerStart) == il[handler] && Next(h.HandlerEnd) == il[finish];
        Instruction? Next(Instruction? instruction)
        {
            if (instruction is null) return null;
            var index = method.Body.Instructions.IndexOf(instruction);
            if (index < 0) return null;
            while (index < method.Body.Instructions.Count && method.Body.Instructions[index].OpCode.Code == Code.Nop) index++;
            return index < method.Body.Instructions.Count ? method.Body.Instructions[index] : null;
        }
    }
    private static readonly string[] Reader =
    [
        "arg0",
        "int3",
        "int1",
        "int1",
        "Newobj:System.Void System.IO.FileStream::.ctor(System.String,System.IO.FileMode,System.IO.FileAccess,System.IO.FileShare)",
        "store1",
        "int0",
        "store2",
        "load1",
        "Callvirt:System.Int64 System.IO.Stream::get_Length()",
        "Conv_I4",
        "store3",
        "load3",
        "Newarr:System.Byte",
        "store0",
        "Br:30",
        "load1",
        "load0",
        "load2",
        "load3",
        "Callvirt:System.Int32 System.IO.Stream::Read(System.Byte[],System.Int32,System.Int32)",
        "store4",
        "load2",
        "load4",
        "Add",
        "store2",
        "load3",
        "load4",
        "Sub",
        "store3",
        "load3",
        "int0",
        "Bgt:16",
        "Leave:39",
        "load1",
        "Brfalse:38",
        "load1",
        "Callvirt:System.Void System.IDisposable::Dispose()",
        "Endfinally",
        "load0",
        "Ret",
    ];
    private static readonly string[] Location =
    [
        "arg0",
        "Castclass:System.Reflection.Assembly",
        "Callvirt:System.String System.Reflection.Assembly::get_Location()",
        "Call:System.Boolean System.IO.File::Exists(System.String)",
        "Brfalse:10",
        "arg0",
        "Castclass:System.Reflection.Assembly",
        "Callvirt:System.String System.Reflection.Assembly::get_Location()",
        "store0",
        "Leave:63",
        "Leave:13",
        "Pop",
        "Leave:13",
        "arg0",
        "Castclass:System.Reflection.Assembly",
        "Callvirt:System.Reflection.AssemblyName System.Reflection.Assembly::GetName()",
        "Callvirt:System.String System.Reflection.AssemblyName::get_CodeBase()",
        "Callvirt:System.String System.Object::ToString()",
        "text:file:///",
        "text:",
        "Callvirt:System.String System.String::Replace(System.String,System.String)",
        "Call:System.Boolean System.IO.File::Exists(System.String)",
        "Brfalse:33",
        "arg0",
        "Castclass:System.Reflection.Assembly",
        "Callvirt:System.Reflection.AssemblyName System.Reflection.Assembly::GetName()",
        "Callvirt:System.String System.Reflection.AssemblyName::get_CodeBase()",
        "Callvirt:System.String System.Object::ToString()",
        "text:file:///",
        "text:",
        "Callvirt:System.String System.String::Replace(System.String,System.String)",
        "store0",
        "Leave:63",
        "Leave:36",
        "Pop",
        "Leave:36",
        "arg0",
        "Callvirt:System.Type System.Object::GetType()",
        "text:Location",
        "Callvirt:System.Reflection.PropertyInfo System.Type::GetProperty(System.String)",
        "arg0",
        "int0",
        "Newarr:System.Object",
        "Callvirt:System.Object System.Reflection.PropertyInfo::GetValue(System.Object,System.Object[])",
        "Callvirt:System.String System.Object::ToString()",
        "Call:System.Boolean System.IO.File::Exists(System.String)",
        "Brfalse:58",
        "arg0",
        "Callvirt:System.Type System.Object::GetType()",
        "text:Location",
        "Callvirt:System.Reflection.PropertyInfo System.Type::GetProperty(System.String)",
        "arg0",
        "int0",
        "Newarr:System.Object",
        "Callvirt:System.Object System.Reflection.PropertyInfo::GetValue(System.Object,System.Object[])",
        "Callvirt:System.String System.Object::ToString()",
        "store0",
        "Leave:63",
        "Leave:61",
        "Pop",
        "Leave:61",
        "text:",
        "Ret",
        "load0",
        "Ret",
    ];
}
