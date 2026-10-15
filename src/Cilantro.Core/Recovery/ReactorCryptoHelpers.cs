using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Recovery;

/// <summary>Attributes complete Reactor crypto utilities within independently established runtime owners.</summary>
internal static class ReactorCryptoHelpers
{
    internal static IReadOnlyList<MethodDef> Find(ArtifactContext context) =>
        ReactorIntegrityHelpers.Owners(context).SelectMany(Recognize).ToArray();

    internal static IReadOnlyList<MethodDef> Recognize(TypeDef owner)
    {
        var result = new HashSet<MethodDef>();
        foreach (var selector in owner.Methods.Where(IsSelector))
        {
            result.Add(selector);
            foreach (var method in owner.NestedTypes.SelectMany(t => t.Methods))
                if (IsStringEncryptor(method, selector)) result.Add(method);
        }
        foreach (var method in owner.Methods)
            if (TryDecryptor(method, out var dependencies))
            {
                result.Add(method);
                foreach (var adapter in owner.Methods.Where(m => IsLocalAdapter(m, dependencies))) result.Add(adapter);
            }
        return result.ToArray();
    }

    private static bool TryDecryptor(MethodDef method, out HashSet<MethodDef> dependencies)
    {
        dependencies = [];
        if (!Plain(method) || method.Body.HasExceptionHandlers || method.Parameters.Count != 1 || !Bytes(method.ReturnType) ||
            !(Bytes(method.Parameters[0].Type) || method.Parameters[0].Type.ElementType == ElementType.Object) ||
            method.Body.Variables.Count != 2 || method.Body.Variables[0].Type.FullName != "System.IO.Stream" ||
            method.Body.Variables[1].Type.FullName != "System.Security.Cryptography.SymmetricAlgorithm") return false;
        var il = Instructions(method);
        if (il.Length != 34 || il[0].Operand is not IMethod streamCall || streamCall.ResolveMethodDef() is not { } stream ||
            il[2].Operand is not IMethod factoryCall || factoryCall.ResolveMethodDef() is not { } factory ||
            il[32].Operand is not IMethod arrayCall || arrayCall.ResolveMethodDef() is not { } array ||
            new[] { stream, factory, array }.Any(m => m.DeclaringType != method.DeclaringType) ||
            !IsFactory(factory) || !IsStreamCreator(stream) || !IsArrayConverter(array)) return false;
        var roles = new Dictionary<MethodDef, string> { [stream] = "stream", [factory] = "factory", [array] = "array" };
        var tokens = Tokens(method, roles);
        if (tokens is null || !tokens.SequenceEqual(DecryptorBody)) return false;
        dependencies.UnionWith(roles.Keys); return true;
    }

    private static bool IsStreamCreator(MethodDef method)
    {
        if (!Plain(method) || method.Parameters.Count != 0 || method.ReturnType.FullName != "System.IO.Stream" || method.Body.HasExceptionHandlers || method.Body.Variables.Count != 0) return false;
        return Tokens(method, [])?.SequenceEqual(StreamCreatorBody) == true;
    }
    private static bool IsArrayConverter(MethodDef method)
    {
        if (!Plain(method) || method.Parameters.Count != 1 ||
            !(method.Parameters[0].Type.FullName == "System.IO.Stream" || method.Parameters[0].Type.ElementType == ElementType.Object) ||
            !Bytes(method.ReturnType) || method.Body.HasExceptionHandlers || method.Body.Variables.Count != 0) return false;
        return Tokens(method, [])?.SequenceEqual(ArrayConverterBody) == true;
    }
    private static bool IsLocalAdapter(MethodDef method, HashSet<MethodDef> targets)
    {
        if (!Plain(method) || method.Body.HasExceptionHandlers || method.Body.Variables.Count != 0 || method.ReturnType.ElementType != ElementType.Object) return false;
        var il = Instructions(method);
        if (il.Length != method.Parameters.Count + 2 || il[^1].OpCode.Code != Code.Ret || il[^2].OpCode.Code != Code.Call ||
            il[^2].Operand is not IMethod called || called.ResolveMethodDef() is not { } target || !targets.Contains(target) ||
            target.Parameters.Count != method.Parameters.Count) return false;
        for (var index = 0; index < method.Parameters.Count; index++)
            if (!il[index].IsLdarg() || il[index].GetParameter(method.Parameters)?.Index != index ||
                !(new SigComparer().Equals(method.Parameters[index].Type, target.Parameters[index].Type) ||
                  method.Parameters[index].Type.ElementType == ElementType.Object && !target.Parameters[index].Type.IsValueType)) return false;
        return true;
    }
    private static bool IsFactory(MethodDef method)
    {
        if (!Plain(method) || method.Parameters.Count != 0 || method.ReturnType.FullName != "System.Security.Cryptography.SymmetricAlgorithm" ||
            method.Body.Variables.Count != 1 || method.Body.Variables[0].Type.FullName != method.ReturnType.FullName || method.Body.ExceptionHandlers.Count != 2) return false;
        var il = Instructions(method);
        if (il.Length != 29 || il[2].Operand is not IMethod called || called.ResolveMethodDef() is not { } policy ||
            policy.DeclaringType != method.DeclaringType || !IsPolicy(policy) ||
            Tokens(method, new() { [policy] = "policy" })?.SequenceEqual(FactoryBody) != true) return false;
        return method.Body.ExceptionHandlers.Any(h => Region(h, 11, 18, 18, 26)) && method.Body.ExceptionHandlers.Any(h => Region(h, 7, 10, 10, 27));
        bool Region(ExceptionHandler h, int start, int end, int handler, int finish) =>
            h.HandlerType == ExceptionHandlerType.Catch && h.FilterStart is null && h.CatchType is TypeRef type && Core(type) && type.FullName is "System.Object" or "System.Exception" &&
            Next(h.TryStart, method) == il[start] && Next(h.TryEnd, method) == il[end] && Next(h.HandlerStart, method) == il[handler] && Next(h.HandlerEnd, method) == il[finish];
    }

    internal static List<string>? Tokens(MethodDef method, Dictionary<MethodDef, string> roles)
    {
        var il = Instructions(method); var tokens = new List<string>();
        foreach (var instruction in il)
        {
            if (instruction.IsLdarg()) { tokens.Add("arg" + instruction.GetParameter(method.Parameters)?.Index); continue; }
            if (instruction.IsLdloc()) { tokens.Add("load" + instruction.GetLocal(method.Body.Variables)?.Index); continue; }
            if (instruction.IsStloc()) { tokens.Add("store" + instruction.GetLocal(method.Body.Variables)?.Index); continue; }
            if (instruction.IsLdcI4()) { tokens.Add("int" + instruction.GetLdcI4Value()); continue; }
            if (instruction.Operand is Instruction branch)
            { tokens.Add(instruction.OpCode.Code.ToString().Replace("_S", "", StringComparison.Ordinal) + ":" + Array.IndexOf(il, Next(branch, method))); continue; }
            if (instruction.OpCode.Code == Code.Ldstr) { tokens.Add("text:" + instruction.Operand); continue; }
            if (instruction.OpCode.Code == Code.Ldtoken && instruction.Operand is IField field && field.ResolveFieldDef() is { IsStatic: true, HasFieldRVA: true } data && data.InitialValue?.Length is 16 or 32)
            { tokens.Add("data" + data.InitialValue.Length); continue; }
            if (instruction.Operand is TypeRef type && Core(type)) { tokens.Add(instruction.OpCode.Code + ":" + type.FullName); continue; }
            if (instruction.Operand is IMethod member)
            {
                if (instruction.OpCode.Code == Code.Call && member.ResolveMethodDef() is { } local && roles.TryGetValue(local, out var role)) { tokens.Add(role); continue; }
                if (member is not MemberRef { DeclaringType: TypeRef owner } ||
                    !(Core(owner) || owner.FullName == "System.Security.Cryptography.AesCryptoServiceProvider" && owner.DefinitionAssembly?.Name.String == "System.Core")) return null;
                tokens.Add(instruction.OpCode.Code + ":" + member.FullName); continue;
            }
            if (instruction.Operand is not null) return null;
            tokens.Add(instruction.OpCode.Code.ToString());
        }
        return tokens;
    }
    private static readonly string[] StreamCreatorBody = ["Newobj:System.Void System.IO.MemoryStream::.ctor()", "Ret"];
    private static readonly string[] ArrayConverterBody = ["arg0", "Castclass:System.IO.MemoryStream", "Callvirt:System.Byte[] System.IO.MemoryStream::ToArray()", "Ret"];
    private static readonly string[] DecryptorBody = [
        "stream", "store0", "factory", "store1", "load1", "int32", "Newarr:System.Byte", "Dup", "data32",
        "Call:System.Void System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(System.Array,System.RuntimeFieldHandle)",
        "Callvirt:System.Void System.Security.Cryptography.SymmetricAlgorithm::set_Key(System.Byte[])", "load1", "int16", "Newarr:System.Byte", "Dup", "data16",
        "Call:System.Void System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(System.Array,System.RuntimeFieldHandle)",
        "Callvirt:System.Void System.Security.Cryptography.SymmetricAlgorithm::set_IV(System.Byte[])", "load0", "load1",
        "Callvirt:System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.SymmetricAlgorithm::CreateDecryptor()", "int1",
        "Newobj:System.Void System.Security.Cryptography.CryptoStream::.ctor(System.IO.Stream,System.Security.Cryptography.ICryptoTransform,System.Security.Cryptography.CryptoStreamMode)",
        "Dup", "arg0", "int0", "arg0", "Ldlen", "Conv_I4", "Callvirt:System.Void System.IO.Stream::Write(System.Byte[],System.Int32,System.Int32)",
        "Callvirt:System.Void System.IO.Stream::Close()", "load0", "array", "Ret"
    ];
    private static readonly string[] FactoryBody = [
        "Ldnull", "store0", "policy", "Brfalse:7", "Newobj:System.Void System.Security.Cryptography.AesCryptoServiceProvider::.ctor()", "store0", "Br:27",
        "Newobj:System.Void System.Security.Cryptography.RijndaelManaged::.ctor()", "store0", "Leave:27", "Pop",
        "text:System.Core, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089", "text:System.Security.Cryptography.AesCryptoServiceProvider",
        "Call:System.Runtime.Remoting.ObjectHandle System.Activator::CreateInstance(System.String,System.String)", "Callvirt:System.Object System.Runtime.Remoting.ObjectHandle::Unwrap()",
        "Castclass:System.Security.Cryptography.SymmetricAlgorithm", "store0", "Leave:26", "Pop",
        "text:System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089", "text:System.Security.Cryptography.AesCryptoServiceProvider",
        "Call:System.Runtime.Remoting.ObjectHandle System.Activator::CreateInstance(System.String,System.String)", "Callvirt:System.Object System.Runtime.Remoting.ObjectHandle::Unwrap()",
        "Castclass:System.Security.Cryptography.SymmetricAlgorithm", "store0", "Leave:26", "Leave:27", "load0", "Ret"
    ];

    // Reactor carries a dormant Unicode/Base64 encryption utility beside its
    // MD5 selector. Match the complete body, argument/local binding and exact
    // framework overloads; a mere call to the selector does not confer ownership.
    internal static bool IsStringEncryptor(MethodDef method, MethodDef selector)
    {
        if (!Plain(method) || method.Body.HasExceptionHandlers || method.Parameters.Count != 2 ||
            method.Parameters.Any(p => p.Type.ElementType != ElementType.String) || method.ReturnType.ElementType != ElementType.String ||
            method.Body.Variables.Count != 4 || method.Body.Variables.Take(3).Any(v => !Bytes(v.Type)) ||
            method.Body.Variables[3].Type.FullName != "System.Security.Cryptography.SymmetricAlgorithm") return false;
        var il = Instructions(method);
        var tokens = new List<string>();
        foreach (var instruction in il)
        {
            if (instruction.IsLdarg()) { tokens.Add("arg" + instruction.GetParameter(method.Parameters)?.Index); continue; }
            if (instruction.IsLdloc()) { tokens.Add("load" + instruction.GetLocal(method.Body.Variables)?.Index); continue; }
            if (instruction.IsStloc()) { tokens.Add("store" + instruction.GetLocal(method.Body.Variables)?.Index); continue; }
            if (instruction.IsLdcI4()) { tokens.Add("int" + instruction.GetLdcI4Value()); continue; }
            if (instruction.OpCode.Code == Code.Ldtoken && instruction.Operand is IField field && field.ResolveFieldDef() is { IsStatic: true, HasFieldRVA: true, InitialValue.Length: 32 })
            { tokens.Add("key32"); continue; }
            if (instruction.OpCode.Code == Code.Newarr && instruction.Operand is TypeRef element && element.FullName == "System.Byte" && Core(element))
            { tokens.Add("bytes"); continue; }
            if (instruction.Operand is IMethod called)
            {
                if (instruction.OpCode.Code == Code.Call && called.ResolveMethodDef() == selector) { tokens.Add("selector"); continue; }
                if (instruction.OpCode.Code == Code.Call && called.ResolveMethodDef() is { } factory && factory.DeclaringType == selector.DeclaringType &&
                    Plain(factory) && factory.Parameters.Count == 0 && factory.ReturnType.FullName == "System.Security.Cryptography.SymmetricAlgorithm")
                { tokens.Add("factory"); continue; }
                if (called is not MemberRef { DeclaringType: TypeRef owner } || !Core(owner)) return false;
                tokens.Add(instruction.OpCode.Code + ":" + called.FullName); continue;
            }
            if (instruction.Operand is not null) return false;
            tokens.Add(instruction.OpCode.Code.ToString());
        }
        return tokens.SequenceEqual(EncryptorBody);
    }

    private static readonly string[] EncryptorBody = [
        "Call:System.Text.Encoding System.Text.Encoding::get_Unicode()", "arg0",
        "Callvirt:System.Byte[] System.Text.Encoding::GetBytes(System.String)", "store0", "int32", "bytes", "Dup", "key32",
        "Call:System.Void System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(System.Array,System.RuntimeFieldHandle)", "store1",
        "Call:System.Text.Encoding System.Text.Encoding::get_Unicode()", "arg1", "Callvirt:System.Byte[] System.Text.Encoding::GetBytes(System.String)",
        "selector", "store2", "Newobj:System.Void System.IO.MemoryStream::.ctor()", "factory", "store3", "load3", "load1",
        "Callvirt:System.Void System.Security.Cryptography.SymmetricAlgorithm::set_Key(System.Byte[])", "load3", "load2",
        "Callvirt:System.Void System.Security.Cryptography.SymmetricAlgorithm::set_IV(System.Byte[])", "Dup", "load3",
        "Callvirt:System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.SymmetricAlgorithm::CreateEncryptor()", "int1",
        "Newobj:System.Void System.Security.Cryptography.CryptoStream::.ctor(System.IO.Stream,System.Security.Cryptography.ICryptoTransform,System.Security.Cryptography.CryptoStreamMode)",
        "Dup", "load0", "int0", "load0", "Ldlen", "Conv_I4", "Callvirt:System.Void System.IO.Stream::Write(System.Byte[],System.Int32,System.Int32)",
        "Callvirt:System.Void System.IO.Stream::Close()", "Callvirt:System.Byte[] System.IO.MemoryStream::ToArray()",
        "Call:System.String System.Convert::ToBase64String(System.Byte[])", "Ret"
    ];

    internal static bool IsSelector(MethodDef method)
    {
        if (!Plain(method) || method.Body.HasExceptionHandlers || method.Body.Variables.Count != 0 ||
            method.Parameters.Count != 1 || !Bytes(method.ReturnType) ||
            !(Bytes(method.Parameters[0].Type) || method.Parameters[0].Type.ElementType == ElementType.Object)) return false;
        var il = Instructions(method);
        return il.Length == 9 && il[0].OpCode.Code == Code.Call &&
            il[0].Operand is IMethod policy && policy.ResolveMethodDef() is { } getter &&
            getter.DeclaringType == method.DeclaringType && IsPolicy(getter) &&
            il[1].OpCode.Code is Code.Brtrue or Code.Brtrue_S && il[1].Operand == il[6] &&
            il[2].OpCode.Code == Code.Newobj && Framework(il[2], "System.Security.Cryptography.MD5CryptoServiceProvider", ".ctor", ElementType.Void, true, 0) &&
            Argument(il[3], method) && il[4].OpCode.Code is Code.Call or Code.Callvirt &&
            Framework(il[4], "System.Security.Cryptography.HashAlgorithm", "ComputeHash", ElementType.SZArray, true, 1) &&
            il[4].Operand is IMethod compute && Bytes(compute.MethodSig.RetType) && Bytes(compute.MethodSig.Params[0]) &&
            il[5].OpCode.Code == Code.Ret && Argument(il[6], method) && il[7].OpCode.Code == Code.Call &&
            il[7].Operand is IMethod fallback && fallback.ResolveMethodDef() is { } implementation &&
            implementation != method && implementation.DeclaringType == method.DeclaringType && Plain(implementation) &&
            new SigComparer().Equals(implementation.MethodSig, method.MethodSig) && il[8].OpCode.Code == Code.Ret;
    }

    private static bool IsPolicy(MethodDef method)
    {
        if (!Plain(method) || method.Parameters.Count != 0 || method.ReturnType.ElementType != ElementType.Boolean ||
            method.Body.HasExceptionHandlers || method.Body.Variables.Count != 0) return false;
        var il = Instructions(method);
        if (il.Length != 7 || il[0].OpCode.Code != Code.Ldsfld ||
            il[0].Operand is not IField first || first.ResolveFieldDef() is not { } ready ||
            il[1].OpCode.Code is not (Code.Brtrue or Code.Brtrue_S) || il[1].Operand != il[5] ||
            il[2].OpCode.Code != Code.Call || il[2].Operand is not IMethod call || call.ResolveMethodDef() is not { } initialize ||
            !il[3].IsLdcI4() || il[3].GetLdcI4Value() != 1 || il[4].OpCode.Code != Code.Stsfld ||
            il[4].Operand is not IField written || written.ResolveFieldDef() != ready ||
            il[5].OpCode.Code != Code.Ldsfld || il[5].Operand is not IField second || second.ResolveFieldDef() is not { } policy ||
            il[6].OpCode.Code != Code.Ret || ready == policy || !Flag(ready, method.DeclaringType) || !Flag(policy, method.DeclaringType)) return false;
        return initialize.DeclaringType == method.DeclaringType && IsPolicyInitializer(initialize, policy);
    }

    private static bool IsPolicyInitializer(MethodDef method, FieldDef policy)
    {
        if (!Plain(method) || method.Parameters.Count != 0 || method.ReturnType.ElementType != ElementType.Void ||
            method.Body.Variables.Count != 0 || method.Body.ExceptionHandlers.Count != 2) return false;
        var il = Instructions(method);
        if (il.Length != 13 || il[0].OpCode.Code != Code.Newobj ||
            !Framework(il[0], "System.Security.Cryptography.MD5CryptoServiceProvider", ".ctor", ElementType.Void, true, 0) ||
            il[1].OpCode.Code != Code.Pop || !Leave(il[2], il[7], method) || il[3].OpCode.Code != Code.Pop ||
            !il[4].IsLdcI4() || il[4].GetLdcI4Value() != 1 || !Write(il[5]) || !Leave(il[6], il[12], method) ||
            il[7].OpCode.Code != Code.Call ||
            !Framework(il[7], "System.Security.Cryptography.CryptoConfig", "get_AllowOnlyFipsAlgorithms", ElementType.Boolean, false, 0) ||
            !Write(il[8]) || !Leave(il[9], il[12], method) || il[10].OpCode.Code != Code.Pop ||
            !Leave(il[11], il[12], method) || il[12].OpCode.Code != Code.Ret) return false;
        var handlers = method.Body.ExceptionHandlers;
        return handlers.Any(h => Catch(h, il[0], il[3], il[7])) && handlers.Any(h => Catch(h, il[7], il[10], il[12]));

        bool Write(Instruction instruction) => instruction.OpCode.Code == Code.Stsfld && instruction.Operand is IField field && field.ResolveFieldDef() == policy;
        bool Catch(ExceptionHandler handler, Instruction start, Instruction handlerStart, Instruction end) =>
            handler.HandlerType == ExceptionHandlerType.Catch && handler.CatchType is TypeRef type &&
            type.FullName is "System.Exception" or "System.Object" && Core(type) &&
            Next(handler.TryStart, method) == start && Next(handler.TryEnd, method) == handlerStart &&
            Next(handler.HandlerStart, method) == handlerStart && Next(handler.HandlerEnd, method) == end;
    }

    private static Instruction? Next(Instruction? instruction, MethodDef method)
    {
        if (instruction is null) return null;
        var index = method.Body.Instructions.IndexOf(instruction);
        if (index < 0) return null;
        while (index < method.Body.Instructions.Count && method.Body.Instructions[index].OpCode.Code == Code.Nop) index++;
        return index < method.Body.Instructions.Count ? method.Body.Instructions[index] : null;
    }

    private static bool Leave(Instruction instruction, Instruction target, MethodDef method) =>
        instruction.OpCode.Code is Code.Leave or Code.Leave_S && Next(instruction.Operand as Instruction, method) == target;
    private static bool Flag(FieldDef field, TypeDef owner) => field.DeclaringType == owner && field.IsStatic && field.FieldType.ElementType == ElementType.Boolean;
    private static bool Plain(MethodDef method) => method.IsStatic && !method.IsConstructor && !method.IsVirtual &&
        !method.HasGenericParameters && !method.DeclaringType.HasGenericParameters && method.HasBody && method.CustomAttributes.Count == 0;
    private static Instruction[] Instructions(MethodDef method) => method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
    private static bool Argument(Instruction instruction, MethodDef method) => instruction.IsLdarg() && instruction.GetParameter(method.Parameters)?.Index == 0;
    private static bool Bytes(TypeSig type) => type is SZArraySig { Next.ElementType: ElementType.U1 };
    private static bool Core(TypeRef type) => type.DefinitionAssembly?.Name.String is "mscorlib" or "System.Private.CoreLib";
    private static bool Framework(Instruction instruction, string owner, string name, ElementType result, bool instance, int parameters) =>
        instruction.Operand is MemberRef { DeclaringType: TypeRef type, MethodSig: { } signature } member &&
        type.FullName == owner && Core(type) && member.Name == name && signature.RetType.ElementType == result &&
        signature.HasThis == instance && signature.Params.Count == parameters && signature.GenParamCount == 0;
}
