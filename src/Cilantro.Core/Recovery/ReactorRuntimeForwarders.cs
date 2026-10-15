using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;

namespace Cilantro.Core.Recovery;

/// <summary>Erased-argument forwarding thunks on independently recovered Reactor runtime owners.</summary>
internal static class ReactorRuntimeForwarders
{
    internal static IReadOnlyList<MethodDef> Find(ArtifactContext context)
    {
        var owners = ReactorIntegrityHelpers.Owners(context);
        var adapters = owners.SelectMany(t => t.NestedTypes).Where(IsReaderAdapter).SelectMany(t => t.Methods).ToHashSet();
        return owners.SelectMany(t => t.Methods).Where(m => IsForwarder(m, adapters)).ToArray();
    }

    internal static void CaptureReaderAdapters(ArtifactContext context)
    {
        foreach (var type in ReactorIntegrityHelpers.Owners(context).SelectMany(t => t.NestedTypes).Where(IsReaderAdapter))
        {
            if (type.Methods.Any(m => !RecoveryOrphans.Of(context).Contains(m.MDToken.Raw)))
                context.AddEvidence(new Evidence("reader-adapter-ownership",
                    "Recognized the complete four-operation BinaryReader adapter under an independently recovered string/proxy runtime owner; deletion still requires deadness, visibility and surviving-reference checks.", type.FullName));
            RecoveryOrphans.Declare(context, type.Methods);
        }
    }

    internal static bool IsReaderAdapter(TypeDef type)
    {
        if (!type.IsNested || type.HasGenericParameters || type.Interfaces.Count != 0 || type.HasCustomAttributes ||
            type.NestedTypes.Count != 0 || type.Events.Count != 0 || type.Fields.Count != 1 || type.Methods.Count != 4 ||
            type.BaseType is not TypeRef { FullName: "System.Object" } || type.Fields[0] is not { IsStatic: false } field ||
            field.FieldType.ToTypeDefOrRef() is not TypeRef { FullName: "System.IO.BinaryReader" } reader ||
            reader.DefinitionAssembly?.Name.String is not ("mscorlib" or "System.Private.CoreLib")) return false;
        var operations = new HashSet<string>(StringComparer.Ordinal);
        foreach (var method in type.Methods)
        {
            if (method.IsStatic || method.IsConstructor || method.IsVirtual || method.HasGenericParameters ||
                !method.HasBody || method.Body.HasExceptionHandlers || method.Body.Variables.Count != 0 || method.HasCustomAttributes) return false;
            var il = method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
            if (il.Length != method.Parameters.Count + 3 || !il[0].IsLdarg() || il[0].GetParameter(method.Parameters)?.Index != 0 ||
                il[1].OpCode.Code != Code.Ldfld || il[1].Operand is not IField loaded || loaded.ResolveFieldDef() != field ||
                il[^2].OpCode.Code != Code.Callvirt || il[^1].OpCode.Code != Code.Ret ||
                il[^2].Operand is not MemberRef { DeclaringType: TypeRef owner, MethodSig: { } signature } target ||
                !new SigComparer().Equals(reader, owner) || !new SigComparer().Equals(method.MethodSig, signature) ||
                !ReaderOperations.Contains(target.FullName) || !operations.Add(target.FullName)) return false;
            for (var index = 1; index < method.Parameters.Count; index++)
                if (!il[index + 1].IsLdarg() || il[index + 1].GetParameter(method.Parameters)?.Index != index) return false;
        }
        // Properties may only name an already checked getter; no accessor can
        // smuggle a fifth operation or leave another method outside this proof.
        return type.Properties.All(p => p.SetMethod is null && p.GetMethod is { } getter && type.Methods.Contains(getter) &&
            p.OtherMethods.Count == 0 && getter.MethodSig.Params.Count == 0 && getter.ReturnType.FullName == "System.IO.Stream");
    }

    private static readonly HashSet<string> ReaderOperations = new(StringComparer.Ordinal) {
        "System.IO.Stream System.IO.BinaryReader::get_BaseStream()",
        "System.Byte[] System.IO.BinaryReader::ReadBytes(System.Int32)",
        "System.Int32 System.IO.BinaryReader::Read(System.Byte[],System.Int32,System.Int32)",
        "System.Void System.IO.BinaryReader::Close()"
    };

    private static bool IsErasedForwarder(MethodDef method) => IsForwarder(method, null);

    private static bool IsForwarder(MethodDef method, HashSet<MethodDef>? adapters)
    {
        if (!method.IsStatic || method.IsConstructor || method.IsVirtual || method.HasGenericParameters ||
            method.DeclaringType.HasGenericParameters || !method.HasBody || method.Body.HasExceptionHandlers ||
            method.Body.Variables.Count != 0 || method.CustomAttributes.Count != 0) return false;
        var il = method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        if (il.Length != method.Parameters.Count + 2 || il[^1].OpCode.Code != Code.Ret ||
            il[^2].OpCode.Code is not (Code.Call or Code.Callvirt) ||
            il[^2].Operand is not IMethod { MethodSig: { } signature } target ||
            signature.GenParamCount != 0 || signature.CallingConvention is not (CallingConvention.Default or CallingConvention.HasThis)) return false;
        var framework = target is MemberRef { DeclaringType: TypeRef external } &&
            external.DefinitionAssembly?.Name.String is ("mscorlib" or "System.Private.CoreLib" or "System.Runtime" or
                "System.IO" or "System.Reflection" or "System.Security.Cryptography.Algorithms" or "System.Security.Cryptography.Primitives");
        framework = framework && target.DeclaringType is TypeRef name &&
            (name.Namespace.String == "System" || name.Namespace.String.StartsWith("System.", StringComparison.Ordinal));
        if ((!framework && (target.ResolveMethodDef() is not { } local || adapters?.Contains(local) != true)) || target.Name == ".ctor") return false;
        var owner = target.DeclaringType;
        var expected = (signature.HasThis ? new[] { owner.ToTypeSig() } : Array.Empty<TypeSig>()).Concat(signature.Params).ToArray();
        if (expected.Length != method.Parameters.Count || il[^2].OpCode.Code == Code.Callvirt && !signature.HasThis) return false;
        var erased = false;
        for (var index = 0; index < expected.Length; index++)
        {
            if (!il[index].IsLdarg() || il[index].GetParameter(method.Parameters)?.Index != index) return false;
            var supplied = method.Parameters[index].Type;
            if (new SigComparer().Equals(supplied, expected[index])) continue;
            if (supplied.ElementType != ElementType.Object || !Reference(expected[index]) || expected[index].ElementType == ElementType.Object) return false;
            erased = true;
        }
        // At least one erased input distinguishes these injected thunks from an
        // ordinary, correctly typed application forwarding method. No cast or
        // other operation may hide additional application behavior.
        return erased && (new SigComparer().Equals(method.ReturnType, signature.RetType) ||
            method.ReturnType.ElementType == ElementType.Object && Reference(signature.RetType));
    }

    private static bool Reference(TypeSig type) => !type.ContainsGenericParameter &&
        (type.ElementType is ElementType.String or ElementType.Object || type is ClassSig or SZArraySig or ArraySig);
}
