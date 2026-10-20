using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>Identifies the closed resource chooser separately from its interpreted stream codec.</summary>
internal static class BabelResourceShape
{
    internal sealed record Resolver(MethodDef Initializer, MethodDef Handler, MethodDef Reader, MethodDef NamesDecoder,
        FieldDef Names, FieldDef Assembly, MethodDef StreamDecoder);

    internal static bool Reviewed(string fingerprint) => fingerprint is
        "9642eca21804cae7c5f28d420c90f96cce2cd5f8ef53969ccf29dab018e9e516" or
        "b5b8b62ae58d9d5e1e76b53cb09b59aeafef27f8691b83b5ee05c9a45aa708cd" or
        "5a599a064b9689763a9a81c441c97261181fa77b38880f5e0756daa24bd554ed";

    internal static IEnumerable<Resolver> Find(ModuleDef module)
    {
        var codecs = BabelStructureDetector.StreamDecoders(module).ToHashSet();
        foreach (var type in module.GetTypes().Where(type => type.Methods.Count == 7 && type.Fields.Count == 5))
        {
            var installers = type.Methods.Where(method => method.IsStatic && method.HasBody && method.ReturnType.ElementType == ElementType.Void &&
                method.MethodSig.Params.Count == 0 && method.Body.Instructions.Any(instruction => instruction.Operand is IMethod called &&
                    called.FullName == "System.Void System.AppDomain::add_ResourceResolve(System.ResolveEventHandler)")).ToArray();
            if (installers.Length != 1) continue;
            var handlers = installers[0].Body.Instructions.Where(instruction => instruction.OpCode.Code == Code.Ldftn)
                .Select(instruction => (instruction.Operand as IMethod)?.ResolveMethodDef()).OfType<MethodDef>().ToArray();
            var readers = type.Methods.Where(method => method.IsStatic && method.HasBody && method.ReturnType.FullName == "System.Reflection.Assembly" &&
                method.MethodSig.Params.Count == 1 && method.MethodSig.Params[0].FullName == "System.IO.Stream").ToArray();
            var names = type.Fields.Where(field => field.IsStatic && field.FieldType.FullName == "System.String[]").ToArray();
            var assemblies = type.Fields.Where(field => field.IsStatic && field.FieldType.FullName == "System.Reflection.Assembly").ToArray();
            var decoders = type.Methods.Where(method => method.IsStatic && method.HasBody && method.ReturnType.ElementType == ElementType.String &&
                method.MethodSig.Params.Count == 1 && method.MethodSig.Params[0].ElementType == ElementType.I4).ToArray();
            if (handlers.Length != 1 || handlers[0].DeclaringType != type || readers.Length != 1 || names.Length != 1 || assemblies.Length != 1 || decoders.Length != 1) continue;
            var used = readers[0].Body.Instructions.Select(instruction => (instruction.Operand as IMethod)?.ResolveMethodDef())
                .OfType<MethodDef>().Where(codecs.Contains).Distinct().ToArray();
            if (used.Length == 1) yield return new(installers[0], handlers[0], readers[0], decoders[0], names[0], assemblies[0], used[0]);
        }
    }

    // Only proof copies are edited. Wire keys/name ciphertext are interpreted
    // using their original values, then their parameter slots are normalized.
    internal static bool TryDescribe(Resolver resolver, out string fingerprint)
    {
        fingerprint = "resource chooser did not normalize";
        var owner = resolver.Initializer.DeclaringType;
        if (owner.NestedTypes.Count != 1 || owner.NestedTypes[0].Methods.Count != 4 ||
            owner.Methods.Any(method => method.HasBody && method.Body.Instructions.Count > 4096)) return false;
        try
        {
            foreach (var method in owner.Methods.Where(method => method.HasBody))
            {
                if (!GeneratedRuntimeBodyNormalization.TryNormalize(method, shortLocals: false, out _)) return false;
            }
            var module = owner.Module;
            var opaque = new TypeRefUser(module, "Cilantro.Proof", "BabelStreamCodec", new AssemblyRefUser("Cilantro.Proof"));
            var calls = resolver.Reader.Body.Instructions.Where(instruction => instruction.OpCode.Code == Code.Call &&
                instruction.Operand is IMethod called && called.ResolveMethodDef() == resolver.StreamDecoder).ToArray();
            if (calls.Length != 1) return false;
            calls[0].Operand = new MemberRefUser(module, "Decode", resolver.StreamDecoder.MethodSig, opaque);
            var literals = resolver.NamesDecoder.Body.Instructions.Where(instruction => instruction.OpCode.Code == Code.Ldstr).ToArray();
            if (literals.Length != 1) return false;
            literals[0].Operand = "$encrypted-resource-name";
            if (MaskXorKeys(resolver.NamesDecoder) != 1 || MaskXorKeys(resolver.Reader) != 3) return false;
            var dataArguments = 0;
            foreach (var method in owner.Methods.Where(method => method.HasBody))
            {
                var il = method.Body.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop).ToArray();
                for (var index = 1; index < il.Length; index++)
                    if (il[index].OpCode.Code == Code.Callvirt && il[index].Operand is IMethod called &&
                        called.DeclaringType.ResolveTypeDef() == owner.NestedTypes[0] && called.Name == "Invoke" && il[index - 1].IsLdcI4())
                    { il[index - 1].OpCode = OpCodes.Ldc_I4; il[index - 1].Operand = 0; dataArguments++; }
            }
            if (dataArguments != 1) return false;
            fingerprint = GeneratedRuntimeShape.ReadCanonicalScopedNames(resolver.Handler).Fingerprint;
            return true;
        }
        catch (Exception exception) when (exception is InvalidOperationException or ArgumentException or KeyNotFoundException or IndexOutOfRangeException)
        { fingerprint = "invalid resource chooser: " + exception.GetType().Name; return false; }
    }

    private static int MaskXorKeys(MethodDef method)
    {
        var count = 0;
        var il = method.Body.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop).ToArray();
        for (var index = 1; index < il.Length; index++)
            if (il[index].OpCode.Code == Code.Xor && il[index - 1].IsLdcI4())
            { il[index - 1].OpCode = OpCodes.Ldc_I4; il[index - 1].Operand = 0; count++; }
        return count;
    }

}
