using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>The packed-array entry point sharing Babel's eager numeric cache.</summary>
internal static class BabelNumericArrayShape
{
    internal sealed record Runtime(MethodDef Factory, MethodDef Reader, MethodDef Codec, MethodDef Names);

    internal static IEnumerable<Runtime> Find(ModuleDef module)
    {
        var codecs = BabelStructureDetector.StreamDecoders(module).ToHashSet();
        foreach (var factory in module.GetTypes().SelectMany(type => type.Methods).Where(method => method.IsStatic && method.HasBody &&
                     !method.HasGenericParameters && method.MethodSig.Params.Count == 1 && method.ReturnType.FullName == "System.Array" &&
                     method.MethodSig.Params[0].FullName is "System.Object" or "System.Byte[]"))
        {
            var calls = factory.Body.Instructions.Select(instruction => instruction.Operand).OfType<IMethod>().ToArray();
            if (!calls.Any(call => call.FullName == "System.Void System.IO.MemoryStream::.ctor(System.Byte[])")) continue;
            var readers = calls.Select(call => call.ResolveMethodDef()).OfType<MethodDef>().Where(method => method.IsStatic && method.HasBody &&
                method.DeclaringType.DeclaringType == factory.DeclaringType && method.ReturnType.FullName == "System.Array" &&
                method.MethodSig.Params.Count == 1 && method.MethodSig.Params[0].FullName is "System.Object" or "System.IO.Stream").Distinct().ToArray();
            var used = calls.Select(call => call.ResolveMethodDef()).OfType<MethodDef>().Where(codecs.Contains).Distinct().ToArray();
            var names = factory.DeclaringType.Methods.Where(method => method.IsStatic && method.HasBody &&
                method.MethodSig.Params.Count == 0 && method.ReturnType.ElementType == ElementType.String).ToArray();
            if (readers.Length == 1 && used.Length == 1 && names.Length == 1) yield return new(factory, readers[0], used[0], names[0]);
        }
    }

    internal static bool Reviewed(string fingerprint) => fingerprint is
        "c816a85a20f4a958792aa54f3266200a07bc385109e7abe6f607be472596844a" or
        "375388d04e72144632d1419eabc36b79ee96064d662aaa7e7d324f0e399a712a" or
        "0ae060e050eb2e517d58dd4c95ffd126d659c241b67d8fd61375b0bc86198aee";

    internal static bool ReviewedCodec(string fingerprint) => BabelHashStringShape.ReviewedCodec(fingerprint) ||
        fingerprint == "fe323fb068ae5cfc2d36b8dcc41414fbd170345abeb9a73243a06a9df643a597";

    internal static bool TryDescribe(Runtime runtime, out string fingerprint)
    {
        fingerprint = "numeric array graph did not normalize";
        var owner = runtime.Factory.DeclaringType;
        if (owner.NestedTypes.Count != 2 || owner.HasGenericParameters) return false;
        try
        {
            var methods = new[] { owner }.Concat(owner.NestedTypes).SelectMany(type => type.Methods).Where(method => method.HasBody).ToArray();
            if (methods.Length > 64 || methods.Sum(method => method.Body.Instructions.Count) > 32_768) return false;
            foreach (var method in methods) if (!GeneratedRuntimeBodyNormalization.TryNormalize(method, false, out _)) return false;
            var cuts = 0;
            foreach (var call in methods.SelectMany(method => method.Body.Instructions).Where(instruction => instruction.OpCode.Code == Code.Call &&
                         instruction.Operand is IMethod called && called.ResolveMethodDef() == runtime.Codec))
            {
                call.Operand = new MemberRefUser(owner.Module, "Decode", runtime.Codec.MethodSig,
                    new TypeRefUser(owner.Module, "Cilantro.Proof", "BabelStreamCodec", new AssemblyRefUser("Cilantro.Proof")));
                cuts++;
            }
            var literals = runtime.Names.Body.Instructions.Where(instruction => instruction.OpCode.Code == Code.Ldstr).ToArray();
            if (cuts != 2 || literals.Length != 1) return false;
            literals[0].Operand = "$encrypted-numeric-resource-name";
            // Integer operands encode randomized wire tags, widths and keys. Actual
            // unmodified code must still decode the concrete input in isolated trials.
            fingerprint = GeneratedRuntimeShape.ReadCanonicalWithIntegerParameters(runtime.Factory).Fingerprint;
            return true;
        }
        catch (Exception exception) when (exception is InvalidOperationException or ArgumentException or KeyNotFoundException or IndexOutOfRangeException)
        { fingerprint = "invalid numeric array graph: " + exception.GetType().Name; return false; }
    }
}
