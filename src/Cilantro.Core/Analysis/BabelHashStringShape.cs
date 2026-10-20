using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>The eager dictionary cache used by modern Babel hash strings.</summary>
internal static class BabelHashStringShape
{
    internal sealed record Cache(MethodDef Wrapper, MethodDef Getter, MethodDef Constructor, MethodDef Initializer,
        MethodDef NamesDecoder, MethodDef StreamDecoder, FieldDef Singleton, FieldDef Dictionary);

    internal static bool Reviewed(string fingerprint) => fingerprint is
        "62c129e4c60a6a39a6cf5bac6adcc6b5c89e353a94aa2cb3cc29ca54ba79051c" or
        "d96f7c6fe59c8f8a74d452b66ed744514906d0f3984760ae85fe5c92d4978c86";

    internal static bool ReviewedCodec(string fingerprint) => fingerprint is
        "000d919c1580235994396872bc1de588e2f88dd249cda991ce2042683792511b" or
        "9b5d16994a87d7cf38bd7282f66de4ec8a36a33180bfb07d50c9f2d259d63ece";

    internal static bool TryDescribeCodec(MethodDef decoder, out string fingerprint)
    {
        fingerprint = "codec did not normalize";
        try
        {
            var graph = GeneratedRuntimeShape.Read(decoder);
            var methods = graph.Types.SelectMany(type => type.Methods).Where(method => method.HasBody).ToArray();
            if (graph.Types.Count > 32 || methods.Length > 192 || methods.Sum(method => method.Body.Instructions.Count) > 65_536) return false;
            foreach (var method in methods) if (!GeneratedRuntimeBodyNormalization.TryNormalize(method, false, out _)) return false;
            fingerprint = GeneratedRuntimeShape.ReadCanonicalWithIntegerParameters(decoder).Fingerprint;
            return true;
        }
        catch (Exception exception) when (exception is InvalidOperationException or ArgumentException or KeyNotFoundException or IndexOutOfRangeException)
        { fingerprint = "invalid codec: " + exception.GetType().Name; return false; }
    }

    internal static IEnumerable<Cache> Find(ModuleDef module)
    {
        var codecs = BabelStructureDetector.StreamDecoders(module).ToHashSet();
        foreach (var wrapper in module.GetTypes().SelectMany(type => type.Methods).Where(method => method.IsStatic && method.HasBody &&
                     method.MethodSig.Params.Count == 1 && method.MethodSig.Params[0].ElementType == ElementType.I4 && method.ReturnType.ElementType == ElementType.String))
        {
            var il = wrapper.Body.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop).ToArray();
            if (il.Length != 4 || il[0].OpCode.Code != Code.Ldsfld || il[0].Operand is not IField field || field.ResolveFieldDef() is not { } singleton ||
                !il[1].IsLdarg() || il[1].GetParameterIndex() != 0 || il[2].OpCode.Code != Code.Callvirt ||
                il[2].Operand is not IMethod target || target.ResolveMethodDef() is not { HasBody: true } getter || il[3].OpCode.Code != Code.Ret) continue;
            var holder = getter.DeclaringType;
            if (holder.DeclaringType != wrapper.DeclaringType || singleton.DeclaringType != holder ||
                holder.FindStaticConstructor() is not { HasBody: true } initializer) continue;
            var constructors = holder.Methods.Where(method => method.IsInstanceConstructor && method.MethodSig.Params.Count == 0 && method.HasBody).ToArray();
            var dictionaries = holder.Fields.Where(candidate => !candidate.IsStatic && candidate.FieldType.FullName == "System.Collections.Generic.Dictionary`2<System.Int32,System.String>").ToArray();
            var names = wrapper.DeclaringType.Methods.Where(method => method != wrapper && method.IsStatic && method.HasBody &&
                method.MethodSig.Params.Count == 1 && method.MethodSig.Params[0].ElementType == ElementType.I4 && method.ReturnType.ElementType == ElementType.String).ToArray();
            if (constructors.Length != 1 || dictionaries.Length != 1 || names.Length != 1) continue;
            var used = constructors[0].Body.Instructions.Select(instruction => (instruction.Operand as IMethod)?.ResolveMethodDef())
                .OfType<MethodDef>().Where(codecs.Contains).Distinct().ToArray();
            if (used.Length == 1) yield return new(wrapper, getter, constructors[0], initializer, names[0], used[0], singleton, dictionaries[0]);
        }
    }

    internal static bool TryDescribe(Cache cache, out string fingerprint)
    {
        fingerprint = "hash cache did not normalize";
        var owner = cache.Wrapper.DeclaringType;
        if (owner.Methods.Count != 3 || owner.NestedTypes.Count != 2 || cache.Getter.DeclaringType.Methods.Count != 3) return false;
        try
        {
            var methods = new[] { owner }.Concat(owner.NestedTypes).SelectMany(type => type.Methods).Where(method => method.HasBody).ToArray();
            foreach (var method in methods) if (!GeneratedRuntimeBodyNormalization.TryNormalize(method, false, out _)) return false;
            var module = owner.Module;
            var calls = cache.Constructor.Body.Instructions.Where(instruction => instruction.OpCode.Code == Code.Call && instruction.Operand is IMethod called &&
                called.ResolveMethodDef() == cache.StreamDecoder).ToArray();
            if (calls.Length != 1) return false;
            calls[0].Operand = new MemberRefUser(module, "Decode", cache.StreamDecoder.MethodSig,
                new TypeRefUser(module, "Cilantro.Proof", "BabelStreamCodec", new AssemblyRefUser("Cilantro.Proof")));
            var literals = cache.NamesDecoder.Body.Instructions.Where(instruction => instruction.OpCode.Code == Code.Ldstr).ToArray();
            if (literals.Length != 1) return false;
            literals[0].Operand = "$encrypted-resource-name";
            var keys = 0;
            var nameIl = cache.NamesDecoder.Body.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop).ToArray();
            for (var index = 1; index < nameIl.Length; index++)
                if (nameIl[index].OpCode.Code == Code.Xor && nameIl[index - 1].IsLdcI4())
                { nameIl[index - 1].OpCode = OpCodes.Ldc_I4; nameIl[index - 1].Operand = 0; keys++; }
            var dataArguments = 0;
            var il = cache.Constructor.Body.Instructions.Where(instruction => instruction.OpCode.Code != Code.Nop).ToArray();
            for (var index = 1; index < il.Length; index++)
                if (il[index].OpCode.Code == Code.Callvirt && il[index].Operand is IMethod called && called.Name == "Invoke" &&
                    called.DeclaringType.ResolveTypeDef()?.DeclaringType == owner && il[index - 1].IsLdcI4())
                { il[index - 1].OpCode = OpCodes.Ldc_I4; il[index - 1].Operand = 0; dataArguments++; }
            // Position-derived integer keys are wire data; the add/xor sequence
            // itself, loop bounds and dictionary operations remain in the graph.
            for (var index = 1; index < il.Length; index++)
                if (il[index].OpCode.Code is Code.Add or Code.Xor && il[index - 1].IsLdcI4())
                { il[index - 1].OpCode = OpCodes.Ldc_I4; il[index - 1].Operand = 0; keys++; }
            if (keys != 3 || dataArguments != 1) return false;
            fingerprint = GeneratedRuntimeShape.ReadCanonical(cache.Wrapper).Fingerprint;
            return true;
        }
        catch (Exception exception) when (exception is InvalidOperationException or ArgumentException or KeyNotFoundException or IndexOutOfRangeException)
        { fingerprint = "invalid hash cache: " + exception.GetType().Name; return false; }
    }
}
