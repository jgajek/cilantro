using System.Security.Cryptography;
using System.Text;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Core.Analysis;

/// <summary>The complete assembly resolver, with its independently checked stream codec separated.</summary>
internal static class BabelEmbeddingShape
{
    internal sealed record Resolver(MethodDef Install, MethodDef Handler, MethodDef Resolve, MethodDef Index, MethodDef Names, MethodDef Codec);
    internal sealed record Description(string Fingerprint, string Data, int LengthKey);

    internal static bool ReviewedPair(string original, string current) => (original, current) is
        ("7b861b4fcc33800495e058b8c62cfe044f6a0a7056e1c22f693a0abb4ce763b9", "5377769fda9d34acb1f384b9f4c817fbbbcf59f9a3c00285f44ad88886f80a9a") or
        ("09203ec513b19180086f7b4d9ebf1aa06a4b9237a464a21c54dbe7630b2c87ab", "8a119a4276b1d9b9d1321e3fe42acb0245f1213326c18405efbf46284b43ba34") or
        ("f92c5108c8b450f2ece6cc22f967a521104ac892699f2e876ca405defe9916cb", "5fd2c0ced6228096120034f7dcd6bd2d5ca998c941761a1c6217d28cbd3da02e");

    internal static IEnumerable<Resolver> Find(ModuleDef module)
    {
        foreach (var type in module.GetTypes().Where(t => t.Methods.Count == 8 && t.Fields.Count == 4 && t.NestedTypes.Count == 2))
        {
            var installs = type.Methods.Where(m => m.IsStatic && m.HasBody && m.MethodSig.Params.Count == 0 && m.ReturnType.ElementType == ElementType.Void &&
                m.Body.Instructions.Any(i => i.Operand is IMethod call && call.FullName == "System.Void System.AppDomain::add_AssemblyResolve(System.ResolveEventHandler)")).ToArray();
            var handlers = installs.SelectMany(m => m.Body.Instructions).Where(i => i.OpCode.Code == Code.Ldftn).Select(i => (i.Operand as IMethod)?.ResolveMethodDef()).OfType<MethodDef>().ToArray();
            var resolves = type.Methods.Where(EmbeddedDependencyRecoveryPass.IsResolver).ToArray();
            var indexes = type.Methods.Where(m => m.IsStatic && m.HasBody && m.ReturnType.ElementType == ElementType.Void && m.MethodSig.Params.Count == 1 && m.MethodSig.Params[0].FullName == "System.IO.Stream").ToArray();
            var names = type.Methods.Where(m => m.IsStatic && m.HasBody && m.ReturnType.ElementType == ElementType.String && m.MethodSig.Params.Count == 1 && m.MethodSig.Params[0].ElementType == ElementType.I4).ToArray();
            if (installs.Length != 1 || handlers.Length != 1 || handlers[0].DeclaringType != type || resolves.Length != 1 || indexes.Length != 1 || names.Length != 1) continue;
            var codecs = resolves[0].Body.Instructions.Where(i => i.OpCode.Code == Code.Call).Select(i => (i.Operand as IMethod)?.ResolveMethodDef())
                .OfType<MethodDef>().Where(m => m.Module == module && m.DeclaringType != type && m.IsStatic && m.HasBody && m.MethodSig.Params.Count == 1 && m.ReturnType.FullName == "System.IO.Stream").Distinct().ToArray();
            if (codecs.Length == 1) yield return new(installs[0], handlers[0], resolves[0], indexes[0], names[0], codecs[0]);
        }
    }

    // Operates only on a disposable proof copy. Values masked here remain part
    // of Data, and the actual stream/name values must be independently decoded.
    internal static Description? Describe(Resolver resolver)
    {
        var data = new List<string>();
        var owner = resolver.Install.DeclaringType;
        foreach (var method in owner.Methods.Where(m => m.HasBody))
            if (!GeneratedRuntimeBodyNormalization.TryNormalize(method, shortLocals: false, out _)) return null;
        var calls = resolver.Resolve.Body.Instructions.Where(i => i.OpCode.Code == Code.Call && i.Operand is IMethod m && m.ResolveMethodDef() == resolver.Codec).ToArray();
        if (calls.Length != 1) return null;
        calls[0].Operand = new MemberRefUser(owner.Module, "Decode", resolver.Codec.MethodSig,
            new TypeRefUser(owner.Module, "Cilantro.Proof", "BabelDependencyCodec", new AssemblyRefUser("Cilantro.Proof")));
        var literals = resolver.Names.Body.Instructions.Where(i => i.OpCode.Code == Code.Ldstr).ToArray();
        if (literals.Length != 1) return null;
        data.Add((string)literals[0].Operand); literals[0].Operand = "$bundle-name";
        if (MaskKeys(resolver.Names) is not { Count: 1 } || MaskKeys(resolver.Index) is not { Count: 2 } || MaskKeys(resolver.Resolve) is not { Count: 1 } lengths) return null;
        var arguments = 0;
        foreach (var method in owner.Methods.Where(m => m.HasBody))
        {
            var il = method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
            for (var n = 1; n < il.Length; n++)
                if (il[n].OpCode.Code == Code.Callvirt && il[n].Operand is IMethod call && call.Name == "Invoke" &&
                    call.DeclaringType.ResolveTypeDef()?.DeclaringType == owner && il[n - 1].IsLdcI4())
                { data.Add(il[n - 1].GetLdcI4Value().ToString(System.Globalization.CultureInfo.InvariantCulture)); il[n - 1].OpCode = OpCodes.Ldc_I4; il[n - 1].Operand = 0; arguments++; }
        }
        if (arguments != 1) return null;
        var graph = GeneratedRuntimeShape.ReadCanonicalScopedNames(resolver.Handler);
        if (graph.Types.Count != 3 || graph.Fingerprint.Length != 64 || graph.Types.Any(t => t.HasDeclSecurities || t.HasGenericParameters ||
            t.HasProperties || t.HasEvents || t.HasInterfaces || t.Methods.Any(m => m.HasGenericParameters || m.HasDeclSecurities))) return null;
        // Producer renaming changes declaration names, not field/method roles.
        // Bind every real name independently to the original input, then use
        // role names only in the disposable metadata proof. Virtual and special
        // constructor names remain literal parts of the reviewed ABI.
        foreach (var type in graph.Types)
        {
            data.Add(System.Text.Json.JsonSerializer.Serialize(new { Type = type.FullName, Fields = type.Fields.Select(f => f.Name.String).ToArray(),
                Methods = type.Methods.Select(m => new { Name = m.Name.String, Parameters = m.ParamDefs.Select(p => p.Name.String).ToArray() }).ToArray() }));
            for (var n = 0; n < type.Fields.Count; n++) type.Fields[n].Name = "$field" + n.ToString(System.Globalization.CultureInfo.InvariantCulture);
            for (var n = 0; n < type.Methods.Count; n++)
            {
                var method = type.Methods[n];
                if (!method.IsVirtual && !method.IsConstructor) method.Name = "$method" + n.ToString(System.Globalization.CultureInfo.InvariantCulture);
                foreach (var parameter in method.ParamDefs) parameter.Name = "$parameter" + parameter.Sequence.ToString(System.Globalization.CultureInfo.InvariantCulture);
            }
        }
        var metadata = BabelDormantMethodRuntime.Describe(graph.Types, scopedTypeNames: true);
        return new(Hash(graph.Fingerprint + "\n" + metadata), Hash(System.Text.Json.JsonSerializer.Serialize(data)), lengths[0]);

        List<int> MaskKeys(MethodDef method)
        {
            var keys = new List<int>(); var il = method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
            for (var n = 1; n < il.Length; n++)
                if (il[n].OpCode.Code == Code.Xor && il[n - 1].IsLdcI4())
                { var value = il[n - 1].GetLdcI4Value(); keys.Add(value); data.Add(value.ToString(System.Globalization.CultureInfo.InvariantCulture)); il[n - 1].OpCode = OpCodes.Ldc_I4; il[n - 1].Operand = 0; }
                else if (n > 1 && il[n].OpCode.Code == Code.Xor && il[n - 1].OpCode.Code == Code.Conv_I8 && il[n - 2].IsLdcI4())
                { var value = il[n - 2].GetLdcI4Value(); keys.Add(value); data.Add(value.ToString(System.Globalization.CultureInfo.InvariantCulture)); il[n - 2].OpCode = OpCodes.Ldc_I4; il[n - 2].Operand = 0; }
            return keys;
        }
    }

    private static string Hash(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
}
