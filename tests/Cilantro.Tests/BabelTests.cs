using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Codec;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class BabelTests
{
    [Theory]
    [InlineData(true, true, true, true)]
    [InlineData(false, true, true, false)]
    [InlineData(true, false, true, false)]
    [InlineData(true, true, false, false)]
    [InlineData(true, true, true, true, true)]
    public void GeneratedStringRuntimeRequiresTheConnectedBabelFeatures(bool numeric, bool emit, bool connected, bool expected, bool erasedStream = false)
    {
        using var context = SyntheticContext.Build(module =>
        {
            TypeRef Ref(string ns, string name) => new TypeRefUser(module, ns, name, module.CorLibTypes.AssemblyRef);
            var host = SyntheticContext.AddType(module, "Strings");
            var nested = new TypeDefUser("", "Factory", module.CorLibTypes.Object.TypeDefOrRef);
            host.NestedTypes.Add(nested);
            var builder = Ref("System.Reflection.Emit", "TypeBuilder");
            var methodBuilder = Ref("System.Reflection.Emit", "MethodBuilder");
            var generator = Ref("System.Reflection.Emit", "ILGenerator");
            var opcode = Ref("System.Reflection.Emit", "OpCode");
            var attributes = Ref("System.Reflection", "MethodAttributes");
            var factory = new MethodDefUser("Build", MethodSig.CreateStatic(new ClassSig(methodBuilder), new ClassSig(builder)), MethodAttributes.Static)
                { Body = new CilBody() };
            nested.Methods.Add(factory);
            foreach (var instruction in new[] { OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldstr.ToInstruction("?"), OpCodes.Ldc_I4_0.ToInstruction(),
                OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "DefineMethod", MethodSig.CreateInstance(new ClassSig(methodBuilder), module.CorLibTypes.String, new ValueTypeSig(attributes)), builder)),
                OpCodes.Pop.ToInstruction() }) factory.Body.Instructions.Add(instruction);
            if (emit)
                foreach (var instruction in new[] { OpCodes.Ldnull.ToInstruction(),
                    OpCodes.Ldsfld.ToInstruction(new MemberRefUser(module, "Ret", new FieldSig(new ValueTypeSig(opcode)), Ref("System.Reflection.Emit", "OpCodes"))),
                    OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "Emit", MethodSig.CreateInstance(module.CorLibTypes.Void, new ValueTypeSig(opcode)), generator)) })
                    factory.Body.Instructions.Add(instruction);
            factory.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); factory.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var domain = Ref("System", "AppDomain"); var table = Ref("System.Collections", "Hashtable");
            var getter = new MethodDefUser("Lookup", MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.Int32), MethodAttributes.Static) { Body = new CilBody() };
            host.Methods.Add(getter);
            foreach (var instruction in new[] {
                OpCodes.Call.ToInstruction(new MemberRefUser(module, "get_CurrentDomain", MethodSig.CreateStatic(new ClassSig(domain)), domain)),
                OpCodes.Ldstr.ToInstruction("cache"),
                OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetData", MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.String), domain)),
                OpCodes.Castclass.ToInstruction(table), OpCodes.Ldarg_0.ToInstruction(), OpCodes.Box.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef),
                OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_Item", MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.Object), table)),
                OpCodes.Castclass.ToInstruction(module.CorLibTypes.String.TypeDefOrRef), OpCodes.Ret.ToInstruction() }) getter.Body.Instructions.Add(instruction);
            var stream = Ref("System.IO", "Stream"); var assembly = Ref("System.Reflection", "Assembly");
            var codec = new MethodDefUser("Decode", MethodSig.CreateStatic(new ClassSig(stream), erasedStream ? module.CorLibTypes.Object : new ClassSig(stream)), MethodAttributes.Static) { Body = new CilBody() };
            host.Methods.Add(codec);
            if (erasedStream)
                foreach (var instruction in new[] {
                    OpCodes.Ldnull.ToInstruction(), OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "ReadUInt16", MethodSig.CreateInstance(module.CorLibTypes.UInt16), Ref("System.IO", "BinaryReader"))), OpCodes.Pop.ToInstruction(),
                    OpCodes.Ldnull.ToInstruction(), OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "CreateDecryptor", MethodSig.CreateInstance(new ClassSig(Ref("System.Security.Cryptography", "ICryptoTransform"))), Ref("System.Security.Cryptography", "SymmetricAlgorithm"))), OpCodes.Pop.ToInstruction() })
                    codec.Body.Instructions.Add(instruction);
            codec.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            if (erasedStream) codec.Body.Instructions.Add(OpCodes.Castclass.ToInstruction(stream));
            codec.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() };
            host.Methods.Add(cctor);
            foreach (var instruction in new[] {
                OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetExecutingAssembly", MethodSig.CreateStatic(new ClassSig(assembly)), assembly)), OpCodes.Ldstr.ToInstruction("data"),
                OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetManifestResourceStream", MethodSig.CreateInstance(new ClassSig(stream), module.CorLibTypes.String), assembly)) }) cctor.Body.Instructions.Add(instruction);
            if (connected) cctor.Body.Instructions.Add(OpCodes.Call.ToInstruction(codec));
            cctor.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); cctor.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            if (numeric)
                foreach (var result in new[] { module.CorLibTypes.Int32, module.CorLibTypes.Int64, module.CorLibTypes.Single, module.CorLibTypes.Double })
                {
                    var method = new MethodDefUser("Get" + result.TypeName, MethodSig.CreateStatic(result, module.CorLibTypes.Int32), MethodAttributes.Static) { Body = new CilBody() };
                    host.Methods.Add(method); method.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
                    if (result.ElementType == ElementType.I8) method.Body.Instructions.Add(OpCodes.Conv_I8.ToInstruction());
                    if (result.ElementType == ElementType.R4) method.Body.Instructions.Add(OpCodes.Conv_R4.ToInstruction());
                    if (result.ElementType == ElementType.R8) method.Body.Instructions.Add(OpCodes.Conv_R8.ToInstruction());
                    method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                }
        });
        Assert.Equal(expected, BabelStructureDetector.Analyze(context.Module).IsBabel);
    }

    [Theory]
    [InlineData(true, false, true)]
    [InlineData(false, false, true)]
    [InlineData(false, true, true)]
    [InlineData(false, true, false)]
    public void LegacyEnvelopesDecodeExactly(bool legacy, bool masked, bool compressed)
    {
        var expected = Encoding.UTF8.GetBytes("Babel resource ground truth 🥬");
        var encoded = Envelope(expected, legacy, masked, compressed);
        Assert.True(BabelResourceCodec.TryDecode(encoded, [], out var actual, out var why), why);
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PublicKeyDerivedKeysDecodeAtTheCorrectOffset(bool legacy)
    {
        var publicKey = Enumerable.Range(1, 40).Select(value => (byte)value).ToArray();
        byte[] expected = [4, 3, 2, 1];
        var encoded = Envelope(expected, legacy, false, true, publicKey);
        Assert.True(BabelResourceCodec.TryDecode(encoded, publicKey, out var actual, out var why), why);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void EveryTruncatedPrefixRefusesWithoutThrowing()
    {
        var encoded = Envelope(new byte[128], false, true, true);
        for (var length = 0; length < encoded.Length; length++)
        {
            Assert.False(BabelResourceCodec.TryDecode(encoded[..length], [], out var actual, out _));
            Assert.Empty(actual);
        }
    }

    [Fact]
    public void CompressedExpansionIsBounded()
    {
        var encoded = Envelope(new byte[BabelResourceCodec.MaximumLength + 1], false, true, true);
        Assert.False(BabelResourceCodec.TryDecode(encoded, [], out var actual, out var why));
        Assert.Empty(actual);
        Assert.Contains("output limit", why, StringComparison.Ordinal);
    }

    [Fact]
    public void MissingPublicKeyAndBadCiphertextRefuse()
    {
        var encoded = Envelope([1, 2, 3], true, false, true);
        encoded[9] = 0; // public-key form instead of embedded key
        Assert.False(BabelResourceCodec.TryDecode(encoded, [], out _, out _));
        encoded = Envelope([1, 2, 3], false, false, true);
        encoded[^1] ^= 0x55;
        Assert.False(BabelResourceCodec.TryDecode(encoded, [], out _, out _));
    }

    [Fact]
    public void RandomAndMalformedHeadersNeverThrow()
    {
        var random = new Random(173);
        for (var index = 0; index < 1000; index++)
        {
            var bytes = new byte[random.Next(19, 256)];
            random.NextBytes(bytes);
            bytes[0] = (byte)(index % 2);
            bytes[1] = 19;
            bytes[2] = 0;
            Assert.False(BabelResourceCodec.TryDecode(bytes, [], out _, out _));
            Assert.False(BabelUnpackingPass.TryReadAssemblyBundle(bytes, out _));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void UnmarkedRuntimeRequiresAnActuallyDecodableEnvelope(bool damaged)
    {
        var bytes = Envelope(Bundle(AssemblyBytes()), false, true, true);
        if (damaged) bytes[^1] ^= 0x55;
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Runtime");
            var stream = new ClassSig(new TypeRefUser(module, "System.IO", "Stream", module.CorLibTypes.AssemblyRef));
            var memory = new ClassSig(new TypeRefUser(module, "System.IO", "MemoryStream", module.CorLibTypes.AssemblyRef));
            var decode = new MethodDefUser("Read", MethodSig.CreateStatic(memory, stream), MethodAttributes.Static) { Body = new CilBody() };
            type.Methods.Add(decode);
            decode.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            decode.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            module.Resources.Add(new EmbeddedResource("packed", bytes, ManifestResourceAttributes.Private));
        });
        Assert.Equal(!damaged, BabelStructureDetector.Analyze(context.Module).IsBabel);
    }

    [Fact]
    public void RecognitionNeedsAnAppliedMarker()
    {
        using var context = SyntheticContext.Build(module => Marker(module, applied: false));
        Assert.False(BabelStructureDetector.Analyze(context.Module).IsBabel);
        using var marked = SyntheticContext.Build(module => Marker(module));
        Assert.True(BabelStructureDetector.Analyze(marked.Module).IsBabel);
        new BabelDetectionPass().Run(marked);
        new ProtectorIdentityPass().Run(marked);
        Assert.True(marked.TryGetFact<ProtectorIdentity>(ProtectorIdentityPass.Fact, out var identity));
        Assert.Equal("babel", identity!.Token);
    }

    [Fact]
    public void BundleValidationIsAtomicAndRejectsTrailingOrInvalidMembers()
    {
        var assembly = AssemblyBytes();
        var valid = Bundle(assembly);
        Assert.True(BabelUnpackingPass.TryReadAssemblyBundle(valid, out var parsed));
        Assert.Equal(assembly, Assert.Single(parsed));
        Assert.False(BabelUnpackingPass.TryReadAssemblyBundle([.. valid, 0], out _));
        Assert.False(BabelUnpackingPass.TryReadAssemblyBundle(Bundle(assembly, [1, 2, 3]), out var invalid));
        Assert.Empty(invalid);
        Assert.False(BabelUnpackingPass.TryReadAssemblyBundle([255, 255, 255, 127], out _));
    }

    [Fact]
    public void UnpackingPreservesSourceAndExistingArtifacts()
    {
        var payload = AssemblyBytes();
        var encoded = Envelope(Bundle(payload), false, true, true);
        using var context = SyntheticContext.Build(module =>
        {
            Marker(module);
            module.Resources.Add(new EmbeddedResource("packed", encoded, ManifestResourceAttributes.Private));
        });
        new BabelDetectionPass().Run(context);
        var result = new BabelUnpackingPass().Run(context);
        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(1, result.Changes);
        Assert.Equal(encoded, Assert.Single(context.Module.Resources.OfType<EmbeddedResource>()).CreateReader().ToArray());
        Assert.True(context.TryGetFact<IReadOnlyList<ExtractedPayload>>("payload.artifacts", out var artifacts));
        Assert.Equal(payload, Assert.Single(artifacts!).Bytes);
        new BabelUnpackingPass().Run(context);
        Assert.True(context.TryGetFact<IReadOnlyList<ExtractedPayload>>("payload.artifacts", out artifacts));
        Assert.Single(artifacts!);
    }

    [Fact]
    public void MalformedEnvelopeReportsPartialAndKeepsInput()
    {
        var encoded = Envelope(Bundle(AssemblyBytes()), false, true, true);
        encoded[^1] ^= 0x55;
        using var context = SyntheticContext.Build(module =>
        {
            Marker(module);
            module.Resources.Add(new EmbeddedResource("packed", encoded, ManifestResourceAttributes.Private));
        });
        new BabelDetectionPass().Run(context);
        var pass = new BabelUnpackingPass();
        Assert.False(pass.GatesEmission);
        Assert.Equal(PassStatus.Partial, pass.Run(context).Status);
        Assert.Single(context.Module.Resources);
    }

    [Fact]
    public void DefaultPipelineRecognizesBabelAndEmitsVerifiedOutput()
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.Babel.").FullName;
        try
        {
            using var context = SyntheticContext.Build(module =>
            {
                Marker(module);
                module.Resources.Add(new EmbeddedResource("packed",
                    Envelope(Bundle(AssemblyBytes()), false, true, true), ManifestResourceAttributes.Private));
            });
            var input = Path.Combine(directory, "marked.dll");
            context.Module.Write(input);
            var result = new CilantroPipeline().Run(input, new PipelineOptions(
                ReportDirectory: Path.Combine(directory, "report"), OutputPath: Path.Combine(directory, "cleaned.dll")));
            Assert.Equal("babel", result.Report.Protector);
            Assert.True(result.Report.VerificationPassed);
            Assert.True(result.Success);
            Assert.NotNull(result.OutputPath);
            Assert.Contains(result.Report.Passes, pass => pass.Pass == "babel-unpacking" && pass.Changes == 1);
            var extracted = Assert.Single(result.Report.Payloads, payload => payload.Origin == PayloadOrigin.EmbeddedDependency);
            Assert.NotNull(extracted.WrittenTo);
            Assert.Equal(extracted.PayloadSha256, Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(extracted.WrittenTo))));
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    internal static void Marker(ModuleDefUser module, bool applied = true)
    {
        var attribute = new TypeDefUser("", "BabelObfuscatorAttribute",
            new TypeRefUser(module, "System", "Attribute", module.CorLibTypes.AssemblyRef));
        module.Types.Add(attribute);
        var constructor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void),
            MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() };
        attribute.Methods.Add(constructor);
        constructor.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
        constructor.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void), attribute.BaseType)));
        constructor.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        if (applied) module.Assembly.CustomAttributes.Add(new CustomAttribute(constructor));
    }

    private static byte[] AssemblyBytes()
    {
        using var module = new ModuleDefUser("child.dll") { Kind = ModuleKind.Dll };
        new AssemblyDefUser("child", new Version(1, 0)).Modules.Add(module);
        using var output = new MemoryStream();
        module.Write(output);
        return output.ToArray();
    }

    private static byte[] Bundle(params byte[][] assemblies)
    {
        using var output = new MemoryStream();
        using var writer = new BinaryWriter(output);
        writer.Write(assemblies.Length);
        foreach (var assembly in assemblies)
        {
            writer.Write("child, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null");
            writer.Write(assembly.Length);
            writer.Write(assembly);
        }
        return output.ToArray();
    }

    private static byte[] Envelope(byte[] plain, bool legacy, bool masked, bool compressed, byte[]? publicKey = null)
    {
        byte[] key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
        if (publicKey is not null)
        {
            key = publicKey.AsSpan(legacy ? 0 : 12, 8).ToArray();
            if (!legacy) key[5] |= 0x80;
        }
        byte[] iv = [1, 2, 3, 4, 5, 6, 7, 8];
        if (compressed)
        {
            using var output = new MemoryStream();
            using (var zlib = new ZLibStream(output, CompressionLevel.SmallestSize, leaveOpen: true)) zlib.Write(plain);
            plain = output.ToArray();
        }
#pragma warning disable CA5351
        using var cipher = DES.Create();
#pragma warning restore CA5351
        cipher.Key = key;
        var encrypted = cipher.EncryptCbc(plain, iv, PaddingMode.PKCS7);
        using var header = new MemoryStream();
        using var fields = new BinaryWriter(header);
        if (!legacy) { fields.Write("fixture"); fields.Write(compressed); }
        fields.Write((byte)8); fields.Write(iv);
        fields.Write(publicKey is null); fields.Write((byte)8);
        if (publicKey is null) fields.Write(key);
        if (legacy) fields.Write(0); // hash length
        using var envelope = new MemoryStream();
        using var writer = new BinaryWriter(envelope);
        var bytes = header.ToArray();
        if (!legacy)
        {
            writer.Write(masked); writer.Write((ushort)bytes.Length);
            byte[] mask = [11, 12, 13, 14, 15, 16, 17, 18];
            if (masked) for (var at = 0; at < bytes.Length; at++) bytes[at] ^= mask[at % mask.Length];
            writer.Write(bytes);
            if (masked) writer.Write(mask);
        }
        else writer.Write(bytes);
        writer.Write(encrypted);
        return envelope.ToArray();
    }
}
