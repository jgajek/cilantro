using Cilantro.Core.Codec;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class DotfuscatorV2Tests
{
    [Fact]
    public void ReviewedNativeFramingDecodesTheCapturedKnownAnswer()
    {
        const string encoded = "aSTDP9FtCNElNoQnSI6nOHgIKTnZu6sRWQ7tmtOy3A9QErZFoAZoqhAIwHY4tJwOTSRAQqSU6UsbCKKezaXUBFdL7Rz2UDjmEw3kQSeklhNbL0FJxv35HFcKoJjRrc4XBAXuFPFWN+lZDdh/RJ7leGwZdA==";
        var key = DotfuscatorV2Codec.Key("Probe", "DescribeCampaign|String DescribeCampaign()");
        Assert.True(DotfuscatorV2Codec.TryDecode(encoded, 0, key, out var text));
        Assert.Equal("PROBE_STR_04 https://probe.invalid:8443/gatePROBE_STR_05 campaign=aabbccddPROBE_STR_06 blacklist=sbiedll.dll,x64dbg", text);
        Assert.Equal(DotfuscatorV2Codec.Key("Caf\u00e9", "M|String M()"), DotfuscatorV2Codec.Key("Cafe\u0301", "M|String M()"));
    }

    [Fact]
    public void InvalidUtf8UsesTheEmittedDecodersReplacementFallback()
    {
        Assert.True(DotfuscatorV2Codec.TryDecode("/w==", 0, new byte[32], out var text));
        Assert.Equal("\ufffd", text);
        Assert.True(DotfuscatorV2Codec.TryDecode("", 0, new byte[32], out text));
        Assert.Equal("", text);
        var indexedKey = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
        Assert.True(DotfuscatorV2Codec.TryDecode("ZA==", 5, indexedKey, out text));
        Assert.Equal("a", text);
        Assert.False(DotfuscatorV2Codec.TryDecode("@@", 0, new byte[32], out _));
        Assert.False(DotfuscatorV2Codec.TryDecode("AA==", -1, new byte[32], out _));
        Assert.False(DotfuscatorV2Codec.TryDecode("AA==", int.MaxValue, new byte[32], out _));
        Assert.False(DotfuscatorV2Codec.TryDecode("AA==", 0, new byte[31], out _));
        Assert.False(DotfuscatorV2Codec.TryDecode(new string('A', 4 * (DotfuscatorV2Codec.MaximumStringBytes / 3 + 2)), 0, new byte[32], out _));
    }

    [Fact]
    public void SignatureUsesReflectionNamesForArraysGenericsAndReferences()
    {
        using var module = ModuleDefMD.Load(typeof(Signatures<>).Assembly.Location);
        var type = module.GetTypes().Single(t => t.Name == "Signatures`1");
        var mix = type.Methods.Single(m => m.Name == "Mix");
        Assert.Equal("Mix|U Mix(T[], Dictionary`2&, U)", DotfuscatorV2Codec.Signature(mix));
        var method = typeof(Signatures<>).GetMethod("Mix")!;
        Assert.Equal($"{method.Name}|{method.ReturnType.Name} {method.Name}({string.Join(", ", method.GetParameters().Select(p => p.ParameterType.Name))})",
            DotfuscatorV2Codec.Signature(mix));
        Assert.Equal("Matrix|Int32[,] Matrix(Int32[,])", DotfuscatorV2Codec.Signature(type.Methods.Single(m => m.Name == "Matrix")));
    }

    [Theory]
    [InlineData(8)]
    [InlineData(10)]
    public void CoreClrFunctionPointerNamesAreEmpty(int version)
    {
        using var module = new ModuleDefUser("Signatures", Guid.Empty,
            new AssemblyRefUser("System.Runtime", new Version(version, 0, 0, 0)));
        var type = new TypeDefUser("Signatures", "Cases", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(type);
        var pointer = new FnPtrSig(MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32));
        var argument = new MethodDefUser("F", MethodSig.CreateStatic(module.CorLibTypes.String, pointer)); type.Methods.Add(argument);
        var returned = new MethodDefUser("Return", MethodSig.CreateStatic(pointer)); type.Methods.Add(returned);
        Assert.Equal("F|String F()", DotfuscatorV2Codec.Signature(argument));
        Assert.Equal("Return| Return()", DotfuscatorV2Codec.Signature(returned));
    }

    [Fact]
    public void LegacyFunctionPointerNamingRemainsUnproved()
    {
        using var module = new ModuleDefUser("Signatures");
        var type = new TypeDefUser("Signatures", "Cases", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(type);
        var pointer = new FnPtrSig(MethodSig.CreateStatic(module.CorLibTypes.Int32));
        var method = new MethodDefUser("F", MethodSig.CreateStatic(module.CorLibTypes.String, pointer)); type.Methods.Add(method);
        Assert.Null(DotfuscatorV2Codec.Signature(method));
    }

    [Fact]
    public void EnvironmentFramingRefusesIncompleteInputs()
    {
        Assert.False(DotfuscatorV2Codec.ValidateEnvironment([], 0, out _));
        Assert.False(DotfuscatorV2Codec.ValidateEnvironment(new byte[20480], 0, out _));
        var forged = new byte[20480];
        new byte[] { 0x31, 0x9a, 0xff, 0xa2 }.CopyTo(forged, 0);
        new byte[] { 0x44, 0x5a, 0x4d, 0xaa }.CopyTo(forged, forged.Length - 4);
        Assert.False(DotfuscatorV2Codec.ValidateEnvironment(forged, 0, out var reason));
        Assert.Contains("signature", reason, StringComparison.Ordinal);
    }

    // Deliberately retain these metadata names and static generic shapes for reflection tests.
#pragma warning disable CA1000, CA1715
    public sealed class Signatures<T>
    {
        public static U Mix<U>(T[] values, ref Dictionary<string, int[,]> state, U argument) => argument;
        public static int[,] Matrix(int[,] values) => values;
    }
#pragma warning restore CA1000, CA1715
}
