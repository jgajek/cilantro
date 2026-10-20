using System.Security.Cryptography;
using Cilantro.Core.Interpretation;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class CryptoAlgorithmSelectionTests
{
    // RFC 2268 section 5: effective key length 64 bits.
    // https://www.rfc-editor.org/rfc/rfc2268
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void Rc2FactoryAndProviderNamesMatchPublishedVector(bool provider, bool decrypt)
    {
        var actual = Transform(provider ? "System.Security.Cryptography.RC2CryptoServiceProvider" : "System.Security.Cryptography.RC2",
            Convert.FromHexString("FFFFFFFFFFFFFFFF"), new byte[8],
            Convert.FromHexString(decrypt ? "278B27E42E2F0D49" : "FFFFFFFFFFFFFFFF"), decrypt);
        Assert.Equal(Convert.FromHexString(decrypt ? "FFFFFFFFFFFFFFFF" : "278B27E42E2F0D49"), actual);
    }

    [Theory]
    [InlineData("System.Security.Cryptography.AesManaged")]
    [InlineData("System.Security.Cryptography.AesCryptoServiceProvider")]
    public void AesProviderAliasesPreserveTheirActualCipher(string name)
    {
        // FIPS 197 Appendix C.1, AES-128.
        var actual = Transform(name, Convert.FromHexString("000102030405060708090A0B0C0D0E0F"), new byte[16],
            Convert.FromHexString("00112233445566778899AABBCCDDEEFF"), false);
        Assert.Equal(Convert.FromHexString("69C4E0D86A7B0430D8CDB78070B4C55A"), actual);
    }

    private static byte[] Transform(string algorithm, byte[] key, byte[] iv, byte[] input, bool decrypt)
    {
        using var module = new ModuleDefUser("Crypto"); var importer = new Importer(module);
        var state = new StaticMachineState(new StaticMachineLimits()); var context = new IntrinsicContext(state);
        var intrinsic = new LoaderFrameworkIntrinsic(); StaticValue receiver;
        if (algorithm == "System.Security.Cryptography.RC2")
        {
            var factory = intrinsic.Invoke(context, importer.Import(typeof(RC2).GetMethod("Create", Type.EmptyTypes)!), []);
            Assert.Equal(StaticExecutionStatus.Completed, factory.Status); receiver = factory.Value;
        }
        else
        {
            Assert.True(state.Heap.TryAllocateObject(algorithm, out receiver));
            var type = new TypeRefUser(module, "System.Security.Cryptography", algorithm[(algorithm.LastIndexOf('.') + 1)..], module.CorLibTypes.AssemblyRef);
            var ctor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), type);
            Assert.True(intrinsic.Matches(ctor));
            Assert.Equal(StaticExecutionStatus.Completed, intrinsic.Invoke(context, ctor, [receiver]).Status);
        }
        Assert.True(state.Heap.TryAllocateByteArray(key, out var keyValue)); Assert.True(state.Heap.TryAllocateByteArray(iv, out var ivValue));
        Assert.True(state.Heap.TryAllocateByteArray(input, out var data));
        foreach (var setting in new[] { ("Key", keyValue), ("IV", ivValue), ("Mode", StaticValue.FromInt32((int)CipherMode.ECB)), ("Padding", StaticValue.FromInt32((int)PaddingMode.None)) })
            Assert.Equal(StaticExecutionStatus.Completed, intrinsic.Invoke(context,
                importer.Import(typeof(SymmetricAlgorithm).GetProperty(setting.Item1)!.SetMethod!), [receiver, setting.Item2]).Status);
        var create = importer.Import(typeof(SymmetricAlgorithm).GetMethod(decrypt ? "CreateDecryptor" : "CreateEncryptor", Type.EmptyTypes)!);
        var transform = intrinsic.Invoke(context, create, [receiver]); Assert.Equal(StaticExecutionStatus.Completed, transform.Status);
        var finish = importer.Import(typeof(ICryptoTransform).GetMethod("TransformFinalBlock")!);
        var result = intrinsic.Invoke(context, finish, [transform.Value, data, StaticValue.FromInt32(0), StaticValue.FromInt32(input.Length)]);
        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        return state.Heap.GetBytesSnapshot(result.Value)!;
    }
}
