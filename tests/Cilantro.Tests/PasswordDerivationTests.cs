using System.Security.Cryptography;
using System.Text;
using Cilantro.Core.Interpretation;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class PasswordDerivationTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SequentialReadsResetAndCopiedInputsMatchTheLegacyConstructor(bool bytesPassword)
    {
        using var module = new ModuleDefUser("Kdf") { Kind = ModuleKind.Dll };
        var state = new StaticMachineState(new StaticMachineLimits());
        var context = new IntrinsicContext(state); var intrinsic = new LoaderFrameworkIntrinsic(); var importer = new Importer(module);
        const string password = "probe password Ω"; byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8];
        Assert.True(state.Heap.TryAllocateObject("System.Security.Cryptography.Rfc2898DeriveBytes", out var receiver));
        Assert.True(state.Heap.TryAllocateByteArray(salt, out var saltValue));
        StaticValue passwordValue;
        if (bytesPassword) Assert.True(state.Heap.TryAllocateByteArray(Encoding.UTF8.GetBytes(password), out passwordValue));
        else Assert.True(state.Heap.TryAllocateString(password, out passwordValue));
        var ctor = importer.Import(typeof(Rfc2898DeriveBytes).GetConstructor([bytesPassword ? typeof(byte[]) : typeof(string), typeof(byte[]), typeof(int)])!);
        Assert.Equal(StaticExecutionStatus.Completed, intrinsic.Invoke(context, ctor, [receiver, passwordValue, saltValue, StaticValue.FromInt32(1000)]).Status);
        Assert.True(state.Heap.TryWriteArray(saltValue, 0, StaticValue.FromInt32(99)));
        var get = importer.Import(typeof(Rfc2898DeriveBytes).GetMethod("GetBytes", [typeof(int)])!);
        byte[] Read(int count)
        {
            var result = intrinsic.Invoke(context, get, [receiver, StaticValue.FromInt32(count)]);
            Assert.Equal(StaticExecutionStatus.Completed, result.Status);
            return state.Heap.GetBytesSnapshot(result.Value)!;
        }
#pragma warning disable CA5350
        var expected = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, 1000, HashAlgorithmName.SHA1, 48);
#pragma warning restore CA5350
        Assert.Equal(expected, Read(32).Concat(Read(16)).ToArray());
        Assert.Equal(StaticExecutionStatus.Completed, intrinsic.Invoke(context, importer.Import(typeof(Rfc2898DeriveBytes).GetMethod("Reset")!), [receiver]).Status);
        Assert.Equal(expected[..32], Read(32));
        Assert.Equal(StaticExecutionStatus.Completed, intrinsic.Invoke(context, importer.Import(typeof(Rfc2898DeriveBytes).GetMethod("Dispose", Type.EmptyTypes)!), [receiver]).Status);
        Assert.NotEqual(StaticExecutionStatus.Completed, intrinsic.Invoke(context, get, [receiver, StaticValue.FromInt32(1)]).Status);
    }

    [Theory]
    [InlineData(0, 16, false)]
    [InlineData(100001, 16, false)]
    [InlineData(1000, 0, false)]
    [InlineData(1000, 65537, false)]
    [InlineData(100000, 1000, false)]
    [InlineData(1000, 16, true)]
    public void InvalidSizesWorkAndInterpreterBudgetRefuse(int iterations, int count, bool exhausted)
    {
        using var module = new ModuleDefUser("Kdf") { Kind = ModuleKind.Dll };
        var state = new StaticMachineState(new StaticMachineLimits()); var intrinsic = new LoaderFrameworkIntrinsic(); var importer = new Importer(module);
        var budget = new StaticWorkBudget(exhausted ? 1 : 4000000);
        var context = new IntrinsicContext(state, ConsumeWork: budget.TryConsumeSteps);
        Assert.True(state.Heap.TryAllocateObject("System.Security.Cryptography.Rfc2898DeriveBytes", out var receiver));
        Assert.True(state.Heap.TryAllocateString("password", out var password));
        Assert.True(state.Heap.TryAllocateByteArray(new byte[8], out var salt));
        var ctor = importer.Import(typeof(Rfc2898DeriveBytes).GetConstructor([typeof(string), typeof(byte[]), typeof(int)])!);
        var created = intrinsic.Invoke(context, ctor, [receiver, password, salt, StaticValue.FromInt32(iterations)]);
        if (iterations is <= 0 or > 100000) { Assert.NotEqual(StaticExecutionStatus.Completed, created.Status); return; }
        Assert.Equal(StaticExecutionStatus.Completed, created.Status);
        var get = importer.Import(typeof(Rfc2898DeriveBytes).GetMethod("GetBytes", [typeof(int)])!);
        var result = intrinsic.Invoke(context, get, [receiver, StaticValue.FromInt32(count)]);
        Assert.Equal(exhausted ? StaticExecutionStatus.StepLimitExceeded : StaticExecutionStatus.InvalidProgram, result.Status);
        Assert.Equal(0, budget.ConsumedSteps);
    }

    [Theory]
    [InlineData("System.Security.Cryptography.Aes", 256, 128)]
    [InlineData("System.Security.Cryptography.RijndaelManaged", 256, 128)]
    [InlineData("System.Security.Cryptography.DES", 64, 64)]
    [InlineData("System.Security.Cryptography.TripleDES", 192, 64)]
    [InlineData("System.Security.Cryptography.RC2", 128, 64)]
    [InlineData("System.Security.Cryptography.RC2CryptoServiceProvider", 128, 64)]
    public void CipherSizesFollowTheActualAlgorithm(string type, int keySize, int blockSize)
    {
        using var module = new ModuleDefUser("Cipher") { Kind = ModuleKind.Dll };
        var state = new StaticMachineState(new StaticMachineLimits()); var intrinsic = new LoaderFrameworkIntrinsic(); var importer = new Importer(module);
        var context = new IntrinsicContext(state);
        Assert.True(state.Heap.TryAllocateObject(type, out var receiver));
        var getKey = importer.Import(typeof(SymmetricAlgorithm).GetProperty("KeySize")!.GetMethod!);
        var getBlock = importer.Import(typeof(SymmetricAlgorithm).GetProperty("BlockSize")!.GetMethod!);
        Assert.Equal(keySize, intrinsic.Invoke(context, getKey, [receiver]).Value.AsInt32());
        Assert.Equal(blockSize, intrinsic.Invoke(context, getBlock, [receiver]).Value.AsInt32());
        Assert.True(state.Heap.TryAllocateObject("UnknownCipher", out var unknown));
        Assert.NotEqual(StaticExecutionStatus.Completed, intrinsic.Invoke(context, getKey, [unknown]).Status);
    }
}
