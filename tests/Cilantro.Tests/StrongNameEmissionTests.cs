using System.Security.Cryptography;
using Cilantro.Core;
using Cilantro.Core.Pipeline;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

namespace Cilantro.Tests;

public sealed class StrongNameEmissionTests
{
    private static readonly Lazy<byte[]> KeyBytes = new(NewKey);
    private static readonly Lazy<byte[]> OtherKeyBytes = new(NewKey);

    [Fact]
    public void RewrittenSignedAssemblyIsSignedWithTheMatchingExplicitKey()
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.Signing.").FullName;
        try
        {
            var input = WriteInput(directory); var before = File.ReadAllBytes(input);
            var keyPath = Path.Combine(directory, "test-only.snk"); File.WriteAllBytes(keyPath, KeyBytes.Value);
            var otherPath = Path.Combine(directory, "another-test-key.snk"); File.WriteAllBytes(otherPath, OtherKeyBytes.Value);
            var result = new CilantroPipeline().Run(input, new PipelineOptions(OutputPath: Path.Combine(directory, "cleaned.dll"),
                ReportDirectory: Path.Combine(directory, "reports"), GenericRecovery: true) { StrongNameKeyFiles = [otherPath, keyPath] });
            Assert.True(result.Success, string.Join("; ", result.Report.VerificationDiagnostics)); Assert.NotNull(result.OutputPath);
            Assert.True(StrongNameEmission.Verify(result.OutputPath, new StrongNameKey(KeyBytes.Value), out var why), why);
            Assert.Equal(before, File.ReadAllBytes(input));
            Assert.Contains(result.Report.Evidence, evidence => evidence.Category == "strong-name-signing");
            var bytes = File.ReadAllBytes(result.OutputPath);
            var offset = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3c, 4)) + 8;
            bytes[offset] ^= 1; File.WriteAllBytes(result.OutputPath, bytes);
            Assert.False(StrongNameEmission.Verify(result.OutputPath, new StrongNameKey(KeyBytes.Value), out _));
        }
        finally { Directory.Delete(directory, true); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void WrongOrMalformedPrivateKeysWithholdTheCleanedFile(bool malformed)
    {
        var directory = Directory.CreateTempSubdirectory("Cilantro.SigningRefusal.").FullName;
        try
        {
            var input = WriteInput(directory); var before = File.ReadAllBytes(input);
            var key = Path.Combine(directory, "wrong.snk"); File.WriteAllBytes(key, malformed ? [1, 2, 3] : OtherKeyBytes.Value);
            var output = Path.Combine(directory, "cleaned.dll");
            var result = new CilantroPipeline().Run(input, new PipelineOptions(OutputPath: output, ReportDirectory: Path.Combine(directory, "reports"),
                GenericRecovery: true) { StrongNameKeyFiles = [key] });
            Assert.False(result.Success); Assert.Null(result.OutputPath); Assert.False(File.Exists(output));
            Assert.Contains(result.Report.VerificationDiagnostics, diagnostic => diagnostic.Contains("Strong-name signing declined", StringComparison.Ordinal));
            Assert.Equal(before, File.ReadAllBytes(input));
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public void UnsignedAssembliesDoNotConsumeKeysOrChangeTheirIdentity()
    {
        using var module = new ModuleDefUser("unsigned.dll");
        Assert.True(StrongNameEmission.TryPrepare(module, ["does-not-exist.snk"], out var key, out _)); Assert.Null(key);
    }

    [Fact]
    public void AStrongNameFlagWithoutAPublicKeyCannotAuthorizeSigning()
    {
        using var module = new ModuleDefUser("invalid.dll") { IsStrongNameSigned = true };
        new AssemblyDefUser("Invalid", new Version(1, 0)).Modules.Add(module);
        Assert.False(StrongNameEmission.TryPrepare(module, ["does-not-exist.snk"], out var key, out _)); Assert.Null(key);
    }

    private static string WriteInput(string directory)
    {
        using var module = new ModuleDefUser("Signed.dll") { Kind = ModuleKind.Dll, IsStrongNameSigned = true };
        var key = new StrongNameKey(KeyBytes.Value);
        new AssemblyDefUser("Signed", new Version(1, 0)) { PublicKey = new PublicKey(key.PublicKey), Attributes = AssemblyAttributes.PublicKey }.Modules.Add(module);
        var type = new TypeDefUser("Test", "Program", module.CorLibTypes.Object.TypeDefOrRef) { Attributes = TypeAttributes.Public };
        module.Types.Add(type);
        var method = new MethodDefUser("Value", MethodSig.CreateStatic(module.CorLibTypes.Int32), MethodAttributes.Public | MethodAttributes.Static)
            { Body = new CilBody() }; type.Methods.Add(method);
        method.Body.Instructions.Add(OpCodes.Ldc_I4_7.ToInstruction()); method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        var options = new ModuleWriterOptions(module); options.InitializeStrongNameSigning(module, key);
        var path = Path.Combine(directory, "Signed.dll"); module.Write(path, options); return path;
    }

    private static byte[] NewKey()
    {
        using var rsa = RSA.Create(2048); var parameters = rsa.ExportParameters(true);
        using var bytes = new MemoryStream(); using var writer = new BinaryWriter(bytes);
        writer.Write((byte)7); writer.Write((byte)2); writer.Write((ushort)0); writer.Write(0x2400u); writer.Write(0x32415352u); writer.Write(2048u);
        uint exponent = 0; foreach (var value in parameters.Exponent!) exponent = exponent << 8 | value; writer.Write(exponent);
        foreach (var value in new[] { parameters.Modulus!, parameters.P!, parameters.Q!, parameters.DP!, parameters.DQ!, parameters.InverseQ!, parameters.D! })
            writer.Write(value.Reverse().ToArray());
        writer.Flush(); return bytes.ToArray();
    }
}
