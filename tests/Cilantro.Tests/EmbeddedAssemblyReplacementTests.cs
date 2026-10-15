using System.Security.Cryptography;
using Cilantro.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class EmbeddedAssemblyReplacementTests
{
    [Fact]
    public void PreservesResourceContractAndDoesNotMutateInput()
    {
        var input = Image();
        var recovered = Image(value: 2);
        var original = new EmbeddedResource("payload", input, ManifestResourceAttributes.Private);
        var prepared = EmbeddedAssemblyReplacement.Prepare(original, Hash(input), recovered);
        Assert.Equal(original.Name, prepared.Name);
        Assert.Equal(original.Attributes, prepared.Attributes);
        Assert.Equal(input, original.CreateReader().ToArray());
        Assert.Equal(recovered, prepared.CreateReader().ToArray());
        var saved = recovered.ToArray();
        recovered[0] = 0;
        Assert.Equal(saved, prepared.CreateReader().ToArray());
    }

    [Theory]
    [InlineData("identity")]
    [InlineData("version")]
    [InlineData("arguments")]
    [InlineData("no-entry")]
    [InlineData("hash")]
    public void RefusesIncompatibleChild(string change)
    {
        var input = Image();
        var recovered = Image(name: change == "identity" ? "Different" : "Child",
            version: change == "version" ? 2 : 1, arguments: change == "arguments", entry: change != "no-entry");
        var resource = new EmbeddedResource("payload", input);
        Assert.Throws<InvalidDataException>(() => EmbeddedAssemblyReplacement.Prepare(resource,
            change == "hash" ? new string('0', 64) : Hash(input), recovered));
        Assert.Equal(input, resource.CreateReader().ToArray());
    }

    private static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    private static byte[] Image(string name = "Child", int version = 1, bool arguments = false, bool entry = true, int value = 1)
    {
        using var module = new ModuleDefUser("child.exe") { Kind = ModuleKind.Console };
        var assembly = new AssemblyDefUser(name, new Version(version, 0, 0, 0));
        assembly.Modules.Add(module);
        var type = new TypeDefUser("Example", "Program", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(type);
        var method = new MethodDefUser("Main", arguments
            ? MethodSig.CreateStatic(module.CorLibTypes.Int32, new SZArraySig(module.CorLibTypes.String))
            : MethodSig.CreateStatic(module.CorLibTypes.Int32), MethodAttributes.Public | MethodAttributes.Static)
            { Body = new CilBody() };
        method.Body.Instructions.Add(Instruction.CreateLdcI4(value));
        method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        type.Methods.Add(method);
        if (entry) module.EntryPoint = method;
        using var stream = new MemoryStream();
        module.Write(stream);
        return stream.ToArray();
    }
}
