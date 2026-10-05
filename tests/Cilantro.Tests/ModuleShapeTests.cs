using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core;
using Cilantro.Core.Verification;

namespace Cilantro.Tests;

/// <summary>
/// Covers the check that the emitted file is the module that was in memory.
/// </summary>
/// <remarks>
/// The point of comparing by name is to survive the renumbering that deletion forces on the writer,
/// so the test that matters is the one where rows were deleted: the check has to accept a file whose
/// tokens all moved, while still catching a member that went missing.
/// </remarks>
public sealed class ModuleShapeTests
{
    [Fact]
    public void DeepPayloadPathsStillVerifyAndDetectChangedOrInvalidFiles()
    {
        using var context = SyntheticContext.Build(module =>
            SyntheticContext.AddType(module, "Host").Methods.Add(NewMethod(module, "Kept")));
        var root = Path.Combine(Path.GetTempPath(), $"Cilantro.LongPath.{Guid.NewGuid():N}");
        var directory = Path.Combine(root, new string('a', 100), new string('b', 100), new string('c', 100));
        var path = Path.Combine(directory, "payload.cleaned.dll");
        Assert.True(path.Length > 260);
        try
        {
            Directory.CreateDirectory(directory);
            context.Module.Write(path);
            var expected = ModuleShape.Capture(context.Module);
            var verified = AssemblyVerifier.VerifyFile(path);
            var roundTrip = AssemblyVerifier.VerifyRoundTrip(path, expected);
            Assert.True(verified.Passed, string.Join("; ", verified.Diagnostics));
            Assert.True(roundTrip.Passed, string.Join("; ", roundTrip.Diagnostics));

            context.Module.GetTypes().Single(type => type.Name == "Host").Methods.Clear();
            context.Module.Write(path);
            Assert.False(AssemblyVerifier.VerifyRoundTrip(path, expected).Passed);

            File.WriteAllBytes(path, [0, 1, 2, 3]);
            Assert.False(AssemblyVerifier.VerifyFile(path).Passed);
            Assert.False(AssemblyVerifier.VerifyRoundTrip(path, expected).Passed);
            File.Delete(path);
            Assert.False(AssemblyVerifier.VerifyFile(path).Passed);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void ARoundTripAgreesWithTheModuleItCameFrom()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Host");
            type.Attributes = TypeAttributes.Public | TypeAttributes.Class;
            type.Methods.Add(NewMethod(module, "Alpha"));
            type.Methods.Add(NewMethod(module, "Beta"));
        });

        Assert.True(WriteAndVerify(context.Module, ModuleShape.Capture(context.Module)).Passed);
    }

    [Fact]
    public void DeletingARowIsAcceptedEvenThoughEveryLaterTokenMoves()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Host");
            type.Attributes = TypeAttributes.Public | TypeAttributes.Class;
            type.Methods.Add(NewMethod(module, "First"));
            type.Methods.Add(NewMethod(module, "Doomed"));
            type.Methods.Add(NewMethod(module, "Last"));
        });
        var host = context.Module.GetTypes().Single(type => type.Name == "Host");
        host.Methods.Remove(host.Methods.Single(method => method.Name == "Doomed"));

        var result = WriteAndVerify(context.Module, ModuleShape.Capture(context.Module));

        Assert.True(result.Passed, string.Join("; ", result.Diagnostics));
    }

    [Fact]
    public void AMemberTheWriterDroppedIsReported()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Host");
            type.Attributes = TypeAttributes.Public | TypeAttributes.Class;
            type.Methods.Add(NewMethod(module, "Kept"));
            type.Methods.Add(NewMethod(module, "Vanishing"));
        });
        var expected = ModuleShape.Capture(context.Module);
        var host = context.Module.GetTypes().Single(type => type.Name == "Host");
        host.Methods.Remove(host.Methods.Single(method => method.Name == "Vanishing"));

        var result = WriteAndVerify(context.Module, expected);

        Assert.False(result.Passed);
        Assert.Contains(result.Diagnostics, message => message.Contains("Vanishing", StringComparison.Ordinal));
    }

    private static MethodDefUser NewMethod(ModuleDef module, string name)
    {
        var method = new MethodDefUser(
            name,
            MethodSig.CreateStatic(module.CorLibTypes.Void),
            MethodImplAttributes.IL,
            MethodAttributes.Public | MethodAttributes.Static)
        {
            Body = new CilBody()
        };
        method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        return method;
    }

    private static VerificationResult WriteAndVerify(ModuleDef module, ModuleShape expected)
    {
        var path = Path.Combine(Path.GetTempPath(), $"Cilantro.Shape.{Guid.NewGuid():N}.dll");
        try
        {
            module.Write(path);
            return AssemblyVerifier.VerifyRoundTrip(path, expected);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
