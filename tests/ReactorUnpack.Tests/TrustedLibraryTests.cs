using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core;
using ReactorUnpack.Core.Interpretation;

namespace ReactorUnpack.Tests;

/// <summary>
/// Covers supplying somebody else's assembly for the interpreter to run the IL of.
/// </summary>
/// <remarks>
/// The point of the feature is a sample whose unpacking runs through a library it did not carry
/// with it, so the tests are shaped the same way: a call out of the sample that goes nowhere until
/// the library is supplied, and a refusal when what is supplied is not what the sample asked for.
/// </remarks>
public sealed class TrustedLibraryTests : IDisposable
{
    private readonly string _folder = Directory.CreateTempSubdirectory("ReactorUnpack.Library").FullName;

    [Fact]
    public void ACallIntoALibraryGoesNowhereUntilTheLibraryIsSupplied()
    {
        var library = WriteLibrary("helper", 41);
        using var context = ArtifactContext.Load(WriteCaller("caller"), [library]);
        var caller = Entry(context);

        var alone = new StaticMachine().Execute(caller);

        Assert.Equal(StaticExecutionStatus.Unsupported, alone.Status);
        Assert.Contains("not allowlisted", alone.Diagnostic, StringComparison.Ordinal);
    }

    [Fact]
    public void ASuppliedLibraryIsRunLikeTheSamplesOwnCode()
    {
        var library = WriteLibrary("helper", 41);
        using var context = ArtifactContext.Load(WriteCaller("caller"), [library]);
        var machine = new StaticMachine();
        machine.State.RegisterModuleMetadata(context.Module);
        foreach (var trusted in context.TrustedModules)
            machine.State.RegisterTrustedModule(trusted);

        var result = machine.Execute(Entry(context));

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(41, result.Value.AsInt32());
    }

    /// <summary>
    /// The identity of the file that was supplied is recorded, because a different build of the
    /// same library is a different program and a result that depended on one should say which.
    /// </summary>
    [Fact]
    public void WhatWasSuppliedIsRecorded()
    {
        var library = WriteLibrary("helper", 41);
        using var context = ArtifactContext.Load(WriteCaller("caller"), [library]);

        var supplied = Assert.Single(context.Libraries);

        Assert.Equal("helper", supplied.Name);
        Assert.Equal("1.0.0.0", supplied.Version);
        Assert.True(supplied.MatchesReference);
        Assert.Equal(64, supplied.Sha256.Length);
    }

    [Fact]
    public void ALibraryTheSampleNeverMentionsIsRefused()
    {
        var unrelated = WriteLibrary("stranger", 7);
        var caller = WriteCaller("caller");

        var thrown = Assert.Throws<TrustedLibraryException>(
            () => ArtifactContext.Load(caller, [unrelated]).Dispose());

        Assert.Contains("stranger is not referenced", thrown.Message, StringComparison.Ordinal);
        Assert.Contains("helper", thrown.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ALibraryThatIsNotThereIsSaidSoPlainly()
    {
        var caller = WriteCaller("caller");

        var thrown = Assert.Throws<TrustedLibraryException>(
            () => ArtifactContext.Load(caller, [Path.Combine(_folder, "absent.dll")]).Dispose());

        Assert.Contains("No such library", thrown.Message, StringComparison.Ordinal);
    }

    public void Dispose() => Directory.Delete(_folder, recursive: true);

    /// <summary>The sample's only method: one call into the library, whose answer it returns.</summary>
    private static MethodDef Entry(ArtifactContext context) => context.Module
        .GetTypes()
        .SelectMany(type => type.Methods)
        .First(method => method.Name == "Ask");

    private string WriteLibrary(string name, int answers)
    {
        var module = new ModuleDefUser($"{name}.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser(name, new Version(1, 0, 0, 0));
        assembly.Modules.Add(module);
        var type = new TypeDefUser("Library", "Answers", module.CorLibTypes.Object.TypeDefOrRef)
        {
            Attributes = TypeAttributes.Public | TypeAttributes.Class
        };
        module.Types.Add(type);
        var method = new MethodDefUser(
            "Answer",
            MethodSig.CreateStatic(module.CorLibTypes.Int32))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, answers));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(method);
        var path = Path.Combine(_folder, $"{name}.dll");
        module.Write(path);
        return path;
    }

    private string WriteCaller(string name)
    {
        var module = new ModuleDefUser($"{name}.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser(name, new Version(1, 0, 0, 0));
        assembly.Modules.Add(module);
        var reference = new AssemblyRefUser("helper", new Version(1, 0, 0, 0));
        module.UpdateRowId(reference);
        var answers = new TypeRefUser(module, "Library", "Answers", reference);
        var type = new TypeDefUser("Sample", "Program", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(type);
        var method = new MethodDefUser("Ask", MethodSig.CreateStatic(module.CorLibTypes.Int32))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        method.Body.Instructions.Add(Instruction.Create(
            OpCodes.Call,
            new MemberRefUser(
                module,
                "Answer",
                MethodSig.CreateStatic(module.CorLibTypes.Int32),
                answers)));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(method);
        var path = Path.Combine(_folder, $"{name}.dll");
        module.Write(path);
        return path;
    }
}
