using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core;
using Cilantro.Core.Interpretation;

namespace Cilantro.Tests;

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
    private readonly string _folder = Directory.CreateTempSubdirectory("Cilantro.Library").FullName;

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
    /// The same call, reached through a delegate instead of spelled directly.
    /// </summary>
    /// <remarks>
    /// Reactor routes its runtime's calls through generated delegates, so this is the shape the
    /// interpreter actually meets on a protected sample. Which library the call lands in is the
    /// sample's business; whether its IL may be run is not, and reaching it through a delegate
    /// cannot be a way of asking for what a direct call would be refused.
    /// </remarks>
    [Fact]
    public void ADelegateIntoALibraryGoesNowhereUntilTheLibraryIsSupplied()
    {
        var library = WriteLibrary("helper", 41);
        using var context = ArtifactContext.Load(WriteDelegateCaller("caller"), [library]);

        var alone = new StaticMachine().Execute(Entry(context));

        Assert.Equal(StaticExecutionStatus.Unsupported, alone.Status);
        Assert.Contains("not allowlisted", alone.Diagnostic, StringComparison.Ordinal);
    }

    [Fact]
    public void ADelegateIntoASuppliedLibraryIsRunLikeTheSamplesOwnCode()
    {
        var library = WriteLibrary("helper", 41);
        using var context = ArtifactContext.Load(WriteDelegateCaller("caller"), [library]);
        var machine = new StaticMachine();
        machine.State.RegisterModuleMetadata(context.Module);
        foreach (var trusted in context.TrustedModules)
            machine.State.RegisterTrustedModule(trusted);

        var result = machine.Execute(Entry(context));

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(41, result.Value.AsInt32());
    }

    /// <summary>
    /// A framework call reached through a delegate is answered by the model, whatever is on disk.
    /// </summary>
    /// <remarks>
    /// This is the shape that made a run depend on the machine it ran on. Reactor reaches
    /// <c>Monitor.Enter</c> through a generated delegate, and the reference resolves to a body on a
    /// machine that has that framework installed and to nothing on one that does not. Interpreting
    /// the framework's own IL loses what the model knows — that a lock with one thread contending
    /// is always taken — because the real <c>Enter</c> hands off to an internal call the machine
    /// cannot follow, leaving the caller to conclude the lock was not acquired. Answering from the
    /// model instead gives the same reading everywhere.
    /// </remarks>
    [Fact]
    public void AFrameworkCallThroughADelegateIsAnsweredByTheModelNotByWhatIsOnDisk()
    {
        var framework = WriteMonitorLibrary("helper");
        // Resolvable but never supplied, which is the position a Windows machine is in: its
        // installed framework answers the reference whether or not the run asked for it.
        using var context = ArtifactContext.Load(WriteMonitorCaller("caller"), [framework]);
        // The point of the test is a body that is there to be run, so say so: were the reference
        // to resolve to nothing, the model would answer for that reason and prove nothing.
        Assert.True(Bound(context).ResolveMethodDef() is { HasBody: true });
        var machine = new StaticMachine();
        machine.State.RegisterModuleMetadata(context.Module);

        var result = machine.Execute(Entry(context));

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(1, result.Value.AsInt32());
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

    /// <summary>The method the sample's delegate was built over.</summary>
    private static IMethod Bound(ArtifactContext context) => context.Module
        .GetTypes()
        .SelectMany(type => type.Methods)
        .Where(method => method.HasBody)
        .SelectMany(method => method.Body.Instructions)
        .Where(instruction => instruction.OpCode == OpCodes.Ldftn)
        .Select(instruction => (IMethod)instruction.Operand)
        .First();

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

    /// <summary>
    /// An assembly on disk that declares the framework's own <c>Monitor</c>, standing in for the
    /// framework a Windows machine has installed and a Linux one does not.
    /// </summary>
    /// <remarks>
    /// Its <c>Enter</c> leaves the caller's flag alone, which is what the real one looks like to
    /// this machine: the framework's body only passes the flag on to an internal call, and an
    /// internal call is not something the interpreter can follow.
    /// </remarks>
    private string WriteMonitorLibrary(string name)
    {
        var module = new ModuleDefUser($"{name}.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser(name, new Version(1, 0, 0, 0));
        assembly.Modules.Add(module);
        var type = new TypeDefUser(
            "System.Threading", "Monitor", module.CorLibTypes.Object.TypeDefOrRef)
        {
            Attributes = TypeAttributes.Public | TypeAttributes.Class
        };
        module.Types.Add(type);
        var method = new MethodDefUser(
            "Enter",
            MethodSig.CreateStatic(
                module.CorLibTypes.Void,
                module.CorLibTypes.Object,
                new ByRefSig(module.CorLibTypes.Boolean)))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(method);
        var path = Path.Combine(_folder, $"{name}.dll");
        module.Write(path);
        return path;
    }

    /// <summary>A sample that takes a lock through a generated delegate and reports the flag.</summary>
    private string WriteMonitorCaller(string name)
    {
        var module = new ModuleDefUser($"{name}.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser(name, new Version(1, 0, 0, 0));
        assembly.Modules.Add(module);
        var reference = new AssemblyRefUser("helper", new Version(1, 0, 0, 0));
        module.UpdateRowId(reference);
        var taking = MethodSig.CreateStatic(
            module.CorLibTypes.Void,
            module.CorLibTypes.Object,
            new ByRefSig(module.CorLibTypes.Boolean));
        var enter = new MemberRefUser(
            module,
            "Enter",
            taking,
            new TypeRefUser(module, "System.Threading", "Monitor", reference));

        // A proxy delegate of the kind Reactor generates: the runtime supplies both bodies, so the
        // only way to know what calling it means is the method it was built over.
        var proxy = new TypeDefUser(
            "Sample",
            "Enterer",
            new TypeRefUser(
                module, "System", "MulticastDelegate", module.CorLibTypes.AssemblyRef))
        {
            Attributes = TypeAttributes.Public | TypeAttributes.Sealed
        };
        module.Types.Add(proxy);
        proxy.Methods.Add(new MethodDefUser(
            ".ctor",
            MethodSig.CreateInstance(
                module.CorLibTypes.Void,
                module.CorLibTypes.Object,
                module.CorLibTypes.IntPtr))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.HideBySig |
                MethodAttributes.SpecialName | MethodAttributes.RTSpecialName,
            ImplAttributes = MethodImplAttributes.Runtime
        });
        var invoke = new MethodDefUser(
            "Invoke",
            MethodSig.CreateInstance(
                module.CorLibTypes.Void,
                module.CorLibTypes.Object,
                new ByRefSig(module.CorLibTypes.Boolean)))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.HideBySig |
                MethodAttributes.NewSlot | MethodAttributes.Virtual,
            ImplAttributes = MethodImplAttributes.Runtime
        };
        proxy.Methods.Add(invoke);

        var type = new TypeDefUser("Sample", "Program", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(type);
        var method = new MethodDefUser("Ask", MethodSig.CreateStatic(module.CorLibTypes.Int32))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        var taken = new Local(module.CorLibTypes.Boolean);
        method.Body.Variables.Add(taken);
        method.Body.InitLocals = true;
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc, taken));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldftn, enter));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Newobj, proxy.FindMethod(".ctor")));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca, taken));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, invoke));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc, taken));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(method);
        var path = Path.Combine(_folder, $"{name}.dll");
        module.Write(path);
        return path;
    }

    /// <summary>The same sample, reaching the library through a delegate it builds first.</summary>
    private string WriteDelegateCaller(string name)
    {
        var module = new ModuleDefUser($"{name}.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser(name, new Version(1, 0, 0, 0));
        assembly.Modules.Add(module);
        var reference = new AssemblyRefUser("helper", new Version(1, 0, 0, 0));
        module.UpdateRowId(reference);
        var answers = new TypeRefUser(module, "Library", "Answers", reference);
        var answer = new MemberRefUser(
            module,
            "Answer",
            MethodSig.CreateStatic(module.CorLibTypes.Int32),
            answers);

        // A framework delegate type, which is what a generated proxy is built over and what the
        // machine is meant never to be able to look inside.
        var function = new TypeSpecUser(new GenericInstSig(
            new ClassSig(new TypeRefUser(
                module, "System", "Func`1", module.CorLibTypes.AssemblyRef)),
            module.CorLibTypes.Int32));
        var construct = new MemberRefUser(
            module,
            ".ctor",
            MethodSig.CreateInstance(
                module.CorLibTypes.Void,
                module.CorLibTypes.Object,
                module.CorLibTypes.IntPtr),
            function);
        var invoke = new MemberRefUser(
            module,
            "Invoke",
            MethodSig.CreateInstance(new GenericVar(0)),
            function);

        var type = new TypeDefUser("Sample", "Program", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(type);
        var method = new MethodDefUser("Ask", MethodSig.CreateStatic(module.CorLibTypes.Int32))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldftn, answer));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Newobj, construct));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, invoke));
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
