using System.Buffers.Binary;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Passes;
using Cilantro.Core.Recovery;

namespace Cilantro.Tests;

public sealed class MethodBodyRecoveryTests
{
    [Fact]
    public void CatalogsOnlyTheCurrentFileBackedStubPrefix()
    {
        var file = CreateImage();
        file[0x200] = 0x0E;
        file[0x201] = 0x16;
        file[0x202] = 0x2A;
        file[0x203] = 0x00;
        var image = new PeImageView(file);

        var accepted = MethodBodyRecoveryInfrastructure.TryCatalogStubPrefixWindows(
            image,
            [new ProtectedMethodStub(0x06000001, 0x1000, "stub", 3)],
            out var windows,
            out var diagnostic);

        Assert.True(accepted, diagnostic);
        var window = Assert.Single(windows);
        Assert.Equal(0x06000001u, window.Token);
        Assert.Equal(0x1000u, window.Rva);
        Assert.Equal(0x200, window.FileOffset);
        Assert.Equal(4, window.Length);
    }

    [Fact]
    public void ReplaysMappedWritesAndPreservesEveryByteOutsideWindows()
    {
        var file = CreateImage();
        var image = new PeImageView(file);
        var windows = new[]
        {
            new StubPrefixWindow(0x06000001, 0x1000, 0x200, 4),
            new StubPrefixWindow(0x06000002, 0x1010, 0x210, 3),
        };
        var writes = new[]
        {
            new MappedImageWrite(0x1000, [1, 2, 3, 4], "MappedImage"),
            new MappedImageWrite(0x1011, [5, 6], "MappedImage"),
        };

        var accepted = MethodBodyRecoveryInfrastructure.TryValidateAndReplayWrites(
            image,
            windows,
            writes,
            out var restored,
            out var touched,
            out var diagnostic);

        Assert.True(accepted, diagnostic);
        Assert.Equal(2, touched.Count);
        Assert.Equal([1, 2, 3, 4], restored[0x200..0x204]);
        Assert.Equal([5, 6], restored[0x211..0x213]);
        for (var index = 0; index < file.Length; index++)
        {
            if (index is >= 0x200 and < 0x204 or >= 0x211 and < 0x213)
                continue;
            Assert.Equal(file[index], restored[index]);
        }
    }

    /// <summary>
    /// A module large enough contains a method that returns the default of its type under
    /// NoInlining and was never encrypted, which the stub catalog cannot tell from a real stub.
    /// Reactor writes no body for it, and the replay has to hand back the ones it did write rather
    /// than discarding a whole module's recovery over the one it did not.
    /// </summary>
    [Fact]
    public void ReplaysTheWrittenWindowsWhenACataloguedStubWasNeverProtected()
    {
        var file = CreateImage();
        var image = new PeImageView(file);
        var windows = new[]
        {
            new StubPrefixWindow(0x06000001, 0x1000, 0x200, 4),
            new StubPrefixWindow(0x06000002, 0x1010, 0x210, 3),
        };
        var writes = new[]
        {
            new MappedImageWrite(0x1000, [1, 2, 3, 4], "MappedImage"),
        };

        var accepted = MethodBodyRecoveryInfrastructure.TryValidateAndReplayWrites(
            image,
            windows,
            writes,
            out var restored,
            out var touched,
            out var diagnostic);

        Assert.True(accepted, diagnostic);
        Assert.Equal([0x06000001u], touched);
        Assert.Equal([1, 2, 3, 4], restored[0x200..0x204]);
        // The window nothing was written into keeps the bytes it shipped with, so the method it
        // stands for is left exactly as it was rather than being reported as recovered.
        Assert.Equal(file[0x210..0x213], restored[0x210..0x213]);
    }

    [Theory]
    [InlineData(0x0FFF, 1)]
    [InlineData(0x1003, 2)]
    [InlineData(0x1004, 1)]
    public void RejectsWritesThatCrossOrEscapeAStubPrefix(int offset, int length)
    {
        var image = new PeImageView(CreateImage());
        var writes = new[]
        {
            new MappedImageWrite(offset, new byte[length], "MappedImage"),
        };

        var accepted = MethodBodyRecoveryInfrastructure.TryValidateAndReplayWrites(
            image,
            [new StubPrefixWindow(0x06000001, 0x1000, 0x200, 4)],
            writes,
            out _,
            out _,
            out var diagnostic);

        Assert.False(accepted);
        Assert.Contains("outside one stub prefix", diagnostic);
    }

    /// <summary>
    /// The bootstrap costs between 2,050 and 2,550 steps per protected stub across every Reactor
    /// sample measured, so its ceiling has to grow with the stub count. The figures below are the
    /// two ends of that range in practice: a 197-stub module, which the old flat ceiling suited,
    /// and a 5,367-stub one, which needed 12,482,286 steps and was refused by it.
    /// </summary>
    [Theory]
    [InlineData(197, 2_000_000)]
    [InlineData(313, 3_130_000)]
    [InlineData(5_367, 53_670_000)]
    public void ScalesTheStepCeilingWithTheNumberOfProtectedStubs(int stubs, int expected) =>
        Assert.Equal(expected, MethodBodyRecoveryPass.StepBudgetFor(stubs));

    [Fact]
    public void KeepsTheSmallestModulesOnTheCeilingTheyAlreadyHad() =>
        Assert.Equal(2_000_000, MethodBodyRecoveryPass.StepBudgetFor(1));

    [Fact]
    public void AllowsTheStepCeilingObservedToBeNeededByTheLargestSampleOnHand() =>
        Assert.True(MethodBodyRecoveryPass.StepBudgetFor(5_367) > 12_482_286);

    /// <summary>
    /// The pass raises its own ceiling rather than reporting a budget and asking to be run again, so
    /// what matters is how far raising it reaches: far enough that anything still unfinished is a loop
    /// that does not terminate rather than a module that is merely large.
    /// </summary>
    /// <remarks>
    /// Pinned against the dearest bootstrap measured, 2,550 steps for each protected method. The claim
    /// the code makes for itself is thirty times that, and a claim in a comment is worth only as much
    /// as something that fails when it stops being true.
    /// </remarks>
    [Fact]
    public void RaisingTheCeilingReachesWellPastWhatABootstrapCosts()
    {
        const int stubs = 5_367;
        const int dearestMeasured = stubs * 2_550;

        var reached = MethodBodyRecoveryPass.StepBudgetFor(stubs);
        for (var raising = 0; raising < MethodBodyRecoveryPass.MostRaisings; raising++)
            reached *= 2;

        Assert.True(
            reached >= 30 * dearestMeasured,
            $"Raising reaches {reached}, only {(double)reached / dearestMeasured:F1} times the cost.");
    }

    /// <summary>
    /// Raising it stays bounded. A ceiling exists to stop code that never finishes, and one that is
    /// raised without limit is no ceiling at all.
    /// </summary>
    [Fact]
    public void RaisingTheCeilingStopsRatherThanGoingOnForever() =>
        Assert.InRange(MethodBodyRecoveryPass.MostRaisings, 1, 5);

    [Fact]
    public void ReinterpretingAfterAGraftStopsRatherThanGoingOnForever() =>
        Assert.InRange(MethodBodyRecoveryPass.MostRounds, 2, 5);

    [Fact]
    public void SeedingTheBootstrapNamesTheModuleWhoseTokensTheLoaderResolves()
    {
        var context = SyntheticContext.Build(module => SyntheticContext.AddType(module, "Holder"));
        var machine = new StaticMachine(new StaticMachineLimits(), modelTypeInitialization: true);

        Assert.True(BootstrapMachine.TryTell(context, machine, out var diagnostic));
        Assert.Empty(diagnostic);
        Assert.Same(context.Module, machine.State.ModuleMetadata);
    }

    /// <summary>
    /// A loader that reaches its own members by token is only interpretable if the machine has been
    /// told which module those tokens belong to, and there is more than one place that runs the
    /// loader. When one of them omitted this, the loader read as refusing an operation rather than as
    /// having been told too little, so the two are pinned to the same account of the module here.
    /// </summary>
    [Fact]
    public void EveryWayOfRunningTheLoaderIsToldTheSameModule()
    {
        var context = SyntheticContext.Build(module => SyntheticContext.AddType(module, "Holder"));
        Assert.True(BootstrapMachine.TrySeed(context, 1_000, out var seeded, out _));
        var told = new StaticMachine(new StaticMachineLimits(), modelTypeInitialization: true);
        Assert.True(BootstrapMachine.TryTell(context, told, out _));

        Assert.Same(seeded!.State.ModuleMetadata, told.State.ModuleMetadata);
        Assert.Equal(seeded.State.AssemblyName, told.State.AssemblyName);
    }

    [Fact]
    public void RequiresDeterministicOrderedWriteLogs()
    {
        var first = new[]
        {
            new MappedImageWrite(1, [1, 2], "MappedImage"),
            new MappedImageWrite(3, [3], "MappedImage"),
        };
        var same = first.Select(write =>
            new MappedImageWrite(write.Offset, (byte[])write.Bytes.Clone(), write.RegionKind)).ToArray();
        var reordered = same.Reverse().ToArray();

        Assert.True(MethodBodyRecoveryInfrastructure.WriteLogsEqual(first, same));
        Assert.False(MethodBodyRecoveryInfrastructure.WriteLogsEqual(first, reordered));
    }

    [Fact]
    public void ClonesBodiesWithLocalParameterBranchAndHandlerRemapping()
    {
        using var sourceModule = NewModule("source");
        using var destinationModule = NewModule("destination");
        var source = NewMethod(sourceModule);
        var destination = NewMethod(destinationModule, withBody: false);

        var cloned = MethodBodyRecoveryInfrastructure.CloneBody(
            source,
            destination,
            destinationModule);

        Assert.NotSame(source.Body, cloned);
        Assert.NotSame(source.Body.Variables[0], cloned.Variables[0]);
        Assert.Same(cloned.Variables[0], cloned.Instructions[1].Operand);
        Assert.Same(destination.Parameters[0], cloned.Instructions[2].Operand);
        Assert.Same(cloned.Instructions[6], cloned.Instructions[3].Operand);
        var targets = Assert.IsType<Instruction[]>(cloned.Instructions[5].Operand);
        Assert.Same(cloned.Instructions[6], targets[0]);
        var handler = Assert.Single(cloned.ExceptionHandlers);
        Assert.Same(cloned.Instructions[0], handler.TryStart);
        Assert.Same(cloned.Instructions[4], handler.TryEnd);
        Assert.Same(cloned.Instructions[6], handler.HandlerStart);
        Assert.Null(handler.HandlerEnd);
        Assert.NotNull(handler.CatchType);
    }

    private static ModuleDefUser NewModule(string name)
    {
        var module = new ModuleDefUser(name + ".dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser(name, new Version(1, 0));
        assembly.Modules.Add(module);
        return module;
    }

    private static MethodDefUser NewMethod(ModuleDef module, bool withBody = true)
    {
        var type = new TypeDefUser("Tests", "Holder", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(type);
        var method = new MethodDefUser(
            "Recover",
            MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32),
            MethodAttributes.Public | MethodAttributes.Static);
        type.Methods.Add(method);
        if (!withBody)
            return method;

        method.Body = new CilBody { InitLocals = true, MaxStack = 2 };
        var local = new Local(module.CorLibTypes.Int32);
        method.Body.Variables.Add(local);
        var instructions = new[]
        {
            Instruction.Create(OpCodes.Ldc_I4_0),
            Instruction.Create(OpCodes.Stloc, local),
            Instruction.Create(OpCodes.Ldarg, method.Parameters[0]),
            new Instruction(OpCodes.Brfalse),
            Instruction.Create(OpCodes.Ldc_I4_0),
            Instruction.Create(OpCodes.Switch, Array.Empty<Instruction>()),
            Instruction.Create(OpCodes.Ret),
        };
        instructions[3].Operand = instructions[6];
        instructions[5].Operand = new[] { instructions[6] };
        foreach (var instruction in instructions)
            method.Body.Instructions.Add(instruction);
        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
        {
            TryStart = instructions[0],
            TryEnd = instructions[4],
            HandlerStart = instructions[6],
            HandlerEnd = null,
            CatchType = module.CorLibTypes.Object.TypeDefOrRef,
        });
        return method;
    }

    private static byte[] CreateImage()
    {
        const int peOffset = 0x80;
        const int optionalHeaderSize = 0xE0;
        var file = new byte[0x400];
        BinaryPrimitives.WriteUInt16LittleEndian(file, 0x5A4D);
        BinaryPrimitives.WriteInt32LittleEndian(file.AsSpan(0x3C), peOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(peOffset), 0x00004550);
        var coff = peOffset + 4;
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(coff), 0x14C);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(coff + 2), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(coff + 16), optionalHeaderSize);
        var optional = coff + 20;
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(optional), 0x10B);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(optional + 28), 0x00400000);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(optional + 32), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(optional + 36), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(optional + 56), 0x2000);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(optional + 60), 0x200);
        var section = optional + optionalHeaderSize;
        System.Text.Encoding.ASCII.GetBytes(".text").CopyTo(file.AsSpan(section));
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(section + 8), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(section + 12), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(section + 16), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(section + 20), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(section + 36), 0x60000020);
        for (var index = 0x200; index < file.Length; index++)
            file[index] = unchecked((byte)index);
        return file;
    }
}
