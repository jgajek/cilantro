using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;

namespace Cilantro.Tests;

/// <summary>
/// Covers recognizing a method a code virtualizer emptied, by the shape of the seam it leaves.
/// </summary>
/// <remarks>
/// The point of matching a shape rather than a known engine is that it should hold when the engine
/// is one the tool has never seen, and should not hold for ordinary code that happens to build an
/// object array. Both halves are worth pinning: a detector that answers yes too easily would report
/// virtualization on clean assemblies, which is worse than saying nothing, because the whole value
/// of the answer is telling an analyst which parts of a report do not cover the code.
/// </remarks>
public sealed class VirtualizedMethodDetectionTests
{
    [Fact]
    public void AStubThatPacksItsArgumentsAndCallsAnInterpreterIsFound()
    {
        var module = NewModule();
        var entry = AddEntry(module);
        AddStub(module, "Hidden", entry, programId: 7, arguments: 2);

        var found = Assert.Single(VirtualizedMethodDetector.Detect(module));

        Assert.Equal("Hidden", found.Stub.Name);
        Assert.Equal(7, found.ProgramId);
        Assert.Equal(2, found.ArgumentCount);
        Assert.Same(entry, found.Entry);
    }

    [Fact]
    public void SeveralStubsSharingOneInterpreterAreAllFound()
    {
        var module = NewModule();
        var entry = AddEntry(module);
        AddStub(module, "First", entry, programId: 0, arguments: 1);
        AddStub(module, "Second", entry, programId: 1, arguments: 3);

        var found = VirtualizedMethodDetector.Detect(module);

        Assert.Equal(2, found.Count);
        Assert.Equal([0, 1], found.Select(item => item.ProgramId));
    }

    /// <summary>
    /// Two stubs claiming the same program mean the constant is not a program identity, so the
    /// reading is wrong and reporting it would invent a fact.
    /// </summary>
    [Fact]
    public void StubsThatDisagreeAboutWhichProgramIsWhichAreNotReported()
    {
        var module = NewModule();
        var entry = AddEntry(module);
        AddStub(module, "First", entry, programId: 4, arguments: 1);
        AddStub(module, "Second", entry, programId: 4, arguments: 1);

        Assert.Empty(VirtualizedMethodDetector.Detect(module));
    }

    [Fact]
    public void AMethodThatDoesWorkOfItsOwnIsNotAStub()
    {
        var module = NewModule();
        var entry = AddEntry(module);
        var stub = AddStub(module, "Busy", entry, programId: 2, arguments: 1);
        var instructions = stub.Body.Instructions;
        instructions.Insert(instructions.Count - 1, OpCodes.Call.ToInstruction(entry));

        Assert.Empty(VirtualizedMethodDetector.Detect(module));
    }

    [Fact]
    public void AMethodThatLeavesOneOfItsArgumentsOutIsNotAStub()
    {
        var module = NewModule();
        var entry = AddEntry(module);
        // Two parameters, but the array only ever receives the first: an interpreter given this
        // could not run a body that reads the second, so the shape is something else.
        AddStub(module, "Partial", entry, programId: 3, arguments: 2, storeArguments: 1);

        Assert.Empty(VirtualizedMethodDetector.Detect(module));
    }

    [Fact]
    public void OrdinaryCodeThatBuildsAnObjectArrayIsNotAStub()
    {
        var module = NewModule();
        var format = new MemberRefUser(
            module,
            "Format",
            MethodSig.CreateStatic(
                module.CorLibTypes.String,
                module.CorLibTypes.String,
                new SZArraySig(module.CorLibTypes.Object)),
            module.CorLibTypes.GetTypeRef("System", "String"));
        var method = new MethodDefUser(
            "Describe",
            MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.Object),
            MethodImplAttributes.IL,
            MethodAttributes.Public | MethodAttributes.Static)
        {
            Body = new CilBody()
        };
        var body = method.Body.Instructions;
        body.Add(OpCodes.Ldstr.ToInstruction("{0}"));
        body.Add(OpCodes.Ldc_I4_1.ToInstruction());
        body.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Object.TypeDefOrRef));
        body.Add(OpCodes.Dup.ToInstruction());
        body.Add(OpCodes.Ldc_I4_0.ToInstruction());
        body.Add(OpCodes.Ldarg_0.ToInstruction());
        body.Add(OpCodes.Stelem_Ref.ToInstruction());
        body.Add(OpCodes.Call.ToInstruction(format));
        body.Add(OpCodes.Ret.ToInstruction());
        module.Types[0].Methods.Add(method);

        Assert.Empty(VirtualizedMethodDetector.Detect(module));
    }

    private static ModuleDefUser NewModule()
    {
        var module = new ModuleDefUser("subject.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser("subject", new Version(1, 0));
        assembly.Modules.Add(module);
        module.Types.Add(new TypeDefUser(
            "Subject", "Holder", module.CorLibTypes.Object.TypeDefOrRef)
        {
            Attributes = TypeAttributes.Public | TypeAttributes.Class
        });
        return module;
    }

    /// <summary>
    /// A program run from a method that does work of its own is still a program the file holds.
    /// </summary>
    /// <remarks>
    /// This is the gap the stub shape leaves, and on a Reactor file it is not a small one: the
    /// program that assigns the state every opaque predicate reads is run from a type initializer
    /// wrapped in the same flattened control flow as everything else. Counting the stubs answers
    /// which methods are nothing but a program, which is the right question for deciding what a
    /// body can be built into and the wrong one for deciding what the file contains.
    /// </remarks>
    [Fact]
    public void AProgramRunFromAMethodThatDoesOtherWorkIsFoundEvenThoughNoStubStandsForIt()
    {
        var module = NewModule();
        var entry = AddEntry(module);
        AddStub(module, "Hidden", entry, programId: 0, arguments: 1);
        AddBusyCaller(module, "Initializer", entry, programId: 1);

        var stubs = VirtualizedMethodDetector.Detect(module);
        var invocations = VirtualizedMethodDetector.Invocations(module, stubs);

        Assert.Single(stubs);
        Assert.Equal([0, 1], invocations.Select(item => item.ProgramId));
        Assert.Equal([true, false], invocations.Select(item => item.Replaced));
        Assert.Equal("Initializer", invocations[1].Caller.Name);
    }

    /// <summary>
    /// What makes a method an interpreter is that a stub enters it that way, so with no stub
    /// matched there is no entry to count calls to.
    /// </summary>
    [Fact]
    public void NoProgramIsFoundWhereNoStubHasShownWhichMethodTheInterpreterIs()
    {
        var module = NewModule();
        var entry = AddEntry(module);
        AddBusyCaller(module, "Initializer", entry, programId: 1);

        Assert.Empty(VirtualizedMethodDetector.Invocations(module, []));
    }

    /// <summary>
    /// A call site that does not say plainly which program it wants is not read as wanting one.
    /// </summary>
    [Fact]
    public void ACallThatDoesNotNameItsProgramWithAConstantIsNotReported()
    {
        var module = NewModule();
        var entry = AddEntry(module);
        AddStub(module, "Hidden", entry, programId: 0, arguments: 1);
        var busy = AddBusyCaller(module, "Computed", entry, programId: 1);
        // The constant becomes a sum, which is still one value on the stack but no longer one the
        // call site states.
        var instructions = busy.Body.Instructions;
        var at = instructions.IndexOf(instructions.First(item => item.OpCode == OpCodes.Ldc_I4));
        instructions.Insert(at + 1, OpCodes.Ldc_I4_1.ToInstruction());
        instructions.Insert(at + 2, OpCodes.Add.ToInstruction());

        var stubs = VirtualizedMethodDetector.Detect(module);

        Assert.Equal([0], VirtualizedMethodDetector.Invocations(module, stubs)
            .Select(item => item.ProgramId));
    }

    private static MethodDefUser AddBusyCaller(
        ModuleDefUser module,
        string name,
        IMethod entry,
        int programId)
    {
        var caller = new MethodDefUser(
            name,
            MethodSig.CreateStatic(module.CorLibTypes.Void),
            MethodImplAttributes.IL,
            MethodAttributes.Public | MethodAttributes.Static)
        {
            Body = new CilBody()
        };
        var packed = new Local(new SZArraySig(module.CorLibTypes.Object));
        caller.Body.Variables.Add(packed);
        var body = caller.Body.Instructions;
        // It takes no arguments to pack, which is by itself enough for the shape match to decline:
        // a method with no parameters cannot be one whose parameters an interpreter was handed.
        body.Add(OpCodes.Ldc_I4_0.ToInstruction());
        body.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Object.TypeDefOrRef));
        body.Add(OpCodes.Stloc.ToInstruction(packed));
        body.Add(OpCodes.Ldc_I4.ToInstruction(programId));
        body.Add(OpCodes.Ldloc.ToInstruction(packed));
        body.Add(OpCodes.Ldnull.ToInstruction());
        body.Add(OpCodes.Call.ToInstruction(entry));
        body.Add(OpCodes.Pop.ToInstruction());
        body.Add(OpCodes.Ret.ToInstruction());
        module.Types[0].Methods.Add(caller);
        return caller;
    }

    private static MethodDefUser AddEntry(ModuleDefUser module)
    {
        var entry = new MethodDefUser(
            "Run",
            MethodSig.CreateStatic(
                new SZArraySig(module.CorLibTypes.Object),
                module.CorLibTypes.Int32,
                module.CorLibTypes.Object,
                module.CorLibTypes.Object),
            MethodImplAttributes.IL,
            MethodAttributes.Public | MethodAttributes.Static)
        {
            Body = new CilBody()
        };
        entry.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
        entry.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        module.Types[0].Methods.Add(entry);
        return entry;
    }

    private static MethodDefUser AddStub(
        ModuleDefUser module,
        string name,
        IMethod entry,
        int programId,
        int arguments,
        int? storeArguments = null)
    {
        var signature = MethodSig.CreateStatic(
            module.CorLibTypes.Void,
            Enumerable.Repeat<TypeSig>(module.CorLibTypes.Object, arguments).ToArray());
        var stub = new MethodDefUser(
            name,
            signature,
            MethodImplAttributes.IL,
            MethodAttributes.Public | MethodAttributes.Static)
        {
            Body = new CilBody()
        };
        var packed = new Local(new SZArraySig(module.CorLibTypes.Object));
        stub.Body.Variables.Add(packed);
        var body = stub.Body.Instructions;
        body.Add(OpCodes.Ldc_I4.ToInstruction(arguments));
        body.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Object.TypeDefOrRef));
        body.Add(OpCodes.Stloc.ToInstruction(packed));
        for (var index = 0; index < (storeArguments ?? arguments); index++)
        {
            body.Add(OpCodes.Ldloc.ToInstruction(packed));
            body.Add(OpCodes.Ldc_I4.ToInstruction(index));
            body.Add(OpCodes.Ldarg.ToInstruction(stub.Parameters[index]));
            body.Add(OpCodes.Stelem_Ref.ToInstruction());
        }
        body.Add(OpCodes.Ldc_I4.ToInstruction(programId));
        body.Add(OpCodes.Ldloc.ToInstruction(packed));
        body.Add(OpCodes.Ldnull.ToInstruction());
        body.Add(OpCodes.Call.ToInstruction(entry));
        body.Add(OpCodes.Pop.ToInstruction());
        body.Add(OpCodes.Ret.ToInstruction());
        module.Types[0].Methods.Add(stub);
        return stub;
    }
}
