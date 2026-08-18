using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;

namespace Cilantro.Tests;

/// <summary>
/// Covers reading a virtualized method's program back out of the engine that decoded it.
/// </summary>
/// <remarks>
/// The engine here is deliberately not the one in any sample. It keeps its program encrypted, uses
/// its own names for everything, and numbers its operations arbitrarily, because those are exactly
/// the things that differ between builds of a real virtualizer and the recovery is worthless if it
/// depends on any of them. What it does share with a real one is the only thing that has to be
/// true: the program is decoded into objects before any of it runs, and the operation being
/// executed is passed to something.
///
/// The encryption matters to the test. If recovery were reading raw bytes rather than what the
/// engine decoded them to, the opcodes would come back as the stored values and not the real ones.
/// </remarks>
public sealed class VirtualProgramRecoveryTests
{
    private const byte Key = 0x5A;

    /// <summary>The four places a clause has to name, under names of the test's own.</summary>
    private static readonly string[] Places = ["From", "To", "Handler", "Ends"];

    /// <summary>Opcode, operand — the shape the listing is written from.</summary>
    private static readonly (int Opcode, int Operand)[] Program =
    [
        (17, 100),
        (42, 0x06000001),
        (17, -3),
        (99, 0)
    ];

    [Fact]
    public void TheProgramTheEngineDecodedIsReadBack()
    {
        using var context = SyntheticContext.Build(AddEngine);
        var method = Assert.Single(VirtualizedMethodDetector.Detect(context.Module));

        var recovered = VirtualProgramRecovery.Recover(context, method, out var diagnostic);

        Assert.NotNull(recovered);
        Assert.Contains("decoded", diagnostic, StringComparison.Ordinal);
        Assert.Equal(
            Program.Select(item => item.Opcode),
            recovered.Instructions.Select(item => item.Opcode));
        Assert.Equal(
            Program.Select(item => (long)item.Operand),
            recovered.Instructions.Select(item =>
                Assert.IsType<VirtualOperand.Number>(item.Operand).Value));
    }

    /// <summary>
    /// An operand that is a token for something in this module is named, because that is what the
    /// listing is read for.
    /// </summary>
    [Fact]
    public void OperandsThatNameThisModuleAreResolved()
    {
        using var context = SyntheticContext.Build(AddEngine);
        var method = Assert.Single(VirtualizedMethodDetector.Detect(context.Module));

        var recovered = VirtualProgramRecovery.Recover(context, method, out _);

        Assert.NotNull(recovered);
        var listing = string.Join("\n", recovered.Render(context.Module));
        var named = context.Module.ResolveToken(0x06000001)?.ToString();
        Assert.NotNull(named);
        Assert.Contains($"100663297   ; {named}", listing, StringComparison.Ordinal);
    }

    [Fact]
    public void AnEngineThatNeverDecodesAnythingIsReportedRatherThanGuessedAt()
    {
        using var context = SyntheticContext.Build(
            module => AddEngine(module, decode: false, guarded: false));
        var method = Assert.Single(VirtualizedMethodDetector.Detect(context.Module));

        Assert.Null(VirtualProgramRecovery.Recover(context, method, out var diagnostic));
        Assert.NotEmpty(diagnostic);
    }

    /// <summary>
    /// Gives the engine a class shaped like an exception clause, and optionally makes one.
    /// </summary>
    /// <remarks>
    /// Declaring the class without making one is the other case worth testing: an engine that can
    /// express guarded regions and expressed none says something a listing should report, and it
    /// is not the same thing as an engine that cannot express them at all.
    /// </remarks>
    private static void Guard(ModuleDefUser module, MethodDef entry, bool made, bool paired = false)
    {
        var clause = SyntheticContext.AddType(module, "Guard");
        var places = Places
            .Select(name => new FieldDefUser(
                name, new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Public))
            .ToList();
        foreach (var place in places)
            clause.Fields.Add(place);
        var caught = new FieldDefUser(
            "Caught",
            new FieldSig(new ClassSig(module.CorLibTypes.GetTypeRef("System", "Type"))),
            FieldAttributes.Public);
        clause.Fields.Add(caught);
        clause.Methods.Add(Constructor(module));
        if (!made)
            return;

        var held = new Local(clause.ToTypeSig());
        entry.Body.Variables.Add(held);
        var written = new List<Instruction>
        {
            OpCodes.Newobj.ToInstruction(clause.FindDefaultConstructor()),
            OpCodes.Stloc.ToInstruction(held)
        };
        for (var place = 0; place < places.Count; place++)
        {
            written.Add(OpCodes.Ldloc.ToInstruction(held));
            written.Add(OpCodes.Ldc_I4.ToInstruction(place));
            written.Add(OpCodes.Stfld.ToInstruction(places[place]));
        }
        written.Add(OpCodes.Ldloc.ToInstruction(held));
        written.Add(OpCodes.Ldtoken.ToInstruction(clause));
        written.Add(OpCodes.Call.ToInstruction(new MemberRefUser(
            module,
            "GetTypeFromHandle",
            MethodSig.CreateStatic(
                new ClassSig(module.CorLibTypes.GetTypeRef("System", "Type")),
                new ValueTypeSig(module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle"))),
            module.CorLibTypes.GetTypeRef("System", "Type"))));
        written.Add(OpCodes.Stfld.ToInstruction(caught));
        if (paired)
            written.AddRange(Holding(module, entry, clause, held));
        for (var at = 0; at < written.Count; at++)
            entry.Body.Instructions.Insert(at, written[at]);
    }

    /// <summary>
    /// Puts the clause inside something that says what it guards, which is where this engine — and
    /// the real one — keeps the other half of a region.
    /// </summary>
    private static List<Instruction> Holding(
        ModuleDefUser module,
        MethodDef entry,
        TypeDef clause,
        Local made)
    {
        var region = SyntheticContext.AddType(module, "Region");
        var from = new FieldDefUser(
            "Begins", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Public);
        var to = new FieldDefUser(
            "Ends", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Public);
        var inside = new FieldDefUser(
            "Clause", new FieldSig(clause.ToTypeSig()), FieldAttributes.Public);
        region.Fields.Add(from);
        region.Fields.Add(to);
        region.Fields.Add(inside);
        region.Methods.Add(Constructor(module));

        var holder = new Local(region.ToTypeSig());
        entry.Body.Variables.Add(holder);
        return
        [
            OpCodes.Newobj.ToInstruction(region.FindDefaultConstructor()),
            OpCodes.Stloc.ToInstruction(holder),
            OpCodes.Ldloc.ToInstruction(holder),
            OpCodes.Ldc_I4.ToInstruction(2),
            OpCodes.Stfld.ToInstruction(from),
            OpCodes.Ldloc.ToInstruction(holder),
            OpCodes.Ldc_I4.ToInstruction(3),
            OpCodes.Stfld.ToInstruction(to),
            OpCodes.Ldloc.ToInstruction(holder),
            OpCodes.Ldloc.ToInstruction(made),
            OpCodes.Stfld.ToInstruction(inside)
        ];
    }

    private static void AddEngine(ModuleDefUser module) =>
        AddEngine(module, decode: true, guarded: false);

    private static void AddGuardedEngine(ModuleDefUser module) =>
        AddEngine(module, decode: true, guarded: true);

    private static void AddGuardlessEngine(ModuleDefUser module) =>
        AddEngine(module, decode: true, guarded: false, shaped: true);

    private static void AddPairedEngine(ModuleDefUser module) =>
        AddEngine(module, decode: true, guarded: true, paired: true);

    /// <summary>
    /// A method's guarded regions are no part of its operations, so a reading that only reads the
    /// operations misses them entirely — and a body rebuilt from one would run the wrong code the
    /// first time anything threw.
    /// </summary>
    [Fact]
    public void TheGuardedRegionsTheEngineParsedAreRead()
    {
        using var context = SyntheticContext.Build(AddGuardedEngine);
        var method = Assert.Single(VirtualizedMethodDetector.Detect(context.Module));

        var recovered = VirtualProgramRecovery.Recover(context, method, out _);

        Assert.NotNull(recovered);
        var region = Assert.Single(recovered.Regions);
        Assert.Equal([0, 1, 2, 3], region.Numbers);
        Assert.Contains(
            "over operations 0, 1, 2, 3",
            string.Join("\n", recovered.Render(context.Module)),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// The numbers in a clause are not labelled, so which of them is the handler is a question the
    /// clause does not answer. What holds the clause does: it carries the range the handler is
    /// there for. Read together they are a region that can be built back, and the listing says
    /// which range is which rather than giving four numbers in the order the engine kept them.
    /// </summary>
    [Fact]
    public void AClauseHeldBySomethingThatSaysWhatItGuardsIsReadAsBoth()
    {
        using var context = SyntheticContext.Build(AddPairedEngine);
        var method = Assert.Single(VirtualizedMethodDetector.Detect(context.Module));

        var recovered = VirtualProgramRecovery.Recover(context, method, out _);

        Assert.NotNull(recovered);
        var region = Assert.Single(recovered.Regions);
        Assert.Equal((2, 3), region.Guarded);
        Assert.Equal((0, 1), region.Handled);
        Assert.Contains(
            "operations 2-3 guarded, handled at 0-1",
            string.Join("\n", recovered.Render(context.Module)),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// Where an engine can express guarded regions and made none, that is worth saying outright:
    /// finding none and being unable to look are different answers to the same question.
    /// </summary>
    [Fact]
    public void AnEngineThatMadeNoRegionsSaysSoRatherThanLeavingItOpen()
    {
        using var context = SyntheticContext.Build(AddGuardlessEngine);
        var method = Assert.Single(VirtualizedMethodDetector.Detect(context.Module));

        var recovered = VirtualProgramRecovery.Recover(context, method, out _);

        Assert.NotNull(recovered);
        Assert.Empty(recovered.Regions);
        Assert.Contains(
            "made none of them",
            string.Join("\n", recovered.Render(context.Module)),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// Builds a module holding a stub, an interpreter, and an encrypted program for it to decode.
    /// </summary>
    private static void AddEngine(
        ModuleDefUser module,
        bool decode,
        bool guarded,
        bool shaped = false,
        bool paired = false)
    {
        var operation = SyntheticContext.AddType(module, "Operation");
        var code = new FieldDefUser(
            "Code", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Public);
        var value = new FieldDefUser(
            "Value", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Public);
        operation.Fields.Add(code);
        operation.Fields.Add(value);
        operation.Methods.Add(Constructor(module));

        var engine = SyntheticContext.AddType(module, "Engine");
        var listOfOperation = new GenericInstSig(
            new ClassSig(module.CorLibTypes.GetTypeRef(
                "System.Collections.Generic", "List`1")),
            operation.ToTypeSig());
        var program = new FieldDefUser(
            "Program", new FieldSig(listOfOperation), FieldAttributes.Public);
        engine.Fields.Add(program);
        engine.Methods.Add(Constructor(module));

        var listConstructor = new MemberRefUser(
            module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void),
            listOfOperation.ToTypeDefOrRef());
        var listAdd = new MemberRefUser(
            module, "Add",
            MethodSig.CreateInstance(module.CorLibTypes.Void, new GenericVar(0)),
            listOfOperation.ToTypeDefOrRef());

        var execute = new MethodDefUser(
            "Execute",
            MethodSig.CreateInstance(module.CorLibTypes.Void, operation.ToTypeSig()),
            MethodImplAttributes.IL,
            MethodAttributes.Public)
        {
            Body = new CilBody()
        };
        execute.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        engine.Methods.Add(execute);

        var stored = Program
            .SelectMany(item => new[] { item.Opcode ^ Key, item.Operand ^ Key })
            .ToArray();
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
        var self = new Local(engine.ToTypeSig());
        var slot = new Local(operation.ToTypeSig());
        var index = new Local(module.CorLibTypes.Int32);
        entry.Body.Variables.Add(self);
        entry.Body.Variables.Add(slot);
        entry.Body.Variables.Add(index);
        var body = entry.Body.Instructions;
        body.Add(OpCodes.Newobj.ToInstruction(engine.FindDefaultConstructor()));
        body.Add(OpCodes.Stloc.ToInstruction(self));
        body.Add(OpCodes.Ldloc.ToInstruction(self));
        body.Add(OpCodes.Newobj.ToInstruction(listConstructor));
        body.Add(OpCodes.Stfld.ToInstruction(program));

        // The whole program is decoded before any of it runs, which is why reading it at the first
        // execution yields all of it rather than a trace.
        if (decode)
        {
            for (var at = 0; at < stored.Length; at += 2)
            {
                body.Add(OpCodes.Newobj.ToInstruction(operation.FindDefaultConstructor()));
                body.Add(OpCodes.Stloc.ToInstruction(slot));
                body.Add(OpCodes.Ldloc.ToInstruction(slot));
                body.Add(OpCodes.Ldc_I4.ToInstruction(stored[at]));
                body.Add(OpCodes.Ldc_I4.ToInstruction((int)Key));
                body.Add(OpCodes.Xor.ToInstruction());
                body.Add(OpCodes.Stfld.ToInstruction(code));
                body.Add(OpCodes.Ldloc.ToInstruction(slot));
                body.Add(OpCodes.Ldc_I4.ToInstruction(stored[at + 1]));
                body.Add(OpCodes.Ldc_I4.ToInstruction((int)Key));
                body.Add(OpCodes.Xor.ToInstruction());
                body.Add(OpCodes.Box.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
                body.Add(OpCodes.Stfld.ToInstruction(value));
                body.Add(OpCodes.Ldloc.ToInstruction(self));
                body.Add(OpCodes.Ldfld.ToInstruction(program));
                body.Add(OpCodes.Ldloc.ToInstruction(slot));
                body.Add(OpCodes.Callvirt.ToInstruction(listAdd));
            }
        }

        var loop = OpCodes.Ldloc.ToInstruction(index);
        var test = OpCodes.Ldloc.ToInstruction(index);
        var done = OpCodes.Ldnull.ToInstruction();
        body.Add(OpCodes.Ldc_I4_0.ToInstruction());
        body.Add(OpCodes.Stloc.ToInstruction(index));
        body.Add(OpCodes.Br.ToInstruction(test));
        body.Add(loop);
        body.Add(OpCodes.Pop.ToInstruction());
        body.Add(OpCodes.Ldloc.ToInstruction(self));
        body.Add(OpCodes.Ldloc.ToInstruction(self));
        body.Add(OpCodes.Ldfld.ToInstruction(program));
        body.Add(OpCodes.Ldloc.ToInstruction(index));
        body.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(
            module, "get_Item",
            MethodSig.CreateInstance(new GenericVar(0), module.CorLibTypes.Int32),
            listOfOperation.ToTypeDefOrRef())));
        body.Add(OpCodes.Callvirt.ToInstruction(execute));
        body.Add(OpCodes.Ldloc.ToInstruction(index));
        body.Add(OpCodes.Ldc_I4_1.ToInstruction());
        body.Add(OpCodes.Add.ToInstruction());
        body.Add(OpCodes.Stloc.ToInstruction(index));
        body.Add(test);
        body.Add(OpCodes.Ldloc.ToInstruction(self));
        body.Add(OpCodes.Ldfld.ToInstruction(program));
        body.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(
            module, "get_Count",
            MethodSig.CreateInstance(module.CorLibTypes.Int32),
            listOfOperation.ToTypeDefOrRef())));
        body.Add(OpCodes.Blt.ToInstruction(loop));
        body.Add(done);
        body.Add(OpCodes.Ret.ToInstruction());
        engine.Methods.Add(entry);

        if (guarded || shaped)
            Guard(module, entry, made: guarded, paired: paired);

        var stub = new MethodDefUser(
            "Hidden",
            MethodSig.CreateStatic(
                module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.Int32),
            MethodImplAttributes.IL,
            MethodAttributes.Public | MethodAttributes.Static)
        {
            Body = new CilBody()
        };
        var packed = new Local(new SZArraySig(module.CorLibTypes.Object));
        stub.Body.Variables.Add(packed);
        var stubBody = stub.Body.Instructions;
        stubBody.Add(OpCodes.Ldc_I4_2.ToInstruction());
        stubBody.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Object.TypeDefOrRef));
        stubBody.Add(OpCodes.Stloc.ToInstruction(packed));
        stubBody.Add(OpCodes.Ldloc.ToInstruction(packed));
        stubBody.Add(OpCodes.Ldc_I4_0.ToInstruction());
        stubBody.Add(OpCodes.Ldarg_0.ToInstruction());
        stubBody.Add(OpCodes.Stelem_Ref.ToInstruction());
        stubBody.Add(OpCodes.Ldloc.ToInstruction(packed));
        stubBody.Add(OpCodes.Ldc_I4_1.ToInstruction());
        stubBody.Add(OpCodes.Ldarg_1.ToInstruction());
        stubBody.Add(OpCodes.Box.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
        stubBody.Add(OpCodes.Stelem_Ref.ToInstruction());
        stubBody.Add(OpCodes.Ldc_I4_0.ToInstruction());
        stubBody.Add(OpCodes.Ldloc.ToInstruction(packed));
        stubBody.Add(OpCodes.Ldnull.ToInstruction());
        stubBody.Add(OpCodes.Call.ToInstruction(entry));
        stubBody.Add(OpCodes.Pop.ToInstruction());
        stubBody.Add(OpCodes.Ret.ToInstruction());
        SyntheticContext.AddType(module, "Surface").Methods.Add(stub);
    }

    private static MethodDefUser Constructor(ModuleDefUser module)
    {
        var constructor = new MethodDefUser(
            ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void),
            MethodImplAttributes.IL,
            MethodAttributes.Public | MethodAttributes.SpecialName |
            MethodAttributes.RTSpecialName)
        {
            Body = new CilBody()
        };
        constructor.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        return constructor;
    }
}
