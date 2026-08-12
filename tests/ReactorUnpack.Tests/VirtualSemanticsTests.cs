using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Recovery;

namespace ReactorUnpack.Tests;

/// <summary>
/// Covers working out what a virtualizer's operations mean by having its engine perform them.
/// </summary>
/// <remarks>
/// The engine here is written to be nothing like the ones in the samples: its own names, its own
/// numbering, its own way of holding a value. What it shares is only what any engine must have —
/// somewhere to keep a stack, some way to make a value, and a method that carries out one operation
/// — because anything else the derivation leaned on would be a thing that changes between builds.
///
/// The numbers it dispatches on are deliberately not the ones any sample uses. A test that passed
/// because the code had learned a sample's numbering would be worse than no test.
/// </remarks>
public sealed class VirtualSemanticsTests
{
    private const int Add = 11;
    private const int Duplicate = 22;
    private const int Discard = 33;
    private const int Jump = 44;
    private const int Length = 55;
    private const int Store = 66;
    private const int Opaque = 77;
    private const int Arm = 88;
    private const int Guarded = 99;
    private const int LoadLocal = 111;
    private const int StoreLocal = 122;
    private const int LoadArgument = 133;
    private const int Nothing = 144;
    private const int JumpTarget = 7;

    [Fact]
    public void ArithmeticIsIdentifiedFromWhatTheEngineComputes()
    {
        var operations = Derive();

        Assert.Equal("add", operations[Add].Name);
        Assert.Equal(2, operations[Add].Pops);
        Assert.Equal(1, operations[Add].Pushes);
    }

    [Fact]
    public void CopyingTheTopOfTheStackIsIdentified()
    {
        var operations = Derive();

        Assert.Equal("dup", operations[Duplicate].Name);
    }

    /// <summary>
    /// A jump is recognized by the engine taking on the operand, which is the one reading that must
    /// not be missed: reported as inert, it would make everything after it look unreachable.
    /// </summary>
    [Fact]
    public void AJumpIsRecognizedRatherThanReportedAsDoingNothing()
    {
        var operations = Derive();

        Assert.Equal("branch", operations[Jump].Name);
        Assert.True(operations[Jump].TouchesState);
    }

    /// <summary>
    /// An operation that consumes a value and shows nothing else is counted, not named. What can be
    /// watched is the engine's own state, so "discards it" would claim more than the trials showed.
    /// </summary>
    [Fact]
    public void AnEffectThatWasNotIdentifiedIsCountedRatherThanGuessed()
    {
        var operations = Derive();

        Assert.False(operations[Discard].Identified);
        Assert.Equal(1, operations[Discard].Pops);
        Assert.Equal(0, operations[Discard].Pushes);
        Assert.Equal("pops 1", operations[Discard].Describe());
    }

    /// <summary>
    /// An operation that refuses numbers is offered an array instead, since refusing is all it does
    /// and the arrangement it accepts is itself a finding.
    /// </summary>
    [Fact]
    public void AnOperationThatWantsAnArrayIsOfferedOneRatherThanGivenUpOn()
    {
        var operations = Derive();

        Assert.Equal("array length", operations[Length].Name);
        Assert.Equal("an array on top", operations[Length].Needs);
    }

    /// <summary>
    /// A store shows nothing on the stack — three values in, none out — so it is recognized by the
    /// array coming back holding what was put in it.
    /// </summary>
    [Fact]
    public void WritingIntoAnArrayIsSeenInTheArrayRatherThanOnTheStack()
    {
        var operations = Derive();

        Assert.Equal("writes an array element", operations[Store].Name);
        Assert.Equal(3, operations[Store].Pops);
        Assert.Equal(0, operations[Store].Pushes);
    }

    /// <summary>
    /// A value we cannot read is still a value, and where it sits still says what was pushed.
    /// Discarding the operation over it would throw away a measurement we have.
    /// </summary>
    [Fact]
    public void AValueThatCannotBeReadStillCountsTowardsTheStackEffect()
    {
        var operations = Derive();

        Assert.Equal(0, operations[Opaque].Pops);
        Assert.Equal(1, operations[Opaque].Pushes);
        Assert.Contains("pushes a", operations[Opaque].Describe(), StringComparison.Ordinal);
    }

    /// <summary>
    /// A wrapper with nothing in any of its places is the engine holding null, and the operation
    /// that leaves one is pushing null. Read as the type of whatever tag sits beside the empty
    /// places, it would be reported as pushing a number it is not pushing.
    /// </summary>
    [Fact]
    public void AWrapperWithNothingInItIsReadAsNullRatherThanAsWhatTagsItHolds()
    {
        var operations = Derive();

        Assert.Equal("pushes nothing at all", operations[Nothing].Name);
        Assert.Equal(0, operations[Nothing].Pops);
        Assert.Equal(1, operations[Nothing].Pushes);
    }

    /// <summary>
    /// Nothing about a table says what it is for, so the arguments of the method are told from its
    /// locals by their number: as many as the method declares, and never reached past. The
    /// distinction is worth making because it is the difference between a listing that says where
    /// a value came from and one that says only that it came from somewhere.
    /// </summary>
    [Fact]
    public void ATableAsLongAsTheMethodsArgumentsIsReadAsTheArguments()
    {
        var operations = Derive();

        Assert.Equal("loads the argument it indexes", operations[LoadArgument].Name);
        Assert.Equal("loads what its operand indexes", operations[LoadLocal].Name);
    }

    /// <summary>
    /// An engine that cannot be given values to work on is asked nothing, and what it did anyway is
    /// still reported. Watching is not a guess: the jump is named because the engine was seen
    /// taking it, which needs no stack to have been arranged.
    /// </summary>
    [Fact]
    public void AnEngineWithNoValuesToSeedYieldsOnlyWhatItWasSeenDoing()
    {
        using var context = SyntheticContext.Build(module => Engine(module, withValues: false));
        var method = Assert.Single(VirtualizedMethodDetector.Detect(context.Module));

        var recovered = VirtualProgramRecovery.Recover(context, method, out _);

        Assert.NotNull(recovered);
        var seen = Assert.Single(recovered.Operations);
        Assert.Equal(Jump, seen.Key);
        Assert.Equal("branch", seen.Value.Name);
    }

    /// <summary>
    /// Where the engine went is read off the order it did things in, which is what makes it a
    /// finding rather than a reading of the operand: the operation after a jump really was the one
    /// it named, and the two agreeing is what licenses reading the rest of them the same way.
    /// </summary>
    [Fact]
    public void WhereAJumpWentIsTakenFromWatchingTheEngineRun()
    {
        var recovered = Recover();

        Assert.Equal(2, recovered.Targets[0]);
        Assert.Equal(4, recovered.Targets[2]);
        Assert.Contains(Jump, recovered.TargetIsOperand);
    }

    /// <summary>
    /// An operation the run never reached says nothing about where anything goes. Counting it as a
    /// jump not taken would make a conditional jump out of every unconditional one.
    /// </summary>
    [Fact]
    public void AnOperationTheRunNeverReachedIsNotReportedAsHavingStayedPut()
    {
        var recovered = Recover();

        Assert.DoesNotContain(1, recovered.Targets.Keys);
        Assert.DoesNotContain(3, recovered.Targets.Keys);
    }

    /// <summary>
    /// An operation that only works once the program has set the engine up cannot be asked
    /// anything: the state it wants is put back between trials. Watching it work in place is the
    /// only way to measure it, and measuring it is the difference between a listing that accounts
    /// for every operation and one with holes in it.
    /// </summary>
    [Fact]
    public void AnOperationTheTrialsCannotPerformIsMeasuredByWatchingItWork()
    {
        var operations = Derive();

        Assert.Equal(1, operations[Guarded].Pops);
        Assert.Equal(1, operations[Guarded].Pushes);
    }

    /// <summary>
    /// An engine keeps what its program is working on somewhere, and reaches it by number. Which
    /// operations put things there and take them back out is most of what a listing is worth, and
    /// it can only be seen by watching, since the trials never vary an operand.
    /// </summary>
    [Fact]
    public void OperationsThatReachIntoTheEnginesTablesAreNamedForIt()
    {
        var operations = Derive();

        Assert.Equal("loads what its operand indexes", operations[LoadLocal].Name);
        Assert.Equal("stores where its operand indexes", operations[StoreLocal].Name);
    }

    /// <summary>
    /// What an operation means is written in the engine's own handler, and the handler is what the
    /// machine walks through to perform it. Reading it off the file is another matter — in a real
    /// engine the handlers are one flattened method behind proxies resolved as it runs — but by the
    /// time the machine is performing an operation it has already been through all of that.
    /// </summary>
    [Fact]
    public void WhatTheHandlerWorksOutIsReadFromWhatTheEngineExecuted()
    {
        var operations = Derive();

        Assert.Contains("add", operations[Add].Computes ?? []);
    }

    /// <summary>
    /// An engine spends most of its instructions on the same housekeeping whatever operation it is
    /// performing, and reporting that as meaning would bury the part that is one.
    /// </summary>
    [Fact]
    public void WorkingEveryOperationDoesIsNotReportedAsWhatOneOfThemMeans()
    {
        var operations = Derive();

        Assert.DoesNotContain(
            operations[Opaque].Computes ?? [],
            working => working.StartsWith("List::", StringComparison.Ordinal));
    }

    private static VirtualProgram Recover()
    {
        using var context = SyntheticContext.Build(module => Engine(module, withValues: true));
        var method = Assert.Single(VirtualizedMethodDetector.Detect(context.Module));
        var recovered = VirtualProgramRecovery.Recover(context, method, out _);
        Assert.NotNull(recovered);
        return recovered;
    }

    private static IReadOnlyDictionary<int, VirtualOperation> Derive()
    {
        using var context = SyntheticContext.Build(module => Engine(module, withValues: true));
        var method = Assert.Single(VirtualizedMethodDetector.Detect(context.Module));
        var recovered = VirtualProgramRecovery.Recover(context, method, out var diagnostic);
        Assert.NotNull(recovered);
        Assert.NotEmpty(diagnostic);
        return recovered.Operations;
    }

    /// <summary>
    /// Builds a module with a stub, a program, and an engine that really performs its operations.
    /// </summary>
    private static void Engine(ModuleDefUser module, bool withValues)
    {
        var cell = SyntheticContext.AddType(module, "Cell");
        var low = Field(module, "Low", module.CorLibTypes.Int32);
        var high = Field(module, "High", module.CorLibTypes.Int32);
        cell.Fields.Add(low);
        cell.Fields.Add(high);
        cell.Methods.Add(Constructor(module));

        var slot = SyntheticContext.AddType(module, "Slot");
        var held = Field(module, "Held", cell.ToTypeSig());
        var raw = Field(module, "Raw", module.CorLibTypes.Object);
        slot.Fields.Add(held);
        slot.Fields.Add(raw);
        slot.Methods.Add(Constructor(module));
        var make = Make(module, slot, cell, low, high, raw);
        slot.Methods.Add(make);

        var operation = SyntheticContext.AddType(module, "Step");
        var code = Field(module, "Code", module.CorLibTypes.Int32);
        var operand = Field(module, "Operand", module.CorLibTypes.Object);
        operation.Fields.Add(code);
        operation.Fields.Add(operand);
        operation.Methods.Add(Constructor(module));

        var engine = SyntheticContext.AddType(module, "Machinery");
        var listOfStep = List(module, operation.ToTypeSig());
        var listOfSlot = List(module, slot.ToTypeSig());
        var program = Field(module, "Program", listOfStep);
        var stack = Field(module, "Stack", listOfSlot);
        var locals = Field(module, "Locals", new SZArraySig(slot.ToTypeSig()));
        var arguments = Field(module, "Arguments", new SZArraySig(slot.ToTypeSig()));
        var position = Field(module, "Position", module.CorLibTypes.Int32);
        var armed = Field(module, "Armed", module.CorLibTypes.Int32);
        engine.Fields.Add(program);
        engine.Fields.Add(stack);
        engine.Fields.Add(locals);
        engine.Fields.Add(arguments);
        engine.Fields.Add(position);
        engine.Fields.Add(armed);
        engine.Methods.Add(Constructor(module));

        var execute = Execute(
            module, engine, operation, slot, cell, code, operand, stack, position, armed, locals,
            arguments, held, low, raw, make, listOfSlot);
        engine.Methods.Add(execute);

        var entry = Entry(
            module, engine, operation, slot, code, operand, program, stack, locals, arguments,
            position, make, execute, listOfStep, listOfSlot, withValues);
        engine.Methods.Add(entry);
        Stub(module, entry);
    }

    /// <summary>
    /// The operations the program is made of: one of each so all are probed, and the jump three
    /// times over so that watching the engine run has something to be sure about.
    /// </summary>
    /// <remarks>
    /// The jumps come first and go forward, because an engine that faults partway through still
    /// has to have taken them by then, and one that jumps backwards would never stop.
    /// </remarks>
    private static readonly (int Code, int Operand)[] Program =
    [
        (Jump, 2),
        (Opaque, 0),
        (Jump, 4),
        (Add, 0),
        (Jump, JumpTarget),
        (Duplicate, 0),
        (Discard, 0),
        (Arm, 0),
        (Guarded, 0),
        (Guarded, 0),
        (StoreLocal, 0),
        (StoreLocal, 1),
        (StoreLocal, 2),
        (StoreLocal, 3),
        (LoadLocal, 0),
        (LoadLocal, 1),
        (LoadLocal, 2),
        (LoadLocal, 3),
        (Add, 0),
        (Duplicate, 0),
        (Add, 0),
        (Discard, 0),
        (Length, 0),
        (Store, 0),
        (Opaque, 0),
        (Nothing, 0),
        (LoadArgument, 0),
        (LoadArgument, 1)
    ];

    /// <summary>What the engine's stack is given to work on before the program starts.</summary>
    private static readonly int[] Seeded = [3, 5, 9, 17, 33, 65];

    private static GenericInstSig List(ModuleDefUser module, TypeSig element) =>
        new(new ClassSig(module.CorLibTypes.GetTypeRef(
            "System.Collections.Generic", "List`1")), element);

    private static FieldDefUser Field(ModuleDefUser module, string name, TypeSig type) =>
        new(name, new FieldSig(type), FieldAttributes.Public);

    /// <summary>
    /// The engine's way of turning a value into something it can stack, kept behind two fields that
    /// hold the same bits, the way a real one overlaps its storage.
    /// </summary>
    private static MethodDefUser Make(
        ModuleDefUser module,
        TypeDef slot,
        TypeDef cell,
        FieldDef low,
        FieldDef high,
        FieldDef raw)
    {
        var make = new MethodDefUser(
            "Wrap",
            MethodSig.CreateStatic(
                slot.ToTypeSig(),
                new ClassSig(module.CorLibTypes.GetTypeRef("System", "Type")),
                module.CorLibTypes.Object),
            MethodImplAttributes.IL,
            MethodAttributes.Public | MethodAttributes.Static)
        {
            Body = new CilBody()
        };
        var made = new Local(slot.ToTypeSig());
        var inner = new Local(cell.ToTypeSig());
        make.Body.Variables.Add(made);
        make.Body.Variables.Add(inner);
        var body = make.Body.Instructions;
        var done = OpCodes.Ldloc.ToInstruction(made);
        body.Add(OpCodes.Newobj.ToInstruction(slot.FindDefaultConstructor()));
        body.Add(OpCodes.Stloc.ToInstruction(made));

        // Whatever it was handed is kept as it came, and only a number is also taken apart, so that
        // the engine has something to offer an operation that works on an array.
        body.Add(OpCodes.Ldloc.ToInstruction(made));
        body.Add(OpCodes.Ldarg_1.ToInstruction());
        body.Add(OpCodes.Stfld.ToInstruction(raw));
        body.Add(OpCodes.Ldarg_1.ToInstruction());
        body.Add(OpCodes.Isinst.ToInstruction(Numbers(module).ToTypeDefOrRef()));
        body.Add(OpCodes.Brtrue.ToInstruction(done));
        body.Add(OpCodes.Newobj.ToInstruction(cell.FindDefaultConstructor()));
        body.Add(OpCodes.Stloc.ToInstruction(inner));
        foreach (var target in new[] { low, high })
        {
            body.Add(OpCodes.Ldloc.ToInstruction(inner));
            body.Add(OpCodes.Ldarg_1.ToInstruction());
            body.Add(OpCodes.Unbox_Any.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
            body.Add(OpCodes.Stfld.ToInstruction(target));
        }
        body.Add(OpCodes.Ldloc.ToInstruction(made));
        body.Add(OpCodes.Ldloc.ToInstruction(inner));
        body.Add(OpCodes.Stfld.ToInstruction(slot.Fields[0]));
        body.Add(done);
        body.Add(OpCodes.Ret.ToInstruction());
        return make;
    }

    /// <summary>Carries out one operation, which is the thing the derivation asks questions of.</summary>
    private static MethodDefUser Execute(
        ModuleDefUser module,
        TypeDef engine,
        TypeDef operation,
        TypeDef slot,
        TypeDef cell,
        FieldDef code,
        FieldDef operand,
        FieldDef stack,
        FieldDef position,
        FieldDef armed,
        FieldDef locals,
        FieldDef arguments,
        FieldDef held,
        FieldDef low,
        FieldDef raw,
        MethodDef make,
        GenericInstSig listOfSlot)
    {
        var execute = new MethodDefUser(
            "Perform",
            MethodSig.CreateInstance(module.CorLibTypes.Void, operation.ToTypeSig()),
            MethodImplAttributes.IL,
            MethodAttributes.Public)
        {
            Body = new CilBody()
        };
        var left = new Local(module.CorLibTypes.Int32);
        var right = new Local(module.CorLibTypes.Int32);
        execute.Body.Variables.Add(left);
        execute.Body.Variables.Add(right);
        var body = execute.Body.Instructions;

        var count = Member(module, listOfSlot, "get_Count", MethodSig.CreateInstance(
            module.CorLibTypes.Int32));
        var item = Member(module, listOfSlot, "get_Item", MethodSig.CreateInstance(
            new GenericVar(0), module.CorLibTypes.Int32));
        var removeAt = Member(module, listOfSlot, "RemoveAt", MethodSig.CreateInstance(
            module.CorLibTypes.Void, module.CorLibTypes.Int32));
        var add = Member(module, listOfSlot, "Add", MethodSig.CreateInstance(
            module.CorLibTypes.Void, new GenericVar(0)));

        var ret = OpCodes.Ret.ToInstruction();
        var tryDuplicate = OpCodes.Nop.ToInstruction();
        var tryDiscard = OpCodes.Nop.ToInstruction();
        var tryJump = OpCodes.Nop.ToInstruction();
        var tryLength = OpCodes.Nop.ToInstruction();
        var tryStore = OpCodes.Nop.ToInstruction();
        var tryOpaque = OpCodes.Nop.ToInstruction();
        var tryArm = OpCodes.Nop.ToInstruction();
        var tryGuarded = OpCodes.Nop.ToInstruction();
        var tryLoadLocal = OpCodes.Nop.ToInstruction();
        var tryStoreLocal = OpCodes.Nop.ToInstruction();
        var tryLoadArgument = OpCodes.Nop.ToInstruction();
        var tryNothing = OpCodes.Nop.ToInstruction();

        // add: take the top two apart, put their sum back.
        body.Add(OpCodes.Ldarg_1.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(code));
        body.Add(OpCodes.Ldc_I4.ToInstruction(Add));
        body.Add(OpCodes.Bne_Un.ToInstruction(tryDuplicate));
        Peek(body, stack, held, low, count, item, 1);
        body.Add(OpCodes.Stloc.ToInstruction(right));
        Peek(body, stack, held, low, count, item, 2);
        body.Add(OpCodes.Stloc.ToInstruction(left));
        Drop(body, stack, count, removeAt);
        Drop(body, stack, count, removeAt);
        body.Add(OpCodes.Ldarg_0.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(stack));
        body.Add(OpCodes.Ldnull.ToInstruction());
        body.Add(OpCodes.Ldloc.ToInstruction(left));
        body.Add(OpCodes.Ldloc.ToInstruction(right));
        body.Add(OpCodes.Add.ToInstruction());
        body.Add(OpCodes.Box.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
        body.Add(OpCodes.Call.ToInstruction(make));
        body.Add(OpCodes.Callvirt.ToInstruction(add));
        body.Add(OpCodes.Br.ToInstruction(ret));

        // dup: put back what is already on top.
        body.Add(tryDuplicate);
        body.Add(OpCodes.Ldarg_1.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(code));
        body.Add(OpCodes.Ldc_I4.ToInstruction(Duplicate));
        body.Add(OpCodes.Bne_Un.ToInstruction(tryDiscard));
        Peek(body, stack, held, low, count, item, 1);
        body.Add(OpCodes.Stloc.ToInstruction(left));
        body.Add(OpCodes.Ldarg_0.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(stack));
        body.Add(OpCodes.Ldnull.ToInstruction());
        body.Add(OpCodes.Ldloc.ToInstruction(left));
        body.Add(OpCodes.Box.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
        body.Add(OpCodes.Call.ToInstruction(make));
        body.Add(OpCodes.Callvirt.ToInstruction(add));
        body.Add(OpCodes.Br.ToInstruction(ret));

        // discard: take one off and say nothing about where it went.
        body.Add(tryDiscard);
        body.Add(OpCodes.Ldarg_1.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(code));
        body.Add(OpCodes.Ldc_I4.ToInstruction(Discard));
        body.Add(OpCodes.Bne_Un.ToInstruction(tryJump));
        Drop(body, stack, count, removeAt);
        body.Add(OpCodes.Br.ToInstruction(ret));

        // jump: move the engine to where the operand says.
        body.Add(tryJump);
        body.Add(OpCodes.Ldarg_1.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(code));
        body.Add(OpCodes.Ldc_I4.ToInstruction(Jump));
        body.Add(OpCodes.Bne_Un.ToInstruction(tryLength));
        body.Add(OpCodes.Ldarg_0.ToInstruction());
        body.Add(OpCodes.Ldarg_1.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(operand));
        body.Add(OpCodes.Unbox_Any.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
        body.Add(OpCodes.Stfld.ToInstruction(position));
        body.Add(OpCodes.Br.ToInstruction(ret));

        // length: refuses anything but an array, and answers with how long it is.
        body.Add(tryLength);
        body.Add(OpCodes.Ldarg_1.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(code));
        body.Add(OpCodes.Ldc_I4.ToInstruction(Length));
        body.Add(OpCodes.Bne_Un.ToInstruction(tryStore));
        Element(body, stack, raw, count, item, module, 1);
        body.Add(OpCodes.Ldlen.ToInstruction());
        body.Add(OpCodes.Conv_I4.ToInstruction());
        body.Add(OpCodes.Stloc.ToInstruction(left));
        Drop(body, stack, count, removeAt);
        body.Add(OpCodes.Ldarg_0.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(stack));
        body.Add(OpCodes.Ldnull.ToInstruction());
        body.Add(OpCodes.Ldloc.ToInstruction(left));
        body.Add(OpCodes.Box.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
        body.Add(OpCodes.Call.ToInstruction(make));
        body.Add(OpCodes.Callvirt.ToInstruction(add));
        body.Add(OpCodes.Br.ToInstruction(ret));

        // store: array, then an index, then a value, and the value ends up in the array.
        body.Add(tryStore);
        body.Add(OpCodes.Ldarg_1.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(code));
        body.Add(OpCodes.Ldc_I4.ToInstruction(Store));
        body.Add(OpCodes.Bne_Un.ToInstruction(tryOpaque));
        Peek(body, stack, held, low, count, item, 1);
        body.Add(OpCodes.Stloc.ToInstruction(right));
        Peek(body, stack, held, low, count, item, 2);
        body.Add(OpCodes.Stloc.ToInstruction(left));
        Element(body, stack, raw, count, item, module, 3);
        body.Add(OpCodes.Ldloc.ToInstruction(left));
        body.Add(OpCodes.Ldloc.ToInstruction(right));
        body.Add(OpCodes.Stelem_I4.ToInstruction());
        Drop(body, stack, count, removeAt);
        Drop(body, stack, count, removeAt);
        Drop(body, stack, count, removeAt);
        body.Add(OpCodes.Br.ToInstruction(ret));

        // opaque: leaves behind a value that holds no number, which is still a value.
        body.Add(tryOpaque);
        body.Add(OpCodes.Ldarg_1.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(code));
        body.Add(OpCodes.Ldc_I4.ToInstruction(Opaque));
        body.Add(OpCodes.Bne_Un.ToInstruction(tryArm));
        body.Add(OpCodes.Ldarg_0.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(stack));
        body.Add(OpCodes.Ldnull.ToInstruction());
        body.Add(OpCodes.Ldc_I4_2.ToInstruction());
        body.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
        body.Add(OpCodes.Call.ToInstruction(make));
        body.Add(OpCodes.Callvirt.ToInstruction(add));
        body.Add(OpCodes.Br.ToInstruction(ret));

        // arm: readies the engine for the operation below, which is what an operation that only
        // works in the middle of a program looks like.
        body.Add(tryArm);
        body.Add(OpCodes.Ldarg_1.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(code));
        body.Add(OpCodes.Ldc_I4.ToInstruction(Arm));
        body.Add(OpCodes.Bne_Un.ToInstruction(tryGuarded));
        body.Add(OpCodes.Ldarg_0.ToInstruction());
        body.Add(OpCodes.Ldc_I4_1.ToInstruction());
        body.Add(OpCodes.Stfld.ToInstruction(armed));
        body.Add(OpCodes.Br.ToInstruction(ret));

        // guarded: refuses unless the program armed it, so it cannot be performed in isolation —
        // the state it wants is put back between trials — but it runs perfectly well in place.
        body.Add(tryGuarded);
        body.Add(OpCodes.Ldarg_1.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(code));
        body.Add(OpCodes.Ldc_I4.ToInstruction(Guarded));
        body.Add(OpCodes.Bne_Un.ToInstruction(tryLoadLocal));
        var allowed = OpCodes.Nop.ToInstruction();
        body.Add(OpCodes.Ldarg_0.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(armed));
        body.Add(OpCodes.Brtrue.ToInstruction(allowed));
        body.Add(OpCodes.Newobj.ToInstruction(new MemberRefUser(
            module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void),
            module.CorLibTypes.GetTypeRef("System", "Exception"))));
        body.Add(OpCodes.Throw.ToInstruction());
        body.Add(allowed);
        Peek(body, stack, held, low, count, item, 1);
        body.Add(OpCodes.Stloc.ToInstruction(left));
        Drop(body, stack, count, removeAt);
        body.Add(OpCodes.Ldarg_0.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(stack));
        body.Add(OpCodes.Ldnull.ToInstruction());
        body.Add(OpCodes.Ldloc.ToInstruction(left));
        body.Add(OpCodes.Ldc_I4_1.ToInstruction());
        body.Add(OpCodes.Add.ToInstruction());
        body.Add(OpCodes.Box.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
        body.Add(OpCodes.Call.ToInstruction(make));
        body.Add(OpCodes.Callvirt.ToInstruction(add));
        body.Add(OpCodes.Br.ToInstruction(ret));

        // load: put on the stack whatever the engine is keeping at the place the operand names.
        body.Add(tryLoadLocal);
        body.Add(OpCodes.Ldarg_1.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(code));
        body.Add(OpCodes.Ldc_I4.ToInstruction(LoadLocal));
        body.Add(OpCodes.Bne_Un.ToInstruction(tryStoreLocal));
        body.Add(OpCodes.Ldarg_0.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(stack));
        body.Add(OpCodes.Ldarg_0.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(locals));
        body.Add(OpCodes.Ldarg_1.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(operand));
        body.Add(OpCodes.Unbox_Any.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
        body.Add(OpCodes.Ldelem_Ref.ToInstruction());
        body.Add(OpCodes.Callvirt.ToInstruction(add));
        body.Add(OpCodes.Br.ToInstruction(ret));

        // store: take the top of the stack and keep it at the place the operand names.
        body.Add(tryStoreLocal);
        body.Add(OpCodes.Ldarg_1.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(code));
        body.Add(OpCodes.Ldc_I4.ToInstruction(StoreLocal));
        body.Add(OpCodes.Bne_Un.ToInstruction(tryLoadArgument));
        body.Add(OpCodes.Ldarg_0.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(locals));
        body.Add(OpCodes.Ldarg_1.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(operand));
        body.Add(OpCodes.Unbox_Any.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
        PeekSlot(body, stack, count, item, 1);
        body.Add(OpCodes.Stelem_Ref.ToInstruction());
        Drop(body, stack, count, removeAt);
        body.Add(OpCodes.Br.ToInstruction(ret));

        // load argument: the same reach into a table, into the one holding what the method was
        // called with rather than the one holding what it is working on.
        body.Add(tryLoadArgument);
        body.Add(OpCodes.Ldarg_1.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(code));
        body.Add(OpCodes.Ldc_I4.ToInstruction(LoadArgument));
        body.Add(OpCodes.Bne_Un.ToInstruction(tryNothing));
        body.Add(OpCodes.Ldarg_0.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(stack));
        body.Add(OpCodes.Ldarg_0.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(arguments));
        body.Add(OpCodes.Ldarg_1.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(operand));
        body.Add(OpCodes.Unbox_Any.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
        body.Add(OpCodes.Ldelem_Ref.ToInstruction());
        body.Add(OpCodes.Callvirt.ToInstruction(add));
        body.Add(OpCodes.Br.ToInstruction(ret));

        // nothing: leaves one of the engine's wrappers with nothing in any of its places.
        body.Add(tryNothing);
        body.Add(OpCodes.Ldarg_1.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(code));
        body.Add(OpCodes.Ldc_I4.ToInstruction(Nothing));
        body.Add(OpCodes.Bne_Un.ToInstruction(ret));
        body.Add(OpCodes.Ldarg_0.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(stack));
        body.Add(OpCodes.Newobj.ToInstruction(slot.FindDefaultConstructor()));
        body.Add(OpCodes.Callvirt.ToInstruction(add));
        body.Add(ret);
        return execute;
    }

    private static SZArraySig Numbers(ModuleDefUser module) => new(module.CorLibTypes.Int32);

    /// <summary>Emits a read of the array carried by the value at a depth below the top.</summary>
    private static void Element(
        IList<Instruction> body,
        FieldDef stack,
        FieldDef raw,
        IMethod count,
        IMethod item,
        ModuleDefUser module,
        int depth)
    {
        PeekSlot(body, stack, count, item, depth);
        body.Add(OpCodes.Ldfld.ToInstruction(raw));
        body.Add(OpCodes.Castclass.ToInstruction(Numbers(module).ToTypeDefOrRef()));
    }

    /// <summary>Emits a read of the number held at a depth below the top of the stack.</summary>
    private static void Peek(
        IList<Instruction> body,
        FieldDef stack,
        FieldDef held,
        FieldDef low,
        IMethod count,
        IMethod item,
        int depth)
    {
        PeekSlot(body, stack, count, item, depth);
        body.Add(OpCodes.Ldfld.ToInstruction(held));
        body.Add(OpCodes.Ldfld.ToInstruction(low));
    }

    private static void PeekSlot(
        IList<Instruction> body,
        FieldDef stack,
        IMethod count,
        IMethod item,
        int depth)
    {
        body.Add(OpCodes.Ldarg_0.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(stack));
        body.Add(OpCodes.Ldarg_0.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(stack));
        body.Add(OpCodes.Callvirt.ToInstruction(count));
        body.Add(OpCodes.Ldc_I4.ToInstruction(depth));
        body.Add(OpCodes.Sub.ToInstruction());
        body.Add(OpCodes.Callvirt.ToInstruction(item));
    }

    private static void Drop(
        IList<Instruction> body,
        FieldDef stack,
        IMethod count,
        IMethod removeAt)
    {
        body.Add(OpCodes.Ldarg_0.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(stack));
        body.Add(OpCodes.Ldarg_0.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(stack));
        body.Add(OpCodes.Callvirt.ToInstruction(count));
        body.Add(OpCodes.Ldc_I4_1.ToInstruction());
        body.Add(OpCodes.Sub.ToInstruction());
        body.Add(OpCodes.Callvirt.ToInstruction(removeAt));
    }

    private static MemberRefUser Member(
        ModuleDefUser module,
        GenericInstSig owner,
        string name,
        MethodSig signature) =>
        new(module, name, signature, owner.ToTypeDefOrRef());

    /// <summary>Decodes the program, then runs it, the way an engine does.</summary>
    private static MethodDefUser Entry(
        ModuleDefUser module,
        TypeDef engine,
        TypeDef operation,
        TypeDef slot,
        FieldDef code,
        FieldDef operand,
        FieldDef program,
        FieldDef stack,
        FieldDef locals,
        FieldDef arguments,
        FieldDef position,
        MethodDef make,
        MethodDef execute,
        GenericInstSig listOfStep,
        GenericInstSig listOfSlot,
        bool withValues)
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
        var self = new Local(engine.ToTypeSig());
        var step = new Local(operation.ToTypeSig());
        entry.Body.Variables.Add(self);
        entry.Body.Variables.Add(step);
        var body = entry.Body.Instructions;
        body.Add(OpCodes.Newobj.ToInstruction(engine.FindDefaultConstructor()));
        body.Add(OpCodes.Stloc.ToInstruction(self));
        body.Add(OpCodes.Ldloc.ToInstruction(self));
        body.Add(OpCodes.Newobj.ToInstruction(Member(
            module, listOfStep, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void))));
        body.Add(OpCodes.Stfld.ToInstruction(program));

        // Without somewhere to put values and something to fill it with, there is nothing to seed,
        // and the derivation is expected to say so rather than invent an answer.
        if (withValues)
        {
            body.Add(OpCodes.Ldloc.ToInstruction(self));
            body.Add(OpCodes.Newobj.ToInstruction(Member(
                module, listOfSlot, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void))));
            body.Add(OpCodes.Stfld.ToInstruction(stack));
            body.Add(OpCodes.Ldloc.ToInstruction(self));
            body.Add(OpCodes.Ldc_I4_4.ToInstruction());
            body.Add(OpCodes.Newarr.ToInstruction(slot.ToTypeSig().ToTypeDefOrRef()));
            body.Add(OpCodes.Stfld.ToInstruction(locals));

            // As many places as the method has arguments, holding what a caller would have passed:
            // something with no number in it, and a number, which between them are what makes a
            // table of arguments unrecognizable by the values it holds alone.
            body.Add(OpCodes.Ldloc.ToInstruction(self));
            body.Add(OpCodes.Ldc_I4_2.ToInstruction());
            body.Add(OpCodes.Newarr.ToInstruction(slot.ToTypeSig().ToTypeDefOrRef()));
            body.Add(OpCodes.Stfld.ToInstruction(arguments));
            body.Add(OpCodes.Ldloc.ToInstruction(self));
            body.Add(OpCodes.Ldfld.ToInstruction(arguments));
            body.Add(OpCodes.Ldc_I4_0.ToInstruction());
            body.Add(OpCodes.Ldnull.ToInstruction());
            body.Add(OpCodes.Ldc_I4_3.ToInstruction());
            body.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
            body.Add(OpCodes.Call.ToInstruction(make));
            body.Add(OpCodes.Stelem_Ref.ToInstruction());
            body.Add(OpCodes.Ldloc.ToInstruction(self));
            body.Add(OpCodes.Ldfld.ToInstruction(arguments));
            body.Add(OpCodes.Ldc_I4_1.ToInstruction());
            body.Add(OpCodes.Ldnull.ToInstruction());
            body.Add(OpCodes.Ldc_I4_0.ToInstruction());
            body.Add(OpCodes.Box.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
            body.Add(OpCodes.Call.ToInstruction(make));
            body.Add(OpCodes.Stelem_Ref.ToInstruction());

            // A program whose operations work on values has to be given some, or it stops at the
            // first of them and there is nothing to watch it do.
            var pushSlot = Member(module, listOfSlot, "Add", MethodSig.CreateInstance(
                module.CorLibTypes.Void, new GenericVar(0)));
            foreach (var seeded in Seeded)
            {
                body.Add(OpCodes.Ldloc.ToInstruction(self));
                body.Add(OpCodes.Ldfld.ToInstruction(stack));
                body.Add(OpCodes.Ldnull.ToInstruction());
                body.Add(OpCodes.Ldc_I4.ToInstruction(seeded));
                body.Add(OpCodes.Box.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
                body.Add(OpCodes.Call.ToInstruction(make));
                body.Add(OpCodes.Callvirt.ToInstruction(pushSlot));
            }
        }

        var addStep = Member(module, listOfStep, "Add", MethodSig.CreateInstance(
            module.CorLibTypes.Void, new GenericVar(0)));
        foreach (var (opcode, value) in Program)
        {
            body.Add(OpCodes.Newobj.ToInstruction(operation.FindDefaultConstructor()));
            body.Add(OpCodes.Stloc.ToInstruction(step));
            body.Add(OpCodes.Ldloc.ToInstruction(step));
            body.Add(OpCodes.Ldc_I4.ToInstruction(opcode));
            body.Add(OpCodes.Stfld.ToInstruction(code));
            body.Add(OpCodes.Ldloc.ToInstruction(step));
            body.Add(OpCodes.Ldc_I4.ToInstruction(value));
            body.Add(OpCodes.Box.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
            body.Add(OpCodes.Stfld.ToInstruction(operand));
            body.Add(OpCodes.Ldloc.ToInstruction(self));
            body.Add(OpCodes.Ldfld.ToInstruction(program));
            body.Add(OpCodes.Ldloc.ToInstruction(step));
            body.Add(OpCodes.Callvirt.ToInstruction(addStep));
        }

        // The operations are carried out one after another, from wherever the engine says it is, so
        // that an operation which moves it is seen to have moved it. Where it advances and where a
        // jump sets it are the same field, which is what any engine must do and all that is
        // assumed of one.
        var next = OpCodes.Ldloc.ToInstruction(self);
        var finished = OpCodes.Ldnull.ToInstruction();
        body.Add(next);
        body.Add(OpCodes.Ldfld.ToInstruction(position));
        body.Add(OpCodes.Ldloc.ToInstruction(self));
        body.Add(OpCodes.Ldfld.ToInstruction(program));
        body.Add(OpCodes.Callvirt.ToInstruction(Member(
            module, listOfStep, "get_Count", MethodSig.CreateInstance(module.CorLibTypes.Int32))));
        body.Add(OpCodes.Bge.ToInstruction(finished));

        body.Add(OpCodes.Ldloc.ToInstruction(self));
        body.Add(OpCodes.Ldfld.ToInstruction(program));
        body.Add(OpCodes.Ldloc.ToInstruction(self));
        body.Add(OpCodes.Ldfld.ToInstruction(position));
        body.Add(OpCodes.Callvirt.ToInstruction(Member(
            module, listOfStep, "get_Item",
            MethodSig.CreateInstance(new GenericVar(0), module.CorLibTypes.Int32))));
        body.Add(OpCodes.Stloc.ToInstruction(step));

        body.Add(OpCodes.Ldloc.ToInstruction(self));
        body.Add(OpCodes.Ldloc.ToInstruction(self));
        body.Add(OpCodes.Ldfld.ToInstruction(position));
        body.Add(OpCodes.Ldc_I4_1.ToInstruction());
        body.Add(OpCodes.Add.ToInstruction());
        body.Add(OpCodes.Stfld.ToInstruction(position));

        body.Add(OpCodes.Ldloc.ToInstruction(self));
        body.Add(OpCodes.Ldloc.ToInstruction(step));
        body.Add(OpCodes.Callvirt.ToInstruction(execute));
        body.Add(OpCodes.Br.ToInstruction(next));

        body.Add(finished);
        body.Add(OpCodes.Ret.ToInstruction());
        return entry;
    }

    private static void Stub(ModuleDefUser module, MethodDef entry)
    {
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
        var body = stub.Body.Instructions;
        body.Add(OpCodes.Ldc_I4_2.ToInstruction());
        body.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Object.TypeDefOrRef));
        body.Add(OpCodes.Stloc.ToInstruction(packed));
        body.Add(OpCodes.Ldloc.ToInstruction(packed));
        body.Add(OpCodes.Ldc_I4_0.ToInstruction());
        body.Add(OpCodes.Ldarg_0.ToInstruction());
        body.Add(OpCodes.Stelem_Ref.ToInstruction());
        body.Add(OpCodes.Ldloc.ToInstruction(packed));
        body.Add(OpCodes.Ldc_I4_1.ToInstruction());
        body.Add(OpCodes.Ldarg_1.ToInstruction());
        body.Add(OpCodes.Box.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
        body.Add(OpCodes.Stelem_Ref.ToInstruction());
        body.Add(OpCodes.Ldc_I4_0.ToInstruction());
        body.Add(OpCodes.Ldloc.ToInstruction(packed));
        body.Add(OpCodes.Ldnull.ToInstruction());
        body.Add(OpCodes.Call.ToInstruction(entry));
        body.Add(OpCodes.Pop.ToInstruction());
        body.Add(OpCodes.Ret.ToInstruction());
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
