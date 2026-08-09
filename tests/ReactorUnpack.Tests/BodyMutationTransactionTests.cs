using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core.Verification;

namespace ReactorUnpack.Tests;

public sealed class BodyMutationTransactionTests
{
    [Fact]
    public void DisposeRestoresCompleteBodyAndOriginalBodyObject()
    {
        using var module = new ModuleDefUser("transaction.dll");
        var method = CreateMethod(module);
        var originalBody = method.Body;
        var before = MethodBodySnapshot.Capture(method);
        var beforeFingerprint = MethodBodyStructuralComparer.Fingerprint(method);

        using (new BodyMutationTransaction(method))
        {
            originalBody.Instructions[0].OpCode = OpCodes.Ldc_I4_8;
            originalBody.Variables.Clear();
            originalBody.ExceptionHandlers.Clear();
            originalBody.InitLocals = false;
            originalBody.KeepOldMaxStack = false;
            originalBody.HeaderSize = 1;
            originalBody.MaxStack = 1;
            originalBody.LocalVarSigTok = 0;

            method.Body = new CilBody();
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        }

        Assert.Same(originalBody, method.Body);
        Assert.True(before.StructurallyEquals(method));
        Assert.Equal(beforeFingerprint, MethodBodyStructuralComparer.Fingerprint(method));
        Assert.True(method.Body.InitLocals);
        Assert.True(method.Body.KeepOldMaxStack);
        Assert.Equal((byte)12, method.Body.HeaderSize);
        Assert.Equal((ushort)4, method.Body.MaxStack);
        Assert.Equal(0x11000001U, method.Body.LocalVarSigTok);
    }

    [Fact]
    public void RollbackRemapsBranchesSwitchesLocalsAndHandlerBoundaries()
    {
        using var module = new ModuleDefUser("transaction.dll");
        var method = CreateMethod(module);
        var snapshot = MethodBodySnapshot.Capture(method);

        using var transaction = new BodyMutationTransaction(method);
        method.Body.Instructions.Clear();
        method.Body.Variables.Clear();
        method.Body.ExceptionHandlers.Clear();

        transaction.Rollback();

        var body = method.Body;
        Assert.Same(body.Variables[0], body.Instructions[1].Operand);
        Assert.Same(body.Variables[0], body.Instructions[2].Operand);
        Assert.Same(body.Instructions[6], body.Instructions[3].Operand);
        Assert.Same(body.Instructions[7], body.Instructions[5].Operand);

        var targets = Assert.IsType<Instruction[]>(body.Instructions[9].Operand);
        Assert.Same(body.Instructions[11], targets[0]);
        Assert.Same(body.Instructions[12], targets[1]);

        var handler = Assert.Single(body.ExceptionHandlers);
        Assert.Same(body.Instructions[0], handler.TryStart);
        Assert.Same(body.Instructions[4], handler.TryEnd);
        Assert.Same(body.Instructions[6], handler.HandlerStart);
        Assert.Same(body.Instructions[8], handler.HandlerEnd);
        Assert.Same(module.CorLibTypes.Object.TypeDefOrRef, handler.CatchType);
        Assert.True(snapshot.StructurallyEquals(body));
    }

    [Fact]
    public void CommitKeepsMutatedAndReplacementBodies()
    {
        using var module = new ModuleDefUser("transaction.dll");
        var method = CreateMethod(module);
        var original = MethodBodySnapshot.Capture(method);
        var replacement = new CilBody { InitLocals = false, MaxStack = 1 };
        replacement.Instructions.Add(Instruction.Create(OpCodes.Ret));

        using (var transaction = new BodyMutationTransaction(method))
        {
            method.Body = replacement;
            transaction.Commit();
        }

        Assert.Same(replacement, method.Body);
        Assert.False(original.StructurallyEquals(method));
    }

    [Fact]
    public void ExplicitRollbackCompletesTransaction()
    {
        using var module = new ModuleDefUser("transaction.dll");
        var method = CreateMethod(module);
        var expected = MethodBodyStructuralComparer.Fingerprint(method);

        using (var transaction = new BodyMutationTransaction(method))
        {
            method.Body.Instructions[0].OpCode = OpCodes.Ldc_I4_8;
            transaction.Rollback();
            transaction.Rollback();
        }

        Assert.Equal(expected, MethodBodyStructuralComparer.Fingerprint(method));
    }

    [Fact]
    public void RollbackRestoresAnAbsentBodyAfterReplacement()
    {
        using var module = new ModuleDefUser("transaction.dll");
        var method = new MethodDefUser("AbstractLike", MethodSig.CreateStatic(module.CorLibTypes.Void));
        Assert.Null(method.Body);

        using (new BodyMutationTransaction(method))
        {
            method.Body = new CilBody();
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        }

        Assert.Null(method.Body);
        Assert.Equal(
            MethodBodyStructuralComparer.Fingerprint((CilBody?)null),
            MethodBodyStructuralComparer.Fingerprint(method));
    }

    [Fact]
    public void StructuralComparerDetectsEveryBodyStructureCategory()
    {
        using var module = new ModuleDefUser("transaction.dll");
        var left = CreateMethod(module);
        var right = CreateMethod(module);

        Assert.True(MethodBodyStructuralComparer.AreEqual(left, right));

        right.Body.Instructions[3].Operand = right.Body.Instructions[7];
        Assert.False(MethodBodyStructuralComparer.AreEqual(left, right));

        right = CreateMethod(module);
        right.Body.Variables[0].Type = module.CorLibTypes.Int64;
        Assert.False(MethodBodyStructuralComparer.AreEqual(left, right));

        right = CreateMethod(module);
        right.Body.ExceptionHandlers[0].HandlerEnd = right.Body.Instructions[9];
        Assert.False(MethodBodyStructuralComparer.AreEqual(left, right));

        right = CreateMethod(module);
        right.Body.MaxStack++;
        Assert.False(MethodBodyStructuralComparer.AreEqual(left, right));
    }

    private static MethodDefUser CreateMethod(ModuleDef module)
    {
        var method = new MethodDefUser(
            "Fixture",
            MethodSig.CreateStatic(module.CorLibTypes.Void));
        var body = new CilBody
        {
            InitLocals = true,
            KeepOldMaxStack = true,
            HeaderSize = 12,
            MaxStack = 4,
            LocalVarSigTok = 0x11000001,
        };
        method.Body = body;

        var value = new Local(module.CorLibTypes.Int32, "value");
        var text = new Local(module.CorLibTypes.String, "text");
        body.Variables.Add(value);
        body.Variables.Add(text);

        var instructions = new[]
        {
            Instruction.Create(OpCodes.Ldc_I4_0),
            Instruction.Create(OpCodes.Stloc, value),
            Instruction.Create(OpCodes.Ldloc, value),
            new Instruction(OpCodes.Brfalse),
            Instruction.Create(OpCodes.Ldstr, "nonzero"),
            new Instruction(OpCodes.Br),
            Instruction.Create(OpCodes.Ldnull),
            Instruction.Create(OpCodes.Pop),
            Instruction.Create(OpCodes.Ldc_I4_0),
            Instruction.Create(OpCodes.Switch, Array.Empty<Instruction>()),
            new Instruction(OpCodes.Br),
            Instruction.Create(OpCodes.Nop),
            Instruction.Create(OpCodes.Ret),
        };
        instructions[3].Operand = instructions[6];
        instructions[5].Operand = instructions[7];
        instructions[9].Operand = new[] { instructions[11], instructions[12] };
        instructions[10].Operand = instructions[12];
        foreach (var instruction in instructions)
            body.Instructions.Add(instruction);

        body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
        {
            TryStart = instructions[0],
            TryEnd = instructions[4],
            HandlerStart = instructions[6],
            HandlerEnd = instructions[8],
            CatchType = module.CorLibTypes.Object.TypeDefOrRef,
        });
        body.UpdateInstructionOffsets();
        return method;
    }
}
