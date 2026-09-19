using Cilantro.Core;
using Cilantro.Core.Passes;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class InstructionMutationReportingTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void OnlyCommittedInstructionChangesArePublished(bool commit)
    {
        using var context = SyntheticContext.Build(_ => { });
        var instruction = OpCodes.Ldc_I4_0.ToInstruction();
        var prior = new ChangeRecord("previous", "test", "", "already committed");
        var record = new ChangeRecord("current", "test", "", "pending");
        context.AddChange(prior);
        using (var transaction = new InstructionMutationTransaction())
        {
            transaction.Capture(instruction);
            instruction.OpCode = OpCodes.Ldc_I4_1;
            transaction.RecordChange(context, record);
            Assert.Equal(prior, Assert.Single(context.Changes));
            if (commit)
                transaction.Commit();
        }

        Assert.Equal(commit ? Code.Ldc_I4_1 : Code.Ldc_I4_0, instruction.OpCode.Code);
        Assert.Equal(commit ? 2 : 1, context.Changes.Count);
        if (commit)
            Assert.Equal(record, context.Changes[1]);
    }

    [Fact]
    public void UnwrittenFieldRollbackDiscardsItsChangeRecords()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Host");
            var field = new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Private | FieldAttributes.Static);
            type.Fields.Add(field);
            var reader = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.Int32), MethodAttributes.Public | MethodAttributes.Static)
            { Body = new CilBody() };
            reader.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(field));
            reader.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            type.Methods.Add(reader);
        });
        var reader = context.Module.GetTypes().SelectMany(t => t.Methods).Single();
        // A reachable operand-less call makes the post-rewrite verification fail.
        reader.Body.Instructions.Insert(0, new Instruction(OpCodes.Call));
        context.SetFact("options.foldUnwrittenState", true);

        var result = new UnwrittenFieldFoldingPass().Run(context);

        Assert.Equal(PassStatus.Partial, result.Status);
        Assert.Equal(0, result.Changes);
        Assert.Equal(Code.Ldsfld, reader.Body.Instructions[1].OpCode.Code);
        Assert.Empty(context.Changes);
    }
}
