using Cilantro.Core;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class BodyMutationBatchTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void BodiesAndRecordsCommitTogetherOrRollBackTogether(bool commit)
    {
        using var context = Build();
        var methods = context.Module.GetTypes().SelectMany(type => type.Methods).ToArray();
        var existing = new ChangeRecord("earlier", "existing", "", "");
        context.AddChange(existing);
        using (var batch = new BodyMutationBatch(methods))
        {
            foreach (var method in methods)
            {
                method.Body.Instructions[0].OpCode = OpCodes.Ldc_I4_2;
                // Recapturing must retain the pre-edit snapshot, not the already modified body.
                batch.Capture(method);
                method.Body.Instructions.Insert(0, OpCodes.Nop.ToInstruction());
                batch.RecordChange(context, new ChangeRecord("current", "rewrite", method.Name, ""));
            }
            Assert.Equal(existing, Assert.Single(context.Changes));
            if (commit)
            {
                batch.Commit();
                batch.Commit();
                batch.Rollback();
            }
        }

        Assert.Equal(commit ? 3 : 1, context.Changes.Count);
        Assert.Same(existing, context.Changes[0]);
        foreach (var method in methods)
        {
            Assert.Equal(commit ? 3 : 2, method.Body.Instructions.Count);
            Assert.Equal(commit ? OpCodes.Ldc_I4_2 : OpCodes.Ldc_I4_1,
                method.Body.Instructions[commit ? 1 : 0].OpCode);
        }
    }

    [Fact]
    public void UnexpectedExceptionsRestoreAllCapturedBodies()
    {
        using var context = Build();
        var methods = context.Module.GetTypes().SelectMany(type => type.Methods).ToArray();
        var snapshots = methods.Select(MethodBodySnapshot.Capture).ToArray();

        Assert.Throws<InvalidOperationException>((Action)(() =>
        {
            using var batch = new BodyMutationBatch();
            foreach (var method in methods)
            {
                batch.Capture(method);
                method.Body.Instructions.Clear();
                batch.RecordChange(context, new ChangeRecord("current", "rewrite", method.Name, ""));
            }
            throw new InvalidOperationException("Interrupted before verification");
        }));

        Assert.Empty(context.Changes);
        for (var i = 0; i < methods.Length; i++)
            Assert.True(snapshots[i].StructurallyEquals(methods[i]));
    }

    private static ArtifactContext Build() => SyntheticContext.Build(module =>
    {
        var type = SyntheticContext.AddType(module, "Host");
        for (var index = 0; index < 2; index++)
        {
            var method = new MethodDefUser($"Method{index}", MethodSig.CreateStatic(module.CorLibTypes.Int32),
                MethodAttributes.Static) { Body = new CilBody() };
            method.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction());
            method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            type.Methods.Add(method);
        }
    });
}
