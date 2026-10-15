using Cilantro.Core;
using Cilantro.Core.Passes;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class TypeRecoveryCompletionTests
{
    [Fact]
    public void CompletionRunsAfterCleanupAndBeforeRenaming()
    {
        var names = CilantroPipeline.CreateDefaultPasses().Select(pass => pass.Name).ToList();
        var completion = names.IndexOf("type-recovery-completion");
        Assert.True(completion > names.IndexOf("control-flow-finalization"));
        Assert.True(completion > names.IndexOf("il-compaction"));
        Assert.True(completion > names.IndexOf("token-runtime-cleanup"));
        Assert.True(completion < names.IndexOf("symbol-renaming"));
    }

    [Theory]
    [InlineData(PassStatus.Success, true)]
    [InlineData(PassStatus.Partial, true)]
    [InlineData(PassStatus.Unsupported, false)]
    [InlineData(PassStatus.Failed, false)]
    [InlineData(null, false)]
    public void LateCompactionExposesCallerWithoutBypassingSkippedTyping(PassStatus? prior, bool repairs)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Consumers");
            var consumer = new MethodDefUser("Use", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Object),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(consumer);
            consumer.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            consumer.Body.Instructions.Add(OpCodes.Ldlen.ToInstruction());
            consumer.Body.Instructions.Add(OpCodes.Conv_I4.ToInstruction());
            consumer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var caller = new MethodDefUser("Caller", MethodSig.CreateStatic(module.CorLibTypes.Int32, new SZArraySig(module.CorLibTypes.Int32)),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(caller);
            var call = OpCodes.Call.ToInstruction(consumer);
            caller.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            caller.Body.Instructions.Add(OpCodes.Br.ToInstruction(call));
            caller.Body.Instructions.Add(call);
            caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        // Leave typing pending to verify completion honors the recorded pass status.
        if (prior is { } status)
            context.AddPassResult(new("array-parameter-typing", status, 0, [], TimeSpan.Zero));
        Assert.True(new IlCompactionPass().Run(context).Changes > 0);
        var result = new TypeRecoveryCompletionPass().Run(context);
        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(repairs ? 1 : 0, result.Changes);
        Assert.Equal(0, new TypeRecoveryCompletionPass().Run(context).Changes);
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
        try
        {
            context.Module.Write(path);
            Assert.Equal(repairs ? 0 : 1, IlVerification.Read(path, []).Count);
        }
        finally { File.Delete(path); }
    }
}
