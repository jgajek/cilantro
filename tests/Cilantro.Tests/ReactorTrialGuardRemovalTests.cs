using Cilantro.Core;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ReactorTrialGuardRemovalTests
{
    [Theory]
    [InlineData("generated", true)]
    [InlineData("application-message", false)]
    [InlineData("side-effect", false)]
    [InlineData("incomplete", false)]
    [InlineData("keep-runtime", false)]
    public void RemovalRequiresExactAttributionNoApplicationEffectsAndCompletedRecovery(string variant, bool removed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var importer = new Importer(module);
            var guard = new MethodDefUser("Guard", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL, MethodAttributes.Static | MethodAttributes.Private) { Body = new CilBody() };
            module.GlobalType.Methods.Add(guard);
            var body = guard.Body.Instructions;
            body.Add(OpCodes.Call.ToInstruction(importer.Import(typeof(DateTime).GetProperty(nameof(DateTime.Now))!.GetMethod!)));
            body.Add(OpCodes.Pop.ToInstruction());
            body.Add(OpCodes.Ldc_I4.ToInstruction(2026));
            body.Add(OpCodes.Ldc_I4_1.ToInstruction());
            body.Add(OpCodes.Ldc_I4_1.ToInstruction());
            body.Add(OpCodes.Newobj.ToInstruction(importer.Import(typeof(DateTime).GetConstructor([typeof(int), typeof(int), typeof(int)])!)));
            body.Add(OpCodes.Pop.ToInstruction());
            if (variant == "side-effect")
            {
                var field = new FieldDefUser("ApplicationState", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
                module.GlobalType.Fields.Add(field);
                body.Add(OpCodes.Ldc_I4_1.ToInstruction());
                body.Add(OpCodes.Stsfld.ToInstruction(field));
            }
            body.Add(OpCodes.Ldstr.ToInstruction(variant == "application-message" ? "Subscription expired" : ReactorTrialGuardRemovalPass.Message));
            body.Add(OpCodes.Newobj.ToInstruction(importer.Import(typeof(Exception).GetConstructor([typeof(string)])!)));
            body.Add(OpCodes.Throw.ToInstruction());
        });
        context.SetFact("options.removeRuntime", variant != "keep-runtime");
        context.SetFact("method-protection.complete", variant != "incomplete");
        var result = new ReactorTrialGuardRemovalPass().Run(context);
        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(removed ? 1 : 0, result.Changes);
        var body = context.Module.GlobalType.Methods.Single(method => method.Name == "Guard").Body;
        Assert.Equal(removed, body.Instructions.Count == 1 && body.Instructions[0].OpCode == OpCodes.Ret);
    }
}
