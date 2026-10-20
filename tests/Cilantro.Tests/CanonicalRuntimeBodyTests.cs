using Cilantro.Core;
using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class CanonicalRuntimeBodyTests
{
    [Fact]
    public void PhysicalBranchOrderIsIgnoredButConditionalMeaningIsRetained()
    {
        using var first = Branches(false, false);
        using var reordered = Branches(true, false);
        using var inverted = Branches(true, true);
        Assert.Equal(Fingerprint(first), Fingerprint(reordered));
        Assert.NotEqual(Fingerprint(first), Fingerprint(inverted));
    }

    [Fact]
    public void MovingARealCallOutsideItsExceptionRegionChangesTheGraph()
    {
        using var inside = ExceptionRegion(false);
        using var outside = ExceptionRegion(true);
        Assert.NotEqual(Fingerprint(inside), Fingerprint(outside));
    }

    private static string Fingerprint(ArtifactContext context) => GeneratedRuntimeShape.ReadCanonical(
        context.Module.GlobalType.Methods.Single(method => method.Name == "Probe")).Fingerprint;

    private static ArtifactContext Branches(bool reordered, bool inverted) => SyntheticContext.Build(module =>
    {
        var method = new MethodDefUser("Probe", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32), MethodAttributes.Static) { Body = new CilBody() };
        module.GlobalType.Methods.Add(method);
        Instruction[] yes = [OpCodes.Ldc_I4_2.ToInstruction(), OpCodes.Ret.ToInstruction()];
        Instruction[] no = [OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Ret.ToInstruction()];
        method.Body.Instructions.Add(OpCodes.Ldarg.ToInstruction(method.Parameters[0]));
        method.Body.Instructions.Add((inverted ? OpCodes.Brfalse : OpCodes.Brtrue).ToInstruction(yes[0]));
        method.Body.Instructions.Add(OpCodes.Br.ToInstruction(no[0]));
        foreach (var instruction in reordered ? yes.Concat(no) : no.Concat(yes)) method.Body.Instructions.Add(instruction);
    });

    private static ArtifactContext ExceptionRegion(bool outside) => SyntheticContext.Build(module =>
    {
        var method = new MethodDefUser("Probe", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodAttributes.Static) { Body = new CilBody() };
        module.GlobalType.Methods.Add(method);
        var start = OpCodes.Nop.ToInstruction();
        var call = OpCodes.Call.ToInstruction(new MemberRefUser(module, "Collect", MethodSig.CreateStatic(module.CorLibTypes.Void),
            new TypeRefUser(module, "System", "GC", module.CorLibTypes.AssemblyRef)));
        var done = OpCodes.Ret.ToInstruction(); var leave = OpCodes.Leave.ToInstruction(done); var handler = OpCodes.Pop.ToInstruction();
        foreach (var instruction in new[] { start, call, leave, handler, OpCodes.Leave.ToInstruction(done), done }) method.Body.Instructions.Add(instruction);
        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
        {
            TryStart = outside ? leave : start, TryEnd = handler, HandlerStart = handler, HandlerEnd = done, CatchType = module.CorLibTypes.Object.TypeDefOrRef
        });
    });
}
