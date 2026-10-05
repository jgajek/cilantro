using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Passes;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ControlFlowFinalizationPassTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void ConstantHelperRetainsTypeInitializationAndApplicationSwitch(bool throws, bool late)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            host.Attributes = TypeAttributes.Public;
            var helperType = SyntheticContext.AddType(module, "Predicate");
            var helper = new MethodDefUser("True", MethodSig.CreateStatic(module.CorLibTypes.Boolean), MethodAttributes.Static)
            { Body = new CilBody() };
            helperType.Methods.Add(helper);
            if (late) Add(helper, OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldc_I4_1.ToInstruction(),
                OpCodes.Add.ToInstruction(), OpCodes.Ret.ToInstruction());
            else Add(helper, OpCodes.Ldnull.ToInstruction(), OpCodes.Ldnull.ToInstruction(),
                OpCodes.Ceq.ToInstruction(), OpCodes.Ret.ToInstruction());
            var count = new FieldDefUser("Count", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static | FieldAttributes.Public);
            host.Fields.Add(count);
            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() };
            helperType.Methods.Add(cctor);
            Add(cctor, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(count));
            if (throws) Add(cctor, OpCodes.Ldnull.ToInstruction(), OpCodes.Throw.ToInstruction());
            else Add(cctor, OpCodes.Ret.ToInstruction());
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
            host.Methods.Add(run);
            var app = OpCodes.Ldarg_0.ToInstruction();
            var selected = Instruction.CreateLdcI4(17);
            Add(run, OpCodes.Call.ToInstruction(helper), OpCodes.Brtrue.ToInstruction(app), Instruction.CreateLdcI4(99),
                OpCodes.Ret.ToInstruction(), app, OpCodes.Switch.ToInstruction([selected]), Instruction.CreateLdcI4(23),
                OpCodes.Ret.ToInstruction(), selected, OpCodes.Ret.ToInstruction());
        });
        var before = new[] { Invoke(0), Invoke(1) };
        Assert.All(before, result => Assert.Equal(1, result.Count));
        string[] expected = throws ? ["System.TypeInitializationException", "System.TypeInitializationException"] : ["17", "23"];
        Assert.Equal(expected, before.Select(result => result.Value));
        var result = new ControlFlowFinalizationPass().Run(context);
        Assert.Equal(PassStatus.Success, result.Status);
        Assert.True(result.Changes > 0);
        var run = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Run");
        Assert.Single(run.Body.Instructions, i => i.OpCode.Code == Code.Call);
        Assert.Single(run.Body.Instructions, i => i.OpCode.Code == Code.Switch);
        Assert.DoesNotContain(run.Body.Instructions, i => i.OpCode.Code is Code.Brtrue or Code.Brtrue_S);
        Assert.True(EvaluationStackAnalyzer.Analyze(run).Valid);
        Assert.Equal(before, new[] { Invoke(0), Invoke(1) });
        Assert.Equal(0, new ControlFlowFinalizationPass().Run(context).Changes);

        (string Value, int Count) Invoke(int argument)
        {
            // Execute only the source-built benign fixture.
            using var stream = new MemoryStream();
            context.Module.Write(stream); stream.Position = 0;
            var loader = new System.Runtime.Loader.AssemblyLoadContext(Guid.NewGuid().ToString(), isCollectible: true);
            try
            {
                var type = loader.LoadFromStream(stream).GetType("Synthetic.Host")!;
                string value;
                try { value = type.GetMethod("Run")!.Invoke(null, [argument])!.ToString()!; }
                catch (System.Reflection.TargetInvocationException ex) { value = ex.InnerException!.GetType().FullName!; }
                return (value, (int)type.GetField("Count")!.GetValue(null)!);
            }
            finally { loader.Unload(); }
        }
    }

    private static void Add(MethodDef method, params Instruction[] instructions)
    {
        foreach (var instruction in instructions) method.Body.Instructions.Add(instruction);
    }
}
