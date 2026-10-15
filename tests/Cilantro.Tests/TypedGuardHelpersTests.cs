using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class TypedGuardHelpersTests
{
    [Theory]
    [InlineData("typed", true)]
    [InlineData("folded", true)]
    [InlineData("folded-writer", false)]
    [InlineData("folded-live", false)]
    [InlineData("struct", true)]
    [InlineData("foreign-type", false)]
    [InlineData("writer", false)]
    [InlineData("live", false)]
    [InlineData("named", false)]
    [InlineData("family", true)]
    [InlineData("family-human", false)]
    [InlineData("family-mismatch", false)]
    [InlineData("family-writer", false)]
    [InlineData("family-low-churn", true)]
    [InlineData("family-repetitive", false)]
    [InlineData("global", true)]
    [InlineData("global-writer", false)]
    [InlineData("discarded", true)]
    [InlineData("discarded-throwing-initializer", true)]
    [InlineData("discarded-beforefieldinit", false)]
    [InlineData("discarded-alternate-entry", false)]
    [InlineData("discarded-memberref", true)]
    [InlineData("discarded-branch-true", true)]
    [InlineData("discarded-branch-false", true)]
    [InlineData("discarded-test-branch", true)]
    public void RetypedAndValueTypeGuardsRetainTheClosedUseRequirements(string scenario, bool removed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = scenario.StartsWith("global", StringComparison.Ordinal) ? module.GlobalType : SyntheticContext.AddType(module, "Owner");
            if (scenario == "struct") { owner.BaseType = module.CorLibTypes.GetTypeRef("System", "ValueType"); owner.Attributes |= TypeAttributes.Sealed; }
            var stored = scenario == "struct" ? module.CorLibTypes.Object :
                scenario == "foreign-type" ? SyntheticContext.AddType(module, "Other").ToTypeSig() : owner.ToTypeSig();
            var field = new FieldDefUser("a1B2c3D4e5F6", new FieldSig(stored), FieldAttributes.Private | FieldAttributes.Static);
            owner.Fields.Add(field);
            MethodDef Add(string name, TypeSig result)
            {
                var method = new MethodDefUser(name, MethodSig.CreateStatic(result))
                    { Attributes = MethodAttributes.Assembly | MethodAttributes.Static, Body = new CilBody() };
                owner.Methods.Add(method); return method;
            }
            var getter = Add("b2C3d4E5f6G7", stored);
            getter.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(field)); getter.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var test = Add("c3D4e5F6g7H8", module.CorLibTypes.Boolean);
            test.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(field)); test.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            test.Body.Instructions.Add(OpCodes.Ceq.ToInstruction()); test.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            if (scenario.StartsWith("family", StringComparison.Ordinal))
            {
                field.Name = "aB1cD2eF3gH4iJ5kL6";
                getter.Name = scenario == "family-human" ? "GetCurrentInstance" : "aaaaBBBBccccDDDDDD";
                test.Name = scenario == "family-mismatch" ? "eeeeFFFFggggHHHHH" : "eeeeFFFFggggHHHHHH";
                if (scenario == "family-low-churn")
                { field.Name = "ABCDabcdEFGH1234ij"; getter.Name = "IJKLijklMNOP5678qr"; test.Name = "QRSTqrstUVWX9012yz"; }
                if (scenario == "family-repetitive")
                { field.Name = "aaaaBBBBccccDD1234"; getter.Name = "bbbbCCCCddddEE1234"; test.Name = "ccccDDDDffffGG1234"; }
            }
            var keep = Add("Keep", module.CorLibTypes.Int32);
            var branchTarget = OpCodes.Ldc_I4.ToInstruction(99);
            if (scenario.StartsWith("discarded", StringComparison.Ordinal))
            {
                if (scenario == "discarded-beforefieldinit") owner.Attributes |= TypeAttributes.BeforeFieldInit;
                else owner.Attributes &= ~TypeAttributes.BeforeFieldInit;
                var pop = scenario is "discarded-branch-true" or "discarded-test-branch" ? OpCodes.Brtrue.ToInstruction(branchTarget) :
                    scenario == "discarded-branch-false" ? OpCodes.Brfalse.ToInstruction(branchTarget) : OpCodes.Pop.ToInstruction();
                if (scenario == "discarded-alternate-entry")
                { keep.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); keep.Body.Instructions.Add(OpCodes.Br.ToInstruction(pop)); }
                IMethod target = scenario == "discarded-memberref" ? new MemberRefUser(module, getter.Name, getter.MethodSig, owner) : getter;
                if (scenario == "discarded-test-branch") target = test;
                keep.Body.Instructions.Add(OpCodes.Call.ToInstruction(target)); keep.Body.Instructions.Add(pop);
                var initializer = Add(".cctor", module.CorLibTypes.Void);
                initializer.Attributes |= MethodAttributes.SpecialName | MethodAttributes.RTSpecialName;
                if (scenario == "discarded-throwing-initializer") {
                    initializer.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); initializer.Body.Instructions.Add(OpCodes.Throw.ToInstruction());
                }
                else initializer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            }
            keep.Body.Instructions.Add(OpCodes.Ldc_I4.ToInstruction(42)); keep.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            if (scenario.Contains("branch", StringComparison.Ordinal))
            { keep.Body.Instructions.Add(branchTarget); keep.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); }
            var root = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, Body = new CilBody() };
            module.GlobalType.Methods.Add(root);
            var il = root.Body.Instructions;
            il.Add(OpCodes.Call.ToInstruction(keep)); il.Add(OpCodes.Pop.ToInstruction());
            if (scenario.StartsWith("folded", StringComparison.Ordinal))
            {
                getter.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
                getter.Body.Instructions.Insert(2, OpCodes.Ldnull.ToInstruction());
            }
            if (scenario is "writer" or "family-writer" or "global-writer" or "folded-writer") { il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Stsfld.ToInstruction(field)); }
            if (scenario is "live" or "folded-live") { il.Add(OpCodes.Call.ToInstruction(getter)); il.Add(OpCodes.Pop.ToInstruction()); }
            if (scenario == "named") { il.Add(OpCodes.Ldstr.ToInstruction(field.Name.String)); il.Add(OpCodes.Pop.ToInstruction()); }
            il.Add(OpCodes.Ret.ToInstruction());
        });
        context.SetFact("options.removeRuntime", true);
        context.SetFact("method-protection.complete", true);
        context.SetFact("reactor.structure", new ReactorStructureFacts(0,0,0,0,0,0,0,false,false,ReactorCapability.DispatcherControlFlow,1,"test"));
        var owner = scenario.StartsWith("global", StringComparison.Ordinal) ? context.Module.GlobalType : context.Module.GetTypes().Single(t => t.Name == "Owner");
        var application = owner.Methods.Single(m => m.Name == "Keep");
        var snapshot = MethodBodySnapshot.Capture(application);
        new RuntimeCleanupPass().Run(context);
        Assert.Equal(removed, owner.Fields.Count == 0);
        if (removed && scenario.StartsWith("discarded", StringComparison.Ordinal))
        {
            Assert.Contains(application.Body.Instructions, i => i.OpCode.Code == Code.Ldtoken && i.Operand == owner);
            Assert.Contains(application.Body.Instructions, i => i.Operand is IMethod m && m.Name == "RunClassConstructor");
            if (scenario.Contains("branch", StringComparison.Ordinal))
            {
                var branch = Assert.Single(application.Body.Instructions, i => i.OpCode.FlowControl == FlowControl.Cond_Branch);
                Assert.Equal(99, ((Instruction)branch.Operand).GetLdcI4Value());
                Assert.Equal(scenario == "discarded-test-branch" ? Code.Ldc_I4_1 : Code.Ldnull,
                    application.Body.Instructions[application.Body.Instructions.IndexOf(branch) - 1].OpCode.Code);
            }
            if (scenario == "discarded-throwing-initializer")
                Assert.Equal(new[] { Code.Ldnull, Code.Throw }, owner.FindStaticConstructor().Body.Instructions.Select(i => i.OpCode.Code));
        }
        else Assert.True(snapshot.StructurallyEquals(application));
        if (removed) Assert.Single(owner.Methods, m => !m.IsStaticConstructor);
        Assert.True(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
            CilantroPipeline.BuildRewriteAllowance(context)).Passed);
    }
}
