using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ConstantGuardHelpersTests
{
    [Theory]
    [InlineData("dead", true)]
    [InlineData("live", false)]
    [InlineData("named", false)]
    [InlineData("human", false)]
    [InlineData("class", false)]
    [InlineData("non-generic", false)]
    [InlineData("false", false)]
    [InlineData("incomplete", false)]
    [InlineData("family", true)]
    [InlineData("family-human", false)]
    [InlineData("family-uniform", false)]
    public void ConstantPairsRequireTheGenericValueTypeFamilyAndDeadness(string scenario, bool removed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Container`1");
            if (scenario != "class") { owner.BaseType = module.CorLibTypes.GetTypeRef("System", "ValueType"); owner.Attributes |= TypeAttributes.Sealed; }
            if (scenario != "non-generic") owner.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            MethodDef Add(string name, TypeSig returns)
            {
                var method = new MethodDefUser(name, MethodSig.CreateStatic(returns))
                    { Attributes = MethodAttributes.Static | MethodAttributes.Assembly, Body = new CilBody() };
                owner.Methods.Add(method); return method;
            }
            var getter = Add(scenario == "human" ? "GetDefaultValue" : "aB1cD2eF3gH4iJ5kL6", module.CorLibTypes.Object);
            getter.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); getter.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var test = Add("bC1dE2fG3hI4jK5lM6", module.CorLibTypes.Boolean);
            if (scenario.StartsWith("family", StringComparison.Ordinal))
            {
                getter.Name = scenario == "family-human" ? "GetCurrentInstance" : "aaaaBBBBccccDDDDDD";
                if (scenario == "family-uniform") test.Name = "eeeeFFFFggggHHHHHH";
            }
            test.Body.Instructions.Add((scenario == "false" ? OpCodes.Ldc_I4_0 : OpCodes.Ldc_I4_1).ToInstruction()); test.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var keep = Add("Keep", module.CorLibTypes.Int32);
            keep.Body.Instructions.Add(OpCodes.Ldc_I4.ToInstruction(42)); keep.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var root = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, Body = new CilBody() };
            module.GlobalType.Methods.Add(root);
            var declaring = owner.HasGenericParameters ? (ITypeDefOrRef)new TypeSpecUser(new GenericInstSig(
                scenario == "class" ? new ClassSig(owner) : new ValueTypeSig(owner), module.CorLibTypes.String)) : owner;
            root.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, keep.Name, keep.MethodSig, declaring)));
            root.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            if (scenario == "live") { root.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, getter.Name, getter.MethodSig, declaring))); root.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); }
            if (scenario == "named") { root.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction(getter.Name.String)); root.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); }
            root.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        context.SetFact("options.removeRuntime", true);
        context.SetFact("method-protection.complete", scenario != "incomplete");
        context.SetFact("reactor.structure", new ReactorStructureFacts(0,0,0,0,0,0,0,false,false,ReactorCapability.DispatcherControlFlow,1,"test"));
        var owner = context.Module.Types.Single(t => t.Name == "Container`1");
        new RuntimeCleanupPass().Run(context);
        Assert.Equal(removed, owner.Methods.Count == 1);
        Assert.Contains(owner.Methods, m => m.Name == "Keep");
        if (scenario == "live") Assert.Contains(owner.Methods, m => m.ReturnType.ElementType == ElementType.Object);
    }
}
