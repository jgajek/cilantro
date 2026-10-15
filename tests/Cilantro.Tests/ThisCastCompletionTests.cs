using Cilantro.Core;
using Cilantro.Core.Passes;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ThisCastCompletionTests
{
    [Theory]
    [InlineData("base", true)]
    [InlineData("self", true)]
    [InlineData("padding", true)]
    [InlineData("spill", true)]
    [InlineData("parameter", false)]
    [InlineData("downcast", false)]
    [InlineData("foreign", false)]
    [InlineData("alternate-entry", false)]
    [InlineData("address", false)]
    public void RemovesOnlyGuaranteedCastsOfTheOriginalReceiver(string scenario, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var parent = SyntheticContext.AddType(module, "Parent");
            var child = SyntheticContext.AddType(module, "Child"); child.BaseType = parent;
            var descendant = SyntheticContext.AddType(module, "Descendant"); descendant.BaseType = child;
            ITypeDefOrRef target = scenario == "self" ? child : scenario == "downcast" ? descendant :
                scenario == "foreign" ? new TypeRefUser(module, "Synthetic", "Parent", new AssemblyRefUser("Foreign")) : parent;
            var method = new MethodDefUser("Run", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object))
            { Attributes = MethodAttributes.Public, Body = new CilBody() };
            child.Methods.Add(method);
            var cast = OpCodes.Castclass.ToInstruction(target);
            if (scenario == "address") { method.Body.Instructions.Add(OpCodes.Ldarga.ToInstruction(method.Parameters[0])); method.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); }
            if (scenario == "alternate-entry") { method.Body.Instructions.Add(OpCodes.Ldarg_1.ToInstruction()); method.Body.Instructions.Add(OpCodes.Br.ToInstruction(cast)); }
            method.Body.Instructions.Add(scenario == "parameter" ? OpCodes.Ldarg_1.ToInstruction() : OpCodes.Ldarg_0.ToInstruction());
            if (scenario == "spill") { var temporary = new Local(module.CorLibTypes.Object); method.Body.Variables.Add(temporary); method.Body.Instructions.Add(OpCodes.Ldarg_1.ToInstruction()); method.Body.Instructions.Add(OpCodes.Stloc.ToInstruction(temporary)); }
            if (scenario == "padding") method.Body.Instructions.Add(OpCodes.Nop.ToInstruction());
            method.Body.Instructions.Add(cast); method.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var result = new ThisCastCompletionPass().Run(context);
        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(expected ? 1 : 0, result.Changes);
        Assert.Equal(0, new ThisCastCompletionPass().Run(context).Changes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RestoresProtectedBaseCallVerificationWithoutChangingTheTarget(bool generic)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var parent = SyntheticContext.AddType(module, "Parent");
            var child = SyntheticContext.AddType(module, "Child"); child.BaseType = parent;
            if (generic) child.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            var target = new MethodDefUser("Protected", MethodSig.CreateInstance(module.CorLibTypes.Void))
            { Attributes = MethodAttributes.Family, Body = new CilBody() };
            parent.Methods.Add(target); target.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var run = new MethodDefUser("Run", MethodSig.CreateInstance(module.CorLibTypes.Void))
            { Attributes = MethodAttributes.Public, Body = new CilBody() };
            child.Methods.Add(run);
            foreach(var i in new[] { OpCodes.Ldarg_0.ToInstruction(), OpCodes.Castclass.ToInstruction(parent), OpCodes.Call.ToInstruction(target), OpCodes.Ret.ToInstruction() }) run.Body.Instructions.Add(i);
        });
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
        try
        {
            context.Module.Write(path);
            Assert.True(IlVerification.Read(path, []).Count > 0);
            Assert.Equal(1, new ThisCastCompletionPass().Run(context).Changes);
            context.Module.Write(path);
            Assert.Equal(0, IlVerification.Read(path, []).Count);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void RetainsCastsAcrossParameterizedBaseTypes()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var parent = SyntheticContext.AddType(module, "Parent");
            parent.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            var child = SyntheticContext.AddType(module, "Child");
            child.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            child.BaseType = new TypeSpecUser(new GenericInstSig(new ClassSig(parent), new GenericVar(0, child)));
            var method = new MethodDefUser("Run", MethodSig.CreateInstance(module.CorLibTypes.Void),
                MethodAttributes.Public) { Body = new CilBody() };
            child.Methods.Add(method);
            method.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            method.Body.Instructions.Add(OpCodes.Castclass.ToInstruction(child.BaseType));
            method.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(0, new ThisCastCompletionPass().Run(context).Changes);
    }
}
