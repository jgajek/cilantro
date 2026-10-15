using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class GenericGuardHelpersTests
{
    [Theory]
    [InlineData("dead", true)]
    [InlineData("live", false)]
    [InlineData("writer", false)]
    [InlineData("address", false)]
    [InlineData("extra-instance-read", false)]
    [InlineData("unresolved-field", false)]
    [InlineData("named", false)]
    [InlineData("public", false)]
    [InlineData("family", true)]
    [InlineData("family-mismatch", false)]
    [InlineData("family-human", false)]
    [InlineData("family-uniform", false)]
    public void GenericGuardRemovalRequiresAllInstantiationsToBeClosed(string scenario, bool removed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Container`1");
            owner.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            if (scenario == "public") owner.Attributes |= TypeAttributes.Public;
            var field = new FieldDefUser("a1B2c3D4e5F6", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Private | FieldAttributes.Static);
            owner.Fields.Add(field);
            MethodDef Add(string name, TypeSig result)
            {
                var method = new MethodDefUser(name, MethodSig.CreateStatic(result))
                    { Attributes = MethodAttributes.Assembly | MethodAttributes.Static, Body = new CilBody() };
                owner.Methods.Add(method); return method;
            }
            var open = new TypeSpecUser(new GenericInstSig(new ClassSig(owner), new GenericVar(0, owner)));
            var fieldReference = new MemberRefUser(module, field.Name, field.FieldSig, open);
            var getter = Add("b2C3d4E5f6G7", module.CorLibTypes.Object);
            if (scenario == "public") getter.Attributes = MethodAttributes.Public | MethodAttributes.Static;
            getter.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(fieldReference)); getter.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var test = Add("c3D4e5F6g7H8", module.CorLibTypes.Boolean);
            test.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(fieldReference)); test.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            test.Body.Instructions.Add(OpCodes.Ceq.ToInstruction()); test.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            if (scenario.StartsWith("family", StringComparison.Ordinal))
            {
                field.Name = "aB1cD2eF3gH4iJ5kL6";
                fieldReference.Name = field.Name;
                getter.Name = scenario == "family-mismatch" ? "aaaaBBBBccccDDDDD" : "aaaaBBBBccccDDDDDD";
                test.Name = "eeeeFFFFggggHHHHHH";
                if (scenario == "family-human") getter.Name = "GetCurrentInstance";
                if (scenario == "family-uniform") { field.Name = "aaaaBBBBccccDD1234"; fieldReference.Name = field.Name; }
            }
            var keep = Add("Keep", module.CorLibTypes.Int32);
            keep.Body.Instructions.Add(OpCodes.Ldc_I4.ToInstruction(42)); keep.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var root = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, Body = new CilBody() };
            module.GlobalType.Methods.Add(root);
            var closed = new TypeSpecUser(new GenericInstSig(new ClassSig(owner), module.CorLibTypes.String));
            var closedField = new MemberRefUser(module, field.Name,
                scenario == "unresolved-field" ? new FieldSig(module.CorLibTypes.String) : field.FieldSig, closed);
            var il = root.Body.Instructions;
            il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, keep.Name, keep.MethodSig, closed))); il.Add(OpCodes.Pop.ToInstruction());
            if (scenario == "live") { il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, getter.Name, getter.MethodSig, closed))); il.Add(OpCodes.Pop.ToInstruction()); }
            if (scenario == "writer") { il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Stsfld.ToInstruction(closedField)); }
            if (scenario is "address" or "extra-instance-read" or "unresolved-field")
            { il.Add((scenario == "address" ? OpCodes.Ldsflda : OpCodes.Ldsfld).ToInstruction(closedField)); il.Add(OpCodes.Pop.ToInstruction()); }
            if (scenario == "named") { il.Add(OpCodes.Ldstr.ToInstruction(field.Name.String)); il.Add(OpCodes.Pop.ToInstruction()); }
            il.Add(OpCodes.Ret.ToInstruction());
        });
        context.SetFact("options.removeRuntime", true);
        context.SetFact("method-protection.complete", true);
        context.SetFact("reactor.structure", new ReactorStructureFacts(0,0,0,0,0,0,0,false,false,ReactorCapability.DispatcherControlFlow,1,"test"));
        var owner = context.Module.GetTypes().Single(t => t.HasGenericParameters);
        var application = owner.Methods.Single(m => m.Name == "Keep");
        var snapshot = MethodBodySnapshot.Capture(application);
        new RuntimeCleanupPass().Run(context);
        Assert.Equal(removed, owner.Fields.Count == 0);
        Assert.Contains(application, owner.Methods);
        Assert.True(snapshot.StructurallyEquals(application));
        if (removed) Assert.Single(owner.Methods);
        Assert.True(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
            CilantroPipeline.BuildRewriteAllowance(context)).Passed);
    }
}
