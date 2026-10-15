using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ReferenceParameterTypingTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void FieldAddressConsumerRequiresKnownReceiverFromEveryCaller(bool known)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var value = SyntheticContext.AddType(module, "Value");
            var field = new FieldDefUser("Count", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Public);
            value.Fields.Add(field);
            var owner = SyntheticContext.AddType(module, "Consumers");
            var target = new MethodDefUser("Use", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Object),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(target);
            target.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            target.Body.Instructions.Add(OpCodes.Ldflda.ToInstruction(field));
            target.Body.Instructions.Add(OpCodes.Ldind_I4.ToInstruction());
            target.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var caller = new MethodDefUser("Caller", MethodSig.CreateStatic(module.CorLibTypes.Int32,
                known ? value.ToTypeSig() : module.CorLibTypes.Object), MethodImplAttributes.IL,
                MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(caller);
            caller.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(target));
            caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var result = new ReferenceParameterTypingPass().Run(context);
        Assert.Equal(known ? 1 : 0, result.Changes);
        var target = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Use");
        Assert.Equal(known ? 1 : 0, target.Body.Instructions.Count(i => i.OpCode.Code == Code.Castclass));
        Assert.Equal(0, new ReferenceParameterTypingPass().Run(context).Changes);
    }
    [Fact]
    public void CallerArgumentsSurviveFallThroughBranchesBeforePreparation()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Consumers");
            var target = new MethodDefUser("Use", MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.Object),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(target);
            target.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            target.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var caller = new MethodDefUser("Caller", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(caller);
            var call = OpCodes.Call.ToInstruction(target);
            caller.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("value"));
            caller.Body.Instructions.Add(OpCodes.Br.ToInstruction(call));
            caller.Body.Instructions.Add(call);
            caller.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(1, new ReferenceParameterTypingPass().Run(context).Changes);
        Assert.True(new Cilantro.Core.Passes.TypingPreparationPass().Run(context).Changes > 0);
        Assert.Equal(0, new ReferenceParameterTypingPass().Run(context).Changes);
        var passes = Cilantro.Core.CilantroPipeline.CreateDefaultPasses().Select(p => p.Name).ToList();
        Assert.True(passes.IndexOf("typing-preparation") < passes.IndexOf("array-parameter-typing"));
        Assert.True(passes.IndexOf("typing-preparation") < passes.IndexOf("reference-parameter-typing"));
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public void MergesOnlyProvenInterfaceImplementations(bool implements, bool inherited)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var contract = SyntheticContext.AddType(module, "IContract");
            contract.Attributes = TypeAttributes.Interface | TypeAttributes.Abstract | TypeAttributes.NotPublic;
            contract.BaseType = null;
            var parent = SyntheticContext.AddType(module, "Parent");
            var value = SyntheticContext.AddType(module, "Value");
            value.BaseType = parent;
            if (implements) (inherited ? parent : value).Interfaces.Add(new InterfaceImplUser(contract));
            var owner = SyntheticContext.AddType(module, "Consumers");
            var target = new MethodDefUser("Use", MethodSig.CreateStatic(new ClassSig(contract), module.CorLibTypes.Object),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(target);
            target.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            target.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            foreach (var type in new[] { contract, value })
            {
                var caller = new MethodDefUser("Caller" + type.Name, MethodSig.CreateStatic(module.CorLibTypes.Void, new ClassSig(type)),
                    MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
                owner.Methods.Add(caller);
                caller.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(target));
                caller.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
                caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            }
        });
        var target = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Use");
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
        try
        {
            context.Module.Write(path);
            Assert.Equal(1, IlVerification.Read(path, []).Count);
            Assert.Equal(implements ? 1 : 0, new ReferenceParameterTypingPass().Run(context).Changes);
            Assert.Equal(ElementType.Object, target.MethodSig.Params[0].ElementType);
            Assert.Equal(implements ? 1 : 0, target.Body.Instructions.Count(i => i.OpCode.Code == Code.Castclass));
            Assert.Equal(0, new ReferenceParameterTypingPass().Run(context).Changes);
            context.Module.Write(path);
            Assert.Equal(implements ? 0 : 1, IlVerification.Read(path, []).Count);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void ExistingCastAfterNopPaddingIsNotDuplicated()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Padded");
            var target = new MethodDefUser("Use", MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.Object),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(target);
            target.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            target.Body.Instructions.Add(OpCodes.Nop.ToInstruction());
            target.Body.Instructions.Add(OpCodes.Castclass.ToInstruction(module.CorLibTypes.String.TypeDefOrRef));
            target.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var caller = new MethodDefUser("Caller", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(caller);
            caller.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("input"));
            caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(target));
            caller.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(0, new ReferenceParameterTypingPass().Run(context).Changes);
        Assert.Single(context.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody)
            .SelectMany(m => m.Body.Instructions), i => i.OpCode.Code == Code.Castclass);
    }
    [Theory]
    [InlineData("string", true)]
    [InlineData("class", true)]
    [InlineData("closed-generic", true)]
    [InlineData("generic-conflict", false)]
    [InlineData("literal", true)]
    [InlineData("isinst", true)]
    [InlineData("isinst-null", true)]
    [InlineData("string-array", true)]
    [InlineData("object-array", false)]
    [InlineData("unknown", false)]
    [InlineData("conflict", false)]
    [InlineData("address", false)]
    [InlineData("handle", false)]
    [InlineData("name", false)]
    public void RestoresOnlyReferenceTypesEstablishedByEveryCaller(string scenario, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Consumers");
            TypeSig concrete = scenario == "class" ? new ClassSig(SyntheticContext.AddType(module, "Value")) : module.CorLibTypes.String;
            TypeDef? generic = null;
            if (scenario is "closed-generic" or "generic-conflict")
            {
                generic = SyntheticContext.AddType(module, "Container`1");
                generic.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
                concrete = new GenericInstSig(new ClassSig(generic), module.CorLibTypes.String);
            }
            var target = new MethodDefUser("Use", MethodSig.CreateStatic(concrete, module.CorLibTypes.Object),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(target);
            var local = new Local(concrete);
            target.Body.Variables.Add(local);
            if (scenario == "address")
            {
                target.Body.Instructions.Add(OpCodes.Ldarga.ToInstruction(target.Parameters[0]));
                target.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            }
            target.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            target.Body.Instructions.Add(OpCodes.Stloc.ToInstruction(local));
            target.Body.Instructions.Add(OpCodes.Ldloc.ToInstruction(local));
            target.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var caller = new MethodDefUser("Caller", MethodSig.CreateStatic(module.CorLibTypes.Void,
                scenario == "unknown" ? module.CorLibTypes.Object : concrete), MethodImplAttributes.IL,
                MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(caller);
            caller.Body.Instructions.Add(scenario == "literal" ? OpCodes.Ldstr.ToInstruction("sample") : OpCodes.Ldarg_0.ToInstruction());
            if (scenario is "string-array" or "object-array")
            {
                caller.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
                caller.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction());
                caller.Body.Instructions.Add(OpCodes.Newarr.ToInstruction(scenario == "string-array" ? module.CorLibTypes.String.TypeDefOrRef : module.CorLibTypes.Object.TypeDefOrRef));
                caller.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
                caller.Body.Instructions.Add(OpCodes.Ldelem_Ref.ToInstruction());
            }
            if (scenario is "isinst" or "isinst-null")
            {
                if (scenario == "isinst-null")
                {
                    caller.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
                    caller.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
                    caller.Body.Instructions.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Byte.TypeDefOrRef));
                }
                caller.Body.Instructions.Add(OpCodes.Isinst.ToInstruction(module.CorLibTypes.String.TypeDefOrRef));
            }
            caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(target));
            caller.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            if (scenario == "conflict")
            {
                caller.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
                caller.Body.Instructions.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Byte.TypeDefOrRef));
                caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(target));
                caller.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            }
            if (scenario == "generic-conflict")
            {
                caller.Body.Variables.Add(new Local(new GenericInstSig(new ClassSig(generic!), module.CorLibTypes.Int32)));
                caller.Body.InitLocals = true;
                caller.Body.Instructions.Add(OpCodes.Ldloc_0.ToInstruction());
                caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(target));
                caller.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            }
            if (scenario is "handle" or "name")
            {
                caller.Body.Instructions.Add(scenario == "handle" ? OpCodes.Ldtoken.ToInstruction(target) : OpCodes.Ldstr.ToInstruction("Use"));
                caller.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            }
            caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var target = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Use");
        var signature = target.MethodSig.ToString();
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
        try
        {
            context.Module.Write(path);
            Assert.Equal(1, IlVerification.Read(path, []).Count);
            Assert.Equal(expected ? 1 : 0, new ReferenceParameterTypingPass().Run(context).Changes);
            Assert.Equal(signature, target.MethodSig.ToString());
            Assert.Equal(0, new ReferenceParameterTypingPass().Run(context).Changes);
            context.Module.Write(path);
            Assert.Equal(expected ? 0 : 1, IlVerification.Read(path, []).Count);
        }
        finally { File.Delete(path); }
    }
}
