using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class GenericConstructionReachabilityTests
{
    [Theory]
    [InlineData("field", true)]
    [InlineData("method", true)]
    [InlineData("external-method", true)]
    [InlineData("unconstrained-field", false)]
    public void GenericConstructionRetainsConstructorAndItsEffects(string scenario, bool retained)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var item = SyntheticContext.AddType(module, "Item");
            var state = new FieldDefUser("State", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static);
            item.Fields.Add(state);
            var ctor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void),
                MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() };
            foreach (var instruction in new[] { OpCodes.Ldarg_0.ToInstruction(), OpCodes.Call.ToInstruction(module.Import(typeof(object).GetConstructor([])!)),
                OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(state), OpCodes.Ret.ToInstruction() }) ctor.Body.Instructions.Add(instruction);
            item.Methods.Add(ctor);
            var api = SyntheticContext.AddType(module, "Api");
            api.Attributes = TypeAttributes.Public;
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL,
                MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
            api.Methods.Add(run);
            if (scenario.EndsWith("field", StringComparison.Ordinal))
            {
                var box = SyntheticContext.AddType(module, "Box`1");
                box.GenericParameters.Add(new GenericParamUser(0, scenario == "field" ? GenericParamAttributes.DefaultConstructorConstraint : GenericParamAttributes.NonVariant, "T"));
                api.Fields.Add(new FieldDefUser("Box", new FieldSig(new GenericInstSig(new ClassSig(box), new ClassSig(item))), FieldAttributes.Public | FieldAttributes.Static));
            }
            else
            {
                IMethodDefOrRef factory;
                if (scenario == "external-method")
                    factory = new MemberRefUser(module, "Create", MethodSig.CreateStaticGeneric(1, module.CorLibTypes.Void),
                        new TypeRefUser(module, "Unknown", "Factory", new AssemblyRefUser("MissingLibrary")));
                else
                {
                    var create = new MethodDefUser("Create", MethodSig.CreateStaticGeneric(1, module.CorLibTypes.Void),
                        MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
                    create.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.DefaultConstructorConstraint, "T"));
                    create.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                    api.Methods.Add(create);
                    factory = create;
                }
                run.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MethodSpecUser(factory, new GenericInstMethodSig(new ClassSig(item)))));
            }
            run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var constructor = context.Module.GetTypes().Single(type => type.Name == "Item").FindInstanceConstructors().Single();
        var reach = ModuleReachability.ComputeWithInstances(context.Module, false);
        Assert.Equal(retained, reach.IsReachable(constructor));
        RecoveryOrphans.Declare(context, [constructor]);
        context.SetFact("method-protection.complete", true);
        context.SetFact("options.removeRuntime", true);
        new RuntimeCleanupPass().Run(context);
        Assert.Equal(retained, constructor.DeclaringType?.Methods.Contains(constructor) == true);
    }
}
