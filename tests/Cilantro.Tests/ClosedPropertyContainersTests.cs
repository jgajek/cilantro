using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ClosedPropertyContainersTests
{
    [Theory]
    [InlineData("read", true)]
    [InlineData("array-escape", false)]
    [InlineData("metadata-escape", false)]
    [InlineData("list", true)]
    [InlineData("list-escape", false)]
    [InlineData("field-address", false)]
    public void RequiresEveryArrayAndContainerUseToClose(string mode, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Owner");
            var property = module.CorLibTypes.GetTypeRef("System.Reflection", "PropertyInfo");
            var array = new SZArraySig(property.ToTypeSig());
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void, array), MethodImplAttributes.IL,
                MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() }; owner.Methods.Add(run);
            var il = run.Body.Instructions;
            il.Add(OpCodes.Ldarg_0.ToInstruction());
            if (mode == "array-escape") { il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction()); return; }
            var saved = new Local(array); run.Body.Variables.Add(saved); il.Add(OpCodes.Stloc.ToInstruction(saved));
            var list = new TypeSpecUser(new GenericInstSig(new ClassSig(module.CorLibTypes.GetTypeRef("System.Collections.Generic", "List`1")), property.ToTypeSig()));
            var field = new FieldDefUser("Items", new FieldSig(list.ToTypeSig()), FieldAttributes.Private | FieldAttributes.Static);
            owner.Fields.Add(field);
            if (mode is "list" or "list-escape" or "field-address") il.Add(OpCodes.Ldsfld.ToInstruction(field));
            il.Add(OpCodes.Ldloc.ToInstruction(saved)); il.Add(OpCodes.Ldc_I4_0.ToInstruction()); il.Add(OpCodes.Ldelem_Ref.ToInstruction());
            if (mode is "list" or "list-escape" or "field-address")
            {
                il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "Add", MethodSig.CreateInstance(module.CorLibTypes.Void, property.ToTypeSig()), list)));
                if (mode == "list-escape")
                {
                    il.Add(OpCodes.Ldsfld.ToInstruction(field));
                    il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetType", MethodSig.CreateInstance(module.CorLibTypes.GetTypeRef("System", "Type").ToTypeSig()), module.CorLibTypes.Object.TypeDefOrRef)));
                    il.Add(OpCodes.Pop.ToInstruction());
                }
                if (mode == "field-address") { il.Add(OpCodes.Ldsflda.ToInstruction(field)); il.Add(OpCodes.Pop.ToInstruction()); }
            }
            else if (mode == "metadata-escape") il.Add(OpCodes.Pop.ToInstruction());
            else
            {
                il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Ldnull.ToInstruction());
                il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetValue", MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.Object, new SZArraySig(module.CorLibTypes.Object)), property)));
                il.Add(OpCodes.Pop.ToInstruction());
            }
            il.Add(OpCodes.Ret.ToInstruction());
        });
        var run = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Run");
        Assert.Equal(expected, ClosedPropertyContainers.Analyze(run, run.Body.Instructions[0]).Closed);
    }
}
