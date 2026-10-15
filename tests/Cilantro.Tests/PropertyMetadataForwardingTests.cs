using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class PropertyMetadataForwardingTests
{
    [Theory]
    [InlineData("direct", true)]
    [InlineData("helper", true)]
    [InlineData("foreign", false)]
    [InlineData("wrong-signature", false)]
    [InlineData("escape", false)]
    [InlineData("address", false)]
    [InlineData("recursive", false)]
    public void FollowsOnlyClosedAttributeReads(string mode, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Owner");
            var member = module.CorLibTypes.GetTypeRef("System.Reflection", "MemberInfo");
            var type = module.CorLibTypes.GetTypeRef("System", "Type");
            var attribute = module.CorLibTypes.GetTypeRef("System", "Attribute");
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void, member.ToTypeSig()),
                MethodImplAttributes.IL, MethodAttributes.Static | MethodAttributes.Private) { Body = new CilBody() };
            owner.Methods.Add(run);
            var helper = new MethodDefUser("Helper", MethodSig.CreateStatic(module.CorLibTypes.Void, member.ToTypeSig()),
                MethodImplAttributes.IL, MethodAttributes.Static | MethodAttributes.Private) { Body = new CilBody() };
            owner.Methods.Add(helper);
            var il = helper.Body.Instructions;
            if (mode == "address") { il.Add(OpCodes.Ldarga.ToInstruction(helper.Parameters[0])); il.Add(OpCodes.Pop.ToInstruction()); }
            il.Add(OpCodes.Ldarg_0.ToInstruction());
            if (mode == "escape") il.Add(OpCodes.Pop.ToInstruction());
            else if (mode == "recursive") il.Add(OpCodes.Call.ToInstruction(helper));
            else
            {
                il.Add(OpCodes.Ldnull.ToInstruction());
                il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetCustomAttribute",
                    MethodSig.CreateStatic(attribute.ToTypeSig(), mode == "wrong-signature" ? module.CorLibTypes.Object : member.ToTypeSig(), type.ToTypeSig()),
                    mode == "foreign" ? new TypeRefUser(module, "System", "Attribute", new AssemblyRefUser("Foreign")) : attribute)));
                il.Add(OpCodes.Pop.ToInstruction());
            }
            il.Add(OpCodes.Ret.ToInstruction());
            if (mode == "direct")
            {
                foreach (var instruction in il) run.Body.Instructions.Add(instruction);
            }
            else
            {
                run.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                run.Body.Instructions.Add(OpCodes.Call.ToInstruction(helper));
                run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            }
        });
        var run = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Run");
        Assert.Equal(expected, ClosedPropertyMetadataUses.IsClosed(run, run.Body.Instructions[0]));
    }
}
