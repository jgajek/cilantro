using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
namespace Cilantro.Tests;

public sealed class RuntimeTypeRelationshipUseTests
{
    [Theory]
    [InlineData("subclass",true)]
    [InlineData("assignable",true)]
    [InlineData("null",true)]
    [InlineData("type-parameter",false)]
    [InlineData("foreign-gettype",false)]
    [InlineData("foreign-query",false)]
    [InlineData("mixed-local",false)]
    [InlineData("address",false)]
    [InlineData("escape",false)]
    [InlineData("unknown-query",false)]
    public void RequiresRuntimeOperandsAndClosedUses(string mode,bool expected)
    {
        using var context=SyntheticContext.Build(module => {
            var owner=SyntheticContext.AddType(module,"Owner");
            var type=module.CorLibTypes.GetTypeRef("System","Type");
            var method=new MethodDefUser("Run",MethodSig.CreateStatic(module.CorLibTypes.Boolean,module.CorLibTypes.Object,type.ToTypeSig()),MethodImplAttributes.IL,MethodAttributes.Static){Body=new CilBody{InitLocals=true}};
            owner.Methods.Add(method);var il=method.Body.Instructions;
            if(mode=="type-parameter") il.Add(OpCodes.Ldarg_1.ToInstruction());
            else if(mode=="null") il.Add(OpCodes.Ldnull.ToInstruction());
            else {
                il.Add(OpCodes.Ldarg_0.ToInstruction());
                var objectType=mode=="foreign-gettype"?new TypeRefUser(module,"System","Object",new AssemblyRefUser("Foreign")):module.CorLibTypes.Object.TypeDefOrRef;
                il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module,"GetType",MethodSig.CreateInstance(type.ToTypeSig()),objectType)));
            }
            il.Add(OpCodes.Ldtoken.ToInstruction(owner));
            il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module,"GetTypeFromHandle",MethodSig.CreateStatic(type.ToTypeSig(),module.CorLibTypes.GetTypeRef("System","RuntimeTypeHandle").ToTypeSig()),type)));
            var local=new Local(type.ToTypeSig());method.Body.Variables.Add(local);il.Add(OpCodes.Stloc.ToInstruction(local));
            if(mode=="mixed-local"){il.Add(OpCodes.Ldarg_1.ToInstruction());il.Add(OpCodes.Stloc.ToInstruction(local));}
            if(mode=="address"){il.Add(OpCodes.Ldloca.ToInstruction(local));il.Add(OpCodes.Pop.ToInstruction());}
            il.Add(OpCodes.Castclass.ToInstruction(type));il.Add(OpCodes.Ldloc.ToInstruction(local));
            if(mode=="escape") {
                var field=new FieldDefUser("Escape",new FieldSig(type.ToTypeSig()),FieldAttributes.Static);owner.Fields.Add(field);
                il.Add(OpCodes.Dup.ToInstruction());il.Add(OpCodes.Stsfld.ToInstruction(field));
            }
            var queryType=mode=="foreign-query"?new TypeRefUser(module,"System","Type",new AssemblyRefUser("Foreign")):type;
            il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module,mode=="unknown-query"?"OtherQuery":mode=="assignable"?"IsAssignableFrom":"IsSubclassOf",MethodSig.CreateInstance(module.CorLibTypes.Boolean,type.ToTypeSig()),queryType)));
            il.Add(OpCodes.Ret.ToInstruction());
        });
        var method=context.Module.GetTypes().Single(t=>t.Name=="Owner").Methods.Single();
        var token=method.Body.Instructions.Single(i=>i.OpCode.Code==Code.Ldtoken);
        Assert.Equal(expected,RuntimeTypeRelationshipUse.IsClosed(method,token));
    }
}
