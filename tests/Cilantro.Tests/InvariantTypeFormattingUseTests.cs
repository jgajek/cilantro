using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
namespace Cilantro.Tests;

public sealed class InvariantTypeFormattingUseTests
{
    [Theory]
    [InlineData("normal",true)]
    [InlineData("branch",true)]
    [InlineData("custom-provider",false)]
    [InlineData("foreign-culture",false)]
    [InlineData("foreign-format",false)]
    [InlineData("array-use",false)]
    [InlineData("wrong-argument",false)]
    [InlineData("wrong-validation",false)]
    [InlineData("alternate-entry",false)]
    [InlineData("cycle",false)]
    public void OnlyInvariantFormattingCanConsumeTheHandle(string mode,bool expected)
    {
        Instruction? token=null; MethodDef? caller=null;
        using var context=SyntheticContext.Build(module => {
            var owner=SyntheticContext.AddType(module,"Owner");
            var obj=module.CorLibTypes.Object; var str=module.CorLibTypes.String;
            var type=module.CorLibTypes.GetTypeRef("System","Type");
            var provider=module.CorLibTypes.GetTypeRef("System","IFormatProvider");
            MethodDef Add(string name,TypeSig ret,params TypeSig[] args) {
                var m=new MethodDefUser(name,MethodSig.CreateStatic(ret,args),MethodImplAttributes.IL,MethodAttributes.Private|MethodAttributes.Static){Body=new CilBody()};
                owner.Methods.Add(m); return m;
            }
            var check=Add("Check",mode=="wrong-validation"?obj:module.CorLibTypes.Void,obj,str);
            if(mode=="wrong-validation") check.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            check.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var helper=Add("Helper",str,obj,obj,new SZArraySig(obj));
            var body=helper.Body.Instructions;
            body.Add(OpCodes.Ldarg_0.ToInstruction()); body.Add(OpCodes.Castclass.ToInstruction(str.TypeDefOrRef));
            body.Add(OpCodes.Ldstr.ToInstruction("format")); body.Add(OpCodes.Call.ToInstruction(check));
            body.Add((mode=="wrong-argument"?OpCodes.Ldarg_0:OpCodes.Ldarg_1).ToInstruction()); body.Add(OpCodes.Castclass.ToInstruction(provider));
            body.Add(OpCodes.Ldarg_0.ToInstruction()); body.Add(OpCodes.Castclass.ToInstruction(str.TypeDefOrRef)); body.Add(OpCodes.Ldarg_2.ToInstruction());
            var formatOwner=mode=="foreign-format"?new TypeRefUser(module,"System","String",new AssemblyRefUser("Foreign")):str.TypeDefOrRef;
            body.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module,"Format",MethodSig.CreateStatic(str,provider.ToTypeSig(),str,new SZArraySig(obj)),formatOwner)));
            body.Add(OpCodes.Ret.ToInstruction());
            if(mode=="branch") body.Insert(0,OpCodes.Br.ToInstruction(body[0]));
            if(mode=="cycle") {var branch=OpCodes.Br.ToInstruction(body[0]);body.Insert(0,branch);branch.Operand=branch;}
            if(mode=="array-use") {body.Insert(0,OpCodes.Pop.ToInstruction());body.Insert(0,OpCodes.Ldarg_2.ToInstruction());}
            var wrapper=Add("Wrap",str,str,provider.ToTypeSig(),obj);
            var w=wrapper.Body.Instructions;
            w.Add(OpCodes.Ldarg_0.ToInstruction());w.Add(OpCodes.Ldarg_1.ToInstruction());w.Add(OpCodes.Ldc_I4_1.ToInstruction());
            w.Add(OpCodes.Newarr.ToInstruction(obj.TypeDefOrRef));w.Add(OpCodes.Dup.ToInstruction());w.Add(OpCodes.Ldc_I4_0.ToInstruction());
            w.Add(OpCodes.Ldarg_2.ToInstruction());w.Add(OpCodes.Stelem_Ref.ToInstruction());w.Add(OpCodes.Call.ToInstruction(helper));w.Add(OpCodes.Ret.ToInstruction());
            caller=Add("Run",str,provider.ToTypeSig());var il=caller.Body.Instructions;
            il.Add(OpCodes.Ldstr.ToInstruction("Type {0}"));
            var culture=mode=="foreign-culture"?new TypeRefUser(module,"System.Globalization","CultureInfo",new AssemblyRefUser("Foreign")):module.CorLibTypes.GetTypeRef("System.Globalization","CultureInfo");
            il.Add(mode=="custom-provider"?OpCodes.Ldarg_0.ToInstruction():OpCodes.Call.ToInstruction(new MemberRefUser(module,"get_InvariantCulture",MethodSig.CreateStatic(culture.ToTypeSig()),culture)));
            token=OpCodes.Ldtoken.ToInstruction(owner);il.Add(token);
            il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module,"GetTypeFromHandle",MethodSig.CreateStatic(type.ToTypeSig(),module.CorLibTypes.GetTypeRef("System","RuntimeTypeHandle").ToTypeSig()),type)));
            il.Add(OpCodes.Call.ToInstruction(wrapper));il.Add(OpCodes.Ret.ToInstruction());
            if(mode=="alternate-entry") { il.Insert(0,OpCodes.Br.ToInstruction(token)); il.Insert(0,OpCodes.Ldarg_0.ToInstruction()); il.Insert(0,OpCodes.Ldstr.ToInstruction("Alternate {0}")); }
        });
        caller=context.Module.GetTypes().Single(t=>t.Name=="Owner").Methods.Single(m=>m.Name=="Run");
        token=caller.Body.Instructions.Single(i=>i.OpCode.Code==Code.Ldtoken);
        Assert.Equal(expected,InvariantTypeFormattingUse.IsClosed(caller,token));
    }
}
