using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
namespace Cilantro.Tests;
public sealed class OptionalResourceSymbolsTests
{
    [Theory]
    [InlineData("normal",true)]
    [InlineData("two-resources",false)]
    [InlineData("foreign-owner",false)]
    [InlineData("foreign-framework",false)]
    [InlineData("address",false)]
    [InlineData("uninitialized",false)]
    [InlineData("reachable-write",false)]
    public void OnlyProvenDeadResourceBranchCanHideNonNullAssignment(string mode,bool expected)
    {
        MethodDef? method=null; Local? symbols=null;
        using var context=SyntheticContext.Build(module=>{
            var owner=SyntheticContext.AddType(module,"Wrapper");
            module.Resources.Add(new EmbeddedResource("payload",new byte[]{1}));
            if(mode=="two-resources")module.Resources.Add(new EmbeddedResource("symbols",new byte[]{2}));
            var type=module.CorLibTypes.GetTypeRef("System","Type");var assembly=module.CorLibTypes.GetTypeRef("System.Reflection","Assembly");
            method=new MethodDefUser("Start",MethodSig.CreateStatic(module.CorLibTypes.Void),MethodAttributes.Static){Body=new CilBody{InitLocals=mode!="uninitialized"}};
            owner.Methods.Add(method);symbols=new Local(new SZArraySig(module.CorLibTypes.Byte));method.Body.Variables.Add(symbols);var il=method.Body.Instructions;
            void Call(OpCode op,string name,MethodSig sig,ITypeDefOrRef declaring)=>il.Add(op.ToInstruction(new MemberRefUser(module,name,sig,declaring)));
            il.Add(OpCodes.Ldnull.ToInstruction());il.Add(OpCodes.Stloc.ToInstruction(symbols));
            il.Add(OpCodes.Ldtoken.ToInstruction(mode=="foreign-owner"?type:owner));
            Call(OpCodes.Call,"GetTypeFromHandle",MethodSig.CreateStatic(type.ToTypeSig(),module.CorLibTypes.GetTypeRef("System","RuntimeTypeHandle").ToTypeSig()),type);
            Call(OpCodes.Callvirt,"get_Assembly",MethodSig.CreateInstance(assembly.ToTypeSig()),type);
            Call(OpCodes.Callvirt,"GetManifestResourceNames",MethodSig.CreateInstance(new SZArraySig(module.CorLibTypes.String)),mode=="foreign-framework"?new TypeRefUser(module,"System.Reflection","Assembly",new AssemblyRefUser("Other")):assembly);
            il.Add(OpCodes.Ldlen.ToInstruction());il.Add(OpCodes.Conv_I4.ToInstruction());il.Add(OpCodes.Ldc_I4_1.ToInstruction());
            var end=OpCodes.Ret.ToInstruction();il.Add(OpCodes.Ble.ToInstruction(end));
            il.Add(OpCodes.Ldc_I4_1.ToInstruction());il.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Byte.TypeDefOrRef));il.Add(OpCodes.Stloc.ToInstruction(symbols));
            if(mode=="reachable-write")il.Insert(0,OpCodes.Br.ToInstruction(il[^3]));
            if(mode=="address"){il.Insert(0,OpCodes.Pop.ToInstruction());il.Insert(0,OpCodes.Ldloca.ToInstruction(symbols));}
            il.Add(end);
        });
        Assert.Equal(expected,OptionalResourceSymbols.IsNull(method!,symbols!));
    }
}
