using Cilantro.Core;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;
public sealed class RecursiveParameterTypingTests
{
    [Theory]
    [InlineData("seed", false, true)]
    [InlineData("seed", true, true)]
    [InlineData("seedless", false, false)]
    [InlineData("unknown", false, false)]
    [InlineData("conflict", false, false)]
    [InlineData("address", false, false)]
    [InlineData("handle", false, false)]
    public void MutualCyclesNeedConcreteConsistentExternalSeeds(string scenario, bool references, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module,"Cycle");
            MethodDef Add(string name,TypeSig type)
            {
                var method = new MethodDefUser(name,MethodSig.CreateStatic(module.CorLibTypes.Void,type))
                { Attributes=MethodAttributes.Static|MethodAttributes.Private,Body=new CilBody() };
                owner.Methods.Add(method);return method;
            }
            var a=Add("A",module.CorLibTypes.Object);var b=Add("B",module.CorLibTypes.Object);
            foreach(var pair in new[]{(a,b),(b,a)})
            {
                var il=pair.Item1.Body.Instructions;
                il.Add(OpCodes.Ldarg_0.ToInstruction());
                il.Add(references ? OpCodes.Callvirt.ToInstruction(new MemberRefUser(module,"get_Length",MethodSig.CreateInstance(module.CorLibTypes.Int32),module.CorLibTypes.String.TypeDefOrRef)) : OpCodes.Ldlen.ToInstruction());
                il.Add(OpCodes.Pop.ToInstruction());
                if(scenario=="address" && pair.Item1==b){il.Add(OpCodes.Ldarga.ToInstruction(b.Parameters[0]));il.Add(OpCodes.Pop.ToInstruction());}
                il.Add(OpCodes.Ldarg_0.ToInstruction());il.Add(OpCodes.Call.ToInstruction(pair.Item2));il.Add(OpCodes.Ret.ToInstruction());
            }
            void Seed(string name,TypeSig type,MethodDef target)
            {
                var caller=Add(name,type);caller.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(target));caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            }
            if(scenario!="seedless")Seed("Start",references ? module.CorLibTypes.String : new SZArraySig(module.CorLibTypes.Byte),a);
            if(scenario=="unknown")Seed("Unknown",module.CorLibTypes.Object,b);
            if(scenario=="conflict")Seed("Conflict",new SZArraySig(module.CorLibTypes.Int32),b);
            if(scenario=="handle"){var expose=Add("Expose",module.CorLibTypes.Object);expose.Body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(a));expose.Body.Instructions.Add(OpCodes.Pop.ToInstruction());expose.Body.Instructions.Add(OpCodes.Ret.ToInstruction());}
        });
        DeobfuscationPass pass=references ? new ReferenceParameterTypingPass() : new ArrayParameterTypingPass();
        var result=pass.Run(context);
        Assert.Equal(PassStatus.Success,result.Status);
        Assert.Equal(expected ? 2 : 0,result.Changes);
        Assert.Equal(0,pass.Run(context).Changes);
        if(expected)
        {
            var path=Path.Combine(Path.GetTempPath(),Guid.NewGuid()+".dll");
            try{context.Module.Write(path);Assert.Equal(0,IlVerification.Read(path,[]).Count);}finally{File.Delete(path);}
        }
    }
}
