using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
namespace Cilantro.Tests;
public sealed class ReferenceParameterContractsTests
{
    [Theory]
    [InlineData("normal",true)]
    [InlineData("cast",true)]
    [InlineData("locals",true)]
    [InlineData("literal",false)]
    [InlineData("foreign-cast",false)]
    [InlineData("foreign-return",false)]
    [InlineData("parameter",false)]
    [InlineData("instance",false)]
    [InlineData("cycle",false)]
    [InlineData("exception",false)]
    public void RequiresMatchingBodyAndTypeBindings(string mode,bool expected)
    {
        using var reference=Module("Reference");using var target=Module("Target");
        var original=Add(reference,reference.CorLibTypes.String);var candidate=Add(target,target.CorLibTypes.Object);
        if(mode=="locals") {
            candidate.Body.Variables.Add(new Local(target.CorLibTypes.Int32));
            foreach(var method in new[]{original,candidate}) {
                var local=new Local(method.Module.CorLibTypes.String);method.Body.Variables.Add(local);
                method.Body.Instructions.Insert(1,OpCodes.Stloc.ToInstruction(local));method.Body.Instructions.Insert(2,OpCodes.Ldloc.ToInstruction(local));
            }
        }
        if(mode is "cast" or "foreign-cast") {
            ITypeDefOrRef cast=mode=="cast"?target.CorLibTypes.String.TypeDefOrRef:new TypeRefUser(target,"System","String",new AssemblyRefUser("Other"));
            candidate.Body.Instructions.Insert(1,OpCodes.Castclass.ToInstruction(cast));
        }
        if(mode=="literal")candidate.Body.Instructions[0]=OpCodes.Ldstr.ToInstruction("changed");
        if(mode=="foreign-return")candidate.MethodSig.RetType=new ClassSig(new TypeRefUser(target,"System","String",new AssemblyRefUser("Other")));
        if(mode=="parameter")candidate.MethodSig.Params[0]=target.CorLibTypes.Int32;
        if(mode=="instance")candidate.IsStatic=false;
        if(mode=="cycle"){var loop=OpCodes.Br.ToInstruction(candidate.Body.Instructions[0]);loop.Operand=loop;candidate.Body.Instructions.Insert(0,loop);}
        if(mode=="exception")candidate.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Finally){TryStart=candidate.Body.Instructions[0],TryEnd=candidate.Body.Instructions[1],HandlerStart=candidate.Body.Instructions[1]});
        Assert.Equal(expected,ReferenceParameterContracts.Match(candidate,ReferenceParameterContracts.Create(original),new Dictionary<string,string>()));
    }
    private static ModuleDefUser Module(string name)
    {
        var module=new ModuleDefUser(name+".dll");var assembly=new AssemblyDefUser(name,new Version(1,0));assembly.Modules.Add(module);return module;
    }
    private static MethodDefUser Add(ModuleDef module,TypeSig parameter)
    {
        var owner=new TypeDefUser("Library","Owner",module.CorLibTypes.Object.TypeDefOrRef);module.Types.Add(owner);
        var method=new MethodDefUser("Method",MethodSig.CreateStatic(module.CorLibTypes.String,parameter),MethodAttributes.Private|MethodAttributes.Static){Body=new CilBody()};owner.Methods.Add(method);
        method.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());return method;
    }
}
