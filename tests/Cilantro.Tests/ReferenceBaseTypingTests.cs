using Cilantro.Core;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;
public sealed class ReferenceBaseTypingTests
{
    [Fact]
    public void ImportsAncestorsResolvedFromAnotherAssembly()
    {
        using var library=new ModuleDefUser("External.dll");
        var assembly=new AssemblyDefUser("External",new Version(1,0));assembly.Modules.Add(library);
        var parent=SyntheticContext.AddType(library,"Parent");parent.Attributes=TypeAttributes.Public;
        var a=SyntheticContext.AddType(library,"A");a.Attributes=TypeAttributes.Public;a.BaseType=parent;
        var b=SyntheticContext.AddType(library,"B");b.Attributes=TypeAttributes.Public;b.BaseType=parent;
        var field=new FieldDefUser("Number",new FieldSig(library.CorLibTypes.Int32),FieldAttributes.Public);parent.Fields.Add(field);
        using var context=SyntheticContext.Build(module=>
        {
            var importer=new Importer(module);var owner=SyntheticContext.AddType(module,"Consumer");
            var use=new MethodDefUser("Use",MethodSig.CreateStatic(module.CorLibTypes.Void,module.CorLibTypes.Object))
            {Attributes=MethodAttributes.Static|MethodAttributes.Private,Body=new CilBody()};owner.Methods.Add(use);
            use.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());use.Body.Instructions.Add(OpCodes.Ldfld.ToInstruction(importer.Import(field)));use.Body.Instructions.Add(OpCodes.Pop.ToInstruction());use.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            foreach(var source in new[]{a,b})
            {
                var caller=new MethodDefUser(source.Name,MethodSig.CreateStatic(module.CorLibTypes.Void,importer.Import(source).ToTypeSig()))
                {Attributes=MethodAttributes.Static|MethodAttributes.Private,Body=new CilBody()};owner.Methods.Add(caller);
                caller.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(use));caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            }
        });
        ((AssemblyResolver)context.Module.Context.AssemblyResolver).AddToCache(assembly);
        Assert.Equal(1,new ReferenceParameterTypingPass().Run(context).Changes);
        var cast=context.Module.GetTypes().SelectMany(t=>t.Methods).Where(m=>m.HasBody).SelectMany(m=>m.Body.Instructions).Single(i=>i.OpCode.Code==Code.Castclass);
        var imported=Assert.IsAssignableFrom<TypeRef>(cast.Operand);
        Assert.Same(context.Module,imported.Module);Assert.Equal("External",imported.DefinitionAssembly.Name.String);
        using var output=new MemoryStream();context.Module.Write(output);Assert.True(output.Length>0);
    }

    [Theory]
    [InlineData("base-derived",true)]
    [InlineData("siblings",true)]
    [InlineData("unrelated",false)]
    [InlineData("unknown",false)]
    public void InfersOnlyAProvenNonObjectCommonBase(string scenario,bool expected)
    {
        using var context=SyntheticContext.Build(module=>
        {
            var parent=SyntheticContext.AddType(module,"Parent");
            var a=SyntheticContext.AddType(module,"A");a.BaseType=parent;
            var b=SyntheticContext.AddType(module,"B");if(scenario!="unrelated")b.BaseType=parent;
            var field=new FieldDefUser("Number",new FieldSig(module.CorLibTypes.Int32),FieldAttributes.Public);parent.Fields.Add(field);
            var owner=SyntheticContext.AddType(module,"Consumer");
            var target=new MethodDefUser("Use",MethodSig.CreateStatic(module.CorLibTypes.Void,module.CorLibTypes.Object))
            {Attributes=MethodAttributes.Static|MethodAttributes.Private,Body=new CilBody()};owner.Methods.Add(target);
            target.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());target.Body.Instructions.Add(OpCodes.Ldfld.ToInstruction(field));target.Body.Instructions.Add(OpCodes.Pop.ToInstruction());target.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            foreach(var (name,type) in new[]{("First",scenario=="base-derived"?parent.ToTypeSig():a.ToTypeSig()),("Second",scenario=="unknown"?module.CorLibTypes.Object:b.ToTypeSig())})
            {
                var caller=new MethodDefUser(name,MethodSig.CreateStatic(module.CorLibTypes.Void,type))
                {Attributes=MethodAttributes.Static|MethodAttributes.Private,Body=new CilBody()};owner.Methods.Add(caller);
                caller.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(target));caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            }
        });
        var path=Path.Combine(Path.GetTempPath(),Guid.NewGuid()+".dll");
        try
        {
            context.Module.Write(path);Assert.Equal(1,IlVerification.Read(path,[]).Count);
            var result=new ReferenceParameterTypingPass().Run(context);Assert.Equal(PassStatus.Success,result.Status);Assert.Equal(expected?1:0,result.Changes);
            Assert.Equal(0,new ReferenceParameterTypingPass().Run(context).Changes);
            if(expected)Assert.Equal("Synthetic.Parent",context.Module.GetTypes().SelectMany(t=>t.Methods).Single(m=>m.Name=="Use").Body.Instructions.Single(i=>i.OpCode.Code==Code.Castclass).Operand.ToString());
            context.Module.Write(path);Assert.Equal(expected?0:1,IlVerification.Read(path,[]).Count);
        }
        finally{File.Delete(path);}
    }
}
