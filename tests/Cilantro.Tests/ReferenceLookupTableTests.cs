using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ReferenceLookupTableTests
{
    private const string Consumer="System.Boolean Newtonsoft.Json.Linq.JToken::ValidateToken(Newtonsoft.Json.Linq.JToken,Newtonsoft.Json.Linq.JTokenType[],System.Boolean)";
    [Theory]
    [InlineData("normal",true)]
    [InlineData("renamed",true)]
    [InlineData("mutable",false)]
    [InlineData("second-write",false)]
    [InlineData("address",false)]
    [InlineData("data-address",false)]
    [InlineData("unknown-consumer",false)]
    [InlineData("short-data",false)]
    [InlineData("skip-assignment",false)]
    [InlineData("alternate-entry",false)]
    public void RequiresClosedDataAndConsumers(string mode,bool expected)
    {
        using var module=new ModuleDefUser("Example.dll");new AssemblyDefUser("Example",new Version(1,0)).Modules.Add(module);
        var owner=new TypeDefUser("Example","Owner",module.CorLibTypes.Object.TypeDefOrRef);module.Types.Add(owner);
        var enumeration=new TypeDefUser("Example","Kind",new TypeRefUser(module,"System","Enum",module.CorLibTypes.AssemblyRef));module.Types.Add(enumeration);
        enumeration.Fields.Add(new FieldDefUser("value__",new FieldSig(module.CorLibTypes.Int32),FieldAttributes.Public|FieldAttributes.SpecialName|FieldAttributes.RTSpecialName));
        var array=new SZArraySig(new ValueTypeSig(enumeration));
        var field=new FieldDefUser(mode=="renamed"?"Renamed":"Table",new FieldSig(array),FieldAttributes.Private|FieldAttributes.Static|FieldAttributes.InitOnly);owner.Fields.Add(field);
        var data=new FieldDefUser("Data",new FieldSig(module.CorLibTypes.Int64),FieldAttributes.Private|FieldAttributes.Static|FieldAttributes.HasFieldRVA){InitialValue=[1,0,0,0,2,0,0,0]};owner.Fields.Add(data);
        var initialize=new MemberRefUser(module,"InitializeArray",MethodSig.CreateStatic(module.CorLibTypes.Void,new ClassSig(new TypeRefUser(module,"System","Array",module.CorLibTypes.AssemblyRef)),new ValueTypeSig(new TypeRefUser(module,"System","RuntimeFieldHandle",module.CorLibTypes.AssemblyRef))),new TypeRefUser(module,"System.Runtime.CompilerServices","RuntimeHelpers",module.CorLibTypes.AssemblyRef));
        var cctor=new MethodDefUser(".cctor",MethodSig.CreateStatic(module.CorLibTypes.Void),MethodAttributes.Private|MethodAttributes.Static|MethodAttributes.SpecialName|MethodAttributes.RTSpecialName){Body=new CilBody()};owner.Methods.Add(cctor);
        foreach(var instruction in new[]{OpCodes.Ldc_I4_2.ToInstruction(),OpCodes.Newarr.ToInstruction(enumeration),OpCodes.Dup.ToInstruction(),OpCodes.Ldtoken.ToInstruction(data),OpCodes.Call.ToInstruction(initialize),OpCodes.Stsfld.ToInstruction(field),OpCodes.Ret.ToInstruction()})cctor.Body.Instructions.Add(instruction);
        var consumer=new MethodDefUser("CertifiedConsumer",MethodSig.CreateStatic(module.CorLibTypes.Boolean,module.CorLibTypes.Object,array,module.CorLibTypes.Boolean),MethodAttributes.Private|MethodAttributes.Static);owner.Methods.Add(consumer);
        var caller=new MethodDefUser("Caller",MethodSig.CreateStatic(module.CorLibTypes.Boolean,module.CorLibTypes.Object),MethodAttributes.Private|MethodAttributes.Static){Body=new CilBody()};owner.Methods.Add(caller);
        foreach(var instruction in new[]{OpCodes.Ldarg_0.ToInstruction(),OpCodes.Ldsfld.ToInstruction(field),OpCodes.Ldc_I4_0.ToInstruction(),OpCodes.Call.ToInstruction(consumer),OpCodes.Ret.ToInstruction()})caller.Body.Instructions.Add(instruction);
        var aliases=new Dictionary<string,string>{{consumer.FullName,Consumer}};
        if(mode=="mutable")field.IsInitOnly=false;
        if(mode=="second-write"){cctor.Body.Instructions.Insert(6,OpCodes.Ldnull.ToInstruction());cctor.Body.Instructions.Insert(7,OpCodes.Stsfld.ToInstruction(field));}
        if(mode=="address")caller.Body.Instructions[1].OpCode=OpCodes.Ldsflda;
        if(mode=="data-address")caller.Body.Instructions.Insert(0,OpCodes.Ldsflda.ToInstruction(data));
        if(mode=="unknown-consumer")aliases.Clear();
        if(mode=="short-data")data.InitialValue=[1,0,0,0];
        if(mode=="skip-assignment")cctor.Body.Instructions.Insert(0,OpCodes.Br.ToInstruction(cctor.Body.Instructions[^1]));
        if(mode=="alternate-entry")cctor.Body.Instructions.Insert(0,OpCodes.Br.ToInstruction(cctor.Body.Instructions[3]));
        Assert.Equal(expected,ReferenceLookupTable.Identify(field,aliases) is not null);
        if(expected){var original=ReferenceLookupTable.Identify(field,aliases);data.InitialValue[0]=3;Assert.NotEqual(original,ReferenceLookupTable.Identify(field,aliases));}
    }
}
