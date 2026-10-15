using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class JsonReceiverFlowTests
{
    [Theory]
    [InlineData("closed", true)]
    [InlineData("alias", true)]
    [InlineData("enumerate", true)]
    [InlineData("unknown-dictionary", false)]
    [InlineData("dictionary-write", false)]
    [InlineData("element-write", false)]
    [InlineData("escape", false)]
    [InlineData("address", false)]
    [InlineData("replace", false)]
    [InlineData("field-store", false)]
    public void OnlyClosedGraphReceiversQualify(string mode, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Application");
            var method = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object), MethodImplAttributes.IL,
                MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody { InitLocals = true } }; owner.Methods.Add(method);
            void Emit(params Instruction[] instructions) { foreach (var i in instructions) method.Body.Instructions.Add(i); }
            var web = new AssemblyRefUser("System.Web.Extensions", new Version(4, 0), new PublicKeyToken("31bf3856ad364e35"));
            var serializer = new TypeRefUser(module, "System.Web.Script.Serialization", "JavaScriptSerializer", web);
            var instance = new Local(serializer.ToTypeSig()); var graph = new Local(module.CorLibTypes.Object); var alias = new Local(module.CorLibTypes.Object);
            method.Body.Variables.Add(instance); method.Body.Variables.Add(graph); method.Body.Variables.Add(alias);
            Emit(OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), serializer)),
                OpCodes.Stloc.ToInstruction(instance), OpCodes.Ldloc.ToInstruction(instance), OpCodes.Ldstr.ToInstruction("{}"),
                OpCodes.Callvirt.ToInstruction(new MethodSpecUser(new MemberRefUser(module, "Deserialize", MethodSig.CreateInstanceGeneric(1, new GenericMVar(0), module.CorLibTypes.String), serializer), new GenericInstMethodSig(module.CorLibTypes.Object))), OpCodes.Stloc.ToInstruction(graph));
            if (mode == "replace") Emit(OpCodes.Ldarg_0.ToInstruction(), OpCodes.Stloc.ToInstruction(graph));
            if (mode == "address") Emit(OpCodes.Ldloca.ToInstruction(graph), OpCodes.Pop.ToInstruction());
            if (mode == "escape")
            {
                var escape = new MethodDefUser("Consume", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object), MethodImplAttributes.IL,
                    MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() }; owner.Methods.Add(escape); escape.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                Emit(OpCodes.Ldloc.ToInstruction(graph), OpCodes.Call.ToInstruction(escape));
            }
            if (mode == "field-store")
            {
                var storage = new FieldDefUser("saved", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Private | FieldAttributes.Static); owner.Fields.Add(storage);
                Emit(OpCodes.Ldloc.ToInstruction(graph), OpCodes.Stsfld.ToInstruction(storage));
            }
            if (mode == "alias") Emit(OpCodes.Ldloc.ToInstruction(graph), OpCodes.Stloc.ToInstruction(alias));
            if (mode == "enumerate")
            {
                var enumerableType = module.CorLibTypes.GetTypeRef("System.Collections", "IEnumerable");
                var enumeratorType = module.CorLibTypes.GetTypeRef("System.Collections", "IEnumerator");
                Emit(OpCodes.Ldloc.ToInstruction(graph), OpCodes.Castclass.ToInstruction(enumerableType),
                    OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetEnumerator", MethodSig.CreateInstance(enumeratorType.ToTypeSig()), enumerableType)),
                    OpCodes.Castclass.ToInstruction(enumeratorType), OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "MoveNext", MethodSig.CreateInstance(module.CorLibTypes.Boolean), enumeratorType)), OpCodes.Pop.ToInstruction());
            }
            if (mode == "element-write")
                Emit(OpCodes.Ldloc.ToInstruction(graph), OpCodes.Castclass.ToInstruction(new SZArraySig(module.CorLibTypes.Object).ToTypeDefOrRef()),
                    OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldarg_0.ToInstruction(), OpCodes.Stelem_Ref.ToInstruction());
            if (mode == "dictionary-write")
            {
                var dictionary = new GenericInstSig(new ClassSig(module.CorLibTypes.GetTypeRef("System.Collections.Generic", "Dictionary`2")), module.CorLibTypes.String, module.CorLibTypes.Object).ToTypeDefOrRef();
                Emit(OpCodes.Ldloc.ToInstruction(graph), OpCodes.Castclass.ToInstruction(dictionary), OpCodes.Ldstr.ToInstruction("key"), OpCodes.Ldarg_0.ToInstruction(),
                    OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "TryAdd", MethodSig.CreateInstance(module.CorLibTypes.Boolean, new GenericVar(0), new GenericVar(1)), dictionary)), OpCodes.Pop.ToInstruction());
            }
            if (mode == "unknown-dictionary")
            {
                var dictionary = new GenericInstSig(new ClassSig(module.CorLibTypes.GetTypeRef("System.Collections.Generic", "Dictionary`2")), module.CorLibTypes.String, module.CorLibTypes.Object).ToTypeDefOrRef();
                Emit(OpCodes.Ldarg_0.ToInstruction(), OpCodes.Castclass.ToInstruction(dictionary), OpCodes.Ldloc.ToInstruction(graph),
                    OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "ContainsValue", MethodSig.CreateInstance(module.CorLibTypes.Boolean, new GenericVar(1)), dictionary)), OpCodes.Pop.ToInstruction());
            }
            var core = new AssemblyRefUser("System.Core", new Version(4, 0), new PublicKeyToken("b77a5c561934e089"));
            var sharp = new AssemblyRefUser("Microsoft.CSharp", new Version(4, 0), new PublicKeyToken("b03f5f7f11d50a3a"));
            TypeRef Sharp(string name) => new TypeRefUser(module, "Microsoft.CSharp.RuntimeBinder", name, sharp);
            var type = module.CorLibTypes.GetTypeRef("System", "Type").ToTypeSig();
            var baseSite = new TypeRefUser(module, "System.Runtime.CompilerServices", "CallSite", core).ToTypeSig();
            var binderType = new TypeRefUser(module, "System.Runtime.CompilerServices", "CallSiteBinder", core).ToTypeSig();
            var delegateType = new GenericInstSig(new ClassSig(module.CorLibTypes.GetTypeRef("System", "Func`3")), baseSite, module.CorLibTypes.Object, module.CorLibTypes.Object);
            var siteType = new GenericInstSig(new ClassSig(new TypeRefUser(module, "System.Runtime.CompilerServices", "CallSite`1", core)), delegateType);
            var field = new FieldDefUser("site", new FieldSig(siteType), FieldAttributes.Private | FieldAttributes.Static); owner.Fields.Add(field);
            var info = Sharp("CSharpArgumentInfo"); var enumerable = new ClassSig(module.CorLibTypes.GetTypeRef("System.Collections.Generic", "IEnumerable`1"));
            Emit(OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldstr.ToInstruction("GetType"), OpCodes.Ldnull.ToInstruction(), OpCodes.Ldtoken.ToInstruction(owner),
                OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetTypeFromHandle", MethodSig.CreateStatic(type, new ValueTypeSig(module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle"))), type.ToTypeDefOrRef())),
                OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Newarr.ToInstruction(info), OpCodes.Dup.ToInstruction(), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldnull.ToInstruction(),
                OpCodes.Call.ToInstruction(new MemberRefUser(module, "Create", MethodSig.CreateStatic(info.ToTypeSig(), new ValueTypeSig(Sharp("CSharpArgumentInfoFlags")), module.CorLibTypes.String), info)), OpCodes.Stelem_Ref.ToInstruction(),
                OpCodes.Call.ToInstruction(new MemberRefUser(module, "InvokeMember", MethodSig.CreateStatic(binderType, new ValueTypeSig(Sharp("CSharpBinderFlags")), module.CorLibTypes.String,
                    new GenericInstSig(enumerable, type), type, new GenericInstSig(enumerable, info.ToTypeSig())), Sharp("Binder"))),
                OpCodes.Call.ToInstruction(new MemberRefUser(module, "Create", MethodSig.CreateStatic(siteType, binderType), siteType.ToTypeDefOrRef())), OpCodes.Stsfld.ToInstruction(field),
                OpCodes.Ldsfld.ToInstruction(field), OpCodes.Ldfld.ToInstruction(new MemberRefUser(module, "Target", new FieldSig(new GenericVar(0)), siteType.ToTypeDefOrRef())),
                OpCodes.Ldsfld.ToInstruction(field), OpCodes.Ldloc.ToInstruction(mode == "alias" ? alias : graph),
                OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "Invoke", MethodSig.CreateInstance(new GenericVar(2), new GenericVar(0), new GenericVar(1)), delegateType.ToTypeDefOrRef())), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Read");
        var result = JsonReceiverFlow.Analyze(context.Module, method, new HashSet<TypeDef>());
        Assert.Equal(expected, result.Closed);
        if(expected) Assert.Single(result.MemberBinders);
    }
}
