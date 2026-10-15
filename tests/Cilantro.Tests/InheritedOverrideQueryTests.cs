using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;
public sealed class InheritedOverrideQueryTests
{
    [Theory]
    [InlineData("none", true)]
    [InlineData("type", true)]
    [InlineData("object", false)]
    [InlineData("string", false)]
    [InlineData("unknown-input", false)]
    [InlineData("wrong-flags", false)]
    public void OptionalReceiverCastMustBeRedundant(string mode, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var closure = SyntheticContext.AddType(module, "Closure");
            var type = module.CorLibTypes.GetTypeRef("System", "Type");
            var methodInfo = module.CorLibTypes.GetTypeRef("System.Reflection", "MethodInfo");
            var memberInfo = module.CorLibTypes.GetTypeRef("System.Reflection", "MemberInfo");
            var name = new FieldDefUser("Name", new FieldSig(module.CorLibTypes.String), FieldAttributes.Public);
            var parent = new FieldDefUser("Parent", new FieldSig(type.ToTypeSig()), FieldAttributes.Public);
            closure.Fields.Add(name); closure.Fields.Add(parent);
            var ctor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), MethodImplAttributes.IL,
                MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() };
            closure.Methods.Add(ctor);
            ctor.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            ctor.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), module.CorLibTypes.Object.TypeDefOrRef)));
            ctor.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var predicate = new MethodDefUser("Matches", MethodSig.CreateInstance(module.CorLibTypes.Boolean, methodInfo.ToTypeSig()), MethodImplAttributes.IL, MethodAttributes.Public) { Body = new CilBody() };
            closure.Methods.Add(predicate);
            var no = OpCodes.Ldc_I4_0.ToInstruction();
            var pi = predicate.Body.Instructions;
            pi.Add(OpCodes.Ldarg_1.ToInstruction());
            pi.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_Name", MethodSig.CreateInstance(module.CorLibTypes.String), memberInfo)));
            pi.Add(OpCodes.Ldarg_0.ToInstruction()); pi.Add(OpCodes.Ldfld.ToInstruction(name));
            pi.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "op_Equality", MethodSig.CreateStatic(module.CorLibTypes.Boolean, module.CorLibTypes.String, module.CorLibTypes.String), module.CorLibTypes.String.TypeDefOrRef)));
            pi.Add(OpCodes.Brfalse.ToInstruction(no)); pi.Add(OpCodes.Ldarg_1.ToInstruction());
            pi.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_DeclaringType", MethodSig.CreateInstance(type.ToTypeSig()), memberInfo)));
            pi.Add(OpCodes.Ldarg_0.ToInstruction()); pi.Add(OpCodes.Ldfld.ToInstruction(parent));
            pi.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "op_Inequality", MethodSig.CreateStatic(module.CorLibTypes.Boolean, type.ToTypeSig(), type.ToTypeSig()), type)));
            pi.Add(OpCodes.Ret.ToInstruction()); pi.Add(no); pi.Add(OpCodes.Ret.ToInstruction());
            var queryOwner = SyntheticContext.AddType(module, "Queries");
            var query = new MethodDefUser("Query", MethodSig.CreateStatic(module.CorLibTypes.Boolean,
                mode == "unknown-input" ? module.CorLibTypes.Object : type.ToTypeSig(), type.ToTypeSig(), module.CorLibTypes.String),
                MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
            queryOwner.Methods.Add(query);
            var local = new Local(closure.ToTypeSig()); query.Body.Variables.Add(local);
            var il = query.Body.Instructions;
            il.Add(OpCodes.Newobj.ToInstruction(ctor)); il.Add(OpCodes.Stloc.ToInstruction(local));
            il.Add(OpCodes.Ldloc.ToInstruction(local)); il.Add(OpCodes.Ldarg_2.ToInstruction()); il.Add(OpCodes.Stfld.ToInstruction(name));
            il.Add(OpCodes.Ldloc.ToInstruction(local)); il.Add(OpCodes.Ldarg_1.ToInstruction()); il.Add(OpCodes.Stfld.ToInstruction(parent));
            il.Add(OpCodes.Ldarg_0.ToInstruction());
            if (mode is "type" or "object" or "string") il.Add(OpCodes.Castclass.ToInstruction(mode == "type" ? type : mode == "object" ? module.CorLibTypes.Object.TypeDefOrRef : module.CorLibTypes.String.TypeDefOrRef));
            il.Add(OpCodes.Ldc_I4.ToInstruction(mode == "wrong-flags" ? 20 : 52));
            il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetMethods", MethodSig.CreateInstance(new SZArraySig(methodInfo.ToTypeSig()), module.CorLibTypes.GetTypeRef("System.Reflection", "BindingFlags").ToTypeSig()), type)));
            il.Add(OpCodes.Ldloc.ToInstruction(local)); il.Add(OpCodes.Ldftn.ToInstruction(predicate));
            var func = module.CorLibTypes.GetTypeRef("System", "Func`2");
            var concreteFunc = new GenericInstSig(new ClassSig(func), methodInfo.ToTypeSig(), module.CorLibTypes.Boolean);
            il.Add(OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr), new TypeSpecUser(concreteFunc))));
            var enumerable = new GenericInstSig(new ClassSig(module.CorLibTypes.GetTypeRef("System.Collections.Generic", "IEnumerable`1")), new GenericMVar(0));
            var genericFunc = new GenericInstSig(new ClassSig(func), new GenericMVar(0), module.CorLibTypes.Boolean);
            var linq = new TypeRefUser(module, "System.Linq", "Enumerable", new AssemblyRefUser(new AssemblyNameInfo("System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089")));
            var any = new MemberRefUser(module, "Any", MethodSig.CreateStaticGeneric(1, module.CorLibTypes.Boolean, enumerable, genericFunc), linq);
            il.Add(OpCodes.Call.ToInstruction(new MethodSpecUser(any, new GenericInstMethodSig(methodInfo.ToTypeSig()))));
            il.Add(OpCodes.Ret.ToInstruction());
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Query");
        var before = method.Body.Instructions.ToArray();
        Assert.Equal(expected, InheritedOverrideQuery.IsClosed(method));
        Assert.Equal(before, method.Body.Instructions.ToArray());
    }
}
