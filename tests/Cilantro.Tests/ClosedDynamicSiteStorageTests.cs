using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ClosedDynamicSiteStorageTests
{
    [Theory]
    [InlineData("closed", true)]
    [InlineData("branch", true)]
    [InlineData("site-escape", false)]
    [InlineData("target-write", false)]
    [InlineData("second-store", false)]
    [InlineData("named", false)]
    [InlineData("exposed", false)]
    [InlineData("public", false)]
    [InlineData("foreign", false)]
    [InlineData("delegate-escape", false)]
    public void OnlyClosedStoredSitesAreReported(string mode, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Application"); owner.Attributes = TypeAttributes.Public;
            var method = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL,
                MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody { KeepOldMaxStack = true, MaxStack = 8 } }; owner.Methods.Add(method);
            var core = new AssemblyRefUser("System.Core", new Version(4, 0), new PublicKeyToken(mode == "foreign" ? "0000000000000000" : "b77a5c561934e089"));
            var csharp = new AssemblyRefUser("Microsoft.CSharp", new Version(4, 0), new PublicKeyToken("b03f5f7f11d50a3a"));
            TypeRef Type(string name) => new TypeRefUser(module, "System.Runtime.CompilerServices", name, core);
            var baseSite = Type("CallSite").ToTypeSig(); var binderType = Type("CallSiteBinder").ToTypeSig();
            var delegateType = new GenericInstSig(new ClassSig(module.CorLibTypes.GetTypeRef("System", "Func`3")), baseSite, module.CorLibTypes.Object, module.CorLibTypes.Object);
            var siteType = new GenericInstSig(new ClassSig(Type("CallSite`1")), delegateType);
            var field = new FieldDefUser("site", new FieldSig(siteType), FieldAttributes.Static | (mode == "public" ? FieldAttributes.Public : FieldAttributes.Private)); owner.Fields.Add(field);
            var target = new MemberRefUser(module, "Target", new FieldSig(new GenericVar(0)), siteType.ToTypeDefOrRef());
            var invoke = new MemberRefUser(module, "Invoke", MethodSig.CreateInstance(new GenericVar(2), new GenericVar(0), new GenericVar(1)), delegateType.ToTypeDefOrRef());
            var binder = new TypeRefUser(module, "Microsoft.CSharp.RuntimeBinder", "Binder", csharp);
            var flags = new ValueTypeSig(new TypeRefUser(module, "Microsoft.CSharp.RuntimeBinder", "CSharpBinderFlags", csharp));
            var runtimeType = module.CorLibTypes.GetTypeRef("System", "Type").ToTypeSig();
            void Emit(params Instruction[] instructions) { foreach(var instruction in instructions) method.Body.Instructions.Add(instruction); }
            Emit(OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldnull.ToInstruction(), OpCodes.Ldnull.ToInstruction(),
                OpCodes.Call.ToInstruction(new MemberRefUser(module, "Convert", MethodSig.CreateStatic(binderType, flags, runtimeType, runtimeType), binder)),
                OpCodes.Call.ToInstruction(new MemberRefUser(module, "Create", MethodSig.CreateStatic(siteType, binderType), siteType.ToTypeDefOrRef())), OpCodes.Stsfld.ToInstruction(field));
            if(mode == "second-store") Emit(OpCodes.Ldnull.ToInstruction(), OpCodes.Stsfld.ToInstruction(field));
            if(mode == "site-escape") Emit(OpCodes.Ldsfld.ToInstruction(field), OpCodes.Pop.ToInstruction());
            if(mode == "target-write") Emit(OpCodes.Ldsfld.ToInstruction(field), OpCodes.Ldnull.ToInstruction(), OpCodes.Stfld.ToInstruction(target));
            if(mode == "named") Emit(OpCodes.Ldstr.ToInstruction("site"), OpCodes.Pop.ToInstruction());
            Emit(OpCodes.Ldsfld.ToInstruction(field), OpCodes.Ldfld.ToInstruction(target));
            if(mode == "delegate-escape") Emit(OpCodes.Dup.ToInstruction(), OpCodes.Pop.ToInstruction());
            var siteLoad = OpCodes.Ldsfld.ToInstruction(field);
            if(mode == "branch") Emit(OpCodes.Br.ToInstruction(siteLoad));
            Emit(siteLoad, OpCodes.Ldnull.ToInstruction(), OpCodes.Callvirt.ToInstruction(invoke), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Read");
        var exposed = new HashSet<TypeDef>(); if(mode == "exposed") exposed.Add(method.DeclaringType);
        Assert.Equal(expected ? 1 : 0, ClosedDynamicSiteStorage.Find(context.Module, method, exposed).Count);
    }
}
