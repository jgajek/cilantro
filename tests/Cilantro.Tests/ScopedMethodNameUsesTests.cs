using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ScopedMethodNameUsesTests
{
    [Theory]
    [InlineData("compare", true)]
    [InlineData("local", true)]
    [InlineData("field", true)]
    [InlineData("other-lookup", true)]
    [InlineData("same-lookup", false)]
    [InlineData("derived-lookup", false)]
    [InlineData("return", false)]
    [InlineData("full-name-return", false)]
    [InlineData("discard", false)]
    [InlineData("unknown-call", false)]
    [InlineData("address", false)]
    [InlineData("field-address", false)]
    [InlineData("named-field", false)]
    [InlineData("exposed", false)]
    public void EveryForwardedNameUseMustBeClosed(string mode, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Owner");
            var other = SyntheticContext.AddType(module, "Other");
            if (mode == "derived-lookup") other.BaseType = owner;
            var candidate = new MethodDefUser("Target", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL,
                MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() }; owner.Methods.Add(candidate);
            candidate.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var storage = new FieldDefUser("Name", new FieldSig(module.CorLibTypes.String), FieldAttributes.Private | FieldAttributes.Static); other.Fields.Add(storage);
            var helper = new MethodDefUser("Use", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.String), MethodImplAttributes.IL,
                MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() }; other.Methods.Add(helper);
            var il = helper.Body.Instructions;
            var runtimeType = module.CorLibTypes.GetTypeRef("System", "Type");
            if (mode.Contains("lookup"))
            {
                il.Add(OpCodes.Ldtoken.ToInstruction(mode == "same-lookup" ? owner : other));
                il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetTypeFromHandle", MethodSig.CreateStatic(runtimeType.ToTypeSig(), module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle").ToTypeSig()), runtimeType)));
                il.Add(OpCodes.Ldarg_0.ToInstruction());
                il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetMethod", MethodSig.CreateInstance(module.CorLibTypes.GetTypeRef("System.Reflection", "MethodInfo").ToTypeSig(), module.CorLibTypes.String), runtimeType)));
                il.Add(OpCodes.Pop.ToInstruction());
            }
            else
            {
                il.Add(OpCodes.Ldarg_0.ToInstruction());
                if (mode is "return" or "full-name-return") { helper.MethodSig.RetType = module.CorLibTypes.String; il.Add(OpCodes.Ret.ToInstruction()); }
                else if (mode == "discard") il.Add(OpCodes.Pop.ToInstruction());
                else if (mode == "unknown-call") il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "WriteLine", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.String), module.CorLibTypes.GetTypeRef("System", "Console"))));
                else
                {
                    if (mode is "field" or "field-address" or "named-field" or "exposed")
                    {
                        il.Add(OpCodes.Stsfld.ToInstruction(storage));
                        if (mode == "field-address") { il.Add(OpCodes.Ldsflda.ToInstruction(storage)); il.Add(OpCodes.Pop.ToInstruction()); }
                        if (mode == "named-field") { il.Add(OpCodes.Ldstr.ToInstruction("Name")); il.Add(OpCodes.Pop.ToInstruction()); }
                        il.Add(OpCodes.Ldsfld.ToInstruction(storage));
                    }
                    if (mode is "local" or "address")
                    {
                        var local = new Local(module.CorLibTypes.String); helper.Body.Variables.Add(local);
                        il.Add(OpCodes.Stloc.ToInstruction(local));
                        if (mode == "address") { il.Add(OpCodes.Ldloca.ToInstruction(local)); il.Add(OpCodes.Pop.ToInstruction()); }
                        il.Add(OpCodes.Ldloc.ToInstruction(local));
                    }
                    il.Add(OpCodes.Ldstr.ToInstruction("ignored"));
                    il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "op_Equality", MethodSig.CreateStatic(module.CorLibTypes.Boolean, module.CorLibTypes.String, module.CorLibTypes.String), module.CorLibTypes.String.TypeDefOrRef)));
                    il.Add(OpCodes.Pop.ToInstruction());
                }
            }
            if (mode is not ("return" or "full-name-return")) il.Add(OpCodes.Ret.ToInstruction());
            var source = new MethodDefUser("Source", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL,
                MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() }; owner.Methods.Add(source);
            source.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction(mode == "full-name-return" ? candidate.FullName : "Target"));
            source.Body.Instructions.Add(OpCodes.Call.ToInstruction(helper));
            if (mode is "return" or "full-name-return") source.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            source.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var methods = context.Module.GetTypes().SelectMany(t => t.Methods).ToArray();
        var source = methods.Single(m => m.Name == "Source");
        var exposed = mode == "exposed" ? new HashSet<TypeDef> { methods.Single(m => m.Name == "Use").DeclaringType } : [];
        var proof = new ScopedMethodNameUses(context.Module, exposed);
        Assert.Equal(expected, proof.Excludes(methods.Single(m => m.Name == "Target"), source, source.Body.Instructions[0], out _));
        Assert.Equal(expected, proof.ExcludesAll(methods.Single(m => m.Name == "Target")));
        Assert.Equal(expected, proof.ExcludesAll(methods.Single(m => m.Name == "Target")));
    }
}
