using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ByRefFieldRestorationTests
{
    [Theory]
    [InlineData("typed", 1)]
    [InlineData("null", 1)]
    [InlineData("read", 1)]
    [InlineData("generic-return", 1)]
    [InlineData("late", 1)]
    [InlineData("late-skipped", 0)]
    [InlineData("wrong-value", 0)]
    [InlineData("escape", 0)]
    [InlineData("branch", 0)]
    [InlineData("duplicate", 0)]
    [InlineData("named", 0)]
    [InlineData("handle", 0)]
    [InlineData("wrong-address-type", 0)]
    public void RestoresStorageOnlyWhenEveryAddressUseAndWriterIsClosed(string variant, int expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Storage");
            var field = new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Private | FieldAttributes.Static);
            owner.Fields.Add(field);
            var byref = new ByRefSig(variant == "wrong-address-type" ? module.CorLibTypes.Object : module.CorLibTypes.String);
            var writer = new MethodDefUser("Write", MethodSig.CreateStatic(module.CorLibTypes.Void, byref))
                { Attributes = MethodAttributes.Private | MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(writer);
            var body = writer.Body.Instructions;
            body.Add(OpCodes.Ldarg_0.ToInstruction());
            if (variant == "escape")
            {
                var local = new Local(byref); writer.Body.Variables.Add(local);
                body.Add(OpCodes.Stloc.ToInstruction(local)); body.Add(OpCodes.Ldloc.ToInstruction(local));
            }
            if (variant == "duplicate") { body.Add(OpCodes.Dup.ToInstruction()); body.Add(OpCodes.Pop.ToInstruction()); }
            var value = variant == "null" ? OpCodes.Ldnull.ToInstruction() :
                variant == "wrong-value" ? OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor",
                    MethodSig.CreateInstance(module.CorLibTypes.Void), module.CorLibTypes.Object.TypeDefOrRef)) : OpCodes.Ldstr.ToInstruction("updated");
            if (variant == "branch") body.Add(OpCodes.Br.ToInstruction(value));
            if (variant == "read") { body.Add(OpCodes.Ldind_Ref.ToInstruction()); body.Add(OpCodes.Pop.ToInstruction()); }
            else
            {
                body.Add(value);
                if (variant == "generic-return")
                {
                    var factory = SyntheticContext.AddType(module, "Factory`1");
                    factory.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
                    var identity = new MethodDefUser("Identity", MethodSig.CreateStatic(new GenericVar(0), new GenericVar(0)))
                        { Attributes = MethodAttributes.Public | MethodAttributes.Static, Body = new CilBody() };
                    factory.Methods.Add(identity);
                    identity.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction()); identity.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                    var instance = new TypeSpecUser(new GenericInstSig(new ClassSig(factory), module.CorLibTypes.String));
                    body.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, identity.Name, identity.MethodSig, instance)));
                }
                body.Add(OpCodes.Stind_Ref.ToInstruction());
            }
            body.Add(OpCodes.Ret.ToInstruction());
            var caller = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.String))
                { Attributes = MethodAttributes.Private | MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(caller);
            var il = caller.Body.Instructions;
            if (variant == "named") { il.Add(OpCodes.Ldstr.ToInstruction("Value")); il.Add(OpCodes.Pop.ToInstruction()); }
            if (variant == "handle") { il.Add(OpCodes.Ldtoken.ToInstruction(field)); il.Add(OpCodes.Pop.ToInstruction()); }
            il.Add(OpCodes.Ldstr.ToInstruction("initial")); il.Add(OpCodes.Stsfld.ToInstruction(field));
            il.Add(OpCodes.Ldsflda.ToInstruction(field)); il.Add(OpCodes.Call.ToInstruction(writer));
            il.Add(OpCodes.Ldsfld.ToInstruction(field)); il.Add(OpCodes.Ret.ToInstruction());
        });
        var late = variant.StartsWith("late", StringComparison.Ordinal);
        if (late) context.AddPassResult(new("type-restoration", variant == "late" ? Cilantro.Core.PassStatus.Success : Cilantro.Core.PassStatus.Unsupported, 0, [], TimeSpan.Zero));
        Assert.Equal(expected, late ? new TypeRecoveryCompletionPass().Run(context).Changes : new TypeRestorationPass().Run(context).Changes);
        Assert.Equal(0, late ? new TypeRecoveryCompletionPass().Run(context).Changes : new TypeRestorationPass().Run(context).Changes);
        if (expected == 0) return;
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
        try
        {
            context.Module.Write(path);
            var result = IlVerification.Read(path, []);
            Assert.Empty(result.Unreadable);
            Assert.Equal(0, result.Count);
        }
        finally { File.Delete(path); }
    }
}
