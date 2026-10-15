using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;
public sealed class ReadonlyConstructorValuesTests
{
    [Theory]
    [InlineData("direct", true)]
    [InlineData("generic", true)]
    [InlineData("unknown", false)]
    [InlineData("bypass", false)]
    [InlineData("rebind-this", false)]
    [InlineData("address", false)]
    [InlineData("mutable", false)]
    [InlineData("named", false)]
    [InlineData("uninitialized", false)]
    public void RequiresClosedDirectConstruction(string mode, bool expected)
    {
        FieldDef field = null!;
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Owner");
            var payload = SyntheticContext.AddType(module, "Payload");
            if (mode == "generic") owner.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            TypeSig storedType = mode == "generic" ? new GenericVar(0, owner) : payload.ToTypeSig();
            field = new FieldDefUser("storage", new FieldSig(storedType),
                FieldAttributes.Private | (mode == "mutable" ? 0 : FieldAttributes.InitOnly)); owner.Fields.Add(field);
            MethodDef Constructor(TypeDef type, params TypeSig[] args)
            {
                var m = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, args),
                    MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
                    { Body = new CilBody() }; type.Methods.Add(m); return m;
            }
            var allocation = Constructor(payload); allocation.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var ctor = Constructor(owner, storedType); var il = ctor.Body.Instructions;
            il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Ldarg_1.ToInstruction());
            il.Add(OpCodes.Stfld.ToInstruction(field)); il.Add(OpCodes.Ret.ToInstruction());
            if (mode == "rebind-this")
            {
                il.Insert(0, OpCodes.Ldnull.ToInstruction());
                il.Insert(1, OpCodes.Starg.ToInstruction(ctor.Parameters[0]));
            }
            if (mode == "bypass") il.Insert(0, OpCodes.Br.ToInstruction(il[^1]));
            if (mode == "uninitialized") Constructor(owner).Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var caller = new MethodDefUser("Build", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL,
                MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() }; owner.Methods.Add(caller);
            var body = caller.Body.Instructions;
            body.Add(mode == "unknown" ? OpCodes.Ldnull.ToInstruction() : OpCodes.Newobj.ToInstruction(allocation));
            IMethod constructed = mode == "generic" ? new MemberRefUser(module, ".ctor", ctor.MethodSig.Clone(),
                new TypeSpecUser(new GenericInstSig(new ClassSig(owner), payload.ToTypeSig()))) : ctor;
            body.Add(OpCodes.Newobj.ToInstruction(constructed));
            if (mode == "address") body.Add(OpCodes.Ldflda.ToInstruction(field));
            body.Add(OpCodes.Pop.ToInstruction());
            if (mode == "named") { body.Add(OpCodes.Ldstr.ToInstruction("storage")); body.Add(OpCodes.Pop.ToInstruction()); }
            body.Add(OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(expected, ReadonlyConstructorValues.Analyze(context.Module.GetTypes().SelectMany(t => t.Fields).Single(f => f.Name == "storage")).Proven);
    }
}
