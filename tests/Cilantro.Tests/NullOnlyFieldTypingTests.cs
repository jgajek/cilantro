using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class NullOnlyFieldTypingTests
{
    [Theory]
    [InlineData("unwritten", true)]
    [InlineData("null", true)]
    [InlineData("unknown", false)]
    [InlineData("address", false)]
    [InlineData("named", false)]
    [InlineData("friend", false)]
    [InlineData("reflection", false)]
    [InlineData("emit", false)]
    public void ConsumerTypingRequiresProofThatAFieldCanOnlyContainNull(string shape, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "NullOnly");
            var field = new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Object), (shape == "friend" ? FieldAttributes.Assembly : FieldAttributes.Private) | FieldAttributes.Static);
            owner.Fields.Add(field);
            if (shape == "friend") module.Assembly.CustomAttributes.Add(new CustomAttribute(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String), module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "InternalsVisibleToAttribute")),
                [new CAArgument(module.CorLibTypes.String, new UTF8String("Friend"))]));
            var run = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.Object), MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(run);
            var il = run.Body.Instructions;
            if (shape == "reflection")
            {
                il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Ldnull.ToInstruction());
                il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "SetValue", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.Object), module.CorLibTypes.GetTypeRef("System.Reflection", "FieldInfo"))));
            }
            if (shape == "emit")
            {
                il.Add(OpCodes.Ldnull.ToInstruction());
                il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetILGenerator", MethodSig.CreateInstance(module.CorLibTypes.GetTypeRef("System.Reflection.Emit", "ILGenerator").ToTypeSig()), module.CorLibTypes.GetTypeRef("System.Reflection.Emit", "DynamicMethod"))));
                il.Add(OpCodes.Pop.ToInstruction());
            }
            if (shape is "null" or "unknown") { il.Add((shape == "null" ? OpCodes.Ldnull : OpCodes.Ldarg_0).ToInstruction()); il.Add(OpCodes.Stsfld.ToInstruction(field)); }
            if (shape == "address") { il.Add(OpCodes.Ldsflda.ToInstruction(field)); il.Add(OpCodes.Pop.ToInstruction()); }
            if (shape == "named") { il.Add(OpCodes.Ldstr.ToInstruction("Value")); il.Add(OpCodes.Pop.ToInstruction()); }
            il.Add(OpCodes.Ldsfld.ToInstruction(field)); il.Add(OpCodes.Ldstr.ToInstruction("suffix"));
            il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "Concat", MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.String, module.CorLibTypes.String), module.CorLibTypes.String.TypeDefOrRef)));
            il.Add(OpCodes.Ret.ToInstruction());
        });
        var pass = new ReferenceFieldTypingPass();
        Assert.Equal(expected ? 1 : 0, pass.Run(context).Changes);
        Assert.Equal(0, pass.Run(context).Changes);
        if (expected)
        {
            var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
            try { context.Module.Write(path); Assert.Equal(0, IlVerification.Read(path, []).Count); }
            finally { File.Delete(path); }
        }
    }

    [Fact]
    public void TypedStaticFieldStoresSelectReferenceParameterConsumers()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Setter");
            var field = new FieldDefUser("Value", new FieldSig(module.CorLibTypes.String), FieldAttributes.Private | FieldAttributes.Static); owner.Fields.Add(field);
            var setter = new MethodDefUser("Set", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object), MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() }; owner.Methods.Add(setter);
            setter.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction()); setter.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(field)); setter.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() }; owner.Methods.Add(run);
            run.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("value")); run.Body.Instructions.Add(OpCodes.Call.ToInstruction(setter)); run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var pass = new ReferenceParameterTypingPass();
        Assert.Equal(1, pass.Run(context).Changes);
        Assert.Equal(0, pass.Run(context).Changes);
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
        try { context.Module.Write(path); Assert.Equal(0, IlVerification.Read(path, []).Count); }
        finally { File.Delete(path); }
    }
}
