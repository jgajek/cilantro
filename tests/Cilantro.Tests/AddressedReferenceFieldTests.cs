using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class AddressedReferenceFieldTests
{
    [Theory]
    [InlineData(true, "closed", true)]
    [InlineData(false, "closed", true)]
    [InlineData(true, "unknown", false)]
    [InlineData(false, "unknown", false)]
    [InlineData(true, "conflict", false)]
    [InlineData(false, "conflict", false)]
    [InlineData(true, "escape", false)]
    [InlineData(false, "escape", false)]
    public void MultidimensionalArraysAndClassesNeedExactClosedWriters(bool matrix, string shape, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Addressed");
            TypeSig concrete = matrix ? new ArraySig(module.CorLibTypes.Int32, 2) :
                module.CorLibTypes.GetTypeRef("System.Text", "StringBuilder").ToTypeSig();
            var field = new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Object),
                FieldAttributes.Private | FieldAttributes.Static); owner.Fields.Add(field);
            MethodDef Add(string name, params TypeSig[] parameters)
            {
                var method = new MethodDefUser(name, MethodSig.CreateStatic(module.CorLibTypes.Void, parameters),
                    MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
                owner.Methods.Add(method); return method;
            }
            void Emit(MethodDef method, params Instruction[] instructions)
            { foreach (var i in instructions) method.Body.Instructions.Add(i); }
            void Value(MethodDef method)
            {
                if (matrix) Emit(method, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Ldc_I4_1.ToInstruction());
                Emit(method, OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", matrix ?
                    MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Int32, module.CorLibTypes.Int32) :
                    MethodSig.CreateInstance(module.CorLibTypes.Void), concrete.ToTypeDefOrRef())));
            }
            var consume = Add("Consume", new ByRefSig(concrete));
            Emit(consume, OpCodes.Ldarg_0.ToInstruction());
            Value(consume); Emit(consume, OpCodes.Stind_Ref.ToInstruction());
            if (shape == "escape")
            {
                var local = new Local(new ByRefSig(concrete)); consume.Body.Variables.Add(local);
                Emit(consume, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Stloc.ToInstruction(local));
            }
            Emit(consume, OpCodes.Ret.ToInstruction());
            var entry = Add("Entry", module.CorLibTypes.Object);
            Value(entry); Emit(entry, OpCodes.Stsfld.ToInstruction(field));
            if (shape == "unknown") Emit(entry, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Stsfld.ToInstruction(field));
            if (shape == "conflict") Emit(entry, OpCodes.Ldstr.ToInstruction("different"), OpCodes.Stsfld.ToInstruction(field));
            Emit(entry, OpCodes.Ldsflda.ToInstruction(field), OpCodes.Call.ToInstruction(consume), OpCodes.Ret.ToInstruction());
        });
        var pass = matrix ? new ArrayFieldTypingPass() : new ReferenceFieldTypingPass();
        Assert.Equal(expected ? 1 : 0, pass.Run(context).Changes);
        Assert.Equal(0, pass.Run(context).Changes);
        var field = context.Module.GetTypes().SelectMany(t => t.Fields).Single();
        Assert.Equal(expected ? matrix ? ElementType.Array : ElementType.Class : ElementType.Object, field.FieldType.ElementType);
        if (expected)
        {
            var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
            try { context.Module.Write(path); Assert.Equal(0, IlVerification.Read(path, []).Count); }
            finally { File.Delete(path); }
        }
    }
}
