using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ComArrayFieldTypingTests
{
    [Theory]
    [InlineData("output", true)]
    [InlineData("input", false)]
    [InlineData("inout", false)]
    [InlineData("no-marshaler", false)]
    [InlineData("not-imported", false)]
    [InlineData("no-guid", false)]
    [InlineData("unknown-writer", false)]
    [InlineData("non-array-writer", false)]
    [InlineData("other-address", false)]
    [InlineData("friend", false)]
    public void OnlyExplicitComSafeArrayOutputsCanRefineAnErasedField(string shape, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var imported = new TypeDefUser("Interop", "Items") { Attributes = TypeAttributes.Public | TypeAttributes.Interface | TypeAttributes.Abstract };
            if (shape != "not-imported") imported.Attributes |= TypeAttributes.Import;
            module.Types.Add(imported);
            if (shape != "no-guid") imported.CustomAttributes.Add(new CustomAttribute(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String), module.CorLibTypes.GetTypeRef("System.Runtime.InteropServices", "GuidAttribute")),
                [new CAArgument(module.CorLibTypes.String, new UTF8String("12345678-1234-1234-1234-123456789012"))]));
            var array = module.CorLibTypes.GetTypeRef("System", "Array").ToTypeSig();
            var call = new MethodDefUser("Read", MethodSig.CreateInstance(module.CorLibTypes.Void, new ByRefSig(array)), MethodImplAttributes.Runtime | MethodImplAttributes.InternalCall,
                MethodAttributes.Public | MethodAttributes.Abstract | MethodAttributes.Virtual | MethodAttributes.NewSlot);
            imported.Methods.Add(call);
            var parameter = new ParamDefUser("result", 1, shape == "input" ? ParamAttributes.In : shape == "inout" ? ParamAttributes.In | ParamAttributes.Out : ParamAttributes.Out);
            if (shape != "no-marshaler") parameter.MarshalType = new SafeArrayMarshalType(VariantType.I4);
            call.ParamDefs.Add(parameter);
            var owner = SyntheticContext.AddType(module, "Owner");
            var field = new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Object), (shape == "friend" ? FieldAttributes.Assembly : FieldAttributes.Private) | FieldAttributes.Static);
            owner.Fields.Add(field);
            if (shape == "friend") module.Assembly.CustomAttributes.Add(new CustomAttribute(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String), module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "InternalsVisibleToAttribute")),
                [new CAArgument(module.CorLibTypes.String, new UTF8String("Friend"))]));
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(array, imported.ToTypeSig(), module.CorLibTypes.Object), MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(run);
            var il = run.Body.Instructions;
            if (shape == "unknown-writer") il.Add(OpCodes.Ldarg_1.ToInstruction());
            else if (shape == "non-array-writer") il.Add(OpCodes.Ldstr.ToInstruction("unknown"));
            else { il.Add(OpCodes.Ldc_I4_0.ToInstruction()); il.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Object.TypeDefOrRef)); }
            il.Add(OpCodes.Stsfld.ToInstruction(field));
            if (shape == "other-address") { il.Add(OpCodes.Ldsflda.ToInstruction(field)); il.Add(OpCodes.Pop.ToInstruction()); }
            il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Ldsflda.ToInstruction(field)); il.Add(OpCodes.Callvirt.ToInstruction(call));
            il.Add(OpCodes.Ldsfld.ToInstruction(field)); il.Add(OpCodes.Ret.ToInstruction());
        });
        var pass = new ArrayFieldTypingPass();
        Assert.Equal(expected ? 1 : 0, pass.Run(context).Changes);
        var field = context.Module.GetTypes().SelectMany(t => t.Fields).Single();
        Assert.Equal(expected ? "System.Array" : "System.Object", field.FieldType.FullName);
        Assert.Equal(0, pass.Run(context).Changes);
        if (expected)
        {
            var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
            try { context.Module.Write(path); Assert.Equal(0, IlVerification.Read(path, []).Count); }
            finally { File.Delete(path); }
        }
    }
}
