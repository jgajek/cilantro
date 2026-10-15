using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DefaultJsonSerializerCallsTests
{
    [Theory]
    [InlineData("default", true)]
    [InlineData("nops", true)]
    [InlineData("alias", false)]
    [InlineData("address", false)]
    [InlineData("overwrite", false)]
    [InlineData("configured", false)]
    [InlineData("foreign", false)]
    [InlineData("typed", false)]
    [InlineData("branch", false)]
    public void RequiresFreshUnexposedInstance(string mode, bool accepted)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Example");
            var method = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.Object),
                MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(method);
            var assembly = new AssemblyRefUser(new AssemblyNameInfo(mode == "foreign"
                ? "Other, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"
                : "System.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"));
            var serializer = new TypeRefUser(module, "System.Web.Script.Serialization", "JavaScriptSerializer", assembly);
            var local = new Local(serializer.ToTypeSig()); method.Body.Variables.Add(local);
            var il = method.Body.Instructions;
            void Emit(params Instruction[] instructions) { foreach (var instruction in instructions) il.Add(instruction); }
            Emit(OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), serializer)),
                OpCodes.Stloc.ToInstruction(local));
            if (mode == "alias") Emit(OpCodes.Ldloc.ToInstruction(local), OpCodes.Pop.ToInstruction());
            if (mode == "address") Emit(OpCodes.Ldloca.ToInstruction(local), OpCodes.Pop.ToInstruction());
            if (mode == "overwrite") Emit(OpCodes.Ldnull.ToInstruction(), OpCodes.Stloc.ToInstruction(local));
            if (mode == "configured") Emit(OpCodes.Ldloc.ToInstruction(local), OpCodes.Ldc_I4_1.ToInstruction(),
                OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "set_RecursionLimit", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Int32), serializer)));
            if (mode == "nops") Emit(OpCodes.Nop.ToInstruction());
            var load = OpCodes.Ldloc.ToInstruction(local);
            if (mode == "branch") Emit(OpCodes.Br.ToInstruction(load));
            Emit(load, OpCodes.Ldstr.ToInstruction("{}"));
            var deserialize = new MemberRefUser(module, "Deserialize", MethodSig.CreateInstanceGeneric(1, new GenericMVar(0), module.CorLibTypes.String), serializer);
            Emit(OpCodes.Callvirt.ToInstruction(new MethodSpecUser(deserialize, new GenericInstMethodSig(mode == "typed" ? module.CorLibTypes.String : module.CorLibTypes.Object))), OpCodes.Ret.ToInstruction());
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Read");
        Assert.Equal(accepted ? 1 : 0, DefaultJsonSerializerCalls.Find(method).Count);
    }
}
