using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
namespace Cilantro.Tests;
public sealed class RawAssemblyBufferUseTests
{
    [Theory]
    [InlineData("normal", true)]
    [InlineData("element", false)]
    [InlineData("length", false)]
    [InlineData("address", false)]
    [InlineData("alias", false)]
    [InlineData("foreign", false)]
    [InlineData("offset", false)]
    public void OnlyAssemblyLoadingMayConsumeTheBuffer(string mode, bool expected)
    {
        MethodDef? method = null; Local? buffer = null;
        using var context = SyntheticContext.Build(module => {
            var owner = SyntheticContext.AddType(module, "Loader");
            var stream = module.CorLibTypes.GetTypeRef("System.IO", "Stream");
            var assembly = module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly");
            var bytes = new SZArraySig(module.CorLibTypes.Byte);
            method = new MethodDefUser("Load", MethodSig.CreateStatic(module.CorLibTypes.Void, stream.ToTypeSig()), MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(method); buffer = new Local(bytes); method.Body.Variables.Add(buffer);
            var il = method.Body.Instructions;
            il.Add(OpCodes.Ldc_I4_8.ToInstruction()); il.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Byte.TypeDefOrRef)); il.Add(OpCodes.Stloc.ToInstruction(buffer));
            il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Ldloc.ToInstruction(buffer)); il.Add((mode == "offset" ? OpCodes.Ldc_I4_1 : OpCodes.Ldc_I4_0).ToInstruction());
            il.Add(OpCodes.Ldloc.ToInstruction(buffer)); il.Add(OpCodes.Ldlen.ToInstruction()); il.Add(OpCodes.Conv_I4.ToInstruction());
            il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "Read", MethodSig.CreateInstance(module.CorLibTypes.Int32, bytes, module.CorLibTypes.Int32, module.CorLibTypes.Int32), stream))); il.Add(OpCodes.Pop.ToInstruction());
            if (mode == "element") { il.Add(OpCodes.Ldloc.ToInstruction(buffer)); il.Add(OpCodes.Ldc_I4_0.ToInstruction()); il.Add(OpCodes.Ldelem_U1.ToInstruction()); il.Add(OpCodes.Pop.ToInstruction()); }
            if (mode == "length") { il.Add(OpCodes.Ldloc.ToInstruction(buffer)); il.Add(OpCodes.Ldlen.ToInstruction()); il.Add(OpCodes.Pop.ToInstruction()); }
            if (mode == "address") { il.Add(OpCodes.Ldloca.ToInstruction(buffer)); il.Add(OpCodes.Pop.ToInstruction()); }
            if (mode == "alias") { var alias = new Local(bytes); method.Body.Variables.Add(alias); il.Add(OpCodes.Ldloc.ToInstruction(buffer)); il.Add(OpCodes.Stloc.ToInstruction(alias)); }
            il.Add(OpCodes.Ldloc.ToInstruction(buffer));
            ITypeDefOrRef target = mode == "foreign" ? new TypeRefUser(module, "System.Reflection", "Assembly", new AssemblyRefUser("Other")) : assembly;
            il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "Load", MethodSig.CreateStatic(assembly.ToTypeSig(), bytes), target))); il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(expected, RawAssemblyBufferUse.IsClosed(method!, buffer!));
    }
}
