using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
namespace Cilantro.Tests;
public sealed class RawResourceProvenanceTests
{
    [Theory]
    [InlineData("normal", true)]
    [InlineData("overwrite", false)]
    [InlineData("foreign-owner", false)]
    [InlineData("foreign-framework", false)]
    [InlineData("missing-resource", false)]
    [InlineData("altered-length", false)]
    [InlineData("alternate-entry", false)]
    public void RequiresContainingAssemblyResourceAndUninterruptedRead(string mode, bool expected)
    {
        MethodDef? method = null; Local? buffer = null;
        using var context = SyntheticContext.Build(module => {
            var owner = SyntheticContext.AddType(module, "Loader");
            if (mode != "missing-resource") module.Resources.Add(new EmbeddedResource("payload", new byte[] { 1 }));
            var streamType = module.CorLibTypes.GetTypeRef("System.IO", "Stream");
            var assembly = module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly");
            var type = module.CorLibTypes.GetTypeRef("System", "Type");
            var bytes = new SZArraySig(module.CorLibTypes.Byte);
            method = new MethodDefUser("Load", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(method); var stream = new Local(streamType.ToTypeSig()); buffer = new Local(bytes);
            method.Body.Variables.Add(stream); method.Body.Variables.Add(buffer);
            var il = method.Body.Instructions;
            void Call(OpCode op, string name, MethodSig sig, ITypeDefOrRef declaring) => il.Add(op.ToInstruction(new MemberRefUser(module,name,sig,declaring)));
            il.Add(OpCodes.Ldtoken.ToInstruction(mode == "foreign-owner" ? type : owner));
            Call(OpCodes.Call,"GetTypeFromHandle",MethodSig.CreateStatic(type.ToTypeSig(),module.CorLibTypes.GetTypeRef("System","RuntimeTypeHandle").ToTypeSig()),type);
            Call(OpCodes.Callvirt,"get_Assembly",MethodSig.CreateInstance(assembly.ToTypeSig()),type);
            il.Add(OpCodes.Ldstr.ToInstruction("payload"));
            Call(OpCodes.Callvirt,"GetManifestResourceStream",MethodSig.CreateInstance(streamType.ToTypeSig(),module.CorLibTypes.String),mode == "foreign-framework" ? new TypeRefUser(module,"System.Reflection","Assembly",new AssemblyRefUser("Other")) : assembly);
            il.Add(OpCodes.Stloc.ToInstruction(stream)); il.Add(OpCodes.Ldloc.ToInstruction(stream));
            Call(OpCodes.Callvirt,"get_Length",MethodSig.CreateInstance(module.CorLibTypes.Int64),streamType);
            il.Add((mode == "altered-length" ? OpCodes.Conv_I : OpCodes.Conv_Ovf_I).ToInstruction());
            il.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Byte.TypeDefOrRef)); il.Add(OpCodes.Stloc.ToInstruction(buffer));
            il.Add(OpCodes.Ldloc.ToInstruction(stream)); il.Add(OpCodes.Ldloc.ToInstruction(buffer)); il.Add(OpCodes.Ldc_I4_0.ToInstruction()); il.Add(OpCodes.Ldloc.ToInstruction(buffer)); il.Add(OpCodes.Ldlen.ToInstruction()); il.Add(OpCodes.Conv_I4.ToInstruction());
            Call(OpCodes.Callvirt,"Read",MethodSig.CreateInstance(module.CorLibTypes.Int32,bytes,module.CorLibTypes.Int32,module.CorLibTypes.Int32),streamType); il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Ldloc.ToInstruction(stream));
            Call(OpCodes.Callvirt,"Close",MethodSig.CreateInstance(module.CorLibTypes.Void),streamType);
            if (mode == "overwrite") foreach (var i in il.Skip(11).Take(8).ToArray()) il.Add(new Instruction(i.OpCode,i.Operand));
            il.Add(OpCodes.Ldloc.ToInstruction(buffer)); Call(OpCodes.Call,"Load",MethodSig.CreateStatic(assembly.ToTypeSig(),bytes),assembly); il.Add(OpCodes.Pop.ToInstruction());
            if (mode == "alternate-entry") il.Add(OpCodes.Br.ToInstruction(il[6])); else il.Add(OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(expected ? "payload" : null, RawAssemblyBufferUse.ResourceName(method!,buffer!));
    }
}
