using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ReferenceFieldTypingTests
{
    [Theory]
    [InlineData("initializer", true)]
    [InlineData("null", true)]
    [InlineData("branch", false)]
    [InlineData("conflict", false)]
    [InlineData("unknown", false)]
    [InlineData("address", false)]
    [InlineData("name", false)]
    [InlineData("type-handle", false)]
    [InlineData("array-element", true)]
    [InlineData("object-array-element", false)]
    [InlineData("closed-generic", true)]
    public void PreservesFieldSignatureAndProvesEveryWriter(string scenario, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Owner");
            var field = new FieldDefUser("Cache", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Private | FieldAttributes.Static);
            owner.Fields.Add(field);
            ITypeDefOrRef builder = scenario == "closed-generic"
                ? new TypeSpecUser(new GenericInstSig(new ClassSig(module.CorLibTypes.GetTypeRef("System.Collections.Generic", "List`1")), module.CorLibTypes.String))
                : new TypeRefUser(module, "System.Text", "StringBuilder", module.CorLibTypes.AssemblyRef);
            var ctor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), builder);
            var setter = new MemberRefUser(module, "set_Capacity", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Int32), builder);
            var getter = new MemberRefUser(module, scenario == "closed-generic" ? "get_Count" : "get_Length", MethodSig.CreateInstance(module.CorLibTypes.Int32), builder);
            var write = new MethodDefUser("Write", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(write);
            var il = write.Body.Instructions;
            var store = OpCodes.Stsfld.ToInstruction(field);
            if (scenario == "branch")
            {
                il.Add(OpCodes.Ldstr.ToInstruction("different type"));
                il.Add(OpCodes.Br.ToInstruction(store));
            }
            if (scenario is "array-element" or "object-array-element")
            {
                il.Add(OpCodes.Ldc_I4_1.ToInstruction());
                il.Add(OpCodes.Newarr.ToInstruction(scenario == "array-element" ? builder : module.CorLibTypes.Object.TypeDefOrRef));
                il.Add(OpCodes.Ldc_I4_0.ToInstruction());
                il.Add(OpCodes.Ldelem_Ref.ToInstruction());
            }
            else if (scenario == "unknown") il.Add(OpCodes.Ldarg_0.ToInstruction());
            else
            {
                il.Add(OpCodes.Newobj.ToInstruction(ctor));
                il.Add(OpCodes.Dup.ToInstruction());
                il.Add(OpCodes.Ldc_I4.ToInstruction(16));
                il.Add(OpCodes.Callvirt.ToInstruction(setter));
            }
            il.Add(store);
            if (scenario is "null" or "conflict")
            {
                il.Add(scenario == "null" ? OpCodes.Ldnull.ToInstruction() : OpCodes.Ldstr.ToInstruction("conflict"));
                il.Add(OpCodes.Stsfld.ToInstruction(field));
            }
            if (scenario is "address" or "name" or "type-handle")
            {
                il.Add(scenario == "address" ? OpCodes.Ldsflda.ToInstruction(field) :
                    scenario == "name" ? OpCodes.Ldstr.ToInstruction("Cache") : OpCodes.Ldtoken.ToInstruction(owner));
                il.Add(OpCodes.Pop.ToInstruction());
            }
            il.Add(OpCodes.Ret.ToInstruction());
            var read = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(read);
            read.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(field));
            read.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(getter));
            read.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            read.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
        try
        {
            context.Module.Write(path);
            Assert.Equal(1, IlVerification.Read(path, []).Count);
            Assert.Equal(expected ? 1 : 0, new ReferenceFieldTypingPass().Run(context).Changes);
            Assert.Equal(ElementType.Object, context.Module.GetTypes().SelectMany(t => t.Fields).Single().FieldType.ElementType);
            Assert.Equal(0, new ReferenceFieldTypingPass().Run(context).Changes);
            context.Module.Write(path);
            Assert.Equal(expected ? 0 : 1, IlVerification.Read(path, []).Count);
        }
        finally { File.Delete(path); }
    }
}
