using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ClosedDelegateIteratorTests
{
    [Theory]
    [InlineData("valid", 1)]
    [InlineData("nop", 1)]
    [InlineData("foreign-where", 0)]
    [InlineData("foreign-join", 0)]
    [InlineData("wrong-element", 0)]
    [InlineData("wrong-return", 0)]
    [InlineData("wrong-predicate", 0)]
    [InlineData("wrong-join", 0)]
    [InlineData("escape", 0)]
    [InlineData("duplicate", 0)]
    [InlineData("branch", 0)]
    public void IteratorMustBeImmediatelyConsumedByExactJoin(string mode, int expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Callbacks");
            var callback = new MethodDefUser("Callback", MethodSig.CreateStatic(module.CorLibTypes.Boolean, module.CorLibTypes.Object), MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(callback);
            Emit(callback, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_Length", MethodSig.CreateInstance(module.CorLibTypes.Int32), module.CorLibTypes.String.TypeDefOrRef)), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Cgt.ToInstruction(), OpCodes.Ret.ToInstruction());
            var sequenceType = module.CorLibTypes.GetTypeRef("System.Collections.Generic", "IEnumerable`1");
            var funcType = module.CorLibTypes.GetTypeRef("System", "Func`2");
            var sequence = new GenericInstSig(new ClassSig(sequenceType), module.CorLibTypes.String);
            var predicate = new GenericInstSig(new ClassSig(funcType), module.CorLibTypes.String, module.CorLibTypes.Boolean);
            var entry = new MethodDefUser("Entry", MethodSig.CreateStatic(module.CorLibTypes.Void, sequence), MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(entry);
            Emit(entry, OpCodes.Ldstr.ToInstruction(","), OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldnull.ToInstruction(), OpCodes.Ldftn.ToInstruction(callback), OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr), new TypeSpecUser(predicate))));
            var openSequence = new GenericInstSig(new ClassSig(sequenceType), new GenericMVar(0));
            var openPredicate = new GenericInstSig(new ClassSig(funcType), new GenericMVar(0), mode == "wrong-predicate" ? module.CorLibTypes.Int32 : module.CorLibTypes.Boolean);
            var whereSignature = MethodSig.CreateStaticGeneric(1, mode == "wrong-return" ? module.CorLibTypes.Object : openSequence, openSequence, openPredicate);
            var linqAssembly = new AssemblyRefUser("System.Core", new Version(4, 0, 0, 0), new PublicKeyToken(mode == "foreign-where" ? "0000000000000000" : "b77a5c561934e089"));
            var where = new MethodSpecUser(new MemberRefUser(module, "Where", whereSignature, new TypeRefUser(module, "System.Linq", "Enumerable", linqAssembly)), new GenericInstMethodSig(mode == "wrong-element" ? module.CorLibTypes.Object : module.CorLibTypes.String));
            Emit(entry, OpCodes.Call.ToInstruction(where));
            if (mode == "nop") Emit(entry, OpCodes.Nop.ToInstruction());
            if (mode == "escape")
            {
                var sink = new MemberRefUser(module, "Store", MethodSig.CreateStatic(module.CorLibTypes.Void, sequence), new TypeRefUser(module, "External", "Sink", new AssemblyRefUser("External", new Version(1, 0))));
                Emit(entry, OpCodes.Dup.ToInstruction(), OpCodes.Call.ToInstruction(sink));
            }
            if (mode == "duplicate") Emit(entry, OpCodes.Dup.ToInstruction(), OpCodes.Pop.ToInstruction());
            var join = OpCodes.Call.ToInstruction(new MemberRefUser(module, mode == "wrong-join" ? "Store" : "Join", MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.String, sequence), mode == "foreign-join" ? new TypeRefUser(module, "System", "String", new AssemblyRefUser("External", new Version(1, 0))) : module.CorLibTypes.String.TypeDefOrRef));
            if (mode == "branch") Emit(entry, OpCodes.Br.ToInstruction(join));
            Emit(entry, join, OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(expected, new ReferenceParameterTypingPass().Run(context).Changes);
        Assert.Equal(0, new ReferenceParameterTypingPass().Run(context).Changes);
    }

    private static void Emit(MethodDef method, params Instruction[] instructions)
    {
        foreach (var instruction in instructions) method.Body.Instructions.Add(instruction);
    }
}
