using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class LocalArrayReferenceFieldTests
{
    [Theory]
    [InlineData("valid", true)]
    [InlineData("forwarded", true)]
    [InlineData("read-write", true)]
    [InlineData("null-write", true)]
    [InlineData("nested-private", true)]
    [InlineData("nested-private-friend", true)]
    [InlineData("wrong-write", false)]
    [InlineData("unknown-call", false)]
    [InlineData("implicit-forward", false)]
    [InlineData("local-alias", false)]
    [InlineData("duplicate", false)]
    [InlineData("reassign", false)]
    [InlineData("argument-address", false)]
    [InlineData("cycle", false)]
    [InlineData("virtual", false)]
    [InlineData("branch-address", false)]
    [InlineData("public-field", false)]
    [InlineData("reflected", false)]
    public void RequiresTypedWritesAndNoAddressEscape(string mode, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Holder");
            if (mode is "nested-private" or "nested-private-friend")
            {
                var outer = SyntheticContext.AddType(module, "Outer");
                module.Types.Remove(owner); outer.NestedTypes.Add(owner); owner.Attributes = TypeAttributes.NestedPrivate;
            }
            if (mode == "nested-private-friend")
            {
                var attribute = module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "InternalsVisibleToAttribute");
                module.Assembly.CustomAttributes.Add(new CustomAttribute(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String), attribute),
                    [new CAArgument(module.CorLibTypes.String, new UTF8String("Friend"))]));
            }
            var array = new SZArraySig(module.CorLibTypes.Byte);
            var field = new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Static |
                (mode is "public-field" or "nested-private" or "nested-private-friend" ? FieldAttributes.Public : FieldAttributes.Private)); owner.Fields.Add(field);
            MethodDef Add(string name, params TypeSig[] parameters)
            {
                var m = new MethodDefUser(name, MethodSig.CreateStatic(module.CorLibTypes.Void, parameters), MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() }; owner.Methods.Add(m); return m;
            }
            var writer = Add("Write", new ByRefSig(array));
            if (mode == "virtual") writer.Attributes |= MethodAttributes.Virtual;
            var writeAddress = OpCodes.Ldarg_0.ToInstruction();
            Emit(writer, writeAddress);
            if (mode == "cycle") Emit(writer, OpCodes.Call.ToInstruction(writer), OpCodes.Ret.ToInstruction());
            else if (mode == "unknown-call") Emit(writer, OpCodes.Call.ToInstruction(new MemberRefUser(module, "Unknown", MethodSig.CreateStatic(module.CorLibTypes.Void, new ByRefSig(array)), module.CorLibTypes.GetTypeRef("System", "GC"))), OpCodes.Ret.ToInstruction());
            else if (mode == "implicit-forward")
            {
                writer.Body.Instructions.Clear();
                Emit(writer, OpCodes.Jmp.ToInstruction(new MemberRefUser(module, "Unknown", MethodSig.CreateStatic(module.CorLibTypes.Void, new ByRefSig(array)), module.CorLibTypes.GetTypeRef("System", "GC"))));
            }
            else if (mode == "local-alias")
            {
                var local = new Local(new ByRefSig(array)); writer.Body.Variables.Add(local);
                Emit(writer, OpCodes.Stloc.ToInstruction(local), OpCodes.Ret.ToInstruction());
            }
            else if (mode == "argument-address")
            { writer.Body.Instructions.Clear(); Emit(writer, OpCodes.Ldarga.ToInstruction(writer.Parameters[0]), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction()); }
            else if (mode == "reassign") Emit(writer, OpCodes.Starg.ToInstruction(writer.Parameters[0]), OpCodes.Ret.ToInstruction());
            else
            {
                if (mode == "duplicate") Emit(writer, OpCodes.Dup.ToInstruction(), OpCodes.Pop.ToInstruction());
                if (mode == "null-write") Emit(writer, OpCodes.Ldnull.ToInstruction());
                else if (mode == "wrong-write") Emit(writer, OpCodes.Ldstr.ToInstruction("bad"));
                else Emit(writer, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Newarr.ToInstruction(module.CorLibTypes.Byte.TypeDefOrRef));
                Emit(writer, OpCodes.Stind_Ref.ToInstruction());
                if (mode == "read-write") Emit(writer, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldind_Ref.ToInstruction(), OpCodes.Ldlen.ToInstruction(), OpCodes.Pop.ToInstruction());
                Emit(writer, OpCodes.Ret.ToInstruction());
            }
            var target = writer;
            if (mode == "forwarded") { target = Add("Forward", new ByRefSig(array)); Emit(target, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Call.ToInstruction(writer), OpCodes.Ret.ToInstruction()); }
            var entry = Add("Entry");
            if (mode == "reflected") Emit(entry, OpCodes.Ldtoken.ToInstruction(owner), OpCodes.Pop.ToInstruction());
            Emit(entry, OpCodes.Ldsflda.ToInstruction(field));
            var call = OpCodes.Call.ToInstruction(target);
            if (mode == "branch-address") Emit(entry, OpCodes.Br.ToInstruction(call));
            Emit(entry, call, OpCodes.Ldsfld.ToInstruction(field), OpCodes.Ldlen.ToInstruction(), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(expected ? 1 : 0, new ArrayFieldTypingPass().Run(context).Changes);
        Assert.Equal(expected ? "System.Byte[]" : "System.Object", context.Module.GetTypes().SelectMany(t => t.Fields).Single().FieldType.FullName);
        Assert.Equal(0, new ArrayFieldTypingPass().Run(context).Changes);
    }
    private static void Emit(MethodDef method, params Instruction[] instructions)
    { foreach (var instruction in instructions) method.Body.Instructions.Add(instruction); }
}
