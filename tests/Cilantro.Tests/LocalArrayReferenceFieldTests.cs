using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class LocalArrayReferenceFieldTests
{
    private static readonly string[] PairNames = ["First", "Last"];
    [Theory]
    [InlineData("valid", true, false)]
    [InlineData("valid", true, true)]
    [InlineData("forwarded", true, false)]
    [InlineData("forwarded", true, true)]
    [InlineData("read-write", true, false)]
    [InlineData("read-write", true, true)]
    [InlineData("null-write", true, false)]
    [InlineData("null-write", true, true)]
    [InlineData("nested-private", true, false)]
    [InlineData("nested-private", true, true)]
    [InlineData("nested-private-friend", true, false)]
    [InlineData("nested-private-friend", true, true)]
    [InlineData("internal", true, false)]
    [InlineData("internal", true, true)]
    [InlineData("internal-friend", false, false)]
    [InlineData("internal-friend", false, true)]
    [InlineData("wrong-write", false, false)]
    [InlineData("wrong-write", false, true)]
    [InlineData("unknown-call", false, false)]
    [InlineData("unknown-call", false, true)]
    [InlineData("implicit-forward", false, false)]
    [InlineData("implicit-forward", false, true)]
    [InlineData("local-alias", false, false)]
    [InlineData("local-alias", false, true)]
    [InlineData("duplicate", false, false)]
    [InlineData("duplicate", false, true)]
    [InlineData("reassign", false, false)]
    [InlineData("reassign", false, true)]
    [InlineData("argument-address", false, false)]
    [InlineData("argument-address", false, true)]
    [InlineData("cycle", false, false)]
    [InlineData("cycle", false, true)]
    [InlineData("virtual", false, false)]
    [InlineData("virtual", false, true)]
    [InlineData("branch-address", false, false)]
    [InlineData("branch-address", false, true)]
    [InlineData("public-field", false, false)]
    [InlineData("public-field", false, true)]
    [InlineData("reflected", false, false)]
    [InlineData("reflected", false, true)]
    [InlineData("direct-typed", true, true)]
    [InlineData("direct-unknown", false, true)]
    [InlineData("direct-conflict", false, true)]
    public void RequiresTypedWritesAndNoAddressEscape(string mode, bool expected, bool strings)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Holder");
            if (mode is "nested-private" or "nested-private-friend")
            {
                var outer = SyntheticContext.AddType(module, "Outer");
                module.Types.Remove(owner); outer.NestedTypes.Add(owner); owner.Attributes = TypeAttributes.NestedPrivate;
            }
            if (mode is "nested-private-friend" or "internal-friend")
            {
                var attribute = module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "InternalsVisibleToAttribute");
                module.Assembly.CustomAttributes.Add(new CustomAttribute(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String), attribute),
                    [new CAArgument(module.CorLibTypes.String, new UTF8String("Friend"))]));
            }
            Instruction Length() => strings ? OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_Length", MethodSig.CreateInstance(module.CorLibTypes.Int32), module.CorLibTypes.String.TypeDefOrRef)) : OpCodes.Ldlen.ToInstruction();
            TypeSig array = strings ? module.CorLibTypes.String : new SZArraySig(module.CorLibTypes.Byte);
            var field = new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Static |
                (mode is "public-field" or "nested-private" or "nested-private-friend" ? FieldAttributes.Public :
                    mode is "internal" or "internal-friend" ? FieldAttributes.Assembly : FieldAttributes.Private)); owner.Fields.Add(field);
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
                else if ((mode == "wrong-write") != strings) Emit(writer, OpCodes.Ldstr.ToInstruction("text"));
                else Emit(writer, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Newarr.ToInstruction(module.CorLibTypes.Byte.TypeDefOrRef));
                Emit(writer, OpCodes.Stind_Ref.ToInstruction());
                if (mode == "read-write") Emit(writer, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldind_Ref.ToInstruction(), Length(), OpCodes.Pop.ToInstruction());
                Emit(writer, OpCodes.Ret.ToInstruction());
            }
            var target = writer;
            if (mode == "forwarded") { target = Add("Forward", new ByRefSig(array)); Emit(target, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Call.ToInstruction(writer), OpCodes.Ret.ToInstruction()); }
            var entry = Add("Entry", module.CorLibTypes.Object);
            if (mode == "direct-typed") Emit(entry, OpCodes.Ldstr.ToInstruction("seed"), OpCodes.Stsfld.ToInstruction(field));
            if (mode == "direct-unknown") Emit(entry, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Stsfld.ToInstruction(field));
            if (mode == "direct-conflict") Emit(entry, OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void), module.CorLibTypes.Object.TypeDefOrRef)), OpCodes.Stsfld.ToInstruction(field));
            if (mode == "reflected") Emit(entry, OpCodes.Ldtoken.ToInstruction(owner), OpCodes.Pop.ToInstruction());
            Emit(entry, OpCodes.Ldsflda.ToInstruction(field));
            var call = OpCodes.Call.ToInstruction(target);
            if (mode == "branch-address") Emit(entry, OpCodes.Br.ToInstruction(call));
            Emit(entry, call, OpCodes.Ldsfld.ToInstruction(field), Length(), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(expected ? 1 : 0, (strings ? new ReferenceFieldTypingPass() : new ArrayFieldTypingPass()).Run(context).Changes);
        Assert.Equal(expected ? strings ? "System.String" : "System.Byte[]" : "System.Object", context.Module.GetTypes().SelectMany(t => t.Fields).Single().FieldType.FullName);
        Assert.Equal(0, (strings ? new ReferenceFieldTypingPass() : new ArrayFieldTypingPass()).Run(context).Changes);
    }
    private static void Emit(MethodDef method, params Instruction[] instructions)
    { foreach (var instruction in instructions) method.Body.Instructions.Add(instruction); }

    [Theory]
    [InlineData("closed", 2)]
    [InlineData("branch", 1)]
    [InlineData("spill", 1)]
    [InlineData("duplicate", 1)]
    public void TracksEachAddressThroughInstanceCallArgumentPreparation(string shape, int expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Pair");
            var array = new SZArraySig(module.CorLibTypes.Byte);
            var fields = PairNames.Select(name => new FieldDefUser(name,
                new FieldSig(module.CorLibTypes.Object), FieldAttributes.Assembly | FieldAttributes.Static)).ToArray();
            foreach (var field in fields) owner.Fields.Add(field);
            var consume = new MethodDefUser("Consume", MethodSig.CreateInstance(module.CorLibTypes.Void,
                new ByRefSig(array), module.CorLibTypes.Int32, new ByRefSig(array)), MethodImplAttributes.IL,
                MethodAttributes.Private) { Body = new CilBody() };
            owner.Methods.Add(consume);
            Emit(consume, OpCodes.Ldarg_1.ToInstruction(), OpCodes.Ldind_Ref.ToInstruction(),
                OpCodes.Ldlen.ToInstruction(), OpCodes.Pop.ToInstruction(), OpCodes.Ldarg_3.ToInstruction(),
                OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Newarr.ToInstruction(module.CorLibTypes.Byte.TypeDefOrRef),
                OpCodes.Stind_Ref.ToInstruction(), OpCodes.Ret.ToInstruction());
            var entry = new MethodDefUser("Entry", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(entry);
            Emit(entry, OpCodes.Ldnull.ToInstruction(), OpCodes.Ldsflda.ToInstruction(fields[0]));
            var count = OpCodes.Ldc_I4_1.ToInstruction();
            if (shape == "branch") Emit(entry, OpCodes.Br.ToInstruction(count));
            if (shape == "duplicate") Emit(entry, OpCodes.Dup.ToInstruction(), OpCodes.Pop.ToInstruction());
            if (shape == "spill")
            {
                var local = new Local(new ByRefSig(module.CorLibTypes.Object)); entry.Body.Variables.Add(local);
                Emit(entry, OpCodes.Stloc.ToInstruction(local), OpCodes.Ldloc.ToInstruction(local));
            }
            Emit(entry, count, OpCodes.Ldsflda.ToInstruction(fields[1]), OpCodes.Call.ToInstruction(consume), OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(expected, new ArrayFieldTypingPass().Run(context).Changes);
        Assert.Equal(0, new ArrayFieldTypingPass().Run(context).Changes);
        if (shape == "closed")
        {
            var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
            try { context.Module.Write(path); Assert.Equal(0, IlVerification.Read(path, []).Count); }
            finally { File.Delete(path); }
        }
    }
}
