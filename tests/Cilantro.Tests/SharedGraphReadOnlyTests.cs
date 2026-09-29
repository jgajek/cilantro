using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class SharedGraphReadOnlyTests
{
    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public void AStructCopyOnlyLosesBorrowedIdentityWhenItContainsNoReferences(bool containsReference, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Lookup");
            var value = new TypeDefUser("Synthetic", "Item", module.CorLibTypes.GetTypeRef("System", "ValueType"))
            { Attributes = TypeAttributes.NotPublic | TypeAttributes.Sealed | TypeAttributes.SequentialLayout };
            module.Types.Add(value);
            var member = new FieldDefUser("Value", new FieldSig(containsReference ? module.CorLibTypes.Object : module.CorLibTypes.Int32));
            value.Fields.Add(member);
            var root = new FieldDefUser("Data", new FieldSig(new SZArraySig(value.ToTypeSig())), FieldAttributes.Static); owner.Fields.Add(root);
            var initializer = owner.FindOrCreateStaticConstructor(); initializer.Body = new CilBody();
            foreach (var i in new[] { OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Newarr.ToInstruction(value), OpCodes.Stsfld.ToInstruction(root), OpCodes.Ret.ToInstruction() }) initializer.Body.Instructions.Add(i);
            var local = new Local(value.ToTypeSig());
            var read = new MethodDefUser("Copy", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodAttributes.Static)
            { Body = new CilBody { InitLocals = true } }; owner.Methods.Add(read); read.Body.Variables.Add(local);
            foreach (var i in new[] { OpCodes.Ldsfld.ToInstruction(root), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldelema.ToInstruction(value),
                OpCodes.Ldobj.ToInstruction(value), OpCodes.Stloc.ToInstruction(local), OpCodes.Ldloca.ToInstruction(local),
                containsReference ? OpCodes.Ldnull.ToInstruction() : OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Stfld.ToInstruction(member), OpCodes.Ret.ToInstruction() }) read.Body.Instructions.Add(i);
        });
        var root = context.Module.GetTypes().SelectMany(t => t.Fields).Single(f => f.Name == "Data");
        Assert.Equal(expected, SharedGraphReadOnly.Check(root).Passed);
    }

    [Theory]
    [InlineData("read", true)]
    [InlineData("loop", true)]
    [InlineData("array-read", true)]
    [InlineData("private-return", true)]
    [InlineData("write", false)]
    [InlineData("array-write", false)]
    [InlineData("external", false)]
    [InlineData("public-return", false)]
    [InlineData("address", false)]
    [InlineData("replacement", false)]
    [InlineData("getter-escape", false)]
    [InlineData("function-pointer", false)]
    [InlineData("initializer-alias", false)]
    [InlineData("array-length", true)]
    [InlineData("primitive-search", true)]
    [InlineData("object-search", false)]
    [InlineData("search-comparer", false)]
    public void FollowsPublishedAliasesAndRefusesMutationOrEscape(string scenario, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Owner");
            var node = SyntheticContext.AddType(module, "Node");
            var reader = SyntheticContext.AddType(module, "Reader");
            var root = new FieldDefUser("Root", new FieldSig(node.ToTypeSig()), FieldAttributes.Static);
            var saved = new FieldDefUser("Saved", new FieldSig(module.CorLibTypes.Object));
            var next = new FieldDefUser("Next", new FieldSig(node.ToTypeSig()));
            var scalar = new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Int32));
            var array = new FieldDefUser("Items", new FieldSig(new SZArraySig(module.CorLibTypes.Int32)));
            owner.Fields.Add(root); reader.Fields.Add(saved); node.Fields.Add(next); node.Fields.Add(scalar); node.Fields.Add(array);
            MethodDef Method(TypeDef type, string name, MethodSig sig, params Instruction[] instructions)
            {
                var method = new MethodDefUser(name, sig) { Attributes = sig.HasThis ? MethodAttributes.Private : MethodAttributes.Static | MethodAttributes.Private, Body = new CilBody() };
                foreach (var i in instructions) method.Body.Instructions.Add(i);
                type.Methods.Add(method); return method;
            }
            var init = Method(owner, ".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void), OpCodes.Ldnull.ToInstruction(), OpCodes.Stsfld.ToInstruction(root), OpCodes.Ret.ToInstruction());
            init.Attributes |= MethodAttributes.SpecialName | MethodAttributes.RTSpecialName;
            Method(reader, "Save", MethodSig.CreateInstance(module.CorLibTypes.Void), OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldsfld.ToInstruction(root), OpCodes.Stfld.ToInstruction(saved), OpCodes.Ret.ToInstruction());
            var get = Method(reader, "Get", MethodSig.CreateStatic(module.CorLibTypes.Int32, node.ToTypeSig()), OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldfld.ToInstruction(scalar), OpCodes.Ret.ToInstruction());
            var read = Method(reader, "Read", MethodSig.CreateInstance(module.CorLibTypes.Int32), OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldfld.ToInstruction(saved), OpCodes.Castclass.ToInstruction(node), OpCodes.Call.ToInstruction(get), OpCodes.Ret.ToInstruction());
            if (scenario == "loop")
            {
                var first = get.Body.Instructions[0];
                var start = OpCodes.Ldarg_0.ToInstruction();
                var prefix = new[] { start, OpCodes.Ldfld.ToInstruction(next), OpCodes.Brfalse.ToInstruction(first), OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldfld.ToInstruction(next), OpCodes.Starg.ToInstruction(get.Parameters[0]), OpCodes.Br.ToInstruction(start) };
                for (var i = 0; i < prefix.Length; i++) get.Body.Instructions.Insert(i, prefix[i]);
            }
            if (scenario is "array-read" or "array-write")
            {
                get.Body.Instructions.Clear();
                foreach (var i in new[] { OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldfld.ToInstruction(array), OpCodes.Ldc_I4_0.ToInstruction() }) get.Body.Instructions.Add(i);
                if (scenario == "array-write")
                {
                    get.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction()); get.Body.Instructions.Add(OpCodes.Stelem_I4.ToInstruction()); get.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
                }
                else get.Body.Instructions.Add(OpCodes.Ldelem_I4.ToInstruction());
                get.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            }
            if (scenario == "write")
            {
                get.Body.Instructions.Insert(0, OpCodes.Ldarg_0.ToInstruction());
                get.Body.Instructions.Insert(1, OpCodes.Ldc_I4_1.ToInstruction());
                get.Body.Instructions.Insert(2, OpCodes.Stfld.ToInstruction(scalar));
            }
            if (scenario == "external")
            {
                var call = new MemberRefUser(module, "KeepAlive", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object), module.CorLibTypes.GetTypeRef("System", "GC"));
                get.Body.Instructions.Insert(0, OpCodes.Ldarg_0.ToInstruction()); get.Body.Instructions.Insert(1, OpCodes.Call.ToInstruction(call));
            }
            if (scenario is "array-length" or "primitive-search" or "object-search" or "search-comparer")
            {
                get.Body.Instructions.Clear();
                get.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                get.Body.Instructions.Add(OpCodes.Ldfld.ToInstruction(array));
                var arrayType = module.CorLibTypes.GetTypeRef("System", "Array");
                if (scenario == "array-length")
                    get.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_Length", MethodSig.CreateInstance(module.CorLibTypes.Int32), arrayType)));
                else
                {
                    var element = scenario == "object-search" ? module.CorLibTypes.Object : module.CorLibTypes.Int32;
                    var signature = MethodSig.CreateStaticGeneric(1, module.CorLibTypes.Int32, new SZArraySig(new GenericMVar(0)), new GenericMVar(0));
                    if (scenario == "search-comparer") signature.Params.Add(module.CorLibTypes.Object);
                    var search = new MethodSpecUser(new MemberRefUser(module, "BinarySearch", signature, arrayType), new GenericInstMethodSig(element));
                    get.Body.Instructions.Add(scenario == "object-search" ? OpCodes.Ldnull.ToInstruction() : OpCodes.Ldc_I4_0.ToInstruction());
                    if (scenario == "search-comparer") get.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
                    get.Body.Instructions.Add(OpCodes.Call.ToInstruction(search));
                }
                get.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            }
            if (scenario is "private-return" or "public-return")
            {
                var identity = Method(reader, "Identity", MethodSig.CreateStatic(node.ToTypeSig(), node.ToTypeSig()), OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ret.ToInstruction());
                if (scenario == "public-return") identity.Access = MethodAttributes.Public;
                read.Body.Instructions.Insert(3, OpCodes.Call.ToInstruction(identity));
            }
            if (scenario == "address") Method(reader, "Address", MethodSig.CreateInstance(module.CorLibTypes.Void), OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldflda.ToInstruction(saved), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
            if (scenario == "replacement") Method(owner, "Replace", MethodSig.CreateStatic(module.CorLibTypes.Void), OpCodes.Ldnull.ToInstruction(), OpCodes.Stsfld.ToInstruction(root), OpCodes.Ret.ToInstruction());
            if (scenario is "getter-escape" or "function-pointer")
            {
                var getter = Method(owner, "Borrow", MethodSig.CreateStatic(node.ToTypeSig()), OpCodes.Ldsfld.ToInstruction(root), OpCodes.Ret.ToInstruction());
                if (scenario == "getter-escape")
                {
                    var escape = Method(owner, "Expose", MethodSig.CreateStatic(node.ToTypeSig()), OpCodes.Call.ToInstruction(getter), OpCodes.Ret.ToInstruction());
                    escape.Access = MethodAttributes.Public;
                }
                else Method(owner, "Pointer", MethodSig.CreateStatic(module.CorLibTypes.Void), OpCodes.Ldftn.ToInstruction(getter), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
            }
            if (scenario == "initializer-alias")
            {
                init.Body.Instructions.Insert(2, OpCodes.Ldsfld.ToInstruction(root)); init.Body.Instructions.Insert(3, OpCodes.Pop.ToInstruction());
            }
        });
        var field = context.Module.GetTypes().SelectMany(t => t.Fields).Single(f => f.Name == "Root");
        var proof = SharedGraphReadOnly.Check(field);
        Assert.True(proof.Passed == expected, proof.Detail);
        if (expected) { Assert.Equal(2, proof.AliasFields); Assert.True(proof.Methods >= 3); }
    }
}
