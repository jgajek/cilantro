using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class DependencyIndexSourceTests
{
    [Theory]
    [InlineData("literal", true)]
    [InlineData("delegate", true)]
    [InlineData("null-test", true)]
    [InlineData("wrong-name", false)]
    [InlineData("foreign", false)]
    [InlineData("other-caller", false)]
    [InlineData("address", false)]
    [InlineData("overwrite", false)]
    [InlineData("consumed", false)]
    [InlineData("repeat", false)]
    [InlineData("bypass", false)]
    [InlineData("handler", false)]
    [InlineData("mutable-binding", false)]
    [InlineData("ambient-decoder", false)]
    public void RequiresFreshOwnedStreamOnEveryCallPath(string variant, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Host");
            var build = new MethodDefUser("Build", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object))
                { Attributes = MethodAttributes.Static | MethodAttributes.Private, Body = new CilBody() };
            build.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); owner.Methods.Add(build);
            var table = new FieldDefUser("Table", new FieldSig(module.CorLibTypes.GetTypeRef("System.Collections", "Hashtable").ToTypeSig()), FieldAttributes.Static);
            owner.Fields.Add(table);
            var method = new MethodDefUser("Resolve", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody { InitLocals = true } };
            owner.Methods.Add(method);
            var streamType = module.CorLibTypes.GetTypeRef("System.IO", "Stream");
            var stream = new Local(streamType.ToTypeSig()); method.Body.Variables.Add(stream);
            var typeType = module.CorLibTypes.GetTypeRef("System", "Type");
            var assembly = module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly");
            var getType = new MemberRefUser(module, "GetTypeFromHandle", MethodSig.CreateStatic(typeType.ToTypeSig(),
                module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle").ToTypeSig()), typeType);
            var getAssembly = new MemberRefUser(module, "get_Assembly", MethodSig.CreateInstance(assembly.ToTypeSig()), typeType);
            var resourceOwner = variant == "foreign" ? new TypeRefUser(module, "System.Reflection", "Assembly", new AssemblyRefUser("Foreign")) : assembly;
            var open = new MemberRefUser(module, "GetManifestResourceStream", MethodSig.CreateInstance(streamType.ToTypeSig(), module.CorLibTypes.String), resourceOwner);
            var il = method.Body.Instructions;
            var entry = OpCodes.Ldtoken.ToInstruction(owner);
            var argument = OpCodes.Ldloc_0.ToInstruction();
            var ret = OpCodes.Ret.ToInstruction();
            if (variant == "bypass") il.Add(OpCodes.Br.ToInstruction(argument));
            il.Add(entry); il.Add(OpCodes.Call.ToInstruction(getType)); il.Add(OpCodes.Callvirt.ToInstruction(getAssembly));
            if (variant is "delegate" or "mutable-binding" or "ambient-decoder")
            {
                var binding = Binding(module, owner, variant, out var invoke);
                var name = new Local(module.CorLibTypes.String); method.Body.Variables.Add(name);
                il.Add(OpCodes.Ldsfld.ToInstruction(binding)); il.Add(OpCodes.Ldc_I4_1.ToInstruction());
                il.Add(OpCodes.Callvirt.ToInstruction(invoke)); il.Add(OpCodes.Stloc_1.ToInstruction());
                il.Add(OpCodes.Castclass.ToInstruction(assembly)); il.Add(OpCodes.Ldloc_1.ToInstruction());
            }
            else il.Add(OpCodes.Ldstr.ToInstruction(variant == "wrong-name" ? "other" : "A"));
            il.Add(OpCodes.Callvirt.ToInstruction(open)); il.Add(OpCodes.Stloc_0.ToInstruction());
            if (variant == "address") { il.Add(OpCodes.Ldloca.ToInstruction(stream)); il.Add(OpCodes.Pop.ToInstruction()); }
            if (variant == "overwrite") { il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Stloc_0.ToInstruction()); }
            if (variant == "null-test") { il.Add(OpCodes.Ldloc_0.ToInstruction()); il.Add(OpCodes.Brfalse.ToInstruction(ret)); }
            if (variant == "consumed")
            {
                il.Add(OpCodes.Ldloc_0.ToInstruction());
                il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "ReadByte", MethodSig.CreateInstance(module.CorLibTypes.Int32), streamType)));
                il.Add(OpCodes.Pop.ToInstruction());
            }
            il.Add(argument); il.Add(OpCodes.Call.ToInstruction(build));
            if (variant == "repeat") { il.Add(OpCodes.Ldloc_0.ToInstruction()); il.Add(OpCodes.Call.ToInstruction(build)); }
            if (variant == "handler")
            {
                il.Add(OpCodes.Leave.ToInstruction(ret));
                var handler = OpCodes.Pop.ToInstruction(); il.Add(handler);
                il.Add(OpCodes.Ldloc_0.ToInstruction()); il.Add(OpCodes.Call.ToInstruction(build)); il.Add(OpCodes.Leave.ToInstruction(ret));
                method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
                    { TryStart = entry, TryEnd = handler, HandlerStart = handler, HandlerEnd = ret,
                      CatchType = module.CorLibTypes.GetTypeRef("System", "Exception") });
            }
            il.Add(ret);
            if (variant == "other-caller")
            {
                var other = new MethodDefUser("Other", MethodSig.CreateStatic(module.CorLibTypes.Void))
                    { Attributes = MethodAttributes.Static, Body = new CilBody() };
                owner.Methods.Add(other);
                other.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); other.Body.Instructions.Add(OpCodes.Call.ToInstruction(build));
                other.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            }
            module.Resources.Add(new EmbeddedResource("A", new byte[] { 1 }, ManifestResourceAttributes.Private));
        });
        var owner = context.Module.GetTypes().Single(t => t.Name == "Host");
        var resource = context.Module.Resources.OfType<EmbeddedResource>().Single();
        var index = new DependencyIndexConstruction.Snapshot(RecoveredResourceOrigin.Capture(resource), owner.Fields.Single(f => f.Name == "Table"), [], 0);
        var actual = DependencyIndexSource.Check(owner.Methods.Single(m => m.Name == "Resolve"), owner.Methods.Single(m => m.Name == "Build"), index, out var reason);
        Assert.True(actual == expected, reason);
    }

    private static FieldDefUser Binding(ModuleDefUser module, TypeDef owner, string variant, out MethodDef invoke)
    {
        var callback = SyntheticContext.AddType(module, "Callback");
        callback.BaseType = module.CorLibTypes.GetTypeRef("System", "MulticastDelegate");
        var ctor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr))
            { Attributes = MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, ImplAttributes = MethodImplAttributes.Runtime };
        invoke = new MethodDefUser("Invoke", MethodSig.CreateInstance(module.CorLibTypes.String, module.CorLibTypes.Int32))
            { Attributes = MethodAttributes.Public | MethodAttributes.Virtual, ImplAttributes = MethodImplAttributes.Runtime };
        callback.Methods.Add(ctor); callback.Methods.Add(invoke);
        var binding = new FieldDefUser("Binding", new FieldSig(callback.ToTypeSig()), FieldAttributes.Private | FieldAttributes.Static);
        owner.Fields.Add(binding);
        var decode = new MethodDefUser("Decode", MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.Int32))
            { Attributes = MethodAttributes.Static, Body = new CilBody() };
        owner.Methods.Add(decode);
        var chars = new MemberRefUser(module, "ToCharArray", MethodSig.CreateInstance(new SZArraySig(module.CorLibTypes.Char)), module.CorLibTypes.String.TypeDefOrRef);
        var make = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, new SZArraySig(module.CorLibTypes.Char)), module.CorLibTypes.String.TypeDefOrRef);
        if (variant == "ambient-decoder") { decode.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(binding)); decode.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); }
        foreach (var i in new[] { OpCodes.Ldstr.ToInstruction("@"), OpCodes.Callvirt.ToInstruction(chars), OpCodes.Dup.ToInstruction(),
            OpCodes.Ldc_I4_0.ToInstruction(), Instruction.CreateLdcI4(64), OpCodes.Ldarg_0.ToInstruction(), OpCodes.Xor.ToInstruction(),
            OpCodes.Conv_U2.ToInstruction(), OpCodes.Stelem_I2.ToInstruction(), OpCodes.Newobj.ToInstruction(make), OpCodes.Ret.ToInstruction() })
            decode.Body.Instructions.Add(i);
        var initializer = owner.FindOrCreateStaticConstructor(); initializer.Body.Instructions.Clear();
        foreach (var i in new[] { OpCodes.Ldnull.ToInstruction(), OpCodes.Ldftn.ToInstruction(decode), OpCodes.Newobj.ToInstruction(ctor),
            OpCodes.Stsfld.ToInstruction(binding), OpCodes.Ret.ToInstruction() }) initializer.Body.Instructions.Add(i);
        if (variant == "mutable-binding")
        {
            var reset = new MethodDefUser("Reset", MethodSig.CreateStatic(module.CorLibTypes.Void)) { Attributes = MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(reset);
            foreach (var i in new[] { OpCodes.Ldnull.ToInstruction(), OpCodes.Stsfld.ToInstruction(binding), OpCodes.Ret.ToInstruction() }) reset.Body.Instructions.Add(i);
        }
        return binding;
    }
}
