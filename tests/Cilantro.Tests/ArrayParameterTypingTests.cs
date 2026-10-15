using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ArrayParameterTypingTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void GenericOwnerReturnUsesTheCallSiteTypeArgument(bool open)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "UsesArray");
            var list = new ClassSig(module.CorLibTypes.GetTypeRef("System.Collections.Generic", "List`1"));
            var listType = new GenericInstSig(list, open ? new GenericVar(0) : module.CorLibTypes.Int32);
            var factory = new MemberRefUser(module, "ToArray", MethodSig.CreateInstance(new SZArraySig(new GenericVar(0))), new TypeSpecUser(listType));
            var consumer = new MethodDefUser("Length", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object))
                { Attributes = MethodAttributes.Private | MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(consumer);
            consumer.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            consumer.Body.Instructions.Add(OpCodes.Ldlen.ToInstruction());
            consumer.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            consumer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var caller = new MethodDefUser("Caller", MethodSig.CreateStatic(module.CorLibTypes.Void, listType))
                { Attributes = MethodAttributes.Private | MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(caller);
            caller.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            caller.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(factory));
            caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(consumer));
            caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(open ? 0 : 1, new ArrayParameterTypingPass().Run(context).Changes);
        Assert.Equal(0, new ArrayParameterTypingPass().Run(context).Changes);
        if (!open)
        {
            var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
            try { context.Module.Write(path); Assert.Equal(0, IlVerification.Read(path, []).Count); }
            finally { File.Delete(path); }
        }
    }
    [Theory]
    [InlineData("field", true)]
    [InlineData("field", false)]
    [InlineData("base-field", true)]
    [InlineData("base-field", false)]
    [InlineData("array-base", true)]
    [InlineData("array-base", false)]
    [InlineData("constructor", true)]
    [InlineData("call", true)]
    [InlineData("local", true)]
    [InlineData("return", true)]
    [InlineData("constructor", false)]
    [InlineData("call", false)]
    [InlineData("local", false)]
    [InlineData("return", false)]
    public void ApiAndSpillConsumersRequireIndependentCallerProof(string consumer, bool known)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Consumers");
            var bytes = new SZArraySig(module.CorLibTypes.Byte);
            var target = new MethodDefUser("Use", MethodSig.CreateStatic(
                consumer == "return" ? bytes : module.CorLibTypes.Void, module.CorLibTypes.Object),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            type.Methods.Add(target);
            target.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            if (consumer is "field" or "base-field")
            {
                var field = new FieldDefUser("Stored", new FieldSig(consumer == "field" ? bytes :
                    module.CorLibTypes.GetTypeRef("System", "Array").ToTypeSig()), FieldAttributes.Private | FieldAttributes.Static);
                type.Fields.Add(field);
                target.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(field));
                target.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(field));
            }
            else if (consumer == "array-base")
            {
                var buffer = module.CorLibTypes.GetTypeRef("System", "Buffer");
                var call = new MemberRefUser(module, "ByteLength", MethodSig.CreateStatic(module.CorLibTypes.Int32,
                    module.CorLibTypes.GetTypeRef("System", "Array").ToTypeSig()), buffer);
                target.Body.Instructions.Add(OpCodes.Call.ToInstruction(call));
            }
            else if (consumer == "constructor")
            {
                var stream = new TypeRefUser(module, "System.IO", "MemoryStream", module.CorLibTypes.AssemblyRef);
                var ctor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, bytes), stream);
                target.Body.Instructions.Add(OpCodes.Newobj.ToInstruction(ctor));
            }
            else if (consumer == "call")
            {
                var convert = new TypeRefUser(module, "System", "Convert", module.CorLibTypes.AssemblyRef);
                var call = new MemberRefUser(module, "ToBase64String", MethodSig.CreateStatic(module.CorLibTypes.String, bytes), convert);
                target.Body.Instructions.Add(OpCodes.Call.ToInstruction(call));
            }
            else if (consumer == "local")
            {
                var local = new Local(bytes);
                target.Body.Variables.Add(local);
                target.Body.Instructions.Add(OpCodes.Stloc.ToInstruction(local));
                target.Body.Instructions.Add(OpCodes.Ldloc.ToInstruction(local));
            }
            if (consumer != "return") target.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            target.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var caller = new MethodDefUser("Caller", MethodSig.CreateStatic(module.CorLibTypes.Void,
                known ? bytes : module.CorLibTypes.Object), MethodImplAttributes.IL,
                MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            type.Methods.Add(caller);
            caller.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(target));
            if (consumer == "return") caller.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
        try
        {
            context.Module.Write(path);
            Assert.Equal(1, IlVerification.Read(path, []).Count);
            Assert.Equal(known ? 1 : 0, new ArrayParameterTypingPass().Run(context).Changes);
            Assert.Equal(0, new ArrayParameterTypingPass().Run(context).Changes);
            context.Module.Write(path);
            Assert.Equal(known ? 0 : 1, IlVerification.Read(path, []).Count);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void TypedPinnedArrayPointerConversionHasAnExistingUnverifiableInstruction()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Pointer");
            var array = new SZArraySig(module.CorLibTypes.Byte);
            var method = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.Void, array),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            type.Methods.Add(method);
            var pinned = new Local(new PinnedSig(array));
            method.Body.Variables.Add(pinned);
            method.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            method.Body.Instructions.Add(OpCodes.Stloc.ToInstruction(pinned));
            method.Body.Instructions.Add(OpCodes.Ldloc.ToInstruction(pinned));
            method.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
            method.Body.Instructions.Add(OpCodes.Ldelema.ToInstruction(module.CorLibTypes.Byte.TypeDefOrRef));
            method.Body.Instructions.Add(OpCodes.Conv_U.ToInstruction());
            method.Body.Instructions.Add(OpCodes.Ldind_U1.ToInstruction());
            method.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
        try
        {
            context.Module.Write(path);
            // This deliberately unsafe pointer conversion already carries this finding
            // without running the repair pass or inserting any cast.
            var reading = IlVerification.Read(path, []);
            Assert.Empty(reading.Unreadable);
            Assert.Contains("ExpectedNumericType", reading.Findings["Pointer::Read"]);
        }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PropagatesProvenArrayTypesThroughCallChainsInOneRun(bool pureForwarders)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Chain");
            MethodDef previous = null!;
            for (var index = 0; index < 4; index++)
            {
                var method = new MethodDefUser("Step" + index,
                    MethodSig.CreateStatic(module.CorLibTypes.Void, index == 3 ? new SZArraySig(module.CorLibTypes.Byte) : module.CorLibTypes.Object),
                    MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
                type.Methods.Add(method);
                if (!pureForwarders || index == 0)
                {
                    method.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                    method.Body.Instructions.Add(OpCodes.Ldlen.ToInstruction());
                    method.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
                }
                if (previous is not null)
                {
                    method.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                    method.Body.Instructions.Add(OpCodes.Call.ToInstruction(previous));
                }
                method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                previous = method;
            }
        });
        Assert.Equal(pureForwarders ? 1 : 3, new ArrayParameterTypingPass().Run(context).Changes);
        Assert.Equal(0, new ArrayParameterTypingPass().Run(context).Changes);
        Assert.Equal(pureForwarders ? 1 : 5, context.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody)
            .SelectMany(m => m.Body.Instructions).Count(i => i.OpCode.Code == Code.Castclass));
    }

    [Theory]
    [InlineData("known", true)]
    [InlineData("array-box", true)]
    [InlineData("array-byref", true)]
    [InlineData("element-only", true)]
    [InlineData("generic-closed", true)]
    [InlineData("generic-open", true)]
    [InlineData("object-byref", false)]
    [InlineData("short-branch", true)]
    [InlineData("unknown", false)]
    [InlineData("conflict", false)]
    [InlineData("address", false)]
    [InlineData("handle", false)]
    [InlineData("name", false)]
    [InlineData("recursive", true)]
    public void RepairsOnlyClosedUnanimousArrayInputs(string scenario, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Arrays");
            MethodDef Add(string name, TypeSig parameter)
            {
                var method = new MethodDefUser(name, MethodSig.CreateStatic(module.CorLibTypes.Void, parameter),
                    MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
                type.Methods.Add(method);
                return method;
            }
            var target = Add("ReadArray", module.CorLibTypes.Object);
            if (scenario is "generic-closed" or "generic-open")
            {
                target.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
                target.MethodSig = MethodSig.CreateStaticGeneric(1, module.CorLibTypes.Void, module.CorLibTypes.Object);
            }
            target.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            if (scenario == "element-only") target.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
            target.Body.Instructions.Add((scenario == "element-only" ? OpCodes.Ldelem_U4 : OpCodes.Ldlen).ToInstruction());
            target.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            if (scenario == "address")
            {
                target.Body.Instructions.Add(OpCodes.Ldarga.ToInstruction(target.Parameters[0]));
                target.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            }
            if (scenario == "recursive")
            {
                target.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                target.Body.Instructions.Add(OpCodes.Call.ToInstruction(target));
            }
            target.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            if (scenario == "short-branch")
            {
                var end = target.Body.Instructions[^1];
                for (var i = 0; i < 124; i++) target.Body.Instructions.Insert(3, OpCodes.Nop.ToInstruction());
                target.Body.Instructions.Insert(0, OpCodes.Br_S.ToInstruction(end));
            }
            var caller = Add("Caller", scenario == "unknown" ? module.CorLibTypes.Object : new SZArraySig(module.CorLibTypes.Int32));
            if (scenario is "array-byref" or "object-byref") caller.MethodSig.Params[0] =
                new ByRefSig(scenario == "array-byref" ? new SZArraySig(module.CorLibTypes.Int32) : module.CorLibTypes.Object);
            caller.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            if (scenario is "array-byref" or "object-byref") caller.Body.Instructions.Add(OpCodes.Ldind_Ref.ToInstruction());
            if (scenario == "array-box") caller.Body.Instructions.Add(OpCodes.Box.ToInstruction(caller.Parameters[0].Type.ToTypeDefOrRef()));
            IMethod invoked = target;
            if (scenario is "generic-closed" or "generic-open")
            {
                if (scenario == "generic-open")
                {
                    caller.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "TCaller"));
                    caller.MethodSig = MethodSig.CreateStaticGeneric(1, module.CorLibTypes.Void, caller.MethodSig.Params[0]);
                }
                invoked = new MethodSpecUser(target, new GenericInstMethodSig(
                    scenario == "generic-open" ? new GenericMVar(0) : module.CorLibTypes.Int32));
            }
            caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(invoked));
            if (scenario == "conflict")
            {
                caller.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
                caller.Body.Instructions.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.String.TypeDefOrRef));
                caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(target));
            }
            if (scenario is "handle" or "name")
            {
                caller.Body.Instructions.Add(scenario == "handle" ? OpCodes.Ldtoken.ToInstruction(target) : OpCodes.Ldstr.ToInstruction("ReadArray"));
                caller.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            }
            caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var target = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "ReadArray");
        var signature = target.MethodSig.ToString();
        var result = new ArrayParameterTypingPass().Run(context);
        Assert.True(result.Changes == (expected ? 1 : 0), string.Join("; ", result.Diagnostics));
        Assert.Equal(signature, target.MethodSig.ToString());
        Assert.Equal(expected ? scenario == "recursive" ? 2 : 1 : 0, target.Body.Instructions.Count(i => i.OpCode.Code == Code.Castclass));
        Assert.Equal(0, new ArrayParameterTypingPass().Run(context).Changes);
        using var output = new MemoryStream();
        context.Module.Write(output);
        Assert.True(output.Length > 0);
    }
}
