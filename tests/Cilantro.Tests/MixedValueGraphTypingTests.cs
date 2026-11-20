using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class MixedValueGraphTypingTests
{
    [Theory]
    [InlineData(false, "seed", true)]
    [InlineData(true, "seed", true)]
    [InlineData(false, "cycle", false)]
    [InlineData(true, "cycle", false)]
    [InlineData(false, "unknown", false)]
    [InlineData(true, "unknown", false)]
    [InlineData(false, "conflict", false)]
    [InlineData(true, "conflict", false)]
    [InlineData(false, "named", false)]
    [InlineData(false, "handle", false)]
    [InlineData(false, "argument-address", false)]
    [InlineData(false, "reassigned", false)]
    [InlineData(false, "local-address", false)]
    [InlineData(false, "friend", false)]
    [InlineData(false, "export", false)]
    [InlineData(false, "fresh-inputs", false)]
    public void AFieldLocalParameterCycleRequiresIndependentClosedInputs(bool array, string shape, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Mixed");
            TypeSig concrete = array ? new SZArraySig(module.CorLibTypes.String) : module.CorLibTypes.String;
            var field = new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Private | FieldAttributes.Static);
            owner.Fields.Add(field);
            MethodDef Add(string name, TypeSig result, params TypeSig[] args)
            {
                var method = new MethodDefUser(name, MethodSig.CreateStatic(result, args),
                    MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody { InitLocals = true } };
                owner.Methods.Add(method); return method;
            }
            var setter = Add("Set", module.CorLibTypes.Void, module.CorLibTypes.Object);
            var il = setter.Body.Instructions;
            if (shape == "argument-address") { il.Add(OpCodes.Ldarga.ToInstruction(setter.Parameters[0])); il.Add(OpCodes.Pop.ToInstruction()); }
            if (shape == "reassigned")
            {
                il.Add(OpCodes.Ldnull.ToInstruction());
                il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetObjectValue", MethodSig.CreateStatic(module.CorLibTypes.Object, module.CorLibTypes.Object), module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "RuntimeHelpers"))));
                il.Add(OpCodes.Starg.ToInstruction(setter.Parameters[0]));
            }
            il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Stsfld.ToInstruction(field)); il.Add(OpCodes.Ret.ToInstruction());
            if (shape is "friend" or "export")
            {
                var attribute = shape == "friend" ? "System.Runtime.CompilerServices.InternalsVisibleToAttribute" : "System.Runtime.InteropServices.UnmanagedCallersOnlyAttribute";
                var dot = attribute.LastIndexOf('.');
                var ctor = new MemberRefUser(module, ".ctor", shape == "friend" ? MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String) : MethodSig.CreateInstance(module.CorLibTypes.Void), module.CorLibTypes.GetTypeRef(attribute[..dot], attribute[(dot + 1)..]));
                var custom = new CustomAttribute(ctor);
                if (shape == "friend")
                { setter.Access = MethodAttributes.Assembly; custom.ConstructorArguments.Add(new CAArgument(module.CorLibTypes.String, "Friend")); module.Assembly.CustomAttributes.Add(custom); }
                else setter.CustomAttributes.Add(custom);
            }
            var cycle = Add("Cycle", module.CorLibTypes.Void);
            var spill = new Local(module.CorLibTypes.Object); cycle.Body.Variables.Add(spill);
            il = cycle.Body.Instructions;
            il.Add(OpCodes.Ldsfld.ToInstruction(field)); il.Add(OpCodes.Stloc.ToInstruction(spill));
            if (shape == "local-address") { il.Add(OpCodes.Ldloca.ToInstruction(spill)); il.Add(OpCodes.Pop.ToInstruction()); }
            il.Add(OpCodes.Ldloc.ToInstruction(spill)); il.Add(OpCodes.Call.ToInstruction(setter)); il.Add(OpCodes.Ret.ToInstruction());
            var seed = Add("Seed", module.CorLibTypes.Void, module.CorLibTypes.Object);
            il = seed.Body.Instructions;
            if (shape != "cycle")
            {
                if (array) { il.Add(OpCodes.Ldc_I4_0.ToInstruction()); il.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.String.TypeDefOrRef)); }
                else il.Add(OpCodes.Ldstr.ToInstruction("seed"));
                il.Add(OpCodes.Call.ToInstruction(setter));
            }
            if (shape == "unknown") { il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Call.ToInstruction(setter)); }
            if (shape == "conflict")
            { il.Add(OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), module.CorLibTypes.Object.TypeDefOrRef))); il.Add(OpCodes.Call.ToInstruction(setter)); }
            if (shape == "named") { il.Add(OpCodes.Ldstr.ToInstruction("Set")); il.Add(OpCodes.Pop.ToInstruction()); }
            if (shape == "handle") { il.Add(OpCodes.Ldftn.ToInstruction(setter)); il.Add(OpCodes.Pop.ToInstruction()); }
            il.Add(OpCodes.Ret.ToInstruction());
            var read = Add("Read", concrete); read.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(field)); read.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        if (shape == "fresh-inputs")
        {
            new ReferenceParameterTypingPass().Run(context);
            var methods = context.Module.GetTypes().SelectMany(t => t.Methods).ToArray();
            var seed = methods.Single(m => m.Name == "Seed"); var setter = methods.Single(m => m.Name == "Set");
            seed.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(setter));
            seed.Body.Instructions.Insert(0, OpCodes.Ldarg_0.ToInstruction());
        }
        var pass = array ? (ArrayFieldTypingPass)new ArrayFieldTypingPass() : new ReferenceFieldTypingPass();
        pass.Run(context);
        var readMethod = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Read");
        Assert.Equal(expected, readMethod.Body.Instructions.Any(i => i.OpCode.Code == Code.Castclass));
        Assert.Equal(0, pass.Run(context).Changes);
        if (expected)
        {
            var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
            try { context.Module.Write(path); Assert.Equal(0, IlVerification.Read(path, []).Count); }
            finally { File.Delete(path); }
        }
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, true)]
    [InlineData(false, false)]
    [InlineData(true, false)]
    public void IndirectLoadsUseTheDeclaredPointeeType(bool array, bool typed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Indirect");
            TypeSig concrete = array ? new SZArraySig(module.CorLibTypes.String) : module.CorLibTypes.String;
            var field = new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Private | FieldAttributes.Static);
            owner.Fields.Add(field);
            var write = new MethodDefUser("Write", MethodSig.CreateStatic(module.CorLibTypes.Void, new ByRefSig(typed ? concrete : module.CorLibTypes.Object)), MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(write);
            write.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction()); write.Body.Instructions.Add(OpCodes.Ldind_Ref.ToInstruction()); write.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(field)); write.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var read = new MethodDefUser("Read", MethodSig.CreateStatic(concrete), MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(read); read.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(field)); read.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var pass = array ? (ArrayFieldTypingPass)new ArrayFieldTypingPass() : new ReferenceFieldTypingPass();
        Assert.Equal(typed ? 1 : 0, pass.Run(context).Changes);
        Assert.Equal(0, pass.Run(context).Changes);
        if (typed)
        {
            var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
            try { context.Module.Write(path); Assert.Equal(0, IlVerification.Read(path, []).Count); }
            finally { File.Delete(path); }
        }
    }
}
