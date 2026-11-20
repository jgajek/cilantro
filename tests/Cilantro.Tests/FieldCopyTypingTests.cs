using Cilantro.Core;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class FieldCopyTypingTests
{
    [Theory]
    [InlineData(false, "typed-source", true)]
    [InlineData(true, "typed-source", true)]
    [InlineData(false, "chain", true)]
    [InlineData(true, "chain", true)]
    [InlineData(false, "null", true)]
    [InlineData(true, "null", true)]
    [InlineData(false, "unknown", false)]
    [InlineData(true, "unknown", false)]
    [InlineData(false, "conflict", false)]
    [InlineData(true, "conflict", false)]
    [InlineData(false, "address", false)]
    [InlineData(true, "address", false)]
    [InlineData(false, "named", false)]
    [InlineData(true, "named", false)]
    [InlineData(false, "cycle", false)]
    [InlineData(true, "cycle", false)]
    [InlineData(false, "alternate-entry", false)]
    [InlineData(true, "alternate-entry", false)]
    [InlineData(false, "seeded-cycle", true)]
    [InlineData(true, "seeded-cycle", true)]
    [InlineData(false, "conflicting-cycle", false)]
    [InlineData(true, "conflicting-cycle", false)]
    [InlineData(false, "unknown-cycle", false)]
    [InlineData(true, "unknown-cycle", false)]
    [InlineData(false, "local-chain", true)]
    [InlineData(false, "local-seeded-cycle", true)]
    [InlineData(false, "local-cycle", false)]
    [InlineData(false, "local-unknown", false)]
    [InlineData(false, "local-address", false)]
    [InlineData(false, "local-uninitialized", false)]
    [InlineData(true, "local-chain", true)]
    [InlineData(true, "local-seeded-cycle", true)]
    [InlineData(true, "local-cycle", false)]
    [InlineData(true, "local-unknown", false)]
    [InlineData(true, "local-address", false)]
    [InlineData(true, "local-uninitialized", false)]
    public void CopyProofsRequireAClosedUnanimousSource(bool array, string shape, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Copies");
            TypeSig concrete = array ? new SZArraySig(module.CorLibTypes.String) : module.CorLibTypes.String;
            var destination = new FieldDefUser("Destination", new FieldSig(module.CorLibTypes.Object),
                FieldAttributes.Private | FieldAttributes.Static);
            var middle = new FieldDefUser("Middle", new FieldSig(module.CorLibTypes.Object),
                FieldAttributes.Private | FieldAttributes.Static);
            var source = new FieldDefUser("Source", new FieldSig(shape == "typed-source" ? concrete : module.CorLibTypes.Object),
                FieldAttributes.Private | FieldAttributes.Static);
            // Reverse dependency order ensures proof does not depend on field/method order.
            owner.Fields.Add(destination); owner.Fields.Add(middle); owner.Fields.Add(source);
            MethodDef Add(string name, TypeSig result, params TypeSig[] parameters)
            {
                var method = new MethodDefUser(name, MethodSig.CreateStatic(result, parameters),
                    MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
                owner.Methods.Add(method); return method;
            }
            void Copy(string name, FieldDef from, FieldDef to)
            {
                var copy = Add(name, module.CorLibTypes.Void);
                copy.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(from));
                if (shape.StartsWith("local-", StringComparison.Ordinal))
                {
                    copy.Body.InitLocals = shape != "local-uninitialized";
                    var local = new Local(module.CorLibTypes.Object); copy.Body.Variables.Add(local);
                    copy.Body.Instructions.Add(OpCodes.Stloc.ToInstruction(local));
                    if (shape == "local-unknown")
                    { copy.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); copy.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetObjectValue", MethodSig.CreateStatic(module.CorLibTypes.Object, module.CorLibTypes.Object), module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "RuntimeHelpers")))); copy.Body.Instructions.Add(OpCodes.Stloc.ToInstruction(local)); }
                    if (shape == "local-address")
                    { copy.Body.Instructions.Add(OpCodes.Ldloca.ToInstruction(local)); copy.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); }
                    copy.Body.Instructions.Add(OpCodes.Ldloc.ToInstruction(local));
                }
                copy.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(to));
                copy.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            }
            Copy("CopyLast", middle, destination);
            Copy("CopyFirst", source, middle);
            if (shape is "cycle" or "local-cycle") Copy("Cycle", destination, source);
            else if (shape != "typed-source")
            {
                var write = Add("Write", module.CorLibTypes.Void, module.CorLibTypes.Object);
                var il = write.Body.Instructions;
                var store = OpCodes.Stsfld.ToInstruction(source);
                if (shape == "alternate-entry")
                { il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Br.ToInstruction(store)); }
                if (array)
                { il.Add(OpCodes.Ldc_I4_1.ToInstruction()); il.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.String.TypeDefOrRef)); }
                else il.Add(OpCodes.Ldstr.ToInstruction("seed"));
                il.Add(store);
                if (shape is "unknown" or "conflict" or "null" or "conflicting-cycle" or "unknown-cycle")
                {
                    if (shape == "null") il.Add(OpCodes.Ldnull.ToInstruction());
                    else if (shape is "unknown" or "unknown-cycle") il.Add(OpCodes.Ldarg_0.ToInstruction());
                    else if (array)
                    { il.Add(OpCodes.Ldc_I4_1.ToInstruction()); il.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef)); }
                    else il.Add(OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor",
                        MethodSig.CreateInstance(module.CorLibTypes.Void), module.CorLibTypes.Object.TypeDefOrRef)));
                    il.Add(OpCodes.Stsfld.ToInstruction(source));
                }
                if (shape == "address")
                { il.Add(OpCodes.Ldsflda.ToInstruction(source)); il.Add(OpCodes.Pop.ToInstruction()); }
                if (shape == "named")
                { il.Add(OpCodes.Ldstr.ToInstruction("Source")); il.Add(OpCodes.Pop.ToInstruction()); }
                il.Add(OpCodes.Ret.ToInstruction());
            }
            if (shape is "seeded-cycle" or "conflicting-cycle" or "unknown-cycle" or "local-seeded-cycle") Copy("Cycle", destination, source);
            var read = Add("Read", concrete);
            read.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(destination));
            read.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        DeobfuscationPass pass = array ? new ArrayFieldTypingPass() : new ReferenceFieldTypingPass();
        var result = pass.Run(context);
        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(expected ? shape == "typed-source" ? 2 : shape is "seeded-cycle" or "local-seeded-cycle" ? 4 : 3 : shape is "local-unknown" or "local-address" or "local-uninitialized" ? 1 : 0, result.Changes);
        Assert.Equal(expected, context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Read")
            .Body.Instructions.Any(i => i.OpCode.Code == Code.Castclass));
        Assert.All(context.Module.GetTypes().SelectMany(t => t.Fields).Where(f => f.Name != "Source" || shape != "typed-source"),
            f => Assert.Equal(ElementType.Object, f.FieldType.ElementType));
        Assert.Equal(0, pass.Run(context).Changes);
        if (expected)
        {
            var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
            try { context.Module.Write(path); Assert.Equal(0, IlVerification.Read(path, []).Count); }
            finally { File.Delete(path); }
        }
    }
}
