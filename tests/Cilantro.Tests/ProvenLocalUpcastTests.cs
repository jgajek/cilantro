using Cilantro.Core.Passes;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ProvenLocalUpcastTests
{
    [Theory]
    [InlineData("valid", true)]
    [InlineData("null", true)]
    [InlineData("spill", true)]
    [InlineData("unknown-writer", false)]
    [InlineData("address", false)]
    [InlineData("uninitialized", false)]
    [InlineData("wrong-cast", false)]
    [InlineData("downcast", false)]
    [InlineData("alternate-store", false)]
    public void RequiresEveryLocalWriteToProveTheType(string mode, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var parent = SyntheticContext.AddType(module, "Parent");
            var child = SyntheticContext.AddType(module, "Child"); child.BaseType = parent;
            var other = SyntheticContext.AddType(module, "Other");
            var grandchild = SyntheticContext.AddType(module, "Grandchild"); grandchild.BaseType = child;
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object), MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody { InitLocals = mode != "uninitialized" } }; child.Methods.Add(run);
            var local = new Local(child.ToTypeSig()); run.Body.Variables.Add(local);
            var store = OpCodes.Stloc.ToInstruction(local);
            Emit(run, mode == "null" ? OpCodes.Ldnull.ToInstruction() : OpCodes.Ldarg_0.ToInstruction());
            if (mode == "alternate-store") Emit(run, OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Brtrue.ToInstruction(store));
            if (mode is not ("null" or "unknown-writer")) Emit(run, OpCodes.Castclass.ToInstruction(mode == "wrong-cast" ? other : child));
            Emit(run, store);
            if (mode == "address") Emit(run, OpCodes.Ldloca.ToInstruction(local), OpCodes.Pop.ToInstruction());
            Emit(run, OpCodes.Ldloc.ToInstruction(local));
            if (mode == "spill")
            { var spill = new Local(module.CorLibTypes.Object); run.Body.Variables.Add(spill); Emit(run, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Stloc.ToInstruction(spill)); }
            Emit(run, OpCodes.Castclass.ToInstruction(mode == "downcast" ? grandchild : parent), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(expected ? 1 : 0, new ThisCastCompletionPass().Run(context).Changes);
        Assert.Equal(0, new ThisCastCompletionPass().Run(context).Changes);
    }

    [Fact]
    public void KeepsDerivedLocalTypeForProtectedMemberAccessFromNestedType()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var parent = SyntheticContext.AddType(module, "Parent");
            var child = SyntheticContext.AddType(module, "Child"); child.BaseType = parent;
            var nested = new TypeDefUser("Nested", module.CorLibTypes.Object.TypeDefOrRef) { Attributes = TypeAttributes.NestedPrivate }; child.NestedTypes.Add(nested);
            var target = new MethodDefUser("Protected", MethodSig.CreateInstance(module.CorLibTypes.Void), MethodAttributes.Family) { Body = new CilBody() }; parent.Methods.Add(target); Emit(target, OpCodes.Ret.ToInstruction());
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object), MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody { InitLocals = true } }; nested.Methods.Add(run);
            var local = new Local(child.ToTypeSig()); run.Body.Variables.Add(local);
            Emit(run, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Castclass.ToInstruction(child), OpCodes.Stloc.ToInstruction(local), OpCodes.Ldloc.ToInstruction(local), OpCodes.Castclass.ToInstruction(parent), OpCodes.Callvirt.ToInstruction(target), OpCodes.Ret.ToInstruction());
        });
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
        try
        {
            context.Module.Write(path);
            Assert.Contains(IlVerification.Read(path).Findings.SelectMany(p => p.Value), c => c == "MethodAccess");
            Assert.Equal(1, new ThisCastCompletionPass().Run(context).Changes);
            context.Module.Write(path);
            Assert.Equal(0, IlVerification.Read(path).Count);
        }
        finally { File.Delete(path); }
    }
    private static void Emit(MethodDef method, params Instruction[] instructions)
    { foreach (var instruction in instructions) method.Body.Instructions.Add(instruction); }
}
