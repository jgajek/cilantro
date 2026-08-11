using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core;
using ReactorUnpack.Core.Recovery;

namespace ReactorUnpack.Tests;

public sealed class BooleanRecoveryPassTests
{
    [Fact]
    public void RestoresBooleansByInterpretingTheRealResolver()
    {
        using var context = SyntheticContext.Build(BuildBooleanProtectedModule);
        // Recovery completeness is the gate the pass shares with string recovery.
        context.SetFact("method-protection.complete", true);

        var result = new BooleanRecoveryPass().Run(context);
        var callers = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.Name == "UsesTrue" || method.Name == "UsesFalse")
            .ToArray();

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(2, result.Changes);
        Assert.DoesNotContain(callers.SelectMany(method => method.Body.Instructions),
            instruction => instruction.Operand is IMethod called && called.Name == "Resolve");
        var usesTrue = callers.Single(method => method.Name == "UsesTrue");
        var usesFalse = callers.Single(method => method.Name == "UsesFalse");
        // (2 & 1) == 0 is true; (3 & 1) == 0 is false.
        Assert.Contains(usesTrue.Body.Instructions,
            instruction => instruction.OpCode.Code == Code.Ldc_I4_1);
        Assert.Contains(usesFalse.Body.Instructions,
            instruction => instruction.OpCode.Code == Code.Ldc_I4_0);
    }

    [Fact]
    public void ReportsNoResolverWhenAbsent()
    {
        using var context = SyntheticContext.Build(module =>
            SyntheticContext.AddType(module, "Empty"));
        context.SetFact("method-protection.complete", true);

        var result = new BooleanRecoveryPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(0, result.Changes);
    }

    private static void BuildBooleanProtectedModule(ModuleDefUser module)
    {
        var host = SyntheticContext.AddType(module, "Host");
        var table = new FieldDefUser(
            "Table",
            new FieldSig(new SZArraySig(module.CorLibTypes.Byte)),
            FieldAttributes.Private | FieldAttributes.Static);
        host.Fields.Add(table);

        var resolver = new MethodDefUser(
            "Resolve",
            MethodSig.CreateStatic(module.CorLibTypes.Boolean, module.CorLibTypes.Int32))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        // A resource-backed field read is what marks this as the boolean resolver; the arithmetic
        // is a stand-in for the real decode that the machine evaluates faithfully.
        resolver.Body.Instructions.Add(Instruction.Create(OpCodes.Ldsfld, table));
        resolver.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
        resolver.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
        resolver.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        resolver.Body.Instructions.Add(Instruction.Create(OpCodes.And));
        resolver.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
        resolver.Body.Instructions.Add(Instruction.Create(OpCodes.Ceq));
        resolver.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        host.Methods.Add(resolver);

        host.Methods.Add(BuildCaller(module, "UsesTrue", resolver, 2));
        host.Methods.Add(BuildCaller(module, "UsesFalse", resolver, 3));
    }

    private static MethodDefUser BuildCaller(
        ModuleDef module, string name, MethodDef resolver, int offset)
    {
        var caller = new MethodDefUser(
            name,
            MethodSig.CreateStatic(module.CorLibTypes.Void))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        caller.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, offset));
        caller.Body.Instructions.Add(Instruction.Create(OpCodes.Call, resolver));
        caller.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
        caller.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        return caller;
    }
}
