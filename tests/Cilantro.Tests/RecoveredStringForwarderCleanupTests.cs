using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using Cilantro.Core.Strings;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class RecoveredStringForwarderCleanupTests
{
    [Theory]
    [InlineData("completed", true)]
    [InlineData("orphan-only", false)]
    [InlineData("named", false)]
    [InlineData("live", false)]
    [InlineData("handle", false)]
    [InlineData("public", false)]
    [InlineData("changed-body", false)]
    public void ReflectedApplicationTypeDoesNotRetainCompletedProtectorForwarder(string mode, bool removed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var runtime = SyntheticContext.AddType(module, "Runtime");
            var resolver = new MethodDefUser("Resolve", MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.Int32),
                MethodAttributes.Static | MethodAttributes.Assembly) { Body = new CilBody() };
            runtime.Methods.Add(resolver);
            resolver.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("decoded"));
            resolver.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var owner = SyntheticContext.AddType(module, "Application"); owner.Attributes = TypeAttributes.Public;
            var alias = new MethodDefUser("Forward", MethodSig.CreateStatic(module.CorLibTypes.Object, module.CorLibTypes.Int32),
                MethodAttributes.Static | (mode == "public" ? MethodAttributes.Public : MethodAttributes.Private)) { Body = new CilBody() };
            owner.Methods.Add(alias);
            alias.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            alias.Body.Instructions.Add(OpCodes.Call.ToInstruction(resolver));
            alias.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var sibling = new MethodDefUser("ApplicationHelper", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodAttributes.Static | MethodAttributes.Private) { Body = new CilBody() };
            owner.Methods.Add(sibling); sibling.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var entry = new MethodDefUser("Entry", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodAttributes.Static | MethodAttributes.Public) { Body = new CilBody() };
            owner.Methods.Add(entry);
            entry.Body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(owner));
            entry.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            entry.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
            entry.Body.Instructions.Add(OpCodes.Call.ToInstruction(alias));
            entry.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            entry.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var owner = context.Module.GetTypes().Single(t => t.Name == "Application");
        var alias = owner.Methods.Single(m => m.Name == "Forward");
        var entry = owner.Methods.Single(m => m.Name == "Entry");
        var resolver = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Resolve");
        if (mode == "orphan-only")
        {
            entry.Body.Instructions.RemoveAt(3); entry.Body.Instructions.RemoveAt(2); entry.Body.Instructions.RemoveAt(2);
            RecoveryOrphans.Declare(context, alias);
        }
        else
        {
            var table = new CapturedStringTable("test", [], [new DecodedStringRecord(0, 7, "decoded")], new Dictionary<uint,int>());
            var result = StringRecoveryPass.Restore(context, "test", resolver, table);
            Assert.Equal(PassStatus.Success, result.Item1); Assert.Equal(1, result.Item2);
        }
        if (mode == "named") { entry.Body.Instructions.Insert(0, OpCodes.Ldstr.ToInstruction("Forward")); entry.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction()); }
        if (mode == "handle") { entry.Body.Instructions.Insert(0, OpCodes.Ldtoken.ToInstruction(alias)); entry.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction()); }
        if (mode == "live") { entry.Body.Instructions.Insert(0, OpCodes.Ldc_I4_0.ToInstruction()); entry.Body.Instructions.Insert(1, OpCodes.Call.ToInstruction(alias)); entry.Body.Instructions.Insert(2, OpCodes.Pop.ToInstruction()); }
        if (mode == "changed-body") { alias.Body.Instructions.Insert(0, OpCodes.Ldstr.ToInstruction("side effect")); alias.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction()); }
        Assert.True(ModuleReachability.Compute(context.Module).IsReflectivelyExposed(owner));
        context.SetFact("options.removeRuntime", true);
        new RuntimeCleanupPass().Run(context);
        Assert.Equal(removed, !owner.Methods.Contains(alias));
        Assert.Contains(owner.Methods, m => m.Name == "ApplicationHelper");
    }
}
