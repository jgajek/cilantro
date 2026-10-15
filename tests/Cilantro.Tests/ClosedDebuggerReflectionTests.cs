using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ClosedDebuggerReflectionTests
{
    [Theory]
    [InlineData("closed", 2, 1)]
    [InlineData("shadow", 0, 0)]
    [InlineData("foreign", 0, 0)]
    [InlineData("other-property", 1, 0)]
    [InlineData("overwrite", 1, 0)]
    public void OnlyKnownFrameworkPropertyReadsStopBlockingRemoval(string scenario, int accesses, int removed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            module.Resources.Add(new EmbeddedResource("protector", new byte[] { 1, 2 }, ManifestResourceAttributes.Private));
            if (scenario == "shadow") module.Types.Add(new TypeDefUser("System.Diagnostics", "Debugger", module.CorLibTypes.Object.TypeDefOrRef));
            var owner = SyntheticContext.AddType(module, "App");
            var method = new MethodDefUser("Query", MethodSig.CreateStatic(module.CorLibTypes.Void))
            { Attributes = MethodAttributes.Static, Body = new CilBody { InitLocals = true } };
            owner.Methods.Add(method);
            var type = new TypeRefUser(module, "System", "Type", scenario == "foreign" ? new AssemblyRefUser("Foreign") : module.CorLibTypes.AssemblyRef);
            var local = new Local(type.ToTypeSig()); method.Body.Variables.Add(local);
            var get = new MemberRefUser(module, "GetType", MethodSig.CreateStatic(type.ToTypeSig(), module.CorLibTypes.String), type);
            var invoke = new MemberRefUser(module, "InvokeMember", MethodSig.CreateInstance(module.CorLibTypes.Object,
                module.CorLibTypes.String, new ValueTypeSig(module.CorLibTypes.GetTypeRef("System.Reflection", "BindingFlags")),
                module.CorLibTypes.GetTypeRef("System.Reflection", "Binder").ToTypeSig(), module.CorLibTypes.Object,
                new SZArraySig(module.CorLibTypes.Object)), type);
            var il = method.Body.Instructions;
            il.Add(OpCodes.Ldstr.ToInstruction("System.Diagnostics.Debugger")); il.Add(OpCodes.Call.ToInstruction(get)); il.Add(OpCodes.Stloc.ToInstruction(local));
            if (scenario == "overwrite") { il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Stloc.ToInstruction(local)); }
            il.Add(OpCodes.Ldloc.ToInstruction(local)); il.Add(OpCodes.Ldstr.ToInstruction(scenario == "other-property" ? "Launch" : "IsAttached"));
            il.Add(Instruction.CreateLdcI4(4096));
            for (var index = 0; index < 3; index++) il.Add(OpCodes.Ldnull.ToInstruction());
            il.Add(OpCodes.Callvirt.ToInstruction(invoke)); il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(accesses, ClosedDebuggerReflection.Find(context.Module).Count);
        context.SetFact("options.removeRuntime", true);
        context.SetFact<IReadOnlyList<RecoveredResourceOrigin>>("strings.validatedResources",
            [RecoveredResourceOrigin.Capture((EmbeddedResource)context.Module.Resources[0])]);
        Assert.Equal(removed, new ProtectorResourceCleanupPass().Run(context).Changes);
    }
}
