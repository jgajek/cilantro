using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ModeledGuidTextTests
{
    [Fact]
    public void ConstrainedGuidToStringUsesTheModeledValue()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var guid = new TypeRefUser(module, "System", "Guid", module.CorLibTypes.AssemblyRef);
            var method = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.String), MethodAttributes.Static | MethodAttributes.Public) { Body = new CilBody() };
            module.GlobalType.Methods.Add(method);
            method.Body.Variables.Add(new Local(new ValueTypeSig(guid)));
            method.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "get_Empty", MethodSig.CreateStatic(new ValueTypeSig(guid)), guid)));
            method.Body.Instructions.Add(OpCodes.Stloc_0.ToInstruction());
            method.Body.Instructions.Add(OpCodes.Ldloca_S.ToInstruction(method.Body.Variables[0]));
            method.Body.Instructions.Add(OpCodes.Constrained.ToInstruction(guid));
            method.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "ToString", MethodSig.CreateInstance(module.CorLibTypes.String), module.CorLibTypes.Object.TypeDefOrRef)));
            method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var machine = new StaticMachine();
        var result = machine.Execute(context.Module.GlobalType.Methods.Single(method => method.Name == "Read"));
        Assert.True(result.Succeeded, result.Diagnostic);
        Assert.True(machine.State.Heap.TryGetString(result.Value, out var text));
        Assert.Equal("00000000-0000-0000-0000-000000000000", text);
    }
}
