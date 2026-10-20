using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ModeledArgumentExceptionTests
{
    [Theory]
    [InlineData(0, false)]
    [InlineData(1, true)]
    [InlineData(2, false)]
    [InlineData(3, false)]
    public void OnlyExplicitMessageConstructionAvoidsLocalizedOrParameterFormatting(int kind, bool supported)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = new TypeRefUser(module, "System", "ArgumentException", module.CorLibTypes.AssemblyRef);
            var method = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodAttributes.Static) { Body = new CilBody() };
            module.GlobalType.Methods.Add(method);
            if (kind is 1 or 2) method.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("explicit message"));
            if (kind == 2) method.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("parameter"));
            if (kind == 3) method.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            var parameters = Enumerable.Repeat<TypeSig>(module.CorLibTypes.String, kind == 2 ? 2 : kind == 0 ? 0 : 1).ToArray();
            method.Body.Instructions.Add(OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, parameters), type)));
            method.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var result = new StaticMachine().Execute(context.Module.GlobalType.Methods.Single(method => method.Name == "Read"));
        Assert.Equal(supported, result.Succeeded);
        if (!supported) Assert.Contains("Only an explicit ArgumentException message", result.Diagnostic);
    }
}
