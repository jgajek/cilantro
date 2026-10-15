using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class MutableParameterTypingTests
{
    [Theory]
    [InlineData("string", true)]
    [InlineData("self", true)]
    [InlineData("null", true)]
    [InlineData("unknown", false)]
    [InlineData("conflict", false)]
    [InlineData("address", false)]
    [InlineData("unseeded", false)]
    public void EveryAssignmentAndInitialCallerMustAgree(string scenario, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Assignments");
            var method = new MethodDefUser("Use", MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.Object, module.CorLibTypes.Object))
                { Attributes = MethodAttributes.Private | MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(method);
            var il = method.Body.Instructions;
            if (scenario == "address") { il.Add(OpCodes.Ldarga.ToInstruction(method.Parameters[0])); il.Add(OpCodes.Pop.ToInstruction()); }
            if (scenario == "string") il.Add(OpCodes.Ldstr.ToInstruction("replacement"));
            else if (scenario == "null") il.Add(OpCodes.Ldnull.ToInstruction());
            else if (scenario == "conflict")
            {
                il.Add(OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), module.CorLibTypes.Object.TypeDefOrRef)));
            }
            else il.Add(scenario == "unknown" ? OpCodes.Ldarg_1.ToInstruction() : OpCodes.Ldarg_0.ToInstruction());
            il.Add(OpCodes.Starg.ToInstruction(method.Parameters[0]));
            il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction());
            var caller = new MethodDefUser("Caller", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object))
                { Attributes = MethodAttributes.Private | MethodAttributes.Static, Body = new CilBody() };
            owner.Methods.Add(caller);
            caller.Body.Instructions.Add(scenario == "unseeded" ? OpCodes.Ldarg_0.ToInstruction() : OpCodes.Ldstr.ToInstruction("initial"));
            caller.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(method));
            caller.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(expected ? 1 : 0, new ReferenceParameterTypingPass().Run(context).Changes);
        Assert.Equal(0, new ReferenceParameterTypingPass().Run(context).Changes);
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
        try
        {
            context.Module.Write(path);
            var reading = IlVerification.Read(path, []);
            Assert.Empty(reading.Unreadable);
            Assert.Equal(expected ? 0 : 1, reading.Count);
        }
        finally { File.Delete(path); }
    }
}
