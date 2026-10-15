using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class JoinedCallerArrayTests
{
    [Theory]
    [InlineData("null", true)]
    [InlineData("typed", true)]
    [InlineData("unknown", false)]
    [InlineData("conflict", false)]
    [InlineData("loop", true)]
    [InlineData("public", false)]
    public void EveryIncomingStackPathMustProveTheArray(string shape, bool recovered)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "JoinedCaller");
            if (shape == "public") owner.Attributes = TypeAttributes.Public;
            var bytes = new SZArraySig(module.CorLibTypes.Byte);
            var target = new MethodDefUser("Use", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object),
                MethodImplAttributes.IL, (shape == "public" ? MethodAttributes.Public : MethodAttributes.Private) | MethodAttributes.Static)
                { Body = new CilBody() };
            owner.Methods.Add(target);
            target.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            target.Body.Instructions.Add(OpCodes.Ldlen.ToInstruction());
            target.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            target.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var other = shape == "unknown" ? module.CorLibTypes.Object :
                shape == "conflict" ? (TypeSig)new SZArraySig(module.CorLibTypes.Int32) : bytes;
            var caller = new MethodDefUser("Caller", MethodSig.CreateStatic(module.CorLibTypes.Void,
                module.CorLibTypes.Boolean, bytes, other), MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static)
                { Body = new CilBody() };
            owner.Methods.Add(caller);
            var alternate = shape is "null" or "public" ? OpCodes.Ldnull.ToInstruction() : OpCodes.Ldarg_2.ToInstruction();
            var join = OpCodes.Call.ToInstruction(target);
            var il = caller.Body.Instructions;
            var start = OpCodes.Ldarg_0.ToInstruction();
            il.Add(start);
            il.Add(OpCodes.Brfalse.ToInstruction(alternate));
            il.Add(OpCodes.Ldarg_1.ToInstruction());
            il.Add(OpCodes.Br.ToInstruction(join));
            il.Add(alternate);
            if (shape == "loop")
            {
                il.Add(OpCodes.Pop.ToInstruction());
                il.Add(OpCodes.Br.ToInstruction(start));
            }
            il.Add(join);
            il.Add(OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(recovered ? 1 : 0, new ArrayParameterTypingPass().Run(context).Changes);
        Assert.Equal(0, new ArrayParameterTypingPass().Run(context).Changes);
        if (recovered)
        {
            var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
            try { context.Module.Write(path); Assert.Equal(0, IlVerification.Read(path, []).Count); }
            finally { File.Delete(path); }
        }
    }
}
