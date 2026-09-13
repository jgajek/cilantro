using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Verification;

namespace Cilantro.Tests;

public sealed class BranchFormsTests
{
    /// <summary>
    /// A short branch whose target a later insertion put out of reach is written long instead.
    /// </summary>
    /// <remarks>
    /// This is what happened to three methods of one payload: a `br.s` reaching back to a dispatcher
    /// head, and the sixteen bytes of temporaries a restored proxy call needed sitting between the
    /// two. The writer said "short branch is too far away" and emitted the truncated displacement,
    /// which jumped one instruction forward instead of a hundred and thirty-six back.
    /// </remarks>
    [Fact]
    public void WritesLongTheBranchThatCanNoLongerReachBack()
    {
        using var module = new ModuleDefUser("branches.dll");
        var type = Hosting(module);
        var method = Looping(module, padding: 200);
        type.Methods.Add(method);
        var branch = method.Body.Instructions[^2];

        Assert.Equal(1, BranchForms.Reach(module));

        Assert.Equal(Code.Br, branch.OpCode.Code);
        Assert.Same(method.Body.Instructions[0], branch.Operand);
    }

    /// <summary>
    /// A method whose branches all reach is left encoded exactly as it was.
    /// </summary>
    [Fact]
    public void LeavesAloneTheMethodWhoseBranchesReach()
    {
        using var module = new ModuleDefUser("branches.dll");
        var type = Hosting(module);
        var method = Looping(module, padding: 4);
        type.Methods.Add(method);
        var before = method.Body.Instructions.Select(instruction => instruction.OpCode).ToArray();

        Assert.Equal(0, BranchForms.Reach(module));

        Assert.Equal(before, method.Body.Instructions.Select(instruction => instruction.OpCode));
    }

    /// <summary>
    /// A short branch left pointing at nothing is not a distance to fix.
    /// </summary>
    /// <remarks>
    /// Re-forming would not give it a target, and the writer says so itself. This exists so that a
    /// broken body cannot be quietly re-encoded on the way past.
    /// </remarks>
    [Fact]
    public void LeavesTheShortBranchWithNoTargetToTheWriterToComplainAbout()
    {
        using var module = new ModuleDefUser("branches.dll");
        var type = Hosting(module);
        var method = Looping(module, padding: 1);
        type.Methods.Add(method);
        method.Body.Instructions[^2].Operand = null;

        Assert.Equal(0, BranchForms.Reach(module));
        Assert.Equal(Code.Br_S, method.Body.Instructions[^2].OpCode.Code);
    }

    private static TypeDefUser Hosting(ModuleDef module)
    {
        var type = new TypeDefUser("Fixture", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(type);
        return type;
    }

    /// <summary>
    /// A method that counts down to zero, with padding between the top of the loop and the branch at
    /// the bottom so that the distance the branch has to cover can be dictated.
    /// </summary>
    private static MethodDefUser Looping(ModuleDef module, int padding)
    {
        var method = new MethodDefUser(
            "Counting",
            MethodSig.CreateStatic(module.CorLibTypes.Void),
            MethodImplAttributes.IL,
            MethodAttributes.Static);
        var counter = new Local(module.CorLibTypes.Int32, "counter");
        var body = new CilBody { InitLocals = true };
        method.Body = body;
        body.Variables.Add(counter);

        var top = Instruction.Create(OpCodes.Ldloc, counter);
        var exit = Instruction.Create(OpCodes.Ret);
        body.Instructions.Add(top);
        body.Instructions.Add(Instruction.Create(OpCodes.Brfalse, exit));
        for (var index = 0; index < padding; index++)
            body.Instructions.Add(Instruction.Create(OpCodes.Nop));
        body.Instructions.Add(Instruction.Create(OpCodes.Br_S, top));
        body.Instructions.Add(exit);
        body.UpdateInstructionOffsets();
        return method;
    }
}
