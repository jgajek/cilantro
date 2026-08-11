using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core;
using ReactorUnpack.Core.Recovery;

namespace ReactorUnpack.Tests;

public sealed class MethodInliningPassTests
{
    [Fact]
    public void RedirectsPassThroughForwarderToItsTarget()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            var target = NewIntFunction(module, "Target");
            var forwarder = NewForwarder(module, "Forward", target);
            host.Methods.Add(target);
            host.Methods.Add(forwarder);
            host.Methods.Add(NewCaller(module, "Caller", forwarder));
        });

        var result = new MethodInliningPass().Run(context);
        var caller = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Single(method => method.Name == "Caller");

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(1, result.Changes);
        Assert.Contains(caller.Body.Instructions,
            instruction => instruction.Operand is IMethod called && called.Name == "Target");
        Assert.DoesNotContain(caller.Body.Instructions,
            instruction => instruction.Operand is IMethod called && called.Name == "Forward");
    }

    [Fact]
    public void LeavesNonForwarderCallsUntouched()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            // A method that does more than pass through (adds a constant) is not a forwarder.
            var target = NewIntFunction(module, "Target");
            var notForwarder = new MethodDefUser(
                "NotForward",
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32))
            {
                Attributes = MethodAttributes.Public | MethodAttributes.Static,
                Body = new CilBody()
            };
            notForwarder.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            notForwarder.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
            notForwarder.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            notForwarder.Body.Instructions.Add(Instruction.Create(OpCodes.Call, target));
            notForwarder.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            host.Methods.Add(target);
            host.Methods.Add(notForwarder);
            host.Methods.Add(NewCaller(module, "Caller", notForwarder));
        });

        var result = new MethodInliningPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(0, result.Changes);
    }

    [Fact]
    public void RedirectsAnObjectTypedWrapperOverAFrameworkCall()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            // object Launder(object) calling string String.Trim(): every slot is written object,
            // which is Reactor's disguise and no cast stands between the argument and the call.
            var launder = NewLaunderer(
                module,
                "Launder",
                module.CorLibTypes.Object,
                new Importer(module).Import(typeof(string).GetMethod(nameof(string.Trim), [])!),
                OpCodes.Callvirt);
            host.Methods.Add(launder);
            host.Methods.Add(NewObjectCaller(module, "Caller", launder));
        });

        var result = new MethodInliningPass().Run(context);
        var caller = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Single(method => method.Name == "Caller");

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(1, result.Changes);
        Assert.Contains(caller.Body.Instructions,
            instruction => instruction.Operand is IMethod called && called.Name == "Trim");
        Assert.DoesNotContain(caller.Body.Instructions,
            instruction => instruction.Operand is IMethod called && called.Name == "Launder");
    }

    [Fact]
    public void LeavesAWrapperAloneWhenItNarrowsWhatTheTargetReturns()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            // The wrapper promises string while the target hands back object, so substituting it
            // would push the obfuscator's type confusion out into the caller.
            var narrowing = NewLaunderer(
                module,
                "Narrow",
                module.CorLibTypes.String,
                new Importer(module).Import(
                    typeof(ICloneable).GetMethod(nameof(ICloneable.Clone))!),
                OpCodes.Callvirt);
            host.Methods.Add(narrowing);
            host.Methods.Add(NewObjectCaller(module, "Caller", narrowing));
        });

        var result = new MethodInliningPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(0, result.Changes);
    }

    /// <summary>
    /// Builds <c>&lt;returns&gt; name(object)</c> whose body loads the argument and calls
    /// <paramref name="target"/> with no conversion between.
    /// </summary>
    private static MethodDefUser NewLaunderer(
        ModuleDef module,
        string name,
        TypeSig returns,
        IMethod target,
        OpCode call)
    {
        var launderer = new MethodDefUser(
            name, MethodSig.CreateStatic(returns, module.CorLibTypes.Object))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        launderer.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
        launderer.Body.Instructions.Add(Instruction.Create(call, target));
        launderer.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        return launderer;
    }

    private static MethodDefUser NewObjectCaller(ModuleDef module, string name, MethodDef callee)
    {
        var caller = new MethodDefUser(name, MethodSig.CreateStatic(module.CorLibTypes.Void))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        caller.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "  padded  "));
        caller.Body.Instructions.Add(Instruction.Create(OpCodes.Call, callee));
        caller.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
        caller.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        return caller;
    }

    private static MethodDefUser NewIntFunction(ModuleDef module, string name)
    {
        var method = new MethodDefUser(
            name, MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        return method;
    }

    private static MethodDefUser NewForwarder(ModuleDef module, string name, MethodDef target)
    {
        var forwarder = new MethodDefUser(
            name, MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        forwarder.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
        forwarder.Body.Instructions.Add(Instruction.Create(OpCodes.Call, target));
        forwarder.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        return forwarder;
    }

    private static MethodDefUser NewCaller(ModuleDef module, string name, MethodDef callee)
    {
        var caller = new MethodDefUser(name, MethodSig.CreateStatic(module.CorLibTypes.Void))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        caller.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_5));
        caller.Body.Instructions.Add(Instruction.Create(OpCodes.Call, callee));
        caller.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
        caller.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        return caller;
    }
}
