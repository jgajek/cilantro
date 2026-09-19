using System.Reflection;
using System.Runtime.Loader;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using MethodAttributes = dnlib.DotNet.MethodAttributes;
using TypeAttributes = dnlib.DotNet.TypeAttributes;

namespace Cilantro.Tests;

public sealed class InliningSafetyTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PreservesTypeInitializerEffectsAndExceptions(bool throws)
    {
        using var context = Build(initializer: true, throws: throws);
        var before = Invoke(context.Module);

        var result = new MethodInliningPass().Run(context);

        Assert.Equal(throws ? "TypeInitializationException" : "42", before);
        Assert.Equal(before, Invoke(context.Module));
        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(0, result.Changes);
        Assert.Empty(context.Changes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PreservesAccessToPrivateMethodsAndPrivateNestedTypes(bool nested)
    {
        using var context = Build(nested: nested);
        Assert.Equal("7", Invoke(context.Module));

        var result = new MethodInliningPass().Run(context);

        Assert.Equal("7", Invoke(context.Module));
        Assert.Equal(0, result.Changes);
    }

    [Fact]
    public void StillInlinesAnAssemblyVisibleTargetAcrossTypes()
    {
        using var context = Build();
        var target = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Target");
        target.Attributes = MethodAttributes.Assembly | MethodAttributes.Static;

        var result = new MethodInliningPass().Run(context);

        Assert.Equal(1, result.Changes);
        Assert.Equal("7", Invoke(context.Module));
        Assert.Single(context.Changes);
    }

    [Fact]
    public void CollapsingAChainDoesNotBorrowTheLastWrappersPrivateAccess()
    {
        using var context = Build(chain: true);
        Assert.Equal("7", Invoke(context.Module));

        var result = new MethodInliningPass().Run(context);

        Assert.Equal("7", Invoke(context.Module));
        Assert.Equal(0, result.Changes);
        Assert.Empty(context.Changes);
    }

    [Fact]
    public void CollapsingAChainStopsBeforeAnEffectfulInitializer()
    {
        using var context = Build(initializer: true, chain: true);
        Assert.Equal("42", Invoke(context.Module));

        var result = new MethodInliningPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(1, result.Changes);
        Assert.Equal("42", Invoke(context.Module));
    }

    [Fact]
    public void AnEmptyInitializerDoesNotPreventInlining()
    {
        using var context = Build(initializer: true);
        var initializer = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.IsStaticConstructor);
        initializer.Body.Instructions.Clear();
        initializer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());

        var result = new MethodInliningPass().Run(context);

        Assert.Equal(1, result.Changes);
        Assert.Equal("0", Invoke(context.Module));
    }

    [Fact]
    public void RecheckWaitsUntilInitializerWorkHasBeenRemoved()
    {
        using var context = Build(initializer: true);
        Assert.Equal(0, new MethodInliningPass().Run(context).Changes);
        var initializer = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.IsStaticConstructor);
        initializer.Body.Instructions.Clear();
        initializer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());

        var result = new MethodInliningRecheckPass().Run(context);

        Assert.Equal(1, result.Changes);
        Assert.Equal("method-inlining-recheck", Assert.Single(context.Changes).Pass);
        Assert.Equal("0", Invoke(context.Module));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RecheckMakesRequiredInitializationExplicit(bool throws)
    {
        using var context = Build(initializer: true, throws: throws);
        var before = Invoke(context.Module);

        var result = new MethodInliningRecheckPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(1, result.Changes);
        Assert.Equal(before, Invoke(context.Module));
        var caller = context.Module.GetTypes().Single(t => t.Name == "Caller").Methods.Single(m => m.Name == "Entry");
        Assert.Contains(caller.Body.Instructions, i => i.Operand is IMethod m && m.Name == "RunClassConstructor");
        Assert.DoesNotContain(caller.Body.Instructions, i => i.Operand is IMethod m && m.Name == "Forward");
    }

    [Fact]
    public void FailedRecheckRestoresInsertedInitializationInstructions()
    {
        using var context = Build(initializer: true);
        var caller = context.Module.GetTypes().Single(t => t.Name == "Caller");
        var entry = caller.Methods.Single(m => m.Name == "Entry");
        var original = entry.Body.Instructions.ToArray();
        AddMethod(caller, "AddedAfterSnapshot", context.Module.CorLibTypes.Int32,
            OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ret.ToInstruction());

        var result = new MethodInliningRecheckPass().Run(context);

        Assert.Equal(PassStatus.Failed, result.Status);
        Assert.Equal(original, entry.Body.Instructions);
        Assert.Equal("Forward", ((IMethod)entry.Body.Instructions[0].Operand).Name);
        Assert.Empty(context.Changes);
        Assert.Equal("42", Invoke(context.Module));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RecheckElidesOnlyAttributedEmptyHelpersAndPreservesInitialization(bool attributed)
    {
        using var context = Build(initializer: true, customize: module =>
        {
            var methods = module.GetTypes().SelectMany(t => t.Methods).ToArray();
            var forward = methods.Single(m => m.Name == "Forward");
            forward.MethodSig = MethodSig.CreateStatic(module.CorLibTypes.Void);
            forward.Body.Instructions.Clear();
            forward.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var entry = methods.Single(m => m.Name == "Entry");
            entry.Body.Instructions.Insert(1, OpCodes.Call.ToInstruction(methods.Single(m => m.Name == "Target")));
        });
        if (attributed)
            RecoveryOrphans.Declare(context, context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Forward"));
        Assert.Equal("42", Invoke(context.Module));

        var result = new MethodInliningRecheckPass().Run(context);

        Assert.Equal(attributed ? 1 : 0, result.Changes);
        Assert.Equal("42", Invoke(context.Module));
    }

    [Fact]
    public void ExplicitInitializationRunsAfterArgumentEvaluation()
    {
        using var context = Build(initializer: true, customize: module =>
        {
            var methods = module.GetTypes().SelectMany(t => t.Methods).ToArray();
            var target = methods.Single(m => m.Name == "Target");
            var forward = methods.Single(m => m.Name == "Forward");
            target.MethodSig.Params.Add(module.CorLibTypes.Int32);
            forward.MethodSig.Params.Add(module.CorLibTypes.Int32);
            forward.Body.Instructions.Insert(0, OpCodes.Ldarg_0.ToInstruction());
            var entry = methods.Single(m => m.Name == "Entry");
            // The argument writes 7; initialization must overwrite it with 42 afterwards.
            entry.Body.Instructions.Insert(0, OpCodes.Ldc_I4_7.ToInstruction());
            entry.Body.Instructions.Insert(1, OpCodes.Stsfld.ToInstruction((IField)target.Body.Instructions[0].Operand));
            entry.Body.Instructions.Insert(2, OpCodes.Ldc_I4_3.ToInstruction());
        });
        Assert.Equal("42", Invoke(context.Module));

        var result = new MethodInliningRecheckPass().Run(context);

        Assert.Equal(1, result.Changes);
        Assert.Equal("42", Invoke(context.Module));
    }

    [Fact]
    public void ExplicitInitializationKeepsBranchTargetsAndExceptionRegions()
    {
        using var context = Build(initializer: true, throws: true);
        var entry = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Entry");
        var call = entry.Body.Instructions[0];
        var resultLocal = new Local(context.Module.CorLibTypes.Int32);
        entry.Body.Variables.Add(resultLocal);
        var start = OpCodes.Br_S.ToInstruction(call);
        var handler = OpCodes.Pop.ToInstruction();
        var end = OpCodes.Ldloc.ToInstruction(resultLocal);
        entry.Body.Instructions.Clear();
        foreach (var instruction in new[] { start, call, OpCodes.Stloc.ToInstruction(resultLocal),
            OpCodes.Leave_S.ToInstruction(end), handler, OpCodes.Ldc_I4_M1.ToInstruction(),
            OpCodes.Stloc.ToInstruction(resultLocal), OpCodes.Leave_S.ToInstruction(end), end, OpCodes.Ret.ToInstruction() })
            entry.Body.Instructions.Add(instruction);
        entry.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
        {
            TryStart = start, TryEnd = handler, HandlerStart = handler, HandlerEnd = end,
            CatchType = new TypeRefUser(context.Module, "System", "Exception", context.Module.CorLibTypes.AssemblyRef)
        });
        Assert.Equal("-1", Invoke(context.Module));

        var result = new MethodInliningRecheckPass().Run(context);

        Assert.Equal(1, result.Changes);
        Assert.Same(call, start.Operand);
        Assert.Equal(OpCodes.Ldtoken, call.OpCode);
        Assert.Equal("-1", Invoke(context.Module));
    }

    [Fact]
    public void EmptyHelperElisionDoesNotStrandATailPrefix()
    {
        using var context = Build(customize: module =>
        {
            var methods = module.GetTypes().SelectMany(t => t.Methods).ToArray();
            var forward = methods.Single(m => m.Name == "Forward");
            forward.MethodSig = MethodSig.CreateStatic(module.CorLibTypes.Void);
            forward.Body.Instructions.Clear();
            forward.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var entry = methods.Single(m => m.Name == "Entry");
            entry.MethodSig = MethodSig.CreateStatic(module.CorLibTypes.Void);
            entry.Body.Instructions.Clear();
            entry.Body.Instructions.Add(OpCodes.Tailcall.ToInstruction());
            entry.Body.Instructions.Add(OpCodes.Call.ToInstruction(forward));
            entry.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var forward = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Forward");
        RecoveryOrphans.Declare(context, forward);

        var result = new MethodInliningRecheckPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(0, result.Changes);
        Assert.Empty(context.Changes);
    }

    [Fact]
    public void FailedVerificationRestoresTheCallWithoutPublishingAChange()
    {
        using var context = Build();
        var target = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Target");
        target.Attributes = MethodAttributes.Assembly | MethodAttributes.Static;
        // Force the structural gate to reject an otherwise eligible rewrite.
        var caller = context.Module.GetTypes().Single(t => t.Name == "Caller");
        AddMethod(caller, "AddedAfterSnapshot", context.Module.CorLibTypes.Int32,
            OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ret.ToInstruction());

        var result = new MethodInliningPass().Run(context);

        Assert.Equal(PassStatus.Failed, result.Status);
        Assert.Equal(0, result.Changes);
        Assert.Empty(context.Changes);
        Assert.Equal("Forward", ((IMethod)caller.Methods.Single(m => m.Name == "Entry").Body.Instructions[0].Operand).Name);
        Assert.Equal("7", Invoke(context.Module));
    }

    private static ArtifactContext Build(bool initializer = false, bool throws = false, bool nested = false,
        bool chain = false, Action<ModuleDefUser>? customize = null) =>
        SyntheticContext.Build(module =>
        {
            var wrapper = SyntheticContext.AddType(module, "Wrapper");
            var caller = SyntheticContext.AddType(module, "Caller");
            wrapper.Attributes = caller.Attributes = TypeAttributes.Public | TypeAttributes.Class;
            MethodDef target;
            if (initializer)
            {
                var state = SyntheticContext.AddType(module, "State");
                var field = new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Int32),
                    dnlib.DotNet.FieldAttributes.Public | dnlib.DotNet.FieldAttributes.Static);
                state.Fields.Add(field);
                target = AddMethod(state, "Target", module.CorLibTypes.Int32,
                    OpCodes.Ldsfld.ToInstruction(field), OpCodes.Ret.ToInstruction());
                var cctor = AddMethod(wrapper, ".cctor", module.CorLibTypes.Void);
                cctor.Attributes = MethodAttributes.Private | MethodAttributes.Static |
                    MethodAttributes.SpecialName | MethodAttributes.RTSpecialName;
                foreach (var instruction in throws
                    ? new[] { OpCodes.Ldnull.ToInstruction(), OpCodes.Throw.ToInstruction() }
                    : new[] { OpCodes.Ldc_I4.ToInstruction(42), OpCodes.Stsfld.ToInstruction(field), OpCodes.Ret.ToInstruction() })
                    cctor.Body.Instructions.Add(instruction);
            }
            else
            {
                var owner = wrapper;
                if (nested)
                {
                    owner = new TypeDefUser("Hidden", module.CorLibTypes.Object.TypeDefOrRef)
                    { Attributes = TypeAttributes.NestedPrivate | TypeAttributes.Class };
                    wrapper.NestedTypes.Add(owner);
                }
                target = AddMethod(owner, "Target", module.CorLibTypes.Int32,
                    OpCodes.Ldc_I4_7.ToInstruction(), OpCodes.Ret.ToInstruction());
                if (!nested)
                    target.Attributes = MethodAttributes.Private | MethodAttributes.Static;
            }
            var forward = AddMethod(wrapper, "Forward", module.CorLibTypes.Int32,
                OpCodes.Call.ToInstruction(target), OpCodes.Ret.ToInstruction());
            if (chain)
                forward = AddMethod(caller, "First", module.CorLibTypes.Int32,
                    OpCodes.Call.ToInstruction(forward), OpCodes.Ret.ToInstruction());
            AddMethod(caller, "Entry", module.CorLibTypes.Int32, OpCodes.Call.ToInstruction(forward),
                OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Add.ToInstruction(), OpCodes.Ret.ToInstruction());
            customize?.Invoke(module);
        });

    private static MethodDefUser AddMethod(TypeDef type, string name, TypeSig returns, params Instruction[] instructions)
    {
        var method = new MethodDefUser(name, MethodSig.CreateStatic(returns), MethodAttributes.Public | MethodAttributes.Static)
        { Body = new CilBody() };
        type.Methods.Add(method);
        foreach (var instruction in instructions)
            method.Body.Instructions.Add(instruction);
        return method;
    }

    private static string Invoke(ModuleDef module)
    {
        using var image = new MemoryStream();
        module.Write(image);
        image.Position = 0;
        var loading = new AssemblyLoadContext(Guid.NewGuid().ToString(), isCollectible: true);
        try
        {
            var assembly = loading.LoadFromStream(image);
            return assembly.GetType("Synthetic.Caller")!.GetMethod("Entry")!.Invoke(null, null)!.ToString()!;
        }
        catch (TargetInvocationException exception)
        {
            return exception.InnerException!.GetType().Name;
        }
        finally
        {
            loading.Unload();
        }
    }
}
