using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Passes;

namespace Cilantro.Tests;

public sealed class DispatcherDeobfuscationTests
{
    [Fact]
    public void QualifiesAndRedirectsClosedConstantDispatcher()
    {
        using var fixture = CreateDispatcher(useHelper: false);

        var analysis = new DispatcherAnalyzer().Analyze(fixture.Method);

        Assert.True(analysis.IsQualified);
        Assert.Equal(0, analysis.Plan!.InitialState);
        Assert.Equal(2, analysis.Plan.Rewrites.Count);

        var result = new DispatcherDeobfuscationPass().Rewrite(fixture.Method);

        Assert.Equal(DispatcherQualification.Qualified, result.Qualification);
        Assert.Equal(2, result.ChangedEdges);
        Assert.Equal(OpCodes.Nop, fixture.InitialStore.OpCode);
        Assert.Equal(OpCodes.Nop, fixture.TransitionStore.OpCode);
        Assert.Same(fixture.Case0, fixture.InitialBranch.Operand);
        Assert.Same(fixture.Case1, fixture.TransitionBranch.Operand);
    }

    [Fact]
    public void EvaluatesProvenParameterlessIntegerHelper()
    {
        using var fixture = CreateDispatcher(useHelper: true);

        var result = new DispatcherDeobfuscationPass().Rewrite(fixture.Method);

        Assert.Equal(DispatcherQualification.Qualified, result.Qualification);
        Assert.Equal(2, result.ChangedEdges);
        Assert.Same(fixture.Case1, fixture.TransitionBranch.Operand);
    }

    [Fact]
    public void PreservesDispatcherLocalWithAdditionalRead()
    {
        using var fixture = CreateDispatcher(useHelper: false);
        var instructions = fixture.Method.Body.Instructions;
        var transitionIndex = instructions.IndexOf(fixture.TransitionStore);
        instructions.Insert(transitionIndex - 1, Instruction.Create(OpCodes.Ldloc, fixture.State));
        instructions.Insert(transitionIndex, Instruction.Create(OpCodes.Pop));

        var beforeTarget = fixture.InitialBranch.Operand;
        var result = new DispatcherDeobfuscationPass().Rewrite(fixture.Method);

        Assert.Equal(DispatcherQualification.Ambiguous, result.Qualification);
        Assert.Equal(0, result.ChangedEdges);
        Assert.Same(beforeTarget, fixture.InitialBranch.Operand);
        Assert.Equal(OpCodes.Stloc, fixture.InitialStore.OpCode);
    }

    [Fact]
    public void RejectsDirectEdgeAcrossExceptionRegionBoundary()
    {
        using var fixture = CreateDispatcher(useHelper: false);
        var instructions = fixture.Method.Body.Instructions;
        var handlerStart = Instruction.Create(OpCodes.Pop);
        var handlerReturn = Instruction.Create(OpCodes.Ret);
        instructions.Add(handlerStart);
        instructions.Add(handlerReturn);
        fixture.Method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
        {
            CatchType = fixture.Module.CorLibTypes.Object.TypeDefOrRef,
            TryStart = fixture.Case1,
            TryEnd = fixture.DispatchLoad,
            HandlerStart = handlerStart,
            HandlerEnd = null
        });

        var analysis = new DispatcherAnalyzer().Analyze(fixture.Method);

        Assert.Equal(DispatcherQualification.Ambiguous, analysis.Qualification);
        Assert.Contains(analysis.Diagnostics,
            diagnostic => diagnostic.Contains("exception-region", StringComparison.Ordinal));
    }

    [Fact]
    public void GraphSplitsAndAnnotatesExceptionBoundaries()
    {
        using var fixture = CreateDispatcher(useHelper: false);
        var instructions = fixture.Method.Body.Instructions;
        var handlerStart = Instruction.Create(OpCodes.Pop);
        var handlerReturn = Instruction.Create(OpCodes.Ret);
        instructions.Add(handlerStart);
        instructions.Add(handlerReturn);
        fixture.Method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
        {
            CatchType = fixture.Module.CorLibTypes.Object.TypeDefOrRef,
            TryStart = fixture.Case0,
            TryEnd = fixture.Case1,
            HandlerStart = handlerStart,
            HandlerEnd = null
        });

        var graph = ControlFlowGraph.Build(fixture.Method);

        Assert.NotEmpty(graph.RegionsOf(fixture.Case0));
        Assert.Empty(graph.RegionsOf(fixture.Case1));
        Assert.Contains(graph.Edges, edge =>
            edge.Kind == ControlFlowEdgeKind.Exception &&
            ReferenceEquals(edge.Target.First, handlerStart));
    }

    private static DispatcherFixture CreateDispatcher(bool useHelper)
    {
        var module = new ModuleDefUser("dispatcher.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser("dispatcher", new Version(1, 0));
        assembly.Modules.Add(module);
        var type = new TypeDefUser("", "Fixture", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(type);

        var helper = new MethodDefUser(
            "Next",
            MethodSig.CreateStatic(module.CorLibTypes.Int32),
            dnlib.DotNet.MethodAttributes.Public | dnlib.DotNet.MethodAttributes.Static);
        helper.Body = new CilBody();
        helper.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        helper.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(helper);

        var method = new MethodDefUser(
            "Flattened",
            MethodSig.CreateStatic(module.CorLibTypes.Void),
            dnlib.DotNet.MethodAttributes.Public | dnlib.DotNet.MethodAttributes.Static);
        method.Body = new CilBody { InitLocals = true };
        var state = new Local(module.CorLibTypes.Int32);
        method.Body.Variables.Add(state);
        type.Methods.Add(method);

        var initialValue = Instruction.Create(OpCodes.Ldc_I4_0);
        var initialStore = Instruction.Create(OpCodes.Stloc, state);
        var initialBranch = Instruction.Create(OpCodes.Br, initialValue);
        var case0 = Instruction.Create(OpCodes.Nop);
        var transitionValue = useHelper
            ? Instruction.Create(OpCodes.Call, helper)
            : Instruction.Create(OpCodes.Ldc_I4_1);
        var transitionStore = Instruction.Create(OpCodes.Stloc, state);
        var transitionBranch = Instruction.Create(OpCodes.Br, initialValue);
        var case1 = Instruction.Create(OpCodes.Ret);
        var dispatchLoad = Instruction.Create(OpCodes.Ldloc, state);
        var dispatchSwitch = Instruction.Create(OpCodes.Switch, new[] { case0, case1 });

        initialBranch.Operand = dispatchLoad;
        transitionBranch.Operand = dispatchLoad;
        method.Body.Instructions.Add(initialValue);
        method.Body.Instructions.Add(initialStore);
        method.Body.Instructions.Add(initialBranch);
        method.Body.Instructions.Add(case0);
        method.Body.Instructions.Add(transitionValue);
        method.Body.Instructions.Add(transitionStore);
        method.Body.Instructions.Add(transitionBranch);
        method.Body.Instructions.Add(case1);
        method.Body.Instructions.Add(dispatchLoad);
        method.Body.Instructions.Add(dispatchSwitch);

        return new DispatcherFixture(
            module,
            method,
            state,
            initialStore,
            initialBranch,
            transitionStore,
            transitionBranch,
            case0,
            case1,
            dispatchLoad);
    }

    private sealed record DispatcherFixture(
        ModuleDefUser Module,
        MethodDef Method,
        Local State,
        Instruction InitialStore,
        Instruction InitialBranch,
        Instruction TransitionStore,
        Instruction TransitionBranch,
        Instruction Case0,
        Instruction Case1,
        Instruction DispatchLoad) : IDisposable
    {
        public void Dispose() => Module.Dispose();
    }
}
