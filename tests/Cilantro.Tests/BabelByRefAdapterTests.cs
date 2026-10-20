using System.Reflection;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using MethodAttributes = dnlib.DotNet.MethodAttributes;
using MethodImplAttributes = dnlib.DotNet.MethodImplAttributes;

namespace Cilantro.Tests;

public sealed class BabelByRefAdapterTests
{
    [Theory]
    [InlineData(false, false, false)]
    [InlineData(false, false, true)]
    [InlineData(false, true, false)]
    [InlineData(false, true, true)]
    [InlineData(true, false, false)]
    [InlineData(true, false, true)]
    [InlineData(true, true, false)]
    [InlineData(true, true, true)]
    public void PrivateCellsPreserveAliasesOutInitializationAndExceptionWriteback(bool alias, bool initializeOut, bool throws)
    {
        using var module = Fixture(alias, initializeOut, throws, out var stub, out var application);
        Assert.True(BabelByRefAdapter.Supported(stub, Dispatch));
        stub.Body = Assert.IsType<CilBody>(BabelByRefAdapter.Build(stub, application, stub, Dispatch));
        Assert.True(EvaluationStackAnalyzer.Analyze(stub).Valid);
        Assert.Single(stub.Body.ExceptionHandlers);
        using var bytes = new MemoryStream(); module.Write(bytes);
        var assembly = Assembly.Load(bytes.ToArray());
        var actual = (int)assembly.GetType("Fixture.Program")!.GetMethod("Run")!.Invoke(null, null)!;
        var initialA = alias && initializeOut ? 0 : 2;
        var initialB = initializeOut ? 0 : 7;
        var workerB = (alias ? initialA : initialB) + 6;
        var result = throws ? -1 : 10;
        var finalA = throws ? initialA : alias ? workerB : 10;
        var finalB = alias ? 7 : throws ? initialB : workerB;
        Assert.Equal(result * 10_000 + finalA * 100 + finalB, actual);
    }

    [Theory]
    [InlineData("tail")]
    [InlineData("jmp")]
    [InlineData("uninitialized")]
    [InlineData("ambient-stack")]
    [InlineData("uninitialized-stub")]
    public void UnprovenInliningContractsAreRetained(string change)
    {
        using var module = Fixture(false, false, false, out var stub, out var application);
        if (change == "uninitialized-stub") { stub.Body.InitLocals = false; Assert.False(BabelByRefAdapter.Supported(stub, Dispatch)); return; }
        if (change == "ambient-stack")
        {
            stub.Body.Instructions.Insert(0, OpCodes.Ldc_I4_1.ToInstruction());
            stub.Body.Instructions.Insert(stub.Body.Instructions.Count - 1, OpCodes.Pop.ToInstruction());
            Assert.False(BabelByRefAdapter.Supported(stub, Dispatch)); return;
        }
        if (change == "uninitialized") application.Body.InitLocals = false;
        else application.Body.Instructions.Insert(0, change == "tail" ? OpCodes.Tailcall.ToInstruction() : OpCodes.Jmp.ToInstruction(stub));
        Assert.Null(BabelByRefAdapter.Build(stub, application, stub, Dispatch));
    }

    private static bool Dispatch(IMethod method) => method.Name == "Dispatch";

    private static ModuleDefUser Fixture(bool alias, bool initializeOut, bool throws, out MethodDef stub, out MethodDef application)
    {
        var module = new ModuleDefUser("BabelByRefFixture.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser("BabelByRefFixture" + Guid.NewGuid().ToString("N"), new Version(1, 0)); assembly.Modules.Add(module);
        var owner = new TypeDefUser("Fixture", "Program", module.CorLibTypes.Object.TypeDefOrRef) { Attributes = dnlib.DotNet.TypeAttributes.Public }; module.Types.Add(owner);
        MethodDef Method(string name, MethodSig signature)
        {
            var method = new MethodDefUser(name, signature, MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody { InitLocals = true } };
            owner.Methods.Add(method); return method;
        }
        var dispatcher = Method("Dispatch", MethodSig.CreateStatic(module.CorLibTypes.Object, module.CorLibTypes.Int32,
            new ClassSig(module.CorLibTypes.GetTypeRef("System.Reflection", "MethodBase")), module.CorLibTypes.Object, new SZArraySig(module.CorLibTypes.Object)));
        dispatcher.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); dispatcher.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        var signature = MethodSig.CreateStatic(module.CorLibTypes.Int32, new ByRefSig(module.CorLibTypes.Int32), new ByRefSig(module.CorLibTypes.Int32));
        stub = Method("Adapted", signature); var il = stub.Body.Instructions;
        var packed = new Local(new SZArraySig(module.CorLibTypes.Object)); stub.Body.Variables.Add(packed);
        if (initializeOut) { il.Add(OpCodes.Ldarg_1.ToInstruction()); il.Add(OpCodes.Ldc_I4_0.ToInstruction()); il.Add(OpCodes.Stind_I4.ToInstruction()); }
        il.Add(OpCodes.Ldc_I4_2.ToInstruction()); il.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Object.TypeDefOrRef));
        for (var index = 0; index < 2; index++)
        {
            il.Add(OpCodes.Dup.ToInstruction()); il.Add(OpCodes.Ldc_I4.ToInstruction(index)); il.Add(OpCodes.Ldarg.ToInstruction(stub.Parameters[index]));
            il.Add(OpCodes.Ldind_I4.ToInstruction()); il.Add(OpCodes.Box.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef)); il.Add(OpCodes.Stelem_Ref.ToInstruction());
        }
        il.Add(OpCodes.Stloc.ToInstruction(packed)); il.Add(OpCodes.Ldc_I4.ToInstruction(42)); il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Ldnull.ToInstruction());
        il.Add(OpCodes.Ldloc.ToInstruction(packed)); il.Add(OpCodes.Call.ToInstruction(dispatcher)); il.Add(OpCodes.Unbox_Any.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef));
        for (var index = 0; index < 2; index++)
        {
            il.Add(OpCodes.Ldarg.ToInstruction(stub.Parameters[index])); il.Add(OpCodes.Ldloc.ToInstruction(packed)); il.Add(OpCodes.Ldc_I4.ToInstruction(index));
            il.Add(OpCodes.Ldelem_Ref.ToInstruction()); il.Add(OpCodes.Unbox_Any.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef)); il.Add(OpCodes.Stind_I4.ToInstruction());
        }
        il.Add(OpCodes.Ret.ToInstruction());
        application = Method("Decoded", signature.Clone()); var app = application.Body.Instructions;
        var answer = new Local(module.CorLibTypes.Int32); application.Body.Variables.Add(answer);
        var start = OpCodes.Ldarg_0.ToInstruction(); app.Add(start); app.Add(OpCodes.Ldc_I4.ToInstruction(10)); app.Add(OpCodes.Stind_I4.ToInstruction());
        app.Add(OpCodes.Ldarg_1.ToInstruction()); app.Add(OpCodes.Ldarg_1.ToInstruction()); app.Add(OpCodes.Ldind_I4.ToInstruction());
        app.Add(OpCodes.Ldc_I4_1.ToInstruction()); app.Add(OpCodes.Add.ToInstruction()); app.Add(OpCodes.Stind_I4.ToInstruction());
        var exception = new Importer(module).Import(typeof(InvalidOperationException));
        if (throws)
        {
            app.Add(OpCodes.Ldstr.ToInstruction("expected")); app.Add(OpCodes.Newobj.ToInstruction(new Importer(module).Import(typeof(InvalidOperationException).GetConstructor([typeof(string)])!))); app.Add(OpCodes.Throw.ToInstruction());
        }
        else { app.Add(OpCodes.Ldarg_0.ToInstruction()); app.Add(OpCodes.Ldind_I4.ToInstruction()); app.Add(OpCodes.Stloc.ToInstruction(answer)); }
        var finish = OpCodes.Ldloc.ToInstruction(answer);
        if (!throws) app.Add(OpCodes.Leave_S.ToInstruction(finish));
        var handler = OpCodes.Ldarg_1.ToInstruction(); app.Add(handler); app.Add(OpCodes.Ldarg_1.ToInstruction()); app.Add(OpCodes.Ldind_I4.ToInstruction());
        app.Add(OpCodes.Ldc_I4_5.ToInstruction()); app.Add(OpCodes.Add.ToInstruction()); app.Add(OpCodes.Stind_I4.ToInstruction()); app.Add(OpCodes.Endfinally.ToInstruction());
        if (!throws) { app.Add(finish); app.Add(OpCodes.Ret.ToInstruction()); }
        application.Body.ExceptionHandlers.Add(new(ExceptionHandlerType.Finally) { TryStart = start, TryEnd = handler, HandlerStart = handler, HandlerEnd = throws ? null : finish });
        var run = Method("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32)); var code = run.Body.Instructions;
        var a = new Local(module.CorLibTypes.Int32); var b = new Local(module.CorLibTypes.Int32); var result = new Local(module.CorLibTypes.Int32);
        run.Body.Variables.Add(a); run.Body.Variables.Add(b); run.Body.Variables.Add(result);
        code.Add(OpCodes.Ldc_I4_2.ToInstruction()); code.Add(OpCodes.Stloc.ToInstruction(a)); code.Add(OpCodes.Ldc_I4_7.ToInstruction()); code.Add(OpCodes.Stloc.ToInstruction(b));
        var attempt = OpCodes.Ldloca.ToInstruction(a); code.Add(attempt); code.Add(OpCodes.Ldloca.ToInstruction(alias ? a : b)); code.Add(OpCodes.Call.ToInstruction(stub)); code.Add(OpCodes.Stloc.ToInstruction(result));
        var done = OpCodes.Ldloc.ToInstruction(result); code.Add(OpCodes.Leave.ToInstruction(done));
        var caught = OpCodes.Pop.ToInstruction(); code.Add(caught); code.Add(OpCodes.Ldc_I4_M1.ToInstruction()); code.Add(OpCodes.Stloc.ToInstruction(result)); code.Add(OpCodes.Leave.ToInstruction(done));
        code.Add(done); code.Add(OpCodes.Ldc_I4.ToInstruction(10_000)); code.Add(OpCodes.Mul.ToInstruction()); code.Add(OpCodes.Ldloc.ToInstruction(a));
        code.Add(OpCodes.Ldc_I4.ToInstruction(100)); code.Add(OpCodes.Mul.ToInstruction()); code.Add(OpCodes.Add.ToInstruction()); code.Add(OpCodes.Ldloc.ToInstruction(b)); code.Add(OpCodes.Add.ToInstruction()); code.Add(OpCodes.Ret.ToInstruction());
        run.Body.ExceptionHandlers.Add(new(ExceptionHandlerType.Catch) { CatchType = exception, TryStart = attempt, TryEnd = caught, HandlerStart = caught, HandlerEnd = done });
        return module;
    }
}
