using System.Reflection;
using System.Reflection.Emit;
using Cilantro.Core;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using OpCodes = dnlib.DotNet.Emit.OpCodes;

namespace Cilantro.Tests;

public sealed class EmittedMethodReconstructionTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void ReconstructedBodyPreservesTheArgumentAndDomainWrite(bool instance, bool empty)
    {
        using var context = Load();
        var factory = Factory(context);
        var generated = EmittedMethodReconstructionPass.Capture(context, factory, out var why);
        Assert.True(generated is not null, why);
        if (instance)
        {
            factory.Attributes &= ~dnlib.DotNet.MethodAttributes.Static;
            factory.MethodSig.HasThis = true;
            factory.Parameters.UpdateParameterTypes();
        }
        factory.Body = EmittedMethodReconstructionPass.Lower(generated, factory);
        var machine = new StaticMachine();
        machine.State.RegisterModuleMetadata(context.Module);
        var heap = machine.State.Heap;
        byte[] input = empty ? [] : [1, 2, 3];
        Assert.True(heap.TryAllocateByteArray(input, out var bytes));
        Assert.True(heap.TryAllocateObject("System.IO.MemoryStream", out var stream));
        var ctor = new MemberRefUser(context.Module, ".ctor",
            MethodSig.CreateInstance(context.Module.CorLibTypes.Void, new SZArraySig(context.Module.CorLibTypes.Byte)),
            context.Module.CorLibTypes.GetTypeRef("System.IO", "MemoryStream"));
        Assert.True(machine.Invoke(ctor, [stream, bytes]).Status == StaticExecutionStatus.Completed);
        var arguments = new List<StaticValue>();
        if (instance)
        {
            Assert.True(heap.TryAllocateObject(factory.DeclaringType.FullName, out var receiver));
            arguments.Add(receiver);
        }
        arguments.Add(stream);
        var result = machine.Execute(factory, arguments);
        Assert.True(result.Succeeded, result.Diagnostic);
        Assert.True(heap.TryGetString(result.Value, out var answer));
        Assert.Equal("answer", answer);
        Assert.True(machine.State.TryGetOrAllocateRuntimeSingleton("System.AppDomain", out var domain));
        Assert.True(heap.TryGetModelValue(domain, "Data:cilantro-emitted-fixture", out StaticValue value));
        Assert.True(heap.TryGetString(value, out var stored));
        Assert.Equal(empty ? "empty" : "retained", stored);
        // This is a repository-built benign oracle, never a corpus binary.
        using var oracleStream = new MemoryStream(input);
        try
        {
            Assert.Equal(Fixture.Factory(oracleStream), answer);
            Assert.Equal(AppDomain.CurrentDomain.GetData("cilantro-emitted-fixture"), stored);
        }
        finally { AppDomain.CurrentDomain.SetData("cilantro-emitted-fixture", null); }
    }

    [Fact]
    public void AnUnmodeledInnerExceptionIsNotInventedAsNull()
    {
        using var context = Load();
        var machine = new StaticMachine();
        machine.State.RegisterModuleMetadata(context.Module);
        Assert.True(machine.State.Heap.TryAllocateObject("System.Exception", out var exception));
        var type = context.Module.CorLibTypes.GetTypeRef("System", "Exception");
        var getter = new MemberRefUser(context.Module, "get_InnerException", MethodSig.CreateInstance(type.ToTypeSig()), type);
        Assert.Equal(StaticExecutionStatus.Unknown, machine.Invoke(getter, [exception]).Status);
    }

    [Fact]
    public void ReconstructedFailureRetainsReflectionExceptionWrapping()
    {
        using var context = Load();
        var factory = Factory(context);
        var generated = EmittedMethodReconstructionPass.Capture(context, factory, out var why);
        Assert.True(generated is not null, why);
        // Isolate exception wrapping from the interpreter's null-stream intrinsic limitation.
        generated.Body.Instructions[0].OpCode = OpCodes.Newobj;
        generated.Body.Instructions[0].Operand = new MemberRefUser(context.Module, ".ctor", MethodSig.CreateInstance(context.Module.CorLibTypes.Void),
            context.Module.CorLibTypes.GetTypeRef("System", "InvalidOperationException"));
        generated.Body.Instructions[1].OpCode = OpCodes.Throw;
        generated.Body.Instructions[1].Operand = null;
        factory.Body = EmittedMethodReconstructionPass.Lower(generated, factory);
        var machine = new StaticMachine();
        machine.State.RegisterModuleMetadata(context.Module);
        var result = machine.Execute(factory, [StaticValue.Null]);
        Assert.True(result.Status == StaticExecutionStatus.Threw, result.Diagnostic);
        Assert.True(machine.State.Heap.TryGetRuntimeTypeName(result.Value, out var type));
        Assert.Equal("System.Reflection.TargetInvocationException", type);
        Assert.True(machine.State.Heap.TryGetModelValue(result.Value, "InnerException", out StaticValue inner));
        Assert.True(machine.State.Heap.TryGetRuntimeTypeName(inner, out var innerType));
        Assert.Equal("System.InvalidOperationException", innerType);
        var oracle = Assert.Throws<TargetInvocationException>(() => typeof(Fixture).GetMethod(nameof(Fixture.Throw))!.Invoke(null, null));
        Assert.IsType<InvalidOperationException>(oracle.InnerException);
    }

    [Theory]
    [InlineData("field")]
    [InlineData("argument")]
    [InlineData("tail")]
    [InlineData("handler")]
    [InlineData("reflection")]
    public void UnprovenConstructionOrChangedTailIsDeclined(string change)
    {
        using var context = Load();
        var factory = Factory(context);
        var il = factory.Body.Instructions;
        if (change == "field")
        {
            var field = new FieldDefUser("Mutable", new FieldSig(context.Module.CorLibTypes.Int32), dnlib.DotNet.FieldAttributes.Static);
            factory.DeclaringType.Fields.Add(field);
            il.Insert(0, OpCodes.Ldsfld.ToInstruction(field)); il.Insert(1, OpCodes.Pop.ToInstruction());
        }
        else if (change == "argument")
        {
            var length = new MemberRefUser(context.Module, "get_Length", MethodSig.CreateInstance(context.Module.CorLibTypes.Int64),
                context.Module.CorLibTypes.GetTypeRef("System.IO", "Stream"));
            il.Insert(0, OpCodes.Ldarg_0.ToInstruction()); il.Insert(1, OpCodes.Callvirt.ToInstruction(length)); il.Insert(2, OpCodes.Pop.ToInstruction());
        }
        else if (change == "reflection")
        {
            var helper = factory.DeclaringType.Methods.Single(m => m.Name == nameof(Fixture.ReadHost));
            il.Insert(0, OpCodes.Call.ToInstruction(helper)); il.Insert(1, OpCodes.Pop.ToInstruction());
        }
        else if (change == "handler")
        {
            factory.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Finally));
        }
        else
        {
            var cast = il.Single(i => i.OpCode.Code == Code.Castclass);
            il.Insert(il.IndexOf(cast) + 1, OpCodes.Pop.ToInstruction());
            il.Insert(il.IndexOf(cast) + 2, OpCodes.Ldstr.ToInstruction("different"));
        }
        Assert.Null(EmittedMethodReconstructionPass.Capture(context, factory, out _));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DisabledOrStrictReconstructionDoesNotChangeFactories(bool strict)
    {
        using var context = Load();
        context.SetFact("options.devirtualize", strict);
        context.SetFact(BootstrapMachine.RunEnvironmentFact, new RunEnvironment(strict: strict));
        var body = Factory(context).Body;
        Assert.Equal(0, new EmittedMethodReconstructionPass().Run(context).Changes);
        Assert.Same(body, Factory(context).Body);
    }

    [Fact]
    public void GeneratedTypeInitializationCannotBeDiscarded()
    {
        using var context = Load();
        var factory = Factory(context);
        var generated = EmittedMethodReconstructionPass.Capture(context, factory, out var why);
        Assert.True(generated is not null, why);
        generated.DeclaringType.Methods.Add(new MethodDefUser(".cctor", MethodSig.CreateStatic(generated.Module.CorLibTypes.Void))
        { Attributes = dnlib.DotNet.MethodAttributes.Static | dnlib.DotNet.MethodAttributes.SpecialName | dnlib.DotNet.MethodAttributes.RTSpecialName,
            Body = new CilBody() });
        Assert.Throws<InvalidOperationException>(() => EmittedMethodReconstructionPass.Lower(generated, factory));
    }

    [Fact]
    public void HelperTypeInitializationCannotBeDiscarded()
    {
        using var context = Load();
        var factory = Factory(context);
        var helperType = new TypeDefUser("Fixture", "Helper", context.Module.CorLibTypes.Object.TypeDefOrRef);
        context.Module.Types.Add(helperType);
        var initializer = new MethodDefUser(".cctor", MethodSig.CreateStatic(context.Module.CorLibTypes.Void))
        { Attributes = dnlib.DotNet.MethodAttributes.Static | dnlib.DotNet.MethodAttributes.SpecialName | dnlib.DotNet.MethodAttributes.RTSpecialName,
            Body = new CilBody() };
        initializer.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction());
        initializer.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
        initializer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        helperType.Methods.Add(initializer);
        var helper = new MethodDefUser("Touch", MethodSig.CreateStatic(context.Module.CorLibTypes.Void))
        { Attributes = dnlib.DotNet.MethodAttributes.Static, Body = new CilBody() };
        helper.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        helperType.Methods.Add(helper);
        factory.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(helper));
        Assert.Null(EmittedMethodReconstructionPass.Capture(context, factory, out var why));
        Assert.Contains("initializer", why);
    }

    [Fact]
    public void ReferencesToOtherGeneratedDeclarationsAreDeclined()
    {
        using var context = Load();
        var factory = Factory(context);
        var generated = EmittedMethodReconstructionPass.Capture(context, factory, out var why);
        Assert.True(generated is not null, why);
        generated.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(generated));
        Assert.Throws<InvalidOperationException>(() => EmittedMethodReconstructionPass.Lower(generated, factory));
    }

    [Theory]
    [InlineData("direct", true)]
    [InlineData("spill", true)]
    [InlineData("jump", true)]
    [InlineData("replace", false)]
    [InlineData("cycle", false)]
    [InlineData("call", false)]
    [InlineData("address", false)]
    [InlineData("other-local", false)]
    [InlineData("foreign-cast", false)]
    public void ReturnTransportRequiresTheOriginalResult(string mode, bool accepted)
    {
        using var context = SyntheticContext.Build(module => { });
        var method = new MethodDefUser("Tail", MethodSig.CreateStatic(context.Module.CorLibTypes.String)) { Body = new CilBody() };
        context.Module.GlobalType.Methods.Add(method);
        var il = method.Body.Instructions;
        var invocation = OpCodes.Nop.ToInstruction(); il.Add(invocation);
        var targetType = mode == "foreign-cast"
            ? new TypeRefUser(context.Module, "System", "String", new AssemblyRefUser("Foreign"))
            : context.Module.CorLibTypes.String.TypeDefOrRef;
        il.Add(OpCodes.Castclass.ToInstruction(targetType));
        var local = new Local(context.Module.CorLibTypes.String); method.Body.Variables.Add(local);
        var ret = OpCodes.Ret.ToInstruction();
        if (mode is "spill" or "jump" or "address" or "other-local")
        {
            il.Add(OpCodes.Stloc.ToInstruction(local));
            var load = OpCodes.Ldloc.ToInstruction(local);
            if (mode == "jump") il.Add(OpCodes.Br.ToInstruction(load));
            if (mode == "address") { il.Add(OpCodes.Ldloca.ToInstruction(local)); il.Add(OpCodes.Pop.ToInstruction()); }
            if (mode == "other-local")
            {
                var other = new Local(context.Module.CorLibTypes.String); method.Body.Variables.Add(other);
                load.Operand = other;
            }
            il.Add(load);
        }
        if (mode == "replace") { il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Ldstr.ToInstruction("replacement")); }
        if (mode == "cycle") { var loop = OpCodes.Br.ToInstruction(ret); loop.Operand = loop; il.Add(loop); }
        if (mode == "call") il.Add(OpCodes.Call.ToInstruction(method));
        il.Add(ret);
        Assert.Equal(accepted, EmittedMethodReconstructionPass.HasUnmodifiedReturn(method, invocation));
    }
    private static ArtifactContext Load() => ArtifactContext.Load(typeof(EmittedMethodReconstructionTests).Assembly.Location);
    private static MethodDef Factory(ArtifactContext context) => context.Module.GetTypes()
        .Single(t => t.FullName == typeof(Fixture).FullName!.Replace('+', '/')).Methods.Single(m => m.Name == "Factory");

    public static class Fixture
    {
        public static object? ReadHost() => typeof(Environment)
            .GetMethod(nameof(Environment.GetEnvironmentVariable), [typeof(string)])!
            .Invoke(null, ["CILANTRO_EMITTED_FIXTURE"]);
        public static void Throw() => throw new InvalidOperationException();
        public static string Factory(Stream stream)
        {
            var assembly = AssemblyBuilder.DefineDynamicAssembly(new AssemblyName("CilantroEmittedFixture"), AssemblyBuilderAccess.Run);
            var module = assembly.DefineDynamicModule("Fixture");
            var type = module.DefineType("Decoder", System.Reflection.TypeAttributes.Public);
            var method = type.DefineMethod("Read", System.Reflection.MethodAttributes.Public | System.Reflection.MethodAttributes.Static,
                typeof(string), [typeof(Stream)]);
            var il = method.GetILGenerator();
            var stored = il.DeclareLocal(typeof(string));
            var empty = il.DefineLabel();
            var ready = il.DefineLabel();
            il.Emit(System.Reflection.Emit.OpCodes.Ldarg_0);
            il.Emit(System.Reflection.Emit.OpCodes.Callvirt, typeof(Stream).GetMethod("get_Length")!);
            il.Emit(System.Reflection.Emit.OpCodes.Brfalse, empty);
            il.Emit(System.Reflection.Emit.OpCodes.Ldstr, "retained");
            il.Emit(System.Reflection.Emit.OpCodes.Br, ready);
            il.MarkLabel(empty);
            il.Emit(System.Reflection.Emit.OpCodes.Ldstr, "empty");
            il.MarkLabel(ready);
            il.Emit(System.Reflection.Emit.OpCodes.Stloc, stored);
            il.Emit(System.Reflection.Emit.OpCodes.Call, typeof(AppDomain).GetMethod("get_CurrentDomain")!);
            il.Emit(System.Reflection.Emit.OpCodes.Ldstr, "cilantro-emitted-fixture");
            il.Emit(System.Reflection.Emit.OpCodes.Ldloc, stored);
            il.Emit(System.Reflection.Emit.OpCodes.Callvirt, typeof(AppDomain).GetMethod("SetData", [typeof(string), typeof(object)])!);
            il.Emit(System.Reflection.Emit.OpCodes.Ldstr, "answer");
            il.Emit(System.Reflection.Emit.OpCodes.Ret);
            var made = type.CreateType();
#pragma warning disable CA1304 // Exercise the exact reflection overload used by the protected factory.
            return (string)made.InvokeMember("Read", BindingFlags.Public | BindingFlags.Static | BindingFlags.InvokeMethod,
                null, null, [stream])!;
#pragma warning restore CA1304
        }
    }
}
