using Cilantro.Core.Interpretation;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class CapturedEntryPointTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ReadsCapturedSignatureWithoutCallingOrBorrowingHomeEntry(bool takesArguments)
    {
        using var home = new ModuleDefUser("home.dll");
        var state = new StaticMachineState(new StaticMachineLimits());
        state.RegisterModuleMetadata(home);
        var heap = state.Heap;
        var intrinsic = new LoaderFrameworkIntrinsic();
        var calls = 0;
        var context = new IntrinsicContext(state, Call: (_, _) => { calls++; return IntrinsicResult.Completed(); });
        var importer = new Importer(home);
        Assert.True(heap.TryAllocateByteArray(Image(takesArguments), out var bytes));
        var assembly = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.Assembly).GetMethod("Load", [typeof(byte[])])!), [bytes]);
        var result = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.Assembly).GetProperty("EntryPoint")!.GetMethod!), [assembly.Value]);
        Assert.True(result.Status == StaticExecutionStatus.Completed, result.Diagnostic);
        var name = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.MemberInfo).GetProperty("Name")!.GetMethod!), [result.Value]);
        Assert.True(heap.TryGetString(name.Value, out var text), name.Diagnostic);
        Assert.Equal("StartPayload", text);
        var parameters = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.MethodBase).GetMethod("GetParameters")!), [result.Value]);
        Assert.True(heap.TryGetLength(parameters.Value, out var count), parameters.Diagnostic);
        Assert.Equal(takesArguments ? 1 : 0, count);
        if (takesArguments)
        {
            Assert.True(heap.TryReadArray(parameters.Value, 0, out var parameter));
            var type = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.ParameterInfo).GetProperty("ParameterType")!.GetMethod!), [parameter]);
            var fullName = intrinsic.Invoke(context, importer.Import(typeof(Type).GetProperty("FullName")!.GetMethod!), [type.Value]);
            Assert.True(heap.TryGetString(fullName.Value, out var parameterName), fullName.Diagnostic);
            Assert.Equal("System.String[]", parameterName);
        }
        var invoked = intrinsic.Invoke(context, importer.Import(typeof(System.Reflection.MethodBase).GetMethod("Invoke", [typeof(object), typeof(object[])])!),
            [result.Value, StaticValue.Null, StaticValue.Null]);
        Assert.NotEqual(StaticExecutionStatus.Completed, invoked.Status);
        Assert.Contains("own module context", invoked.Diagnostic);
        Assert.Equal(0, calls);
        Assert.Single(state.CapturedAssemblyLoads);
        Assert.DoesNotContain(home.Types, t => !t.IsGlobalModuleType);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MissingEntryIsNullButInvalidMetadataIsRefused(bool malformed)
    {
        using var module = new ModuleDefUser("library.dll");
        new AssemblyDefUser("Library", new Version(1, 0)).Modules.Add(module);
        using var stream = new MemoryStream(); module.Write(stream);
        var state = new StaticMachineState(new StaticMachineLimits());
        state.RegisterModuleMetadata(module);
        Assert.True(state.Heap.TryAllocateObject("System.Reflection.Assembly", out var receiver));
        state.Heap.TrySetModelValue(receiver, "LoadedImage", malformed ? new byte[] { 1, 2, 3 } : stream.ToArray());
        var result = new LoaderFrameworkIntrinsic().Invoke(new IntrinsicContext(state),
            new Importer(module).Import(typeof(System.Reflection.Assembly).GetProperty("EntryPoint")!.GetMethod!), [receiver]);
        if (malformed) Assert.NotEqual(StaticExecutionStatus.Completed, result.Status);
        else
        {
            Assert.Equal(StaticExecutionStatus.Completed, result.Status);
            Assert.Equal(StaticValueKind.Null, result.Value.Kind);
        }
    }

    private static byte[] Image(bool takesArguments)
    {
        using var module = new ModuleDefUser("payload.exe") { Kind = ModuleKind.Console };
        new AssemblyDefUser("Payload", new Version(1, 0)).Modules.Add(module);
        var owner = new TypeDefUser("Payload", "Program", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(owner);
        var method = new MethodDefUser("StartPayload", takesArguments
            ? MethodSig.CreateStatic(module.CorLibTypes.Void, new SZArraySig(module.CorLibTypes.String))
            : MethodSig.CreateStatic(module.CorLibTypes.Void), MethodAttributes.Static | MethodAttributes.Public)
            { Body = new CilBody() };
        method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        owner.Methods.Add(method); module.EntryPoint = method;
        using var stream = new MemoryStream(); module.Write(stream); return stream.ToArray();
    }
}
