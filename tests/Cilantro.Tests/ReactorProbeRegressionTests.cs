using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Passes;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.PE;
namespace Cilantro.Tests;

public sealed class ReactorProbeRegressionTests
{
    [Fact]
    public void AppendedReconstructionMetadataPreservesExistingNumericTokens()
    {
        using var context = SyntheticContext.Build(module =>
        {
            for (var index = 0; index < 2; index++)
            {
                var type = SyntheticContext.AddType(module, index == 0 ? "First" : "Second");
                var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void),
                    MethodImplAttributes.IL, MethodAttributes.Static) { Body = new CilBody() };
                method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                type.Methods.Add(method);
            }
        });
        var original = context.Module.GetTypes().SelectMany(t => t.Methods)
            .ToDictionary(m => m.MDToken.Raw, m => m.FullName);
        var first = context.Module.GetTypes().Single(t => t.Name == "First");
        var rebuilt = new MethodDefUser("Rebuilt", MethodSig.CreateStatic(context.Module.CorLibTypes.Void),
            MethodImplAttributes.IL, MethodAttributes.Static) { Body = new CilBody() };
        rebuilt.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        first.Methods.Add(rebuilt);
        ReadingMarker.Add(context.Module).Mark(rebuilt);
        using var stream = new MemoryStream();
        var options = new dnlib.DotNet.Writer.ModuleWriterOptions(context.Module);
        options.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.PreserveAll;
        context.Module.Write(stream, options);
        using var emitted = ModuleDefMD.Load(stream.ToArray());

        foreach (var (token, name) in original)
            Assert.Equal(name, ((MethodDef)emitted.ResolveToken(token)).FullName);
        Assert.Contains(emitted.GetTypes().SelectMany(t => t.Methods), m => m.Name == "Rebuilt");
    }

    [Theory]
    [InlineData("System.Reflection", "Module", "ResolveMethod")]
    [InlineData("System", "ModuleHandle", "ResolveMethodHandle")]
    public void NumericTokenConsumersPreventDeclarationDeletion(string ns, string typeName, string operation)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            host.Attributes = TypeAttributes.Public;
            var target = new MethodDefUser("Hidden", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static)
                { Body = new CilBody() };
            target.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            host.Methods.Add(target);
            var consumer = new MethodDefUser("Resolve", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.Static)
                { Body = new CilBody() };
            consumer.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            consumer.Body.Instructions.Add(OpCodes.Ldc_I4.ToInstruction(0x06000001));
            consumer.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, operation,
                MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.Int32),
                module.CorLibTypes.GetTypeRef(ns, typeName))));
            consumer.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            consumer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            host.Methods.Add(consumer);
        });
        var target = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Hidden");
        RecoveryOrphans.Declare(context, target);
        context.SetFact("options.removeRuntime", true);

        var result = new RuntimeCleanupPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(0, result.Changes);
        Assert.Contains(target, target.DeclaringType.Methods);
        Assert.Contains(result.Diagnostics, note => note.Contains("numeric metadata tokens"));
    }

    [Fact]
    public void UnreachableHandlerEndSuffixBecomesEndOfMethod()
    {
        using var module = new ModuleDefUser("Fixture");
        var type = SyntheticContext.AddType(module, "Host");
        var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32))
            { Attributes = MethodAttributes.Static, Body = new CilBody() };
        type.Methods.Add(method);
        var start = OpCodes.Nop.ToInstruction(); var result = OpCodes.Ldc_I4_0.ToInstruction();
        var handler = OpCodes.Endfinally.ToInstruction(); var end = OpCodes.Nop.ToInstruction();
        foreach (var i in new[] { OpCodes.Br.ToInstruction(start), result, OpCodes.Ret.ToInstruction(), start,
            OpCodes.Leave.ToInstruction(result), handler, end, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Ret.ToInstruction() }) method.Body.Instructions.Add(i);
        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Finally)
            { TryStart=start, TryEnd=handler, HandlerStart=handler, HandlerEnd=end });
        ControlFlowCompletionPass.TryComplete(method);
        Assert.Equal(Code.Endfinally, method.Body.Instructions[^1].OpCode.Code);
        Assert.Null(method.Body.ExceptionHandlers[0].HandlerEnd);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void HarvestSkipsZeroSentinelAndMappedImagePointers(bool native)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var record = SyntheticContext.AddType(module, "Record");
            if (native) {
                record.Fields.Add(new FieldDefUser("Size", new FieldSig(module.CorLibTypes.Int32)));
                record.Fields.Add(new FieldDefUser("Pointer", new FieldSig(module.CorLibTypes.IntPtr)));
            } else record.Fields.Add(new FieldDefUser("Bytes", new FieldSig(new SZArraySig(module.CorLibTypes.Byte))));
            record.Fields.Add(new FieldDefUser("Table", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Static));
        });
        var state = new StaticMachineState(new StaticMachineLimits()); var heap = state.Heap;
        var type = context.Module.GetTypes().Single(t => t.Name == "Record");
        Assert.True(heap.TryAllocateObject(type.FullName, out var entry));
        var code = new byte[] { 0x16, 0x2A };
        if (native) {
            Assert.True(state.TryRegisterImage(code, 0x400000));
            Assert.True(heap.TryWriteField(entry, type.FindField("Size"), StaticValue.FromInt32(code.Length)));
            Assert.True(heap.TryWriteField(entry, type.FindField("Pointer"), StaticValue.FromInt64(0x400000)));
        } else {
            Assert.True(heap.TryAllocateByteArray(code, out var bytes));
            Assert.True(heap.TryWriteField(entry, type.FindField("Bytes"), bytes));
        }
        Assert.True(heap.TryAllocateObject("System.Collections.Hashtable", out var table));
        Assert.True(heap.TrySetModelValue(table, "Entries", new Dictionary<StaticValue, StaticValue>
            { [StaticValue.FromInt64(0)] = entry, [StaticValue.FromInt64(0x402000)] = entry }));
        state.WriteStaticField(type.FindField("Table"), table);
        var found = NecroBitBodyRecovery.Harvest(context.Module, state);
        if (native) Assert.Empty(found);
        else { Assert.Equal(0x402000, Assert.Single(found).Key); Assert.Equal(code, found[0].Il); }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void MarkerlessBodyRequiresAndPreservesExceptionSections(bool withHandler)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Host");
            var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32))
                { Attributes = MethodAttributes.Static, Body = new CilBody { InitLocals = true } };
            type.Methods.Add(method); method.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            var start = OpCodes.Ldc_I4_1.ToInstruction(); var handler = OpCodes.Pop.ToInstruction();
            var end = OpCodes.Ldloc_0.ToInstruction();
            foreach (var i in new[] { start, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Div.ToInstruction(),
                OpCodes.Stloc_0.ToInstruction(), OpCodes.Leave.ToInstruction(end), handler,
                OpCodes.Ldc_I4_M1.ToInstruction(), OpCodes.Stloc_0.ToInstruction(), OpCodes.Leave.ToInstruction(end), end, OpCodes.Ret.ToInstruction() })
                method.Body.Instructions.Add(i);
            if (withHandler) method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
                { TryStart = start, TryEnd = handler, HandlerStart = handler, HandlerEnd = end,
                  CatchType = module.CorLibTypes.GetTypeRef("System", "DivideByZeroException") });
            else { method.Body.Instructions.Clear(); method.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction()); method.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); }
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single();
        var ilRva = (uint)method.RVA + method.Body.HeaderSize;
        var reader = context.Module.Metadata.PEImage.CreateReader();
        reader.Position = (uint)context.Module.Metadata.PEImage.ToFileOffset((RVA)ilRva);
        var last = method.Body.Instructions[^1];
        var code = reader.ReadBytes((int)(last.Offset + last.GetSize()));
        var result = NecroBitBodyRecovery.TryApply(context,
            [new ProtectedMethodStub(method.MDToken.Raw, (uint)method.RVA, method.FullName, method.Body.Instructions.Count)],
            [new NecroBitBody(0x400000 + ilRva, code, false)], [], out var recovered, out var notes);
        Assert.Equal(withHandler, result);
        if (withHandler) {
            Assert.Single(recovered); Assert.Single(method.Body.ExceptionHandlers);
            Assert.Same(method.Body.Instructions[0], method.Body.ExceptionHandlers[0].TryStart);
            var answer = new StaticMachine().Execute(method, [StaticValue.FromInt32(0)]);
            Assert.Equal(StaticExecutionStatus.Completed, answer.Status); Assert.Equal(-1, answer.Value.AsInt32());
        } else Assert.Empty(recovered);
    }

    [Fact]
    public void CleanupPreservesRuntimeDelegateConstructorWithoutAnExplicitCall()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var delegateType = new TypeDefUser("Synthetic", "HiddenDelegate", module.CorLibTypes.GetTypeRef("System", "MulticastDelegate"));
            module.Types.Add(delegateType);
            delegateType.Methods.Add(new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr),
                MethodImplAttributes.Runtime, MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName));
            delegateType.Methods.Add(new MethodDefUser("Invoke", MethodSig.CreateInstance(module.CorLibTypes.Void),
                MethodImplAttributes.Runtime, MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.NewSlot));
            var host = SyntheticContext.AddType(module, "Host"); host.Attributes = TypeAttributes.Public;
            host.Fields.Add(new FieldDefUser("Callback", new FieldSig(delegateType.ToTypeSig()), FieldAttributes.Public | FieldAttributes.Static));
        });
        var type = context.Module.GetTypes().Single(t => t.Name == "HiddenDelegate");
        var ctor = type.FindMethod(".ctor");
        RecoveryOrphans.Declare(context, ctor);
        context.SetFact("options.removeRuntime", true);
        new RuntimeCleanupPass().Run(context);
        Assert.Contains(type, context.Module.Types); Assert.Contains(ctor, type.Methods);
    }
}
