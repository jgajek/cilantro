using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Recovery;

namespace ReactorUnpack.Tests;

/// <summary>
/// Covers the proof that decides whether a loader-initialized field is a program-wide constant, and
/// the rewrite that depends on it.
/// </summary>
/// <remarks>
/// The interesting cases are the refusals. Folding a field something can still write would silently
/// change behavior, and unlike a malformed rewrite that failure would pass verification, so each way
/// a later write can reach the field is exercised on its own.
/// </remarks>
public sealed class GlobalStateFoldingTests
{
    [Fact]
    public void FieldWrittenOnlyByATypeInitializerIsWriteOnce()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Holder");
            var field = AddStaticInt(type, "state");
            AddInitializer(module, type, field);
        });

        var safety = FieldWriteSafety.Analyze(context.Module);

        Assert.Null(safety.Refusal);
        Assert.True(safety.IsWriteOnceDuringInitialization(FieldToken(context, "state")));
    }

    [Fact]
    public void FieldAnOrdinaryMethodCanWriteIsNotWriteOnce()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Holder");
            var field = AddStaticInt(type, "state");
            AddInitializer(module, type, field);

            var setter = new MethodDefUser(
                "Set",
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL,
                MethodAttributes.Assembly | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            setter.Body.Instructions.Add(OpCodes.Ldc_I4.ToInstruction(9));
            setter.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(field));
            setter.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            type.Methods.Add(setter);
            AddPublicCaller(module, setter);
        });

        var safety = FieldWriteSafety.Analyze(context.Module);

        Assert.Null(safety.Refusal);
        Assert.False(safety.IsWriteOnceDuringInitialization(FieldToken(context, "state")));
    }

    [Fact]
    public void FieldWhoseAddressIsTakenIsNotWriteOnce()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Holder");
            var field = AddStaticInt(type, "state");
            AddInitializer(module, type, field);

            var leak = new MethodDefUser(
                "Leak",
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            leak.Body.Instructions.Add(OpCodes.Ldsflda.ToInstruction(field));
            leak.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            leak.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            type.Methods.Add(leak);
        });

        var safety = FieldWriteSafety.Analyze(context.Module);

        Assert.False(safety.IsWriteOnceDuringInitialization(FieldToken(context, "state")));
    }

    [Fact]
    public void ExternallyVisibleFieldIsNeverWriteOnce()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Holder");
            type.Attributes = TypeAttributes.Public | TypeAttributes.Class;
            var field = AddStaticInt(type, "state");
            AddInitializer(module, type, field);
        });

        var safety = FieldWriteSafety.Analyze(context.Module);

        Assert.False(safety.IsWriteOnceDuringInitialization(FieldToken(context, "state")));
    }

    [Fact]
    public void ReachableReflectiveWriteRefusesTheWholeAnalysis()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Holder");
            var field = AddStaticInt(type, "state");
            AddInitializer(module, type, field);

            var fieldInfo = new TypeRefUser(module, "System.Reflection", "FieldInfo", module.CorLibTypes.AssemblyRef);
            var setValue = new MemberRefUser(
                module,
                "SetValue",
                MethodSig.CreateInstance(
                    module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.Object),
                fieldInfo);
            var writer = new MethodDefUser(
                "WriteAnything",
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL,
                MethodAttributes.Assembly | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            writer.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            writer.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            writer.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            writer.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(setValue));
            writer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            type.Methods.Add(writer);
            AddPublicCaller(module, writer);
        });

        var safety = FieldWriteSafety.Analyze(context.Module);

        Assert.NotNull(safety.Refusal);
        Assert.False(safety.IsWriteOnceDuringInitialization(FieldToken(context, "state")));
    }

    [Fact]
    public void UnreachableMethodsAreNotCountedAsWriters()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Holder");
            var field = AddStaticInt(type, "state");
            AddInitializer(module, type, field);

            // Private, never called: this cannot run, so it cannot overwrite anything.
            var orphan = new MethodDefUser(
                "Orphan",
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL,
                MethodAttributes.Private | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            orphan.Body.Instructions.Add(OpCodes.Ldc_I4.ToInstruction(9));
            orphan.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(field));
            orphan.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            type.Methods.Add(orphan);
        });

        var safety = FieldWriteSafety.Analyze(context.Module);

        Assert.True(safety.IsWriteOnceDuringInitialization(FieldToken(context, "state")));
    }

    [Fact]
    public void ProvenStaticReadsBecomeConstantsAndTheModuleStillVerifies()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Holder");
            var field = AddStaticInt(type, "state");
            AddInitializer(module, type, field);

            var reader = new MethodDefUser(
                "Read",
                MethodSig.CreateStatic(module.CorLibTypes.Int32),
                MethodImplAttributes.IL,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            reader.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(field));
            reader.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            type.Methods.Add(reader);
        });

        var token = FieldToken(context, "state");
        context.SetFact(
            "globals.state",
            new CapturedGlobalState(
                new Dictionary<uint, int>(),
                new Dictionary<uint, int> { [token] = 42 }));

        var result = new GlobalPredicateFoldingPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(1, result.Changes);
        var read = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Single(method => method.Name == "Read");
        Assert.Equal(OpCodes.Ldc_I4, read.Body.Instructions[0].OpCode);
        Assert.Equal(42, read.Body.Instructions[0].Operand);
    }

    [Fact]
    public void FoldingIsWithheldWhenNoStateWasProven()
    {
        using var context = SyntheticContext.Build(module =>
            SyntheticContext.AddType(module, "Holder"));

        var result = new GlobalPredicateFoldingPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(0, result.Changes);
    }

    /// <summary>
    /// Gives <paramref name="target"/> a way to run, by calling it from the assembly's public surface.
    /// </summary>
    /// <remarks>
    /// Without this the analysis is right to ignore a writer: a method in a non-public type that
    /// nothing calls can never execute, so it can never overwrite anything.
    /// </remarks>
    private static void AddPublicCaller(ModuleDefUser module, MethodDef target)
    {
        var entry = SyntheticContext.AddType(module, "Api");
        entry.Attributes = TypeAttributes.Public | TypeAttributes.Class;
        var caller = new MethodDefUser(
            "Run",
            MethodSig.CreateStatic(module.CorLibTypes.Void),
            MethodImplAttributes.IL,
            MethodAttributes.Public | MethodAttributes.Static)
        {
            Body = new CilBody()
        };
        caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(target));
        caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        entry.Methods.Add(caller);
    }

    private static FieldDefUser AddStaticInt(TypeDef type, string name)
    {
        var field = new FieldDefUser(
            name,
            new FieldSig(type.Module.CorLibTypes.Int32),
            FieldAttributes.Private | FieldAttributes.Static);
        type.Fields.Add(field);
        return field;
    }

    private static void AddInitializer(ModuleDefUser module, TypeDef type, FieldDefUser field)
    {
        var initializer = new MethodDefUser(
            ".cctor",
            MethodSig.CreateStatic(module.CorLibTypes.Void),
            MethodImplAttributes.IL,
            MethodAttributes.Private | MethodAttributes.Static |
            MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
        {
            Body = new CilBody()
        };
        initializer.Body.Instructions.Add(OpCodes.Ldc_I4.ToInstruction(42));
        initializer.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(field));
        initializer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        type.Methods.Add(initializer);
    }

    private static uint FieldToken(ArtifactContext context, string name) =>
        context.Module.GetTypes()
            .SelectMany(type => type.Fields)
            .Single(field => field.Name == name)
            .MDToken.Raw;
}
