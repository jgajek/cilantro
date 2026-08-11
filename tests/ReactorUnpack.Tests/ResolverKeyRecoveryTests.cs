using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Interpretation;
using ReactorUnpack.Core.Strings;

namespace ReactorUnpack.Tests;

public sealed class ResolverKeyRecoveryTests
{
    [Fact]
    public void ForwardingWrapperCountsAsAResolverAlias()
    {
        using var module = NewModule();
        var resolver = NewResolver(module);
        var alias = NewForwarder(module, "Forward", module.CorLibTypes.String, resolver);

        var aliases = ResolverAliasAnalysis.Resolve(module, resolver);

        Assert.Contains(resolver, aliases);
        Assert.Contains(alias, aliases);
        Assert.Equal(2, aliases.Count);
    }

    [Fact]
    public void AliasClosureFollowsChainedForwarders()
    {
        using var module = NewModule();
        var resolver = NewResolver(module);
        var first = NewForwarder(module, "First", module.CorLibTypes.String, resolver);
        var second = NewForwarder(module, "Second", module.CorLibTypes.Object, first);

        var aliases = ResolverAliasAnalysis.Resolve(module, resolver);

        Assert.Contains(second, aliases);
        Assert.Equal(3, aliases.Count);
    }

    [Fact]
    public void ForwarderThatReadsItsArgumentTwiceIsNotAnAlias()
    {
        using var module = NewModule();
        var resolver = NewResolver(module);
        // A body that observes the offset a second time is doing more than forwarding, so the
        // argument at its call sites cannot be attributed to the single resolver call.
        var suspicious = NewMethod(
            module, "Doubtful",
            MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.Int32));
        suspicious.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
        suspicious.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
        suspicious.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
        suspicious.Body.Instructions.Add(Instruction.Create(OpCodes.Call, resolver));
        suspicious.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

        var aliases = ResolverAliasAnalysis.Resolve(module, resolver);

        Assert.DoesNotContain(suspicious, aliases);
    }

    [Fact]
    public void ForwarderWithAnExceptionHandlerIsNotAnAlias()
    {
        using var module = NewModule();
        var resolver = NewResolver(module);
        var guarded = NewForwarder(module, "Guarded", module.CorLibTypes.String, resolver);
        var start = guarded.Body.Instructions[0];
        guarded.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Finally)
        {
            TryStart = start,
            TryEnd = guarded.Body.Instructions[^1],
            HandlerStart = guarded.Body.Instructions[^1],
            HandlerEnd = guarded.Body.Instructions[^1]
        });

        var aliases = ResolverAliasAnalysis.Resolve(module, resolver);

        Assert.DoesNotContain(guarded, aliases);
    }

    [Fact]
    public void SelfRootedSingletonWithIntegerBlockIsAKeyHolder()
    {
        using var module = NewModule();
        var holder = NewKeyHolder(module, integerFieldCount: 12);

        Assert.True(ReactorStructureDetector.IsResolverKeyHolder(holder));
    }

    [Fact]
    public void OrdinaryTypeWithFewIntegerFieldsIsNotAKeyHolder()
    {
        using var module = NewModule();
        var holder = NewKeyHolder(module, integerFieldCount: 3);

        Assert.False(ReactorStructureDetector.IsResolverKeyHolder(holder));
    }

    [Fact]
    public void CaptureReadsOnlyFieldsTheInterpretationAssigned()
    {
        using var module = NewModule();
        var holder = NewKeyHolder(module, integerFieldCount: 8);
        var assigned = holder.Fields.First(field =>
            !field.IsStatic && field.FieldSig.Type.ElementType == ElementType.I4);
        var singleton = holder.Fields.First(field => field.IsStatic);
        var machine = new StaticMachine();
        Assert.True(machine.State.Heap.TryAllocateObject(holder.FullName, out var instance));
        Assert.True(machine.State.Heap.TryWriteField(
            instance, assigned, StaticValue.FromInt32(1234)));
        machine.State.WriteStaticField(singleton, instance);

        var keys = InitializedFieldCapture.CaptureInstanceIntegers(module, machine.State);

        // Only the written field is trusted; the untouched siblings must stay absent rather than
        // resolving through a defaulted zero.
        Assert.Equal(1234, keys[assigned.MDToken.Raw]);
        Assert.Single(keys);
    }

    [Fact]
    public void CapturesAgreeRejectsDivergentValues()
    {
        var first = new Dictionary<uint, int> { [1] = 10, [2] = 20 };
        var same = new Dictionary<uint, int> { [2] = 20, [1] = 10 };
        var divergent = new Dictionary<uint, int> { [1] = 10, [2] = 21 };
        var shorter = new Dictionary<uint, int> { [1] = 10 };

        Assert.True(InitializedFieldCapture.CapturesAgree(first, same));
        Assert.False(InitializedFieldCapture.CapturesAgree(first, divergent));
        Assert.False(InitializedFieldCapture.CapturesAgree(first, shorter));
    }

    [Fact]
    public void StrictFieldReadDistinguishesUnassignedFromZero()
    {
        using var module = NewModule();
        var holder = NewKeyHolder(module, integerFieldCount: 2);
        var fields = holder.Fields
            .Where(field => !field.IsStatic && field.FieldSig.Type.ElementType == ElementType.I4)
            .ToArray();
        var heap = new StaticHeap(new StaticMachineLimits());
        Assert.True(heap.TryAllocateObject(holder.FullName, out var instance));
        Assert.True(heap.TryWriteField(instance, fields[0], StaticValue.FromInt32(0)));

        Assert.True(heap.TryReadAssignedField(instance, fields[0], out var stored));
        Assert.Equal(0, stored.AsInt32());
        Assert.False(heap.TryReadAssignedField(instance, fields[1], out _));
        // The permissive read still models CLR defaulting for ordinary interpretation.
        Assert.True(heap.TryReadField(instance, fields[1], out var defaulted));
        Assert.Equal(0, defaulted.AsInt32());
    }

    private static ModuleDefUser NewModule()
    {
        var module = new ModuleDefUser("resolver-keys.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser("resolver-keys", new Version(1, 0));
        assembly.Modules.Add(module);
        return module;
    }

    private static TypeDef HostType(ModuleDef module)
    {
        var type = module.Types.FirstOrDefault(item => item.Name == "Runtime");
        if (type is null)
        {
            type = new TypeDefUser("Tests", "Runtime", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);
        }
        return type;
    }

    private static MethodDefUser NewMethod(ModuleDef module, string name, MethodSig signature)
    {
        var method = new MethodDefUser(name, signature)
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        HostType(module).Methods.Add(method);
        return method;
    }

    private static MethodDefUser NewResolver(ModuleDef module)
    {
        var resolver = NewMethod(
            module, "Resolve",
            MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.Int32));
        resolver.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
        resolver.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        return resolver;
    }

    private static MethodDefUser NewForwarder(
        ModuleDef module,
        string name,
        TypeSig returnType,
        MethodDef target)
    {
        var forwarder = NewMethod(
            module, name, MethodSig.CreateStatic(returnType, module.CorLibTypes.Int32));
        forwarder.Body.Instructions.Add(Instruction.Create(OpCodes.Nop));
        forwarder.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
        forwarder.Body.Instructions.Add(Instruction.Create(OpCodes.Call, target));
        forwarder.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        return forwarder;
    }

    private static TypeDefUser NewKeyHolder(ModuleDef module, int integerFieldCount)
    {
        var holder = new TypeDefUser(
            "Tests", "KeyHolder", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(holder);
        holder.Fields.Add(new FieldDefUser(
            "singleton",
            new FieldSig(holder.ToTypeSig()),
            FieldAttributes.Static | FieldAttributes.Public));
        for (var index = 0; index < integerFieldCount; index++)
        {
            holder.Fields.Add(new FieldDefUser(
                $"key{index}",
                new FieldSig(module.CorLibTypes.Int32),
                FieldAttributes.Public));
        }
        var initializer = new MethodDefUser(
            ".cctor",
            MethodSig.CreateStatic(module.CorLibTypes.Void))
        {
            Attributes = MethodAttributes.Static | MethodAttributes.SpecialName |
                MethodAttributes.RTSpecialName | MethodAttributes.Private,
            Body = new CilBody()
        };
        initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        holder.Methods.Add(initializer);
        return holder;
    }
}
