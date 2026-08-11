using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Interpretation;
using ReactorUnpack.Core.Recovery;

namespace ReactorUnpack.Tests;

/// <summary>
/// Covers the proof that lets Reactor's bootstrap calls be cut: a complete account of what a loader
/// entry point does, and no way for what it did to be noticed once the calls are gone.
/// </summary>
/// <remarks>
/// Each test fixes one half of that. The account is only complete because the machine records
/// handing the runtime an event handler, which is the one modeled call that changes the program
/// while leaving nothing behind for the interpretation to see, so that has to be shown to reach the
/// evidence. And unobservability has to be judged against the module as it would be after the edit
/// rather than as it is, because Reactor's readers are reached through function pointers taken
/// inside the loader and are stranded by the very removal being considered.
/// </remarks>
public sealed class LoaderCallElisionTests
{
    [Fact]
    public void SubscribingToTheRuntimeIsRecordedAsAnEffect()
    {
        using var module = NewModule();
        var subscribe = Subscriber(module);

        var machine = new StaticMachine();
        var result = machine.Execute(subscribe);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(
            ["AppDomain.ResourceResolve"],
            machine.State.LoaderEvidence.EffectsOf(subscribe.MDToken.Raw).Registrations);
    }

    [Fact]
    public void ALoaderCallGoesWhenItsOnlyReaderIsStrandedByItsRemoval()
    {
        using var context = LoaderContext();
        var install = Method(context, "Install");

        var result = new LoaderCallElisionPass().Run(context);

        Assert.True(result.Status == PassStatus.Success, string.Join("; ", result.Diagnostics));
        Assert.Equal(1, result.Changes);
        Assert.DoesNotContain(
            Method(context, ".cctor").Body.Instructions,
            instruction => instruction.Operand is IMethod called &&
                called.ResolveMethodDef() == install);
        Assert.Contains(RecoveryOrphans.Of(context), token => token == install.MDToken.Raw);
    }

    /// <summary>
    /// The call was the initializer's whole body, so removing it leaves an initializer that runs
    /// and returns. Cleanup will only take that away if it is told, and this pass is what emptied it.
    /// </summary>
    [Fact]
    public void TheInitializerLeftWithNothingInItIsClaimedToo()
    {
        using var context = LoaderContext();

        var result = new LoaderCallElisionPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        var initializer = Method(context, ".cctor");
        Assert.True(EmptyTypeInitializers.DoesNothing(initializer));
        Assert.Contains(RecoveryOrphans.Of(context), token => token == initializer.MDToken.Raw);
    }

    [Fact]
    public void ALoaderCallStaysWhileReachableCodeReadsWhatItWrote()
    {
        using var context = LoaderContext(observeFromProgram: true);

        var result = new LoaderCallElisionPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(0, result.Changes);
        Assert.Contains(
            Method(context, ".cctor").Body.Instructions,
            instruction => instruction.Operand is IMethod called &&
                called.Name == "Install");
    }

    [Fact]
    public void ALoaderCallStaysWhileItHandsTheRuntimeAHandler()
    {
        using var context = LoaderContext(registers: true);

        var result = new LoaderCallElisionPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(0, result.Changes);
        Assert.Contains(
            Method(context, ".cctor").Body.Instructions,
            instruction => instruction.Operand is IMethod called &&
                called.Name == "Install");
    }

    /// <summary>
    /// A module shaped like a protected one: a loader entry point called from the initializer of a
    /// program type, writing state that only the loader's own helper reads.
    /// </summary>
    /// <param name="observeFromProgram">
    /// Whether the program itself also reads that state, which is what makes the write observable
    /// and the call load-bearing.
    /// </param>
    /// <param name="registers">
    /// Whether the entry point hands the runtime a handler, which is an effect that outlives it and
    /// that removing the call would silently undo.
    /// </param>
    private static ArtifactContext LoaderContext(
        bool observeFromProgram = false,
        bool registers = false)
    {
        FieldDef? state = null;
        MethodDef? install = null;
        var context = SyntheticContext.Build(module =>
        {
            var runtime = SyntheticContext.AddType(module, "Runtime");
            state = new FieldDefUser(
                "state",
                new FieldSig(module.CorLibTypes.Int32),
                FieldAttributes.Assembly | FieldAttributes.Static);
            runtime.Fields.Add(state);

            // Only the entry point reaches this, so it survives the elision or not exactly as the
            // entry point does. That is the question the pass has to answer correctly.
            var helper = Static(module, "ReadState", module.CorLibTypes.Int32);
            helper.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(state));
            helper.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            runtime.Methods.Add(helper);

            install = Static(module, "Install", module.CorLibTypes.Void);
            install.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction());
            install.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(state));
            install.Body.Instructions.Add(OpCodes.Call.ToInstruction(helper));
            install.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            if (registers)
                Subscribe(module, runtime, install);
            install.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            runtime.Methods.Add(install);

            var program = new TypeDefUser("Synthetic", "Program", module.CorLibTypes.Object.TypeDefOrRef)
            {
                Attributes = TypeAttributes.Public | TypeAttributes.Class
            };
            module.Types.Add(program);

            var initializer = new MethodDefUser(
                ".cctor",
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig |
                MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            initializer.Body.Instructions.Add(OpCodes.Call.ToInstruction(install));
            initializer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            program.Methods.Add(initializer);

            var entry = new MethodDefUser(
                "Run",
                MethodSig.CreateStatic(module.CorLibTypes.Int32),
                MethodImplAttributes.IL,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            if (observeFromProgram)
                entry.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(state));
            else
                entry.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
            entry.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            program.Methods.Add(entry);
        });

        context.SetFact("method-protection.complete", true);
        var token = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Single(method => method.Name == "Install")
            .MDToken.Raw;
        context.SetFact("bootstrap.evidence", new LoaderInterpretationEvidence(
            [],
            new Dictionary<uint, LoaderMethodEffects>
            {
                [token] = new(
                    [$"System.Int32 Synthetic.Runtime::state"],
                    WroteMappedImage: false,
                    WroteScratchRegion: false,
                    registers ? ["AppDomain.ResourceResolve"] : [])
            }));
        return context;
    }

    private static MethodDef Method(ArtifactContext context, string name) =>
        context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Single(method => method.Name == name);

    private static MethodDefUser Static(ModuleDef module, string name, TypeSig returnType) =>
        new(
            name,
            MethodSig.CreateStatic(returnType),
            MethodImplAttributes.IL,
            MethodAttributes.Assembly | MethodAttributes.Static)
        {
            Body = new CilBody()
        };

    /// <summary>
    /// A method that performs <c>AppDomain.CurrentDomain.ResourceResolve += handler</c>.
    /// </summary>
    private static MethodDefUser Subscriber(ModuleDefUser module)
    {
        var host = new TypeDefUser("Synthetic", "Host", module.CorLibTypes.Object.TypeDefOrRef)
        {
            Attributes = TypeAttributes.NotPublic | TypeAttributes.Class
        };
        module.Types.Add(host);
        var subscribe = Static(module, "Subscribe", module.CorLibTypes.Void);
        Subscribe(module, host, subscribe);
        subscribe.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        host.Methods.Add(subscribe);
        return subscribe;
    }

    /// <summary>
    /// Appends a resource-resolve subscription, and the handler it subscribes, to a method.
    /// </summary>
    private static void Subscribe(ModuleDef module, TypeDef host, MethodDef subscriber)
    {
        var corlib = module.CorLibTypes.AssemblyRef;
        var appDomain = new TypeRefUser(module, "System", "AppDomain", corlib);
        var handlerType = new TypeRefUser(module, "System", "ResolveEventHandler", corlib);
        var eventArgs = new TypeRefUser(module, "System", "ResolveEventArgs", corlib);
        var assemblyType = new TypeRefUser(module, "System.Reflection", "Assembly", corlib);

        var handler = new MethodDefUser(
            "Resolve",
            MethodSig.CreateStatic(
                assemblyType.ToTypeSig(), module.CorLibTypes.Object, eventArgs.ToTypeSig()),
            MethodImplAttributes.IL,
            MethodAttributes.Assembly | MethodAttributes.Static)
        {
            Body = new CilBody()
        };
        handler.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
        handler.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        host.Methods.Add(handler);

        var body = subscriber.Body.Instructions;
        body.Add(OpCodes.Call.ToInstruction(new MemberRefUser(
            module, "get_CurrentDomain", MethodSig.CreateStatic(appDomain.ToTypeSig()), appDomain)));
        body.Add(OpCodes.Ldnull.ToInstruction());
        body.Add(OpCodes.Ldftn.ToInstruction(handler));
        body.Add(OpCodes.Newobj.ToInstruction(new MemberRefUser(
            module,
            ".ctor",
            MethodSig.CreateInstance(
                module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr),
            handlerType)));
        body.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(
            module,
            "add_ResourceResolve",
            MethodSig.CreateInstance(module.CorLibTypes.Void, handlerType.ToTypeSig()),
            appDomain)));
    }

    private static ModuleDefUser NewModule()
    {
        var module = new ModuleDefUser("LoaderCallElisionTests.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser("LoaderCallElisionTests", new Version(1, 0, 0, 0));
        assembly.Modules.Add(module);
        return module;
    }
}
