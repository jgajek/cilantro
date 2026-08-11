using System.IO.Compression;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core;
using ReactorUnpack.Core.Analysis;
using ReactorUnpack.Core.Interpretation;
using ReactorUnpack.Core.Recovery;

namespace ReactorUnpack.Tests;

/// <summary>
/// Covers reading Reactor's encrypted managed-resource bundle back into named streams.
/// </summary>
/// <remarks>
/// Two things have to hold for the real path to work, and each fails silently on its own. The
/// interpreter has to drain one stream into another, because that is the last step of every
/// decompression Reactor emits and a missing model there stops the interpretation just short of the
/// plaintext. And the plaintext has to be recognised as the satellite assembly it is, including
/// being rejected when it is anything else, since that recognition is what picks the bundle out of
/// the many buffers a decryptor allocates.
/// </remarks>
public sealed class ResourceRestorationTests
{
    [Fact]
    public void DrainingACompressedStreamIntoAnotherYieldsTheInflatedBytes()
    {
        var plaintext = new byte[512];
        for (var index = 0; index < plaintext.Length; index++)
            plaintext[index] = (byte)(index % 7);
        using var module = NewModule();
        var state = new StaticMachineState(new StaticMachineLimits());
        var intrinsic = new LoaderFrameworkIntrinsic();
        var source = NewMemoryStream(module, state, intrinsic, Deflate(plaintext));
        var inflater = NewDeflateStream(module, state, intrinsic, source);
        var destination = NewMemoryStream(module, state, intrinsic, []);

        var copy = intrinsic.Invoke(
            new IntrinsicContext(state),
            new MemberRefUser(
                module,
                "CopyTo",
                MethodSig.CreateInstance(module.CorLibTypes.Void, StreamSig(module)),
                StreamType(module)),
            [inflater, destination]);

        Assert.Equal(StaticExecutionStatus.Completed, copy.Status);
        Assert.True(state.Heap.TryGetModelValue(destination, "Buffer", out StaticValue written));
        Assert.Equal(plaintext, state.Heap.GetBytesSnapshot(written));
    }

    [Fact]
    public void ASatelliteAssemblyIsReadBackAsItsNamedStreams()
    {
        var bundle = NewSatellite(
            ("App.g.resources", [1, 2, 3]),
            ("App.Strings.resources", [4, 5]));

        Assert.True(ResourceContainer.TryParse(bundle, out var streams));
        Assert.Equal(
            ["App.Strings.resources", "App.g.resources"],
            streams.Select(stream => stream.Name).Order(StringComparer.Ordinal));
        Assert.Equal(
            [1, 2, 3],
            streams.Single(stream => stream.Name == "App.g.resources").Data);
    }

    [Fact]
    public void AnAssemblyWithoutResourcesIsNotMistakenForTheBundle()
    {
        Assert.False(ResourceContainer.LooksLikeContainer(NewSatellite()));
    }

    [Fact]
    public void AnIntermediateDecryptionBufferIsNotMistakenForTheBundle()
    {
        var noise = new byte[4096];
        for (var index = 0; index < noise.Length; index++)
            noise[index] = (byte)(index * 31 % 251);

        Assert.False(ResourceContainer.LooksLikeContainer(noise));
        Assert.False(ResourceContainer.LooksLikeContainer([]));
    }

    [Fact]
    public void TheResolveHookGoesOnceItsResourcesAreOnTheModule()
    {
        using var context = HookContext();
        Reattach(context, "App.g.resources");

        var result = new ResourceHookElisionPass().Run(context);
        var installer = Installer(context);

        Assert.True(
            result.Status == PassStatus.Success, string.Join("; ", result.Diagnostics));
        Assert.Equal(1, result.Changes);
        Assert.DoesNotContain(
            installer.Body.Instructions,
            instruction => instruction.Operand is IMethod called &&
                called.Name == "add_ResourceResolve");
        Assert.Contains(
            RecoveryOrphans.Of(context),
            token => token == Handler(context).MDToken.Raw);
    }

    [Fact]
    public void TheResolveHookStaysWhenNothingWasReattached()
    {
        using var context = HookContext();

        var result = new ResourceHookElisionPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(0, result.Changes);
        Assert.Contains(
            Installer(context).Body.Instructions,
            instruction => instruction.Operand is IMethod called &&
                called.Name == "add_ResourceResolve");
    }

    [Fact]
    public void TheResolveHookStaysWhileAnUnextractedPayloadCouldNeedIt()
    {
        using var context = HookContext(ResourceRole.ManagedPayload);
        Reattach(context, "App.g.resources");

        var result = new ResourceHookElisionPass().Run(context);

        Assert.Equal(PassStatus.Unsupported, result.Status);
        Assert.Contains(
            Installer(context).Body.Instructions,
            instruction => instruction.Operand is IMethod called &&
                called.Name == "add_ResourceResolve");
    }

    /// <summary>
    /// Puts a resource on the module and declares it, as restoration would have.
    /// </summary>
    private static void Reattach(ArtifactContext context, string name)
    {
        context.Module.Resources.Add(
            new EmbeddedResource(name, [1, 2, 3], ManifestResourceAttributes.Public));
        context.SetFact<IReadOnlySet<string>>(
            "resources.addedResources", new HashSet<string>(StringComparer.Ordinal) { name });
    }

    private static MethodDef Installer(ArtifactContext context) =>
        context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Single(method => method.Name == "Install");

    private static MethodDef Handler(ArtifactContext context) =>
        context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Single(method => method.Name == "Resolve");

    /// <summary>
    /// A module holding the shape the pass keys on: a handler subscribed to
    /// <c>AppDomain.CurrentDomain.ResourceResolve</c> from an installer.
    /// </summary>
    private static ArtifactContext HookContext(ResourceRole role = ResourceRole.EncryptedResourceBundle)
    {
        var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "ResolverHost");
            var corlib = module.CorLibTypes.AssemblyRef;
            var appDomain = new TypeRefUser(module, "System", "AppDomain", corlib);
            var handlerType = new TypeRefUser(module, "System", "ResolveEventHandler", corlib);
            var eventArgs = new TypeRefUser(module, "System", "ResolveEventArgs", corlib);
            var assemblyType = new TypeRefUser(module, "System.Reflection", "Assembly", corlib);

            var resolve = new MethodDefUser(
                "Resolve",
                MethodSig.CreateStatic(
                    assemblyType.ToTypeSig(),
                    module.CorLibTypes.Object,
                    eventArgs.ToTypeSig()),
                MethodImplAttributes.IL,
                MethodAttributes.Assembly | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            resolve.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            resolve.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            host.Methods.Add(resolve);

            var install = new MethodDefUser(
                "Install",
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL,
                MethodAttributes.Assembly | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            install.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(
                module,
                "get_CurrentDomain",
                MethodSig.CreateStatic(appDomain.ToTypeSig()),
                appDomain)));
            install.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
            install.Body.Instructions.Add(OpCodes.Ldftn.ToInstruction(resolve));
            install.Body.Instructions.Add(OpCodes.Newobj.ToInstruction(new MemberRefUser(
                module,
                ".ctor",
                MethodSig.CreateInstance(
                    module.CorLibTypes.Void,
                    module.CorLibTypes.Object,
                    module.CorLibTypes.IntPtr),
                handlerType)));
            install.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(
                module,
                "add_ResourceResolve",
                MethodSig.CreateInstance(module.CorLibTypes.Void, handlerType.ToTypeSig()),
                appDomain)));
            install.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            host.Methods.Add(install);
        });
        context.SetFact<IReadOnlyList<ResourceRoleFact>>(
            "resource.roles", [new ResourceRoleFact("bundle", role, 1.0, [], [])]);
        return context;
    }

    private static byte[] Deflate(byte[] plaintext)
    {
        using var compressed = new MemoryStream();
        using (var deflate = new DeflateStream(compressed, CompressionMode.Compress, true))
            deflate.Write(plaintext, 0, plaintext.Length);
        return compressed.ToArray();
    }

    private static byte[] NewSatellite(params (string Name, byte[] Data)[] resources)
    {
        using var module = new ModuleDefUser("Satellite.resources.dll");
        module.Kind = ModuleKind.Dll;
        var assembly = new AssemblyDefUser("Satellite.resources", new Version(1, 0, 0, 0));
        assembly.Modules.Add(module);
        foreach (var resource in resources)
        {
            module.Resources.Add(new EmbeddedResource(
                resource.Name, resource.Data, ManifestResourceAttributes.Public));
        }

        using var written = new MemoryStream();
        module.Write(written);
        return written.ToArray();
    }

    private static TypeRefUser StreamType(ModuleDef module) =>
        new(module, "System.IO", "Stream", module.CorLibTypes.AssemblyRef);

    private static TypeSig StreamSig(ModuleDef module) => StreamType(module).ToTypeSig();

    private static StaticValue NewMemoryStream(
        ModuleDef module,
        StaticMachineState state,
        LoaderFrameworkIntrinsic intrinsic,
        byte[] initial)
    {
        var type = new TypeRefUser(
            module, "System.IO", "MemoryStream", module.CorLibTypes.AssemblyRef);
        Assert.True(state.Heap.TryAllocateObject("System.IO.MemoryStream", out var stream));
        if (initial.Length == 0)
        {
            Assert.Equal(
                StaticExecutionStatus.Completed,
                intrinsic.Invoke(
                    new IntrinsicContext(state),
                    new MemberRefUser(
                        module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), type),
                    [stream]).Status);
            return stream;
        }

        Assert.True(state.Heap.TryAllocateByteArray(initial, out var buffer));
        Assert.Equal(
            StaticExecutionStatus.Completed,
            intrinsic.Invoke(
                new IntrinsicContext(state),
                new MemberRefUser(
                    module,
                    ".ctor",
                    MethodSig.CreateInstance(
                        module.CorLibTypes.Void, new SZArraySig(module.CorLibTypes.Byte)),
                    type),
                [stream, buffer]).Status);
        return stream;
    }

    private static StaticValue NewDeflateStream(
        ModuleDef module,
        StaticMachineState state,
        LoaderFrameworkIntrinsic intrinsic,
        StaticValue source)
    {
        var type = new TypeRefUser(
            module, "System.IO.Compression", "DeflateStream", module.CorLibTypes.AssemblyRef);
        Assert.True(state.Heap.TryAllocateObject(
            "System.IO.Compression.DeflateStream", out var inflater));
        Assert.Equal(
            StaticExecutionStatus.Completed,
            intrinsic.Invoke(
                new IntrinsicContext(state),
                new MemberRefUser(
                    module,
                    ".ctor",
                    MethodSig.CreateInstance(
                        module.CorLibTypes.Void, StreamSig(module), module.CorLibTypes.Int32),
                    type),
                [inflater, source, StaticValue.FromInt32(0)]).Status);
        return inflater;
    }

    private static ModuleDefUser NewModule()
    {
        var module = new ModuleDefUser("ResourceRestorationTests.dll");
        module.Kind = ModuleKind.Dll;
        var assembly = new AssemblyDefUser("ResourceRestorationTests", new Version(1, 0, 0, 0));
        assembly.Modules.Add(module);
        return module;
    }
}
