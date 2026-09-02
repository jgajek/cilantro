using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;

namespace Cilantro.Tests;

/// <summary>
/// Covers which methods the reachability walk treats as able to run.
/// </summary>
/// <remarks>
/// The deletions and constant-folding downstream are only as sound as this set, and the failure mode
/// is silent: a method wrongly left out is a method whose code can be deleted or whose writes are
/// ignored. Each root kind is therefore checked on its own, along with the deliberate
/// over-approximation on virtual dispatch, and the edge of the module, where the walk has to stop
/// for the answer to be about the file rather than about the machine reading it.
/// </remarks>
public sealed class ModuleReachabilityTests : IDisposable
{
    private readonly string _folder =
        Directory.CreateTempSubdirectory("Cilantro.Reachability").FullName;

    public void Dispose() => Directory.Delete(_folder, recursive: true);

    [Fact]
    public void PublicSurfaceAndWhatItCallsAreReachable()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Api");
            type.Attributes = TypeAttributes.Public | TypeAttributes.Class;
            var helper = AddMethod(type, "Helper", MethodAttributes.Private | MethodAttributes.Static);
            var entry = AddMethod(type, "Run", MethodAttributes.Public | MethodAttributes.Static);
            entry.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(helper));
        });

        var reachability = ModuleReachability.Compute(context.Module);

        Assert.True(reachability.IsReachable(Find(context, "Run")));
        Assert.True(reachability.IsReachable(Find(context, "Helper")));
    }

    [Fact]
    public void PublicMethodOfANonPublicTypeIsNotAnEntryFromOutside()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Internal");
            AddMethod(type, "Orphan", MethodAttributes.Public | MethodAttributes.Static);
        });

        var reachability = ModuleReachability.Compute(context.Module);

        Assert.False(reachability.IsReachable(Find(context, "Orphan")));
    }

    [Fact]
    public void TypeInitializersAndFinalizersAreRootsTheRuntimeInvokes()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Hidden");
            AddMethod(
                type,
                ".cctor",
                MethodAttributes.Private | MethodAttributes.Static |
                MethodAttributes.SpecialName | MethodAttributes.RTSpecialName);
            AddMethod(type, "Finalize", MethodAttributes.Family | MethodAttributes.Virtual, isStatic: false);
        });

        var reachability = ModuleReachability.Compute(context.Module);

        Assert.True(reachability.IsReachable(Find(context, ".cctor")));
        Assert.True(reachability.IsReachable(Find(context, "Finalize")));
    }

    [Fact]
    public void CallvirtKeepsEveryOverrideThatCouldSatisfyIt()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var api = SyntheticContext.AddType(module, "Api");
            api.Attributes = TypeAttributes.Public | TypeAttributes.Class;

            var baseType = SyntheticContext.AddType(module, "Shape");
            var declared = AddMethod(
                baseType, "Draw", MethodAttributes.Public | MethodAttributes.Virtual, isStatic: false);

            var derived = SyntheticContext.AddType(module, "Circle");
            derived.BaseType = baseType;
            AddMethod(
                derived, "Draw", MethodAttributes.Public | MethodAttributes.Virtual, isStatic: false);

            var entry = AddMethod(api, "Run", MethodAttributes.Public | MethodAttributes.Static);
            entry.Body.Instructions.Insert(0, OpCodes.Ldnull.ToInstruction());
            entry.Body.Instructions.Insert(1, OpCodes.Callvirt.ToInstruction(declared));
        });

        var reachability = ModuleReachability.Compute(context.Module);

        var overrides = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.Name == "Draw")
            .ToArray();
        Assert.Equal(2, overrides.Length);
        Assert.All(overrides, method => Assert.True(reachability.IsReachable(method)));
    }

    [Fact]
    public void LoadingATypeHandleExposesItToReflectionWithoutRunningIt()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var api = SyntheticContext.AddType(module, "Api");
            api.Attributes = TypeAttributes.Public | TypeAttributes.Class;
            var hidden = SyntheticContext.AddType(module, "Hidden");
            AddMethod(hidden, "Never", MethodAttributes.Private | MethodAttributes.Static);

            var entry = AddMethod(api, "Run", MethodAttributes.Public | MethodAttributes.Static);
            entry.Body.Instructions.Insert(0, OpCodes.Ldtoken.ToInstruction(hidden));
            entry.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
        });

        var reachability = ModuleReachability.Compute(context.Module);

        var hidden = context.Module.GetTypes().Single(type => type.Name == "Hidden");
        Assert.True(reachability.IsReflectivelyExposed(hidden));
        Assert.False(reachability.IsReachable(Find(context, "Never")));
    }

    /// <summary>
    /// A body outside the module is not read, however resolvable it happens to be here.
    /// </summary>
    /// <remarks>
    /// This is what made the same sample clean up differently on two machines. The walk followed a
    /// call out of the module, and on a machine whose framework was installed it found a body,
    /// stepped into somebody else's IL, and marked this module's methods reachable wherever that
    /// IL called something of a matching shape — so scaffolding that was plainly dead on one desk
    /// was kept on another. The library here stands in for that framework: resolvable, never
    /// supplied, and calling something shaped like a method of the sample it knows nothing about.
    /// </remarks>
    [Fact]
    public void SomebodyElsesBodyIsNotReadEvenWhenItIsThereToRead()
    {
        var library = WriteLibraryCalling("helper", "Draw");
        using var context = Core.ArtifactContext.Load(WriteCallerOf("caller", "helper"), [library]);
        // The point of the test is a body that is there to be stepped into, so say so.
        var reference = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody)
            .SelectMany(method => method.Body.Instructions)
            .Where(instruction => instruction.OpCode == OpCodes.Call)
            .Select(instruction => (IMethod)instruction.Operand)
            .First();
        Assert.True(reference.ResolveMethodDef() is { HasBody: true });

        var reachability = ModuleReachability.Compute(context.Module);

        Assert.False(reachability.IsReachable(Find(context, "Draw")));
        Assert.All(
            reachability.ReachableMethods,
            method => Assert.Same(context.Module, method.Module));
    }

    /// <summary>
    /// A library whose one method calls something named <paramref name="calls"/>, matching the
    /// shape of a method the sample declares and nothing in the sample calls.
    /// </summary>
    private string WriteLibraryCalling(string name, string calls)
    {
        var module = new ModuleDefUser($"{name}.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser(name, new Version(1, 0, 0, 0));
        assembly.Modules.Add(module);
        var type = new TypeDefUser("Library", "Answers", module.CorLibTypes.Object.TypeDefOrRef)
        {
            Attributes = TypeAttributes.Public | TypeAttributes.Class
        };
        module.Types.Add(type);
        var method = new MethodDefUser(
            "Answer", MethodSig.CreateStatic(module.CorLibTypes.Int32))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
        method.Body.Instructions.Add(Instruction.Create(
            OpCodes.Callvirt,
            new MemberRefUser(
                module,
                calls,
                MethodSig.CreateInstance(module.CorLibTypes.Void),
                type)));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 41));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(method);
        var path = Path.Combine(_folder, $"{name}.dll");
        module.Write(path);
        return path;
    }

    /// <summary>
    /// A sample that calls into the library, and separately declares a virtual method of the shape
    /// the library's body calls, which nothing in the sample reaches.
    /// </summary>
    private string WriteCallerOf(string name, string library)
    {
        var module = new ModuleDefUser($"{name}.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser(name, new Version(1, 0, 0, 0));
        assembly.Modules.Add(module);
        var reference = new AssemblyRefUser(library, new Version(1, 0, 0, 0));
        module.UpdateRowId(reference);

        var api = new TypeDefUser("Sample", "Api", module.CorLibTypes.Object.TypeDefOrRef)
        {
            Attributes = TypeAttributes.Public | TypeAttributes.Class
        };
        module.Types.Add(api);
        var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Int32))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        run.Body.Instructions.Add(Instruction.Create(
            OpCodes.Call,
            new MemberRefUser(
                module,
                "Answer",
                MethodSig.CreateStatic(module.CorLibTypes.Int32),
                new TypeRefUser(module, "Library", "Answers", reference))));
        run.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        api.Methods.Add(run);

        // Not visible from outside and nothing here calls it, so the only way it could be reached
        // is by reading the library's body.
        var scaffolding = new TypeDefUser(
            "Sample", "Scaffolding", module.CorLibTypes.Object.TypeDefOrRef);
        module.Types.Add(scaffolding);
        scaffolding.Methods.Add(new MethodDefUser(
            "Draw", MethodSig.CreateInstance(module.CorLibTypes.Void))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Virtual |
                MethodAttributes.NewSlot,
            Body = new CilBody()
        });
        scaffolding.FindMethod("Draw").Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

        var path = Path.Combine(_folder, $"{name}.dll");
        module.Write(path);
        return path;
    }

    private static MethodDefUser AddMethod(
        TypeDef type, string name, MethodAttributes attributes, bool isStatic = true)
    {
        var signature = isStatic
            ? MethodSig.CreateStatic(type.Module.CorLibTypes.Void)
            : MethodSig.CreateInstance(type.Module.CorLibTypes.Void);
        var method = new MethodDefUser(name, signature, MethodImplAttributes.IL, attributes)
        {
            Body = new CilBody()
        };
        method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        type.Methods.Add(method);
        return method;
    }

    private static MethodDef Find(Core.ArtifactContext context, string name) =>
        context.Module.GetTypes().SelectMany(type => type.Methods).First(method => method.Name == name);
}
