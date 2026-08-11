using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core.Analysis;

namespace ReactorUnpack.Tests;

/// <summary>
/// Covers which methods the reachability walk treats as able to run.
/// </summary>
/// <remarks>
/// The deletions and constant-folding downstream are only as sound as this set, and the failure mode
/// is silent: a method wrongly left out is a method whose code can be deleted or whose writes are
/// ignored. Each root kind is therefore checked on its own, along with the deliberate
/// over-approximation on virtual dispatch.
/// </remarks>
public sealed class ModuleReachabilityTests
{
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
