using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class InheritedVirtualImplementationTests
{
    [Theory]
    [InlineData("base", true)]
    [InlineData("derived", true)]
    [InlineData("generic", true)]
    [InlineData("override", false)]
    [InlineData("shadow", false)]
    [InlineData("explicit", false)]
    [InlineData("unrelated", false)]
    [InlineData("unresolved", false)]
    public void RequiresAnUnchangedKnownInheritanceChain(string mode, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var root = SyntheticContext.AddType(module, "Base");
            if (mode == "generic") root.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            var declaration = new MethodDefUser("Invoke", MethodSig.CreateInstance(module.CorLibTypes.Boolean), MethodImplAttributes.IL,
                MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.NewSlot) { Body = new CilBody() };
            root.Methods.Add(declaration); declaration.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction()); declaration.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var derived = SyntheticContext.AddType(module, "Derived");
            derived.BaseType = mode == "generic" ? new TypeSpecUser(new GenericInstSig(new ClassSig(root), module.CorLibTypes.String)) : root;
            if (mode == "unrelated") derived.BaseType = module.CorLibTypes.Object.TypeDefOrRef;
            if (mode == "unresolved") derived.BaseType = new TypeRefUser(module, "Unknown", "Base", new AssemblyRefUser("Missing"));
            if (mode is "override" or "shadow" or "explicit")
            {
                var replacement = new MethodDefUser(mode == "explicit" ? "DifferentName" : "Invoke", declaration.MethodSig.Clone(),
                    MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.Virtual | (mode == "shadow" ? MethodAttributes.NewSlot : 0)) { Body = new CilBody() };
                replacement.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction()); replacement.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                if (mode == "explicit") replacement.Overrides.Add(new MethodOverride(replacement, declaration));
                derived.Methods.Add(replacement);
            }
        });
        var root = context.Module.GetTypes().Single(t => t.Name == "Base");
        var runtime = context.Module.GetTypes().Single(t => t.Name == (mode == "base" ? "Base" : "Derived"));
        Assert.Equal(expected, InheritedVirtualImplementation.IsUnchanged(runtime.ToTypeSig(), root.Methods.Single()));
        if (mode == "generic")
        {
            Assert.True(InheritedVirtualImplementation.IsUnchanged(runtime.ToTypeSig(), root.Methods.Single(),
                new GenericInstSig(new ClassSig(root), context.Module.CorLibTypes.String)));
            Assert.False(InheritedVirtualImplementation.IsUnchanged(runtime.ToTypeSig(), root.Methods.Single(),
                new GenericInstSig(new ClassSig(root), context.Module.CorLibTypes.Object)));
        }
    }
}
