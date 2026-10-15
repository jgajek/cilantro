using Cilantro.Core;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class EmbeddedDependencyRecoveryTests
{
    [Theory]
    [InlineData("valid", 1)] [InlineData("foreign", 0)]
    [InlineData("wrong-identity", 0)] [InlineData("throw", 0)]
    [InlineData("unreferenced", 1)] [InlineData("query-dependent", 0)]
    public void CapturesOnlyAnAgreedResourceBackedDependency(string variant, int expected)
    {
        using var context = Fixture(variant);
        var resolver = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Resolve");
        var body = resolver.Body;
        var resource = context.Module.Resources.Single();
        var result = new EmbeddedDependencyRecoveryPass().Run(context);
        Assert.Equal(expected, result.Changes);
        Assert.Same(body, resolver.Body);
        Assert.Same(resource, context.Module.Resources.Single());
        if (expected == 0) return;
        Assert.Equal(PassStatus.Success, result.Status);
        Assert.True(context.TryGetFact<IReadOnlyList<ExtractedPayload>>("payload.artifacts", out var captures));
        var capture = Assert.Single(captures!);
        Assert.Equal("Dependency", capture.Info.AssemblyName);
        Assert.Equal(PayloadOrigin.EmbeddedDependency, capture.Info.Origin);
        Assert.Equal("dependency", capture.Info.SourceResource);
        Assert.Equal(((EmbeddedResource)resource).CreateReader().ToArray(), capture.Bytes);
        Assert.Equal(0, new EmbeddedDependencyRecoveryPass().Run(context).Changes);
        Assert.True(context.TryGetFact<IReadOnlyList<ExtractedPayload>>("payload.artifacts", out captures));
        Assert.Single(captures!);
    }

    [Fact]
    public void ExhaustionIsARefusalNotAnEmptyResolverResponse()
    {
        using var context = Fixture("valid");
        var resolver = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Resolve");
        Assert.False(EmbeddedDependencyRecoveryPass.TryRead(context, resolver,
            "Dependency, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null", new StaticWorkBudget(1), out var capture, out var why));
        Assert.Null(capture);
        Assert.NotEmpty(why);
    }

    private static ArtifactContext Fixture(string variant)
    {
        using var dependency = new ModuleDefUser("Dependency.dll") { Kind = ModuleKind.Dll };
        new AssemblyDefUser(variant == "wrong-identity" ? "Other" : "Dependency", new Version(1, 0, 0, 0)).Modules.Add(dependency);
        using var output = new MemoryStream(); dependency.Write(output); var bytes = output.ToArray();
        return SyntheticContext.Build(module =>
        {
            module.Resources.Add(new EmbeddedResource("dependency", bytes, ManifestResourceAttributes.Private));
            var host = SyntheticContext.AddType(module, "Host");
            if (variant is not ("unreferenced" or "query-dependent"))
                host.Fields.Add(new FieldDefUser("Reference", new FieldSig(new ClassSig(new TypeRefUser(module, "Lib", "Thing",
                    new AssemblyRefUser("Dependency", new Version(1, 0, 0, 0))))), FieldAttributes.Static));
            var assembly = new TypeRefUser(module, "System.Reflection", "Assembly",
                variant == "foreign" ? new AssemblyRefUser("Foreign", new Version(1, 0)) : module.CorLibTypes.AssemblyRef);
            var stream = module.CorLibTypes.GetTypeRef("System.IO", "Stream");
            var reader = module.CorLibTypes.GetTypeRef("System.IO", "BinaryReader");
            var resolver = new MethodDefUser("Resolve", MethodSig.CreateStatic(assembly.ToTypeSig(), module.CorLibTypes.String))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            host.Methods.Add(resolver);
            if (variant is "unreferenced" or "query-dependent")
            {
                var tableType = module.CorLibTypes.GetTypeRef("System.Collections", "Hashtable");
                var table = new FieldDefUser("Lookup", new FieldSig(tableType.ToTypeSig()), FieldAttributes.Static);
                host.Fields.Add(table);
                var add = new MemberRefUser(module, "Add", MethodSig.CreateInstance(module.CorLibTypes.Void,
                    module.CorLibTypes.Object, module.CorLibTypes.Object), tableType);
                var init = host.FindOrCreateStaticConstructor(); init.Body.Instructions.Clear();
                foreach (var instruction in new[] {
                    OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), tableType)),
                    OpCodes.Dup.ToInstruction(), OpCodes.Ldstr.ToInstruction("Dependency, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null"),
                    OpCodes.Ldnull.ToInstruction(), OpCodes.Callvirt.ToInstruction(add), OpCodes.Stsfld.ToInstruction(table), OpCodes.Ret.ToInstruction() })
                    init.Body.Instructions.Add(instruction);
                if (variant == "query-dependent")
                    Add(OpCodes.Ldsfld.ToInstruction(table), OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldnull.ToInstruction(), OpCodes.Callvirt.ToInstruction(add));
            }
            var missing = OpCodes.Ldnull.ToInstruction();
            Add(OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldstr.ToInstruction("Dependency, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null"),
                OpCodes.Call.ToInstruction(new MemberRefUser(module, "op_Equality", MethodSig.CreateStatic(module.CorLibTypes.Boolean,
                    module.CorLibTypes.String, module.CorLibTypes.String), module.CorLibTypes.String.TypeDefOrRef)),
                OpCodes.Brfalse.ToInstruction(missing));
            if (variant == "throw") Add(OpCodes.Ldnull.ToInstruction(), OpCodes.Throw.ToInstruction());
            Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetExecutingAssembly", MethodSig.CreateStatic(assembly.ToTypeSig()), assembly)),
                OpCodes.Ldstr.ToInstruction("dependency"),
                OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetManifestResourceStream", MethodSig.CreateInstance(stream.ToTypeSig(), module.CorLibTypes.String), assembly)),
                OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, stream.ToTypeSig()), reader)),
                OpCodes.Ldc_I4.ToInstruction(bytes.Length),
                OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "ReadBytes", MethodSig.CreateInstance(new SZArraySig(module.CorLibTypes.Byte), module.CorLibTypes.Int32), reader)),
                OpCodes.Call.ToInstruction(new MemberRefUser(module, "Load", MethodSig.CreateStatic(assembly.ToTypeSig(), new SZArraySig(module.CorLibTypes.Byte)), assembly)),
                OpCodes.Ret.ToInstruction(), missing, OpCodes.Ret.ToInstruction());
            void Add(params Instruction[] instructions) { foreach (var instruction in instructions) resolver.Body.Instructions.Add(instruction); }
        });
    }
}
