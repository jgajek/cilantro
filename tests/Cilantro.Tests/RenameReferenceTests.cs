using Cilantro.Core.Recovery;
using Cilantro.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class RenameReferenceTests
{
    [Fact]
    public void InheritedMemberReferencesFollowTheirDeclaringDefinitions()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var parent = SyntheticContext.AddType(module, "Parent");
            var derived = SyntheticContext.AddType(module, "Derived");
            derived.BaseType = parent;
            var field = new FieldDefUser("sT1uV2wX3yZ4", new FieldSig(module.CorLibTypes.Int32),
                FieldAttributes.Assembly | FieldAttributes.Static);
            parent.Fields.Add(field);
            var method = new MethodDefUser("kL1mN2oP3qR4", MethodSig.CreateStatic(module.CorLibTypes.Int32),
                MethodAttributes.Assembly | MethodAttributes.Static) { Body = new CilBody() };
            parent.Methods.Add(method);
            method.Body.Instructions.Add(OpCodes.Ldc_I4_7.ToInstruction());
            method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var app = SyntheticContext.AddType(module, "Application");
            app.Attributes = TypeAttributes.Public;
            var entry = new MethodDefUser("Entry", MethodSig.CreateStatic(module.CorLibTypes.Int32),
                MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
            app.Methods.Add(entry);
            var owner = new TypeRefUser(module, derived.Namespace, derived.Name, module);
            var fieldOwner = new TypeRefUser(module, parent.Namespace, parent.Name, module);
            entry.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, method.Name, method.MethodSig, owner)));
            entry.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(new MemberRefUser(module, field.Name, field.FieldSig, fieldOwner)));
            entry.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(new MemberRefUser(module, field.Name, field.FieldSig, fieldOwner)));
            entry.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var parent = context.Module.GetTypes().Single(t => t.Name == "Parent");
        var entry = context.Module.GetTypes().Single(t => t.Name == "Application").Methods.Single();
        AssertFixtureReturnsSeven(context.Module);
        context.SetFact("options.renameSymbols", true);
        new SymbolRenamingPass().Run(context);
        Assert.NotEqual("kL1mN2oP3qR4", parent.Methods.Single().Name.String);
        Assert.Equal(parent.Methods.Single().Name, ((MemberRef)entry.Body.Instructions[0].Operand).Name);
        Assert.Equal(parent.Fields.Single().Name, ((MemberRef)entry.Body.Instructions[1].Operand).Name);
        var allowance = CilantroPipeline.BuildRewriteAllowance(context);
        Assert.True(AssemblyVerifier.Verify(context.Module, allowance: allowance).Passed);
        var methodReference = (MemberRef)entry.Body.Instructions[0].Operand;
        var renamed = methodReference.Name;
        methodReference.Name = "kL1mN2oP3qR4";
        Assert.Contains(AssemblyVerifier.Verify(context.Module, allowance: allowance).Diagnostics,
            message => message.Contains("Local member reference no longer resolves"));
        methodReference.Name = renamed;
        AssertFixtureReturnsSeven(context.Module);
    }

    private static void AssertFixtureReturnsSeven(ModuleDef module)
    {
        using var bytes = new MemoryStream(); module.Write(bytes); bytes.Position = 0;
        var loader = new System.Runtime.Loader.AssemblyLoadContext(Guid.NewGuid().ToString(), isCollectible: true);
        try
        {
            // Execute only the source-built fixture to verify actual CLR member binding.
            var assembly = loader.LoadFromStream(bytes);
            Assert.Equal(7, assembly.GetType("Synthetic.Application")!.GetMethod("Entry")!.Invoke(null, null));
        }
        finally { loader.Unload(); }
    }

    [Theory]
    [InlineData("module")]
    [InlineData("assembly")]
    [InlineData("module-ref")]
    public void LocalNameBasedReferencesFollowRenamingAndForeignLookalikesDoNot(string scopeKind)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "aB1cD2eF3gH4");
            var nested = new TypeDefUser("", "zX9wV8uT7sR6", module.CorLibTypes.Object.TypeDefOrRef)
                { Attributes = TypeAttributes.NestedAssembly };
            owner.NestedTypes.Add(nested);
            var answer = new MethodDefUser("kL1mN2oP3qR4", MethodSig.CreateStatic(module.CorLibTypes.Int32),
                MethodAttributes.Assembly | MethodAttributes.Static) { Body = new CilBody() };
            nested.Methods.Add(answer);
            answer.Body.Instructions.Add(OpCodes.Ldc_I4_7.ToInstruction()); answer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            IResolutionScope scope = scopeKind switch
            {
                "module" => module,
                "assembly" => new AssemblyRefUser(module.Assembly),
                _ => new ModuleRefUser(module, module.Name)
            };
            var rootRef = new TypeRefUser(module, owner.Namespace, owner.Name, scope);
            var nestedRef = new TypeRefUser(module, "", nested.Name, rootRef);
            var field = new FieldDefUser("sT1uV2wX3yZ4", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Assembly | FieldAttributes.Static);
            nested.Fields.Add(field);
            var fieldRef = new MemberRefUser(module, field.Name, field.FieldSig, nestedRef);
            answer.Body.Instructions.Clear();
            answer.Body.Instructions.Add(OpCodes.Ldc_I4_7.ToInstruction());
            answer.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(fieldRef));
            answer.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(fieldRef));
            answer.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var foreign = new TypeRefUser(module, owner.Namespace, owner.Name, new AssemblyRefUser("Foreign"));
            var app = SyntheticContext.AddType(module, "Application"); app.Attributes = TypeAttributes.Public;
            app.Fields.Add(new FieldDefUser("Foreign", new FieldSig(foreign.ToTypeSig()), FieldAttributes.Private));
            var missing = new TypeRefUser(module, "Synthetic", "PreexistingMissing", module);
            app.Fields.Add(new FieldDefUser("Missing", new FieldSig(missing.ToTypeSig()), FieldAttributes.Private));
            var entry = new MethodDefUser("Entry", MethodSig.CreateStatic(module.CorLibTypes.Int32),
                MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody { InitLocals = true } };
            app.Methods.Add(entry);
            entry.Body.Variables.Add(new Local(nestedRef.ToTypeSig()));
            entry.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, answer.Name, answer.MethodSig, nestedRef)));
            entry.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var owner = context.Module.GetTypes().Single(t => t.Name == "aB1cD2eF3gH4");
        var nested = owner.NestedTypes.Single();
        var app = context.Module.GetTypes().Single(t => t.Name == "Application");
        var entry = app.Methods.Single();
        var reference = (MemberRef)entry.Body.Instructions[0].Operand;
        var addedRoot = new TypeRefUser(context.Module, owner.Namespace, owner.Name, context.Module);
        var addedNested = new TypeRefUser(context.Module, "", nested.Name, addedRoot);
        var oldNestedName = addedNested.Name;
        entry.Body.Variables.Add(new Local(addedNested.ToTypeSig()));
        context.SetFact("options.renameSymbols", true);
        new SymbolRenamingPass().Run(context);
        Assert.NotEqual("aB1cD2eF3gH4", owner.Name.String);
        Assert.Equal(nested.FullName, entry.Body.Variables[0].Type.FullName);
        Assert.Equal(nested.FullName, entry.Body.Variables[1].Type.FullName);
        Assert.Equal(nested.FullName, reference.DeclaringType.FullName);
        Assert.Equal(nested.Methods.Single().Name, reference.Name);
        Assert.Equal(nested.Fields.Single().Name, ((MemberRef)nested.Methods.Single().Body.Instructions[1].Operand).Name);
        Assert.Equal("Synthetic.aB1cD2eF3gH4", app.Fields.Single(f => f.Name == "Foreign").FieldSig.Type.FullName);
        var allowance = CilantroPipeline.BuildRewriteAllowance(context);
        Assert.True(AssemblyVerifier.Verify(context.Module, allowance: allowance).Passed);
        var fieldReference = (MemberRef)nested.Methods.Single().Body.Instructions[1].Operand;
        var renamedField = fieldReference.Name;
        fieldReference.Name = "sT1uV2wX3yZ4";
        Assert.Contains(AssemblyVerifier.Verify(context.Module, allowance: allowance).Diagnostics,
            message => message.Contains("Local member reference no longer resolves"));
        fieldReference.Name = renamedField;
        var newNestedName = addedNested.Name;
        addedNested.Name = oldNestedName;
        var broken = AssemblyVerifier.Verify(context.Module, allowance: allowance);
        Assert.False(broken.Passed);
        Assert.Contains(broken.Diagnostics, message => message.Contains("Local type reference no longer resolves"));
        addedNested.Name = newNestedName;
        // Only this source-built benign fixture is executed, never a corpus input.
        // Drop the unused external lookalike field before loading the fixture.
        app.Fields.Clear();
        using var bytes = new MemoryStream(); context.Module.Write(bytes);
        using var reloaded = ModuleDefMD.Load(bytes.ToArray());
        Assert.True(AssemblyVerifier.Verify(reloaded, allowance: allowance).Passed);
        Assert.Equal(nested.FullName, reloaded.GetTypes().Single(t => t.Name == "Application").Methods.Single().Body.Variables[0].Type.FullName);
        // .NET Core's in-memory loader rejects ModuleRef-based module loading;
        // that scope is checked through the serialized metadata above.
        if (scopeKind == "module-ref") return;
        var assembly = System.Reflection.Assembly.Load(bytes.ToArray());
        Assert.Equal(7, assembly.GetType(app.FullName)!.GetMethod("Entry")!.Invoke(null, null));
    }

    [Fact]
    public void PreexistingMissingMemberIsAllowedAcrossItsOwnerRename()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "aB1cD2eF3gH4");
            var caller = new MethodDefUser("Caller", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(caller);
            var reference = new TypeRefUser(module, owner.Namespace, owner.Name, module);
            caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "Missing",
                MethodSig.CreateStatic(module.CorLibTypes.Void), reference)));
            caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        context.SetFact("options.renameSymbols", true);
        new SymbolRenamingPass().Run(context);
        var allowance = CilantroPipeline.BuildRewriteAllowance(context);
        Assert.True(AssemblyVerifier.Verify(context.Module, allowance: allowance).Passed);
        using var bytes = new MemoryStream(); context.Module.Write(bytes);
        using var reloaded = ModuleDefMD.Load(bytes.ToArray());
        Assert.True(AssemblyVerifier.Verify(reloaded, allowance: allowance).Passed);
        var missing = (MemberRef)reloaded.GetTypes().SelectMany(type => type.Methods).Single().Body.Instructions[0].Operand;
        missing.Name = "NewlyMissing";
        Assert.Contains(AssemblyVerifier.Verify(reloaded, allowance: allowance).Diagnostics,
            message => message.Contains("Local member reference no longer resolves"));
    }
}
