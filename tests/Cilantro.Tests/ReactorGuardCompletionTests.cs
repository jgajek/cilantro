using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Passes;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ReactorGuardCompletionTests
{
    [Theory]
    [InlineData("pure", true)]
    [InlineData("normal", false)]
    [InlineData("throw", false)]
    [InlineData("reenter", false)]
    public void CompletedPoolShimRequiresOnlyPrivateNonReentrantInitialization(string prefix, bool removed)
    {
        using var context = Fixture(prefix == "pure" ? "normal" : prefix);
        var owner = context.Module.GetTypes().Single(t => t.Name == "Pool");
        if (prefix == "pure")
        {
            var cctor = owner.FindStaticConstructor();
            cctor.Body = new CilBody(); Add(cctor, OpCodes.Call.ToInstruction(Method(context, "Initialize")), OpCodes.Ret.ToInstruction());
        }
        var before = new[] { Invoke(context, 0), Invoke(context, 1), Invoke(context, 4) };
        context.SetFact("options.removeRuntime", true);
        Assert.Equal(3, new ReactorGuardCompletionPass().Run(context).Changes);
        Assert.Equal(removed ? 1 : 0, new UnusedReactorPoolRemovalPass().Run(context).Changes);
        Assert.Equal(!removed, context.Module.GetTypes().Contains(owner));
        Assert.Equal(before, new[] { Invoke(context, 0), Invoke(context, 1), Invoke(context, 4) });
        Assert.Single(Method(context, "Run").Body.Instructions, i => i.OpCode.Code == Code.Switch);
        var check = AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
            CilantroPipeline.BuildRewriteAllowance(context));
        Assert.True(check.Passed, string.Join("; ", check.Diagnostics));
        Assert.Equal(0, new UnusedReactorPoolRemovalPass().Run(context).Changes);
    }

    [Theory]
    [InlineData("finalizer")]
    [InlineData("verification")]
    public void PrivatePoolShimIsRetainedWhenLifetimeEffectsOrVerificationPreventRemoval(string reason)
    {
        using var context = Fixture("normal");
        var owner = context.Module.GetTypes().Single(t => t.Name == "Pool");
        var cctor = owner.FindStaticConstructor();
        cctor.Body = new CilBody();
        Add(cctor, OpCodes.Call.ToInstruction(Method(context, "Initialize")), OpCodes.Ret.ToInstruction());
        context.SetFact("options.removeRuntime", true);
        Assert.Equal(3, new ReactorGuardCompletionPass().Run(context).Changes);
        if (reason == "finalizer")
        {
            var finalizer = new MethodDefUser("Finalize", MethodSig.CreateInstance(context.Module.CorLibTypes.Void),
                MethodAttributes.Family | MethodAttributes.Virtual) { Body = new CilBody() };
            Add(finalizer, OpCodes.Ret.ToInstruction());
            owner.Methods.Add(finalizer);
        }
        else context.SetFact("cleanup.removedFieldCount", 999);
        var bodies = context.Module.GetTypes().SelectMany(t => t.Methods).ToDictionary(m => m, MethodBodySnapshot.Capture);
        Assert.Equal(0, new UnusedReactorPoolRemovalPass().Run(context).Changes);
        Assert.Contains(owner, context.Module.GetTypes());
        Assert.All(bodies, pair => Assert.True(pair.Value.StructurallyEquals(pair.Key)));
    }

    [Theory]
    [InlineData("field")]
    [InlineData("null-literal")]
    [InlineData("true-literal")]
    public void AnUnusedOrdinaryPoolCanCompleteItsNullGuardsAndBeRemoved(string form)
    {
        using var source = Fixture("normal");
        MakeOrdinaryPool(source);
        if (form != "field")
        {
            var getter = Method(source, "GetUnused");
            getter.Body = new CilBody(); Add(getter, OpCodes.Ldnull.ToInstruction(), OpCodes.Ret.ToInstruction());
            var predicate = Method(source, "IsUnusedNull");
            predicate.Body = new CilBody();
            if (form == "true-literal") Add(predicate, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Ret.ToInstruction());
            else Add(predicate, OpCodes.Ldnull.ToInstruction(), OpCodes.Ldnull.ToInstruction(), OpCodes.Ceq.ToInstruction(), OpCodes.Ret.ToInstruction());
            var initialize = Method(source, "Initialize");
            Instruction[] noise = [OpCodes.Ldc_I4_7.ToInstruction(), OpCodes.Ldnull.ToInstruction(), OpCodes.Pop.ToInstruction(),
                OpCodes.Pop.ToInstruction(), OpCodes.Call.ToInstruction(predicate), OpCodes.Pop.ToInstruction()];
            foreach (var instruction in noise.Reverse()) initialize.Body.Instructions.Insert(0, instruction);
        }
        var run = Method(source, "Run");
        run.Body = new CilBody(); Add(run, OpCodes.Ldc_I4_7.ToInstruction(), OpCodes.Ret.ToInstruction());
        var path = Path.Combine(Path.GetTempPath(), $"Cilantro.UnusedPool.{Guid.NewGuid():N}.dll");
        try
        {
            source.Module.Write(path);
            using var context = ArtifactContext.Load(path);
            context.SetFact("options.removeRuntime", true);
            Assert.Equal(0, new ReactorGuardCompletionPass().Run(context).Changes);
            Assert.Contains(context.Changes, c => c.Kind == "complete-reactor-pool-initializer");
            Assert.Equal(1, new UnusedReactorPoolRemovalPass().Run(context).Changes);
            var check = AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
                CilantroPipeline.BuildRewriteAllowance(context));
            Assert.True(check.Passed, string.Join("; ", check.Diagnostics));
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }

    [Fact]
    public void OrdinaryPoolWrapperCanCompleteGuardsAroundLiftedInitializer()
    {
        using var context = Fixture("normal");
        var owner = MakeOrdinaryPool(context);
        var initializer = Method(context, "Initialize");
        var original = initializer.Body.Instructions.Skip(8).ToArray();
        var lifted = New(owner, "LiftedInitialization", context.Module.CorLibTypes.Void);
        foreach (var instruction in original) lifted.Body.Instructions.Add(instruction);
        var call = OpCodes.Call.ToInstruction(lifted);
        foreach (var instruction in initializer.Body.Instructions.Take(8))
            if (instruction.Operand == original[0]) instruction.Operand = call;
        foreach (var instruction in original) initializer.Body.Instructions.Remove(instruction);
        Add(initializer, call, OpCodes.Ret.ToInstruction());
        var run = Method(context, "Run");
        run.Body = new CilBody(); Add(run, OpCodes.Ldc_I4_7.ToInstruction(), OpCodes.Ret.ToInstruction());
        var path = Path.Combine(Path.GetTempPath(), $"Cilantro.PoolChain.{Guid.NewGuid():N}.dll");
        try
        {
            context.Module.Write(path);
            using var recovered = ArtifactContext.Load(path);
            recovered.SetFact("options.removeRuntime", true);
            new ReactorGuardCompletionPass().Run(recovered);
            Assert.Contains(recovered.Changes, c => c.Kind == "complete-reactor-pool-initializer");
            var removal = new UnusedReactorPoolRemovalPass().Run(recovered);
            Assert.True(removal.Changes == 1, string.Join("; ", removal.Diagnostics));
            Assert.DoesNotContain(recovered.Module.GetTypes(), t => t.FullName == owner.FullName);
            Assert.Equal("7:0", Invoke(recovered, 0));
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }

    [Theory]
    [InlineData("unused", true)]
    [InlineData("new-initializer", true)]
    [InlineData("read", false)]
    [InlineData("handle", false)]
    [InlineData("name", false)]
    [InlineData("method-call", false)]
    [InlineData("signature", false)]
    [InlineData("writer", false)]
    [InlineData("application", false)]
    [InlineData("public", false)]
    [InlineData("keep-runtime", false)]
    [InlineData("attribute", false)]
    [InlineData("bad-accounting", false)]
    [InlineData("entrypoint", false)]
    [InlineData("constraint", false)]
    public void OnlyAClosedAndWhollyUnusedProtectorPoolIsDeleted(string scenario, bool removed)
    {
        using var context = Fixture("normal");
        var pool = context.Module.GetTypes().Single(t => t.Name == "Pool");
        var run = Method(context, "Run");
        if (scenario != "read")
        {
            run.Body = new CilBody();
            Add(run, OpCodes.Ldc_I4_7.ToInstruction(), OpCodes.Ret.ToInstruction());
        }
        if (scenario == "handle")
        {
            run.Body.Instructions.Insert(0, OpCodes.Ldtoken.ToInstruction(pool));
            run.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
        }
        if (scenario == "name")
        {
            run.Body.Instructions.Insert(0, OpCodes.Ldstr.ToInstruction(pool.FullName));
            run.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
        }
        if (scenario == "method-call")
        {
            var touch = New(pool, "Touch", context.Module.CorLibTypes.Void);
            Add(touch, OpCodes.Ret.ToInstruction());
            run.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(touch));
        }
        if (scenario == "signature") run.DeclaringType.Fields.Add(new FieldDefUser("ApplicationPool",
            new FieldSig(pool.ToTypeSig()), FieldAttributes.Private | FieldAttributes.Static));
        if (scenario == "writer")
        {
            var root = pool.Fields.Single(f => f.Name == "Root");
            run.Body.Instructions.Insert(0, OpCodes.Ldnull.ToInstruction());
            run.Body.Instructions.Insert(1, OpCodes.Stsfld.ToInstruction(root));
        }
        if (scenario == "application") Method(context, "Initialize").CustomAttributes.Clear();
        if (scenario == "attribute")
        {
            var module = context.Module;
            var systemType = module.CorLibTypes.GetTypeRef("System", "Type").ToTypeSig();
            var attribute = new TypeRefUser(module, "System.ComponentModel", "TypeConverterAttribute", module.CorLibTypes.AssemblyRef);
            var ctor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, systemType), attribute);
            run.DeclaringType.CustomAttributes.Add(new CustomAttribute(ctor, [new CAArgument(systemType, pool.ToTypeSig())]));
        }
        if (scenario == "public") pool.Attributes |= TypeAttributes.Public;
        if (scenario == "entrypoint") context.Module.EntryPoint = Method(context, "Initialize");
        if (scenario == "constraint")
        {
            var parameter = new GenericParamUser(0, GenericParamAttributes.NonVariant, "T");
            parameter.GenericParamConstraints.Add(new GenericParamConstraintUser(pool));
            run.GenericParameters.Add(parameter);
        }
        if (scenario == "bad-accounting") context.SetFact(VirtualizationRebuildPass.AddedMethodsFact, 1);
        if (scenario == "new-initializer")
        {
            var original = Method(context, "Initialize");
            var lifted = New(pool, "Lifted", context.Module.CorLibTypes.Void);
            lifted.Body = original.Body;
            original.Body = new CilBody(); Add(original, OpCodes.Ret.ToInstruction());
            foreach (var attribute in original.CustomAttributes) lifted.CustomAttributes.Add(attribute);
            original.CustomAttributes.Clear();
            foreach (var instruction in pool.FindStaticConstructor().Body.Instructions.Where(i => i.Operand == original)) instruction.Operand = lifted;
            context.SetFact(VirtualizationRebuildPass.AddedMethodsFact, 1);
        }
        var before = MethodBodySnapshot.Capture(run);
        context.SetFact("options.removeRuntime", scenario != "keep-runtime");
        var result = new UnusedReactorPoolRemovalPass().Run(context);
        Assert.Equal(removed ? 1 : 0, result.Changes);
        Assert.Equal(!removed, context.Module.GetTypes().Contains(pool));
        Assert.True(before.StructurallyEquals(run));
        if (scenario == "bad-accounting") Assert.Equal(PassStatus.Partial, result.Status);
        if (removed)
        {
            var check = AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
                CilantroPipeline.BuildRewriteAllowance(context));
            Assert.True(check.Passed, string.Join("; ", check.Diagnostics));
            Assert.Single(context.Changes, change => change.Kind == "remove-orphaned-rebuilt-method");
            Assert.Equal(0, new UnusedReactorPoolRemovalPass().Run(context).Changes);
        }
    }

    [Theory]
    [InlineData("normal")]
    [InlineData("throw")]
    [InlineData("reenter")]
    public void OrdinaryPoolRemovesInitializerAndApplicationGuards(string prefix)
    {
        using var context = Fixture(prefix);
        var owner = MakeOrdinaryPool(context);
        var before = new[] { Invoke(context, 0), Invoke(context, 1), Invoke(context, 4) };
        context.SetFact("options.removeRuntime", true);
        Assert.Equal(3, new ReactorGuardCompletionPass().Run(context).Changes);
        Assert.Equal(before, new[] { Invoke(context, 0), Invoke(context, 1), Invoke(context, 4) });
        Assert.Single(Method(context, "Run").Body.Instructions, i => i.OpCode.Code == Code.Switch);
        Assert.DoesNotContain(owner.Fields, f => !f.IsStatic);
        Assert.Equal(3, Method(context, "Initialize").Body.Instructions.Count);
        Assert.Equal(0, new ReactorGuardCompletionPass().Run(context).Changes);
    }

    [Theory]
    [InlineData("normal")]
    [InlineData("throw")]
    [InlineData("reenter")]
    public void EarlyHelperCompletionLeavesOrdinaryPoolForDedicatedProof(string prefix)
    {
        using var context = Fixture(prefix);
        var owner = MakeOrdinaryPool(context);
        owner.Fields.Single(f => f.Name == "Unused").Name = "aB1cD2eF3gH4iJ5kL6";
        Method(context, "GetUnused").Name = "bC1dE2fG3hI4jK5lM6";
        Method(context, "IsUnusedNull").Name = "cD1eF2gH3iJ4kL5mN6";
        context.SetFact("options.removeRuntime", true);
        context.SetFact("method-protection.complete", true);
        context.SetFact("reactor.structure", new ReactorStructureFacts(0,0,0,0,0,0,0,false,false,ReactorCapability.DispatcherControlFlow,1,"test"));
        Assert.Single(ReactorGuardHelpers.Find(context));
        var before = new[] { Invoke(context, 0), Invoke(context, 1), Invoke(context, 4) };
        var snapshot = MethodBodySnapshot.Capture(Method(context, "Initialize"));
        Assert.Equal(0, ReactorGuardHelpers.CompleteCalls(context));
        Assert.True(snapshot.StructurallyEquals(Method(context, "Initialize")));
        Assert.Equal(3, new ReactorGuardCompletionPass().Run(context).Changes);
        Assert.DoesNotContain(owner.Fields, f => !f.IsStatic);
        Assert.Equal(before, new[] { Invoke(context, 0), Invoke(context, 1), Invoke(context, 4) });
        Assert.Single(Method(context, "Run").Body.Instructions, i => i.OpCode.Code == Code.Switch);
    }

    [Theory]
    [InlineData("writer")]
    [InlineData("address")]
    [InlineData("name")]
    [InlineData("handle")]
    [InlineData("application-owner")]
    [InlineData("unknown-call")]
    public void OrdinaryInitializerProofRollsBackWhenPoolIsNotClosed(string refusal)
    {
        using var context = Fixture("normal");
        var owner = MakeOrdinaryPool(context);
        var field = owner.Fields.Single(f => f.Name == "Unused");
        var run = Method(context, "Run");
        Instruction[] injected = refusal switch
        {
            "writer" => [OpCodes.Ldnull.ToInstruction(), OpCodes.Stsfld.ToInstruction(field)],
            "address" => [OpCodes.Ldsflda.ToInstruction(field), OpCodes.Pop.ToInstruction()],
            "name" => [OpCodes.Ldstr.ToInstruction(field.Name), OpCodes.Pop.ToInstruction()],
            "handle" => [OpCodes.Ldtoken.ToInstruction(field), OpCodes.Pop.ToInstruction()],
            _ => []
        };
        foreach (var i in injected.Reverse()) run.Body.Instructions.Insert(0, i);
        if (refusal == "application-owner") owner.Name = "ApplicationPool";
        if (refusal == "unknown-call") Method(context, "Initialize").Body.Instructions.Insert(0,
            OpCodes.Call.ToInstruction(Method(context, "Prefix")));
        var initializer = Method(context, "Initialize");
        var snapshot = MethodBodySnapshot.Capture(initializer);
        context.SetFact("options.removeRuntime", true);
        Assert.Equal(0, new ReactorGuardCompletionPass().Run(context).Changes);
        Assert.True(snapshot.StructurallyEquals(initializer));
        Assert.Equal(16, owner.Fields.Count(f => !f.IsStatic));
    }

    private static TypeDef MakeOrdinaryPool(ArtifactContext context)
    {
        var owner = context.Module.GetTypes().Single(t => t.Name == "Pool");
        owner.Namespace = "";
        owner.Name = "<Module>{f24410e4-b55b-41b6-88bc-2ff5e4fd3988}";
        var initializer = Method(context, "Initialize");
        initializer.CustomAttributes.Clear();
        var field = new FieldDefUser("Unused", new FieldSig(owner.ToTypeSig()), FieldAttributes.Assembly | FieldAttributes.Static);
        owner.Fields.Add(field);
        var get = New(owner, "GetUnused", owner.ToTypeSig());
        Add(get, OpCodes.Ldsfld.ToInstruction(field), OpCodes.Ret.ToInstruction());
        var check = New(owner, "IsUnusedNull", context.Module.CorLibTypes.Boolean);
        Add(check, OpCodes.Ldsfld.ToInstruction(field), OpCodes.Ldnull.ToInstruction(), OpCodes.Ceq.ToInstruction(), OpCodes.Ret.ToInstruction());
        var original = initializer.Body.Instructions[0];
        var second = OpCodes.Call.ToInstruction(check);
        Instruction[] prefix = [OpCodes.Call.ToInstruction(get), OpCodes.Brfalse.ToInstruction(second),
            OpCodes.Ldnull.ToInstruction(), OpCodes.Throw.ToInstruction(), second, OpCodes.Brtrue.ToInstruction(original),
            OpCodes.Ldnull.ToInstruction(), OpCodes.Throw.ToInstruction()];
        foreach (var i in prefix.Reverse()) initializer.Body.Instructions.Insert(0, i);
        return owner;
    }

    [Fact]
    public void GeneralReflectionRefusalRemainsInForce()
    {
        using var context = Fixture("normal");
        var module = context.Module;
        var reflection = module.CorLibTypes.GetTypeRef("System.Reflection", "FieldInfo");
        var setter = New(Method(context, "Run").DeclaringType, "ReflectiveSetter", module.CorLibTypes.Void,
            reflection.ToTypeSig(), module.CorLibTypes.Object, module.CorLibTypes.Object);
        Add(setter, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldarg_1.ToInstruction(), OpCodes.Ldarg_2.ToInstruction(),
            OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "SetValue", MethodSig.CreateInstance(module.CorLibTypes.Void,
                module.CorLibTypes.Object, module.CorLibTypes.Object), reflection)), OpCodes.Ret.ToInstruction());
        Assert.NotNull(FieldWriteSafety.Analyze(module).Refusal);
        context.SetFact("options.removeRuntime", true);
        Assert.Equal(3, new ReactorGuardCompletionPass().Run(context).Changes);
        Assert.NotNull(FieldWriteSafety.Analyze(module).Refusal);
        Assert.Contains(setter.Body.Instructions, i => i.Operand is IMethod m && m.Name == "SetValue");
    }

    [Theory]
    [InlineData("normal")]
    [InlineData("throw")]
    public void FailedCheckDoesNotSuppressCheckInCatchHandler(string prefix)
    {
        using var context = Fixture(prefix);
        var run = Method(context, "Run");
        var pool = context.Module.GetTypes().Single(t => t.Name == "Pool");
        var root = pool.Fields.Single(f => f.IsStatic);
        var field = pool.Fields.First(f => !f.IsStatic);
        var start = OpCodes.Ldsfld.ToInstruction(root); var handler = OpCodes.Pop.ToInstruction(); var end = Instruction.CreateLdcI4(7);
        run.Body = new CilBody();
        Add(run, start, OpCodes.Ldfld.ToInstruction(field), OpCodes.Pop.ToInstruction(), OpCodes.Leave.ToInstruction(end),
            handler, OpCodes.Ldsfld.ToInstruction(root), OpCodes.Ldfld.ToInstruction(field), OpCodes.Pop.ToInstruction(),
            OpCodes.Leave.ToInstruction(end), end, OpCodes.Ret.ToInstruction());
        run.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
        { TryStart = start, TryEnd = handler, HandlerStart = handler, HandlerEnd = end,
            CatchType = context.Module.CorLibTypes.GetTypeRef("System", "Exception") });
        var before = Invoke(context, 0);
        context.SetFact("options.removeRuntime", true);
        Assert.Equal(2, new ReactorGuardCompletionPass().Run(context).Changes);
        Assert.Equal(before, Invoke(context, 0));
        Assert.Equal(2, run.Body.Instructions.Count(i => i.OpCode.Code == Code.Call));
    }

    [Theory]
    [InlineData("normal")]
    [InlineData("throw")]
    [InlineData("reenter")]
    public void RemovesGuardsPreservingInitializationExceptionsAndApplicationSwitch(string prefix)
    {
        using var context = Fixture(prefix);
        var before = new[] { Invoke(context, 0), Invoke(context, 1), Invoke(context, 4) };
        Assert.All(before, r => Assert.EndsWith(":1", r, StringComparison.Ordinal));
        context.SetFact("options.removeRuntime", true);
        var result = new ReactorGuardCompletionPass().Run(context);
        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(3, result.Changes);
        var run = Method(context, "Run");
        Assert.DoesNotContain(run.Body.Instructions, i => i.OpCode.Code == Code.Ldfld);
        Assert.DoesNotContain(run.Body.Instructions, i => i.OpCode.Code is Code.Brtrue or Code.Brtrue_S or Code.Brfalse or Code.Brfalse_S);
        Assert.Single(run.Body.Instructions, i => i.OpCode.Code == Code.Switch);
        Assert.Single(run.Body.Instructions, i => i.OpCode.Code == Code.Call);
        Assert.True(EvaluationStackAnalyzer.Analyze(run).Valid);
        Assert.Equal(before, new[] { Invoke(context, 0), Invoke(context, 1), Invoke(context, 4) });
        Assert.Equal(0, new ReactorGuardCompletionPass().Run(context).Changes);
        Assert.True(context.TryGetFact<int>(VirtualizationRebuildPass.AddedMethodsFact, out var added));
        Assert.Equal(1, added);
        Assert.True(context.TryGetFact<int>("cleanup.removedFieldCount", out var removed));
        Assert.Equal(16, removed);
        Assert.Single(context.Module.GetTypes().Single(t => t.Name == "Pool").Fields);
        var verified = AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
            new RewriteAllowance(AddedMethodCount: added, RemovedFieldCount: removed));
        Assert.True(verified.Passed, string.Join("; ", verified.Diagnostics));
    }

    [Theory]
    [InlineData("disabled")]
    [InlineData("unmarked")]
    [InlineData("escape")]
    [InlineData("address")]
    [InlineData("writer")]
    [InlineData("reinitialize")]
    [InlineData("repeat-cctor")]
    [InlineData("function-pointer")]
    [InlineData("type-handle")]
    [InlineData("field-handle")]
    [InlineData("field-name")]
    [InlineData("numeric-token")]
    [InlineData("unknown-initializer")]
    public void RefusesPoolWithoutClosedConstructionAndUses(string refusal)
    {
        using var context = Fixture("normal");
        context.SetFact("options.removeRuntime", refusal != "disabled");
        var owner = context.Module.GetTypes().Single(t => t.Name == "Pool");
        var root = owner.Fields.Single(f => f.IsStatic);
        var field = owner.Fields.First(f => !f.IsStatic);
        var initializer = Method(context, "Initialize");
        var run = Method(context, "Run");
        var injected = new List<Instruction>();
        switch (refusal)
        {
            case "unmarked": initializer.CustomAttributes.Clear(); break;
            case "escape": injected.AddRange([OpCodes.Ldsfld.ToInstruction(root), OpCodes.Call.ToInstruction(
                new MemberRefUser(context.Module, "KeepAlive", MethodSig.CreateStatic(context.Module.CorLibTypes.Void, context.Module.CorLibTypes.Object), context.Module.CorLibTypes.GetTypeRef("System", "GC")))]); break;
            case "address": injected.AddRange([OpCodes.Ldsflda.ToInstruction(root), OpCodes.Pop.ToInstruction()]); break;
            case "writer": injected.AddRange([OpCodes.Ldsfld.ToInstruction(root), Instruction.CreateLdcI4(9), OpCodes.Stfld.ToInstruction(field)]); break;
            case "reinitialize": injected.Add(OpCodes.Call.ToInstruction(initializer)); break;
            case "repeat-cctor": injected.Add(OpCodes.Call.ToInstruction(owner.FindStaticConstructor())); break;
            case "function-pointer": injected.AddRange([OpCodes.Ldftn.ToInstruction(initializer), OpCodes.Pop.ToInstruction()]); break;
            case "type-handle": injected.AddRange([OpCodes.Ldtoken.ToInstruction(owner), OpCodes.Pop.ToInstruction()]); break;
            case "field-handle": injected.AddRange([OpCodes.Ldtoken.ToInstruction(root), OpCodes.Pop.ToInstruction()]); break;
            case "field-name": injected.AddRange([OpCodes.Ldstr.ToInstruction(field.Name.String), OpCodes.Pop.ToInstruction()]); break;
            case "numeric-token":
                injected.AddRange([OpCodes.Ldnull.ToInstruction(), Instruction.CreateLdcI4(unchecked((int)field.MDToken.Raw)),
                    OpCodes.Callvirt.ToInstruction(new MemberRefUser(context.Module, "ResolveField", MethodSig.CreateInstance(
                        context.Module.CorLibTypes.GetTypeRef("System.Reflection", "FieldInfo").ToTypeSig(), context.Module.CorLibTypes.Int32),
                        context.Module.CorLibTypes.GetTypeRef("System.Reflection", "Module"))), OpCodes.Pop.ToInstruction()]); break;
            case "unknown-initializer":
                var value = initializer.Body.Instructions.First(i => i.IsLdcI4());
                value.OpCode = OpCodes.Ldsfld; value.Operand = Method(context, "Prefix").DeclaringType.Fields.Single(); break;
        }
        for (var n = injected.Count - 1; n >= 0; n--) run.Body.Instructions.Insert(0, injected[n]);
        var before = run.Body.Instructions.Select(i => i.ToString()).ToArray();
        Assert.Equal(0, new ReactorGuardCompletionPass().Run(context).Changes);
        Assert.Equal(before, run.Body.Instructions.Select(i => i.ToString()));
        Assert.DoesNotContain(owner.Methods, m => m.Name == "EnsureProtectorInitialized");
    }

    private static ArtifactContext Fixture(string prefix) => SyntheticContext.Build(module =>
    {
        var host = SyntheticContext.AddType(module, "Host"); host.Attributes = TypeAttributes.Public;
        var pool = SyntheticContext.AddType(module, "Pool"); pool.Attributes = TypeAttributes.Sealed;
        var root = new FieldDefUser("Root", new FieldSig(pool.ToTypeSig()), FieldAttributes.Assembly | FieldAttributes.Static); pool.Fields.Add(root);
        var fields = Enumerable.Range(0, 16).Select(n => new FieldDefUser("m_" + n.ToString("x32", System.Globalization.CultureInfo.InvariantCulture),
            new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Assembly)).ToArray();
        foreach (var field in fields) pool.Fields.Add(field);
        var ctor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void),
            MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() }; pool.Methods.Add(ctor);
        Add(ctor, OpCodes.Ldarg_0.ToInstruction(), OpCodes.Call.ToInstruction(new MemberRefUser(module, ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void), module.CorLibTypes.Object.TypeDefOrRef)), OpCodes.Ret.ToInstruction());
        var initialize = New(pool, "Initialize", module.CorLibTypes.Void);
        ReadingMarker.Add(module).Mark(initialize);
        Add(initialize, OpCodes.Newobj.ToInstruction(ctor), OpCodes.Stsfld.ToInstruction(root));
        for (var n = 0; n < fields.Length; n++) Add(initialize, OpCodes.Ldsfld.ToInstruction(root), Instruction.CreateLdcI4(n), OpCodes.Stfld.ToInstruction(fields[n]));
        Add(initialize, OpCodes.Ret.ToInstruction());
        var count = new FieldDefUser("Count", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Public | FieldAttributes.Static); host.Fields.Add(count);
        var run = New(host, "Run", module.CorLibTypes.Int32, module.CorLibTypes.Int32);
        var pre = New(host, "Prefix", module.CorLibTypes.Void);
        Add(pre, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(count));
        if (prefix == "throw") Add(pre, OpCodes.Ldnull.ToInstruction(), OpCodes.Throw.ToInstruction());
        else
        {
            if (prefix == "reenter") Add(pre, OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Call.ToInstruction(run), OpCodes.Pop.ToInstruction());
            Add(pre, OpCodes.Ret.ToInstruction());
        }
        var cctor = New(pool, ".cctor", module.CorLibTypes.Void);
        cctor.Attributes = MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName;
        Add(cctor, OpCodes.Call.ToInstruction(pre), OpCodes.Call.ToInstruction(initialize), OpCodes.Ret.ToInstruction());
        var app = OpCodes.Ldarg_0.ToInstruction(); var zero = Instruction.CreateLdcI4(17); var one = Instruction.CreateLdcI4(23);
        Add(run, OpCodes.Ldsfld.ToInstruction(root), OpCodes.Ldfld.ToInstruction(fields[2]), OpCodes.Pop.ToInstruction(),
            OpCodes.Ldsfld.ToInstruction(root), OpCodes.Ldfld.ToInstruction(fields[1]), OpCodes.Brtrue.ToInstruction(app),
            Instruction.CreateLdcI4(99), OpCodes.Ret.ToInstruction(), app, OpCodes.Switch.ToInstruction([zero, one]),
            Instruction.CreateLdcI4(29), OpCodes.Ret.ToInstruction(), zero, OpCodes.Ret.ToInstruction(), one,
            OpCodes.Ldsfld.ToInstruction(root), OpCodes.Ldfld.ToInstruction(fields[0]), OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
    });

    private static MethodDefUser New(TypeDef type, string name, TypeSig result, params TypeSig[] parameters)
    {
        var method = new MethodDefUser(name, MethodSig.CreateStatic(result, parameters), MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
        type.Methods.Add(method); return method;
    }
    private static void Add(MethodDef method, params Instruction[] instructions) { foreach (var i in instructions) method.Body.Instructions.Add(i); }
    private static MethodDef Method(ArtifactContext context, string name) => context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == name);
    private static string Invoke(ArtifactContext context, int argument)
    {
        // Only the source-built benign fixture is executed in the CLR.
        using var stream = new MemoryStream(); context.Module.Write(stream); stream.Position = 0;
        var loader = new System.Runtime.Loader.AssemblyLoadContext(Guid.NewGuid().ToString(), isCollectible: true);
        try
        {
            var host = loader.LoadFromStream(stream).GetType("Synthetic.Host")!;
            string result;
            try { result = host.GetMethod("Run")!.Invoke(null, [argument])!.ToString()!; }
            catch (System.Reflection.TargetInvocationException exception) { result = exception.InnerException!.GetType().FullName!; }
            return result + ":" + host.GetField("Count")!.GetValue(null);
        }
        finally { loader.Unload(); }
    }
}
