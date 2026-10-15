using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;

namespace Cilantro.Tests;

/// <summary>
/// The reading that asks a resolver instead of looking for its table.
/// </summary>
/// <remarks>
/// The shape under test is the one a sample protected twice tends to have underneath Reactor: the
/// strings are decrypted once into a dictionary parked in a slot of the application domain, and every
/// use of one is a call passing the number it was filed under. There is no run of bytes anywhere for a
/// table reading to frame, so the only thing that knows where the strings are is the method that
/// fetches them, and the only way to find out is to ask it.
/// </remarks>
public sealed class StringLookupRecoveryTests
{
    [Fact]
    public void SharedDecoderInitializationSurvivesRemovalOfOwnedStringCalls()
    {
        using var context = CompletionFixture("shared-initializer");
        Triage(context);
        Assert.Equal(3, new StringLookupRecoveryPass().Run(context).Changes);
        context.SetFact("options.removeRuntime", true);
        var result = new StringLookupCompletionPass().Run(context);
        Assert.Equal(3, result.Changes);
        var caller = Method(context, "Uses");
        Assert.DoesNotContain(caller.Body.Instructions, i => i.Operand is IMethod m && m.Name == "Fetch");
        Assert.Equal(3, caller.Body.Instructions.Count(i => i.Operand is IMethod m && m.Name == "RunClassConstructor"));
        new RuntimeCleanupPass().Run(context);
        Assert.DoesNotContain(context.Module.GetTypes(), t => t.Name == "Holder");
        var decoder = context.Module.GetTypes().Single(t => t.Name == "PrivateDecoder");
        var machine = new StaticMachine(modelTypeInitialization: true);
        Assert.True(machine.Execute(caller).Succeeded);
        Assert.Equal(7, machine.State.ReadStaticField(decoder.Fields.Single()).AsInt32());
        Assert.True(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure,
            CilantroPipeline.BuildRewriteAllowance(context)).Passed);
    }

    [Theory]
    [InlineData("normal")]
    [InlineData("private-helper")]
    [InlineData("resource")]
    public void CompletedOwnedLookupRemovesCallsAndTheWholeHolder(string scenario)
    {
        using var context = CompletionFixture(scenario);
        Triage(context);
        Assert.Equal(3, new StringLookupRecoveryPass().Run(context).Changes);
        context.SetFact("options.removeRuntime", true);
        var result = new StringLookupCompletionPass().Run(context);
        Assert.Equal(3, result.Changes);
        Assert.Equal(PassStatus.Success, result.Status);
        var caller = Method(context, "Uses");
        Assert.DoesNotContain(caller.Body.Instructions, i => i.Operand is IMethod m && m.Name == "Fetch");
        new RuntimeCleanupPass().Run(context);
        Assert.DoesNotContain(context.Module.GetTypes(), t => t.Name == "Holder");
        Assert.DoesNotContain(context.Module.GetTypes(), t => t.Name == "PrivateDecoder");
        Assert.Contains(context.Module.GetTypes(), t => t.Name == "Consumer");
        if (scenario == "resource")
        {
            Assert.Equal(1, new ProtectorResourceCleanupPass().Run(context).Changes);
            Assert.Empty(context.Module.Resources);
        }
        Assert.Equal(["second", "first", "second"], caller.Body.Instructions
            .Where(i => i.OpCode.Code == Code.Ldstr).Select(i => (string)i.Operand));
    }

    [Fact]
    public void LateLookupCompletionRemovesHelpersAfterTheirLastOtherConsumerWasRecovered()
    {
        using var context = CompletionFixture("orphan-helper-consumer");
        Triage(context);
        Assert.Equal(3, new StringLookupRecoveryPass().Run(context).Changes);
        context.SetFact("options.removeRuntime", true);
        Assert.Equal(0, new StringLookupCompletionPass().Run(context).Changes);
        RecoveryOrphans.DeclareSubtree(context, [Method(context, "OldNumericLookup")]);
        new RuntimeCleanupPass().Run(context);
        Assert.Equal(3, new StringLookupFinalizationPass().Run(context).Changes);
        Assert.True(new StringRuntimeCleanupPass().Run(context).Changes > 0);
        var check = AssemblyVerifier.Verify(context.Module, context.OriginalIdentity,
            context.OriginalStructure, CilantroPipeline.BuildRewriteAllowance(context));
        Assert.True(check.Passed, string.Join("; ", check.Diagnostics));
        Assert.DoesNotContain(context.Module.GetTypes(), t => t.Name == "Holder" || t.Name == "PrivateDecoder");
        Assert.Equal(0, new StringLookupFinalizationPass().Run(context).Changes);
        Assert.Equal(0, new StringRuntimeCleanupPass().Run(context).Changes);
    }

    [Theory]
    [InlineData("public")]
    [InlineData("other-reader")]
    [InlineData("slot-name")]
    [InlineData("holder-name")]
    [InlineData("observable-write")]
    [InlineData("table-escape")]
    [InlineData("handle")]
    [InlineData("metadata-escape")]
    [InlineData("shared-helper")]
    [InlineData("shared-initializer-and-write")]
    [InlineData("changed-literal")]
    public void OwnedLookupCompletionKeepsObservableOrExposedState(string scenario)
    {
        using var context = CompletionFixture(scenario);
        Triage(context);
        Assert.Equal(3, new StringLookupRecoveryPass().Run(context).Changes);
        if (scenario == "public") Method(context, "Fetch").DeclaringType.Attributes = TypeAttributes.Public | TypeAttributes.Sealed;
        var caller = Method(context, "Uses");
        if (scenario == "changed-literal")
            caller.Body.Instructions.First(i => i.OpCode.Code == Code.Ldstr).Operand = "not the recovered answer";
        var before = Cilantro.Core.Verification.MethodBodySnapshot.Capture(caller);
        context.SetFact("options.removeRuntime", true);
        Assert.Equal(0, new StringLookupCompletionPass().Run(context).Changes);
        Assert.True(before.StructurallyEquals(caller));
        Assert.Contains(caller.Body.Instructions, i => i.Operand is IMethod m && m.Name == "Fetch");
    }

    private static ArtifactContext CompletionFixture(string scenario) => SyntheticContext.Build(module =>
    {
        var holder = SyntheticContext.AddType(module, "Holder");
        holder.Attributes = TypeAttributes.Sealed | TypeAttributes.NotPublic;
        var key = new FieldDefUser("SlotKey", new FieldSig(module.CorLibTypes.String), FieldAttributes.Private | FieldAttributes.Static);
        holder.Fields.Add(key);
        var filler = Filler(module, "private-string-slot", (41, "first"), (42, "second")); holder.Methods.Add(filler);
        filler.Body.Instructions.Insert(0, OpCodes.Ldstr.ToInstruction("private-string-slot"));
        filler.Body.Instructions.Insert(1, OpCodes.Stsfld.ToInstruction(key));
        var fetch = Fetcher(module, "Fetch", "private-string-slot"); holder.Methods.Add(fetch);
        if (scenario == "resource")
        {
            module.Resources.Add(new EmbeddedResource("strings", new byte[] { 1, 2 }, ManifestResourceAttributes.Private));
            var assembly = module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly");
            filler.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetExecutingAssembly", MethodSig.CreateStatic(assembly.ToTypeSig()), assembly)));
            filler.Body.Instructions.Insert(1, OpCodes.Ldstr.ToInstruction("strings"));
            filler.Body.Instructions.Insert(2, OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetManifestResourceStream", MethodSig.CreateInstance(module.CorLibTypes.GetTypeRef("System.IO", "Stream").ToTypeSig(), module.CorLibTypes.String), assembly)));
            filler.Body.Instructions.Insert(3, OpCodes.Pop.ToInstruction());
        }
        var getKey = fetch.Body.Instructions.Single(i => i.OpCode.Code == Code.Ldstr);
        getKey.OpCode = OpCodes.Ldsfld; getKey.Operand = key;
        var consumer = SyntheticContext.AddType(module, "Consumer"); consumer.Attributes = TypeAttributes.Public;
        var caller = Caller(module, "Uses", fetch, 42, 41, 42); consumer.Methods.Add(caller);
        if (scenario == "observable-write")
        {
            var field = new FieldDefUser("ApplicationCount", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Public | FieldAttributes.Static);
            consumer.Fields.Add(field);
            filler.Body.Instructions.Insert(0, OpCodes.Ldc_I4_7.ToInstruction());
            filler.Body.Instructions.Insert(1, OpCodes.Stsfld.ToInstruction(field));
        }
        if (scenario == "table-escape")
        {
            var field = new FieldDefUser("ApplicationTable", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Public | FieldAttributes.Static);
            consumer.Fields.Add(field);
            filler.Body.Instructions.Insert(filler.Body.Instructions.Count - 1, OpCodes.Ldloc_0.ToInstruction());
            filler.Body.Instructions.Insert(filler.Body.Instructions.Count - 1, OpCodes.Stsfld.ToInstruction(field));
        }
        if (scenario == "metadata-escape")
        {
            var field = new FieldDefUser("ApplicationHandle", new FieldSig(new ValueTypeSig(new TypeRefUser(module,
                "System", "RuntimeTypeHandle", module.CorLibTypes.AssemblyRef))), FieldAttributes.Public | FieldAttributes.Static);
            consumer.Fields.Add(field);
            filler.Body.Instructions.Insert(0, OpCodes.Ldtoken.ToInstruction(holder));
            filler.Body.Instructions.Insert(1, OpCodes.Stsfld.ToInstruction(field));
        }
        if (scenario is "private-helper" or "shared-helper" or "orphan-helper-consumer" or "shared-initializer" or "shared-initializer-and-write")
        {
            var helper = SyntheticContext.AddType(module, "PrivateDecoder");
            helper.Attributes = TypeAttributes.NotPublic | TypeAttributes.Sealed;
            var field = new FieldDefUser("Cache", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static | FieldAttributes.Assembly);
            helper.Fields.Add(field);
            var initialize = new MethodDefUser("Decode", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL, MethodAttributes.Assembly | MethodAttributes.Static) { Body = new CilBody() };
            initialize.Body.Instructions.Add(OpCodes.Ldc_I4_7.ToInstruction());
            initialize.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(field));
            initialize.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            helper.Methods.Add(initialize);
            if (scenario.StartsWith("shared-initializer", StringComparison.Ordinal))
            {
                var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                    MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName |
                    MethodAttributes.RTSpecialName) { Body = new CilBody() };
                cctor.Body.Instructions.Add(OpCodes.Ldc_I4_7.ToInstruction());
                cctor.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(field));
                cctor.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                helper.Methods.Add(cctor);
                initialize.Body.Instructions.Clear();
                if (scenario == "shared-initializer-and-write")
                {
                    initialize.Body.Instructions.Add(OpCodes.Ldc_I4_8.ToInstruction());
                    initialize.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(field));
                }
                initialize.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            }
            filler.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(initialize));
            if (scenario == "shared-helper" || scenario.StartsWith("shared-initializer", StringComparison.Ordinal))
            {
                caller.Body.Instructions.Insert(0, OpCodes.Ldsfld.ToInstruction(field));
                caller.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
            }
            if (scenario == "orphan-helper-consumer")
            {
                var oldOwner = SyntheticContext.AddType(module, "OldNumericHolder");
                oldOwner.Attributes = TypeAttributes.NotPublic | TypeAttributes.Sealed;
                var oldLookup = new MethodDefUser("OldNumericLookup", MethodSig.CreateStatic(module.CorLibTypes.Int32),
                    MethodImplAttributes.IL, MethodAttributes.Assembly | MethodAttributes.Static) { Body = new CilBody() };
                oldLookup.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(field));
                oldLookup.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                oldOwner.Methods.Add(oldLookup);
            }
        }
        if (scenario is "slot-name" or "holder-name" or "handle")
        {
            caller.Body.Instructions.Insert(0, scenario == "handle" ? OpCodes.Ldtoken.ToInstruction(holder) :
                OpCodes.Ldstr.ToInstruction(scenario == "slot-name" ? "private-string-slot" : holder.FullName));
            caller.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
        }
        if (scenario == "other-reader")
        {
            var other = Fetcher(module, "Other", "private-string-slot");
            consumer.Methods.Add(other);
        }
    });

    [Fact]
    public void StringsKeptInADomainSlotAreRestoredByAskingTheMethodThatFetchesThem()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Holder");
            type.Methods.Add(Filler(module, "slot", (41, "first"), (42, "second")));
            var fetch = Fetcher(module, "Fetch", "slot");
            type.Methods.Add(fetch);
            SyntheticContext.AddType(module, "Consumer").Methods.Add(Caller(module, "Uses", fetch, 42, 41, 42));
        });

        Triage(context);
        var result = new StringLookupRecoveryPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(3, result.Changes);
        var caller = Method(context, "Uses");
        Assert.Equal(
            ["second", "first", "second"],
            caller.Body.Instructions
                .Where(instruction => instruction.OpCode == OpCodes.Ldstr)
                .Select(instruction => (string?)instruction.Operand));
        Assert.Contains(
            caller.Body.Instructions,
            instruction => instruction.OpCode == OpCodes.Call &&
                instruction.Operand is IMethod called && called.Name == "Fetch");
        var machine = new StaticMachine(modelTypeInitialization: true);
        Assert.True(machine.Execute(caller).Succeeded);
        Assert.True(machine.State.TryGetOrAllocateRuntimeSingleton("System.AppDomain", out var domain));
        Assert.True(machine.State.Heap.TryGetModelValue(domain, "Data:slot", out StaticValue _));
    }

    [Fact]
    public void LookupRuntimeEffectsAreNotErasedByLiteralRecovery()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Holder");
            // Run the domain write on every lookup, rather than once in a type initializer.
            var fetch = Filler(module, "slot", (41, "first"));
            fetch.Name = "Fetch";
            fetch.Attributes = MethodAttributes.Public | MethodAttributes.Static;
            fetch.MethodSig = MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.Int32);
            fetch.Body.Instructions.Insert(fetch.Body.Instructions.Count - 1, OpCodes.Ldstr.ToInstruction("first"));
            type.Methods.Add(fetch);
            type.Methods.Add(Caller(module, "Uses", fetch, 41));
        });
        Triage(context);
        var result = new StringLookupRecoveryPass().Run(context);
        Assert.Equal(PassStatus.Partial, result.Status);
        Assert.Equal(0, result.Changes);
        Assert.Contains(result.Diagnostics, value => value.Contains("runtime effects", StringComparison.Ordinal));
        Assert.DoesNotContain(Method(context, "Uses").Body.Instructions, instruction => instruction.OpCode == OpCodes.Ldstr);
    }

    [Fact]
    public void ALookupWithoutInitializationEffectsCanStillBeRemoved()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Holder");
            var fetch = new MethodDefUser("Fetch", MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.Int32))
                { Attributes = MethodAttributes.Static, Body = new CilBody() };
            fetch.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("plain"));
            fetch.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            type.Methods.Add(fetch);
            type.Methods.Add(Caller(module, "Uses", fetch, 41));
        });
        Triage(context);
        Assert.Equal(1, new StringLookupRecoveryPass().Run(context).Changes);
        Assert.DoesNotContain(Method(context, "Uses").Body.Instructions, instruction => instruction.OpCode == OpCodes.Call);
    }

    /// <summary>
    /// One use whose number cannot be settled leaves every use of that lookup alone.
    /// </summary>
    /// <remarks>
    /// Restoring the rest would read well and behave badly. The strings that were restored would be
    /// right, and the call left behind would be a call into machinery the cleanup afterwards has every
    /// reason to delete, because the only thing keeping it alive was the calls that are now literals.
    /// </remarks>
    [Fact]
    public void AUseWhoseNumberCannotBeSettledLeavesTheWholeLookupAsItWas()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Holder");
            type.Methods.Add(Filler(module, "slot", (41, "first")));
            var fetch = Fetcher(module, "Fetch", "slot");
            type.Methods.Add(fetch);
            var caller = Caller(module, "Uses", fetch, 41);
            // A number arrived at by two different routes is a number this reading declines to name.
            var body = caller.Body.Instructions;
            body.Insert(0, Instruction.Create(OpCodes.Stloc_0));
            body.Insert(0, Instruction.CreateLdcI4(41));
            body.Insert(0, Instruction.Create(OpCodes.Stloc_0));
            body.Insert(0, Instruction.CreateLdcI4(42));
            body[4] = Instruction.Create(OpCodes.Ldloc_0);
            caller.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            type.Methods.Add(caller);
        });

        Triage(context);
        var result = new StringLookupRecoveryPass().Run(context);

        Assert.Equal(PassStatus.Partial, result.Status);
        Assert.Equal(0, result.Changes);
        Assert.Contains(
            result.Diagnostics,
            said => said.Contains("could not settle", StringComparison.Ordinal));
        Assert.Contains(
            Method(context, "Uses").Body.Instructions,
            instruction => instruction.Operand is IMethod called && called.Name == "Fetch");
        // The uses nobody could read are still counted, so a run cannot report every string it has
        // as recovered when one of them was never touched.
        Assert.True(context.TryGetFact<int>("strings.callSites", out var counted));
        Assert.Equal(1, counted);
    }

    /// <summary>
    /// A public method that happens to take a number and give back a string is left alone.
    /// </summary>
    /// <remarks>
    /// Machinery a protector added is never part of what the assembly shows the outside world, and
    /// turning a call to something that is into a literal would be a change to the program rather
    /// than a reading of it.
    /// </remarks>
    [Fact]
    public void AMethodOnTheAssemblysOwnSurfaceIsNotTreatedAsALookup()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Holder");
            type.Attributes = TypeAttributes.Public | TypeAttributes.Class;
            type.Methods.Add(Filler(module, "slot", (41, "first")));
            var fetch = Fetcher(module, "Fetch", "slot");
            type.Methods.Add(fetch);
            type.Methods.Add(Caller(module, "Uses", fetch, 41));
        });

        Triage(context);
        var result = new StringLookupRecoveryPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(0, result.Changes);
        Assert.Contains(
            Method(context, "Uses").Body.Instructions,
            instruction => instruction.Operand is IMethod called && called.Name == "Fetch");
    }

    /// <summary>
    /// A method whose number is always its caller's own parameter is program logic, not a lookup.
    /// </summary>
    /// <remarks>
    /// A resolver of hidden literals is called with the number the literal was filed under, a
    /// constant written at the site. A method reached only with whatever number its caller happens
    /// to hold is being used, not decoded: there is no literal to write in its place, and counting
    /// its calls as strings left undone would report a gap that no rewrite could ever close.
    /// </remarks>
    [Fact]
    public void AMethodCalledOnlyWithACallersParameterIsLeftAsProgramLogic()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Holder");
            var fetch = Fetcher(module, "Fetch", "slot");
            type.Methods.Add(fetch);
            type.Methods.Add(ParameterCaller(module, "Uses", fetch));
        });

        Triage(context);
        var result = new StringLookupRecoveryPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(0, result.Changes);
        Assert.Contains(
            result.Diagnostics,
            said => said.Contains("pass-through", StringComparison.Ordinal));
        Assert.Contains(
            Method(context, "Uses").Body.Instructions,
            instruction => instruction.Operand is IMethod called && called.Name == "Fetch");
        // Nothing here was a string left undone, so nothing is owed against the run's totals.
        context.TryGetFact<int>("strings.callSites", out var counted);
        Assert.Equal(0, counted);
    }

    /// <summary>
    /// A method that reaches for randomness is program logic, however it is called.
    /// </summary>
    /// <remarks>
    /// A decoder of build-time strings answers the same for the same number every time. One that
    /// draws on a random source gives a different answer each run, which is proof it is the program's
    /// own and not a table of literals, even where its number is a plain constant. Asking it would
    /// get one of the many answers it may give, so it is neither restored nor counted as unread.
    /// </remarks>
    [Fact]
    public void AMethodThatReadsRandomnessIsLeftAsProgramLogic()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Holder");
            var fetch = RandomFetcher(module, "Fetch");
            type.Methods.Add(fetch);
            type.Methods.Add(Caller(module, "Uses", fetch, 8));
        });

        Triage(context);
        var result = new StringLookupRecoveryPass().Run(context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(0, result.Changes);
        Assert.Contains(
            result.Diagnostics,
            said => said.Contains("no two runs share", StringComparison.Ordinal));
        Assert.Contains(
            Method(context, "Uses").Body.Instructions,
            instruction => instruction.Operand is IMethod called && called.Name == "Fetch");
        context.TryGetFact<int>("strings.callSites", out var counted);
        Assert.Equal(0, counted);
    }

    /// <summary>
    /// The sample that led to this reading, whose strings are kept two layers down.
    /// </summary>
    /// <remarks>
    /// Reactor's own table holds seventeen strings here and the layer underneath it holds the rest,
    /// including everything the sample uses to decide whether it is being watched and where it reports
    /// to. A run that read only Reactor's layer reported seventeen of seventeen, which was true of
    /// the layer it read and wrong about the file.
    /// </remarks>
    [SampleFact]
    [Trait(Cost.Key, Cost.High)]
    public void TheLayerUnderneathReactorsOwnStringsIsReadToo()
    {
        var reports = Path.Combine(
            Path.GetTempPath(), $"Cilantro.Lookup.{Guid.NewGuid():N}");
        try
        {
            var result = new CilantroPipeline().Run(
                Checkout.Sample("Mlfhntkcvb.payload.Lqcuzgc.dll"),
                new PipelineOptions(AnalyzeOnly: true, ReportDirectory: reports));

            var reading = Assert.Single(
                result.Report.Passes, pass => pass.Pass == "string-lookup-recovery");
            Assert.Equal(PassStatus.Success, reading.Status);
            Assert.Equal(155, reading.Changes);
            Assert.Equal(172, result.Report.Recovery.StringCallSites);
            Assert.Equal(172, result.Report.Recovery.ReplacedStringSites);
        }
        finally
        {
            if (Directory.Exists(reports))
                Directory.Delete(reports, true);
        }
    }

    /// <summary>Reads the module the way the tool's default mode does.</summary>
    private static void Triage(ArtifactContext context) =>
        context.SetFact(
            BootstrapMachine.RunEnvironmentFact,
            new RunEnvironment(
                new HostEnvironment(HostProfile.Workstation),
                RunDeclarations.None,
                new BlockerLedger(),
                strict: false));

    private static MethodDef Method(ArtifactContext context, string name) =>
        context.Module.GetTypes().SelectMany(type => type.Methods)
            .First(method => method.Name == name);

    /// <summary>
    /// Decrypts nothing and files two strings under their numbers, which is the part of a lookup that
    /// runs once.
    /// </summary>
    private static MethodDefUser Filler(
        ModuleDefUser module,
        string slot,
        params (int Key, string Value)[] entries)
    {
        var table = new TypeRefUser(
            module, "System.Collections", "Hashtable", module.CorLibTypes.AssemblyRef);
        var made = new MemberRefUser(
            module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), table);
        var files = new MemberRefUser(
            module,
            "set_Item",
            MethodSig.CreateInstance(
                module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.Object),
            table);
        var filler = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void))
        {
            Attributes = MethodAttributes.Private | MethodAttributes.Static |
                MethodAttributes.SpecialName | MethodAttributes.RTSpecialName,
            Body = new CilBody()
        };
        filler.Body.Variables.Add(new Local(table.ToTypeSig()));
        var body = filler.Body.Instructions;
        body.Add(Instruction.Create(OpCodes.Newobj, made));
        body.Add(Instruction.Create(OpCodes.Stloc_0));
        foreach (var entry in entries)
        {
            body.Add(Instruction.Create(OpCodes.Ldloc_0));
            body.Add(Instruction.CreateLdcI4(entry.Key));
            body.Add(Instruction.Create(OpCodes.Box, module.CorLibTypes.Int32.ToTypeDefOrRef()));
            body.Add(Instruction.Create(OpCodes.Ldstr, entry.Value));
            body.Add(Instruction.Create(OpCodes.Callvirt, files));
        }
        body.Add(Instruction.Create(OpCodes.Call, Domain(module)));
        body.Add(Instruction.Create(OpCodes.Ldstr, slot));
        body.Add(Instruction.Create(OpCodes.Ldloc_0));
        body.Add(Instruction.Create(OpCodes.Callvirt, new MemberRefUser(
            module,
            "SetData",
            MethodSig.CreateInstance(
                module.CorLibTypes.Void, module.CorLibTypes.String, module.CorLibTypes.Object),
            new TypeRefUser(module, "System", "AppDomain", module.CorLibTypes.AssemblyRef))));
        body.Add(Instruction.Create(OpCodes.Ret));
        return filler;
    }

    /// <summary>Fetches one filed string, which is the part of a lookup every use calls.</summary>
    private static MethodDefUser Fetcher(ModuleDefUser module, string name, string slot)
    {
        var domain = new TypeRefUser(module, "System", "AppDomain", module.CorLibTypes.AssemblyRef);
        var table = new TypeRefUser(
            module, "System.Collections", "Hashtable", module.CorLibTypes.AssemblyRef);
        var fetcher = new MethodDefUser(
            name,
            MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.Int32))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        var body = fetcher.Body.Instructions;
        body.Add(Instruction.Create(OpCodes.Call, Domain(module)));
        body.Add(Instruction.Create(OpCodes.Ldstr, slot));
        body.Add(Instruction.Create(OpCodes.Callvirt, new MemberRefUser(
            module,
            "GetData",
            MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.String),
            domain)));
        body.Add(Instruction.Create(OpCodes.Castclass, table));
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.Create(OpCodes.Box, module.CorLibTypes.Int32.ToTypeDefOrRef()));
        body.Add(Instruction.Create(OpCodes.Callvirt, new MemberRefUser(
            module,
            "get_Item",
            MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.Object),
            table)));
        body.Add(Instruction.Create(
            OpCodes.Castclass, module.CorLibTypes.String.ToTypeDefOrRef()));
        body.Add(Instruction.Create(OpCodes.Ret));
        return fetcher;
    }

    private static MemberRefUser Domain(ModuleDefUser module) => new(
        module,
        "get_CurrentDomain",
        MethodSig.CreateStatic(
            new TypeRefUser(module, "System", "AppDomain", module.CorLibTypes.AssemblyRef)
                .ToTypeSig()),
        new TypeRefUser(module, "System", "AppDomain", module.CorLibTypes.AssemblyRef));

    private static MethodDefUser Caller(
        ModuleDefUser module,
        string name,
        MethodDef fetcher,
        params int[] keys)
    {
        var caller = new MethodDefUser(name, MethodSig.CreateStatic(module.CorLibTypes.Void))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        var body = caller.Body.Instructions;
        foreach (var key in keys)
        {
            body.Add(Instruction.CreateLdcI4(key));
            body.Add(Instruction.Create(OpCodes.Call, fetcher));
            body.Add(Instruction.Create(OpCodes.Pop));
        }
        body.Add(Instruction.Create(OpCodes.Ret));
        return caller;
    }

    /// <summary>A caller that hands the fetcher its own parameter rather than a constant.</summary>
    private static MethodDefUser ParameterCaller(
        ModuleDefUser module,
        string name,
        MethodDef fetcher)
    {
        var caller = new MethodDefUser(
            name, MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        var body = caller.Body.Instructions;
        body.Add(Instruction.Create(OpCodes.Ldarg_0));
        body.Add(Instruction.Create(OpCodes.Call, fetcher));
        body.Add(Instruction.Create(OpCodes.Pop));
        body.Add(Instruction.Create(OpCodes.Ret));
        return caller;
    }

    /// <summary>A <c>string(int)</c> method whose body draws on a random source.</summary>
    private static MethodDefUser RandomFetcher(ModuleDefUser module, string name)
    {
        var random = new TypeRefUser(module, "System", "Random", module.CorLibTypes.AssemblyRef);
        var made = new MemberRefUser(
            module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), random);
        var next = new MemberRefUser(
            module, "Next", MethodSig.CreateInstance(module.CorLibTypes.Int32), random);
        var fetcher = new MethodDefUser(
            name,
            MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.Int32))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        var body = fetcher.Body.Instructions;
        body.Add(Instruction.Create(OpCodes.Newobj, made));
        body.Add(Instruction.Create(OpCodes.Callvirt, next));
        body.Add(Instruction.Create(OpCodes.Pop));
        body.Add(Instruction.Create(OpCodes.Ldstr, "seed"));
        body.Add(Instruction.Create(OpCodes.Ret));
        return fetcher;
    }
}
