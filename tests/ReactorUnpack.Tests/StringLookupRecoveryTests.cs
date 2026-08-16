using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core;
using ReactorUnpack.Core.Interpretation;
using ReactorUnpack.Core.Recovery;

namespace ReactorUnpack.Tests;

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
    public void StringsKeptInADomainSlotAreRestoredByAskingTheMethodThatFetchesThem()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Holder");
            type.Methods.Add(Filler(module, "slot", (41, "first"), (42, "second")));
            var fetch = Fetcher(module, "Fetch", "slot");
            type.Methods.Add(fetch);
            type.Methods.Add(Caller(module, "Uses", fetch, 42, 41, 42));
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
        Assert.DoesNotContain(
            caller.Body.Instructions,
            instruction => instruction.OpCode == OpCodes.Call &&
                instruction.Operand is IMethod called && called.Name == "Fetch");
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
            Path.GetTempPath(), $"ReactorUnpack.Lookup.{Guid.NewGuid():N}");
        try
        {
            var result = new ReactorPipeline().Run(
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
}
