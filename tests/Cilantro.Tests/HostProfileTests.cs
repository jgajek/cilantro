using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Interpretation;

namespace Cilantro.Tests;

/// <summary>
/// Covers what the machine says when interpreted code asks about the computer it is running on.
/// </summary>
/// <remarks>
/// Two properties matter more than any single answer. The first is that the built-in profile answers
/// exactly what the intrinsics used to answer on their own, because a default that said more would
/// change what every sample recovers without anyone having asked for it. The second is that a
/// question nobody has answered is refused by naming the fact that would answer it, because that is
/// what turns a dead end into a thing somebody can fix.
/// </remarks>
public sealed class HostProfileTests
{
    [Fact]
    public void TheDefaultProfileReadsTheClockTheWayTheMachineAlwaysHas()
    {
        using var module = NewModule();
        var machine = new StaticMachine();

        var result = machine.Execute(Calls(
            module, "System", "DateTime", "get_UtcNow", module.CorLibTypes.Object));

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.True(machine.State.Heap.TryGetModelValue(result.Value, "Ticks", out long ticks));
        Assert.Equal(new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc).Ticks, ticks);
    }

    [Fact]
    public void AProfileSaysWhatTheClockReads()
    {
        using var module = NewModule();
        var machine = Under("""
            { "facts": { "time:UtcNow": "2024-03-09T14:25:00Z" } }
            """);

        var result = machine.Execute(Calls(
            module, "System", "DateTime", "get_UtcNow", module.CorLibTypes.Object));

        Assert.True(machine.State.Heap.TryGetModelValue(result.Value, "Ticks", out long ticks));
        Assert.Equal(
            new DateTime(2024, 3, 9, 14, 25, 0, DateTimeKind.Utc).Ticks,
            ticks);
    }

    /// <summary>
    /// The refusal has to name the key, because the reader of it is deciding what to write down and
    /// has no other way of learning what the machine would accept.
    /// </summary>
    /// <remarks>
    /// Pinned against a profile that is explicitly sparse rather than against whatever the built-in
    /// default happens to hold, so that the property under test stays this one. A default that grew an
    /// answer for this question would otherwise turn the test green by making it about something else.
    /// </remarks>
    [Fact]
    public void AQuestionNoProfileAnswersIsRefusedByNamingWhatWouldAnswerIt()
    {
        using var module = NewModule();

        var result = Under("""{ "facts": { } }""").Execute(Calls(
            module, "System", "Environment", "get_MachineName", module.CorLibTypes.String));

        Assert.Equal(StaticExecutionStatus.Unsupported, result.Status);
        Assert.Contains("env:MachineName", result.Diagnostic, StringComparison.Ordinal);
        Assert.Contains("--host-profile", result.Diagnostic, StringComparison.Ordinal);
    }

    [Fact]
    public void AProfileThatNamesTheMachineAnswersForIt()
    {
        using var module = NewModule();
        var machine = Under("""
            { "name": "bench", "facts": { "env:MachineName": "DESKTOP-7QK2" } }
            """);

        var result = machine.Execute(Calls(
            module, "System", "Environment", "get_MachineName", module.CorLibTypes.String));

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.True(machine.State.Heap.TryGetString(result.Value, out var name));
        Assert.Equal("DESKTOP-7QK2", name);
    }

    /// <summary>
    /// A value that came from the profile says so, so that a reader tracing a recovered constant
    /// back can tell the difference between something the sample determined and something a person
    /// asserted.
    /// </summary>
    [Fact]
    public void AnAnswerCarriesWhereItCameFrom()
    {
        using var module = NewModule();
        var machine = Under("""
            { "facts": { "env:ProcessorCount": 8 } }
            """);

        var result = machine.Execute(Calls(
            module, "System", "Environment", "get_ProcessorCount", module.CorLibTypes.Int32));

        Assert.Equal(8, result.Value.AsInt32());
        Assert.Contains(
            "Host host env:ProcessorCount",
            machine.State.Provenance.Render(result.Value.ProvenanceId),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// The portrait the tool assumes ships inside it, so the common case needs no file, and everything
    /// in it reads as assumed rather than as anybody's statement.
    /// </summary>
    [Fact]
    public void TheAssumedWorkstationShipsInsideTheTool()
    {
        var workstation = HostProfile.Workstation;

        Assert.Equal("windows-10-workstation", workstation.Name);
        Assert.True(workstation.TryAnswer("wmi:Win32_DiskDrive.SerialNumber", out var disk));
        Assert.Equal("S3YJNB0M604271", disk.Text);
        Assert.All(workstation.Answers.Values, answer => Assert.False(answer.Stated));
        // Nothing material: a made-up machine name costs a plausible detail, made-up bytes would cost
        // a wrong answer to the only question the reader asked.
        Assert.DoesNotContain(
            workstation.Answers.Values,
            answer => answer.Kind == HostAnswerKind.Bytes);
        // It says the same thing twice about the disk, and the two agree.
        Assert.True(workstation.TryAnswer("volume:C.Serial", out var serial));
        Assert.True(workstation.TryAnswer("wmi:Win32_LogicalDisk.VolumeSerialNumber", out var text));
        Assert.Equal(text.Text, serial.Number.ToString("X8", null));
    }

    /// <summary>
    /// The workstation answers every folder a Windows machine has a folder for.
    /// </summary>
    /// <remarks>
    /// A profile that answers some of them stops a run on whichever one the sample happens to ask
    /// about, and the sample chooses. There is nothing sample-specific about where Windows keeps
    /// these, so answering a subset buys no caution — it only moves the dead end. Every value is a
    /// path the profile's own user and drive already imply, and the ones Windows itself answers with
    /// an empty string are answered that way rather than left out.
    /// </remarks>
    [Fact]
    public void TheAssumedWorkstationKnowsWhereWindowsKeepsThings()
    {
        var workstation = HostProfile.Workstation;

        foreach (var folder in Enum.GetValues<Environment.SpecialFolder>().Distinct())
        {
            Assert.True(
                workstation.TryAnswer($"env:folder:{(int)folder}", out var path),
                $"The workstation does not say where {folder} is.");
            Assert.Equal(HostAnswerKind.Text, path.Kind);
        }

        Assert.True(workstation.TryAnswer("env:folder:42", out var programFiles));
        Assert.Equal("C:\\Program Files (x86)", programFiles.Text);
        // Windows answers these with nothing, and nothing is an answer.
        Assert.True(workstation.TryAnswer("env:folder:17", out var myComputer));
        Assert.Equal(string.Empty, myComputer.Text);
    }

    /// <summary>
    /// An answer nobody stated says that too, and says it differently, because the two are worth
    /// telling apart: one is checkable against the machine somebody described, and the other is the
    /// tool's own portrait of a plausible computer.
    /// </summary>
    [Fact]
    public void AnAnswerNobodyStatedSaysItWasAssumed()
    {
        using var module = NewModule();
        var machine = new StaticMachine();

        var result = machine.Execute(Calls(
            module, "System.Diagnostics", "Debugger", "get_IsAttached", module.CorLibTypes.Boolean));

        Assert.Contains(
            "Assumed host debugger:IsAttached",
            machine.State.Provenance.Render(result.Value.ProvenanceId),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// Stating one fact does not make a person answerable for the fourteen they inherited, so what
    /// they said and what the default assumed stay apart inside one profile.
    /// </summary>
    [Fact]
    public void StatingOneFactDoesNotClaimTheOthersWereStated()
    {
        var profile = HostProfile.Parse("""{ "facts": { "env:MachineName": "DESKTOP-7QK2" } }""", "x");

        Assert.True(profile.TryAnswer("env:MachineName", out var named));
        Assert.True(named.Stated);
        Assert.True(profile.TryAnswer("debugger:IsAttached", out var debugger));
        Assert.False(debugger.Stated);
    }

    /// <summary>
    /// A platform call is a boundary rather than a gap, except where all it does is report a fact.
    /// Then it is a gap, and the profile is what closes it.
    /// </summary>
    [Fact]
    public void ANativeCallThatOnlyAsksTheHostSomethingIsAnsweredFromTheProfile()
    {
        using var module = NewModule();
        var machine = Under("""
            { "facts": { "native:user32!SetProcessDPIAware": true } }
            """);

        var result = machine.Execute(CallsNative(module, "user32.dll", "SetProcessDPIAware"));

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(1, result.Value.AsInt32());
    }

    /// <remarks>
    /// Explicitly sparse, and explicitly strict: the first so that the profile is known not to answer
    /// this, and the second because a run that is allowed to assume steps over the call instead, which
    /// is a different property covered elsewhere.
    /// </remarks>
    [Fact]
    public void ANativeCallTheProfileSaysNothingAboutStillStops()
    {
        using var module = NewModule();

        var result = Under("""{ "facts": { } }""", strict: true).Execute(
            CallsNative(module, "user32.dll", "SetProcessDPIAware"));

        Assert.Equal(StaticExecutionStatus.Unsupported, result.Status);
        Assert.Contains(
            "native:user32!SetProcessDPIAware", result.Diagnostic, StringComparison.Ordinal);
    }

    [Fact]
    public void AWmiPropertyIsAnsweredForTheClassTheQueryNames()
    {
        using var module = NewModule();
        var machine = Under("""
            { "facts": { "wmi:Win32_ComputerSystem.Manufacturer": "Dell Inc." } }
            """);
        var management = new TypeRefUser(
            module, "System.Management", "ManagementClass", module.CorLibTypes.AssemblyRef);
        var method = NewMethod(module, "Ask", MethodSig.CreateStatic(module.CorLibTypes.Object));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "Win32_ComputerSystem"));
        method.Body.Instructions.Add(Instruction.Create(
            OpCodes.Newobj,
            new MemberRefUser(
                module,
                ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String),
                management)));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "Manufacturer"));
        method.Body.Instructions.Add(Instruction.Create(
            OpCodes.Callvirt,
            new MemberRefUser(
                module,
                "GetPropertyValue",
                MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.String),
                management)));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

        var result = machine.Execute(method);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.True(machine.State.Heap.TryGetString(result.Value, out var manufacturer));
        Assert.Equal("Dell Inc.", manufacturer);
    }

    /// <summary>
    /// A stager keeps its next stage in a binary registry value, so an analyst who has that value
    /// has the payload and needs somewhere to state it.
    /// </summary>
    [Fact]
    public void AProfileStatesBytesAndTheRegistryHandsThemBack()
    {
        using var module = NewModule();
        var stage = new byte[] { 0x4D, 0x5A, 0x90, 0x00 };
        var machine = Under($$"""
            {
              "facts": {
                "registry:HKEY_CURRENT_USER\\Software\\Stage!blob":
                  { "base64": "{{Convert.ToBase64String(stage)}}" }
              }
            }
            """);

        var result = machine.Execute(ReadsRegistry(module, "Software\\Stage", "blob"));

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.True(machine.State.Heap.TryGetLength(result.Value, out var length));
        Assert.Equal(stage.Length, length);
        for (var index = 0; index < stage.Length; index++)
        {
            Assert.True(machine.State.Heap.TryReadArray(result.Value, index, out var read));
            Assert.Equal(stage[index], (byte)read.AsInt32());
        }
    }

    [Fact]
    public void AProfileRejectsBytesThatAreNotBase64()
    {
        var thrown = Assert.Throws<HostProfileException>(() => HostProfile.Parse(
            """
            { "facts": { "registry:HKEY_CURRENT_USER\\Software\\Stage!blob": { "base64": "n@t" } } }
            """,
            "odd"));

        Assert.Contains("base64", thrown.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AProfileRejectsAKeyAboutSomethingItDoesNotDescribe()
    {
        var thrown = Assert.Throws<HostProfileException>(() => HostProfile.Parse(
            """
            { "facts": { "weather:Tuesday": "rain" } }
            """,
            "odd"));

        Assert.Contains("weather", thrown.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AProfileRejectsASectionItHasNoUseFor()
    {
        var thrown = Assert.Throws<HostProfileException>(() => HostProfile.Parse(
            """
            { "facts": {}, "notes": "ignore me" }
            """,
            "odd"));

        Assert.Contains("notes", thrown.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The hash identifies the answers rather than the file, because a report naming a profile is
    /// telling a reader which answers were used and two files saying the same thing said it.
    /// </summary>
    [Fact]
    public void ProfilesWithTheSameAnswersHashAlike()
    {
        var one = HostProfile.Parse(
            """
            { "name": "bench", "facts": { "env:UserName": "mhoffman", "process:Id": 4120 } }
            """,
            "one");
        var again = HostProfile.Parse(
            """
            { "name": "bench", "facts": { "process:Id": 4120, "env:UserName": "mhoffman" } }
            """,
            "two");
        var different = HostProfile.Parse(
            """
            { "name": "bench", "facts": { "env:UserName": "someone", "process:Id": 4120 } }
            """,
            "three");

        Assert.Equal(one.Sha256, again.Sha256);
        Assert.NotEqual(one.Sha256, different.Sha256);
    }

    /// <summary>A profile states what differs; the answers it says nothing about survive.</summary>
    [Fact]
    public void AProfileKeepsTheDefaultsItSaysNothingAbout()
    {
        var profile = HostProfile.Parse("""{ "facts": { "process:Id": 4120 } }""", "bench");

        Assert.True(profile.TryAnswer("process:Id", out var id));
        Assert.Equal(4120, id.Number);
        Assert.True(profile.TryAnswer("debugger:IsAttached", out var attached));
        Assert.False(attached.Flag);
    }

    [Fact]
    public void WhatTheRunAskedAboutTheHostIsKept()
    {
        using var module = NewModule();
        var machine = Under("""{ "facts": { "env:UserName": "mhoffman" } }""");

        machine.Execute(Calls(
            module, "System", "Environment", "get_UserName", module.CorLibTypes.String));
        machine.Execute(Calls(
            module, "System", "Environment", "get_MachineName", module.CorLibTypes.String));

        var asked = machine.State.Host.Questions;
        Assert.Equal(
            ["env:MachineName", "env:UserName"],
            asked.Select(question => question.Key));
        Assert.False(asked[0].Answer.IsAnswered);
        Assert.Equal("\"mhoffman\"", asked[1].Answer.Describe());
    }

    /// <summary>
    /// Two machines given the same profile answer the same way, which is what the two-run agreement
    /// the rest of the tool rests on requires of anything the profile touches.
    /// </summary>
    [Fact]
    public void TwoMachinesUnderOneProfileAnswerAlike()
    {
        using var module = NewModule();
        const string stated = """{ "facts": { "env:UserName": "mhoffman" } }""";
        var method = Calls(
            module, "System", "Environment", "get_UserName", module.CorLibTypes.String);

        var first = Under(stated);
        var second = Under(stated);
        var one = first.Execute(method);
        var other = second.Execute(method);

        Assert.True(first.State.Heap.TryGetString(one.Value, out var told));
        Assert.True(second.State.Heap.TryGetString(other.Value, out var again));
        Assert.Equal(told, again);
    }

    /// <summary>A machine standing on its own still has the answers, so nothing needs a pipeline.</summary>
    [Fact]
    public void AMachineNobodyHandedAProfileStillHasOne()
    {
        var state = new StaticMachineState(new StaticMachineLimits());

        Assert.Equal("default", state.Host.Profile.Name);
        Assert.True(state.TryAskHost("debugger:IsAttached", out var attached));
        Assert.False(attached.Flag);
    }

    private static StaticMachine Under(string profile, bool strict = true)
    {
        var machine = new StaticMachine();
        machine.State.RegisterRunEnvironment(new RunEnvironment(
            new HostEnvironment(HostProfile.Parse(profile, "test")),
            strict: strict));
        return machine;
    }

    /// <summary>A method whose whole body is one call of a framework member and a return.</summary>
    private static MethodDefUser Calls(
        ModuleDefUser module,
        string space,
        string type,
        string member,
        TypeSig returns)
    {
        var declaring = new TypeRefUser(module, space, type, module.CorLibTypes.AssemblyRef);
        var method = NewMethod(module, $"Call{member}", MethodSig.CreateStatic(returns));
        method.Body.Instructions.Add(Instruction.Create(
            OpCodes.Call,
            new MemberRefUser(module, member, MethodSig.CreateStatic(returns), declaring)));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        return method;
    }

    /// <summary>A method that opens a key under the current user and reads one value from it.</summary>
    private static MethodDefUser ReadsRegistry(ModuleDefUser module, string path, string value)
    {
        var registry = new TypeRefUser(
            module, "Microsoft.Win32", "Registry", module.CorLibTypes.AssemblyRef);
        var key = new TypeRefUser(
            module, "Microsoft.Win32", "RegistryKey", module.CorLibTypes.AssemblyRef);
        var method = NewMethod(module, "Read", MethodSig.CreateStatic(module.CorLibTypes.Object));
        var body = method.Body.Instructions;
        body.Add(Instruction.Create(OpCodes.Call, new MemberRefUser(
            module, "get_CurrentUser", MethodSig.CreateStatic(key.ToTypeSig()), registry)));
        body.Add(Instruction.Create(OpCodes.Ldstr, path));
        body.Add(Instruction.Create(OpCodes.Callvirt, new MemberRefUser(
            module,
            "OpenSubKey",
            MethodSig.CreateInstance(key.ToTypeSig(), module.CorLibTypes.String),
            key)));
        body.Add(Instruction.Create(OpCodes.Ldstr, value));
        body.Add(Instruction.Create(OpCodes.Callvirt, new MemberRefUser(
            module,
            "GetValue",
            MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.String),
            key)));
        body.Add(Instruction.Create(OpCodes.Ret));
        return method;
    }

    /// <summary>A method that calls a platform entry point declared in this module.</summary>
    private static MethodDefUser CallsNative(ModuleDefUser module, string library, string entry)
    {
        var declaring = module.Types.FirstOrDefault(item => item.Name == "Program") ??
            new TypeDefUser("Tests", "Program", module.CorLibTypes.Object.TypeDefOrRef);
        if (!module.Types.Contains(declaring))
            module.Types.Add(declaring);
        var imported = new MethodDefUser(
            entry,
            MethodSig.CreateStatic(module.CorLibTypes.Int32),
            MethodImplAttributes.PreserveSig,
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PinvokeImpl)
        {
            ImplMap = new ImplMapUser(new ModuleRefUser(module, library), entry, 0)
        };
        declaring.Methods.Add(imported);
        var method = NewMethod(module, $"Call{entry}", MethodSig.CreateStatic(module.CorLibTypes.Int32));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Call, imported));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        return method;
    }

    private static ModuleDefUser NewModule()
    {
        var module = new ModuleDefUser("host-profile.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser("host-profile", new Version(1, 0));
        assembly.Modules.Add(module);
        return module;
    }

    private static MethodDefUser NewMethod(ModuleDef module, string name, MethodSig signature)
    {
        var method = new MethodDefUser(name, signature)
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        var type = module.Types.FirstOrDefault(item => item.Name == "Program");
        if (type is null)
        {
            type = new TypeDefUser("Tests", "Program", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);
        }

        type.Methods.Add(method);
        return method;
    }
}
