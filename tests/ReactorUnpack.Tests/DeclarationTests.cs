using dnlib.DotNet;
using ReactorUnpack.Core;
using ReactorUnpack.Core.Interpretation;

namespace ReactorUnpack.Tests;

/// <summary>
/// Covers the one file a caller hands over to say what a run may be told.
/// </summary>
/// <remarks>
/// The tests are mostly about refusals: what the parser will not accept, and what the machine will not
/// do with what it accepted. That is where the value is, because the file is written by whoever is
/// driving the tool — increasingly a program — and a section quietly ignored, or a declaration quietly
/// standing in front of real code, would be a lie told with the tool's authority behind it.
/// </remarks>
public sealed class DeclarationTests
{
    [Fact]
    public void EverySectionIsRead()
    {
        var declarations = RunDeclarations.Parse(
            """
            {
              "name": "lqcuzgc",
              "facts": { "env:MachineName": "DESKTOP-7QK2" },
              "libraries": ["/opt/lib/protobuf-net.dll"],
              "budgets": { "steps": 40000000, "depth": 128 },
              "passes": { "skip": ["virtualization-disassembly"] },
              "calls": { "System.Boolean Vendor.Guard::Ok()": { "returns": true } }
            }
            """,
            "unnamed");

        Assert.Equal("lqcuzgc", declarations.Name);
        Assert.True(declarations.Facts.TryAnswer("env:MachineName", out var named));
        Assert.Equal("DESKTOP-7QK2", named.Text);
        Assert.Equal(["/opt/lib/protobuf-net.dll"], declarations.Libraries);
        Assert.Equal(40_000_000, declarations.Budgets.Steps);
        Assert.Equal(128, declarations.Budgets.Depth);
        Assert.True(declarations.Skips("virtualization-disassembly"));
        Assert.Single(declarations.Calls);
    }

    /// <summary>
    /// A host profile is the facts section written on its own, so the file somebody already has keeps
    /// working when they start using the fuller form.
    /// </summary>
    [Fact]
    public void AHostProfileIsAValidSetOfDeclarations()
    {
        var declarations = RunDeclarations.Parse(
            """{ "name": "workstation", "facts": { "env:ProcessorCount": 8 } }""",
            "unnamed");

        Assert.Equal("workstation", declarations.Facts.Name);
        Assert.True(declarations.Facts.TryAnswer("env:ProcessorCount", out var count));
        Assert.Equal(8, count.Number);
    }

    /// <summary>
    /// The facts are checked the way a profile checks them, since they are the same facts and a family
    /// nothing ever asks about is the commonest way to write a file that does nothing.
    /// </summary>
    [Fact]
    public void AFactAboutSomethingTheToolNeverAsksAboutIsRefused()
    {
        var thrown = Assert.Throws<HostProfileException>(() => RunDeclarations.Parse(
            """{ "facts": { "weather:Today": "rain" } }""",
            "odd"));

        Assert.Contains("weather", thrown.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ASectionTheToolDoesNotHaveIsRefused()
    {
        var thrown = Assert.Throws<DeclarationException>(() => RunDeclarations.Parse(
            """{ "assumptions": { "everything": true } }""",
            "odd"));

        Assert.Contains("\"calls\"", thrown.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ABudgetThatIsNotAFigureAboveZeroIsRefused()
    {
        Assert.Throws<DeclarationException>(() => RunDeclarations.Parse(
            """{ "budgets": { "steps": 0 } }""",
            "odd"));
        Assert.Throws<DeclarationException>(() => RunDeclarations.Parse(
            """{ "budgets": { "paitence": 10 } }""",
            "odd"));
    }

    /// <summary>
    /// The key has to be the signature the refusal printed, because anything else is a declaration
    /// that will never be consulted and will look like the tool ignored it.
    /// </summary>
    [Fact]
    public void ACallDeclaredUnderSomethingThatIsNotASignatureIsRefused()
    {
        var thrown = Assert.Throws<DeclarationException>(() => RunDeclarations.Parse(
            """{ "calls": { "Guard.Ok": { "returns": true } } }""",
            "odd"));

        Assert.Contains("::", thrown.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ACallMustSayEitherWhatItReturnsOrThatItDoesNothing()
    {
        Assert.Throws<DeclarationException>(() => RunDeclarations.Parse(
            """{ "calls": { "System.Void A.B::C()": { "returns": 1, "inert": true } } }""",
            "odd"));
        Assert.Throws<DeclarationException>(() => RunDeclarations.Parse(
            """{ "calls": { "System.Void A.B::C()": { "does": "nothing" } } }""",
            "odd"));
    }

    /// <summary>
    /// The hash names what was declared rather than how it was typed, so a report and the file behind
    /// it can be matched up after somebody has reformatted the file.
    /// </summary>
    [Fact]
    public void TwoFilesSayingTheSameThingHashAlike()
    {
        var one = RunDeclarations.Parse(
            """{ "name": "a", "facts": { "env:UserName": "mhoffman" } }""",
            "unnamed");
        var same = RunDeclarations.Parse(
            "{\n  \"facts\":{\"env:UserName\":\"mhoffman\"},\n  \"name\":\"a\"\n}",
            "unnamed");
        var different = RunDeclarations.Parse(
            """{ "name": "a", "facts": { "env:UserName": "jgajek" } }""",
            "unnamed");

        Assert.Equal(one.Sha256, same.Sha256);
        Assert.NotEqual(one.Sha256, different.Sha256);
    }

    /// <summary>
    /// Declaring what a call does is the one thing a file cannot do on its own authority, so it takes
    /// a decision at the command line as well.
    /// </summary>
    [Fact]
    public void ADeclaredCallIsIgnoredUntilItIsAllowed()
    {
        using var module = BlockerTests.NewModule();
        var (method, signature) = BlockerTests.CallsUnmodeled(module, module.CorLibTypes.String);
        var declared = Declaring(signature, """{ "returns": "MIT-9931" }""");

        var refused = Under(declared, calls: false).Execute(method);

        Assert.Equal(StaticExecutionStatus.Unsupported, refused.Status);
    }

    [Fact]
    public void AnAllowedDeclarationAnswersTheCallThatWouldHaveStoppedTheRun()
    {
        using var module = BlockerTests.NewModule();
        var (method, signature) = BlockerTests.CallsUnmodeled(module, module.CorLibTypes.String);
        var machine = Under(Declaring(signature, """{ "returns": "MIT-9931" }"""), calls: true);

        var result = machine.Execute(method);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.True(machine.State.Heap.TryGetString(result.Value, out var licence));
        Assert.Equal("MIT-9931", licence);
        Assert.Empty(machine.State.Blockers.Blockers);
    }

    /// <summary>
    /// A value that came out of a declaration says so, so that a reader tracing a recovered constant
    /// back reaches the assertion it rests on rather than stopping at a call.
    /// </summary>
    [Fact]
    public void ADeclaredValueCarriesThatItWasDeclared()
    {
        using var module = BlockerTests.NewModule();
        var (method, signature) = BlockerTests.CallsUnmodeled(module, module.CorLibTypes.Int32);
        var machine = Under(Declaring(signature, """{ "returns": 7 }"""), calls: true);

        var result = machine.Execute(method);

        Assert.Equal(7, result.Value.AsInt32());
        Assert.Contains(
            "Declared",
            machine.State.Provenance.Render(result.Value.ProvenanceId),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// A call declared to do nothing is recorded as handing something to the runtime, so that the pass
    /// which removes loader frames it can prove do nothing cannot prove it from a declaration.
    /// </summary>
    [Fact]
    public void ACallDeclaredInertIsStillSomethingTheFrameDid()
    {
        using var module = BlockerTests.NewModule();
        var (method, signature) = BlockerTests.CallsUnmodeled(module, module.CorLibTypes.Void);
        var machine = Under(Declaring(signature, """{ "inert": true }"""), calls: true);

        var result = machine.Execute(method);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        var evidence = machine.State.LoaderEvidence;
        Assert.Contains(
            $"declared call {signature}",
            evidence.Effects.SelectMany(effect => effect.Value.Registrations),
            StringComparer.Ordinal);
        Assert.Contains(
            evidence.Observations,
            observation => observation.Kind == LoaderObservationKind.DeclaredCall &&
                observation.Detail.StartsWith(signature, StringComparison.Ordinal));
    }

    /// <summary>
    /// A call that returns something cannot be declared inert, because "does nothing" says nothing
    /// about the value the program is about to use.
    /// </summary>
    [Fact]
    public void ACallThatReturnsSomethingCannotBeDeclaredToDoNothing()
    {
        using var module = BlockerTests.NewModule();
        var (method, signature) = BlockerTests.CallsUnmodeled(module, module.CorLibTypes.String);
        var machine = Under(Declaring(signature, """{ "inert": true }"""), calls: true);

        var result = machine.Execute(method);

        Assert.Equal(StaticExecutionStatus.Unsupported, result.Status);
        Assert.Contains("returns a value", result.Diagnostic, StringComparison.Ordinal);
    }

    /// <summary>
    /// A declaration nothing asked about is reported, because a key spelled differently from the one
    /// the run asks under is the likeliest mistake in the file and looks exactly like being ignored.
    /// </summary>
    [Fact]
    public void ADeclarationNothingAskedAboutIsReportedAsUnused()
    {
        using var module = BlockerTests.NewModule();
        var (method, signature) = BlockerTests.CallsUnmodeled(module, module.CorLibTypes.String);
        var declarations = RunDeclarations.Parse(
            $$"""
            {
              "calls": {
                "{{signature}}": { "returns": "used" },
                "System.String Vendor.Support.Licence::Other()": { "returns": "never asked" }
              }
            }
            """,
            "test").Allowing(calls: true);
        var machine = new StaticMachine();
        machine.State.RegisterRunEnvironment(new RunEnvironment(declarations: declarations));

        machine.Execute(method);

        Assert.Equal(
            ["System.String Vendor.Support.Licence::Other() returns \"never asked\""],
            declarations.Unconsulted.Select(call => $"{call.Method} {call.Describe()}"));
        Assert.Single(declarations.Consulted);
    }

    /// <summary>
    /// A declared budget replaces the figure of whichever pass is running rather than becoming a
    /// figure of its own, because it is a statement about the run.
    /// </summary>
    [Fact]
    public void ADeclaredBudgetReplacesTheFigureThePassWouldHaveUsed()
    {
        var declarations = RunDeclarations.Parse(
            """{ "budgets": { "steps": 9000, "allocatedBytes": 1073741824 } }""",
            "test");

        var limits = declarations.Budgets.Over(new StaticMachineLimits(
            MaximumSteps: 2_000_000,
            MaximumRecursionDepth: 64,
            MaximumAllocatedBytes: 256 * 1024 * 1024,
            MaximumArrayLength: 8 * 1024 * 1024));

        Assert.Equal(9_000, limits.MaximumSteps);
        Assert.Equal(1024L * 1024 * 1024, limits.MaximumAllocatedBytes);
        // A budget raised for the sake of one large read has to carry the largest single read with it.
        Assert.Equal(1024 * 1024 * 1024, limits.MaximumArrayLength);
        Assert.Equal(64, limits.MaximumRecursionDepth);
    }

    /// <summary>Told nothing, a run behaves exactly as it did before any of this existed.</summary>
    [Fact]
    public void ARunToldNothingIsToldNothing()
    {
        Assert.Equal("default", RunDeclarations.None.Facts.Name);
        Assert.False(RunDeclarations.None.Budgets.Stated);
        Assert.Empty(RunDeclarations.None.Calls);
        Assert.False(RunDeclarations.None.Allowing(calls: true).TryAnswerCall("anything", out _));
        Assert.False(RunDeclarations.None.CallsAllowed);
    }

    /// <summary>
    /// The same fact stated in a profile and in a set of declarations is refused rather than settled by
    /// precedence, because whichever file lost would have lost silently.
    /// </summary>
    [SampleFact]
    public void TheFactsCannotBeStatedInTwoPlacesAtOnce()
    {
        var directory = Temporary();
        try
        {
            var declared = Path.Combine(directory, "d.json");
            var profile = Path.Combine(directory, "p.json");
            File.WriteAllText(declared, """{ "facts": { "env:UserName": "one" } }""");
            File.WriteAllText(profile, """{ "facts": { "env:UserName": "other" } }""");

            var thrown = Assert.Throws<DeclarationException>(() => new ReactorPipeline().Run(
                Sample("Qafcakg.payload.Ptnifif.dll"),
                new PipelineOptions(
                    AnalyzeOnly: true,
                    ReportDirectory: directory,
                    HostProfilePath: profile,
                    DeclarationsPath: declared)));

            Assert.Contains("stated twice", thrown.Message, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(directory, true);
        }
    }

    /// <summary>
    /// Method-body recovery and string-table recovery built their machines by hand and never saw the
    /// run's environment, so a profile handed to the run was silently ignored by both. A budget is the
    /// cheapest way to prove the environment now arrives: only a machine that read the declarations can
    /// stop for a budget nothing else set.
    /// </summary>
    [SampleFact]
    public void WhatTheRunWasToldReachesTheMachineThatRecoversMethodBodies()
    {
        var directory = Temporary();
        try
        {
            var declared = Path.Combine(directory, "d.json");
            File.WriteAllText(declared, """{ "name": "miserly", "budgets": { "steps": 8 } }""");

            var result = new ReactorPipeline().Run(
                Sample("Qafcakg.payload.Ptnifif.dll"),
                new PipelineOptions(
                    AnalyzeOnly: true,
                    ReportDirectory: directory,
                    DeclarationsPath: declared));

            var blocker = Assert.Single(
                result.Report.Blockers!,
                item => item.Kind == BlockerKind.Budget && item.Pass == "method-body-recovery");
            Assert.Contains("steps", blocker.Declare!, StringComparison.Ordinal);
            Assert.Equal("miserly", result.Report.Declarations!.Name);
        }
        finally
        {
            Directory.Delete(directory, true);
        }
    }

    private static string Sample(string filename) => Checkout.Sample(filename);

    private static string Temporary()
    {
        var path = Path.Combine(Path.GetTempPath(), $"ReactorUnpack.Tests.{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }

    private static string Declaring(string signature, string outcome) =>
        $$"""{ "calls": { "{{signature}}": {{outcome}} } }""";

    private static StaticMachine Under(string declarations, bool calls)
    {
        var machine = new StaticMachine();
        machine.State.RegisterRunEnvironment(new RunEnvironment(
            declarations: RunDeclarations.Parse(declarations, "test").Allowing(calls)));
        return machine;
    }
}
