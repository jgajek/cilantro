using System.Text.Json.Nodes;
using Cilantro.Core.Interpretation;

namespace Cilantro.Tests;

/// <summary>
/// Covers the step between one run and the next.
/// </summary>
/// <remarks>
/// The property worth holding onto is that what comes out of here goes straight back in: a draft that
/// the declarations parser then refuses would turn a loop into a two-step dance where every remedy has
/// to be checked by hand, which is the thing the remedies exist to avoid. So most of these end by
/// parsing what was produced.
/// </remarks>
public sealed class NextDeclarationsTests
{
    /// <summary>
    /// The whole point in one test: a stop the tool can answer is answered, without being asked.
    /// </summary>
    [Fact]
    public void AStopTheToolCanAnswerIsWrittenInWithoutBeingAsked()
    {
        var draft = NextDeclarations.From([Stopped(Declaring.Budget("steps", 750_000))]);

        Assert.Equal(["budgets.steps"], draft.Applied);
        Assert.Empty(draft.Wanted);
        Assert.Empty(draft.Flags);
        var declared = RunDeclarations.Parse(draft.Json, "next");
        Assert.Equal(10_000_000, declared.Budgets.Steps);
    }

    /// <summary>
    /// A stop that needs an answer is not guessed at. It comes back named, with the kind of value it
    /// wants, and nothing is written for it.
    /// </summary>
    [Fact]
    public void AStopThatNeedsAnAnswerIsHandedBackRatherThanGuessedAt()
    {
        var draft = NextDeclarations.From([Stopped(Declaring.Fact("wmi:Win32_DiskDrive.SerialNumber"))]);

        var wanted = Assert.Single(draft.Wanted);
        Assert.Equal("facts", wanted.Section);
        Assert.Equal("wmi:Win32_DiskDrive.SerialNumber", wanted.Name);
        Assert.Empty(draft.Applied);
        Assert.DoesNotContain("wmi:", draft.Json, StringComparison.Ordinal);
    }

    /// <summary>
    /// Supplied, the same stop is written in — and the answer lands where the remedy left the gap
    /// rather than replacing the shape around it.
    /// </summary>
    [Fact]
    public void AnAnswerGoesWhereTheRemedyLeftTheGap()
    {
        const string call = "System.String Vendor.Support.Licence::Check()";

        var draft = NextDeclarations.From(
            [Stopped(Declaring.Call(call, returnsSomething: true, "System.String"))],
            new Dictionary<string, JsonNode?> { [call] = JsonValue.Create("MIT-9931") });

        Assert.Empty(draft.Wanted);
        Assert.Equal(["--allow-declared-calls"], draft.Flags);
        var declared = RunDeclarations.Parse(draft.Json, "next").Allowing(calls: true);
        Assert.True(declared.TryAnswerCall(call, out var answered));
        Assert.False(answered.Inert);
    }

    /// <summary>
    /// A call that hands nothing back needs no answer, so it is written in whole — but it still needs
    /// the switch, because declaring what somebody else's code does is a decision either way.
    /// </summary>
    [Fact]
    public void ACallThatNeedsNoAnswerIsStillOnlyUsedWithTheSwitch()
    {
        const string call = "System.Void System.Threading.Thread::set_IsBackground(System.Boolean)";

        var draft = NextDeclarations.From(
            [Stopped(Declaring.Call(call, returnsSomething: false))]);

        Assert.Equal([$"calls.{call}"], draft.Applied);
        Assert.Equal(["--allow-declared-calls"], draft.Flags);
        var declared = RunDeclarations.Parse(draft.Json, "next").Allowing(calls: true);
        Assert.True(declared.TryAnswerCall(call, out var answered));
        Assert.True(answered.Inert);
    }

    /// <summary>
    /// A loop accumulates. What was declared last time is still declared this time, or every round
    /// would undo the one before it.
    /// </summary>
    [Fact]
    public void WhatWasAlreadyDeclaredSurvivesTheNextRound()
    {
        var first = NextDeclarations.From(
            [Stopped(Declaring.Fact("env:MachineName"))],
            new Dictionary<string, JsonNode?> { ["env:MachineName"] = JsonValue.Create("DESKTOP-7QK2") },
            name: "ptnifif");

        var second = NextDeclarations.From(
            [Stopped(Declaring.Budget("steps", 750_000))],
            from: first.Json);

        var declared = RunDeclarations.Parse(second.Json, "next");
        Assert.Equal("ptnifif", declared.Name);
        Assert.Equal(10_000_000, declared.Budgets.Steps);
        Assert.True(declared.Facts.TryAnswer("env:MachineName", out var answer));
        Assert.Equal("DESKTOP-7QK2", answer.Text);
    }

    /// <summary>
    /// Something the caller knew before being asked is written in anyway. A run reports the first stop
    /// on a path and no further, so the fact that closes the second one will not be asked for until the
    /// first is out of the way — and a caller that has both should not need two rounds to say so.
    /// </summary>
    [Fact]
    public void SomethingKnownBeforeItWasAskedForIsWrittenInAnyway()
    {
        var draft = NextDeclarations.From(
            [],
            new Dictionary<string, JsonNode?>
            {
                ["env:UserName"] = JsonValue.Create("aled"),
                ["System.Boolean Vendor.Guard::Ok()"] = JsonValue.Create(true)
            });

        var declared = RunDeclarations.Parse(draft.Json, "next").Allowing(calls: true);
        Assert.True(declared.Facts.TryAnswer("env:UserName", out _));
        Assert.True(declared.TryAnswerCall("System.Boolean Vendor.Guard::Ok()", out _));
        Assert.Equal(["--allow-declared-calls"], draft.Flags);
    }

    /// <summary>
    /// A stop no declaration closes is reported as such rather than being left out, because a caller
    /// looping until the file stops growing needs to know the difference between "nothing more to say"
    /// and "nothing more that saying anything will fix".
    /// </summary>
    [Fact]
    public void AStopNoFileWillCloseIsSaidToBeOne()
    {
        var draft = NextDeclarations.From(
        [
            new Blocker(
                BlockerKind.UnsupportedInstruction, "arglist", "It does not run arglist.",
                null, null, "method-bodies", 1)
        ]);

        var beyond = Assert.Single(draft.Beyond);
        Assert.Equal("arglist", beyond.Key);
        Assert.Empty(draft.Applied);
        Assert.Empty(draft.Wanted);
    }

    private static Blocker Stopped(Remedy remedy) => new(
        remedy.Section switch
        {
            "facts" => BlockerKind.UnstatedFact,
            "budgets" => BlockerKind.Budget,
            _ => BlockerKind.UnmodeledCall
        },
        remedy.Name,
        "for the test",
        remedy,
        null,
        "string-table-recovery",
        1);
}
