using Cilantro.Core;

namespace Cilantro.Tests;

/// <summary>
/// Holds the cleaned copies to what ECMA-335 says, by comparison with the protected input.
/// </summary>
/// <remarks>
/// Reactor's output does not verify. Every sample here carries findings before CILantro touches it —
/// between 186 and 377 of them — so "the cleaned copy verifies" is not a claim this tool could make
/// about anything, and a gate that asked for it would be a gate nobody could pass. What a run can be
/// held to is the comparison: a method the protector left verifiable is still verifiable afterwards,
/// and the count of findings goes down rather than up.
///
/// The numbers are pinned exactly rather than as ceilings, so that an improvement fails here too and
/// has to be written down. That is the point of them: three separate defect classes reached the
/// emitted files of this corpus while every other gate in the suite stayed green, and each one was
/// found by reading these differences rather than by any test.
/// </remarks>
public sealed class IlVerificationTests
{
    /// <summary>
    /// What the verifier is expected to say about one sample.
    /// </summary>
    /// <param name="Sample">The protected file, as it sits in the samples directory.</param>
    /// <param name="Was">Findings the verifier reads in the protected input.</param>
    /// <param name="Is">Findings it reads in the cleaned output.</param>
    /// <param name="Broken">
    /// Methods with findings in the output that had none in the input. Every one of these is either
    /// a method the verifier could not read from the input at all, or a defect.
    /// </param>
    /// <param name="Worsened">Methods with more findings in the output than in the input.</param>
    /// <param name="Unreadable">
    /// Of the broken, how many the verifier could not read from the input. There is no before to
    /// compare those with, and a run that turns a body the importer refused into one it can read has
    /// improved the file whatever the reading says.
    /// </param>
    public sealed record Expected(
        string Sample,
        int Was,
        int Is,
        int Broken,
        int Worsened,
        int Unreadable);

    public static TheoryData<Expected> Samples =>
    [
        // The virtualized payload, and the only one with anything left. What is new is an
        // ExpectedArray on a method the verifier could not import from the protected input, and one
        // method that reports two findings where the input reported one: Reactor passes an
        // object-typed field to File::WriteAllBytes and to Assembly::LoadFile, both of which want a
        // string. The input does the same thing through an adapter that also declares String, so it
        // was equally unverifiable there; it went unreported because ILVerify abandons a block at
        // its first error, and the block it abandoned is the one this run fixed.
        new Expected("Mlfhntkcvb.payload.Lqcuzgc.dll", Was: 377, Is: 277, Broken: 1, Worsened: 1,
            Unreadable: 1),

        // The three non-virtualized Reactor 6 builds come out clean, which is worth stating plainly:
        // every finding the protector left is gone and none replaced it.
        new Expected("Reason.PAC.dll", Was: 202, Is: 0, Broken: 0, Worsened: 0, Unreadable: 0),
        new Expected("rsServiceController.dll", Was: 186, Is: 0, Broken: 0, Worsened: 0,
            Unreadable: 0),
        new Expected("rsDatabase.protected.dll", Was: 205, Is: 0, Broken: 0, Worsened: 0,
            Unreadable: 0),
    ];

    [SampleTheory]
    [MemberData(nameof(Samples))]
    [Trait(Cost.Key, Cost.High)]
    public void TheCleanedCopyBreaksNothingTheProtectorLeftVerifiable(Expected expected)
    {
        var sample = Checkout.Sample(expected.Sample);
        var stem = Path.GetFileNameWithoutExtension(expected.Sample);
        var outputDirectory = Path.Combine(
            Path.GetTempPath(),
            $"Cilantro.IlVerificationTests.{Guid.NewGuid():N}");
        var outputPath = Path.Combine(outputDirectory, $"{stem}.cleaned.dll");
        try
        {
            // A default run, which is what an analyst gets and therefore what is worth measuring.
            // Names are left as they are so that the two readings name the same methods.
            var result = new CilantroPipeline().Run(sample, new PipelineOptions(
                PreserveTokens: true,
                RenameSymbols: false,
                OutputPath: outputPath,
                ReportDirectory: outputDirectory));

            Assert.True(result.Success);
            Assert.NotNull(result.OutputPath);

            var libraries = Path.Combine(Checkout.Samples, "libraries");
            var difference = IlVerification.Against(
                IlVerification.Read(sample, libraries),
                IlVerification.Read(result.OutputPath, libraries));

            Assert.Equal(
                (expected.Was, expected.Is, expected.Broken, expected.Worsened),
                (difference.Was.Count, difference.Is.Count, difference.Broken.Count,
                    difference.Worsened.Count));
            Assert.Equal(
                expected.Unreadable,
                difference.BrokenButUnreadableBefore.Count);

            // Two classes that reached emitted files while every other gate stayed green, named here
            // so that their return is a failure with their own name on it rather than a count that
            // moved. BackwardBranch is a stack a forward scan cannot name, which is what a dispatcher
            // rewrite leaves when the state stays on the back edge; PathStackDepth is two paths
            // meeting at a depth they disagree on, which is what a truncated short branch produced.
            Assert.DoesNotContain("BackwardBranch", difference.Is.Codes);
            Assert.DoesNotContain("PathStackDepth", difference.Is.Codes);
        }
        finally
        {
            if (Directory.Exists(outputDirectory))
                Directory.Delete(outputDirectory, recursive: true);
        }
    }
}
