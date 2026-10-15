using Cilantro.Core.Interpretation;

namespace Cilantro.Tests;

public sealed class LoaderTraceScopeTests
{
    [Fact]
    public void OverflowRecordsEveryDroppedKindWithoutChangingEarlierSnapshots()
    {
        var recorder = new LoaderEvidenceRecorder();
        for (var i = 0; i < 4097; i++) recorder.Observe(LoaderObservationKind.DebuggerProbe, "probe", false);
        var first = recorder.Snapshot();
        Assert.True(first.ObservationsTruncated);
        Assert.False(first.HasCompleteObservations(LoaderObservationKind.DebuggerProbe));
        Assert.True(first.HasCompleteObservations(LoaderObservationKind.ManagedResourceRead));
        recorder.Observe(LoaderObservationKind.ManagedResourceRead, "resource");
        var second = recorder.Snapshot();
        Assert.False(second.HasCompleteObservations(LoaderObservationKind.ManagedResourceRead));
        Assert.True(first.HasCompleteObservations(LoaderObservationKind.ManagedResourceRead));
        Assert.False(first.Agrees(second));
        Assert.Equal(4096, second.Observations.Count);
    }

    [Fact]
    public void LegacyTruncationWithoutKindEvidenceCannotAuthorizeAResourceProof()
    {
        var legacy = LoaderInterpretationEvidence.Empty with { ObservationsTruncated = true };
        Assert.False(legacy.HasCompleteObservations(LoaderObservationKind.ManagedResourceRead));
        var known = legacy with { TruncatedObservationKinds = [LoaderObservationKind.DebuggerProbe] };
        Assert.False(legacy.Agrees(known));
        Assert.True(known.Agrees(known with { TruncatedObservationKinds = [LoaderObservationKind.DebuggerProbe] }));
    }
}
