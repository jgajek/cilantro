using Cilantro.Core.Payload;

namespace Cilantro.Tests;

public sealed class ManagedImageTests
{
    [Fact]
    public void BytesTooShortToBeAnImageAreDeclinedRatherThanThrownOn()
    {
        var truncated = new byte[48];
        truncated[0] = (byte)'M';
        truncated[1] = (byte)'Z';

        var read = PayloadStageValidator.TryValidateManaged(truncated, out var payload);

        Assert.False(read);
        Assert.Null(payload);
    }

    [Fact]
    public void BytesThatBeginLikeAnImageAndThenStopAreDeclinedRatherThanThrownOn()
    {
        // A DOS header the reader can get through, followed by nothing it can use: the shape a
        // wrongly keyed resource takes when it happens to inflate.
        var partial = new byte[512];
        partial[0] = (byte)'M';
        partial[1] = (byte)'Z';
        partial[0x3C] = 0x80;
        partial[0x80] = (byte)'P';
        partial[0x81] = (byte)'E';

        var read = PayloadStageValidator.TryValidateManaged(partial, out var payload);

        Assert.False(read);
        Assert.Null(payload);
    }
}
