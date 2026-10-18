using Cilantro.Core.Interpretation;

namespace Cilantro.Tests;

public sealed class FrameworkReflectionCacheTests
{
    [Fact]
    public void ConcurrentInterpretationsCanPublishPositiveAndNegativeFrameworkLookups()
    {
        Parallel.For(0, 4096, index =>
        {
            Assert.Null(LoaderFrameworkIntrinsic.WellKnown("Microsoft.CilantroMissingType" + index, null));
            Assert.Equal(typeof(System.Reflection.ConstructorInfo),
                LoaderFrameworkIntrinsic.WellKnown("System.Reflection.ConstructorInfo", null));
            Assert.Equal(typeof(Dictionary<string, long>),
                LoaderFrameworkIntrinsic.WellKnown("System.Collections.Generic.Dictionary`2<System.String,System.Int64>", null));
        });
    }
}
