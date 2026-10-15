using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class RecoveredResourceOriginTests
{
    [Fact]
    public void OriginRequiresBothExactNameAndContent()
    {
        var origin = RecoveredResourceOrigin.Capture(Resource("table", [1, 2, 3]));
        Assert.True(origin.Matches(Resource("table", [1, 2, 3])));
        Assert.False(origin.Matches(Resource("other", [1, 2, 3])));
        Assert.False(origin.Matches(Resource("table", [1, 2, 4])));
    }

    [Fact]
    public void MergingLoaderKeysPreservesTheActualResourceOrigin()
    {
        using var context = SyntheticContext.Build(_ => { });
        context.SetFact<IReadOnlyDictionary<uint, int>>("bootstrap.integerFields", new Dictionary<uint, int> { [1] = 42 });
        var origin = RecoveredResourceOrigin.Capture(Resource("table", [1, 2, 3]));
        var table = new CapturedStringTable("initializer", [], [], new Dictionary<uint, int>(), origin);
        var merged = StringTableRecoveryPass.MergeLoaderKeys(context, table);
        Assert.Equal(42, merged.IntegerFields[1]);
        Assert.Equal(origin, merged.Resource);
    }

    private static EmbeddedResource Resource(string name, byte[] bytes) => new(name, bytes, ManifestResourceAttributes.Private);
}
