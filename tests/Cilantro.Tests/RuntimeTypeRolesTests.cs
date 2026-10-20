using Cilantro.Core.Analysis;

namespace Cilantro.Tests;

public sealed class RuntimeTypeRolesTests
{
    [Theory]
    [InlineData("System.IO.Stream a[]", "System.IO.Stream $type0[]")]
    [InlineData("System.Collections.Hashtable", "System.Collections.Hashtable")]
    [InlineData("Namespace.a", "Namespace.a")]
    [InlineData("aa a a/b", "aa $type0 $type1")]
    [InlineData("System.Collections.Generic.List`1<a>", "System.Collections.Generic.List`1<$type0>")]
    [InlineData("a&,a*,a[,,]", "$type0&,$type0*,$type0[,,]")]
    [InlineData("e a", "$type2 $type0")]
    public void ShortNamesCannotRewriteFrameworkNamesOrPreviouslyInsertedRoles(string text, string expected)
    {
        Assert.Equal(expected, RuntimeTypeRoles.Replace(text, [("a", "$type0"), ("a/b", "$type1"), ("e", "$type2")]));
    }

    [Fact]
    public void SourceNamesThatLookLikeRoleMarkersDoNotRewriteInsertedMarkers()
    {
        Assert.Equal("$type0[] $type1[]", RuntimeTypeRoles.Replace("a[] $type0[]", [("a", "$type0"), ("$type0", "$type1")]));
    }
}
