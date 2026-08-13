using System.Reflection;
using ReactorUnpack.Core;

namespace ReactorUnpack.Tests;

/// <summary>
/// Covers what a download says about itself.
/// </summary>
public sealed class ReleaseMetadataTests
{
    /// <summary>
    /// The version in the file's properties and the version the tool prints are set in two different
    /// places, so they can drift. A binary whose properties read one number while it reports another
    /// makes every bug report about it ambiguous, which is worth a test on its own.
    /// </summary>
    [Fact]
    public void TheBuildStampsTheVersionTheToolReports()
    {
        var stamped = typeof(ReactorPipeline).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>();

        Assert.NotNull(stamped);
        // A deterministic build appends +<commit> to the informational version; the number is what
        // has to match.
        Assert.Equal(
            ReactorPipeline.Version,
            stamped.InformationalVersion.Split('+')[0]);
    }
}
