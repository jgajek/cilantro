using Cilantro.Core.Pipeline;
using Cilantro.Core.Recovery;

namespace Cilantro.Tests;

public sealed class DependencyDeploymentEmissionTests
{
    [Theory]
    [InlineData("new")]
    [InlineData("identical")]
    [InlineData("conflict")]
    [InlineData("host-conflict")]
    public void PublicationPreflightsAllTargetsAndPreservesConflictingFiles(string mode)
    {
        using var context = SyntheticContext.Build(_ => { });
        context.SetFact<IReadOnlyList<BabelDependencyDeploymentPass.Dependency>>(BabelDependencyDeploymentPass.Fact,
            [new("First.dll", [1, 2, 3]), new("Second.dll", [4, 5, 6])]);
        var directory = Directory.CreateTempSubdirectory("Cilantro.DependencyDeployment.").FullName;
        try
        {
            var second = Path.Combine(directory, "Second.dll");
            if (mode == "identical") File.WriteAllBytes(second, [4, 5, 6]);
            if (mode == "conflict") File.WriteAllBytes(second, [9]);
            var output = Path.Combine(directory, mode == "host-conflict" ? "First.dll" : "Host.dll");
            var expected = mode is "new" or "identical";
            Assert.Equal(expected, DependencyDeploymentEmission.TryWrite(context, output, out _, out _, validateOnly: true));
            Assert.False(File.Exists(Path.Combine(directory, "First.dll")));
            Assert.Equal(expected, DependencyDeploymentEmission.TryWrite(context, output, out var paths, out _));
            if (expected)
            {
                Assert.Equal(2, paths.Count); Assert.Equal(new byte[] { 1, 2, 3 }, File.ReadAllBytes(paths[0]));
                Assert.Equal(new byte[] { 4, 5, 6 }, File.ReadAllBytes(paths[1]));
            }
            else
            {
                Assert.Empty(paths); Assert.False(File.Exists(Path.Combine(directory, "First.dll")));
                if (mode == "conflict") Assert.Equal(new byte[] { 9 }, File.ReadAllBytes(second));
            }
        }
        finally { Directory.Delete(directory, true); }
    }
}
