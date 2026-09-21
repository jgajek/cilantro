using System.Security.Cryptography;
using dnlib.DotNet;
using Cilantro.Core;

namespace Cilantro.Tests;

public sealed class EmbeddedAssemblyRecoveryTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void NativeContinuationUsesManagedRecoveryAndHonorsTheOutputDestination(bool success)
    {
        using var fixture = new Fixture();
        var child = fixture.File("managed.dll", "managed");
        var payload = fixture.File("payload.dll", "payload");
        var root = fixture.Root with
        {
            Report = fixture.Root.Report with { Protector = "reactor-bootstrap" },
            ExtractedPayloadPaths = [child]
        };
        var output = Path.Combine(fixture.DirectoryPath, "requested.dll");
        var calls = 0;
        var result = EmbeddedAssemblyRecovery.Run(root,
            new PipelineOptions(OutputPath: output, Strict: true, Devirtualize: false, LibraryPaths: ["declared-library.dll"]), (path, actual) =>
            {
                calls++;
                Assert.Equal(child, path);
                Assert.Equal(output, actual.OutputPath);
                Assert.True(actual.Strict);
                Assert.False(actual.Devirtualizes);
                Assert.Equal(["declared-library.dll"], actual.LibraryPaths);
                return fixture.Result(path) with { Success = success, ExtractedPayloadPaths = [payload] };
            }, nativeOnly: true);
        Assert.Equal(1, calls);
        Assert.Equal(success, result.Success);
        Assert.Equal(success, result.EmbeddedRecovery!.Complete);
        Assert.Equal("managed", System.IO.File.ReadAllText(child));
        Assert.Equal(root.Report.InputPath, result.Report.InputPath);
        Assert.Equal(2, result.EmbeddedRecovery.Nodes.Count);
        Assert.Equal(success ? "recovered" : "incomplete", result.EmbeddedRecovery.Nodes[1].Status);
    }

    [Fact]
    public void NativeOutputCannotOverwriteTheWrapperOrRawManagedStage()
    {
        using var fixture = new Fixture();
        var child = fixture.File("child.dll", "protected");
        var root = fixture.Root with
        {
            Report = fixture.Root.Report with { Protector = "reactor-bootstrap" },
            ExtractedPayloadPaths = [child]
        };
        foreach (var output in new[] { child, root.Report.InputPath })
        {
            var result = EmbeddedAssemblyRecovery.Run(root, new(OutputPath: output),
                (_, _) => throw new InvalidOperationException("Must not run"), nativeOnly: true);
            Assert.False(result.Success);
            Assert.Equal("failed", result.EmbeddedRecovery!.Nodes[1].Status);
            Assert.Contains("must not overwrite", result.EmbeddedRecovery.Nodes[1].Diagnostic!, StringComparison.Ordinal);
            Assert.Equal("protected", System.IO.File.ReadAllText(child));
        }
    }

    [Fact]
    public void NativeContinuationStillUsesTheSharedTraversalLimits()
    {
        using var fixture = new Fixture();
        var root = fixture.Root with
        {
            Report = fixture.Root.Report with { Protector = "reactor-bootstrap" },
            ExtractedPayloadPaths = [fixture.File("native1", "1")]
        };
        var count = 1;
        var result = EmbeddedAssemblyRecovery.Run(root, new(), (path, _) =>
        {
            count++;
            return fixture.Result(path) with
            {
                Report = fixture.Result(path).Report with { Protector = "reactor-bootstrap" },
                ExtractedPayloadPaths = [fixture.File("native" + count, count.ToString(System.Globalization.CultureInfo.InvariantCulture))]
            };
        }, nativeOnly: true);
        Assert.False(result.Success);
        Assert.Equal("limited", result.EmbeddedRecovery!.Nodes[^1].Status);
        Assert.Equal(EmbeddedAssemblyRecovery.MaximumDepth + 1, result.EmbeddedRecovery.Nodes[^1].Depth);
    }

    [Fact]
    public void DeduplicatesByContentAndRecordsCyclesWithoutRepeatingWork()
    {
        using var fixture = new Fixture();
        var child = fixture.File("child", "child");
        var duplicate = fixture.File("duplicate", "child");
        var root = fixture.Root with { ExtractedPayloadPaths = [child, duplicate] };
        var calls = 0;
        var result = EmbeddedAssemblyRecovery.Run(root, new(), (path, _) =>
        {
            calls++;
            return fixture.Result(path) with { ExtractedPayloadPaths = [root.Report.InputPath] };
        });
        Assert.Equal(1, calls);
        Assert.Equal(2, result.EmbeddedRecovery!.Nodes.Count);
        Assert.Equal(3, result.EmbeddedRecovery.Links.Count);
        Assert.Equal(0, result.EmbeddedRecovery.Links[^1].Child);
        Assert.True(result.Success);
    }

    [Fact]
    public void DescendantsOfAnIncompleteStageAreStillRecovered()
    {
        using var fixture = new Fixture();
        var child = fixture.File("child", "child");
        var grandchild = fixture.File("grandchild", "grandchild");
        var root = fixture.Root with { ExtractedPayloadPaths = [child] };
        var result = EmbeddedAssemblyRecovery.Run(root, new(), (path, _) =>
            fixture.Result(path) with { Success = path != child, ExtractedPayloadPaths = path == child ? [grandchild] : [] });
        Assert.False(result.Success);
        Assert.Equal(3, result.EmbeddedRecovery!.Nodes.Count);
        Assert.Equal("recovered", result.EmbeddedRecovery.Nodes[2].Status);
        Assert.NotNull(result.EmbeddedRecovery.Nodes[1].Run);
    }

    [Fact]
    public void DepthAndArtifactLimitsProduceExplicitIncompleteResults()
    {
        using var fixture = new Fixture();
        var root = fixture.Root with { ExtractedPayloadPaths = [fixture.File("child1", "1")] };
        var count = 1;
        var result = EmbeddedAssemblyRecovery.Run(root, new(), (path, _) =>
        {
            count++;
            return fixture.Result(path) with { ExtractedPayloadPaths = [fixture.File("child" + count, count.ToString(System.Globalization.CultureInfo.InvariantCulture))] };
        });
        Assert.False(result.Success);
        Assert.Equal("limited", result.EmbeddedRecovery!.Nodes[^1].Status);
        Assert.Equal(EmbeddedAssemblyRecovery.MaximumDepth + 1, result.EmbeddedRecovery.Nodes[^1].Depth);

        var many = Enumerable.Range(0, 40).Select(i => fixture.File("many" + i, "many" + i)).ToArray();
        var invoked = 0;
        result = EmbeddedAssemblyRecovery.Run(root with { ExtractedPayloadPaths = many }, new(), (path, _) =>
        {
            invoked++;
            return fixture.Result(path);
        });
        Assert.Equal(EmbeddedAssemblyRecovery.MaximumArtifacts - 1, invoked);
        Assert.False(result.Success);
    }

    [Fact]
    public void PreservesRequestedRecoverySettingsAndIsolatesChildOutputs()
    {
        using var fixture = new Fixture();
        var child = fixture.File("child.dll", "child");
        var root = fixture.Root with { ExtractedPayloadPaths = [child] };
        var options = new PipelineOptions(GenericRecovery: true, Strict: true, AnalyzeOnly: true,
            RecoverEmbeddedAssemblies: true, StatusPath: "root.status", OutputPath: "root.cleaned");
        var result = EmbeddedAssemblyRecovery.Run(root, options, (path, actual) =>
        {
            Assert.True(actual.GenericRecovery);
            Assert.True(actual.Strict);
            Assert.True(actual.AnalyzeOnly);
            Assert.False(actual.RecoverEmbeddedAssemblies);
            Assert.Null(actual.StatusPath);
            Assert.NotEqual(options.OutputPath, actual.OutputPath);
            Assert.Contains(Hash(path), actual.ReportDirectory!, StringComparison.Ordinal);
            return fixture.Result(path);
        });
        Assert.True(File.Exists(result.EmbeddedRecoveryReportPath));
        Assert.Equal(result.EmbeddedRecoveryReportPath, RunManifest.Of(result).Wrote.Embedded);
    }

    [Fact]
    public void FailedChildDoesNotPreventItsSiblingFromBeingRecovered()
    {
        using var fixture = new Fixture();
        var bad = fixture.File("bad", "bad");
        var good = fixture.File("good", "good");
        var result = EmbeddedAssemblyRecovery.Run(fixture.Root with { ExtractedPayloadPaths = [bad, good] }, new(), (path, _) =>
            path == bad ? throw new BadImageFormatException("Invalid child") : fixture.Result(path));
        Assert.False(result.Success);
        Assert.Equal("failed", result.EmbeddedRecovery!.Nodes[1].Status);
        Assert.Equal("recovered", result.EmbeddedRecovery.Nodes[2].Status);
    }

    [Fact]
    public void ByteBudgetStopsBeforeRunningAnotherChild()
    {
        using var fixture = new Fixture();
        var child = fixture.File("child", "child");
        var root = fixture.Root with
        {
            ExtractedPayloadPaths = [child],
            Report = fixture.Root.Report with { InputLength = EmbeddedAssemblyRecovery.MaximumInputBytes }
        };
        var result = EmbeddedAssemblyRecovery.Run(root, new(), (_, _) => throw new InvalidOperationException("Must not run"));
        Assert.False(result.Success);
        var limited = result.EmbeddedRecovery!.Nodes[1];
        Assert.Equal("limited", limited.Status);
        Assert.Contains("byte limit", limited.Diagnostic!, StringComparison.Ordinal);
    }

    [Fact]
    public void CancellationIsNotReportedAsAChildFailure()
    {
        using var fixture = new Fixture();
        var child = fixture.File("child", "child");
        Assert.Throws<OperationCanceledException>(() => EmbeddedAssemblyRecovery.Run(
            fixture.Root with { ExtractedPayloadPaths = [child] }, new(), (_, _) => throw new OperationCanceledException()));
    }

    private static string Hash(string path) => Convert.ToHexStringLower(SHA256.HashData(System.IO.File.ReadAllBytes(path)));

    private sealed class Fixture : IDisposable
    {
        public string DirectoryPath { get; } = Directory.CreateTempSubdirectory("Cilantro.Children").FullName;
        public PipelineResult Root { get; }
        public Fixture()
        {
            using var module = new ModuleDefUser("root.dll") { Kind = ModuleKind.Dll };
            var assembly = new AssemblyDefUser("root", new Version(1, 0));
            assembly.Modules.Add(module);
            var input = Path.Combine(DirectoryPath, "root.dll");
            module.Write(input);
            Root = new CilantroPipeline([]).Run(input, new PipelineOptions(AnalyzeOnly: true, ReportDirectory: DirectoryPath));
        }
        public string File(string name, string text)
        {
            var path = Path.Combine(DirectoryPath, name);
            System.IO.File.WriteAllText(path, text);
            return path;
        }
        public PipelineResult Result(string path) => Root with
        {
            ExtractedPayloadPaths = [], Report = Root.Report with { InputPath = path, InputSha256 = Hash(path) }
        };
        public void Dispose() => Directory.Delete(DirectoryPath, true);
    }
}
