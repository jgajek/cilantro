using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;

namespace Cilantro.Tests;

public sealed class BabelLegacyCheckTests
{
    [BabelCorpusFact]
    public void ReviewedLegacyChecksAreRemovedButChangedImportsAreRefused()
    {
        var root = Environment.GetEnvironmentVariable("CILANTRO_BABEL_SAMPLES")!;
        var directory = Directory.CreateTempSubdirectory("Cilantro.BabelLegacyChecks.").FullName;
        try
        {
            foreach (var (name, sites) in new[] { ("Zebekeadu.dll", 1), ("pin_mxi_decoded_stage.exe", 2) })
            {
                using (var context = ArtifactContext.Load(Path.Combine(root, name)))
                {
                    new BabelDetectionPass().Run(context);
                    var result = new BabelCheckPass().Run(context);
                    Assert.True(result.Status == PassStatus.Success, string.Join("; ", result.Diagnostics));
                    Assert.Equal(sites, result.Changes);
                }
                var path = Path.Combine(directory, name);
                using (var module = ModuleDefMD.Load(Path.Combine(root, name)))
                {
                    var check = BabelCheckShape.Find(module).Single(check => check.Kind == "debugging");
                    check.Graph.Types.SelectMany(type => type.Methods).First(method => method.IsPinvokeImpl).ImplMap.Name = "UnreviewedNativeProbe";
                    module.Write(path);
                }
                using (var context = ArtifactContext.Load(path))
                {
                    new BabelDetectionPass().Run(context);
                    var snapshots = context.Module.GetTypes().SelectMany(type => type.Methods).Where(method => method.HasBody).ToDictionary(method => method, MethodBodySnapshot.Capture);
                    var result = new BabelCheckPass().Run(context);
                    Assert.Equal(PassStatus.Unsupported, result.Status);
                    Assert.Equal(0, result.Changes);
                    Assert.All(snapshots, item => Assert.True(item.Value.StructurallyEquals(item.Key)));
                    Assert.Empty(context.Changes);
                }
            }
        }
        finally { Directory.Delete(directory, true); }
    }
}
