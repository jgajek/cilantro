using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;

namespace Cilantro.Tests;

/// <summary>
/// Covers putting a read-back body into the assembly the analyst opens: that it lands in the
/// method, that it says what it is, that cleanup keeps it, and that the identity gate was told.
/// </summary>
/// <remarks>
/// This is the one thing the tool writes into a cleaned copy that it cannot prove, so what is
/// tested here is mostly the labelling and the accounting rather than the code that was built.
/// Whether the body is right is a question for the run check and for the corpus, neither of which
/// a synthetic program can stand in for.
/// </remarks>
public sealed class VirtualizationRebuildTests
{
    private const int Push = 1;
    private const int Store = 2;
    private const int Return = 9;

    [Fact]
    public void TheBodyGoesIntoTheMethodAndSaysWhereItCameFrom()
    {
        using var sample = new Sample();
        sample.Context.SetFact("options.devirtualize", true);
        Declare(sample.Context);

        var result = new VirtualizationRebuildPass().Run(sample.Context);

        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(1, result.Changes);
        var stub = Stub(sample.Context);
        Assert.True(stub.Body.Instructions.Count > 1);
        var marker = Assert.Single(stub.CustomAttributes);
        Assert.Equal("Cilantro.RebuiltFromReadingAttribute", marker.TypeFullName);
        Assert.Contains(
            "not the original code",
            marker.ConstructorArguments[0].Value.ToString(),
            StringComparison.Ordinal);
        Assert.Contains(
            sample.Context.Module.GetTypes(),
            type => type.Name == "RebuiltFromReadingAttribute" && !type.IsPublic);
    }

    /// <summary>
    /// The marker is a declaration the input did not have, so the gate has to be told about it in
    /// the same terms it is told about a deletion, or the run's own addition fails verification.
    /// </summary>
    [Fact]
    public void TheDeclarationsItAddedAreDeclaredToTheGate()
    {
        using var sample = new Sample();
        sample.Context.SetFact("options.devirtualize", true);
        Declare(sample.Context);

        new VirtualizationRebuildPass().Run(sample.Context);

        var undeclared = AssemblyVerifier.Verify(
            sample.Context.Module,
            sample.Context.OriginalIdentity,
            sample.Context.OriginalStructure);
        Assert.False(undeclared.Passed);

        var declared = AssemblyVerifier.Verify(
            sample.Context.Module,
            sample.Context.OriginalIdentity,
            sample.Context.OriginalStructure,
            CilantroPipeline.BuildRewriteAllowance(sample.Context));
        Assert.True(declared.Passed, string.Join("; ", declared.Diagnostics));
    }

    [Fact]
    public void ARunToldNotToBuildLeavesTheStubAsItShipped()
    {
        using var sample = new Sample();
        Declare(sample.Context);

        var result = new VirtualizationRebuildPass().Run(sample.Context);

        Assert.Equal(0, result.Changes);
        Assert.Single(Stub(sample.Context).Body.Instructions);
        Assert.Empty(Stub(sample.Context).CustomAttributes);
        Assert.Contains("left as stubs", string.Join(" ", result.Diagnostics), StringComparison.Ordinal);
    }

    /// <summary>
    /// A virtualized method is one nothing in the module calls by name, so the reading that goes
    /// into it would be deleted by the pass that removes what recovery orphaned — along with the
    /// helpers its code calls, which would leave the body naming things that are gone.
    /// </summary>
    [Fact]
    public void CleanupKeepsAMethodTheRunBuiltAndWhatItsBodyCalls()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            // Externally visible so the type survives on its own account, which leaves the
            // question this test asks to be about its methods.
            host.Attributes = TypeAttributes.Public | TypeAttributes.Class;
            host.Methods.Add(Empty(module, "Helper"));
            host.Methods.Add(Empty(module, "AlsoOrphaned"));
            var built = Empty(module, "WasVirtualized");
            built.Body.Instructions.Insert(
                0, OpCodes.Call.ToInstruction(host.Methods.Single(method => method.Name == "Helper")));
            host.Methods.Add(built);
        });
        context.SetFact("options.removeRuntime", true);
        foreach (var name in new[] { "Helper", "AlsoOrphaned", "WasVirtualized" })
            RecoveryOrphans.Declare(context, Find(context, name));
        context.SetFact<IReadOnlySet<uint>>(
            VirtualizationRebuildPass.RebuiltFact,
            new HashSet<uint> { Find(context, "WasVirtualized").MDToken.Raw });

        new RuntimeCleanupPass().Run(context);

        var host = context.Module.GetTypes().Single(type => type.Name == "Host");
        Assert.Contains(host.Methods, method => method.Name == "WasVirtualized");
        Assert.Contains(host.Methods, method => method.Name == "Helper");
        // Nothing else changed: an orphan the built body does not need still goes.
        Assert.DoesNotContain(host.Methods, method => method.Name == "AlsoOrphaned");
    }

    private static MethodDef Stub(ArtifactContext context) => context.Module.Types
        .SelectMany(type => type.Methods)
        .First(method => method.Name == "Stub");

    private static MethodDef Find(ArtifactContext context, string name) => context.Module.GetTypes()
        .SelectMany(type => type.Methods)
        .Single(method => method.Name == name);

    private static MethodDefUser Empty(ModuleDef module, string name)
    {
        var method = new MethodDefUser(name, MethodSig.CreateStatic(module.CorLibTypes.Void))
        {
            Attributes = MethodAttributes.Assembly | MethodAttributes.Static,
            Body = new CilBody()
        };
        method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        return method;
    }

    /// <summary>Stands in for the pass that reads the engine, with a program of three operations.</summary>
    private static void Declare(ArtifactContext context)
    {
        var stub = Stub(context);
        var operations = new (int Opcode, VirtualOperand Operand)[]
        {
            (Push, new VirtualOperand.Number(7)),
            (Store, new VirtualOperand.Number(0)),
            (Return, new VirtualOperand.None())
        };
        var program = new VirtualProgram(
            new VirtualizedMethod(stub, stub, 0, 0),
            "Synthetic.Instruction",
            [
                .. operations.Select((operation, index) =>
                    new VirtualInstruction(index, operation.Opcode, operation.Operand))
            ])
        {
            Operations = new Dictionary<int, VirtualOperation>
            {
                [Push] = new(Push, 0, 1, "pushes its operand"),
                [Store] = new(Store, 1, 0, "stores where its operand indexes"),
                [Return] = new(Return, 1, 0, "returns the value it takes")
            }
        };
        context.SetFact<IReadOnlyList<VirtualProgram>>("virtualization.programs", [program]);
    }

    /// <summary>
    /// A synthetic module that stays on disk for as long as the test runs.
    /// </summary>
    /// <remarks>
    /// The run check loads the input a second time, so unlike every other synthetic module here
    /// this one cannot be deleted the moment it is loaded. What the check makes of a module that
    /// unpacks nothing is that it could not be made, which is the answer under test elsewhere.
    /// </remarks>
    private sealed class Sample : IDisposable
    {
        private readonly string _path;

        public Sample()
        {
            var module = new ModuleDefUser("synthetic.dll") { Kind = ModuleKind.Dll };
            var assembly = new AssemblyDefUser("synthetic", new Version(1, 0));
            assembly.Modules.Add(module);
            var type = SyntheticContext.AddType(module, "Held");
            var stub = new MethodDefUser(
                "Stub",
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL,
                MethodAttributes.Assembly | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            stub.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            type.Methods.Add(stub);

            _path = Path.Combine(
                Path.GetTempPath(), $"Cilantro.Rebuild.{Guid.NewGuid():N}.dll");
            module.Write(_path);
            Context = ArtifactContext.Load(_path);
        }

        public ArtifactContext Context { get; }

        public void Dispose()
        {
            Context.Dispose();
            File.Delete(_path);
        }
    }
}
