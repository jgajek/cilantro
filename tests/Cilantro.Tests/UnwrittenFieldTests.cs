using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;

namespace Cilantro.Tests;

/// <summary>
/// Covers reading a field nothing writes as the value the runtime left in it.
/// </summary>
/// <remarks>
/// The conclusion is only worth as much as the routes it closes, so most of what is pinned here is
/// the refusals. The one that matters most on a protected file is the last: a module that builds
/// code while it runs can write anything, and Reactor's interpreter does exactly that — the state
/// its opaque predicates read is assigned by a virtualized method, so a search of the instructions
/// that are present finds no write and would conclude, wrongly, that there never is one.
/// </remarks>
public sealed class UnwrittenFieldTests
{
    [Fact]
    public void AStaticFieldNothingWritesHoldsWhatTheRuntimeLeftInIt()
    {
        var module = NewModule();
        var field = AddField(module, "Never", module.CorLibTypes.Object);
        Read(module, field);

        var proven = UnwrittenFields.Prove(module);

        Assert.Null(proven.Refusal);
        Assert.True(proven.Holds(field));
    }

    [Fact]
    public void AFieldSomethingWritesIsNotReadAsHoldingAnything()
    {
        var module = NewModule();
        var field = AddField(module, "Assigned", module.CorLibTypes.Object);
        var writer = Read(module, field);
        writer.Body.Instructions.Insert(0, OpCodes.Ldnull.ToInstruction());
        writer.Body.Instructions.Insert(1, OpCodes.Stsfld.ToInstruction(field));

        Assert.False(UnwrittenFields.Prove(module).Holds(field));
    }

    /// <summary>
    /// A field whose address is handed out can be written through the address, and no
    /// <c>stsfld</c> naming it need ever appear.
    /// </summary>
    [Fact]
    public void AFieldWhoseAddressIsTakenIsNotReadAsHoldingAnything()
    {
        var module = NewModule();
        var field = AddField(module, "Addressed", module.CorLibTypes.Int32);
        var reader = Read(module, field);
        reader.Body.Instructions.Insert(0, OpCodes.Ldsflda.ToInstruction(field));
        reader.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());

        Assert.False(UnwrittenFields.Prove(module).Holds(field));
    }

    /// <summary>
    /// Taking a type's handle is how reachable code gets hold of a field of it by name, so its
    /// fields are out of reach of this reading.
    /// </summary>
    [Fact]
    public void AFieldOfATypeWhoseHandleIsTakenIsNotReadAsHoldingAnything()
    {
        var module = NewModule();
        var field = AddField(module, "Exposed", module.CorLibTypes.Object);
        var reader = Read(module, field);
        reader.Body.Instructions.Insert(0, OpCodes.Ldtoken.ToInstruction(module.Types[1]));
        reader.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());

        Assert.False(UnwrittenFields.Prove(module).Holds(field));
    }

    /// <summary>
    /// This is the shape that makes the whole question unanswerable on a Reactor file, and the
    /// reason its flattening cannot be undone by reading the fields its predicates test.
    /// </summary>
    [Fact]
    public void NothingIsReadAsHoldingAnythingWhereTheModuleBuildsCodeWhileItRuns()
    {
        var module = NewModule();
        var field = AddField(module, "Never", module.CorLibTypes.Object);
        var reader = Read(module, field);
        var emit = new MemberRefUser(
            module,
            "Emit",
            MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Int32),
            new TypeRefUser(module, "System.Reflection.Emit", "ILGenerator", module.CorLibTypes
                .AssemblyRef));
        reader.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(emit));

        var proven = UnwrittenFields.Prove(module);

        Assert.NotNull(proven.Refusal);
        Assert.Contains("builds code while it runs", proven.Refusal, StringComparison.Ordinal);
        Assert.False(proven.Holds(field));
        Assert.Equal(0, proven.Count);
    }

    private static ModuleDefUser NewModule()
    {
        var module = new ModuleDefUser("Sample.dll", Guid.NewGuid(), new AssemblyRefUser(
            "System.Runtime", new Version(8, 0, 0, 0)));
        var assembly = new AssemblyDefUser("Sample", new Version(1, 0, 0, 0));
        assembly.Modules.Add(module);
        module.Types.Add(new TypeDefUser("", "<Module>", null));
        module.Types.Add(new TypeDefUser("Sample", "Holder", module.CorLibTypes.Object.TypeDefOrRef)
        {
            // Externally invisible, since a field anything outside could write is refused for that
            // reason and would hide whichever reason the test is actually about.
            Attributes = TypeAttributes.NotPublic | TypeAttributes.Class
        });
        return module;
    }

    private static FieldDefUser AddField(ModuleDefUser module, string name, TypeSig type)
    {
        var field = new FieldDefUser(
            name,
            new FieldSig(type),
            FieldAttributes.Assembly | FieldAttributes.Static);
        module.Types[1].Fields.Add(field);
        return field;
    }

    /// <summary>A reachable method that reads the field, there being nothing to say about one
    /// nothing reads.</summary>
    private static MethodDefUser Read(ModuleDefUser module, FieldDef field)
    {
        var reader = new MethodDefUser(
            "Main",
            MethodSig.CreateStatic(module.CorLibTypes.Void),
            MethodImplAttributes.IL,
            MethodAttributes.Public | MethodAttributes.Static)
        {
            Body = new CilBody()
        };
        reader.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(field));
        reader.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
        reader.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        module.Types[1].Methods.Add(reader);
        module.EntryPoint = reader;
        return reader;
    }
}
