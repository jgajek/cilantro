using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;

namespace Cilantro.Tests;

public sealed class ConstantStringPassTests
{
    [Fact]
    public void ACallToADecoderThatOnlyEverReturnsOneStringBecomesTheString()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Holder");
            type.Methods.Add(Decoder(module, "Hidden"));
            type.Methods.Add(Caller(module, "Uses", type.Methods[0]));
        });

        Protected(context);
        var result = new ConstantStringPass().Run(context);

        var caller = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .First(method => method.Name == "Uses");
        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(1, result.Changes);
        Assert.Contains(
            caller.Body.Instructions,
            instruction => instruction.OpCode == OpCodes.Ldstr &&
                (string?)instruction.Operand == "top");
        Assert.DoesNotContain(
            caller.Body.Instructions,
            instruction => instruction.OpCode == OpCodes.Call);
    }

    /// <summary>
    /// A method whose result is constant but which also writes something down is left alone: the
    /// call is doing two things and only one of them is the string.
    /// </summary>
    [Fact]
    public void ADecoderThatWritesAFieldOnItsWayOutKeepsItsCall()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Holder");
            var noticed = new FieldDefUser(
                "Noticed",
                new FieldSig(module.CorLibTypes.String),
                FieldAttributes.Public | FieldAttributes.Static);
            type.Fields.Add(noticed);
            var decoder = Decoder(module, "Hidden");
            var body = decoder.Body.Instructions;
            body.Insert(body.Count - 1, Instruction.Create(OpCodes.Dup));
            body.Insert(body.Count - 1, Instruction.Create(OpCodes.Stsfld, noticed));
            type.Methods.Add(decoder);
            type.Methods.Add(Caller(module, "Uses", decoder));
        });

        Protected(context);
        var result = new ConstantStringPass().Run(context);

        var caller = context.Module.GetTypes()
            .SelectMany(type => type.Methods)
            .First(method => method.Name == "Uses");
        Assert.Equal(PassStatus.Success, result.Status);
        Assert.Equal(0, result.Changes);
        Assert.Contains(
            caller.Body.Instructions,
            instruction => instruction.OpCode == OpCodes.Call);
    }

    /// <summary>Says a protector was found, which is the pass's precondition for editing.</summary>
    private static void Protected(ArtifactContext context) =>
        context.SetFact(
            "reactor.structure",
            new ReactorStructureFacts(
                DelegateProxyCount: 0,
                DeadCallPrefixCount: 0,
                DispatcherMethodCount: 0,
                MethodStubCount: 0,
                StringResolverCount: 0,
                HighEntropyResourceCount: 0,
                VirtualizedMethodCount: 0,
                ReferencesClrJit: false,
                HasRuntimeModulePointerAccess: false,
                Capabilities: ReactorCapability.ProtectedStrings,
                Confidence: 1.0,
                Generation: "reactor6"));

    /// <summary>Builds "top" out of a scrambled literal, the way the samples do.</summary>
    private static MethodDefUser Decoder(ModuleDefUser module, string name)
    {
        var text = new TypeRefUser(module, "System", "String", module.CorLibTypes.AssemblyRef);
        var characters = new SZArraySig(module.CorLibTypes.Char);
        var apart = new MemberRefUser(
            module, "ToCharArray", MethodSig.CreateInstance(characters), text);
        var together = new MemberRefUser(
            module,
            ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void, characters),
            text);
        var decoder = new MethodDefUser(name, MethodSig.CreateStatic(module.CorLibTypes.String))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        decoder.Body.Variables.Add(new Local(characters));
        var body = decoder.Body.Instructions;
        body.Add(Instruction.Create(OpCodes.Ldstr, "ZA^"));
        body.Add(Instruction.Create(OpCodes.Call, apart));
        body.Add(Instruction.Create(OpCodes.Stloc_0));
        for (var index = 0; index < 3; index++)
        {
            body.Add(Instruction.Create(OpCodes.Ldloc_0));
            body.Add(Instruction.Create(OpCodes.Ldc_I4, index));
            body.Add(Instruction.Create(OpCodes.Ldloc_0));
            body.Add(Instruction.Create(OpCodes.Ldc_I4, index));
            body.Add(Instruction.Create(OpCodes.Ldelem_U2));
            body.Add(Instruction.Create(OpCodes.Ldc_I4, 0x2E));
            body.Add(Instruction.Create(OpCodes.Xor));
            body.Add(Instruction.Create(OpCodes.Conv_U2));
            body.Add(Instruction.Create(OpCodes.Stelem_I2));
        }
        body.Add(Instruction.Create(OpCodes.Ldloc_0));
        body.Add(Instruction.Create(OpCodes.Newobj, together));
        body.Add(Instruction.Create(OpCodes.Ret));
        return decoder;
    }

    private static MethodDefUser Caller(ModuleDefUser module, string name, MethodDef decoder)
    {
        var caller = new MethodDefUser(name, MethodSig.CreateStatic(module.CorLibTypes.String))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        caller.Body.Instructions.Add(Instruction.Create(OpCodes.Call, decoder));
        caller.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        return caller;
    }
}
