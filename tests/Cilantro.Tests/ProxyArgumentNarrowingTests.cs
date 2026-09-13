using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Proxy;

namespace Cilantro.Tests;

/// <summary>
/// Covers putting back the conversion a proxy adapter was doing, once its call site goes straight
/// to the target.
/// </summary>
/// <remarks>
/// Reactor writes its adapters against `object` and widens the signatures of the methods that call
/// them to match, so the value reaching an adapter is already the target's type and nothing says
/// so. The adapter is what made that verifiable, the delegate behind it having the real signature;
/// bypassing it without saying so leaves IL that runs and does not verify.
/// </remarks>
public sealed class ProxyArgumentNarrowingTests
{
    [Fact]
    public void CastsTheReceiverTheAdapterTookAsAnObject()
    {
        using var fixture = Fixture.Build(receiverIsObject: true, extraArgument: false);

        var narrowing = ProxyArgumentNarrowing.Plan(fixture.Adapter, fixture.Target);

        var conversion = Assert.Single(Assert.IsType<ProxyArgumentNarrowing.Reconciliation>(narrowing)
            .Conversions);
        Assert.Equal(0, conversion.Position);
        Assert.Equal(fixture.Widget.FullName, conversion.Operand.FullName);
        Assert.Equal(Code.Castclass, conversion.How.Code);

        Redirect(fixture);
        ProxyArgumentNarrowing.Apply(fixture.Caller, fixture.Call, narrowing!);

        // Only the receiver is on the stack, so the cast goes straight in front of the call.
        Assert.Equal(
            new[] { Code.Ldarg_0, Code.Nop, Code.Castclass, Code.Callvirt, Code.Ret },
            fixture.Caller.Body.Instructions.Select(instruction => instruction.OpCode.Code));
        Assert.True(EvaluationStackAnalyzer.Analyze(fixture.Caller).Valid);
    }

    /// <summary>
    /// The receiver is the deepest thing on the stack, so reaching it means taking the arguments
    /// above it off and putting them straight back.
    /// </summary>
    [Fact]
    public void ReachesAReceiverUnderAnotherArgumentByPuttingThatArgumentAside()
    {
        using var fixture = Fixture.Build(receiverIsObject: true, extraArgument: true);

        var narrowing = ProxyArgumentNarrowing.Plan(fixture.Adapter, fixture.Target);
        Redirect(fixture);
        ProxyArgumentNarrowing.Apply(fixture.Caller, fixture.Call, narrowing!);

        Assert.Equal(
            new[]
            {
                Code.Ldarg_0, Code.Ldarg_1, Code.Nop,
                Code.Stloc, Code.Castclass, Code.Ldloc,
                Code.Callvirt, Code.Ret
            },
            fixture.Caller.Body.Instructions.Select(instruction => instruction.OpCode.Code));

        // A method given a local it reads before writing has to say its locals are zeroed, however
        // little that matters for a temporary written on the line before it is read.
        Assert.True(fixture.Caller.Body.InitLocals);
        Assert.Equal(
            fixture.Caller.Module.CorLibTypes.Int32.FullName,
            Assert.Single(fixture.Caller.Body.Variables).Type.FullName);
        Assert.True(EvaluationStackAnalyzer.Analyze(fixture.Caller).Valid);
    }

    [Fact]
    public void LeavesTheAdapterAloneWhereNothingNeedsNarrowing()
    {
        using var fixture = Fixture.Build(receiverIsObject: false, extraArgument: true);

        var narrowing = ProxyArgumentNarrowing.Plan(fixture.Adapter, fixture.Target);

        Assert.Empty(Assert.IsType<ProxyArgumentNarrowing.Reconciliation>(narrowing).Conversions);
    }

    /// <summary>
    /// The other direction: where the target's own parameter is the object and the adapter took the
    /// particular thing, the stack already does the widening and nothing needs emitting.
    /// </summary>
    [Fact]
    public void EmitsNothingWhereItIsTheTargetThatTakesTheObject()
    {
        using var fixture = Fixture.Build(receiverIsObject: false, extraArgument: false);
        var target = new MemberRefUser(
            fixture.Module,
            "Poke",
            MethodSig.CreateStatic(
                fixture.Module.CorLibTypes.Void, fixture.Module.CorLibTypes.Object),
            fixture.Widget);

        var narrowing = ProxyArgumentNarrowing.Plan(fixture.Adapter, target);

        Assert.Empty(Assert.IsType<ProxyArgumentNarrowing.Reconciliation>(narrowing).Conversions);
    }

    /// <summary>
    /// A value widened to object is widened by boxing it, which the adapter's own signature was
    /// doing on the way in.
    /// </summary>
    [Fact]
    public void BoxesAValueTheTargetTakesAsAnObject()
    {
        using var fixture = Fixture.Build(receiverIsObject: false, extraArgument: true);
        var target = new MemberRefUser(
            fixture.Module,
            "Poke",
            MethodSig.CreateInstance(
                fixture.Module.CorLibTypes.Void, fixture.Module.CorLibTypes.Object),
            fixture.Widget);

        var narrowing = ProxyArgumentNarrowing.Plan(fixture.Adapter, target);

        var conversion = Assert.Single(Assert.IsType<ProxyArgumentNarrowing.Reconciliation>(narrowing)
            .Conversions);
        Assert.Equal(1, conversion.Position);
        Assert.Equal(Code.Box, conversion.How.Code);
        Assert.Equal(fixture.Module.CorLibTypes.Int32.FullName, conversion.Operand.FullName);
    }

    /// <summary>
    /// A refusal rather than a guess: an argument the adapter took by reference where the target
    /// wants it by value is not something a conversion in front of the call can reconcile.
    /// </summary>
    [Fact]
    public void RefusesWhereTheDifferenceIsNotAnObjectWidening()
    {
        using var fixture = Fixture.Build(receiverIsObject: false, extraArgument: true);
        fixture.Adapter.MethodSig.Params[1] = new ByRefSig(
            fixture.Caller.Module.CorLibTypes.Int32);

        Assert.Null(ProxyArgumentNarrowing.Plan(fixture.Adapter, fixture.Target));
    }

    /// <summary>
    /// An instance call on a value type goes through a managed pointer, and an adapter standing in
    /// for one takes the pointer. That is the calling convention, not a widening, whether or not the
    /// receiver's own definition is reachable to say it is a value type.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void TakesAValueTypeReceiverByReferenceAsTheConventionRatherThanADifference(
        bool definitionIsReachable)
    {
        using var fixture = Fixture.Build(receiverIsObject: false, extraArgument: false);
        ITypeDefOrRef declaring;
        if (definitionIsReachable)
        {
            fixture.Widget.BaseType = new TypeRefUser(
                fixture.Module, "System", "ValueType", fixture.Module.CorLibTypes.AssemblyRef);
            Assert.True(fixture.Widget.IsValueType);
            declaring = fixture.Widget;
        }
        else
        {
            // Nothing in the module says what this is; the adapter's signature is all there is.
            declaring = new TypeRefUser(
                fixture.Module, "System", "TimeSpan", fixture.Module.CorLibTypes.AssemblyRef);
        }

        var target = new MemberRefUser(
            fixture.Module,
            "Poke",
            MethodSig.CreateInstance(fixture.Module.CorLibTypes.Void),
            declaring);
        fixture.Adapter.MethodSig.Params[0] = new ByRefSig(declaring.ToTypeSig());

        var narrowing = ProxyArgumentNarrowing.Plan(fixture.Adapter, target);

        Assert.Empty(Assert.IsType<ProxyArgumentNarrowing.Reconciliation>(narrowing).Conversions);
    }

    /// <summary>
    /// What the pass does before narrowing: the field load goes, and the adapter call becomes the
    /// call it was standing in for.
    /// </summary>
    private static void Redirect(Fixture fixture)
    {
        fixture.FieldLoad.OpCode = OpCodes.Nop;
        fixture.FieldLoad.Operand = null;
        fixture.Call.OpCode = OpCodes.Callvirt;
        fixture.Call.Operand = fixture.Target;
    }

    private sealed record Fixture(
        ModuleDefUser Module,
        TypeDef Widget,
        MethodDef Target,
        MethodDef Adapter,
        MethodDef Caller,
        Instruction FieldLoad,
        Instruction Call) : IDisposable
    {
        public static Fixture Build(bool receiverIsObject, bool extraArgument)
        {
            var module = new ModuleDefUser("proxy.dll") { Kind = ModuleKind.Dll };
            var assembly = new AssemblyDefUser("proxy", new Version(1, 0));
            assembly.Modules.Add(module);
            var host = new TypeDefUser("", "Host", module.CorLibTypes.Object.TypeDefOrRef);
            var widget = new TypeDefUser("", "Widget", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(host);
            module.Types.Add(widget);

            var target = new MethodDefUser(
                "Poke",
                extraArgument
                    ? MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Int32)
                    : MethodSig.CreateInstance(module.CorLibTypes.Void),
                dnlib.DotNet.MethodAttributes.Public | dnlib.DotNet.MethodAttributes.Virtual);
            widget.Methods.Add(target);

            var receiver = receiverIsObject
                ? module.CorLibTypes.Object
                : (TypeSig)widget.ToTypeSig();
            var adapterSig = extraArgument
                ? MethodSig.CreateStatic(
                    module.CorLibTypes.Void, receiver, module.CorLibTypes.Int32, host.ToTypeSig())
                : MethodSig.CreateStatic(module.CorLibTypes.Void, receiver, host.ToTypeSig());
            var adapter = new MethodDefUser(
                "XheaEjYKBi",
                adapterSig,
                dnlib.DotNet.MethodAttributes.Public | dnlib.DotNet.MethodAttributes.Static);
            host.Methods.Add(adapter);

            // Widened to match the adapter, which is what the protector does to the method holding
            // the call site as well as to the adapter itself.
            var caller = new MethodDefUser(
                "Call",
                extraArgument
                    ? MethodSig.CreateStatic(
                        module.CorLibTypes.Void, receiver, module.CorLibTypes.Int32)
                    : MethodSig.CreateStatic(module.CorLibTypes.Void, receiver),
                dnlib.DotNet.MethodAttributes.Public | dnlib.DotNet.MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            host.Methods.Add(caller);

            var proxyField = new FieldDefUser(
                "Held",
                new FieldSig(host.ToTypeSig()),
                dnlib.DotNet.FieldAttributes.Public | dnlib.DotNet.FieldAttributes.Static);
            host.Fields.Add(proxyField);

            var fieldLoad = Instruction.Create(OpCodes.Ldsfld, proxyField);
            var call = Instruction.Create(OpCodes.Call, adapter);
            var instructions = caller.Body.Instructions;
            instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            if (extraArgument)
                instructions.Add(Instruction.Create(OpCodes.Ldarg_1));
            instructions.Add(fieldLoad);
            instructions.Add(call);
            instructions.Add(Instruction.Create(OpCodes.Ret));
            caller.Body.UpdateInstructionOffsets();

            return new Fixture(module, widget, target, adapter, caller, fieldLoad, call);
        }

        public void Dispose() => Module.Dispose();
    }
}
