using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;

namespace Cilantro.Tests;

/// <summary>
/// The date-based trial guard recogniser and the interpretation-time neutralisation it feeds.
/// </summary>
public sealed class TrialGuardTests
{
    [Fact]
    public void AVoidGuardThatReadsTheClockBuildsAnInstantAndThrowsIsFound()
    {
        using var context = SyntheticContext.Build(module =>
            AddGuard(module, "Guard", readsClock: true, buildsInstant: true, throws: true));

        var found = TrialGuardAnalysis.Find(context.Module, []);

        var guard = Method(context.Module, "Guard");
        Assert.Contains(guard.MDToken.Raw, found);
    }

    [Theory]
    [InlineData(false, true, true)]
    [InlineData(true, false, true)]
    [InlineData(true, true, false)]
    public void AMethodMissingAnyOfTheThreeSignalsIsNotAGuard(
        bool readsClock, bool buildsInstant, bool throws)
    {
        using var context = SyntheticContext.Build(module =>
            AddGuard(module, "Candidate", readsClock, buildsInstant, throws));

        var found = TrialGuardAnalysis.Find(context.Module, []);

        Assert.DoesNotContain(Method(context.Module, "Candidate").MDToken.Raw, found);
    }

    [Fact]
    public void AClockReadHiddenBehindAProxyFieldIsSeenThroughItsBinding()
    {
        using var context = SyntheticContext.Build(module =>
            AddGuard(module, "Proxied", readsClock: false, buildsInstant: true, throws: true,
                clockProxyField: true));

        var module = context.Module;
        var guard = Method(module, "Proxied");
        var proxyField = module.GetTypes()
            .SelectMany(type => type.Fields)
            .Single(field => field.Name == "ClockProxy");
        var getNow = module.GetTypes()
            .SelectMany(type => type.Methods)
            .Where(method => method.HasBody)
            .SelectMany(method => method.Body.Instructions)
            .Select(instruction => instruction.Operand)
            .OfType<IMethod>()
            .First(method => method.FullName == "System.DateTime System.DateTime::get_Now()");

        // With no binding the ldsfld is just a field read, so nothing marks it a clock read; the
        // binding that says the field returns the wall clock is what the resolver leaves behind.
        Assert.DoesNotContain(guard.MDToken.Raw, TrialGuardAnalysis.Find(module, []));
        Assert.Contains(
            guard.MDToken.Raw,
            TrialGuardAnalysis.Find(
                module, [(proxyField.MDToken.Raw, getNow.MDToken.Raw)]));
    }

    [Fact]
    public void ANeutralisedVoidMethodIsEnteredAndLeftInsteadOfRun()
    {
        using var context = SyntheticContext.Build(module =>
        {
            var type = SyntheticContext.AddType(module, "Thrower");
            var method = new MethodDefUser(
                "Boom",
                MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Attributes = MethodAttributes.Public | MethodAttributes.Static,
                Body = new CilBody()
            };
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Throw));
            type.Methods.Add(method);
        });

        var boom = Method(context.Module, "Boom");

        var ran = new StaticMachine();
        Assert.Equal(StaticExecutionStatus.Threw, ran.Execute(boom).Status);

        var neutralised = new StaticMachine();
        neutralised.State.RegisterNeutralizedMethod(boom.MDToken.Raw);
        var result = neutralised.Execute(boom);
        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(1, neutralised.State.NeutralizedInvocations);
    }

    private static MethodDef Method(ModuleDef module, string name) => module.GetTypes()
        .SelectMany(type => type.Methods)
        .Single(method => method.Name == name);

    private static void AddGuard(
        ModuleDefUser module,
        string name,
        bool readsClock,
        bool buildsInstant,
        bool throws,
        bool clockProxyField = false)
    {
        var importer = new Importer(module);
        var getNow = importer.Import(
            typeof(DateTime).GetProperty(nameof(DateTime.Now))!.GetGetMethod()!);
        var instant = importer.Import(
            typeof(DateTime).GetConstructor([typeof(int), typeof(int), typeof(int)])!);
        var exception = importer.Import(
            typeof(Exception).GetConstructor([typeof(string)])!);

        var type = SyntheticContext.AddType(module, name + "Type");
        var method = new MethodDefUser(
            name,
            MethodSig.CreateStatic(module.CorLibTypes.Void))
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        var body = method.Body.Instructions;

        if (clockProxyField)
        {
            var field = new FieldDefUser(
                "ClockProxy",
                new FieldSig(module.CorLibTypes.Object),
                FieldAttributes.Public | FieldAttributes.Static);
            type.Fields.Add(field);
            body.Add(Instruction.Create(OpCodes.Ldsfld, field));
            body.Add(Instruction.Create(OpCodes.Pop));

            // The binding the test supplies has to resolve to a real DateTime::get_Now, so a
            // sibling that names it keeps that token in the module even though the guard reaches
            // the clock only through its proxy field.
            var sibling = new MethodDefUser(
                "ClockSource",
                MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Attributes = MethodAttributes.Public | MethodAttributes.Static,
                Body = new CilBody()
            };
            sibling.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getNow));
            sibling.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            sibling.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            type.Methods.Add(sibling);
        }
        else if (readsClock)
        {
            body.Add(Instruction.Create(OpCodes.Call, getNow));
            body.Add(Instruction.Create(OpCodes.Pop));
        }

        if (buildsInstant)
        {
            body.Add(Instruction.Create(OpCodes.Ldc_I4, 2026));
            body.Add(Instruction.Create(OpCodes.Ldc_I4, 8));
            body.Add(Instruction.Create(OpCodes.Ldc_I4, 30));
            body.Add(Instruction.Create(OpCodes.Newobj, instant));
            body.Add(Instruction.Create(OpCodes.Pop));
        }

        if (throws)
        {
            body.Add(Instruction.Create(OpCodes.Ldstr, "unregistered"));
            body.Add(Instruction.Create(OpCodes.Newobj, exception));
            body.Add(Instruction.Create(OpCodes.Throw));
        }
        else
        {
            body.Add(Instruction.Create(OpCodes.Ret));
        }

        type.Methods.Add(method);
    }
}
