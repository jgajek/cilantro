using System.Security.Cryptography;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core.Interpretation;

namespace ReactorUnpack.Tests;

/// <summary>
/// Covers the framework types the machine models because samples pass through them on the way to
/// something worth recovering.
/// </summary>
/// <remarks>
/// Each of these was a place an interpretation stopped on a real sample, and the fix is only worth
/// having if it gives the answer the framework gives. So the expected values here are computed with
/// the framework rather than written out: a model that agrees with a copy of the answer somebody
/// typed is only as good as the typing.
/// </remarks>
public sealed class FrameworkModelTests
{
    [Fact]
    public void AStringIsBuiltUpAndReadBack()
    {
        using var module = NewModule();
        var builder = Builder(module);
        var method = NewMethod(module, "Build", MethodSig.CreateStatic(module.CorLibTypes.String));
        var body = method.Body.Instructions;
        body.Add(Instruction.Create(OpCodes.Newobj, Member(
            module, builder, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void))));
        body.Add(Instruction.Create(OpCodes.Ldstr, "ab"));
        body.Add(Instruction.Create(OpCodes.Callvirt, Member(
            module,
            builder,
            "Append",
            MethodSig.CreateInstance(Sig(module, builder), module.CorLibTypes.String))));
        body.Add(Instruction.Create(OpCodes.Ldc_I4, 'c'));
        body.Add(Instruction.Create(OpCodes.Callvirt, Member(
            module,
            builder,
            "Append",
            MethodSig.CreateInstance(Sig(module, builder), module.CorLibTypes.Char))));
        body.Add(Instruction.Create(OpCodes.Ldc_I4_7));
        body.Add(Instruction.Create(OpCodes.Callvirt, Member(
            module,
            builder,
            "Append",
            MethodSig.CreateInstance(Sig(module, builder), module.CorLibTypes.Int32))));
        body.Add(Instruction.Create(OpCodes.Callvirt, Member(
            module, builder, "ToString", MethodSig.CreateInstance(module.CorLibTypes.String))));
        body.Add(Instruction.Create(OpCodes.Ret));

        var machine = new StaticMachine();
        var result = machine.Execute(method);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.True(machine.State.Heap.TryGetString(result.Value, out var built));
        Assert.Equal("abc7", built);
    }

    /// <summary>
    /// Concatenation and logging reach a builder through <c>object</c>, and what a call site holds
    /// something as says nothing about what it is.
    /// </summary>
    [Fact]
    public void ABuilderAskedForItsTextThroughObjectStillAnswers()
    {
        using var module = NewModule();
        var builder = Builder(module);
        var method = NewMethod(module, "Read", MethodSig.CreateStatic(module.CorLibTypes.String));
        var body = method.Body.Instructions;
        body.Add(Instruction.Create(OpCodes.Ldstr, "carried"));
        body.Add(Instruction.Create(OpCodes.Newobj, Member(
            module,
            builder,
            ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String))));
        body.Add(Instruction.Create(OpCodes.Callvirt, Member(
            module,
            new TypeRefUser(module, "System", "Object", module.CorLibTypes.AssemblyRef),
            "ToString",
            MethodSig.CreateInstance(module.CorLibTypes.String))));
        body.Add(Instruction.Create(OpCodes.Ret));

        var machine = new StaticMachine();
        var result = machine.Execute(method);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.True(machine.State.Heap.TryGetString(result.Value, out var text));
        Assert.Equal("carried", text);
    }

    /// <summary>A fingerprint becomes a string two hex digits at a time.</summary>
    [Fact]
    public void ANumberWrittenAsHexReadsAsTheFrameworkWritesIt()
    {
        using var module = NewModule();

        var machine = new StaticMachine();
        var result = machine.Execute(Formats(module, "System.Byte", 200, "x2"));

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.True(machine.State.Heap.TryGetString(result.Value, out var written));
        Assert.Equal(((byte)200).ToString("x2", null), written);
    }

    /// <summary>
    /// A format that reads differently depending on the culture in force is refused, because nothing
    /// states which culture the machine the sample expects is running under.
    /// </summary>
    [Fact]
    public void ANumberWrittenWithSeparatorsIsRefusedRatherThanGuessed()
    {
        using var module = NewModule();

        var result = new StaticMachine().Execute(Formats(module, "System.Int32", 1234567, "N0"));

        Assert.NotEqual(StaticExecutionStatus.Completed, result.Status);
        Assert.Contains("N0", result.Diagnostic, StringComparison.Ordinal);
    }

    [Fact]
    public void ADurationIsTheTicksTheFrameworkMakesOfIt()
    {
        using var module = NewModule();
        var span = new TypeRefUser(module, "System", "TimeSpan", module.CorLibTypes.AssemblyRef);
        var method = NewMethod(module, "Wait", MethodSig.CreateStatic(module.CorLibTypes.Int64));
        var body = method.Body.Instructions;
        body.Add(Instruction.Create(OpCodes.Ldc_R8, 2.5));
        body.Add(Instruction.Create(OpCodes.Call, Member(
            module,
            span,
            "FromSeconds",
            MethodSig.CreateStatic(Sig(module, span), module.CorLibTypes.Double))));
        body.Add(Instruction.Create(OpCodes.Callvirt, Member(
            module, span, "get_Ticks", MethodSig.CreateInstance(module.CorLibTypes.Int64))));
        body.Add(Instruction.Create(OpCodes.Ret));

        var result = new StaticMachine().Execute(method);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(TimeSpan.FromSeconds(2.5).Ticks, result.Value.AsInt64());
    }

    /// <summary>
    /// Which algorithm a hash is belongs to the object, not to the variable it is held in, so the
    /// same call through the base type has to reach the same answer.
    /// </summary>
#pragma warning disable CA5351
    [Fact]
    public void AHashTakenThroughTheBaseTypeUsesTheAlgorithmItWasCreatedAs()
    {
        using var module = NewModule();
        byte[] input = [1, 2, 3, 4];
        var md5 = new TypeRefUser(
            module, "System.Security.Cryptography", "MD5", module.CorLibTypes.AssemblyRef);
        var algorithm = new TypeRefUser(
            module, "System.Security.Cryptography", "HashAlgorithm", module.CorLibTypes.AssemblyRef);
        var method = NewMethod(module, "Digest", MethodSig.CreateStatic(Bytes(module)));
        var body = method.Body.Instructions;
        body.Add(Instruction.Create(OpCodes.Call, Member(
            module, md5, "Create", MethodSig.CreateStatic(Sig(module, md5)))));
        PushBytes(module, body, input);
        body.Add(Instruction.Create(OpCodes.Callvirt, Member(
            module,
            algorithm,
            "ComputeHash",
            MethodSig.CreateInstance(Bytes(module), Bytes(module)))));
        body.Add(Instruction.Create(OpCodes.Ret));

        var machine = new StaticMachine();
        var result = machine.Execute(method);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        var digest = new byte[16];
        Assert.True(machine.State.Heap.TryReadBytes(result.Value, 0, digest));
        Assert.Equal(MD5.HashData(input), digest);
    }
#pragma warning restore CA5351

    /// <summary>
    /// A certificate built from bytes hands the bytes back, because that much is knowable without
    /// running a parser over what the sample supplied.
    /// </summary>
    [Fact]
    public void ACertificateHandsBackTheBytesItWasBuiltFrom()
    {
        using var module = NewModule();
        byte[] encoded = [0x30, 0x82, 0x01, 0x00, 0x30, 0x00];

        var machine = new StaticMachine();
        var result = machine.Execute(Certificate(module, encoded, "get_RawData", Bytes(module)));

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        var read = new byte[encoded.Length];
        Assert.True(machine.State.Heap.TryReadBytes(result.Value, 0, read));
        Assert.Equal(encoded, read);
    }

    [Fact]
    public void ACertificateWillNotBeDecodedToAnswerWhatIsInIt()
    {
        using var module = NewModule();

        var result = new StaticMachine().Execute(Certificate(
            module, [0x30, 0x82, 0x01, 0x00, 0x30, 0x00], "get_Subject", module.CorLibTypes.String));

        Assert.NotEqual(StaticExecutionStatus.Completed, result.Status);
        Assert.Contains("decoding it", result.Diagnostic, StringComparison.Ordinal);
    }

    /// <summary>
    /// In a world with one process, a name nothing else took is free, so the program reads itself as
    /// the first copy running.
    /// </summary>
    [Fact]
    public void AMutexNothingElseHoldsIsTaken()
    {
        using var module = NewModule();

        var result = new StaticMachine().Execute(TakesMutex(module));

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(1, result.Value.AsInt32());
    }

    /// <summary>And a profile describing a machine the sample already runs on says so.</summary>
    [Fact]
    public void AProfileCanSayACopyIsAlreadyRunning()
    {
        using var module = NewModule();
        var machine = new StaticMachine();
        machine.State.RegisterHostEnvironment(new HostEnvironment(HostProfile.Parse(
            """{ "facts": { "process:MutexHeld": true } }""",
            "busy")));

        var result = machine.Execute(TakesMutex(module));

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(0, result.Value.AsInt32());
        Assert.Contains(
            MutexIntrinsic.HeldKey,
            machine.State.Host.Questions.Select(question => question.Key));
    }

    /// <summary>
    /// The framework a sample was built against reaches the hives through static fields, and a field
    /// read has no call for an intrinsic to answer, so the machine has to know them itself.
    /// </summary>
    [Fact]
    public void ARegistryHiveReachedAsAStaticFieldOpens()
    {
        using var module = NewModule();
        var key = new TypeRefUser(
            module, "Microsoft.Win32", "RegistryKey", module.CorLibTypes.AssemblyRef);
        var registry = new TypeRefUser(
            module, "Microsoft.Win32", "Registry", module.CorLibTypes.AssemblyRef);
        var method = NewMethod(module, "Hive", MethodSig.CreateStatic(module.CorLibTypes.String));
        var body = method.Body.Instructions;
        body.Add(Instruction.Create(OpCodes.Ldsfld, new MemberRefUser(
            module, "CurrentUser", new FieldSig(Sig(module, key)), registry)));
        body.Add(Instruction.Create(OpCodes.Callvirt, Member(
            module, key, "get_Name", MethodSig.CreateInstance(module.CorLibTypes.String))));
        body.Add(Instruction.Create(OpCodes.Ret));

        var machine = new StaticMachine();
        var result = machine.Execute(method);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.True(machine.State.Heap.TryGetString(result.Value, out var named));
        Assert.Equal("HKEY_CURRENT_USER", named);
    }

    [Fact]
    public void TheEmptyStringIsAStringAndNotNothing()
    {
        using var module = NewModule();
        var method = NewMethod(module, "Empty", MethodSig.CreateStatic(module.CorLibTypes.String));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldsfld, new MemberRefUser(
            module,
            "Empty",
            new FieldSig(module.CorLibTypes.String),
            new TypeRefUser(module, "System", "String", module.CorLibTypes.AssemblyRef))));
        method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

        var machine = new StaticMachine();
        var result = machine.Execute(method);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.True(machine.State.Heap.TryGetString(result.Value, out var empty));
        Assert.Equal(string.Empty, empty);
    }

    /// <summary>A method that formats one number and returns the text.</summary>
    /// <summary>
    /// A stager builds its addresses and its paths with a format string, so what comes out of one has
    /// to be what the framework would have written.
    /// </summary>
    [Fact]
    public void AFilledFormatStringReadsAsTheFrameworkWritesIt()
    {
        using var module = NewModule();
        var method = NewMethod(module, "Fill", MethodSig.CreateStatic(module.CorLibTypes.String));
        var body = method.Body.Instructions;
        body.Add(Instruction.Create(OpCodes.Ldstr, "https://{0}/{1}"));
        body.Add(Instruction.Create(OpCodes.Ldstr, "host.invalid"));
        body.Add(Instruction.Create(OpCodes.Ldc_I4, 7));
        body.Add(Instruction.Create(OpCodes.Box, module.CorLibTypes.Int32.ToTypeDefOrRef()));
        body.Add(Instruction.Create(OpCodes.Call, Member(
            module,
            new TypeRefUser(module, "System", "String", module.CorLibTypes.AssemblyRef),
            "Format",
            MethodSig.CreateStatic(
                module.CorLibTypes.String,
                module.CorLibTypes.String,
                module.CorLibTypes.Object,
                module.CorLibTypes.Object))));
        body.Add(Instruction.Create(OpCodes.Ret));

        var machine = new StaticMachine();
        var result = machine.Execute(method);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.True(machine.State.Heap.TryGetString(result.Value, out var filled));
        Assert.Equal(string.Format(null, "https://{0}/{1}", "host.invalid", 7), filled);
    }

    /// <summary>
    /// How a value reads under a named format is a culture's business, and nothing states which
    /// culture the machine the sample expects is under.
    /// </summary>
    [Fact]
    public void AFormatItemThatNamesHowToWriteItsValueIsRefused()
    {
        using var module = NewModule();
        var method = NewMethod(module, "Fill", MethodSig.CreateStatic(module.CorLibTypes.String));
        var body = method.Body.Instructions;
        body.Add(Instruction.Create(OpCodes.Ldstr, "{0:X2}"));
        body.Add(Instruction.Create(OpCodes.Ldc_I4, 200));
        body.Add(Instruction.Create(OpCodes.Box, module.CorLibTypes.Int32.ToTypeDefOrRef()));
        body.Add(Instruction.Create(OpCodes.Call, Member(
            module,
            new TypeRefUser(module, "System", "String", module.CorLibTypes.AssemblyRef),
            "Format",
            MethodSig.CreateStatic(
                module.CorLibTypes.String,
                module.CorLibTypes.String,
                module.CorLibTypes.Object))));
        body.Add(Instruction.Create(OpCodes.Ret));

        var result = new StaticMachine().Execute(method);

        Assert.NotEqual(StaticExecutionStatus.Completed, result.Status);
    }

    /// <summary>Nothing is collected here, so a weak reference still has what it was given.</summary>
    [Fact]
    public void AWeakReferenceHoldsWhatItWasGiven()
    {
        using var module = NewModule();
        var weak = new TypeRefUser(
            module, "System", "WeakReference", module.CorLibTypes.AssemblyRef);
        var method = NewMethod(module, "Keep", MethodSig.CreateStatic(module.CorLibTypes.String));
        var body = method.Body.Instructions;
        body.Add(Instruction.Create(OpCodes.Ldstr, "pooled"));
        body.Add(Instruction.Create(OpCodes.Newobj, Member(
            module,
            weak,
            ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object))));
        body.Add(Instruction.Create(OpCodes.Callvirt, Member(
            module, weak, "get_Target", MethodSig.CreateInstance(module.CorLibTypes.Object))));
        body.Add(Instruction.Create(OpCodes.Castclass, module.CorLibTypes.String.ToTypeDefOrRef()));
        body.Add(Instruction.Create(OpCodes.Ret));

        var machine = new StaticMachine();
        var result = machine.Execute(method);

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.True(machine.State.Heap.TryGetString(result.Value, out var held));
        Assert.Equal("pooled", held);
    }

    /// <summary>
    /// An async method is driven to its end and its task carries the result, because nothing it
    /// waits for can still be running.
    /// </summary>
    [Fact]
    public void AnAsyncMethodRunsThroughToItsResult()
    {
        using var module = NewModule();

        var result = new StaticMachine().Execute(Awaits(module, 42));

        Assert.Equal(StaticExecutionStatus.Completed, result.Status);
        Assert.Equal(42, result.Value.AsInt32());
    }

    /// <summary>
    /// A request says where it was going, because that is the part of it worth reporting when it
    /// cannot be made.
    /// </summary>
    [Fact]
    public void AnHttpRequestIsRefusedAndSaysWhereItWasGoing()
    {
        using var module = NewModule();
        var client = new TypeRefUser(
            module, "System.Net.Http", "HttpClient", module.CorLibTypes.AssemblyRef);
        var method = NewMethod(module, "Fetch", MethodSig.CreateStatic(module.CorLibTypes.Object));
        var body = method.Body.Instructions;
        body.Add(Instruction.Create(OpCodes.Newobj, Member(
            module, client, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void))));
        body.Add(Instruction.Create(OpCodes.Ldstr, "https://host.invalid/stage"));
        body.Add(Instruction.Create(OpCodes.Callvirt, Member(
            module,
            client,
            "GetAsync",
            MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.String))));
        body.Add(Instruction.Create(OpCodes.Ret));

        var result = new StaticMachine().Execute(method);

        Assert.NotEqual(StaticExecutionStatus.Completed, result.Status);
        Assert.Contains("https://host.invalid/stage", result.Diagnostic, StringComparison.Ordinal);
    }

    /// <summary>
    /// A method shaped the way the compiler shapes an <c>async</c> one: a state machine whose
    /// <c>MoveNext</c> hands the builder a result, started and then read for its task.
    /// </summary>
    private static MethodDefUser Awaits(ModuleDefUser module, int produces)
    {
        var builder = new GenericInstSig(
            new ValueTypeSig(new TypeRefUser(
                module,
                "System.Runtime.CompilerServices",
                "AsyncTaskMethodBuilder`1",
                module.CorLibTypes.AssemblyRef)),
            module.CorLibTypes.Int32);
        var task = new GenericInstSig(
            new ClassSig(new TypeRefUser(
                module,
                "System.Threading.Tasks",
                "Task`1",
                module.CorLibTypes.AssemblyRef)),
            module.CorLibTypes.Int32);
        var machine = new TypeDefUser(
            "Tests",
            "StateMachine",
            new TypeRefUser(module, "System", "ValueType", module.CorLibTypes.AssemblyRef));
        machine.Attributes = TypeAttributes.NestedPrivate | TypeAttributes.SequentialLayout;
        module.Types.Add(machine);
        var held = new FieldDefUser(
            "builder", new FieldSig(builder), FieldAttributes.Public);
        machine.Fields.Add(held);

        var moves = new MethodDefUser(
            "MoveNext",
            MethodSig.CreateInstance(module.CorLibTypes.Void))
        {
            Attributes = MethodAttributes.Public,
            Body = new CilBody()
        };
        machine.Methods.Add(moves);
        var advancing = moves.Body.Instructions;
        advancing.Add(Instruction.Create(OpCodes.Ldarg_0));
        advancing.Add(Instruction.Create(OpCodes.Ldflda, held));
        advancing.Add(Instruction.Create(OpCodes.Ldc_I4, produces));
        advancing.Add(Instruction.Create(OpCodes.Call, new MemberRefUser(
            module,
            "SetResult",
            MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Int32),
            builder.ToTypeDefOrRef())));
        advancing.Add(Instruction.Create(OpCodes.Ret));

        var method = NewMethod(module, "Run", MethodSig.CreateStatic(module.CorLibTypes.Int32));
        var local = new Local(machine.ToTypeSig());
        method.Body.Variables.Add(local);
        var body = method.Body.Instructions;
        body.Add(Instruction.Create(OpCodes.Ldloca, local));
        body.Add(Instruction.Create(OpCodes.Call, new MemberRefUser(
            module, "Create", MethodSig.CreateStatic(builder), builder.ToTypeDefOrRef())));
        body.Add(Instruction.Create(OpCodes.Stfld, held));
        body.Add(Instruction.Create(OpCodes.Ldloca, local));
        body.Add(Instruction.Create(OpCodes.Ldflda, held));
        body.Add(Instruction.Create(OpCodes.Ldloca, local));
        body.Add(Instruction.Create(OpCodes.Call, new MethodSpecUser(
            new MemberRefUser(
                module,
                "Start",
                MethodSig.CreateInstanceGeneric(
                    1, module.CorLibTypes.Void, new ByRefSig(new GenericMVar(0))),
                builder.ToTypeDefOrRef()),
            new GenericInstMethodSig(machine.ToTypeSig()))));
        body.Add(Instruction.Create(OpCodes.Ldloca, local));
        body.Add(Instruction.Create(OpCodes.Ldflda, held));
        body.Add(Instruction.Create(OpCodes.Call, new MemberRefUser(
            module, "get_Task", MethodSig.CreateInstance(task), builder.ToTypeDefOrRef())));
        body.Add(Instruction.Create(OpCodes.Callvirt, new MemberRefUser(
            module,
            "get_Result",
            MethodSig.CreateInstance(module.CorLibTypes.Int32),
            task.ToTypeDefOrRef())));
        body.Add(Instruction.Create(OpCodes.Ret));
        return method;
    }

    private static MethodDefUser Formats(
        ModuleDefUser module,
        string type,
        int value,
        string format)
    {
        var separator = type.LastIndexOf('.');
        var declaring = new TypeRefUser(
            module, type[..separator], type[(separator + 1)..], module.CorLibTypes.AssemblyRef);
        var method = NewMethod(module, "Format", MethodSig.CreateStatic(module.CorLibTypes.String));
        var body = method.Body.Instructions;
        var local = new Local(Sig(module, declaring));
        method.Body.Variables.Add(local);
        body.Add(Instruction.Create(OpCodes.Ldc_I4, value));
        body.Add(Instruction.Create(OpCodes.Stloc, local));
        body.Add(Instruction.Create(OpCodes.Ldloca, local));
        body.Add(Instruction.Create(OpCodes.Ldstr, format));
        body.Add(Instruction.Create(OpCodes.Call, Member(
            module,
            declaring,
            "ToString",
            MethodSig.CreateInstance(module.CorLibTypes.String, module.CorLibTypes.String))));
        body.Add(Instruction.Create(OpCodes.Ret));
        return method;
    }

    /// <summary>A method that builds a certificate from bytes and asks it one thing.</summary>
    private static MethodDefUser Certificate(
        ModuleDefUser module,
        byte[] encoded,
        string member,
        TypeSig returns)
    {
        var certificate = new TypeRefUser(
            module,
            "System.Security.Cryptography.X509Certificates",
            "X509Certificate2",
            module.CorLibTypes.AssemblyRef);
        var method = NewMethod(module, $"Ask{member}", MethodSig.CreateStatic(returns));
        var body = method.Body.Instructions;
        PushBytes(module, body, encoded);
        body.Add(Instruction.Create(OpCodes.Newobj, Member(
            module,
            certificate,
            ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void, Bytes(module)))));
        body.Add(Instruction.Create(OpCodes.Callvirt, Member(
            module, certificate, member, MethodSig.CreateInstance(returns))));
        body.Add(Instruction.Create(OpCodes.Ret));
        return method;
    }

    /// <summary>A method that takes a named mutex and reports whether it got it.</summary>
    private static MethodDefUser TakesMutex(ModuleDefUser module)
    {
        var mutex = new TypeRefUser(
            module, "System.Threading", "Mutex", module.CorLibTypes.AssemblyRef);
        var method = NewMethod(module, "Take", MethodSig.CreateStatic(module.CorLibTypes.Boolean));
        var body = method.Body.Instructions;
        body.Add(Instruction.Create(OpCodes.Ldc_I4_1));
        body.Add(Instruction.Create(OpCodes.Ldstr, "Global\\only-me"));
        body.Add(Instruction.Create(OpCodes.Newobj, Member(
            module,
            mutex,
            ".ctor",
            MethodSig.CreateInstance(
                module.CorLibTypes.Void,
                module.CorLibTypes.Boolean,
                module.CorLibTypes.String))));
        body.Add(Instruction.Create(OpCodes.Callvirt, Member(
            module, mutex, "WaitOne", MethodSig.CreateInstance(module.CorLibTypes.Boolean))));
        body.Add(Instruction.Create(OpCodes.Ret));
        return method;
    }

    private static void PushBytes(ModuleDef module, IList<Instruction> body, byte[] bytes)
    {
        body.Add(Instruction.Create(OpCodes.Ldc_I4, bytes.Length));
        body.Add(Instruction.Create(OpCodes.Newarr, module.CorLibTypes.Byte.ToTypeDefOrRef()));
        for (var index = 0; index < bytes.Length; index++)
        {
            body.Add(Instruction.Create(OpCodes.Dup));
            body.Add(Instruction.Create(OpCodes.Ldc_I4, index));
            body.Add(Instruction.Create(OpCodes.Ldc_I4, (int)bytes[index]));
            body.Add(Instruction.Create(OpCodes.Stelem_I1));
        }
    }

    private static TypeRefUser Builder(ModuleDefUser module) => new(
        module, "System.Text", "StringBuilder", module.CorLibTypes.AssemblyRef);

    private static SZArraySig Bytes(ModuleDef module) => new(module.CorLibTypes.Byte);

    private static TypeSig Sig(ModuleDef module, ITypeDefOrRef type) =>
        type.ToTypeSig() ?? module.CorLibTypes.Object;

    private static MemberRefUser Member(
        ModuleDef module,
        ITypeDefOrRef declaring,
        string name,
        MethodSig signature) => new(module, name, signature, declaring);

    private static ModuleDefUser NewModule()
    {
        var module = new ModuleDefUser("framework-model.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser("framework-model", new Version(1, 0));
        assembly.Modules.Add(module);
        return module;
    }

    private static MethodDefUser NewMethod(ModuleDef module, string name, MethodSig signature)
    {
        var method = new MethodDefUser(name, signature)
        {
            Attributes = MethodAttributes.Public | MethodAttributes.Static,
            Body = new CilBody()
        };
        var type = module.Types.FirstOrDefault(item => item.Name == "Program");
        if (type is null)
        {
            type = new TypeDefUser("Tests", "Program", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);
        }

        type.Methods.Add(method);
        return method;
    }
}
