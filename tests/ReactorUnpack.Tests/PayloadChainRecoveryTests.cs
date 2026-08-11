using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ReactorUnpack.Core;
using ReactorUnpack.Core.Recovery;

namespace ReactorUnpack.Tests;

/// <summary>
/// Covers recovering a payload by interpreting the unpacker a module carries for itself.
/// </summary>
/// <remarks>
/// The interesting case is not the decryption, which is arithmetic the machine already does, but
/// where the recovery is allowed to start. A crypter's driver is as likely to be written as a class
/// with a constructor as it is to be written as a static method, and a driver that keeps its key in
/// a field the constructor fills cannot be entered by allocating an instance and hoping: the key
/// would be zero and the payload would come out as noise. So the driver here is deliberately shaped
/// that way, and the test passes only if the receiver was really constructed.
/// </remarks>
public sealed class PayloadChainRecoveryTests
{
    private const byte Key = 0x5A;

    [Fact]
    public void APayloadUnpackedByAConstructedDriverIsRecovered()
    {
        var payload = NewPayloadAssembly();
        using var context = SyntheticContext.Build(module =>
            AddDriver(module, Encode(payload, Key), constructorSetsKey: true));

        var recovered = PayloadChainRecovery.Recover(context, out var diagnostics);

        Assert.Empty(diagnostics);
        Assert.Equal("payload", Assert.Single(recovered).AssemblyName);
        Assert.Equal(payload, recovered[0].Image);
    }

    [Fact]
    public void ADriverWhoseConstructorLeftTheKeyUnsetRecoversNothing()
    {
        var payload = NewPayloadAssembly();
        using var context = SyntheticContext.Build(module =>
            AddDriver(module, Encode(payload, Key), constructorSetsKey: false));

        Assert.Empty(PayloadChainRecovery.Recover(context, out var diagnostics));
        Assert.NotEmpty(diagnostics);
    }

    private static byte[] Encode(byte[] payload, byte key) =>
        [.. payload.Select(value => (byte)(value ^ key))];

    /// <summary>
    /// Builds a small but real assembly, so recovery has to parse metadata to accept it.
    /// </summary>
    private static byte[] NewPayloadAssembly()
    {
        var module = new ModuleDefUser("payload.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser("payload", new Version(1, 0));
        assembly.Modules.Add(module);
        module.Types.Add(new TypeDefUser(
            "Payload", "Marker", module.CorLibTypes.Object.TypeDefOrRef)
        {
            Attributes = TypeAttributes.Public | TypeAttributes.Class
        });
        using var buffer = new MemoryStream();
        module.Write(buffer);
        return buffer.ToArray();
    }

    /// <summary>
    /// Adds a driver whose instance method decodes an embedded blob and loads it.
    /// </summary>
    private static void AddDriver(ModuleDefUser module, byte[] encoded, bool constructorSetsKey)
    {
        var driver = SyntheticContext.AddType(module, "Driver");
        var keyField = new FieldDefUser(
            "key",
            new FieldSig(module.CorLibTypes.Int32),
            FieldAttributes.Private);
        driver.Fields.Add(keyField);
        driver.Methods.Add(NewConstructor(module, keyField, constructorSetsKey));
        driver.Methods.Add(NewUnpacker(module, keyField, NewDataField(module, encoded), encoded.Length));
    }

    private static MethodDefUser NewConstructor(
        ModuleDefUser module,
        FieldDef keyField,
        bool setsKey)
    {
        var constructor = new MethodDefUser(
            ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void),
            MethodImplAttributes.IL,
            MethodAttributes.Public | MethodAttributes.HideBySig |
            MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
        {
            Body = new CilBody()
        };
        var body = constructor.Body.Instructions;
        body.Add(OpCodes.Ldarg_0.ToInstruction());
        body.Add(OpCodes.Call.ToInstruction(new MemberRefUser(
            module,
            ".ctor",
            MethodSig.CreateInstance(module.CorLibTypes.Void),
            module.CorLibTypes.Object.TypeDefOrRef)));
        if (setsKey)
        {
            body.Add(OpCodes.Ldarg_0.ToInstruction());
            body.Add(OpCodes.Ldc_I4.ToInstruction((int)Key));
            body.Add(OpCodes.Stfld.ToInstruction(keyField));
        }

        body.Add(OpCodes.Ret.ToInstruction());
        return constructor;
    }

    /// <summary>
    /// An instance method that fills a buffer from static data, undoes the encoding with the key
    /// its constructor stored, and hands the result to <c>Assembly.Load</c>.
    /// </summary>
    private static MethodDefUser NewUnpacker(
        ModuleDefUser module,
        FieldDef keyField,
        FieldDef dataField,
        int length)
    {
        var unpacker = new MethodDefUser(
            "Unpack",
            MethodSig.CreateInstance(module.CorLibTypes.Void),
            MethodImplAttributes.IL,
            MethodAttributes.Public | MethodAttributes.HideBySig)
        {
            Body = new CilBody()
        };
        var buffer = new Local(new SZArraySig(module.CorLibTypes.Byte));
        var index = new Local(module.CorLibTypes.Int32);
        unpacker.Body.Variables.Add(buffer);
        unpacker.Body.Variables.Add(index);

        var condition = OpCodes.Ldloc.ToInstruction(index);
        var body = unpacker.Body.Instructions;
        body.Add(OpCodes.Ldc_I4.ToInstruction(length));
        body.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Byte.TypeDefOrRef));
        body.Add(OpCodes.Stloc.ToInstruction(buffer));
        body.Add(OpCodes.Ldloc.ToInstruction(buffer));
        body.Add(OpCodes.Ldtoken.ToInstruction(dataField));
        body.Add(OpCodes.Call.ToInstruction(new MemberRefUser(
            module,
            "InitializeArray",
            MethodSig.CreateStatic(
                module.CorLibTypes.Void,
                new ClassSig(module.CorLibTypes.GetTypeRef("System", "Array")),
                new ValueTypeSig(
                    module.CorLibTypes.GetTypeRef("System", "RuntimeFieldHandle"))),
            module.CorLibTypes.GetTypeRef(
                "System.Runtime.CompilerServices", "RuntimeHelpers"))));
        body.Add(OpCodes.Ldc_I4_0.ToInstruction());
        body.Add(OpCodes.Stloc.ToInstruction(index));
        body.Add(OpCodes.Br.ToInstruction(condition));

        var loop = OpCodes.Ldloc.ToInstruction(buffer);
        body.Add(loop);
        body.Add(OpCodes.Ldloc.ToInstruction(index));
        body.Add(OpCodes.Ldloc.ToInstruction(buffer));
        body.Add(OpCodes.Ldloc.ToInstruction(index));
        body.Add(OpCodes.Ldelem_U1.ToInstruction());
        body.Add(OpCodes.Ldarg_0.ToInstruction());
        body.Add(OpCodes.Ldfld.ToInstruction(keyField));
        body.Add(OpCodes.Xor.ToInstruction());
        body.Add(OpCodes.Conv_U1.ToInstruction());
        body.Add(OpCodes.Stelem_I1.ToInstruction());
        body.Add(OpCodes.Ldloc.ToInstruction(index));
        body.Add(OpCodes.Ldc_I4_1.ToInstruction());
        body.Add(OpCodes.Add.ToInstruction());
        body.Add(OpCodes.Stloc.ToInstruction(index));

        body.Add(condition);
        body.Add(OpCodes.Ldc_I4.ToInstruction(length));
        body.Add(OpCodes.Blt.ToInstruction(loop));
        body.Add(OpCodes.Ldloc.ToInstruction(buffer));
        body.Add(OpCodes.Call.ToInstruction(new MemberRefUser(
            module,
            "Load",
            MethodSig.CreateStatic(
                new ClassSig(module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly")),
                new SZArraySig(module.CorLibTypes.Byte)),
            module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly"))));
        body.Add(OpCodes.Pop.ToInstruction());
        body.Add(OpCodes.Ret.ToInstruction());
        return unpacker;
    }

    /// <summary>
    /// Places the encoded payload in field data, the way a compiler lays out an array literal.
    /// </summary>
    private static FieldDefUser NewDataField(ModuleDefUser module, byte[] data)
    {
        var details = new TypeDefUser(
            string.Empty,
            "<PrivateImplementationDetails>",
            module.CorLibTypes.Object.TypeDefOrRef)
        {
            Attributes = TypeAttributes.NotPublic | TypeAttributes.Sealed
        };
        module.Types.Add(details);
        var storage = new TypeDefUser(
            string.Empty,
            $"__StaticArrayInitTypeSize={data.Length}",
            module.CorLibTypes.GetTypeRef("System", "ValueType"))
        {
            Attributes = TypeAttributes.NestedPrivate | TypeAttributes.ExplicitLayout |
                TypeAttributes.Sealed,
            ClassLayout = new ClassLayoutUser(1, (uint)data.Length)
        };
        details.NestedTypes.Add(storage);
        var field = new FieldDefUser(
            "payload",
            new FieldSig(storage.ToTypeSig()),
            FieldAttributes.Assembly | FieldAttributes.Static | FieldAttributes.HasFieldRVA)
        {
            InitialValue = data
        };
        details.Fields.Add(field);
        return field;
    }
}
