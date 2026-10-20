using System.Reflection;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using MethodAttributes = dnlib.DotNet.MethodAttributes;
using MethodImplAttributes = dnlib.DotNet.MethodImplAttributes;

namespace Cilantro.Tests;

public sealed class BabelByRefLiteralTests
{
    [Theory]
    [InlineData("Boolean")]
    [InlineData("SByte")]
    [InlineData("Byte")]
    [InlineData("Int16")]
    [InlineData("UInt16")]
    [InlineData("Char")]
    [InlineData("Int32")]
    [InlineData("UInt32")]
    [InlineData("Int64")]
    [InlineData("UInt64")]
    [InlineData("Single")]
    [InlineData("Double")]
    [InlineData("String")]
    public void CopybackRetainsPrimitiveWidthsFloatingBitsAndReferenceTypes(string kind)
    {
        using var module = new ModuleDefUser("ByRefLiteral.dll") { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser("ByRefLiteral" + Guid.NewGuid().ToString("N"), new Version(1, 0)); assembly.Modules.Add(module);
        var owner = new TypeDefUser("Fixture", "Program", module.CorLibTypes.Object.TypeDefOrRef) { Attributes = dnlib.DotNet.TypeAttributes.Public }; module.Types.Add(owner);
        var types = module.CorLibTypes;
        var (type, load, store, literal, expected) = kind switch
        {
            "Boolean" => (types.Boolean, OpCodes.Ldind_U1, OpCodes.Stind_I1, OpCodes.Ldc_I4_1.ToInstruction(), (object)true),
            "SByte" => (types.SByte, OpCodes.Ldind_I1, OpCodes.Stind_I1, OpCodes.Ldc_I4.ToInstruction(-17), (object)(sbyte)-17),
            "Byte" => (types.Byte, OpCodes.Ldind_U1, OpCodes.Stind_I1, OpCodes.Ldc_I4.ToInstruction(241), (object)(byte)241),
            "Int16" => (types.Int16, OpCodes.Ldind_I2, OpCodes.Stind_I2, OpCodes.Ldc_I4.ToInstruction(-30001), (object)(short)-30001),
            "UInt16" => (types.UInt16, OpCodes.Ldind_U2, OpCodes.Stind_I2, OpCodes.Ldc_I4.ToInstruction(60001), (object)(ushort)60001),
            "Char" => (types.Char, OpCodes.Ldind_U2, OpCodes.Stind_I2, OpCodes.Ldc_I4.ToInstruction(0xD834), (object)'\uD834'),
            "Int32" => (types.Int32, OpCodes.Ldind_I4, OpCodes.Stind_I4, OpCodes.Ldc_I4.ToInstruction(int.MinValue), (object)int.MinValue),
            "UInt32" => (types.UInt32, OpCodes.Ldind_U4, OpCodes.Stind_I4, OpCodes.Ldc_I4.ToInstruction(-1), (object)uint.MaxValue),
            "Int64" => (types.Int64, OpCodes.Ldind_I8, OpCodes.Stind_I8, OpCodes.Ldc_I8.ToInstruction(long.MinValue), (object)long.MinValue),
            "UInt64" => (types.UInt64, OpCodes.Ldind_I8, OpCodes.Stind_I8, OpCodes.Ldc_I8.ToInstruction(-1L), (object)ulong.MaxValue),
            "Single" => (types.Single, OpCodes.Ldind_R4, OpCodes.Stind_R4, OpCodes.Ldc_R4.ToInstruction(-0.0f), (object)(-0.0f)),
            "Double" => (types.Double, OpCodes.Ldind_R8, OpCodes.Stind_R8, OpCodes.Ldc_R8.ToInstruction(-0.0), (object)(-0.0)),
            _ => (types.String, OpCodes.Ldind_Ref, OpCodes.Stind_Ref, OpCodes.Ldstr.ToInstruction("updated Ω"), (object)"updated Ω")
        };
        MethodDef Method(string name, MethodSig signature)
        {
            var method = new MethodDefUser(name, signature, MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody { InitLocals = true } };
            owner.Methods.Add(method); return method;
        }
        var dispatch = Method("Dispatch", MethodSig.CreateStatic(types.Object, types.Int32, new ClassSig(types.GetTypeRef("System.Reflection", "MethodBase")), types.Object, new SZArraySig(types.Object)));
        dispatch.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); dispatch.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        var signature = MethodSig.CreateStatic(types.Void, new ByRefSig(type));
        var stub = Method("Adapted", signature); var il = stub.Body.Instructions;
        var packed = new Local(new SZArraySig(types.Object)); stub.Body.Variables.Add(packed);
        il.Add(OpCodes.Ldc_I4_1.ToInstruction()); il.Add(OpCodes.Newarr.ToInstruction(types.Object.TypeDefOrRef)); il.Add(OpCodes.Dup.ToInstruction()); il.Add(OpCodes.Ldc_I4_0.ToInstruction());
        il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(load.ToInstruction()); if (type.IsValueType) il.Add(OpCodes.Box.ToInstruction(type.TypeDefOrRef));
        il.Add(OpCodes.Stelem_Ref.ToInstruction()); il.Add(OpCodes.Stloc.ToInstruction(packed)); il.Add(OpCodes.Ldc_I4.ToInstruction(42)); il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Ldnull.ToInstruction());
        il.Add(OpCodes.Ldloc.ToInstruction(packed)); il.Add(OpCodes.Call.ToInstruction(dispatch)); il.Add(OpCodes.Pop.ToInstruction());
        il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Ldloc.ToInstruction(packed)); il.Add(OpCodes.Ldc_I4_0.ToInstruction()); il.Add(OpCodes.Ldelem_Ref.ToInstruction());
        il.Add((type.IsValueType ? OpCodes.Unbox_Any : OpCodes.Castclass).ToInstruction(type.TypeDefOrRef)); il.Add(store.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction());
        var decoded = Method("Decoded", signature.Clone()); decoded.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction()); decoded.Body.Instructions.Add(literal);
        decoded.Body.Instructions.Add(store.ToInstruction()); decoded.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        Assert.True(BabelByRefAdapter.Supported(stub, method => method.Name == "Dispatch"));
        stub.Body = Assert.IsType<CilBody>(BabelByRefAdapter.Build(stub, decoded, stub, method => method.Name == "Dispatch"));
        Assert.True(EvaluationStackAnalyzer.Analyze(stub).Valid);
        var run = Method("Run", MethodSig.CreateStatic(types.Object)); var value = new Local(type); run.Body.Variables.Add(value);
        run.Body.Instructions.Add(OpCodes.Ldloca.ToInstruction(value)); run.Body.Instructions.Add(OpCodes.Call.ToInstruction(stub)); run.Body.Instructions.Add(OpCodes.Ldloc.ToInstruction(value));
        if (type.IsValueType) run.Body.Instructions.Add(OpCodes.Box.ToInstruction(type.TypeDefOrRef)); run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        using var bytes = new MemoryStream(); module.Write(bytes);
        var actual = Assembly.Load(bytes.ToArray()).GetType("Fixture.Program")!.GetMethod("Run")!.Invoke(null, null);
        Assert.Equal(expected.GetType(), actual!.GetType()); Assert.Equal(expected, actual);
        if (actual is float single) Assert.Equal(BitConverter.SingleToInt32Bits((float)expected), BitConverter.SingleToInt32Bits(single));
        if (actual is double number) Assert.Equal(BitConverter.DoubleToInt64Bits((double)expected), BitConverter.DoubleToInt64Bits(number));
    }
}
