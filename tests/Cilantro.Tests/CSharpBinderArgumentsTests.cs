using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class CSharpBinderArgumentsTests
{
    [Theory]
    [InlineData("member", true)]
    [InlineData("convert", true)]
    [InlineData("index", true)]
    [InlineData("unary", true)]
    [InlineData("binary", true)]
    [InlineData("missing", false)]
    [InlineData("duplicate", false)]
    [InlineData("escape", false)]
    [InlineData("foreign", false)]
    [InlineData("branch", false)]
    [InlineData("generic-member", false)]
    public void DecodesOnlyClosedExactConstruction(string mode, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Application");
            var method = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL,
                MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody { KeepOldMaxStack = true, MaxStack = 16 } }; owner.Methods.Add(method);
            var csharp = new AssemblyRefUser("Microsoft.CSharp", new Version(4, 0), new PublicKeyToken(mode == "foreign" ? "0000000000000000" : "b03f5f7f11d50a3a"));
            var core = new AssemblyRefUser("System.Core", new Version(4, 0), new PublicKeyToken("b77a5c561934e089"));
            TypeRef Sharp(string name) => new TypeRefUser(module, "Microsoft.CSharp.RuntimeBinder", name, csharp);
            var type = module.CorLibTypes.GetTypeRef("System", "Type").ToTypeSig();
            var info = Sharp("CSharpArgumentInfo"); var flags = new ValueTypeSig(Sharp("CSharpBinderFlags"));
            var infoFlags = new ValueTypeSig(Sharp("CSharpArgumentInfoFlags"));
            var enumerable = module.CorLibTypes.GetTypeRef("System.Collections.Generic", "IEnumerable`1");
            TypeSig Sequence(TypeSig element) => new GenericInstSig(new ClassSig(enumerable), element);
            void Emit(params Instruction[] instructions) { foreach (var i in instructions) method.Body.Instructions.Add(i); }
            void TypeValue(ITypeDefOrRef value) => Emit(OpCodes.Ldtoken.ToInstruction(value), OpCodes.Call.ToInstruction(new MemberRefUser(module,
                "GetTypeFromHandle", MethodSig.CreateStatic(type, new ValueTypeSig(module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle"))), type.ToTypeDefOrRef())));
            Emit(OpCodes.Ldc_I4_0.ToInstruction());
            var parameters = new List<TypeSig> { flags };
            var name = mode == "convert" ? "Convert" : mode == "index" ? "GetIndex" : mode == "unary" ? "UnaryOperation" : mode == "binary" ? "BinaryOperation" : "InvokeMember";
            if (name == "Convert") { TypeValue(module.CorLibTypes.String.TypeDefOrRef); parameters.Add(type); }
            else if (name == "InvokeMember")
            {
                Emit(OpCodes.Ldstr.ToInstruction("GetType")); parameters.Add(module.CorLibTypes.String);
                if (mode == "generic-member") Emit(OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Newarr.ToInstruction(type.ToTypeDefOrRef()));
                else Emit(OpCodes.Ldnull.ToInstruction());
                parameters.Add(Sequence(type));
            }
            else if (name is "UnaryOperation" or "BinaryOperation")
            {
                Emit(Instruction.CreateLdcI4(name == "UnaryOperation" ? 83 : 35));
                parameters.Add(new ValueTypeSig(new TypeRefUser(module, "System.Linq.Expressions", "ExpressionType", core)));
            }
            TypeValue(owner); parameters.Add(type);
            if (name != "Convert")
            {
                var count = name == "BinaryOperation" ? 2 : 1;
                Emit(Instruction.CreateLdcI4(count), OpCodes.Newarr.ToInstruction(info));
                if (mode == "escape") Emit(OpCodes.Dup.ToInstruction(), OpCodes.Pop.ToInstruction());
                for (var n = 0; n < (mode == "missing" ? 0 : mode == "duplicate" ? 2 : count); n++)
                {
                    Emit(OpCodes.Dup.ToInstruction(), Instruction.CreateLdcI4(mode == "duplicate" ? 0 : n), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Ldnull.ToInstruction(),
                        OpCodes.Call.ToInstruction(new MemberRefUser(module, "Create", MethodSig.CreateStatic(info.ToTypeSig(), infoFlags, module.CorLibTypes.String), info)), OpCodes.Stelem_Ref.ToInstruction());
                }
                parameters.Add(Sequence(info.ToTypeSig()));
            }
            var call = OpCodes.Call.ToInstruction(new MemberRefUser(module, name, MethodSig.CreateStatic(
                new ClassSig(new TypeRefUser(module, "System.Runtime.CompilerServices", "CallSiteBinder", core)), parameters.ToArray()), Sharp("Binder")));
            if (mode == "branch") Emit(OpCodes.Br.ToInstruction(call));
            Emit(call, OpCodes.Pop.ToInstruction(), OpCodes.Ret.ToInstruction());
        });
        var method = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Read");
        var binder = method.Body.Instructions.Single(i => i.Operand is IMethod reference && reference.DeclaringType.FullName == "Microsoft.CSharp.RuntimeBinder.Binder");
        var descriptor = new CSharpBinderArguments(method).Read(binder);
        Assert.Equal(expected, descriptor is not null);
        if (descriptor is not null) { Assert.Equal(0, descriptor.Flags); Assert.Same(method.DeclaringType, descriptor.Context); }
        if(mode == "member") Assert.Equal("GetType", descriptor!.Name);
        if(mode == "convert") Assert.Equal("System.String", descriptor!.ConversionType!.FullName);
    }
}
