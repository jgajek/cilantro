using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ReactorProxySetupTests
{
    [Theory]
    [InlineData("unused", true, true)]
    [InlineData("threaded", true, true)]
    [InlineData("framework-casts", true, true)]
    [InlineData("foreign-cast", false, false)]
    [InlineData("wrong-cast", false, false)]
    [InlineData("called", true, false)]
    [InlineData("handle", true, false)]
    [InlineData("public", true, false)]
    [InlineData("application", false, false)]
    [InlineData("missing-operation", false, false)]
    [InlineData("wrong-token", false, false)]
    [InlineData("foreign", false, false)]
    [InlineData("conditional", false, false)]
    [InlineData("loop", false, false)]
    [InlineData("extra-write", false, false)]
    [InlineData("not-reactor", false, false)]
    [InlineData("keep-runtime", true, false)]
    public void RecognitionDoesNotBypassCleanupSafety(string scenario, bool recognized, bool removed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, scenario == "application" ? "ApplicationHelpers" : "aB1cD2eF3gH4");
            owner.Namespace = "";
            if (scenario == "public") owner.Attributes = TypeAttributes.Public;
            TypeRef T(string ns, string name) => new TypeRefUser(module, ns, name, module.CorLibTypes.AssemblyRef);
            var type = T("System", "Type");
            var assembly = T("System.Reflection", "Assembly");
            var reflectionModule = T("System.Reflection", "Module");
            var member = T("System.Reflection", "MemberInfo");
            var field = T("System.Reflection", "FieldInfo");
            var method = T("System.Reflection", "MethodInfo");
            var @delegate = T("System", "Delegate");
            var slot = new FieldDefUser("Module", new FieldSig(new ClassSig(reflectionModule)), FieldAttributes.Static | FieldAttributes.Private);
            owner.Fields.Add(slot);
            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodAttributes.Static | MethodAttributes.Private | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = new CilBody() };
            owner.Methods.Add(cctor);
            var code = cctor.Body.Instructions;
            code.Add(OpCodes.Ldtoken.ToInstruction(owner));
            code.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetTypeFromHandle", MethodSig.CreateStatic(new ClassSig(type), new ValueTypeSig(T("System", "RuntimeTypeHandle"))), type)));
            if (scenario is "framework-casts" or "foreign-cast" or "wrong-cast")
                code.Add(OpCodes.Castclass.ToInstruction(scenario == "foreign-cast"
                    ? new TypeRefUser(module, "System", "Type", new AssemblyRefUser("Foreign", new Version(1, 0)))
                    : scenario == "wrong-cast" ? assembly : type));
            code.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_Assembly", MethodSig.CreateInstance(new ClassSig(assembly)), type)));
            if (scenario == "framework-casts") code.Add(OpCodes.Castclass.ToInstruction(assembly));
            code.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_ManifestModule", MethodSig.CreateInstance(new ClassSig(reflectionModule)), assembly)));
            if (scenario == "framework-casts") code.Add(OpCodes.Castclass.ToInstruction(reflectionModule));
            code.Add(OpCodes.Stsfld.ToInstruction(slot));
            code.Add(OpCodes.Ret.ToInstruction());
            if (scenario == "threaded")
            {
                var first = code[0]; var tail = OpCodes.Br.ToInstruction(first);
                code.Insert(0, OpCodes.Br.ToInstruction(tail)); code.Add(OpCodes.Nop.ToInstruction()); code.Add(tail);
            }
            if (scenario == "loop") code.Insert(0, OpCodes.Br.ToInstruction(code[0]));
            if (scenario == "loop") code[0].Operand = code[0];
            if (scenario == "conditional") { code.Insert(0, OpCodes.Brtrue.ToInstruction(code[^1])); code.Insert(0, OpCodes.Ldc_I4_0.ToInstruction()); }
            if (scenario == "extra-write") { code.Insert(0, OpCodes.Stsfld.ToInstruction(slot)); code.Insert(0, OpCodes.Ldnull.ToInstruction()); }
            var builder = new MethodDefUser("Build", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32),
                MethodAttributes.Static | (scenario == "public" ? MethodAttributes.Public : MethodAttributes.Assembly)) { Body = new CilBody() };
            owner.Methods.Add(builder);
            var body = builder.Body.Instructions;
            body.Add(OpCodes.Ldsfld.ToInstruction(slot)); body.Add(OpCodes.Pop.ToInstruction());
            body.Add(Instruction.CreateLdcI4(scenario == "wrong-token" ? 42 : 0x02000000)); body.Add(OpCodes.Pop.ToInstruction());
            body.Add(Instruction.CreateLdcI4(0x06000000)); body.Add(OpCodes.Pop.ToInstruction());
            void Call(TypeRef declaring, string name, MethodSig signature)
            {
                if (signature.HasThis) body.Add(OpCodes.Ldnull.ToInstruction());
                foreach (var arg in signature.Params) body.Add(arg.ElementType == ElementType.I4 ? OpCodes.Ldc_I4_0.ToInstruction() : OpCodes.Ldnull.ToInstruction());
                body.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, name, signature, declaring)));
                if (signature.RetType.ElementType != ElementType.Void) body.Add(OpCodes.Pop.ToInstruction());
            }
            Call(reflectionModule, "ResolveType", MethodSig.CreateInstance(new ClassSig(type), module.CorLibTypes.Int32));
            Call(reflectionModule, "ResolveMethod", MethodSig.CreateInstance(new ClassSig(T("System.Reflection", "MethodBase")), module.CorLibTypes.Int32));
            Call(member, "get_MetadataToken", MethodSig.CreateInstance(module.CorLibTypes.Int32));
            Call(type, "GetFields", MethodSig.CreateInstance(new SZArraySig(new ClassSig(field))));
            if (scenario == "foreign") @delegate.ResolutionScope = new AssemblyRefUser(new AssemblyNameInfo("Foreign, Version=1.0.0.0"));
            Call(@delegate, "CreateDelegate", MethodSig.CreateStatic(new ClassSig(@delegate), new ClassSig(type), new ClassSig(method)));
            if (scenario != "missing-operation") Call(field, "SetValue", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.Object));
            body.Add(OpCodes.Ret.ToInstruction());
            var app = SyntheticContext.AddType(module, "Application"); app.Attributes = TypeAttributes.Public;
            var entry = new MethodDefUser("Entry", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
            app.Methods.Add(entry);
            if (scenario == "called") { entry.Body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction()); entry.Body.Instructions.Add(OpCodes.Call.ToInstruction(builder)); }
            if (scenario == "handle") { entry.Body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(builder)); entry.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); }
            entry.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        context.SetFact("reactor.structure", new ReactorStructureFacts(0, 0, 0, 0, 0, 0, 0, false, false, ReactorCapability.None, scenario == "not-reactor" ? 0 : 1, "test"));
        var builder = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Build");
        Assert.Equal(recognized, ReactorProxySetup.Find(context).Contains(builder));
        context.SetFact("options.removeRuntime", scenario != "keep-runtime");
        new RuntimeCleanupPass().Run(context);
        Assert.Equal(!removed, context.Module.GetTypes().SelectMany(t => t.Methods).Contains(builder));
    }
}
