using Cilantro.Core.Analysis;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class RetiredProxyMapBuilderTests
{
    [Theory]
    [InlineData("unused", true, true)]
    [InlineData("namespace", true, true)]
    [InlineData("called", true, false)]
    [InlineData("handle", true, false)]
    [InlineData("public", true, false)]
    [InlineData("resource-present", false, false)]
    [InlineData("foreign", false, false)]
    [InlineData("missing-operation", false, false)]
    [InlineData("application", false, false)]
    [InlineData("not-reactor", false, false)]
    [InlineData("keep-runtime", true, false)]
    [InlineData("island", true, true)]
    [InlineData("island-no-proof", true, true)]
    [InlineData("island-other-owner", true, true)]
    [InlineData("island-field", true, true)]
    [InlineData("island-handle", true, false)]
    [InlineData("island-public", true, false)]
    [InlineData("island-nested", true, true)]
    [InlineData("island-rebuilt", true, true)]
    public void OnlyUnusedAttributedBuilderIsRemoved(string scenario, bool recognized, bool removed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            TypeRef T(string name) { var dot = name.LastIndexOf('.'); return new TypeRefUser(module, name[..dot], name[(dot + 1)..], module.CorLibTypes.AssemblyRef); }
            var type = T("System.Type"); var handle = T("System.RuntimeTypeHandle");
            var owner = SyntheticContext.AddType(module, scenario == "application" ? "ApplicationHelpers" : "aB1cD2eF3gH4"); owner.Namespace = "";
            if (scenario == "namespace") owner.Namespace = "Application";
            if (scenario is "public" or "island-public") owner.Attributes = TypeAttributes.Public;
            var builder = new MethodDefUser("Build", MethodSig.CreateStatic(module.CorLibTypes.Void, new ValueTypeSig(handle)), MethodAttributes.Static | MethodAttributes.Public) { Body = new CilBody() }; owner.Methods.Add(builder);
            var il = builder.Body.Instructions;
            IMethod Member(string declaring, string name, TypeSig result, params TypeSig[] arguments) => new MemberRefUser(module, name, MethodSig.CreateInstance(result, arguments), T(declaring));
            var getType = new MemberRefUser(module, "GetTypeFromHandle", MethodSig.CreateStatic(type.ToTypeSig(), new ValueTypeSig(handle)), type);
            il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Call.ToInstruction(getType)); il.Add(OpCodes.Pop.ToInstruction());
            il.Add(OpCodes.Ldtoken.ToInstruction(owner)); il.Add(OpCodes.Call.ToInstruction(getType));
            il.Add(OpCodes.Callvirt.ToInstruction(Member("System.Type", "get_Assembly", T("System.Reflection.Assembly").ToTypeSig())));
            il.Add(OpCodes.Ldstr.ToInstruction("missing.map"));
            il.Add(OpCodes.Callvirt.ToInstruction(Member("System.Reflection.Assembly", "GetManifestResourceStream", T("System.IO.Stream").ToTypeSig(), module.CorLibTypes.String))); il.Add(OpCodes.Pop.ToInstruction());
            void Operation(string declaring, string name, TypeSig result, params TypeSig[] args)
            {
                var call = Member(declaring, name, result, args);
                if (declaring == "System.Delegate") call.MethodSig.HasThis = false;
                if (scenario == "foreign" && name == "GetParameters") ((TypeRef)call.DeclaringType).ResolutionScope = new AssemblyRefUser("Foreign");
                if (call.MethodSig.HasThis) il.Add(OpCodes.Ldnull.ToInstruction());
                foreach (var arg in args) il.Add(arg.ElementType == ElementType.I4 || arg is ValueTypeSig ? OpCodes.Ldc_I4_0.ToInstruction() : OpCodes.Ldnull.ToInstruction());
                il.Add(OpCodes.Call.ToInstruction(call)); if (result.ElementType != ElementType.Void) il.Add(OpCodes.Pop.ToInstruction());
            }
            TypeSig C(string n) => T(n).ToTypeSig();
            Operation("System.Type", "GetFields", new SZArraySig(C("System.Reflection.FieldInfo")), new ValueTypeSig(T("System.Reflection.BindingFlags")));
            Operation("System.Reflection.MemberInfo", "get_MetadataToken", module.CorLibTypes.Int32);
            Operation("System.Reflection.Module", "ResolveMethod", C("System.Reflection.MethodBase"), module.CorLibTypes.Int32, new SZArraySig(type.ToTypeSig()), new SZArraySig(type.ToTypeSig()));
            Operation("System.Delegate", "CreateDelegate", C("System.Delegate"), type.ToTypeSig(), C("System.Reflection.MethodInfo"));
            Operation("System.Reflection.FieldInfo", "SetValue", module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.Object);
            Operation("System.Reflection.MethodBase", "GetParameters", new SZArraySig(C("System.Reflection.ParameterInfo")));
            Operation("System.Reflection.Emit.DynamicMethod", "GetILGenerator", C("System.Reflection.Emit.ILGenerator"));
            if (scenario != "missing-operation") Operation("System.Reflection.Emit.DynamicMethod", "CreateDelegate", C("System.Delegate"), type.ToTypeSig());
            il.Add(OpCodes.Ret.ToInstruction());
            if (scenario == "resource-present") module.Resources.Add(new EmbeddedResource("missing.map", new byte[] { 1 }, ManifestResourceAttributes.Private));
            var app = SyntheticContext.AddType(module, "Application"); app.Attributes = TypeAttributes.Public;
            if (scenario.StartsWith("island", StringComparison.Ordinal))
            {
                var gate = new MethodDefUser("Gate", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodAttributes.Static | MethodAttributes.Private) { Body = new CilBody() };
                (scenario == "island-other-owner" ? app : owner).Methods.Add(gate); gate.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                // Keep this otherwise isolated owner reachable through conservative
                // reflection analysis. Ordinary dead-type pruning must not make
                // the ownership-proof negative controls pass vacuously.
                var virtualMethod = new MethodDefUser("ToString", MethodSig.CreateInstance(module.CorLibTypes.String),
                    MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.HideBySig) { Body = new CilBody() };
                virtualMethod.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("runtime"));
                virtualMethod.Body.Instructions.Add(OpCodes.Ret.ToInstruction()); owner.Methods.Add(virtualMethod);
                var importer = new Importer(module);
                var read = new MethodDefUser("Read", MethodSig.CreateStatic(module.CorLibTypes.String, importer.ImportAsTypeSig(typeof(Type))),
                    MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
                app.Methods.Add(read);
                read.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                read.Body.Instructions.Add(OpCodes.Call.ToInstruction(importer.Import(typeof(Activator).GetMethod("CreateInstance", [typeof(Type)])!)));
                read.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(importer.Import(typeof(object).GetMethod("ToString")!)));
                read.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            }
            var entry = new MethodDefUser("Entry", MethodSig.CreateStatic(module.CorLibTypes.Void, new ValueTypeSig(handle)), MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() }; app.Methods.Add(entry);
            if (scenario == "called") { entry.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction()); entry.Body.Instructions.Add(OpCodes.Call.ToInstruction(builder)); }
            if (scenario == "handle") { entry.Body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(builder)); entry.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); }
            if (scenario == "island-handle") { entry.Body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(owner)); entry.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); }
            if (scenario is "island-field" or "island-nested")
            {
                TypeDef holder = owner;
                if (scenario == "island-nested")
                {
                    holder = new TypeDefUser("", "Nested", module.CorLibTypes.Object.TypeDefOrRef) { Attributes = TypeAttributes.NestedAssembly };
                    owner.NestedTypes.Add(holder);
                }
                var field = new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Static | FieldAttributes.Assembly);
                holder.Fields.Add(field); entry.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(field)); entry.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            }
            entry.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        context.SetFact("reactor.structure", new ReactorStructureFacts(0, 0, 0, 0, 0, 0, 0, false, false, ReactorCapability.None, scenario == "not-reactor" ? 0 : 1, "test"));
        var builder = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Build");
        var owner = builder.DeclaringType;
        if (scenario == "island-rebuilt") ReadingMarker.Add(context.Module).Mark(owner.Methods.Single(m => m.Name == "ToString"));
        if (scenario.StartsWith("island", StringComparison.Ordinal) && scenario != "island-no-proof")
            context.SetFact("antitamper.memoryLoadEntryPoint", context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Gate").MDToken.Raw);
        Assert.Equal(recognized, ReactorProxySetup.Find(context).Contains(builder));
        context.SetFact("options.removeRuntime", scenario != "keep-runtime");
        new RuntimeCleanupPass().Run(context);
        if (scenario.StartsWith("island", StringComparison.Ordinal))
            Assert.Equal(scenario != "island", context.Module.GetTypes().Contains(owner));
        else Assert.Equal(!removed, context.Module.GetTypes().SelectMany(t => t.Methods).Contains(builder));
    }
}
