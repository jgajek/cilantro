using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ReactorCryptoHelpersTests
{
    private static readonly string[] HelperNames = ["ReadString", "BindProxy", "Keep", "UnusedApplicationHelper"];

    [SampleTheory]
    [InlineData("cleaned", true)]
    [InlineData("trial-call-remains", false)]
    [InlineData("wrong-key-size", false)]
    [InlineData("wrong-factory-branch", false)]
    [InlineData("wrong-handler", false)]
    [InlineData("extra-effect", false)]
    [InlineData("different-operation", false)]
    public void RecognizesCompleteDecryptorOnlyAfterOtherEffectsAreRemoved(string scenario, bool expected)
    {
        using var module = ModuleDefMD.Load(Checkout.Sample("reactor7-probe-net48.full.exe"));
        var method = Assert.Single(module.GetTypes().SelectMany(t => t.Methods), m => m.IsStatic && m.HasBody &&
            m.ReturnType.FullName == "System.Byte[]" && m.MethodSig.Params.Count == 1 &&
            m.Body.Instructions.Any(i => i.Operand is IMethod called && called.Name == "CreateDecryptor"));
        // This fixture still has its trial call. Model the state after the
        // separate trial-removal pass; this recognizer must reject the raw body.
        Assert.DoesNotContain(method, ReactorCryptoHelpers.Recognize(method.DeclaringType));
        var trailing = method.Body.Instructions[^2];
        Assert.Equal(Code.Call, trailing.OpCode.Code);
        Assert.Equal(ElementType.Void, ((IMethod)trailing.Operand).MethodSig.RetType.ElementType);
        if (scenario != "trial-call-remains") method.Body.Instructions.Remove(trailing);
        var factory = ((IMethod)method.Body.Instructions[2].Operand).ResolveMethodDef();
        if (scenario == "wrong-key-size")
            ((IField)method.Body.Instructions.First(i => i.OpCode.Code == Code.Ldtoken).Operand).ResolveFieldDef().InitialValue = new byte[31];
        if (scenario == "wrong-factory-branch") factory.Body.Instructions[3].OpCode = OpCodes.Brtrue;
        if (scenario == "wrong-handler") factory.Body.ExceptionHandlers[0].TryEnd = factory.Body.ExceptionHandlers[0].HandlerEnd;
        if (scenario == "extra-effect")
        {
            method.Body.Instructions.Insert(0, OpCodes.Ldstr.ToInstruction("application effect"));
            method.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
        }
        if (scenario == "different-operation")
            ((MemberRef)method.Body.Instructions.Single(i => i.Operand is IMethod called && called.Name == "CreateDecryptor").Operand).Name = "CreateEncryptor";
        Assert.Equal(expected, ReactorCryptoHelpers.Recognize(method.DeclaringType).Contains(method));
    }

    [SampleTheory]
    [InlineData("original", true)]
    [InlineData("extra-effect", false)]
    [InlineData("wrong-argument", false)]
    [InlineData("wrong-operation", false)]
    public void ProtectedBenignFixtureConfirmsSelectorPattern(string scenario, bool expected)
    {
        // Static metadata inspection of the authored benign probe; no fixture execution.
        using var module = ModuleDefMD.Load(Checkout.Sample("reactor7-probe-net48.full.exe"));
        var selector = Assert.Single(module.GetTypes().SelectMany(t => t.Methods), ReactorCryptoHelpers.IsSelector);
        if (scenario == "extra-effect")
        {
            selector.Body.Instructions.Insert(0, OpCodes.Ldstr.ToInstruction("application effect"));
            selector.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction());
        }
        if (scenario == "wrong-argument") selector.Body.Instructions.First(i => i.OpCode.Code == Code.Ldarg_0).OpCode = OpCodes.Ldnull;
        if (scenario == "wrong-operation")
            ((MemberRef)selector.Body.Instructions.Single(i => i.Operand is IMethod m && m.Name == "ComputeHash").Operand).Name = "ApplicationTransform";
        Assert.Equal(expected, ReactorCryptoHelpers.IsSelector(selector));
    }
    [Theory]
    [InlineData("dead", true)]
    [InlineData("live-fallback", true)]
    [InlineData("live-selector", false)]
    [InlineData("handle", false)]
    [InlineData("foreign-provider", false)]
    [InlineData("foreign-fallback", false)]
    [InlineData("different-flag", false)]
    [InlineData("wrong-branch", false)]
    [InlineData("extra-effect", false)]
    [InlineData("same-resource", false)]
    [InlineData("incomplete", false)]
    [InlineData("encryptor-key-size", false)]
    [InlineData("encryptor-argument", false)]
    [InlineData("encryptor-operation", false)]
    public void RemovesOnlyAttributedSelectorAndItsUnusedLocalDependencies(string scenario, bool removed)
    {
        using var context = SyntheticContext.Build(module =>
        {
            module.Resources.Add(new EmbeddedResource("strings", [1], ManifestResourceAttributes.Private));
            module.Resources.Add(new EmbeddedResource("proxies", [2], ManifestResourceAttributes.Private));
            var owner = SyntheticContext.AddType(module, "a1B2c3D4e5F6");
            owner.Namespace = "ordinary";
            var other = SyntheticContext.AddType(module, "Application");
            var bytes = new SZArraySig(module.CorLibTypes.Byte);
            var fallback = Add(scenario == "foreign-fallback" ? other : owner, "Fallback", bytes, bytes);
            fallback.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            fallback.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var ready = new FieldDefUser("Ready", new FieldSig(module.CorLibTypes.Boolean), FieldAttributes.Private | FieldAttributes.Static);
            var policy = new FieldDefUser("Policy", ready.FieldSig, ready.Attributes);
            owner.Fields.Add(ready); owner.Fields.Add(policy);
            var provider = new TypeRefUser(module, "System.Security.Cryptography", "MD5CryptoServiceProvider",
                scenario == "foreign-provider" ? new AssemblyRefUser("Foreign") : module.CorLibTypes.AssemblyRef);
            var constructor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), provider);
            var initializer = Add(owner, "InitializePolicy", module.CorLibTypes.Void);
            var end = OpCodes.Ret.ToInstruction();
            var query = OpCodes.Call.ToInstruction(new MemberRefUser(module, "get_AllowOnlyFipsAlgorithms",
                MethodSig.CreateStatic(module.CorLibTypes.Boolean), module.CorLibTypes.GetTypeRef("System.Security.Cryptography", "CryptoConfig")));
            var catchProvider = OpCodes.Pop.ToInstruction();
            var catchQuery = OpCodes.Pop.ToInstruction();
            var first = OpCodes.Newobj.ToInstruction(constructor);
            foreach (var instruction in new[] { first, OpCodes.Pop.ToInstruction(), OpCodes.Leave.ToInstruction(query),
                catchProvider, OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(policy), OpCodes.Leave.ToInstruction(end),
                query, OpCodes.Stsfld.ToInstruction(scenario == "different-flag" ? ready : policy), OpCodes.Leave.ToInstruction(end),
                catchQuery, OpCodes.Leave.ToInstruction(end), end }) initializer.Body.Instructions.Add(instruction);
            initializer.Body.ExceptionHandlers.Add(new(ExceptionHandlerType.Catch) {
                TryStart = first, TryEnd = catchProvider, HandlerStart = catchProvider, HandlerEnd = query,
                CatchType = module.CorLibTypes.GetTypeRef("System", "Exception") });
            initializer.Body.ExceptionHandlers.Add(new(ExceptionHandlerType.Catch) {
                TryStart = query, TryEnd = catchQuery, HandlerStart = catchQuery, HandlerEnd = end,
                CatchType = module.CorLibTypes.GetTypeRef("System", "Exception") });
            var getter = Add(owner, "GetPolicy", module.CorLibTypes.Boolean);
            var read = OpCodes.Ldsfld.ToInstruction(policy);
            foreach (var instruction in new[] { OpCodes.Ldsfld.ToInstruction(ready), OpCodes.Brtrue.ToInstruction(read),
                OpCodes.Call.ToInstruction(initializer), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Stsfld.ToInstruction(ready), read,
                OpCodes.Ret.ToInstruction() }) getter.Body.Instructions.Add(instruction);
            var selector = Add(owner, "SelectHash", bytes, bytes);
            var alternative = OpCodes.Ldarg_0.ToInstruction();
            foreach (var instruction in new[] { OpCodes.Call.ToInstruction(getter), OpCodes.Brtrue.ToInstruction(alternative),
                OpCodes.Newobj.ToInstruction(constructor), OpCodes.Ldarg_0.ToInstruction(),
                OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "ComputeHash", MethodSig.CreateInstance(bytes, bytes),
                    module.CorLibTypes.GetTypeRef("System.Security.Cryptography", "HashAlgorithm"))), OpCodes.Ret.ToInstruction(),
                alternative, OpCodes.Call.ToInstruction(fallback), OpCodes.Ret.ToInstruction() }) selector.Body.Instructions.Add(instruction);
            if (scenario == "wrong-branch") selector.Body.Instructions[1].OpCode = OpCodes.Brfalse;
            if (scenario == "extra-effect") { initializer.Body.Instructions.Insert(0, OpCodes.Ldstr.ToInstruction("effect")); initializer.Body.Instructions.Insert(1, OpCodes.Pop.ToInstruction()); }
            AddEncryptor(module, owner, selector, scenario);
            foreach (var name in HelperNames)
                Add(owner, name, module.CorLibTypes.Void).Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var root = Add(module.GlobalType, ".cctor", module.CorLibTypes.Void);
            root.Attributes |= MethodAttributes.SpecialName | MethodAttributes.RTSpecialName;
            root.Body.Instructions.Add(OpCodes.Call.ToInstruction(owner.Methods.Single(m => m.Name == "Keep")));
            if (scenario is "live-selector" or "live-fallback")
            {
                root.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
                root.Body.Instructions.Add(OpCodes.Call.ToInstruction(scenario == "live-selector" ? selector : fallback));
                root.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            }
            if (scenario == "handle") { root.Body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(selector)); root.Body.Instructions.Add(OpCodes.Pop.ToInstruction()); }
            root.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var owner = context.Module.GetTypes().Single(t => t.Name == "a1B2c3D4e5F6");
        var resources = context.Module.Resources.OfType<EmbeddedResource>().ToArray();
        DecodedResourceOwnership.Remember(context, RecoveredResourceOrigin.Capture(resources[0]), [owner.Methods.Single(m => m.Name == "ReadString")]);
        DecodedResourceOwnership.Remember(context, RecoveredResourceOrigin.Capture(resources[scenario == "same-resource" ? 0 : 1]),
            [owner.Methods.Single(m => m.Name == "BindProxy")], [owner]);
        context.SetFact("options.removeRuntime", true);
        context.SetFact("method-protection.complete", scenario != "incomplete");
        context.SetFact("reactor.structure", new ReactorStructureFacts(0, 0, 0, 0, 0, 0, 0, false, false, ReactorCapability.ProtectedStrings, 1, "test"));
        new RuntimeCleanupPass().Run(context);
        new RuntimeCleanupPass().Run(context);
        Assert.Equal(removed, !owner.Methods.Any(m => m.Name == "SelectHash"));
        Assert.Equal(removed && scenario != "live-fallback", !context.Module.GetTypes().SelectMany(t => t.Methods).Any(m => m.Name == "Fallback"));
        Assert.Contains(owner.Methods, m => m.Name == "UnusedApplicationHelper");
    }

    private static void AddEncryptor(ModuleDefUser module, TypeDef owner, MethodDef selector, string scenario)
    {
        var utility = new TypeDefUser("", "EncryptionUtility", module.CorLibTypes.Object.TypeDefOrRef) { Attributes = TypeAttributes.NestedPrivate };
        owner.NestedTypes.Add(utility);
        var blob = new TypeDefUser("", "KeyStorage", module.CorLibTypes.GetTypeRef("System", "ValueType")) {
            Attributes = TypeAttributes.NestedPrivate | TypeAttributes.ExplicitLayout | TypeAttributes.Sealed,
            ClassLayout = new ClassLayoutUser(1, scenario == "encryptor-key-size" ? 31u : 32u) };
        owner.NestedTypes.Add(blob);
        var key = new FieldDefUser("Key", new FieldSig(new ValueTypeSig(blob)), FieldAttributes.Static | FieldAttributes.Assembly | FieldAttributes.HasFieldRVA) {
            InitialValue = new byte[scenario == "encryptor-key-size" ? 31 : 32] };
        owner.Fields.Add(key);
        var bytes = new SZArraySig(module.CorLibTypes.Byte);
        var algorithm = module.CorLibTypes.GetTypeRef("System.Security.Cryptography", "SymmetricAlgorithm");
        var factory = Add(owner, "CreateAlgorithm", algorithm.ToTypeSig());
        factory.Body.Instructions.Add(OpCodes.Ldnull.ToInstruction()); factory.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        var encryptor = Add(utility, "Encrypt", module.CorLibTypes.String, module.CorLibTypes.String, module.CorLibTypes.String);
        for (var i = 0; i < 3; i++) encryptor.Body.Variables.Add(new Local(bytes));
        encryptor.Body.Variables.Add(new Local(algorithm.ToTypeSig()));
        var il = encryptor.Body.Instructions;
        var encoding = module.CorLibTypes.GetTypeRef("System.Text", "Encoding");
        var stream = module.CorLibTypes.GetTypeRef("System.IO", "Stream");
        var memory = module.CorLibTypes.GetTypeRef("System.IO", "MemoryStream");
        var transform = module.CorLibTypes.GetTypeRef("System.Security.Cryptography", "ICryptoTransform");
        void Call(OpCode opcode, TypeRef type, string name, MethodSig signature) => il.Add(opcode.ToInstruction(new MemberRefUser(module, name, signature, type)));
        void Unicode() => Call(OpCodes.Call, encoding, "get_Unicode", MethodSig.CreateStatic(encoding.ToTypeSig()));
        void Encode() => Call(OpCodes.Callvirt, encoding, "GetBytes", MethodSig.CreateInstance(bytes, module.CorLibTypes.String));
        Unicode(); il.Add((scenario == "encryptor-argument" ? OpCodes.Ldarg_1 : OpCodes.Ldarg_0).ToInstruction()); Encode(); il.Add(OpCodes.Stloc_0.ToInstruction());
        il.Add(OpCodes.Ldc_I4.ToInstruction(32)); il.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Byte.TypeDefOrRef)); il.Add(OpCodes.Dup.ToInstruction()); il.Add(OpCodes.Ldtoken.ToInstruction(key));
        Call(OpCodes.Call, module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "RuntimeHelpers"), "InitializeArray", MethodSig.CreateStatic(module.CorLibTypes.Void,
            module.CorLibTypes.GetTypeRef("System", "Array").ToTypeSig(), new ValueTypeSig(module.CorLibTypes.GetTypeRef("System", "RuntimeFieldHandle"))));
        il.Add(OpCodes.Stloc_1.ToInstruction()); Unicode(); il.Add(OpCodes.Ldarg_1.ToInstruction()); Encode(); il.Add(OpCodes.Call.ToInstruction(selector)); il.Add(OpCodes.Stloc_2.ToInstruction());
        Call(OpCodes.Newobj, memory, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void)); il.Add(OpCodes.Call.ToInstruction(factory)); il.Add(OpCodes.Stloc_3.ToInstruction());
        il.Add(OpCodes.Ldloc_3.ToInstruction()); il.Add(OpCodes.Ldloc_1.ToInstruction()); Call(OpCodes.Callvirt, algorithm, "set_Key", MethodSig.CreateInstance(module.CorLibTypes.Void, bytes));
        il.Add(OpCodes.Ldloc_3.ToInstruction()); il.Add(OpCodes.Ldloc_2.ToInstruction()); Call(OpCodes.Callvirt, algorithm, "set_IV", MethodSig.CreateInstance(module.CorLibTypes.Void, bytes));
        il.Add(OpCodes.Dup.ToInstruction()); il.Add(OpCodes.Ldloc_3.ToInstruction()); Call(OpCodes.Callvirt, algorithm, "CreateEncryptor", MethodSig.CreateInstance(transform.ToTypeSig()));
        il.Add(OpCodes.Ldc_I4_1.ToInstruction()); Call(OpCodes.Newobj, module.CorLibTypes.GetTypeRef("System.Security.Cryptography", "CryptoStream"), ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void,
            stream.ToTypeSig(), transform.ToTypeSig(), new ValueTypeSig(module.CorLibTypes.GetTypeRef("System.Security.Cryptography", "CryptoStreamMode"))));
        il.Add(OpCodes.Dup.ToInstruction()); il.Add(OpCodes.Ldloc_0.ToInstruction()); il.Add(OpCodes.Ldc_I4_0.ToInstruction()); il.Add(OpCodes.Ldloc_0.ToInstruction()); il.Add(OpCodes.Ldlen.ToInstruction()); il.Add(OpCodes.Conv_I4.ToInstruction());
        Call(OpCodes.Callvirt, stream, "Write", MethodSig.CreateInstance(module.CorLibTypes.Void, bytes, module.CorLibTypes.Int32, module.CorLibTypes.Int32));
        Call(OpCodes.Callvirt, stream, "Close", MethodSig.CreateInstance(module.CorLibTypes.Void)); Call(OpCodes.Callvirt, memory, "ToArray", MethodSig.CreateInstance(bytes));
        Call(OpCodes.Call, module.CorLibTypes.GetTypeRef("System", "Convert"), scenario == "encryptor-operation" ? "ApplicationTransform" : "ToBase64String", MethodSig.CreateStatic(module.CorLibTypes.String, bytes));
        il.Add(OpCodes.Ret.ToInstruction());
    }

    private static MethodDefUser Add(TypeDef owner, string name, TypeSig result, params TypeSig[] parameters)
    {
        var method = new MethodDefUser(name, MethodSig.CreateStatic(result, parameters), MethodAttributes.Static | MethodAttributes.Private) { Body = new CilBody() };
        owner.Methods.Add(method); return method;
    }
}
