using System.Security.Cryptography;
using Cilantro.Core;
using Cilantro.Core.Interpretation;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class LateNumericInitializationTests
{
    [Theory]
    [InlineData(false, true, false, true)]
    [InlineData(true, true, false, false)]
    [InlineData(false, false, false, false)]
    [InlineData(false, true, true, false)]
    public void LateFileRefusalRetriesFreshTablesWithoutImportingHostValues(
        bool acceptedSignature, bool readFile, bool ambientTable, bool folds)
    {
        using var rsa = RSA.Create(1024);
        var digest = new byte[20];
        var signature = acceptedSignature ? rsa.SignHash(digest, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1) : new byte[128];
        using var context = SyntheticContext.Build(module =>
        {
            var host = SyntheticContext.AddType(module, "Host");
            var owner = SyntheticContext.AddType(module, "Table");
            MethodDef Make(TypeDef type, string name, MethodSig sig, params Instruction[] il)
            {
                var method = new MethodDefUser(name, sig)
                {
                    Attributes = sig.HasThis ? MethodAttributes.Private : MethodAttributes.Static,
                    Body = new CilBody()
                };
                if (name is ".ctor" or ".cctor") method.Attributes |= MethodAttributes.SpecialName | MethodAttributes.RTSpecialName;
                foreach (var instruction in il) method.Body.Instructions.Add(instruction);
                type.Methods.Add(method);
                return method;
            }
            var assembly = module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly");
            var executing = new MemberRefUser(module, "GetExecutingAssembly", MethodSig.CreateStatic(assembly.ToTypeSig()), assembly);
            var location = new MemberRefUser(module, "get_Location", MethodSig.CreateInstance(module.CorLibTypes.String), assembly);
            var empty = new MemberRefUser(module, "IsNullOrEmpty", MethodSig.CreateStatic(module.CorLibTypes.Boolean, module.CorLibTypes.String), module.CorLibTypes.String.TypeDefOrRef);
            var fips = new MemberRefUser(module, "get_AllowOnlyFipsAlgorithms", MethodSig.CreateStatic(module.CorLibTypes.Boolean), module.CorLibTypes.GetTypeRef("System.Security.Cryptography", "CryptoConfig"));
            var bytes = new SZArraySig(module.CorLibTypes.Byte);
            var read = new MemberRefUser(module, "ReadAllBytes", MethodSig.CreateStatic(bytes, module.CorLibTypes.String), module.CorLibTypes.GetTypeRef("System.IO", "File"));
            var rsaType = module.CorLibTypes.GetTypeRef("System.Security.Cryptography", "RSACryptoServiceProvider");
            var rsaCtor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), rsaType);
            var xml = new MemberRefUser(module, "FromXmlString", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String), rsaType);
            var verify = new MemberRefUser(module, "VerifyHash", MethodSig.CreateInstance(module.CorLibTypes.Boolean, bytes, module.CorLibTypes.String, bytes), rsaType);
            var decode = new MemberRefUser(module, "FromBase64String", MethodSig.CreateStatic(bytes, module.CorLibTypes.String), module.CorLibTypes.GetTypeRef("System", "Convert"));
            var done = OpCodes.Ret.ToInstruction();
            var gate = Make(host, "Check", MethodSig.CreateStatic(module.CorLibTypes.Void),
                OpCodes.Call.ToInstruction(executing), OpCodes.Callvirt.ToInstruction(location), OpCodes.Call.ToInstruction(empty), OpCodes.Brtrue.ToInstruction(done),
                OpCodes.Call.ToInstruction(fips), OpCodes.Pop.ToInstruction());
            if (readFile)
                foreach (var i in new[] { OpCodes.Call.ToInstruction(executing), OpCodes.Callvirt.ToInstruction(location), OpCodes.Call.ToInstruction(read), OpCodes.Pop.ToInstruction() }) gate.Body.Instructions.Add(i);
            foreach (var i in new[] {
                OpCodes.Newobj.ToInstruction(rsaCtor), OpCodes.Dup.ToInstruction(), OpCodes.Ldstr.ToInstruction(rsa.ToXmlString(false)), OpCodes.Callvirt.ToInstruction(xml),
                OpCodes.Ldstr.ToInstruction(Convert.ToBase64String(digest)), OpCodes.Call.ToInstruction(decode), OpCodes.Ldstr.ToInstruction("SHA1"),
                OpCodes.Ldstr.ToInstruction(Convert.ToBase64String(signature)), OpCodes.Call.ToInstruction(decode), OpCodes.Callvirt.ToInstruction(verify),
                OpCodes.Brtrue.ToInstruction(done), OpCodes.Ldnull.ToInstruction(), OpCodes.Throw.ToInstruction(), done }) gate.Body.Instructions.Add(i);
            Make(module.GlobalType, ".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void), OpCodes.Call.ToInstruction(gate), OpCodes.Ret.ToInstruction());
            var holder = new FieldDefUser("Instance", new FieldSig(owner.ToTypeSig()), FieldAttributes.Static | FieldAttributes.InitOnly);
            var values = new FieldDefUser("Values", new FieldSig(new SZArraySig(module.CorLibTypes.Int32)));
            owner.Fields.Add(holder); owner.Fields.Add(values);
            var tick = new MemberRefUser(module, "get_TickCount", MethodSig.CreateStatic(module.CorLibTypes.Int32), module.CorLibTypes.GetTypeRef("System", "Environment"));
            var ctor = Make(owner, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void),
                OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldc_I4_1.ToInstruction(), OpCodes.Newarr.ToInstruction(module.CorLibTypes.Int32.TypeDefOrRef), OpCodes.Stfld.ToInstruction(values),
                OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldfld.ToInstruction(values), OpCodes.Ldc_I4_0.ToInstruction(),
                ambientTable ? OpCodes.Call.ToInstruction(tick) : Instruction.CreateLdcI4(123), OpCodes.Stelem_I4.ToInstruction(), OpCodes.Ret.ToInstruction());
            Make(owner, ".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void), OpCodes.Call.ToInstruction(gate),
                OpCodes.Newobj.ToInstruction(ctor), OpCodes.Stsfld.ToInstruction(holder), OpCodes.Ret.ToInstruction());
            var getter = Make(owner, "Read", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                OpCodes.Ldsfld.ToInstruction(holder), OpCodes.Ldfld.ToInstruction(values), OpCodes.Ldarg_0.ToInstruction(), OpCodes.Ldelem_I4.ToInstruction(), OpCodes.Ret.ToInstruction());
            Make(host, "Caller", MethodSig.CreateStatic(module.CorLibTypes.Int32), OpCodes.Ldc_I4_0.ToInstruction(), OpCodes.Call.ToInstruction(getter), OpCodes.Ret.ToInstruction());
        });
        context.SetFact(BootstrapMachine.RunEnvironmentFact, new RunEnvironment(new HostEnvironment(HostProfile.Workstation)));
        var gate = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Check");
        var original = gate.Body.Instructions.ToArray();
        Assert.Equal(0, new NumericTableRecoveryPass().Run(context).Changes);
        Assert.DoesNotContain(context.Evidence, e => e.Category == "interpretation-environment");
        var result = new NumericTableCompletionPass().Run(context);
        Assert.Equal(folds ? 1 : 0, result.Changes);
        Assert.Equal(original, gate.Body.Instructions);
        Assert.True(AssemblyVerifier.Verify(context.Module).Passed);
        Assert.True(BootstrapMachine.TrySeed(context, 100_000, out var machine, out _));
        Assert.Equal(!acceptedSignature && readFile, machine!.State.ModuleFileIsAbsent);
        if (folds)
        {
            var caller = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Caller");
            var answer = machine.Execute(caller);
            Assert.True(answer.Succeeded, answer.Diagnostic);
            Assert.Equal(123, answer.Value.AsInt32());
            Assert.Equal(0, new NumericTableCompletionPass().Run(context).Changes);
        }
    }
}
