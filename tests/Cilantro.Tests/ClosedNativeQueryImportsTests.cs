using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ClosedNativeQueryImportsTests
{
    [Theory]
    [InlineData("IsDebuggerPresent", false, 2)]
    [InlineData("FindResourceA", false, 0)]
    [InlineData("IsDebuggerPresent", true, 1)]
    [InlineData("foreign-library", false, 0)]
    [InlineData("wrong-signature", false, 0)]
    [InlineData("foreign-delegate", false, 0)]
    [InlineData("NtQueryInformationProcess", false, 2)]
    [InlineData("managed-buffer", false, 0)]
    public void OnlyClosedLiteralQueryFactoriesAreAttributed(string export, bool escape, int expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            module.Resources.Add(new EmbeddedResource("protector", new byte[] { 1, 2, 3 }, ManifestResourceAttributes.Private));
            var type = SyntheticContext.AddType(module, "Factory");
            MethodDef Native(string name, params TypeSig[] parameters)
            {
                var method = new MethodDefUser(name, MethodSig.CreateStatic(module.CorLibTypes.IntPtr, parameters))
                { Attributes = MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.PinvokeImpl,
                    ImplMap = new ImplMapUser(new ModuleRefUser(module, "kernel32.dll"), name, PInvokeAttributes.CallConvWinapi) };
                type.Methods.Add(method); return method;
            }
            var load = Native("LoadLibrary", module.CorLibTypes.String);
            var address = Native("GetProcAddress", module.CorLibTypes.IntPtr, module.CorLibTypes.String);
            var systemType = new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef);
            var systemDelegate = new TypeRefUser(module, "System", "Delegate", module.CorLibTypes.AssemblyRef);
            var factory = new MethodDefUser("Create", MethodSig.CreateStatic(new ClassSig(systemDelegate), module.CorLibTypes.String, module.CorLibTypes.String))
            { Attributes = MethodAttributes.Private | MethodAttributes.Static, Body = new CilBody() };
            factory.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            factory.MethodSig.Generic = true; factory.MethodSig.GenParamCount = 1; type.Methods.Add(factory);
            var getType = new MemberRefUser(module, "GetTypeFromHandle", MethodSig.CreateStatic(new ClassSig(systemType),
                new ValueTypeSig(new TypeRefUser(module, "System", "RuntimeTypeHandle", module.CorLibTypes.AssemblyRef))), systemType);
            var marshal = new MemberRefUser(module, "GetDelegateForFunctionPointer", MethodSig.CreateStatic(new ClassSig(systemDelegate),
                module.CorLibTypes.IntPtr, new ClassSig(systemType)), new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef));
            foreach (var instruction in new[] { OpCodes.Ldarg_0.ToInstruction(), OpCodes.Call.ToInstruction(load), OpCodes.Ldarg_1.ToInstruction(),
                         OpCodes.Call.ToInstruction(address), OpCodes.Ldtoken.ToInstruction(new TypeSpecUser(new GenericMVar(0))),
                         OpCodes.Call.ToInstruction(getType), OpCodes.Call.ToInstruction(marshal), OpCodes.Ret.ToInstruction() })
                factory.Body.Instructions.Add(instruction);
            var query = SyntheticContext.AddType(module, "Query");
            query.BaseType = new TypeRefUser(module, "System", "MulticastDelegate", module.CorLibTypes.AssemblyRef);
            if (export == "foreign-delegate")
                query.BaseType = new TypeRefUser(module, "System", "MulticastDelegate", new AssemblyRefUser("Foreign"));
            query.Methods.Add(new MethodDefUser("Invoke", MethodSig.CreateInstance(export == "wrong-signature" ? module.CorLibTypes.Int32 : module.CorLibTypes.Boolean), MethodImplAttributes.Runtime,
                MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.NewSlot));
            if (export is "NtQueryInformationProcess" or "managed-buffer")
            {
                var buffer = SyntheticContext.AddType(module, "Buffer");
                buffer.BaseType = new TypeRefUser(module, "System", "ValueType", module.CorLibTypes.AssemblyRef);
                buffer.Attributes = TypeAttributes.NotPublic | TypeAttributes.SequentialLayout | TypeAttributes.Sealed;
                for (var index = 0; index < 6; index++)
                    buffer.Fields.Add(new FieldDefUser("Field" + index, new FieldSig(export == "managed-buffer" && index == 0 ? module.CorLibTypes.String : module.CorLibTypes.IntPtr), FieldAttributes.Public));
                query.Methods[0].MethodSig = MethodSig.CreateInstance(module.CorLibTypes.Int32, module.CorLibTypes.IntPtr,
                    module.CorLibTypes.Int32, new ByRefSig(new ValueTypeSig(buffer)), module.CorLibTypes.Int32, new ByRefSig(module.CorLibTypes.Int32));
            }
            var caller = new MethodDefUser("Caller", MethodSig.CreateStatic(module.CorLibTypes.Void))
            { Attributes = MethodAttributes.Private | MethodAttributes.Static, Body = new CilBody() };
            type.Methods.Add(caller);
            caller.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction(export == "foreign-library" ? "custom.dll" : export is "NtQueryInformationProcess" or "managed-buffer" ? "ntdll.dll" : "kernel32.dll"));
            caller.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction(export is "foreign-library" or "wrong-signature" or "foreign-delegate" ? "IsDebuggerPresent" : export == "managed-buffer" ? "NtQueryInformationProcess" : export));
            caller.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MethodSpecUser(factory, new GenericInstMethodSig(query.ToTypeSig()))));
            caller.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            if (escape)
            {
                caller.Body.Instructions.Add(OpCodes.Ldftn.ToInstruction(load));
                caller.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            }
            caller.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(expected, ClosedNativeQueryImports.Find(context.Module).Count);
        if (escape)
            Assert.DoesNotContain(ClosedNativeQueryImports.Find(context.Module), method => method.Name == "LoadLibrary");
        context.SetFact("options.removeRuntime", true);
        context.SetFact<IReadOnlyList<RecoveredResourceOrigin>>("strings.validatedResources",
            [RecoveredResourceOrigin.Capture((EmbeddedResource)context.Module.Resources[0])]);
        var removal = new ProtectorResourceCleanupPass().Run(context);
        Assert.Equal(expected == 2 ? 1 : 0, removal.Changes);
    }
}
