using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using Cilantro.Core.Verification;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ProtectorResourceCleanupTests
{
    [Theory]
    [InlineData("GetForegroundWindow", false, true)]
    [InlineData("GetForegroundWindow", true, false)]
    [InlineData("SetProcessDPIAware", false, true)]
    [InlineData("SetProcessDPIAware", true, false)]
    [InlineData("SetThreadExecutionState", false, true)]
    [InlineData("SetThreadExecutionState", true, false)]
    [InlineData("GetLastInputInfo", false, true)]
    [InlineData("GetLastInputInfo", true, false)]
    [InlineData("GetWindowText", false, false)]
    [InlineData("GetWindowTextLength", false, false)]
    public void FixedNativeQueriesRequireExactUnmanagedSignatures(string entry, bool malformed, bool expected)
    {
        using var module = new ModuleDefUser("Test");
        var result = entry == "GetForegroundWindow" ? module.CorLibTypes.IntPtr :
            entry == "SetThreadExecutionState" ? module.CorLibTypes.UInt32 : module.CorLibTypes.Boolean;
        var method = new MethodDefUser("Query", MethodSig.CreateStatic(result))
        {
            Attributes = MethodAttributes.Static | MethodAttributes.PinvokeImpl,
            ImplMap = new ImplMapUser(new ModuleRefUser(module, entry == "SetThreadExecutionState" ? "kernel32.dll" : "user32.dll"), entry, PInvokeAttributes.CallConvWinapi)
        };
        module.GlobalType.Methods.Add(method);
        if (entry == "SetThreadExecutionState") method.MethodSig.Params.Add(module.CorLibTypes.UInt32);
        if (entry == "GetLastInputInfo")
        {
            var buffer = new TypeDefUser("InputInfo", new TypeRefUser(module, "System", "ValueType", module.CorLibTypes.AssemblyRef))
            { Attributes = TypeAttributes.SequentialLayout | TypeAttributes.Sealed };
            module.Types.Add(buffer);
            buffer.Fields.Add(new FieldDefUser("Size", new FieldSig(module.CorLibTypes.UInt32), FieldAttributes.Public));
            buffer.Fields.Add(new FieldDefUser("Tick", new FieldSig(malformed ? module.CorLibTypes.String : module.CorLibTypes.UInt32), FieldAttributes.Public));
            method.MethodSig.Params.Add(new ByRefSig(new ValueTypeSig(buffer)));
        }
        else if (malformed) method.MethodSig.Params.Add(module.CorLibTypes.Object);
        Assert.Equal(expected, ProtectorResourceCleanupPass.IsKnownNonResourceImport(method));
        method.ImplMap.Module.Name = "custom.dll";
        Assert.False(ProtectorResourceCleanupPass.IsKnownNonResourceImport(method));
    }

    [Theory]
    [InlineData("kernel32.dll", "IsDebuggerPresent", false, true)]
    [InlineData("custom.dll", "IsDebuggerPresent", false, false)]
    [InlineData("kernel32.dll", "isdebuggerpresent", false, false)]
    [InlineData("kernel32.dll", "IsDebuggerPresent", true, false)]
    public void DebuggerQueryDoesNotImplyResourceAccess(string library, string entry, bool parameter, bool expected)
    {
        using var module = new ModuleDefUser("Test");
        var method = new MethodDefUser("Probe", MethodSig.CreateStatic(module.CorLibTypes.Boolean))
        {
            Attributes = MethodAttributes.Static | MethodAttributes.PinvokeImpl,
            ImplMap = new ImplMapUser(new ModuleRefUser(module, library), entry, PInvokeAttributes.CallConvWinapi)
        };
        if (parameter) method.MethodSig.Params.Add(module.CorLibTypes.Object);
        Assert.Equal(expected, ProtectorResourceCleanupPass.IsKnownNonResourceImport(method));
    }

    [Theory]
    [InlineData("removed", 1)]
    [InlineData("parsed-name", 1)]
    [InlineData("parsed-name-cast", 1)]
    [InlineData("parsed-name-escape", 0)]
    [InlineData("parsed-name-foreign", 0)]
    [InlineData("parsed-name-entry", 0)]
    [InlineData("discarded-assembly", 1)]
    [InlineData("discarded-assembly-spill", 0)]
    [InlineData("discarded-assembly-entry", 0)]
    [InlineData("discarded-assembly-foreign", 0)]
    [InlineData("dependency", 1)]
    [InlineData("dependency-changed", 0)]
    [InlineData("disabled", 0)]
    [InlineData("unattributed", 0)]
    [InlineData("changed", 0)]
    [InlineData("literal", 0)]
    [InlineData("computed", 0)]
    [InlineData("type-handle", 1)]
    [InlineData("foreign-type-handle", 0)]
    [InlineData("bundle", 1)]
    [InlineData("changed-entry", 0)]
    [InlineData("application-role", 0)]
    [InlineData("service-import", 1)]
    [InlineData("foreign-import", 0)]
    [InlineData("resource-import", 0)]
    [InlineData("native-resolver", 0)]
    [InlineData("literal-resource", 1)]
    [InlineData("dynamic-resource", 0)]
    [InlineData("alternate-resource", 0)]
    [InlineData("foreign-resource", 0)]
    [InlineData("padded-resource", 1)]
    [InlineData("spill-resource", 1)]
    [InlineData("spill-other-local", 0)]
    [InlineData("spill-foreign-cast", 0)]
    [InlineData("spill-alternate-entry", 0)]
    [InlineData("spill-dynamic", 0)]
    [InlineData("assembly-name", 1)]
    [InlineData("assembly-name-init", 1)]
    [InlineData("assembly-name-escape", 0)]
    [InlineData("assembly-name-foreign", 0)]
    [InlineData("assembly-name-entry", 0)]
    [InlineData("assembly-name-key", 1)]
    [InlineData("assembly-name-key-casts", 1)]
    [InlineData("assembly-name-key-escape", 0)]
    [InlineData("assembly-name-key-foreign", 0)]
    [InlineData("assembly-name-key-entry", 0)]
    public void OnlyAttributedUnusedUnchangedResourcesAreRemoved(string scenario, int expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            module.Resources.Add(new EmbeddedResource("protector", new byte[] { 1, 2 }, ManifestResourceAttributes.Private));
            module.Resources.Add(new EmbeddedResource("application", new byte[] { 3, 4 }, ManifestResourceAttributes.Private));
            var type = SyntheticContext.AddType(module, "App");
            var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Public | MethodAttributes.Static, Body = new CilBody() };
            type.Methods.Add(method);
            if (scenario.StartsWith("discarded-assembly", StringComparison.Ordinal))
            {
                var metadataType = new TypeRefUser(module, "System", "Type",
                    scenario == "discarded-assembly-foreign" ? new AssemblyRefUser("Foreign") : module.CorLibTypes.AssemblyRef);
                var assembly = module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly");
                var getAssembly = OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_Assembly", MethodSig.CreateInstance(assembly.ToTypeSig()), metadataType));
                if (scenario == "discarded-assembly-entry")
                {
                    method.MethodSig.Params.Add(metadataType.ToTypeSig()); method.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                    method.Body.Instructions.Add(OpCodes.Br.ToInstruction(getAssembly));
                }
                method.Body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(type));
                method.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetTypeFromHandle", MethodSig.CreateStatic(metadataType.ToTypeSig(),
                    new ValueTypeSig(module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle"))), metadataType)));
                method.Body.Instructions.Add(getAssembly);
                if (scenario == "discarded-assembly-spill")
                {
                    var local = new Local(assembly.ToTypeSig()); method.Body.Variables.Add(local);
                    method.Body.Instructions.Add(OpCodes.Stloc.ToInstruction(local)); method.Body.Instructions.Add(OpCodes.Ldloc.ToInstruction(local));
                }
                method.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("unused name")); method.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
                method.Body.Instructions.Add(OpCodes.Castclass.ToInstruction(assembly)); method.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            }
            if (scenario.StartsWith("parsed-name", StringComparison.Ordinal))
            {
                var name = new TypeRefUser(module, "System.Reflection", "AssemblyName",
                    scenario == "parsed-name-foreign" ? new AssemblyRefUser("Foreign") : module.CorLibTypes.AssemblyRef);
                var full = OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "get_FullName",
                    MethodSig.CreateInstance(module.CorLibTypes.String), name));
                if (scenario == "parsed-name-entry")
                {
                    method.MethodSig.Params.Add(name.ToTypeSig());
                    method.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                    method.Body.Instructions.Add(OpCodes.Br.ToInstruction(full));
                }
                method.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("Example, Version=1.0.0.0"));
                method.Body.Instructions.Add(OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor",
                    MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String), name)));
                if (scenario == "parsed-name-cast")
                { method.Body.Instructions.Add(OpCodes.Nop.ToInstruction()); method.Body.Instructions.Add(OpCodes.Castclass.ToInstruction(name)); }
                if (scenario == "parsed-name-escape") method.Body.Instructions.Add(OpCodes.Dup.ToInstruction());
                method.Body.Instructions.Add(full); method.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
                if (scenario == "parsed-name-escape") method.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            }
            if (scenario.StartsWith("assembly-name", StringComparison.Ordinal))
            {
                var assembly = new TypeRefUser(module, "System.Reflection", "Assembly", module.CorLibTypes.AssemblyRef);
                var name = new TypeRefUser(module, "System.Reflection", "AssemblyName", module.CorLibTypes.AssemblyRef);
                var get = new MemberRefUser(module, "GetExecutingAssembly", MethodSig.CreateStatic(new ClassSig(assembly)), assembly);
                var getName = OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetName", MethodSig.CreateInstance(new ClassSig(name)), assembly));
                if (scenario.EndsWith("-entry", StringComparison.Ordinal))
                {
                    method.MethodSig = MethodSig.CreateStatic(module.CorLibTypes.Void, new ClassSig(assembly));
                    method.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                    method.Body.Instructions.Add(OpCodes.Br.ToInstruction(getName));
                }
                method.Body.Instructions.Add(OpCodes.Call.ToInstruction(get));
                if (scenario == "assembly-name-key-casts") method.Body.Instructions.Add(OpCodes.Castclass.ToInstruction(assembly));
                if (scenario == "assembly-name-init")
                {
                    var helpers = new TypeRefUser(module, "System.Runtime.CompilerServices", "RuntimeHelpers", module.CorLibTypes.AssemblyRef);
                    var handle = new TypeRefUser(module, "System", "RuntimeTypeHandle", module.CorLibTypes.AssemblyRef);
                    method.Body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(type));
                    method.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "RunClassConstructor", MethodSig.CreateStatic(module.CorLibTypes.Void, new ValueTypeSig(handle)), helpers)));
                }
                method.Body.Instructions.Add(getName);
                if (scenario == "assembly-name-key-casts") method.Body.Instructions.Add(OpCodes.Castclass.ToInstruction(name));
                if (scenario.EndsWith("-escape", StringComparison.Ordinal)) method.Body.Instructions.Add(OpCodes.Dup.ToInstruction());
                if (scenario.EndsWith("-foreign", StringComparison.Ordinal)) name.ResolutionScope = new AssemblyRefUser("Foreign", new Version(1, 0));
                var key = scenario.Contains("-key", StringComparison.Ordinal);
                method.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, key ? "GetPublicKey" : "get_Name",
                    MethodSig.CreateInstance(key ? new SZArraySig(module.CorLibTypes.Byte) : module.CorLibTypes.String), name)));
                method.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
                if (scenario.EndsWith("-escape", StringComparison.Ordinal)) method.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            }
            if (scenario.StartsWith("spill-", StringComparison.Ordinal) || scenario is "literal-resource" or "dynamic-resource" or "alternate-resource" or "foreign-resource" or "padded-resource")
            {
                IResolutionScope scope = scenario == "foreign-resource" ? new AssemblyRefUser("Foreign", new Version(1, 0)) : module.CorLibTypes.AssemblyRef;
                var assembly = new TypeRefUser(module, "System.Reflection", "Assembly", scope);
                var stream = new TypeRefUser(module, "System.IO", "Stream", scope);
                var get = new MemberRefUser(module, "GetExecutingAssembly", MethodSig.CreateStatic(new ClassSig(assembly)), assembly);
                var read = OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetManifestResourceStream",
                    MethodSig.CreateInstance(new ClassSig(stream), module.CorLibTypes.String), assembly));
                if (scenario == "alternate-resource")
                {
                    method.MethodSig = MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.String);
                    method.Body.Instructions.Add(OpCodes.Call.ToInstruction(get));
                    method.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                    method.Body.Instructions.Add(OpCodes.Br.ToInstruction(read));
                }
                method.Body.Instructions.Add(OpCodes.Call.ToInstruction(get));
                if (scenario == "padded-resource") method.Body.Instructions.Add(OpCodes.Nop.ToInstruction());
                method.Body.Instructions.Add(scenario is "dynamic-resource" or "spill-dynamic" ? OpCodes.Ldnull.ToInstruction() : OpCodes.Ldstr.ToInstruction("application"));
                if (scenario == "padded-resource") method.Body.Instructions.Add(OpCodes.Nop.ToInstruction());
                if (scenario.StartsWith("spill-", StringComparison.Ordinal))
                {
                    var local = new Local(module.CorLibTypes.String);
                    var other = new Local(module.CorLibTypes.String);
                    method.Body.Variables.Add(local); method.Body.Variables.Add(other);
                    method.Body.InitLocals = true;
                    method.Body.Instructions.Add(OpCodes.Stloc.ToInstruction(local));
                    var cast = OpCodes.Castclass.ToInstruction(scenario == "spill-foreign-cast"
                        ? new TypeRefUser(module, "System.Reflection", "Assembly", new AssemblyRefUser("Foreign", new Version(1, 0))) : assembly);
                    method.Body.Instructions.Add(cast);
                    method.Body.Instructions.Add(OpCodes.Ldloc.ToInstruction(scenario == "spill-other-local" ? other : local));
                    if (scenario == "spill-alternate-entry")
                    {
                        method.MethodSig = MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.String);
                        method.Body.Instructions.Insert(0, OpCodes.Br.ToInstruction(cast));
                        method.Body.Instructions.Insert(0, OpCodes.Call.ToInstruction(get));
                        method.Body.Instructions.Insert(0, OpCodes.Stloc.ToInstruction(local));
                        method.Body.Instructions.Insert(0, OpCodes.Ldarg_0.ToInstruction());
                    }
                }
                method.Body.Instructions.Add(read);
                method.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            }
            if (scenario is "service-import" or "foreign-import" or "resource-import" or "native-resolver")
            {
                var import = new MethodDefUser("NativeCall", MethodSig.CreateStatic(module.CorLibTypes.Boolean, module.CorLibTypes.IntPtr))
                {
                    Attributes = MethodAttributes.Static | MethodAttributes.PinvokeImpl,
                    ImplMap = new ImplMapUser(new ModuleRefUser(module, scenario == "foreign-import" ? "custom.dll" : "advapi32.dll"),
                        scenario == "resource-import" ? "FindResourceW" : "CloseServiceHandle", 0)
                };
                type.Methods.Add(import);
                if (scenario == "native-resolver")
                {
                    var native = new TypeRefUser(module, "System.Runtime.InteropServices", "NativeLibrary", module.CorLibTypes.AssemblyRef);
                    method.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("custom.dll"));
                    method.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "Load",
                        MethodSig.CreateStatic(module.CorLibTypes.IntPtr, module.CorLibTypes.String), native)));
                    method.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
                }
            }
            if (scenario == "literal")
            {
                method.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("protector"));
                method.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            }
            if (scenario == "computed")
            {
                var assembly = new TypeRefUser(module, "System.Reflection", "Assembly", module.CorLibTypes.AssemblyRef);
                method.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetExecutingAssembly", MethodSig.CreateStatic(new ClassSig(assembly)), assembly)));
                method.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            }
            if (scenario is "type-handle" or "foreign-type-handle")
            {
                IResolutionScope scope = scenario == "type-handle" ? module.CorLibTypes.AssemblyRef : new AssemblyRefUser("Foreign", new Version(1, 0));
                var systemType = new TypeRefUser(module, "System", "Type", scope);
                var handle = new TypeRefUser(module, "System", "RuntimeTypeHandle", scope);
                method.Body.Instructions.Add(OpCodes.Ldtoken.ToInstruction(type));
                method.Body.Instructions.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetTypeFromHandle",
                    MethodSig.CreateStatic(new ClassSig(systemType), new ValueTypeSig(handle)), systemType)));
                method.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
            }
            method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        });
        var original = context.Module.Resources.OfType<EmbeddedResource>().First();
        var origin = RecoveredResourceOrigin.Capture(original);
        if (scenario == "changed") origin = origin with { Sha256 = "wrong" };
        if (scenario is "bundle" or "changed-entry")
        {
            var entry = RecoveredResourceOrigin.Capture(context.Module.Resources.OfType<EmbeddedResource>().Last());
            if (scenario == "changed-entry") entry = entry with { Sha256 = "changed" };
            context.SetFact<IReadOnlyList<RestoredResourceBundle>>("resources.validatedBundles", new[] { new RestoredResourceBundle(origin, new[] { entry }) });
        }
        else if (scenario is "dependency" or "dependency-changed")
            context.SetFact<IReadOnlyList<RecoveredResourceOrigin>>(DependencyInputCompletionPass.RetiredResourcesFact,
                [scenario == "dependency-changed" ? origin with { Sha256 = "changed" } : origin]);
        else if (scenario != "unattributed") context.SetFact("proxy.validatedResource", origin);
        if (scenario == "application-role") context.SetFact<IReadOnlyList<ResourceRoleFact>>("resource.roles",
            new[] { new ResourceRoleFact("protector", ResourceRole.ManagedPayload, 1, [], []) });
        context.SetFact("options.removeRuntime", scenario != "disabled");
        var bodies = context.Module.GetTypes().SelectMany(t => t.Methods).ToDictionary(m => m, MethodBodySnapshot.Capture);
        Assert.Equal(expected, new ProtectorResourceCleanupPass().Run(context).Changes);
        Assert.Equal(2 - expected, context.Module.Resources.Count);
        Assert.Contains(context.Module.Resources, r => r.Name == "application");
        Assert.True(bodies.All(p => p.Value.StructurallyEquals(p.Key)));
        Assert.True(AssemblyVerifier.Verify(context.Module, context.OriginalIdentity, context.OriginalStructure, CilantroPipeline.BuildRewriteAllowance(context)).Passed);
        Assert.Equal(0, new ProtectorResourceCleanupPass().Run(context).Changes);
        using var bytes = new MemoryStream(); context.Module.Write(bytes);
        using var reload = ModuleDefMD.Load(bytes.ToArray());
        Assert.Equal(2 - expected, reload.Resources.Count);
        Assert.Equal(context.Module.GetTypes().SelectMany(t => t.Methods).Count(m => m.IsPinvokeImpl),
            reload.GetTypes().SelectMany(t => t.Methods).Count(m => m.IsPinvokeImpl));
    }
}
