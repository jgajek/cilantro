using Cilantro.Core;
using Cilantro.Core.Analysis;
using Cilantro.Core.Recovery;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class ResourceLookupTypingTests
{
    [Theory]
    [InlineData("resource", false, true)]
    [InlineData("resource", true, true)]
    [InlineData("initializer", false, true)]
    [InlineData("initializer", true, true)]
    [InlineData("reflection", false, false)]
    [InlineData("reflection", true, false)]
    [InlineData("foreign", false, false)]
    [InlineData("foreign", true, false)]
    public void ClosedIdentityUsesDoNotInventFieldWriters(string shape, bool array, bool expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Owner"); owner.Attributes = TypeAttributes.Public;
            TypeSig concrete = array ? new SZArraySig(module.CorLibTypes.Byte) : module.CorLibTypes.String;
            var field = new FieldDefUser("Value", new FieldSig(module.CorLibTypes.Object), FieldAttributes.Private | FieldAttributes.Static);
            owner.Fields.Add(field);
            MethodDef Add(string name, TypeSig result)
            {
                var m = new MethodDefUser(name, MethodSig.CreateStatic(result), MethodImplAttributes.IL,
                    MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
                owner.Methods.Add(m); return m;
            }
            var write = Add("Write", module.CorLibTypes.Void);
            if (array)
            { write.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction()); write.Body.Instructions.Add(OpCodes.Newarr.ToInstruction(module.CorLibTypes.Byte.TypeDefOrRef)); }
            else write.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("seed"));
            write.Body.Instructions.Add(OpCodes.Stsfld.ToInstruction(field)); write.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var read = Add("Read", concrete);
            read.Body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(field)); read.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var use = Add("Use", module.CorLibTypes.Void);
            var il = use.Body.Instructions; il.Add(OpCodes.Ldtoken.ToInstruction(owner));
            if (shape == "initializer")
                il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "RunClassConstructor",
                    MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle").ToTypeSig()),
                    module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "RuntimeHelpers"))));
            else if (shape == "reflection") il.Add(OpCodes.Pop.ToInstruction());
            else
            {
                var type = module.CorLibTypes.GetTypeRef("System", "Type");
                il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetTypeFromHandle",
                    MethodSig.CreateStatic(type.ToTypeSig(), module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle").ToTypeSig()), type)));
                var manager = new TypeRefUser(module, "System.ComponentModel", "ComponentResourceManager",
                    new AssemblyRefUser("System", new Version(4, 0, 0, 0), new PublicKeyToken(shape == "foreign" ? "0000000000000000" : "b77a5c561934e089")));
                il.Add(OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, type.ToTypeSig()), manager)));
                il.Add(OpCodes.Pop.ToInstruction());
            }
            il.Add(OpCodes.Ret.ToInstruction());
        });
        DeobfuscationPass pass = array ? new ArrayFieldTypingPass() : new ReferenceFieldTypingPass();
        Assert.Equal(expected ? 1 : 0, pass.Run(context).Changes);
        Assert.Equal(ElementType.Object, context.Module.GetTypes().SelectMany(t => t.Fields).Single().FieldType.ElementType);
        Assert.Equal(0, pass.Run(context).Changes);
        if (expected)
        {
            var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
            try { context.Module.Write(path); Assert.Equal(0, IlVerification.Read(path, []).Count); }
            finally { File.Delete(path); }
        }
    }

    [Theory]
    [InlineData("closed", false, true)]
    [InlineData("closed", true, true)]
    [InlineData("foreign", false, false)]
    [InlineData("conversion", false, false)]
    [InlineData("reflection", false, false)]
    [InlineData("branch", false, false)]
    [InlineData("friend", false, false)]
    [InlineData("called", false, false)]
    [InlineData("handle", false, false)]
    [InlineData("public", false, false)]
    [InlineData("export", false, false)]
    [InlineData("plain-closed", false, true)]
    [InlineData("plain-closed", true, true)]
    [InlineData("plain-friend", false, false)]
    [InlineData("plain-called", false, false)]
    [InlineData("plain-handle", false, false)]
    [InlineData("plain-named", false, false)]
    [InlineData("plain-export", false, false)]
    [InlineData("plain-attribute", false, false)]
    [InlineData("plain-accessor", false, false)]
    public void ResourceIdentityDoesNotInventACallerForAClosedUncalledForwarder(string shape, bool array, bool expected)
    {
        var resourceLookup = !shape.StartsWith("plain-", StringComparison.Ordinal);
        if (!resourceLookup) shape = shape[6..];
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "Form"); owner.Attributes = TypeAttributes.Public;
            TypeSig concrete = array ? new SZArraySig(module.CorLibTypes.Byte) : module.CorLibTypes.String;
            var target = new MethodDefUser("Target", MethodSig.CreateStatic(concrete, module.CorLibTypes.Object),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(target);
            target.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction()); target.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            var wrapper = new MethodDefUser("Forward", MethodSig.CreateStatic(concrete, module.CorLibTypes.Object),
                MethodImplAttributes.IL, MethodAttributes.Static | (shape == "public" ? MethodAttributes.Public : MethodAttributes.Assembly)) { Body = new CilBody() };
            owner.Methods.Add(wrapper);
            wrapper.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            wrapper.Body.Instructions.Add(OpCodes.Call.ToInstruction(target)); wrapper.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
            if (shape == "attribute") wrapper.CustomAttributes.Add(new CustomAttribute(new MemberRefUser(module, ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void), module.CorLibTypes.GetTypeRef("System", "ObsoleteAttribute"))));
            if (shape == "accessor") owner.Properties.Add(new PropertyDefUser("Value", PropertySig.CreateStatic(concrete, module.CorLibTypes.Object)) { GetMethod = wrapper });
            if (shape == "friend")
                module.Assembly.CustomAttributes.Add(new CustomAttribute(new MemberRefUser(module, ".ctor",
                    MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String),
                    module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "InternalsVisibleToAttribute")),
                    [new CAArgument(module.CorLibTypes.String, new UTF8String("Friend"))]));
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void, concrete, module.CorLibTypes.Object),
                MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
            owner.Methods.Add(run);
            var il = run.Body.Instructions;
            var type = module.CorLibTypes.GetTypeRef("System", "Type");
            var resource = new TypeRefUser(module, "System.ComponentModel", "ComponentResourceManager",
                new AssemblyRefUser("System", new Version(4, 0, 0, 0), new PublicKeyToken(shape == "foreign" ? "0000000000000000" : "b77a5c561934e089")));
            var convert = OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetTypeFromHandle",
                MethodSig.CreateStatic(type.ToTypeSig(), module.CorLibTypes.GetTypeRef("System", "RuntimeTypeHandle").ToTypeSig()),
                shape == "conversion" ? new TypeRefUser(module, "System", "Type", new AssemblyRefUser("Foreign")) : type));
            if (shape == "branch")
            { il.Add(OpCodes.Ldtoken.ToInstruction(owner)); il.Add(OpCodes.Br.ToInstruction(convert)); }
            if (resourceLookup)
            {
                il.Add(OpCodes.Ldtoken.ToInstruction(owner)); il.Add(convert);
                il.Add(OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, type.ToTypeSig()), resource)));
                il.Add(OpCodes.Pop.ToInstruction());
            }
            if (shape == "named") { il.Add(OpCodes.Ldstr.ToInstruction("Forward")); il.Add(OpCodes.Pop.ToInstruction()); }
            if (shape == "reflection")
            { il.Add(OpCodes.Ldtoken.ToInstruction(owner)); il.Add(OpCodes.Pop.ToInstruction()); }
            if (shape == "called")
            { il.Add(OpCodes.Ldarg_1.ToInstruction()); il.Add(OpCodes.Call.ToInstruction(wrapper)); il.Add(OpCodes.Pop.ToInstruction()); }
            if (shape == "handle")
            { il.Add(OpCodes.Ldtoken.ToInstruction(wrapper)); il.Add(OpCodes.Pop.ToInstruction()); }
            il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Call.ToInstruction(target));
            il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction());
        });
        var methods = context.Module.GetTypes().SelectMany(t => t.Methods).ToArray();
        var wrapper = methods.Single(m => m.Name == "Forward"); var body = wrapper.Body;
        if (shape == "export") wrapper.ExportInfo = new MethodExportInfo { Name = "Exported" };
        var methodCount = methods.Length;
        DeobfuscationPass pass = array ? new ArrayParameterTypingPass() : new ReferenceParameterTypingPass();
        Assert.Equal(expected ? 1 : 0, pass.Run(context).Changes);
        Assert.Same(body, wrapper.Body);
        Assert.Equal(methodCount, context.Module.GetTypes().Sum(t => t.Methods.Count));
        Assert.Equal(0, pass.Run(context).Changes);
        if (expected)
        {
            Assert.Contains(context.Evidence, e => e.Category == (resourceLookup ? "typing-uncalled-resource-forwarder" : "typing-uncalled-internal-method"));
            Assert.DoesNotContain(context.Module.GetTypes().Single(t => t.Name == "Form"), ModuleReachability.Compute(context.Module).ReflectivelyExposedTypes);
            var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".dll");
            try { context.Module.Write(path); Assert.Equal(0, IlVerification.Read(path, []).Count); }
            finally { File.Delete(path); }
        }
    }
}
