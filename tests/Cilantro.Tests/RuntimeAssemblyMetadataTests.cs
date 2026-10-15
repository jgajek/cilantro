using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class RuntimeAssemblyMetadataTests
{
    [Theory]
    [InlineData("runtime", true)]
    [InlineData("mutated", false)]
    [InlineData("foreign", false)]
    [InlineData("first", true)]
    [InlineData("first-predicate", true)]
    [InlineData("foreign-linq", false)]
    [InlineData("default-overload", false)]
    [InlineData("direct-predicate", true)]
    [InlineData("escaped-predicate", true)]
    [InlineData("cached-predicate", true)]
    [InlineData("cached-any", true)]
    [InlineData("cache-read", true)]
    [InlineData("cache-write", true)]
    public void RuntimeAssemblyNamesDoNotCertifyForeignAssemblyInvocation(string scenario, bool nameKnown)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var cached = scenario is "cached-predicate" or "cached-any" or "cache-read" or "cache-write";
            var assembly = module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly");
            var array = new SZArraySig(assembly.ToTypeSig());
            var domain = new TypeRefUser(module, "System", "AppDomain", scenario == "foreign" ? new AssemblyRefUser("Foreign") : module.CorLibTypes.AssemblyRef);
            var getDomain = new MemberRefUser(module, "get_CurrentDomain", MethodSig.CreateStatic(domain.ToTypeSig()), domain);
            var getAssemblies = new MemberRefUser(module, "GetAssemblies", MethodSig.CreateInstance(array), domain);
            var getName = new MemberRefUser(module, "get_FullName", MethodSig.CreateInstance(module.CorLibTypes.String), assembly);
            var getTypes = new MemberRefUser(module, "GetTypes", MethodSig.CreateInstance(new SZArraySig(module.CorLibTypes.GetTypeRef("System", "Type").ToTypeSig())), assembly);
            var owner = SyntheticContext.AddType(module, "App");
            var method = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void, assembly.ToTypeSig()))
            { Attributes = MethodAttributes.Static, Body = new CilBody { InitLocals = true } };
            owner.Methods.Add(method);
            var local = new Local(array); method.Body.Variables.Add(local);
            var il = method.Body.Instructions;
            il.Add(OpCodes.Call.ToInstruction(getDomain)); il.Add(OpCodes.Callvirt.ToInstruction(getAssemblies)); il.Add(OpCodes.Stloc.ToInstruction(local));
            if (scenario == "mutated")
            {
                il.Add(OpCodes.Ldloc.ToInstruction(local)); il.Add(OpCodes.Ldc_I4_0.ToInstruction());
                il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Stelem_Ref.ToInstruction());
            }
            il.Add(OpCodes.Ldloc.ToInstruction(local));
            if (cached || scenario is "first" or "first-predicate" or "foreign-linq" or "default-overload" or "direct-predicate" or "escaped-predicate")
            {
                var linq = new TypeRefUser(module, "System.Linq", "Enumerable", new AssemblyRefUser(scenario == "foreign-linq" ? "Foreign" : "System.Core",
                    new Version(4, 0, 0, 0), new PublicKeyToken("b77a5c561934e089")));
                var sequence = new GenericInstSig(new ClassSig(module.CorLibTypes.GetTypeRef("System.Collections.Generic", "IEnumerable`1")), new GenericMVar(0));
                var signature = MethodSig.CreateStatic(new GenericMVar(0), sequence);
                signature.Generic = true; signature.GenParamCount = 1;
                MethodDef? predicate = null;
                FieldDef? cache = null; Instruction? cachedCall = null;
                if (cached || scenario is "first-predicate" or "default-overload" or "direct-predicate" or "escaped-predicate")
                {
                    signature.Params.Add(scenario == "default-overload" ? new GenericMVar(0) :
                        new GenericInstSig(new ClassSig(module.CorLibTypes.GetTypeRef("System", "Func`2")), new GenericMVar(0), module.CorLibTypes.Boolean));
                    if (cached)
                    {
                        cache = new FieldDefUser("Cache", new FieldSig(new GenericInstSig(new ClassSig(module.CorLibTypes.GetTypeRef("System", "Func`2")), assembly.ToTypeSig(), module.CorLibTypes.Boolean)), FieldAttributes.Private | FieldAttributes.Static);
                        owner.Fields.Add(cache); cachedCall = OpCodes.Nop.ToInstruction();
                        var create = OpCodes.Pop.ToInstruction();
                        il.Add(OpCodes.Ldsfld.ToInstruction(cache)); il.Add(OpCodes.Dup.ToInstruction());
                        il.Add(OpCodes.Brfalse.ToInstruction(create)); il.Add(OpCodes.Br.ToInstruction(cachedCall)); il.Add(create);
                    }
                    il.Add(OpCodes.Ldnull.ToInstruction());
                    if (cached || scenario is "direct-predicate" or "escaped-predicate")
                    {
                        predicate = new MethodDefUser("Predicate", MethodSig.CreateStatic(module.CorLibTypes.Boolean, assembly.ToTypeSig()))
                        { Attributes = MethodAttributes.Private | MethodAttributes.Static, Body = new CilBody() };
                        owner.Methods.Add(predicate);
                        predicate.Body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
                        predicate.Body.Instructions.Add(OpCodes.Callvirt.ToInstruction(getName));
                        predicate.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
                        predicate.Body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction());
                        predicate.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                        il.Add(OpCodes.Ldftn.ToInstruction(predicate));
                        var predicateType = new TypeSpecUser(new GenericInstSig(new ClassSig(module.CorLibTypes.GetTypeRef("System", "Func`2")), assembly.ToTypeSig(), module.CorLibTypes.Boolean));
                        il.Add(OpCodes.Newobj.ToInstruction(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void,
                            module.CorLibTypes.Object, module.CorLibTypes.IntPtr), predicateType)));
                    }
                    if (cache != null) { il.Add(OpCodes.Dup.ToInstruction()); il.Add(OpCodes.Stsfld.ToInstruction(cache)); }
                }
                if (scenario == "cached-any") signature.RetType = module.CorLibTypes.Boolean;
                var queryCall = OpCodes.Call.ToInstruction(new MethodSpecUser(new MemberRefUser(module, scenario == "cached-any" ? "Any" : "FirstOrDefault", signature, linq),
                    new GenericInstMethodSig(assembly.ToTypeSig())));
                if (cachedCall != null) { cachedCall.OpCode = queryCall.OpCode; cachedCall.Operand = queryCall.Operand; il.Add(cachedCall); }
                else il.Add(queryCall);
                if (scenario == "cache-read") { il.Add(OpCodes.Ldsfld.ToInstruction(cache!)); il.Add(OpCodes.Pop.ToInstruction()); }
                if (scenario == "cache-write") { il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Stsfld.ToInstruction(cache!)); }
                if (scenario == "cached-any")
                {
                    il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Call.ToInstruction(getDomain)); il.Add(OpCodes.Callvirt.ToInstruction(getAssemblies));
                    il.Add(OpCodes.Ldc_I4_0.ToInstruction()); il.Add(OpCodes.Ldelem_Ref.ToInstruction());
                }
                if (scenario == "escaped-predicate") { il.Add(OpCodes.Ldftn.ToInstruction(predicate!)); il.Add(OpCodes.Pop.ToInstruction()); }
            }
            else { il.Add(OpCodes.Ldc_I4_0.ToInstruction()); il.Add(OpCodes.Ldelem_Ref.ToInstruction()); }
            il.Add(OpCodes.Dup.ToInstruction()); il.Add(OpCodes.Callvirt.ToInstruction(getName)); il.Add(OpCodes.Pop.ToInstruction());
            il.Add(OpCodes.Callvirt.ToInstruction(getTypes)); il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction());
        });
        var proven = LoadedAssemblyFlow.Find(context.Module);
        Assert.Equal(nameKnown, proven.Any(i => i.Operand is IMethod m && m.Name == "get_FullName"));
        Assert.DoesNotContain(proven, i => i.Operand is IMethod m && m.Name == "GetTypes");
        if (scenario is "direct-predicate" or "escaped-predicate" or "cached-predicate" or "cached-any" or "cache-read" or "cache-write")
        {
            var predicate = context.Module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Predicate");
            Assert.Equal(scenario is "direct-predicate" or "cached-predicate" or "cached-any", predicate.Body.Instructions.Any(proven.Contains));
        }
    }
}
