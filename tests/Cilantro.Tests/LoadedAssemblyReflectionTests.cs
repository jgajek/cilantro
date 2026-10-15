using Cilantro.Core.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Cilantro.Tests;

public sealed class LoadedAssemblyReflectionTests
{
    [Theory]
    [InlineData("direct", 3)]
    [InlineData("spill", 3)]
    [InlineData("own-assembly", 0)]
    [InlineData("overwritten", 0)]
    [InlineData("addressed", 0)]
    [InlineData("branch", 3)]
    [InlineData("typed-overload", 3)]
    [InlineData("flags-overload", 3)]
    [InlineData("foreign", 0)]
    public void ClassifiesOnlyTheLocalLoadedAssemblyChain(string scenario, int expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "App");
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void))
                { Attributes = MethodAttributes.Static, Body = new CilBody { InitLocals = true } }; owner.Methods.Add(run);
            var assembly = new TypeRefUser(module, "System.Reflection", "Assembly",
                scenario == "foreign" ? new AssemblyRefUser("Foreign") : module.CorLibTypes.AssemblyRef);
            var type = module.CorLibTypes.GetTypeRef("System", "Type");
            var method = module.CorLibTypes.GetTypeRef("System.Reflection", "MethodInfo");
            var methodBase = module.CorLibTypes.GetTypeRef("System.Reflection", "MethodBase");
            var il = run.Body.Instructions;
            il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "Load",
                MethodSig.CreateStatic(assembly.ToTypeSig(), new SZArraySig(module.CorLibTypes.Byte)), assembly)));
            if (scenario == "own-assembly")
            {
                il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "GetExecutingAssembly",
                    MethodSig.CreateStatic(assembly.ToTypeSig()), assembly)));
            }
            if (scenario is "spill" or "overwritten" or "addressed")
            {
                var local = new Local(assembly.ToTypeSig()); run.Body.Variables.Add(local);
                il.Add(OpCodes.Stloc.ToInstruction(local));
                if (scenario == "overwritten") { il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Stloc.ToInstruction(local)); }
                if (scenario == "addressed") { il.Add(OpCodes.Ldloca.ToInstruction(local)); il.Add(OpCodes.Pop.ToInstruction()); }
                il.Add(OpCodes.Ldloc.ToInstruction(local));
            }
            var name = OpCodes.Ldstr.ToInstruction("Type");
            if (scenario == "branch") il.Add(OpCodes.Br.ToInstruction(name));
            il.Add(name);
            var getType = MethodSig.CreateInstance(type.ToTypeSig(), module.CorLibTypes.String);
            if (scenario is "typed-overload" or "flags-overload")
            { il.Add(OpCodes.Ldc_I4_1.ToInstruction()); getType.Params.Add(module.CorLibTypes.Boolean); }
            if (scenario == "flags-overload")
            { il.Add(OpCodes.Ldc_I4_0.ToInstruction()); getType.Params.Add(module.CorLibTypes.Boolean); }
            il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetType", getType, assembly)));
            il.Add(OpCodes.Castclass.ToInstruction(type)); il.Add(OpCodes.Ldstr.ToInstruction("Method"));
            var getMethod = MethodSig.CreateInstance(method.ToTypeSig(), module.CorLibTypes.String);
            if (scenario == "typed-overload")
            { il.Add(OpCodes.Ldnull.ToInstruction()); getMethod.Params.Add(new SZArraySig(type.ToTypeSig())); }
            if (scenario == "flags-overload")
            {
                il.Add(OpCodes.Ldc_I4.ToInstruction(24));
                getMethod.Params.Add(new ValueTypeSig(module.CorLibTypes.GetTypeRef("System.Reflection", "BindingFlags")));
            }
            il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetMethod", getMethod, type)));
            il.Add(OpCodes.Ldnull.ToInstruction()); il.Add(OpCodes.Ldnull.ToInstruction());
            il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "Invoke",
                MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.Object, new SZArraySig(module.CorLibTypes.Object)), methodBase)));
            il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(expected, LoadedAssemblyReflection.Find(context.Module).Count);
    }

    [Theory]
    [InlineData(false, false, 1)]
    [InlineData(true, false, 1)]
    [InlineData(false, true, 1)]
    public void CarriesLoadedOrInitiallyNullLocalsAcrossJoinsAndLeave(bool join, bool leave, int expected)
    {
        using var context = SyntheticContext.Build(module =>
        {
            var owner = SyntheticContext.AddType(module, "App");
            var run = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Boolean))
                { Attributes = MethodAttributes.Static, Body = new CilBody { InitLocals = true } };
            owner.Methods.Add(run);
            var assembly = module.CorLibTypes.GetTypeRef("System.Reflection", "Assembly");
            var type = module.CorLibTypes.GetTypeRef("System", "Type");
            var local = new Local(assembly.ToTypeSig()); run.Body.Variables.Add(local);
            var read = OpCodes.Ldloc.ToInstruction(local);
            var il = run.Body.Instructions;
            if (join) { il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Brtrue.ToInstruction(read)); }
            il.Add(OpCodes.Ldnull.ToInstruction());
            il.Add(OpCodes.Call.ToInstruction(new MemberRefUser(module, "Load",
                MethodSig.CreateStatic(assembly.ToTypeSig(), new SZArraySig(module.CorLibTypes.Byte)), assembly)));
            il.Add(OpCodes.Stloc.ToInstruction(local));
            il.Add((leave ? OpCodes.Leave : OpCodes.Br).ToInstruction(read));
            il.Add(read); il.Add(OpCodes.Ldstr.ToInstruction("Type"));
            il.Add(OpCodes.Callvirt.ToInstruction(new MemberRefUser(module, "GetType",
                MethodSig.CreateInstance(type.ToTypeSig(), module.CorLibTypes.String), assembly)));
            il.Add(OpCodes.Pop.ToInstruction()); il.Add(OpCodes.Ret.ToInstruction());
        });
        Assert.Equal(expected, LoadedAssemblyReflection.Find(context.Module).Count);
    }
}
